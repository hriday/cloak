# Production Deploy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring up `https://cloak.moosha.org/` on the existing droplet (`/opt/cloak/`) following the `thirdumpire` pattern: Caddy → docker compose (web + db) → Postgres + Django, with manual `./deploy.sh` for updates.

**Architecture:** Caddy reverse-proxies to a docker container on `127.0.0.1:9091`. Web container is Django + gunicorn (1 worker, 4 threads, tuned for 512 MB RAM). DB container is Postgres 16-alpine with `shared_buffers=32MB`. Static files served from inside Django via WhiteNoise. Nightly pg_dump cron writes 7-day rotating backups to `/opt/cloak/backups/`. Spec: `docs/superpowers/specs/2026-05-23-production-deploy-design.md`.

**Tech Stack:** Caddy 2 (already running), Docker compose, Postgres 16-alpine, Django 5, gunicorn, WhiteNoise.

---

## File Structure

**Already in place (no changes needed):**
- `requirements.txt` — gunicorn, whitenoise, psycopg[binary] already listed.
- `cloak/settings.py` — WhiteNoise middleware, STATIC_ROOT, STORAGES, CSRF_TRUSTED_ORIGINS, SECURE_PROXY_SSL_HEADER all already set.
- `Dockerfile` — builds correctly, exposes 8000, uses entrypoint.sh.
- `entrypoint.sh` — runs migrate → loaddata → collectstatic → gunicorn. Just needs worker count tuning via env var.

**Modified:**
- `entrypoint.sh` — read worker / thread counts from env (`GUNICORN_WORKERS`, `GUNICORN_THREADS`) with sensible dev defaults.

**Created:**
- `docker-compose.prod.yml` — prod-only compose: port 9091, tuned Postgres, named volumes, restart-unless-stopped.
- `deploy.sh` — SSH wrapper that runs the update sequence on the server.
- `docs/deploy.md` — first-time setup + update runbook.

**Server-side artifacts (created at first deploy, not in the repo):**
- `/opt/cloak/` — git clone target.
- `/opt/cloak/.env` — generated secrets (mode 0600, root-owned).
- `/opt/cloak/backups/` — empty dir for nightly pg_dump output.
- Append cloak block to `/etc/caddy/Caddyfile`.
- `/etc/cron.d/cloak-pgbackup` — nightly backup cron.
- `/root/.ssh/cloak_deploy_ed25519` — deploy SSH key for git clone (private repo).
- Same key's `.pub` added to GitHub repo as a read-only deploy key.

---

## Task 1: Tune `entrypoint.sh` for env-controlled worker / thread counts

**Files:**
- Modify: `entrypoint.sh:16` (the final `exec gunicorn` line)

- [ ] **Step 1: Replace the gunicorn invocation**

Current line 16:

```sh
exec gunicorn cloak.wsgi:application --bind 0.0.0.0:8000 --workers 3 --access-logfile -
```

Replace with:

```sh
exec gunicorn cloak.wsgi:application \
  --bind 0.0.0.0:8000 \
  --workers "${GUNICORN_WORKERS:-3}" \
  --threads "${GUNICORN_THREADS:-1}" \
  --access-logfile -
```

Defaults preserve dev behavior (3 workers, 1 thread). Prod env will set `GUNICORN_WORKERS=1` and `GUNICORN_THREADS=4` to fit the 512 MB memory budget.

- [ ] **Step 2: Sanity-check existing tests still pass**

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/pytest 2>&1 | tail -3 && npm test 2>&1 | tail -5`
Expected: all green (this change doesn't affect Python or JS tests; it's a shell-script tweak).

- [ ] **Step 3: Commit**

```bash
git add entrypoint.sh
git commit -m "$(cat <<'EOF'
chore(entrypoint): make gunicorn worker/thread counts env-tunable

Dev keeps the existing 3 workers / 1 thread default. Prod will
set GUNICORN_WORKERS=1 / GUNICORN_THREADS=4 via the prod env file
to fit the 512MB droplet's memory budget.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Create `docker-compose.prod.yml`

**Files:**
- Create: `docker-compose.prod.yml`

- [ ] **Step 1: Create the file**

Create `docker-compose.prod.yml`:

```yaml
services:
  web:
    build: .
    env_file: .env
    ports:
      - "127.0.0.1:9091:8000"
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - staticfiles_data:/app/staticfiles
    restart: unless-stopped
  db:
    image: postgres:16-alpine
    env_file: .env
    command: >
      postgres
      -c shared_buffers=32MB
      -c max_connections=10
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $$POSTGRES_USER"]
      interval: 5s
      timeout: 3s
      retries: 10
    restart: unless-stopped

volumes:
  pgdata:
  staticfiles_data:
```

Differences from the existing `docker-compose.yml`:
- Port: `127.0.0.1:9091:8000` instead of `127.0.0.1:8000:8000` (avoid colliding with dev, match Caddy upstream).
- Postgres: `postgres:16-alpine` (smaller image) + tuned `shared_buffers` / `max_connections`.
- Adds `staticfiles_data` volume so collectstatic survives container rebuilds.
- `restart: unless-stopped` on both services (already in dev compose — keep for prod).

- [ ] **Step 2: Locally lint the compose file**

Run: `cd /Users/hriday/code/enc_algo && docker compose -f docker-compose.prod.yml config > /dev/null && echo OK`
Expected: `OK`. (If it errors, fix the YAML before committing.)

- [ ] **Step 3: Commit**

```bash
git add docker-compose.prod.yml
git commit -m "$(cat <<'EOF'
feat(deploy): docker-compose.prod.yml for cloak.moosha.org

Mirror of the dev compose with prod-tuned settings:
- port 127.0.0.1:9091:8000 (Caddy upstream; doesn't collide with dev's 8000)
- postgres:16-alpine with shared_buffers=32MB, max_connections=10
- staticfiles_data volume so collectstatic persists across rebuilds
- restart: unless-stopped

Same env_file pattern (.env) as dev.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Create `deploy.sh`

**Files:**
- Create: `deploy.sh` (executable, top-level)

- [ ] **Step 1: Create the script**

Create `deploy.sh`:

```sh
#!/bin/sh
# Update-time deploy. First-time setup is documented in docs/deploy.md.
# Pushes nothing — assumes you've already `git push origin main`.
set -e

HOST="${CLOAK_DEPLOY_HOST:-root@cloak.moosha.org}"

echo "→ Deploying to $HOST"
ssh "$HOST" /bin/sh <<'REMOTE'
  set -e
  cd /opt/cloak
  echo "→ git pull"
  git pull origin main
  echo "→ docker compose up -d --build"
  docker compose -f docker-compose.prod.yml up -d --build
  echo "→ web container logs (last 30 lines):"
  docker compose -f docker-compose.prod.yml logs --tail=30 web
REMOTE
echo "✓ Done. Verify: curl -I https://cloak.moosha.org/"
```

- [ ] **Step 2: Make it executable**

Run: `cd /Users/hriday/code/enc_algo && chmod +x deploy.sh && ls -la deploy.sh`
Expected: `-rwxr-xr-x ... deploy.sh` (mode includes execute).

- [ ] **Step 3: Shellcheck (if installed locally — otherwise skip)**

Run: `cd /Users/hriday/code/enc_algo && command -v shellcheck >/dev/null && shellcheck deploy.sh || echo "(shellcheck not installed; skipping)"`
Expected: clean output, or the skip message.

- [ ] **Step 4: Commit**

```bash
git add deploy.sh
git commit -m "$(cat <<'EOF'
feat(deploy): deploy.sh — git pull + docker compose up on the server

Manual update-time deploy. Assumes you've already pushed to
origin/main. SSH'es to root@cloak.moosha.org by default; override
with CLOAK_DEPLOY_HOST env var.

Tails the last 30 lines of web container logs after restart so
boot output (migrate, loaddata, collectstatic, gunicorn) is
visible locally.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Create `docs/deploy.md` runbook

**Files:**
- Create: `docs/deploy.md`

- [ ] **Step 1: Create the runbook**

Create `docs/deploy.md`:

````markdown
# Deploy Runbook — cloak.moosha.org

## Server inventory
- DigitalOcean droplet (1 vCPU, 512 MB RAM, 10 GB disk)
- Ubuntu, Caddy 2 already serving sibling sites, Docker 29 installed
- Deploy directory: `/opt/cloak/`
- Internal port: 9091 (Caddy → docker)

## First-time setup (one-off, SSH manually)

Run these on the server as root.

### 1. Generate a deploy SSH key for git clone (private repo)

```sh
ssh-keygen -t ed25519 -f /root/.ssh/cloak_deploy_ed25519 -N "" -C "cloak-deploy@$(hostname)"
cat /root/.ssh/cloak_deploy_ed25519.pub
```

Copy the `.pub` output. On GitHub: repo Settings → Deploy keys → Add deploy key. Title: "cloak.moosha.org". Paste. Leave write access **off**.

### 2. Configure git to use the deploy key

Add to `/root/.ssh/config`:

```
Host github-cloak
  HostName github.com
  User git
  IdentityFile /root/.ssh/cloak_deploy_ed25519
  IdentitiesOnly yes
```

### 3. Clone the repo

```sh
git clone git@github-cloak:hriday/cloak.git /opt/cloak
cd /opt/cloak
mkdir -p backups
```

### 4. Write `.env`

```sh
cat > /opt/cloak/.env <<EOF
DJANGO_SECRET_KEY=$(openssl rand -hex 32)
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=cloak.moosha.org
GUNICORN_WORKERS=1
GUNICORN_THREADS=4
POSTGRES_USER=cloak
POSTGRES_PASSWORD=$(openssl rand -hex 16)
POSTGRES_DB=cloak
EOF

# Build the DATABASE_URL from the values just generated
PGPASS=$(grep '^POSTGRES_PASSWORD=' /opt/cloak/.env | cut -d= -f2)
echo "DATABASE_URL=postgres://cloak:${PGPASS}@db:5432/cloak" >> /opt/cloak/.env

chmod 600 /opt/cloak/.env
```

### 5. Bring up the containers

```sh
cd /opt/cloak
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml ps
```

Wait until both services show `Up (healthy)` (a few seconds).

Verify locally:

```sh
curl -I http://localhost:9091/
```

Expect `HTTP/1.1 200 OK`.

### 6. Add the Caddy block

Append to `/etc/caddy/Caddyfile`:

```
cloak.moosha.org {
    reverse_proxy localhost:9091
    encode gzip zstd
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy strict-origin-when-cross-origin
        -Server
    }
    @static path /static/*
    header @static Cache-Control "public, max-age=604800, immutable"
}
```

Reload Caddy:

```sh
systemctl reload caddy
```

Verify externally:

```sh
curl -I https://cloak.moosha.org/
```

Expect `HTTP/2 200`. If you get a TLS handshake error, give Caddy ~30s to provision the LE cert and retry.

### 7. Install the nightly backup cron

Write `/etc/cron.d/cloak-pgbackup`:

```
0 3 * * * root cd /opt/cloak && docker compose -f docker-compose.prod.yml exec -T db pg_dump -U cloak cloak | gzip > /opt/cloak/backups/$(date +\%F).sql.gz && find /opt/cloak/backups -name "*.sql.gz" -mtime +7 -delete
```

Don't forget the file needs to be `0644` and end in a newline. Cron picks it up automatically.

### 8. Promote yourself to superuser

After signing up at https://cloak.moosha.org/accounts/signup/ as `hriday@hriday.org`:

```sh
cd /opt/cloak
docker compose -f docker-compose.prod.yml exec web python manage.py shell -c \
  "from django.contrib.auth import get_user_model; U=get_user_model(); \
   u=U.objects.get(email='hriday@hriday.org'); u.is_staff=True; u.is_superuser=True; u.save(); \
   print('OK:', u.email, 'staff=', u.is_staff, 'super=', u.is_superuser)"
```

Visit https://cloak.moosha.org/admin/ and confirm.

## Update deploy (every push to main)

From your local machine:

```sh
git push origin main
./deploy.sh
```

`deploy.sh` SSHes to the server, pulls main, rebuilds + restarts containers, tails the last 30 web log lines.

## Recovery

### Container won't start

```sh
ssh root@cloak.moosha.org
cd /opt/cloak
docker compose -f docker-compose.prod.yml logs --tail=100 web
```

Common causes: bad migration, missing env var, fixture PK conflict.

### Database restore from backup

```sh
ssh root@cloak.moosha.org
cd /opt/cloak
ls backups/   # find the date you want
gunzip < backups/YYYY-MM-DD.sql.gz | docker compose -f docker-compose.prod.yml exec -T db psql -U cloak cloak
```

### Caddy cert renewal failing

```sh
ssh root@cloak.moosha.org
systemctl restart caddy
journalctl -u caddy --since "1 hour ago" | tail -50
```
````

- [ ] **Step 2: Commit**

```bash
git add docs/deploy.md
git commit -m "$(cat <<'EOF'
docs: deploy runbook for cloak.moosha.org

First-time setup (SSH key for private repo clone, .env generation,
docker compose up, Caddyfile block, backup cron, superuser
promotion) plus update-time deploy via ./deploy.sh.

Includes recovery steps for container failure, DB restore from
nightly pg_dump backup, and Caddy cert renewal.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Local pre-flight + push

**Files:** None changed; this is a verification + push task.

- [ ] **Step 1: Build the prod image locally to catch any Dockerfile regression**

Run: `cd /Users/hriday/code/enc_algo && docker compose -f docker-compose.prod.yml build 2>&1 | tail -10`
Expected: builds successfully, ends with something like `=> => naming to enc_algo-web ...`.

If it fails, fix the Dockerfile / requirements.txt issue before proceeding.

- [ ] **Step 2: Run all tests one more time**

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/pytest 2>&1 | tail -3`
Expected: all green.

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -5`
Expected: all green.

- [ ] **Step 3: Push to origin/main**

Run: `cd /Users/hriday/code/enc_algo && git push origin main`
Expected: push succeeds. (Many commits ahead of origin from this session — expected; this pushes all of them.)

---

## Task 6: Server — set up GitHub deploy key

**Files:** None in repo; this is server-side. Requires manual user step to add the key to GitHub.

- [ ] **Step 1: Generate the key on the server**

```sh
ssh root@cloak.moosha.org
ssh-keygen -t ed25519 -f /root/.ssh/cloak_deploy_ed25519 -N "" -C "cloak-deploy@$(hostname)"
cat /root/.ssh/cloak_deploy_ed25519.pub
```

Copy the public key output (one long `ssh-ed25519 AAAA... cloak-deploy@...` line).

- [ ] **Step 2: Add the key to GitHub as a deploy key (manual user action)**

User action: on GitHub, navigate to the `cloak` repo → Settings → Deploy keys → Add deploy key.
- Title: `cloak.moosha.org`
- Key: paste the contents from Step 1
- Write access: leave **unchecked** (we only need to pull)
- Click "Add key"

- [ ] **Step 3: Configure git's SSH for the new key**

Back on the server, append to `/root/.ssh/config` (create the file if it doesn't exist):

```
Host github-cloak
  HostName github.com
  User git
  IdentityFile /root/.ssh/cloak_deploy_ed25519
  IdentitiesOnly yes
```

`chmod 600 /root/.ssh/config` if you just created it.

- [ ] **Step 4: Verify connectivity**

```sh
ssh -T git@github-cloak
```

Expect: `Hi hriday/cloak! You've successfully authenticated, but GitHub does not provide shell access.`

If you instead see a permission-denied error, GitHub hasn't accepted the key yet — re-check Step 2.

---

## Task 7: Server — clone + .env

**Files:** None in repo; server-side only.

- [ ] **Step 1: Clone the repo**

```sh
ssh root@cloak.moosha.org
rmdir /opt/cloak 2>/dev/null || true  # remove if empty
git clone git@github-cloak:hriday/cloak.git /opt/cloak
cd /opt/cloak
mkdir -p backups
```

- [ ] **Step 2: Generate `.env`**

```sh
cd /opt/cloak
PGPASS=$(openssl rand -hex 16)
cat > .env <<EOF
DJANGO_SECRET_KEY=$(openssl rand -hex 32)
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=cloak.moosha.org
GUNICORN_WORKERS=1
GUNICORN_THREADS=4
POSTGRES_USER=cloak
POSTGRES_PASSWORD=${PGPASS}
POSTGRES_DB=cloak
DATABASE_URL=postgres://cloak:${PGPASS}@db:5432/cloak
EOF
chmod 600 .env
ls -la .env
```

Expected: file exists, mode `-rw-------`, owned by root.

- [ ] **Step 3: Verify the .env values look reasonable**

```sh
cd /opt/cloak
grep -v PASSWORD .env  # omit the secret from screen
```

Expect a sensible set of keys, no obvious typos. Don't worry about the values; passwords are correct by construction.

---

## Task 8: Server — bring up containers + verify

**Files:** None in repo; server-side only.

- [ ] **Step 1: Build + start containers**

```sh
ssh root@cloak.moosha.org
cd /opt/cloak
docker compose -f docker-compose.prod.yml up -d --build
```

First build takes ~2–5 minutes (downloads python:3.12-slim, postgres:16-alpine, installs Python deps).

- [ ] **Step 2: Wait for healthy + check logs**

```sh
sleep 15
docker compose -f docker-compose.prod.yml ps
```

Expect both `cloak-web-1` and `cloak-db-1` showing `Up (healthy)` (or `Up X seconds (healthy)`).

If web is `Restarting`, get the logs:

```sh
docker compose -f docker-compose.prod.yml logs --tail=50 web
```

Common boot failures: missing env var (check `.env`), bad migration, fixture PK conflict (re-run locally first to confirm).

- [ ] **Step 3: Verify locally on the box**

```sh
curl -I http://localhost:9091/
```

Expect `HTTP/1.1 200 OK`.

If 502, the web container isn't ready — wait another 10s and retry.

---

## Task 9: Server — Caddy block + reload

**Files:** Modifies `/etc/caddy/Caddyfile` on the server.

- [ ] **Step 1: Append the cloak block**

```sh
ssh root@cloak.moosha.org
cat >> /etc/caddy/Caddyfile <<'EOF'

cloak.moosha.org {
    reverse_proxy localhost:9091
    encode gzip zstd
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy strict-origin-when-cross-origin
        -Server
    }
    @static path /static/*
    header @static Cache-Control "public, max-age=604800, immutable"
}
EOF
```

(Note the blank line before `cloak.moosha.org` so it visually separates from the previous block.)

- [ ] **Step 2: Validate Caddyfile syntax**

```sh
caddy validate --config /etc/caddy/Caddyfile
```

Expect: `Valid configuration`.

If there's a syntax error (e.g., unmatched brace), edit `/etc/caddy/Caddyfile` and try again. **Don't reload Caddy with an invalid config** — it would take down the existing sites.

- [ ] **Step 3: Reload Caddy**

```sh
systemctl reload caddy
journalctl -u caddy --since "1 minute ago" | tail -20
```

Look for an entry about provisioning a TLS cert for `cloak.moosha.org`. First reload may take 10–30s while Caddy talks to Let's Encrypt.

- [ ] **Step 4: Verify externally**

From your local machine (not the server):

```sh
curl -I https://cloak.moosha.org/
```

Expect: `HTTP/2 200`, `strict-transport-security: ...`, no `server: Caddy` header.

If you get a TLS handshake error, wait 30s and retry — Caddy may still be provisioning the cert.

---

## Task 10: Server — backup cron

**Files:** Creates `/etc/cron.d/cloak-pgbackup` on the server.

- [ ] **Step 1: Write the cron file**

```sh
ssh root@cloak.moosha.org
cat > /etc/cron.d/cloak-pgbackup <<'EOF'
0 3 * * * root cd /opt/cloak && docker compose -f docker-compose.prod.yml exec -T db pg_dump -U cloak cloak | gzip > /opt/cloak/backups/$(date +\%F).sql.gz && find /opt/cloak/backups -name "*.sql.gz" -mtime +7 -delete
EOF
chmod 644 /etc/cron.d/cloak-pgbackup
```

(Cron requires the file mode be exactly `644` and end in a newline. The heredoc gives the trailing newline.)

- [ ] **Step 2: Force a one-off run to verify the command works**

```sh
cd /opt/cloak && docker compose -f docker-compose.prod.yml exec -T db pg_dump -U cloak cloak | gzip > /opt/cloak/backups/manual-$(date +%F-%H%M).sql.gz
ls -la /opt/cloak/backups/
gunzip -t /opt/cloak/backups/manual-*.sql.gz && echo "backup integrity OK"
```

Expect: a `.sql.gz` file > 1 KB, integrity OK.

If the command errors, the cron will too — fix it before relying on the cron (most common cause: postgres user/db name mismatch with the .env).

---

## Task 11: Server — sign up + promote admin

**Files:** None on disk; database state change.

- [ ] **Step 1: Sign up via the web UI**

On the user's local machine: open `https://cloak.moosha.org/accounts/signup/`, sign up as `hriday@hriday.org` with a password the user chooses.

- [ ] **Step 2: Promote on the server**

```sh
ssh root@cloak.moosha.org
cd /opt/cloak
docker compose -f docker-compose.prod.yml exec web python manage.py shell -c \
  "from django.contrib.auth import get_user_model; U=get_user_model(); \
   u=U.objects.get(email='hriday@hriday.org'); u.is_staff=True; u.is_superuser=True; u.save(); \
   print('OK:', u.email, 'staff=', u.is_staff, 'super=', u.is_superuser)"
```

Expect: `OK: hriday@hriday.org staff= True super= True`.

If `DoesNotExist`, the signup didn't land — re-check Step 1.

- [ ] **Step 3: Verify admin access**

User action: visit `https://cloak.moosha.org/admin/`, log in as `hriday@hriday.org`. Confirm the sidebar shows Algorithms, Lessons, Steps, User progress (the custom admin from earlier).

---

## Task 12: End-to-end smoke

**Files:** None. Final verification.

- [ ] **Step 1: Browse the live site**

User action: open `https://cloak.moosha.org/` and:
1. Confirm landing page shows logo + 2 algorithm cards (RSA, Hybrid Encryption).
2. Click RSA → confirm the lesson loads.
3. Walk one step (e.g., pick p=3, q=5) → confirm "Check" works → state persists on reload.
4. Visit `/admin/` → confirm User progress shows the row for the user who just walked the lesson.

- [ ] **Step 2: Verify HSTS + security headers**

From local:

```sh
curl -sI https://cloak.moosha.org/ | grep -iE "strict-transport|x-content-type|x-frame|referrer-policy|server"
```

Expect: `strict-transport-security` present, `x-content-type-options: nosniff`, `x-frame-options: DENY`, `referrer-policy: strict-origin-when-cross-origin`, **no** `server: caddy` header (it should be stripped).

- [ ] **Step 3: Tomorrow morning — verify the cron fired**

```sh
ssh root@cloak.moosha.org "ls -la /opt/cloak/backups/" 
```

Expect: a file with today's date (e.g., `2026-05-24.sql.gz`) created around 03:00 server time.

If missing, check `journalctl -u cron --since "yesterday"` for errors.

---

## Verification before declaring done

- [ ] All 5 of Phase 1 commits pushed to `origin/main`.
- [ ] `https://cloak.moosha.org/` returns 200 with TLS cert from Let's Encrypt.
- [ ] Both `cloak-web-1` and `cloak-db-1` containers show `Up (healthy)`.
- [ ] `hriday@hriday.org` can log into `https://cloak.moosha.org/admin/`.
- [ ] A manual backup file exists in `/opt/cloak/backups/` and `gunzip -t` validates clean.
- [ ] `./deploy.sh` from local pulls + rebuilds successfully (you can re-run it as a no-op check).
- [ ] Browser smoke walks RSA lesson step 1 end-to-end with state persistence.
