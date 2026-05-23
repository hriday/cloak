# Production Deploy — Design

**Date:** 2026-05-23
**Project:** `cloak`
**Target:** `cloak.moosha.org` (143.110.208.106), deploy directory `/opt/cloak/`

## Goal

Stand up the cloak teaching site at `https://cloak.moosha.org/` on the existing DigitalOcean droplet. Mirror the deployment pattern already in use for the sibling `thirdumpire` app on the same box: Caddy as TLS-terminating reverse proxy, Docker for the app + database, manual `./deploy.sh` for updates. Use Postgres (not SQLite) per project preference.

## Server inventory (already in place)

- Ubuntu droplet, 1 vCPU, **512 MB RAM**, 10 GB disk.
- Caddy running on ports 80/443 with auto-LE, currently serving `cyber.moosha.org`, `stablecoin.moosha.org`, `thirdumpire.app`.
- Docker 29.1.3 installed.
- `/opt/cloak/` exists but is empty.
- DNS `cloak.moosha.org` already resolves to the server IP.
- SSH access as `root` works.

## Non-goals

- CI/CD via GitHub Actions (manual `./deploy.sh` is enough for v1).
- Staging environment (push directly to prod).
- Off-server backups (nightly pg_dump writes to the same disk; off-site backup is a future cron).
- Monitoring / alerting beyond root's local mail.
- Auto-rollback.
- Bare-metal install (Docker matches the rest of the box).
- SQLite (Postgres is the chosen DB even though it's heavier).

## Architecture

| Layer | Choice | Notes |
|---|---|---|
| TLS + reverse proxy | **Caddy** (already running) | New Caddyfile block for `cloak.moosha.org`. Auto-LE cert. |
| Container runtime | **Docker** (already installed) | Two containers: `web` (Django + gunicorn) and `db` (Postgres 16-alpine). |
| WSGI server | **Gunicorn** inside `web` | `--workers 1 --threads 4` to fit memory budget. |
| Database | **Postgres 16-alpine** in a container | Volume-mounted `pgdata`. Internal docker network only. Tuned for low memory (`shared_buffers=32MB`, `max_connections=10`). |
| Static files | **WhiteNoise** middleware | Serves `/static/` from inside Django with hashed filenames + gzipped variants. Avoids a Caddy static-path config. |
| Internal port | **9091** (free; 8080/9090/3456 are taken) | `web` bound to `127.0.0.1:9091`; `db` not exposed. |

### Memory budget (tight but workable)

| Process | RSS estimate |
|---|---|
| caddy | ~20 MB |
| docker daemon + containerd | ~130 MB |
| thirdumpire (existing) | ~100 MB |
| cloak web (gunicorn 1 worker + Django) | ~150 MB |
| cloak postgres (tuned) | ~80 MB |
| system + sshd | ~80 MB |
| **Total** | **~560 MB** (vs 512 MB ceiling) |

Linux will swap moderately. Acceptable for a low-traffic teaching site. Upgrade to 1 GB droplet ($12/mo) if real load justifies it.

## Components

### Repo additions

**`docker-compose.prod.yml`** (~30 lines):
- `web` service: `build: .`, `env_file: .env`, `ports: ["127.0.0.1:9091:8000"]`, `restart: unless-stopped`, `depends_on: { db: { condition: service_healthy } }`, uses `entrypoint.prod.sh`, mounts `staticfiles_data:/app/staticfiles`.
- `db` service: `image: postgres:16-alpine`, `env_file: .env`, `command: postgres -c shared_buffers=32MB -c max_connections=10`, `volumes: [pgdata:/var/lib/postgresql/data]`, healthcheck identical to dev, `restart: unless-stopped`. No host port mapping.
- Named volumes: `pgdata`, `staticfiles_data`.

**`entrypoint.prod.sh`** (~15 lines, executable):

```sh
#!/bin/sh
set -e
until pg_isready -h db -U "$POSTGRES_USER" >/dev/null 2>&1; do sleep 1; done
python manage.py migrate --noinput
for f in algorithms/*/fixtures.json; do python manage.py loaddata "$f"; done
python manage.py collectstatic --noinput
exec gunicorn cloak.wsgi:application --workers 1 --threads 4 --bind 0.0.0.0:8000 --access-logfile -
```

**`requirements.txt` additions** (verify each; add if missing):
- `gunicorn>=22`
- `whitenoise>=6`
- `psycopg[binary]>=3` (already present per existing Postgres setup)

**`cloak/settings.py` changes**:
- Add `"whitenoise.middleware.WhiteNoiseMiddleware"` immediately after `"django.middleware.security.SecurityMiddleware"`.
- Set `STATIC_ROOT = BASE_DIR / "staticfiles"`.
- Set `STORAGES = {"staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"}}`.
- Add `SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")`.
- Ensure `CSRF_TRUSTED_ORIGINS` includes `https://cloak.moosha.org` (read from env or hardcoded).

**`docs/deploy.md`** — runbook with two sections:
1. First-time setup (SSH commands).
2. Update deploy (`./deploy.sh` summary + manual recovery steps).

**`deploy.sh`** (~20 lines, top-level, executable):

```sh
#!/bin/sh
set -e
ssh root@cloak.moosha.org <<'REMOTE'
  set -e
  cd /opt/cloak
  git pull origin main
  docker compose -f docker-compose.prod.yml up -d --build
  echo "--- web logs ---"
  docker compose -f docker-compose.prod.yml logs --tail=30 web
REMOTE
```

### Server-side artifacts (one-time setup)

**`/etc/caddy/Caddyfile`** — append:

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

Reload caddy after appending: `systemctl reload caddy`.

**`/opt/cloak/.env`** (mode 0600, root-owned):

```
DJANGO_SECRET_KEY=<openssl rand -hex 32>
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=cloak.moosha.org
DATABASE_URL=postgres://cloak:<generated>@db:5432/cloak
POSTGRES_USER=cloak
POSTGRES_PASSWORD=<same as above>
POSTGRES_DB=cloak
```

**`/etc/cron.d/cloak-pgbackup`** — nightly backup:

```
0 3 * * * root cd /opt/cloak && docker compose -f docker-compose.prod.yml exec -T db pg_dump -U cloak cloak | gzip > /opt/cloak/backups/$(date +\%F).sql.gz && find /opt/cloak/backups -name "*.sql.gz" -mtime +7 -delete
```

Runs at 03:00. Keeps 7 days. Errors go to root's mail.

## Lifecycle / data flow

### First-time provisioning

```
1. SSH root@cloak.moosha.org
2. mkdir -p /opt/cloak/{backups}; git clone https://github.com/hriday/cloak.git /opt/cloak
3. Generate secrets and write /opt/cloak/.env (mode 0600)
4. docker compose -f docker-compose.prod.yml up -d --build
   → entrypoint runs migrate, loaddata, collectstatic; gunicorn starts
5. Append cloak block to /etc/caddy/Caddyfile
6. systemctl reload caddy → Caddy provisions LE cert
7. curl -I https://cloak.moosha.org/ — expect 200
8. Install /etc/cron.d/cloak-pgbackup
```

### Steady-state deploy

```
local:    git push origin main
local:    ./deploy.sh
              ↓ ssh
remote:   cd /opt/cloak; git pull origin main
remote:   docker compose -f docker-compose.prod.yml up -d --build
              ↓ web container restarts; entrypoint.prod.sh runs
              ├── pg_isready loop
              ├── migrate (idempotent)
              ├── loaddata for each algorithms/*/fixtures.json (idempotent — replaces by PK)
              ├── collectstatic --noinput
              └── exec gunicorn
remote:   docker compose logs --tail=30 web  (visible from local)
```

### Request flow

```
browser → https://cloak.moosha.org/...
       ↓ TLS at Caddy; security headers added; gzip/zstd encoding
Caddy  → http://localhost:9091/... (HTTP_X_FORWARDED_PROTO: https)
       ↓ docker
gunicorn → Django (WhiteNoise middleware first)
       ↓ if /static/* → WhiteNoise serves with hashed filenames + long cache
       ↓ else → Django views/templates → Postgres reads/writes
       ↓
response → Caddy → browser
```

### Backup flow

```
03:00 → cron → docker compose exec -T db pg_dump → gzip → /opt/cloak/backups/YYYY-MM-DD.sql.gz
                                                        → find -mtime +7 -delete
```

## Error handling / failure modes

| Failure | What happens | Recovery |
|---|---|---|
| Bad code pushed to main | `docker compose up -d --build` brings up broken container; healthcheck fails | `git revert` + redeploy. |
| Migration error | Container exits before gunicorn starts; web is briefly down | Logs visible from `./deploy.sh` tail; manual fix + redeploy. |
| `loaddata` PK conflict | Same as migration error: entrypoint exits non-zero | Fix fixture in dev (caught by tests); redeploy. |
| Postgres data corruption | Restore from latest nightly: `gunzip < backup.sql.gz \| docker compose exec -T db psql -U cloak cloak` | Documented in deploy.md. |
| Disk full | New images can't pull; backups fail | `docker system prune -a`; consider larger droplet. |
| 512 MB OOM | OOM-killer picks largest process (probably gunicorn worker); container restarts | Mitigations: 1 worker, tuned Postgres. Upgrade droplet if recurrent. |
| Caddy cert renewal failure | Existing cert valid up to 30 days after expiry | Caddy auto-retries hourly; manual `systemctl restart caddy` if needed. |
| Container won't start after deploy | gunicorn never listens | Tail logs: `docker compose -f docker-compose.prod.yml logs web`. |

## Security hardening (v1)

- `.env` mode 0600, root-owned.
- `DJANGO_DEBUG=False`.
- `DJANGO_ALLOWED_HOSTS=cloak.moosha.org`.
- `SECURE_PROXY_SSL_HEADER` set so Django knows it's behind TLS.
- Caddy adds `X-Content-Type-Options nosniff`, `X-Frame-Options DENY`, `Referrer-Policy strict-origin-when-cross-origin`; strips `Server`.
- `db` container not host-exposed.
- `web` container bound to `127.0.0.1:9091` only.
- Postgres password generated via `openssl rand -hex 16`.
- `CompressedManifestStaticFilesStorage` — hashed filenames make cache poisoning of old assets impossible.
- `CSRF_TRUSTED_ORIGINS = ["https://cloak.moosha.org"]`.

Future hardening (out of scope for v1):
- `unattended-upgrades` for OS security patches.
- `fail2ban` for SSH.
- HSTS preload.
- Content-Security-Policy header.

## Verification checklist

### Pre-deploy (local)

- `.venv/bin/pytest` green
- `npm test` green
- `docker compose -f docker-compose.prod.yml build` succeeds locally

### First-time setup

- `docker compose -f docker-compose.prod.yml ps` shows both services `Up (healthy)`
- `curl -I http://localhost:9091/` from the server returns `200`
- `curl -I https://cloak.moosha.org/` returns `200` with no `Server: Caddy` header; `strict-transport-security` set
- Browser smoke: load landing → open RSA lesson → complete one step → refresh → state persists

### Steady-state deploy

- `./deploy.sh` exits zero
- Tail shows `Listening at: http://0.0.0.0:8000` (gunicorn boot)
- No `[ERROR]` lines from migrate / loaddata / collectstatic
- `curl -I https://cloak.moosha.org/` returns `200`

### Admin verification (post-first-deploy)

- Sign up at `https://cloak.moosha.org/accounts/signup/` as `hriday@hriday.org`
- SSH to server, run:
  ```
  docker compose -f docker-compose.prod.yml exec web python manage.py shell -c \
    "from django.contrib.auth import get_user_model; U=get_user_model(); \
     u=U.objects.get(email='hriday@hriday.org'); u.is_staff=True; u.is_superuser=True; u.save()"
  ```
- Visit `https://cloak.moosha.org/admin/`, log in, see the User Progress list

### Backup verification (next day)

- `ls /opt/cloak/backups/` shows a `.sql.gz` file dated today's date
- `gunzip -t /opt/cloak/backups/<file>.sql.gz` returns clean
