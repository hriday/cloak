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
