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
