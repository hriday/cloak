#!/bin/sh
set -e

echo "Running migrations..."
python manage.py migrate --noinput

echo "Loading algorithm fixtures..."
for f in algorithms/*/fixtures.json; do
    [ -f "$f" ] && python manage.py loaddata "$f"
done

echo "Collecting static..."
python manage.py collectstatic --noinput

echo "Starting gunicorn..."
exec gunicorn cloak.wsgi:application \
  --bind 0.0.0.0:8000 \
  --workers "${GUNICORN_WORKERS:-3}" \
  --threads "${GUNICORN_THREADS:-1}" \
  --access-logfile -
