# cloak

Teaching site for encryption algorithms. RSA first; more coming. Live at https://cloak.moosha.org.

## Local development

    python3.12 -m venv .venv
    .venv/bin/pip install -r requirements.txt

    cp .env.example .env
    # edit .env if needed

    .venv/bin/python manage.py migrate
    .venv/bin/python manage.py loaddata algorithms/rsa/fixtures.json
    .venv/bin/python manage.py runserver

Visit http://localhost:8000/.

## Tests

    .venv/bin/pytest             # Python tests
    node --test static/algorithms/*/tests/*.test.js   # JS tests

JS-Python parity is enforced in `tests/test_parity.py`.

## Deploy (host with Caddy in front)

The artifact is `docker-compose.yml` + the `web` image (built from `Dockerfile`).

1. On the server, clone the repo and write `.env` (set `DJANGO_DEBUG=False`, real `DJANGO_SECRET_KEY`, real Postgres credentials).
2. `make up` → web container binds `127.0.0.1:8000`; Postgres lives in a sibling container.
3. Add a stanza to the host's Caddyfile:

       cloak.moosha.org {
           reverse_proxy 127.0.0.1:8000
       }

4. Reload Caddy.

The web container handles `migrate`, `loaddata algorithms/*/fixtures.json`, `collectstatic`, then runs gunicorn — see `entrypoint.sh`.

## Adding a new algorithm

The framework is data-driven. To add `foo`:

1. Create `algorithms/foo/{logic.py, validators.py, codegen.py, fixtures.json}`.
2. Create `static/algorithms/foo/{math.js, validators.js, codegen.js}` plus tests.
3. The validator + codegen keys named in `fixtures.json` must exist in both Python and JS modules.
4. `make loadalgos` (or rebuild the image).

No core code changes needed.

## Spec & plan

- Spec: [docs/superpowers/specs/2026-05-21-cloak-rsa-design.md](docs/superpowers/specs/2026-05-21-cloak-rsa-design.md)
- Plan: [docs/superpowers/plans/2026-05-21-cloak-rsa-mvp.md](docs/superpowers/plans/2026-05-21-cloak-rsa-mvp.md)
