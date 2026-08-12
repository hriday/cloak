# cloak

Teaching site for cryptography — 34 algorithm lessons from RSA to Argon2id,
grouped into guided journeys. Live at https://cloak.moosha.org. Catalog and
open ideas: [docs/roadmap.md](docs/roadmap.md).

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

1. Create `algorithms/foo/fixtures.json` (Algorithm + Lesson + Step rows;
   PK convention: algorithm/lesson PK = catalog order, step PK = lesson PK × 10 + step order).
2. Create `static/algorithms/foo/{validators.js, codegen.js}` plus tests in
   `static/algorithms/foo/tests/` — the validator keys named in the fixture
   must be exported by `validators.js`, and `codegen.js` must export
   `full_script(state)`. (The original RSA lesson also has Python mirrors in
   `algorithms/rsa/`; newer lessons are JS-only.)
3. Interactive steps with custom UI additionally need: a template branch in
   `core/templates/core/lesson.html` and slug registrations in
   `static/core/wizard.js` (`hasCustomInputBranch` SLUGS, `MULTI_INPUT_SLUGS`
   if the validator takes an object, `EXPLORATORY_SLUGS` if the branch renders
   its own Continue button).
4. `make loadalgos` (or rebuild the image — the entrypoint reloads all
   fixtures on every container start).

Plain info-step lessons need no core code changes.

## Spec & plan

- Spec: [docs/superpowers/specs/2026-05-21-cloak-rsa-design.md](docs/superpowers/specs/2026-05-21-cloak-rsa-design.md)
- Plan: [docs/superpowers/plans/2026-05-21-cloak-rsa-mvp.md](docs/superpowers/plans/2026-05-21-cloak-rsa-mvp.md)
