# Cloak — RSA Teaching Site (MVP) Design

**Date:** 2026-05-21
**Project:** `cloak`
**Repo:** github.com/hriday/cloak
**Domain:** cloak.moosha.org
**Working directory:** /Users/hriday/code/enc_algo (to be moved/renamed during repo init)

## Goal

A web app that teaches encryption algorithms by walking the learner through the actual computation, compute-along, step by step. RSA ships first. The framework is built so additional algorithms (to be decided after RSA ships) can be added later as data + small per-algorithm modules, with no changes to views, templates, or progress logic.

## Audience and tone

CS students and curious developers. Comfortable with code and math notation. Direct prose, real symbols (φ, ≡), real code. No hand-waving primers on modular arithmetic.

## User experience

### Landing
`/` lists algorithms as cards. RSA is the only live algorithm at MVP. A generic "More algorithms coming soon" card sits alongside it; specific future algorithms are decided after RSA ships. No login required to land or to start RSA.

### Algorithm intro page
`/algorithms/rsa/` — short concept page covering: what RSA solves (key exchange / asymmetric encryption), the cast of characters (p, q, n, φ(n), e, d), and a "Start the lesson" CTA.

### Wizard runner
`/algorithms/rsa/learn/` — one step per screen, with:
- A progress bar showing N steps total
- The step's prompt (markdown, interpolated with prior values from `state`)
- An input area (numeric, multi-numeric, or choose-from-list)
- "Check" button → JS validates → on success, advance; on failure, hint
- An inline collapsed Python snippet showing the line(s) for this step
- A "Show full script so far" button (top right) that opens a modal with the cumulative `.py`, with copy and download buttons
- Back / Forward navigation between completed steps

### Save progress
A guest user 2+ steps in sees a persistent "Save your progress" banner that links to signup. On signup, any `localStorage` progress is imported into their account.

### Dashboard
`/me/progress` (logged-in only) — per-algorithm progress with resume links.

### RSA lesson — the exact step list (MVP)

1. **Intro / pick p and q** (`input-multi`, kind: `input-multi`) — user enters two primes, each ≤ 3 digits. Validates: both prime, p ≠ q.
2. **Compute n = p · q** (`input-numeric`).
3. **Compute φ(n) = (p−1)(q−1)** (`input-numeric`).
4. **Pick e coprime to φ(n)** (`choose-from-list`) — site generates a list of valid candidates (e.g., {3, 5, 7, 11, 13, 17, ...} filtered by `gcd(e, φ) = 1`); user picks one.
5. **Compute d ≡ e⁻¹ (mod φ(n))** (`input-numeric`) — validate `(d · e) % φ == 1`.
6. **Choose a message** (`input-numeric`) — small integer `m < n`.
7. **Encrypt: c = m^e mod n** (`input-numeric`).
8. **Decrypt: m = c^d mod n** (`input-numeric`) — confirm round-trip.
9. **Done** (`info`) — summary, full Python script, "Try another algorithm" CTA.

## Architecture

### Tech stack
- **Backend:** Django (latest LTS) + Django REST framework for the small JSON surface HTMX doesn't cover
- **Frontend:** Django templates + HTMX (partial updates) + Alpine.js (client reactivity) + plain JS modules for BigInt math
- **DB:** Postgres 16
- **Auth:** Django built-in (email + password). Magic link / SSO deferred to v2.
- **Deployment:** Docker Compose, two services (`web`, `db`). The host runs Caddy in front of multiple sites and reverse-proxies `cloak.moosha.org` to the `web` container's bound port. TLS termination, HTTPS, and HSTS live in the host's Caddyfile, not in the artifact. WhiteNoise serves `/static/` from inside `web`.

### Where computation lives
Math runs **client-side** in JS BigInt. The user is the one doing the math; the browser validates. The server stores only progress state, not values it computed itself. Backend has Python implementations of the same logic for:
1. Defensive re-validation when state syncs to the server (rejects tampered state with a soft error).
2. The canonical reference shown in the codegen output — the Python the user sees IS the backend's logic.

### URL surface

```
/                              Landing (algorithm picker)
/algorithms/<slug>/            Algorithm intro
/algorithms/<slug>/learn/      Wizard runner (lesson)
/accounts/login/               Django auth views
/accounts/signup/
/accounts/logout/
/me/progress/                  Dashboard

# JSON (DRF)
POST /api/progress/<lesson_slug>/        Save progress (logged-in only)
GET  /api/progress/<lesson_slug>/        Hydrate progress
POST /api/progress/import/               Import localStorage state on first login
```

### Data model

```
User                                Django default
  id, email (unique), password, ...

Algorithm
  slug             unique     'rsa'
  name                        'RSA'
  family                      'asymmetric' | 'symmetric' | 'pq'
  intro_template              path to a template
  status                      'live' | 'coming-soon'
  order            int        for sort on landing

Lesson
  algorithm        FK         RSA → one lesson for MVP: 'encrypt-decrypt'
  slug
  title
  order            int
  (unique: algorithm + slug)

Step
  lesson           FK
  order            int
  slug
  kind                        'info' | 'input-numeric' | 'input-multi' | 'choose-from-list'
  prompt_template             markdown string, rendered with state via Django template engine
  validator_key               name of fn in algorithm's validators module ('compute_phi', ...)
  codegen_key                 name of fn in algorithm's codegen module
  (unique: lesson + slug; unique: lesson + order)

UserProgress
  user             FK
  lesson           FK
  current_step_order   int
  state                JSONB    {"p": 61, "q": 53, "n": 3233, "phi": 3120, ...}
  completed_at         datetime nullable
  updated_at           datetime
  (unique: user + lesson)
```

### Per-algorithm module layout

```
cloak/
├── algorithms/
│   ├── __init__.py
│   ├── rsa/
│   │   ├── __init__.py
│   │   ├── logic.py            canonical Python (used by tests, mirrored to user as code)
│   │   ├── validators.py       per-step server-side validators (defensive only)
│   │   ├── codegen.py          per-step code-line generators
│   │   └── fixtures.json       Lesson + Step rows for `loaddata`
│   └── (future: des/, blowfish/, kyber/...)
│
└── static/algorithms/
    ├── rsa/
    │   ├── math.js             BigInt math impl (browser truth)
    │   ├── validators.js       per-step validators with hints
    │   └── codegen.js          per-step code-line generators (mirrors codegen.py)
    └── ...
```

### The step contract

A `Step` row references string keys (`validator_key`, `codegen_key`). At runtime the wizard:
1. Server renders the step shell with `prompt_template` + current `state`.
2. Client (Alpine) calls `validators.js[step.validator_key](input, state)` on "Check".
3. Validator returns `{ok: true, value: {key: val, ...}}` on success or `{ok: false, hint: "..."}` on failure.
4. On success: `state = {...state, ...value}`, append `codegen.js[step.codegen_key](state)` to the running `.py` buffer, advance step, POST progress (debounced).
5. Page reload: hydrate `state` and `current_step_order` from server (logged-in) or localStorage (guest).

#### Validator example

```python
# algorithms/rsa/validators.py
def compute_phi(input_str: str, state: dict) -> dict:
    try:
        got = int(input_str)
    except ValueError:
        return {"ok": False, "hint": "Enter a whole number."}
    expected = (state["p"] - 1) * (state["q"] - 1)
    if got != expected:
        return {"ok": False, "hint": f"φ(n) = (p-1)(q-1) with p={state['p']}, q={state['q']}."}
    return {"ok": True, "value": {"phi": got}}
```

```js
// static/algorithms/rsa/validators.js
export const compute_phi = (input, state) => {
  let got;
  try { got = BigInt(input); } catch { return { ok: false, hint: "Enter a whole number." }; }
  const expected = (BigInt(state.p) - 1n) * (BigInt(state.q) - 1n);
  if (got !== expected) {
    return { ok: false, hint: `φ(n) = (p-1)(q-1) with p=${state.p}, q=${state.q}.` };
  }
  return { ok: true, value: { phi: got.toString() } };
};
```

#### Codegen example

```python
# algorithms/rsa/codegen.py
def compute_phi(state):
    return f"phi = (p - 1) * (q - 1)  # phi = {state['phi']}"
```

```js
// static/algorithms/rsa/codegen.js
export const compute_phi = (state) => `phi = (p - 1) * (q - 1)  # phi = ${state.phi}`;
```

The JS and Python codegen output must agree byte-for-byte. A test pinned to a fixed `state` snapshot enforces this.

### Validator kinds and the cases they accept

- `input-numeric`: validators return `{ok, value: {<key>: int|string}}`.
- `input-multi`: input is an object `{p: "61", q: "53"}`. Validator may inspect multiple fields.
- `choose-from-list`: input is the selected option's id (a string). Validator confirms it's in the legal set.
- `info`: no validator. "Continue" advances unconditionally.

For RSA's "Pick e coprime to φ(n)" step, validation is **property-based**: any `e` with `gcd(e, φ) = 1` and `1 < e < φ` is accepted, not a fixed value.

### Guest progress and import

Guest state lives in `localStorage` under keys like `cloak.progress.rsa.encrypt-decrypt`. Shape mirrors `UserProgress`:

```json
{
  "state": { "p": 61, "q": 53, "n": 3233, "phi": 3120 },
  "current_step_order": 4,
  "updated_at": "2026-05-21T15:32:00Z"
}
```

On signup/login, the frontend reads all `cloak.progress.*` keys and POSTs them to `/api/progress/import/`. The backend:
1. Validates each blob by re-running Python validators through the implied step sequence.
2. For each lesson, if no `UserProgress` exists, creates one. If one exists, keeps whichever has the higher `current_step_order`.
3. Returns the canonical set; frontend clears localStorage on success.

### Defensive backend validation

When `POST /api/progress/<lesson_slug>/` arrives, the server runs Python validators in order against `state` to confirm internal consistency (e.g., `phi == (p-1)(q-1)`). On failure, return 400 with a soft error. This guards the DB from corrupted state from hand-edited localStorage; it is not a security mechanism. CSRF and standard Django auth handle access control.

### Tests

- **pytest** for Python: logic, validators (happy path + each hint), codegen (snapshot tests), models, API endpoints (DRF test client).
- **node:test** (or vitest) for JS modules: validators and codegen.
- **Parity test**: a pytest test loads the JS codegen module via `node -e` against a fixed list of `state` snapshots and asserts the JS output matches the Python output byte-for-byte. Same for validators (boolean + hint string).
- **Django integration**: smoke test that loads RSA fixtures and the lesson page renders.

### Deployment

The deploy artifact is a `docker-compose.yml` plus the `web` image (built from the repo's `Dockerfile`). The host machine already runs Caddy in front of several sites; the host's Caddyfile is updated separately by the operator (out of this artifact's scope) with a stanza like:

```caddyfile
cloak.moosha.org {
    reverse_proxy 127.0.0.1:8000
}
```

`docker-compose.yml`:
```yaml
services:
  web:
    build: .
    env_file: .env
    ports: ["127.0.0.1:8000:8000"]   # bound to loopback; Caddy on the host proxies in
    depends_on: [db]
    restart: unless-stopped
  db:
    image: postgres:16
    volumes: [pgdata:/var/lib/postgresql/data]
    env_file: .env
    restart: unless-stopped

volumes:
  pgdata:
```

The web container's port binds to `127.0.0.1` only — never the public interface — since Caddy is the sole ingress.

`Dockerfile`: `python:3.12-slim` → install deps → COPY app → entrypoint runs `migrate`, `loaddata algorithms/*/fixtures.json`, then `gunicorn cloak.wsgi`.

`.env` holds `DJANGO_SECRET_KEY`, `DATABASE_URL`, `DEBUG=False`, `ALLOWED_HOSTS=cloak.moosha.org,localhost`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`.

`SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")` is set in Django so request URLs reflect the Caddy-terminated HTTPS. `CSRF_TRUSTED_ORIGINS = ["https://cloak.moosha.org"]`.

WhiteNoise serves `/static/` in production. TLS, HSTS, and HTTPS redirects are Caddy's job and are not configured inside the artifact.

`Makefile` targets: `up`, `down`, `migrate`, `loadalgos`, `test`, `shell`, `logs`.

## Repository layout

```
cloak/
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── Makefile
├── requirements.txt
├── manage.py
├── cloak/                        # Django project package
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
│   └── asgi.py
├── core/                         # generic lesson runner app
│   ├── models.py                 # Algorithm, Lesson, Step, UserProgress
│   ├── views.py                  # landing, intro, learn (wizard)
│   ├── api.py                    # DRF progress endpoints
│   ├── templates/core/
│   │   ├── base.html
│   │   ├── landing.html
│   │   ├── algorithm_intro.html
│   │   ├── lesson.html           # wizard shell
│   │   └── partials/step.html    # HTMX-swappable step body
│   └── tests/
├── accounts/                     # signup / dashboard
│   ├── views.py
│   ├── templates/accounts/
│   └── tests/
├── algorithms/
│   └── rsa/
│       ├── logic.py
│       ├── validators.py
│       ├── codegen.py
│       └── fixtures.json
├── static/
│   ├── core/
│   │   ├── app.js                # wizard runtime (Alpine bindings, HTMX hooks)
│   │   └── style.css
│   └── algorithms/rsa/
│       ├── math.js
│       ├── validators.js
│       └── codegen.js
└── docs/
    └── superpowers/specs/
        └── 2026-05-21-cloak-rsa-design.md
```

## MVP scope

**In:**
- Multi-algorithm framework (models, step contract, dual JS/Python validators + codegen, fixtures-driven content)
- RSA lesson fully implemented (the 9 steps above)
- Guest mode + localStorage progress
- Email/password signup, guest progress import on signup
- Dashboard with RSA progress + a generic "more algorithms coming soon" card
- Inline per-step Python + "show full script" modal with copy and download
- Docker Compose artifact (web + db) deployed behind host Caddy at cloak.moosha.org
- Test suites (pytest, JS test runner, parity test)

**Out (v2+):**
- Algorithms beyond RSA (specific next algorithms decided after RSA ships; framework supports them)
- Magic link / SSO auth
- Shareable lesson URLs
- Difficulty modes / expanded hint system
- TLS termination inside the artifact (Caddy on host owns this)
- Admin UI beyond Django default

## Open questions / explicit non-decisions

- **e selection list size:** to keep "pick e" usable, the candidate list will be capped at the first ~12 valid `e` values starting from 3. This is a UX detail; can adjust in implementation.
- **Message encoding for step 6:** MVP accepts only a single integer `m < n`. ASCII / string encoding is a v2 enhancement.
- **Primality check for p, q:** trial division is fine for ≤ 3-digit inputs. No Miller-Rabin needed for MVP.
