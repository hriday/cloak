# Cloak — RSA Teaching Site (MVP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and deploy `cloak.moosha.org` — a Django site that teaches RSA via a compute-along wizard, generates the equivalent Python code per step, and is structured so additional algorithms can be added later as data + per-algorithm modules.

**Architecture:** Django + Django REST Framework backend, Postgres DB, Django templates + HTMX + Alpine.js frontend, JS BigInt for client-side math. Per-algorithm modules (Python `logic`/`validators`/`codegen` + JS mirrors) drive a generic step-runner. Docker Compose artifact (web + db); host Caddy handles TLS.

**Tech Stack:** Python 3.12, Django 5.x, DRF, Postgres 16, HTMX, Alpine.js, JS BigInt (browser native), WhiteNoise, gunicorn, pytest, pytest-django, node:test (Node 20+), Docker Compose.

**Spec:** [docs/superpowers/specs/2026-05-21-cloak-rsa-design.md](../specs/2026-05-21-cloak-rsa-design.md)

**Working directory:** `/Users/hriday/code/enc_algo` (project files live here; remote will be `github.com/hriday/cloak`). Directory rename to `cloak` is at the operator's discretion and does not affect any code.

---

## File Structure

Files created across the plan, grouped by responsibility:

**Project root:**
- `Dockerfile`, `docker-compose.yml`, `.env.example`, `.gitignore`, `Makefile`, `requirements.txt`, `manage.py`, `README.md`, `pytest.ini`, `package.json` (JS test runner only)

**Django project package (`cloak/`):**
- `cloak/settings.py`, `cloak/urls.py`, `cloak/wsgi.py`, `cloak/asgi.py`, `cloak/__init__.py`

**Core app (`core/`) — generic lesson runner:**
- `core/models.py` (Algorithm, Lesson, Step, UserProgress)
- `core/admin.py`, `core/apps.py`, `core/migrations/`
- `core/views.py` (landing, algorithm intro, lesson wizard, dashboard)
- `core/api.py` (DRF progress endpoints)
- `core/serializers.py`
- `core/urls.py`, `core/api_urls.py`
- `core/algorithm_loader.py` (load per-algorithm Python modules by slug)
- `core/templates/core/base.html`, `landing.html`, `algorithm_intro.html`, `lesson.html`, `partials/step.html`
- `core/tests/test_models.py`, `test_views.py`, `test_api.py`, `test_algorithm_loader.py`, `test_e2e.py`

**Accounts app (`accounts/`):**
- `accounts/views.py` (signup), `accounts/urls.py`, `accounts/forms.py`
- `accounts/templates/registration/login.html`, `signup.html`, `logged_out.html`
- `accounts/tests/test_signup.py`

**RSA algorithm (`algorithms/rsa/`):**
- `algorithms/__init__.py`, `algorithms/rsa/__init__.py`
- `algorithms/rsa/logic.py` (pure math)
- `algorithms/rsa/validators.py` (per-step validators)
- `algorithms/rsa/codegen.py` (per-step code-line generators)
- `algorithms/rsa/fixtures.json` (Algorithm/Lesson/Step rows)
- `algorithms/rsa/tests/test_logic.py`, `test_validators.py`, `test_codegen.py`

**Static (`static/`):**
- `static/core/style.css`, `static/core/wizard.js` (Alpine runtime + dynamic algorithm-module loading)
- `static/algorithms/rsa/math.js`, `validators.js`, `codegen.js`
- `static/algorithms/rsa/tests/math.test.js`, `validators.test.js`, `codegen.test.js`

**Parity tests:**
- `tests/test_parity.py` (asserts JS and Python validators/codegen agree)

---

## Task 1: Repo and project scaffold

**Files:**
- Create: `.gitignore`, `requirements.txt`, `pytest.ini`, `README.md`, `manage.py`, `cloak/__init__.py`, `cloak/settings.py`, `cloak/urls.py`, `cloak/wsgi.py`, `cloak/asgi.py`

- [ ] **Step 1: Initialize git in the working directory**

```bash
cd /Users/hriday/code/enc_algo
git init -b main
git remote add origin git@github.com:hriday/cloak.git
```

- [ ] **Step 2: Write `.gitignore`**

```
# Python
__pycache__/
*.py[cod]
*.egg-info/
.pytest_cache/
.venv/
venv/

# Django
*.sqlite3
staticfiles/
media/

# Node
node_modules/

# Environment
.env
.env.local

# Editor / OS
.DS_Store
.vscode/
.idea/

# Superpowers workspace (already exists)
.superpowers/
```

- [ ] **Step 3: Write `requirements.txt`**

```
Django>=5.0,<5.2
djangorestframework>=3.15
psycopg[binary]>=3.1
gunicorn>=22
whitenoise>=6.6
pytest>=8
pytest-django>=4.8
```

- [ ] **Step 4: Write `pytest.ini`**

```ini
[pytest]
DJANGO_SETTINGS_MODULE = cloak.settings
python_files = tests.py test_*.py *_tests.py
testpaths = .
```

- [ ] **Step 5: Create Python venv and install deps**

```bash
python3.12 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

Expected: pip finishes without error.

- [ ] **Step 6: Run `django-admin` to scaffold the project package**

```bash
.venv/bin/django-admin startproject cloak .
```

Expected: creates `cloak/__init__.py`, `cloak/settings.py`, `cloak/urls.py`, `cloak/wsgi.py`, `cloak/asgi.py`, and `manage.py`. If `cloak/` already exists as an empty package, `startproject` will not overwrite; delete the empty dir first.

- [ ] **Step 7: Confirm scaffold by running the dev server**

```bash
.venv/bin/python manage.py runserver 0.0.0.0:8000 &
sleep 2
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/
kill %1
```

Expected: `200` (Django welcome page). The trailing `kill` shuts down the server.

- [ ] **Step 8: Write minimal `README.md`**

```markdown
# cloak

Teaching site for encryption algorithms (RSA first). Lives at https://cloak.moosha.org.

## Local dev
```
make up        # docker compose up
make migrate   # apply migrations
make loadalgos # load algorithm fixtures
make test      # run pytest + JS tests
```

Source spec: `docs/superpowers/specs/2026-05-21-cloak-rsa-design.md`
```

- [ ] **Step 9: Commit**

```bash
git add .gitignore requirements.txt pytest.ini README.md manage.py cloak/ docs/
git commit -m "feat: scaffold Django project"
```

---

## Task 2: Settings, env, and Postgres wiring

**Files:**
- Modify: `cloak/settings.py`
- Create: `.env.example`

- [ ] **Step 1: Write `.env.example`**

```
DJANGO_SECRET_KEY=change-me-in-prod
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,cloak.moosha.org
DATABASE_URL=postgres://cloak:cloak@db:5432/cloak
POSTGRES_USER=cloak
POSTGRES_PASSWORD=cloak
POSTGRES_DB=cloak
```

- [ ] **Step 2: Replace `cloak/settings.py` with an env-driven version**

Replace the file's contents (preserve the auto-generated `SECRET_KEY` only as a fallback for tests). New file:

```python
import os
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-insecure-key")
DEBUG = os.environ.get("DJANGO_DEBUG", "False").lower() == "true"
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "core",
    "accounts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "cloak.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "cloak.wsgi.application"

# Database
_db_url = os.environ.get("DATABASE_URL")
if _db_url:
    p = urlparse(_db_url)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": p.path.lstrip("/"),
            "USER": p.username,
            "PASSWORD": p.password,
            "HOST": p.hostname,
            "PORT": str(p.port or 5432),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/me/progress/"
LOGOUT_REDIRECT_URL = "/"

CSRF_TRUSTED_ORIGINS = ["https://cloak.moosha.org"]
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}
```

- [ ] **Step 3: Run `check` to confirm settings parse**

```bash
DJANGO_SECRET_KEY=test DJANGO_DEBUG=True .venv/bin/python manage.py check
```

Expected: `System check identified no issues (0 silenced).`

- [ ] **Step 4: Commit**

```bash
git add cloak/settings.py .env.example
git commit -m "feat: env-driven settings + Postgres config"
```

---

## Task 3: Docker Compose artifact

**Files:**
- Create: `Dockerfile`, `docker-compose.yml`, `entrypoint.sh`, `Makefile`

- [ ] **Step 1: Write `Dockerfile`**

```dockerfile
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x ./entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
```

- [ ] **Step 2: Write `entrypoint.sh`**

```bash
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
exec gunicorn cloak.wsgi:application --bind 0.0.0.0:8000 --workers 3 --access-logfile -
```

- [ ] **Step 3: Write `docker-compose.yml`**

```yaml
services:
  web:
    build: .
    env_file: .env
    ports:
      - "127.0.0.1:8000:8000"
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped
  db:
    image: postgres:16
    env_file: .env
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
```

- [ ] **Step 4: Write `Makefile`**

```makefile
.PHONY: up down build migrate loadalgos test shell logs

up:
	docker compose up -d --build

down:
	docker compose down

build:
	docker compose build

migrate:
	docker compose exec web python manage.py migrate

loadalgos:
	docker compose exec web sh -c 'for f in algorithms/*/fixtures.json; do python manage.py loaddata "$$f"; done'

test:
	.venv/bin/pytest -v
	node --test static/**/tests/*.test.js

shell:
	docker compose exec web python manage.py shell

logs:
	docker compose logs -f web
```

- [ ] **Step 5: Copy `.env.example` to `.env` for local dev**

```bash
cp .env.example .env
```

- [ ] **Step 6: Build the image to confirm it works**

```bash
docker compose build web
```

Expected: image builds without error. (If Docker is unavailable in the dev environment, skip and rely on CI / production for verification.)

- [ ] **Step 7: Commit**

```bash
git add Dockerfile docker-compose.yml entrypoint.sh Makefile
git commit -m "feat: docker compose artifact (web + db) for Caddy-fronted deploy"
```

---

## Task 4: Core app skeleton and URL routing

**Files:**
- Create: `core/__init__.py`, `core/apps.py`, `core/views.py`, `core/urls.py`, `core/admin.py`
- Create: `accounts/__init__.py`, `accounts/apps.py`, `accounts/urls.py`, `accounts/views.py`
- Modify: `cloak/urls.py`

- [ ] **Step 1: Create both apps via manage.py**

```bash
.venv/bin/python manage.py startapp core
.venv/bin/python manage.py startapp accounts
```

- [ ] **Step 2: Replace `cloak/urls.py`**

```python
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("accounts/", include("accounts.urls")),
    path("api/", include("core.api_urls")),
    path("", include("core.urls")),
]
```

- [ ] **Step 3: Write a placeholder `core/urls.py`**

```python
from django.urls import path
from . import views

urlpatterns = [
    path("", views.landing, name="landing"),
]
```

- [ ] **Step 4: Write a placeholder `core/api_urls.py`**

```python
from django.urls import path

urlpatterns = []
```

- [ ] **Step 5: Write a placeholder `accounts/urls.py`**

```python
from django.urls import path

urlpatterns = []
```

- [ ] **Step 6: Write a placeholder `core/views.py`**

```python
from django.http import HttpResponse

def landing(request):
    return HttpResponse("Cloak landing — to be implemented.")
```

- [ ] **Step 7: Run `manage.py check`**

```bash
DJANGO_SECRET_KEY=test .venv/bin/python manage.py check
```

Expected: `System check identified no issues (0 silenced).`

- [ ] **Step 8: Commit**

```bash
git add core/ accounts/ cloak/urls.py
git commit -m "feat: scaffold core and accounts apps with URL routing"
```

---

## Task 5: Models — Algorithm, Lesson, Step, UserProgress

**Files:**
- Modify: `core/models.py`
- Modify: `core/admin.py`
- Test: `core/tests/__init__.py`, `core/tests/test_models.py`

- [ ] **Step 1: Write failing model tests**

Create `core/tests/__init__.py` (empty file), then `core/tests/test_models.py`:

```python
import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from core.models import Algorithm, Lesson, Step, UserProgress


@pytest.mark.django_db
def test_algorithm_slug_unique():
    Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    with pytest.raises(IntegrityError):
        Algorithm.objects.create(slug="rsa", name="RSA 2", family="asymmetric", status="live", order=2)


@pytest.mark.django_db
def test_lesson_belongs_to_algorithm():
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    lesson = Lesson.objects.create(algorithm=algo, slug="encrypt-decrypt", title="Encrypt & Decrypt", order=1)
    assert lesson.algorithm == algo
    assert str(lesson) == "RSA — Encrypt & Decrypt"


@pytest.mark.django_db
def test_step_ordering_unique_within_lesson():
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    lesson = Lesson.objects.create(algorithm=algo, slug="encrypt-decrypt", title="t", order=1)
    Step.objects.create(lesson=lesson, order=1, slug="pick-pq", kind="input-multi",
                        prompt_template="pick p,q", validator_key="pick_pq", codegen_key="pick_pq")
    with pytest.raises(IntegrityError):
        Step.objects.create(lesson=lesson, order=1, slug="pick-pq-2", kind="input-multi",
                            prompt_template="x", validator_key="x", codegen_key="x")


@pytest.mark.django_db
def test_user_progress_state_is_jsonb():
    User = get_user_model()
    user = User.objects.create_user(username="u", email="u@e.com", password="pw")
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    lesson = Lesson.objects.create(algorithm=algo, slug="enc", title="t", order=1)
    progress = UserProgress.objects.create(
        user=user, lesson=lesson, current_step_order=3, state={"p": 61, "q": 53, "n": 3233}
    )
    progress.refresh_from_db()
    assert progress.state["p"] == 61
    assert progress.state["n"] == 3233
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_models.py -v
```

Expected: `ImportError` / collection failure (models don't exist yet).

- [ ] **Step 3: Write `core/models.py`**

```python
from django.conf import settings
from django.db import models


class Algorithm(models.Model):
    FAMILY_CHOICES = [
        ("asymmetric", "Asymmetric"),
        ("symmetric", "Symmetric"),
        ("pq", "Post-Quantum"),
    ]
    STATUS_CHOICES = [
        ("live", "Live"),
        ("coming-soon", "Coming soon"),
    ]
    slug = models.SlugField(unique=True)
    name = models.CharField(max_length=80)
    family = models.CharField(max_length=20, choices=FAMILY_CHOICES)
    intro_template = models.CharField(max_length=200, blank=True, default="")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="coming-soon")
    order = models.IntegerField(default=0)

    class Meta:
        ordering = ["order", "name"]

    def __str__(self):
        return self.name


class Lesson(models.Model):
    algorithm = models.ForeignKey(Algorithm, on_delete=models.CASCADE, related_name="lessons")
    slug = models.SlugField()
    title = models.CharField(max_length=120)
    order = models.IntegerField(default=0)

    class Meta:
        ordering = ["order"]
        constraints = [
            models.UniqueConstraint(fields=["algorithm", "slug"], name="unique_lesson_slug_per_algo"),
        ]

    def __str__(self):
        return f"{self.algorithm.name} — {self.title}"


class Step(models.Model):
    KIND_CHOICES = [
        ("info", "Info"),
        ("input-numeric", "Numeric input"),
        ("input-multi", "Multi-numeric input"),
        ("choose-from-list", "Choose from list"),
    ]
    lesson = models.ForeignKey(Lesson, on_delete=models.CASCADE, related_name="steps")
    order = models.IntegerField()
    slug = models.SlugField()
    kind = models.CharField(max_length=20, choices=KIND_CHOICES)
    prompt_template = models.TextField()
    validator_key = models.CharField(max_length=80, blank=True, default="")
    codegen_key = models.CharField(max_length=80, blank=True, default="")

    class Meta:
        ordering = ["order"]
        constraints = [
            models.UniqueConstraint(fields=["lesson", "slug"], name="unique_step_slug_per_lesson"),
            models.UniqueConstraint(fields=["lesson", "order"], name="unique_step_order_per_lesson"),
        ]

    def __str__(self):
        return f"{self.lesson} :: {self.slug}"


class UserProgress(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="progress")
    lesson = models.ForeignKey(Lesson, on_delete=models.CASCADE)
    current_step_order = models.IntegerField(default=1)
    state = models.JSONField(default=dict)
    completed_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "lesson"], name="unique_progress_per_user_lesson"),
        ]
```

- [ ] **Step 4: Register models in admin**

Write `core/admin.py`:

```python
from django.contrib import admin
from .models import Algorithm, Lesson, Step, UserProgress

admin.site.register(Algorithm)
admin.site.register(Lesson)
admin.site.register(Step)
admin.site.register(UserProgress)
```

- [ ] **Step 5: Create migrations and run them**

```bash
DJANGO_SECRET_KEY=test .venv/bin/python manage.py makemigrations core
DJANGO_SECRET_KEY=test .venv/bin/python manage.py migrate
```

Expected: migration created at `core/migrations/0001_initial.py`, applied successfully.

- [ ] **Step 6: Run tests**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_models.py -v
```

Expected: 4 tests pass.

- [ ] **Step 7: Commit**

```bash
git add core/models.py core/admin.py core/migrations/ core/tests/
git commit -m "feat: Algorithm/Lesson/Step/UserProgress models with tests"
```

---

## Task 6: Algorithm module loader

**Files:**
- Create: `core/algorithm_loader.py`
- Create: `core/tests/test_algorithm_loader.py`
- Create: `algorithms/__init__.py`, `algorithms/rsa/__init__.py` (empty placeholders)
- Create: `algorithms/rsa/validators.py`, `algorithms/rsa/codegen.py` (stubs only)

The loader resolves `algorithm.slug → validators module / codegen module` by name. This lets `core/api.py` look up validators dynamically and stay generic.

- [ ] **Step 1: Create algorithm package placeholders**

```bash
mkdir -p algorithms/rsa
touch algorithms/__init__.py algorithms/rsa/__init__.py
```

Write `algorithms/rsa/validators.py`:

```python
def ping():
    return "rsa-validators-ok"
```

Write `algorithms/rsa/codegen.py`:

```python
def ping():
    return "rsa-codegen-ok"
```

- [ ] **Step 2: Write failing tests**

Create `core/tests/test_algorithm_loader.py`:

```python
import pytest
from core.algorithm_loader import get_validators, get_codegen, AlgorithmNotFound


def test_get_validators_for_rsa():
    mod = get_validators("rsa")
    assert mod.ping() == "rsa-validators-ok"


def test_get_codegen_for_rsa():
    mod = get_codegen("rsa")
    assert mod.ping() == "rsa-codegen-ok"


def test_unknown_algorithm_raises():
    with pytest.raises(AlgorithmNotFound):
        get_validators("does-not-exist")
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_algorithm_loader.py -v
```

Expected: import error (`core.algorithm_loader` doesn't exist).

- [ ] **Step 4: Write `core/algorithm_loader.py`**

```python
import importlib
import re

_SLUG_RE = re.compile(r"^[a-z0-9_-]+$")


class AlgorithmNotFound(LookupError):
    pass


def _safe_import(slug: str, submodule: str):
    if not _SLUG_RE.match(slug):
        raise AlgorithmNotFound(f"invalid slug: {slug!r}")
    try:
        return importlib.import_module(f"algorithms.{slug.replace('-', '_')}.{submodule}")
    except ModuleNotFoundError as e:
        raise AlgorithmNotFound(f"algorithm {slug!r} has no {submodule} module") from e


def get_validators(slug: str):
    return _safe_import(slug, "validators")


def get_codegen(slug: str):
    return _safe_import(slug, "codegen")
```

- [ ] **Step 5: Run tests**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_algorithm_loader.py -v
```

Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add core/algorithm_loader.py core/tests/test_algorithm_loader.py algorithms/
git commit -m "feat: dynamic per-algorithm module loader"
```

---

## Task 7: RSA logic.py — pure math

**Files:**
- Modify: `algorithms/rsa/logic.py`
- Create: `algorithms/rsa/tests/__init__.py`, `algorithms/rsa/tests/test_logic.py`

- [ ] **Step 1: Write failing tests**

Create `algorithms/rsa/tests/__init__.py` (empty), then `algorithms/rsa/tests/test_logic.py`:

```python
import pytest
from algorithms.rsa.logic import is_prime, gcd, phi, modinv, encrypt, decrypt, coprime_candidates


def test_is_prime():
    assert is_prime(2)
    assert is_prime(61)
    assert is_prime(997)
    assert not is_prime(1)
    assert not is_prime(0)
    assert not is_prime(-7)
    assert not is_prime(60)


def test_gcd():
    assert gcd(48, 18) == 6
    assert gcd(17, 5) == 1


def test_phi():
    assert phi(61, 53) == 3120


def test_modinv():
    assert modinv(17, 3120) == 2753
    assert (17 * 2753) % 3120 == 1


def test_modinv_no_inverse_raises():
    with pytest.raises(ValueError):
        modinv(6, 9)  # gcd != 1


def test_encrypt_decrypt_roundtrip():
    e, n, d = 17, 3233, 2753
    c = encrypt(65, e, n)
    assert c == pow(65, e, n)
    assert decrypt(c, d, n) == 65


def test_coprime_candidates():
    cands = coprime_candidates(3120, limit=10)
    assert all(gcd(c, 3120) == 1 for c in cands)
    assert 1 not in cands
    assert all(c < 3120 for c in cands)
    assert len(cands) == 10
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest algorithms/rsa/tests/test_logic.py -v
```

Expected: import error (`logic.py` is empty).

- [ ] **Step 3: Write `algorithms/rsa/logic.py`**

```python
def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def phi(p: int, q: int) -> int:
    return (p - 1) * (q - 1)


def _egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError(f"no modular inverse: gcd({a}, {m}) = {g}")
    return x % m


def encrypt(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


def decrypt(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


def coprime_candidates(phi_n: int, limit: int = 12) -> list[int]:
    """First `limit` values e where 1 < e < phi_n and gcd(e, phi_n) == 1, starting from e = 3."""
    out = []
    e = 3
    while len(out) < limit and e < phi_n:
        if gcd(e, phi_n) == 1:
            out.append(e)
        e += 2
    return out
```

- [ ] **Step 4: Run tests**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest algorithms/rsa/tests/test_logic.py -v
```

Expected: 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add algorithms/rsa/logic.py algorithms/rsa/tests/
git commit -m "feat: RSA pure-math logic with tests"
```

---

## Task 8: RSA validators.py

Each validator returns `{"ok": True, "value": {...}}` or `{"ok": False, "hint": "..."}` — exact shape mirrored in JS.

**Files:**
- Modify: `algorithms/rsa/validators.py`
- Create: `algorithms/rsa/tests/test_validators.py`

- [ ] **Step 1: Write failing tests**

Create `algorithms/rsa/tests/test_validators.py`:

```python
import pytest
from algorithms.rsa import validators as v


def test_pick_pq_happy():
    r = v.pick_pq({"p": "61", "q": "53"}, {})
    assert r == {"ok": True, "value": {"p": 61, "q": 53}}


def test_pick_pq_rejects_non_prime():
    r = v.pick_pq({"p": "60", "q": "53"}, {})
    assert r["ok"] is False
    assert "prime" in r["hint"].lower()


def test_pick_pq_rejects_equal_p_q():
    r = v.pick_pq({"p": "61", "q": "61"}, {})
    assert r["ok"] is False
    assert r["hint"]


def test_pick_pq_rejects_too_large():
    r = v.pick_pq({"p": "1009", "q": "53"}, {})  # 4 digits
    assert r["ok"] is False


def test_compute_n_happy():
    r = v.compute_n("3233", {"p": 61, "q": 53})
    assert r == {"ok": True, "value": {"n": 3233}}


def test_compute_n_wrong():
    r = v.compute_n("3000", {"p": 61, "q": 53})
    assert r["ok"] is False


def test_compute_phi_happy():
    r = v.compute_phi("3120", {"p": 61, "q": 53})
    assert r == {"ok": True, "value": {"phi": 3120}}


def test_pick_e_accepts_any_coprime():
    r = v.pick_e("17", {"phi": 3120})
    assert r == {"ok": True, "value": {"e": 17}}


def test_pick_e_rejects_non_coprime():
    r = v.pick_e("6", {"phi": 3120})
    assert r["ok"] is False


def test_compute_d_happy():
    r = v.compute_d("2753", {"e": 17, "phi": 3120})
    assert r == {"ok": True, "value": {"d": 2753}}


def test_compute_d_wrong():
    r = v.compute_d("99", {"e": 17, "phi": 3120})
    assert r["ok"] is False


def test_pick_message_must_be_less_than_n():
    r = v.pick_message("65", {"n": 3233})
    assert r == {"ok": True, "value": {"m": 65}}
    bad = v.pick_message("4000", {"n": 3233})
    assert bad["ok"] is False


def test_encrypt_happy():
    r = v.encrypt(str(pow(65, 17, 3233)), {"m": 65, "e": 17, "n": 3233})
    assert r["ok"] is True


def test_decrypt_happy():
    c = pow(65, 17, 3233)
    r = v.decrypt("65", {"c": c, "d": 2753, "n": 3233})
    assert r == {"ok": True, "value": {"m_decrypted": 65}}
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest algorithms/rsa/tests/test_validators.py -v
```

Expected: import / attribute errors.

- [ ] **Step 3: Replace `algorithms/rsa/validators.py`**

```python
from algorithms.rsa.logic import is_prime, gcd, phi as _phi, modinv, encrypt as _encrypt


def _parse_int(s):
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return None


def pick_pq(input_obj, state):
    p = _parse_int(input_obj.get("p"))
    q = _parse_int(input_obj.get("q"))
    if p is None or q is None:
        return {"ok": False, "hint": "Enter whole numbers for both p and q."}
    if p == q:
        return {"ok": False, "hint": "p and q must be different primes."}
    if not (2 <= p <= 999 and 2 <= q <= 999):
        return {"ok": False, "hint": "p and q must be at most 3 digits (between 2 and 999)."}
    if not is_prime(p):
        return {"ok": False, "hint": f"{p} is not prime."}
    if not is_prime(q):
        return {"ok": False, "hint": f"{q} is not prime."}
    return {"ok": True, "value": {"p": p, "q": q}}


def compute_n(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    expected = state["p"] * state["q"]
    if got != expected:
        return {"ok": False, "hint": f"n = p · q. With p={state['p']}, q={state['q']}."}
    return {"ok": True, "value": {"n": got}}


def compute_phi(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    expected = _phi(state["p"], state["q"])
    if got != expected:
        return {"ok": False, "hint": f"φ(n) = (p-1)(q-1). With p={state['p']}, q={state['q']}."}
    return {"ok": True, "value": {"phi": got}}


def pick_e(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    if not (1 < got < state["phi"]):
        return {"ok": False, "hint": f"e must satisfy 1 < e < φ(n) = {state['phi']}."}
    if gcd(got, state["phi"]) != 1:
        return {"ok": False, "hint": f"e must be coprime to φ(n). gcd({got}, {state['phi']}) ≠ 1."}
    return {"ok": True, "value": {"e": got}}


def compute_d(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    expected = modinv(state["e"], state["phi"])
    if got != expected:
        return {"ok": False, "hint": f"d satisfies (d · e) ≡ 1 (mod φ). With e={state['e']}, φ={state['phi']}."}
    return {"ok": True, "value": {"d": got}}


def pick_message(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    if not (0 <= got < state["n"]):
        return {"ok": False, "hint": f"Message must satisfy 0 ≤ m < n = {state['n']}."}
    return {"ok": True, "value": {"m": got}}


def encrypt(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    expected = _encrypt(state["m"], state["e"], state["n"])
    if got != expected:
        return {"ok": False, "hint": f"c = m^e mod n. With m={state['m']}, e={state['e']}, n={state['n']}."}
    return {"ok": True, "value": {"c": got}}


def decrypt(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    expected = pow(state["c"], state["d"], state["n"])
    if got != expected:
        return {"ok": False, "hint": f"m = c^d mod n. With c={state['c']}, d={state['d']}, n={state['n']}."}
    return {"ok": True, "value": {"m_decrypted": got}}


def info(_input, _state):
    return {"ok": True, "value": {}}
```

- [ ] **Step 4: Run tests**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest algorithms/rsa/tests/test_validators.py -v
```

Expected: 14 tests pass.

- [ ] **Step 5: Commit**

```bash
git add algorithms/rsa/validators.py algorithms/rsa/tests/test_validators.py
git commit -m "feat: RSA per-step validators with hint messages"
```

---

## Task 9: RSA codegen.py

Each codegen function returns the exact Python line(s) to render for that step, with values filled in from `state`. The output must match the JS codegen byte-for-byte.

**Files:**
- Modify: `algorithms/rsa/codegen.py`
- Create: `algorithms/rsa/tests/test_codegen.py`

- [ ] **Step 1: Write failing tests**

Create `algorithms/rsa/tests/test_codegen.py`:

```python
from algorithms.rsa import codegen as cg


STATE_FULL = {
    "p": 61, "q": 53, "n": 3233, "phi": 3120, "e": 17, "d": 2753,
    "m": 65, "c": pow(65, 17, 3233), "m_decrypted": 65,
}


def test_pick_pq_line():
    assert cg.pick_pq(STATE_FULL) == "p, q = 61, 53"


def test_compute_n_line():
    assert cg.compute_n(STATE_FULL) == "n = p * q  # n = 3233"


def test_compute_phi_line():
    assert cg.compute_phi(STATE_FULL) == "phi = (p - 1) * (q - 1)  # phi = 3120"


def test_pick_e_line():
    assert cg.pick_e(STATE_FULL) == "e = 17  # gcd(e, phi) == 1"


def test_compute_d_line():
    assert cg.compute_d(STATE_FULL) == "d = pow(e, -1, phi)  # d = 2753"


def test_pick_message_line():
    assert cg.pick_message(STATE_FULL) == "m = 65"


def test_encrypt_line():
    expected_c = pow(65, 17, 3233)
    assert cg.encrypt(STATE_FULL) == f"c = pow(m, e, n)  # c = {expected_c}"


def test_decrypt_line():
    assert cg.decrypt(STATE_FULL) == "m_decrypted = pow(c, d, n)  # m_decrypted = 65"


def test_info_returns_empty_string():
    assert cg.info(STATE_FULL) == ""


def test_full_script():
    script = cg.full_script(STATE_FULL)
    assert script.startswith("# RSA lesson — generated by cloak.moosha.org\n")
    assert "p, q = 61, 53" in script
    assert "m_decrypted = pow(c, d, n)" in script
    assert script.endswith("\n")
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest algorithms/rsa/tests/test_codegen.py -v
```

Expected: attribute errors / wrong return.

- [ ] **Step 3: Replace `algorithms/rsa/codegen.py`**

```python
def pick_pq(state):
    return f"p, q = {state['p']}, {state['q']}"


def compute_n(state):
    return f"n = p * q  # n = {state['n']}"


def compute_phi(state):
    return f"phi = (p - 1) * (q - 1)  # phi = {state['phi']}"


def pick_e(state):
    return f"e = {state['e']}  # gcd(e, phi) == 1"


def compute_d(state):
    return f"d = pow(e, -1, phi)  # d = {state['d']}"


def pick_message(state):
    return f"m = {state['m']}"


def encrypt(state):
    return f"c = pow(m, e, n)  # c = {state['c']}"


def decrypt(state):
    return f"m_decrypted = pow(c, d, n)  # m_decrypted = {state['m_decrypted']}"


def info(_state):
    return ""


_ORDER = [pick_pq, compute_n, compute_phi, pick_e, compute_d, pick_message, encrypt, decrypt]


def full_script(state):
    lines = ["# RSA lesson — generated by cloak.moosha.org", ""]
    for fn in _ORDER:
        keys_needed = {
            pick_pq: ["p", "q"],
            compute_n: ["n"],
            compute_phi: ["phi"],
            pick_e: ["e"],
            compute_d: ["d"],
            pick_message: ["m"],
            encrypt: ["c"],
            decrypt: ["m_decrypted"],
        }[fn]
        if all(k in state for k in keys_needed):
            lines.append(fn(state))
    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Run tests**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest algorithms/rsa/tests/test_codegen.py -v
```

Expected: 10 tests pass.

- [ ] **Step 5: Commit**

```bash
git add algorithms/rsa/codegen.py algorithms/rsa/tests/test_codegen.py
git commit -m "feat: RSA per-step codegen + full_script aggregator"
```

---

## Task 10: RSA fixtures.json

Defines the Algorithm + Lesson + 9 Step rows that drive the wizard.

**Files:**
- Create: `algorithms/rsa/fixtures.json`
- Create: `core/tests/test_fixtures.py`

- [ ] **Step 1: Write failing fixture test**

Create `core/tests/test_fixtures.py`:

```python
import pytest
from django.core.management import call_command
from core.models import Algorithm, Lesson, Step


@pytest.mark.django_db
def test_rsa_fixture_loads():
    call_command("loaddata", "algorithms/rsa/fixtures.json")
    algo = Algorithm.objects.get(slug="rsa")
    assert algo.status == "live"
    lesson = Lesson.objects.get(algorithm=algo, slug="encrypt-decrypt")
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 9
    assert [s.slug for s in steps] == [
        "intro", "pick-pq", "compute-n", "compute-phi", "pick-e",
        "compute-d", "pick-message", "encrypt", "decrypt-done",
    ]
```

- [ ] **Step 2: Run to confirm failure**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_fixtures.py -v
```

Expected: `FileNotFoundError` or similar.

- [ ] **Step 3: Write `algorithms/rsa/fixtures.json`**

```json
[
  {
    "model": "core.algorithm",
    "pk": 1,
    "fields": {
      "slug": "rsa",
      "name": "RSA",
      "family": "asymmetric",
      "status": "live",
      "order": 1,
      "intro_template": ""
    }
  },
  {
    "model": "core.lesson",
    "pk": 1,
    "fields": {
      "algorithm": 1,
      "slug": "encrypt-decrypt",
      "title": "Encrypt & Decrypt a Number",
      "order": 1
    }
  },
  {
    "model": "core.step",
    "pk": 1,
    "fields": {
      "lesson": 1, "order": 1, "slug": "intro", "kind": "info",
      "prompt_template": "## Welcome to RSA\n\nYou'll pick two primes, derive a public and private key, encrypt a number, then decrypt it. Compute each step yourself; the site will check your work and show you the Python equivalent.",
      "validator_key": "info", "codegen_key": "info"
    }
  },
  {
    "model": "core.step",
    "pk": 2,
    "fields": {
      "lesson": 1, "order": 2, "slug": "pick-pq", "kind": "input-multi",
      "prompt_template": "### Pick two primes\n\nChoose **p** and **q**, each a prime up to 3 digits (between 2 and 999). They must be different.",
      "validator_key": "pick_pq", "codegen_key": "pick_pq"
    }
  },
  {
    "model": "core.step",
    "pk": 3,
    "fields": {
      "lesson": 1, "order": 3, "slug": "compute-n", "kind": "input-numeric",
      "prompt_template": "### Compute n\n\nn is the modulus of both the public and private key.\n\n`n = p · q` — with p = {{ state.p }}, q = {{ state.q }}.",
      "validator_key": "compute_n", "codegen_key": "compute_n"
    }
  },
  {
    "model": "core.step",
    "pk": 4,
    "fields": {
      "lesson": 1, "order": 4, "slug": "compute-phi", "kind": "input-numeric",
      "prompt_template": "### Compute φ(n)\n\nEuler's totient. For two primes, `φ(n) = (p-1)(q-1)`.\n\nWith p = {{ state.p }}, q = {{ state.q }}.",
      "validator_key": "compute_phi", "codegen_key": "compute_phi"
    }
  },
  {
    "model": "core.step",
    "pk": 5,
    "fields": {
      "lesson": 1, "order": 5, "slug": "pick-e", "kind": "choose-from-list",
      "prompt_template": "### Pick e (public exponent)\n\nChoose any e with 1 < e < φ(n) and gcd(e, φ) = 1. The list below shows the first valid candidates.",
      "validator_key": "pick_e", "codegen_key": "pick_e"
    }
  },
  {
    "model": "core.step",
    "pk": 6,
    "fields": {
      "lesson": 1, "order": 6, "slug": "compute-d", "kind": "input-numeric",
      "prompt_template": "### Compute d (private exponent)\n\nd is the modular inverse of e mod φ(n) — that is, `(d · e) ≡ 1 (mod φ)`.\n\nWith e = {{ state.e }}, φ = {{ state.phi }}.",
      "validator_key": "compute_d", "codegen_key": "compute_d"
    }
  },
  {
    "model": "core.step",
    "pk": 7,
    "fields": {
      "lesson": 1, "order": 7, "slug": "pick-message", "kind": "input-numeric",
      "prompt_template": "### Choose a message\n\nPick a small integer m with 0 ≤ m < n = {{ state.n }}. We'll encrypt this.",
      "validator_key": "pick_message", "codegen_key": "pick_message"
    }
  },
  {
    "model": "core.step",
    "pk": 8,
    "fields": {
      "lesson": 1, "order": 8, "slug": "encrypt", "kind": "input-numeric",
      "prompt_template": "### Encrypt\n\n`c = m^e mod n`. Compute the ciphertext c with m = {{ state.m }}, e = {{ state.e }}, n = {{ state.n }}.",
      "validator_key": "encrypt", "codegen_key": "encrypt"
    }
  },
  {
    "model": "core.step",
    "pk": 9,
    "fields": {
      "lesson": 1, "order": 9, "slug": "decrypt-done", "kind": "input-numeric",
      "prompt_template": "### Decrypt\n\n`m = c^d mod n`. Apply the private exponent d = {{ state.d }} to c = {{ state.c }} (mod n = {{ state.n }}). You should recover the original message.",
      "validator_key": "decrypt", "codegen_key": "decrypt"
    }
  }
]
```

- [ ] **Step 4: Run tests**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_fixtures.py -v
```

Expected: passes.

- [ ] **Step 5: Commit**

```bash
git add algorithms/rsa/fixtures.json core/tests/test_fixtures.py
git commit -m "feat: RSA fixtures (Algorithm, Lesson, 9 Steps)"
```

---

## Task 11: JS BigInt math module

**Files:**
- Create: `static/algorithms/rsa/math.js`
- Create: `static/algorithms/rsa/tests/math.test.js`
- Create: `package.json` (root)

- [ ] **Step 1: Write `package.json`**

```json
{
  "name": "cloak",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "node --test static/algorithms/*/tests/*.test.js"
  }
}
```

- [ ] **Step 2: Write failing test**

Create `static/algorithms/rsa/tests/math.test.js`:

```javascript
import { test } from "node:test";
import assert from "node:assert/strict";
import { isPrime, gcd, modInv, modPow, phi, coprimeCandidates } from "../math.js";

test("isPrime", () => {
  assert.equal(isPrime(2n), true);
  assert.equal(isPrime(61n), true);
  assert.equal(isPrime(997n), true);
  assert.equal(isPrime(1n), false);
  assert.equal(isPrime(60n), false);
});

test("gcd", () => {
  assert.equal(gcd(48n, 18n), 6n);
  assert.equal(gcd(17n, 5n), 1n);
});

test("phi", () => {
  assert.equal(phi(61n, 53n), 3120n);
});

test("modInv", () => {
  assert.equal(modInv(17n, 3120n), 2753n);
});

test("modPow encrypt/decrypt roundtrip", () => {
  const c = modPow(65n, 17n, 3233n);
  assert.equal(modPow(c, 2753n, 3233n), 65n);
});

test("coprimeCandidates", () => {
  const cands = coprimeCandidates(3120n, 10);
  assert.equal(cands.length, 10);
  for (const e of cands) {
    assert.equal(gcd(e, 3120n), 1n);
  }
});
```

- [ ] **Step 3: Run test to confirm failure**

```bash
node --test static/algorithms/rsa/tests/math.test.js
```

Expected: import resolution error.

- [ ] **Step 4: Write `static/algorithms/rsa/math.js`**

```javascript
export function isPrime(n) {
  if (n < 2n) return false;
  if (n < 4n) return true;
  if (n % 2n === 0n) return false;
  let i = 3n;
  while (i * i <= n) {
    if (n % i === 0n) return false;
    i += 2n;
  }
  return true;
}

export function gcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b) { [a, b] = [b, a % b]; }
  return a;
}

export function phi(p, q) {
  return (p - 1n) * (q - 1n);
}

function _egcd(a, b) {
  if (b === 0n) return { g: a, x: 1n, y: 0n };
  const r = _egcd(b, a % b);
  return { g: r.g, x: r.y, y: r.x - (a / b) * r.y };
}

export function modInv(a, m) {
  const r = _egcd(((a % m) + m) % m, m);
  if (r.g !== 1n) throw new Error(`no modular inverse: gcd(${a}, ${m}) = ${r.g}`);
  return ((r.x % m) + m) % m;
}

export function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

export function coprimeCandidates(phiN, limit = 12) {
  const out = [];
  let e = 3n;
  while (out.length < limit && e < phiN) {
    if (gcd(e, phiN) === 1n) out.push(e);
    e += 2n;
  }
  return out;
}
```

- [ ] **Step 5: Run tests**

```bash
node --test static/algorithms/rsa/tests/math.test.js
```

Expected: 6 tests pass.

- [ ] **Step 6: Commit**

```bash
git add static/algorithms/rsa/math.js static/algorithms/rsa/tests/math.test.js package.json
git commit -m "feat: JS BigInt math module for RSA with tests"
```

---

## Task 12: JS validators module

**Files:**
- Create: `static/algorithms/rsa/validators.js`
- Create: `static/algorithms/rsa/tests/validators.test.js`

- [ ] **Step 1: Write failing tests**

Create `static/algorithms/rsa/tests/validators.test.js`:

```javascript
import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("pick_pq happy", () => {
  assert.deepEqual(v.pick_pq({ p: "61", q: "53" }, {}), { ok: true, value: { p: 61, q: 53 } });
});

test("pick_pq rejects non-prime", () => {
  const r = v.pick_pq({ p: "60", q: "53" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /prime/i);
});

test("compute_phi wrong", () => {
  const r = v.compute_phi("3000", { p: 61, q: 53 });
  assert.equal(r.ok, false);
});

test("pick_e accepts any coprime", () => {
  assert.deepEqual(v.pick_e("17", { phi: 3120 }), { ok: true, value: { e: 17 } });
});

test("pick_e rejects non-coprime", () => {
  const r = v.pick_e("6", { phi: 3120 });
  assert.equal(r.ok, false);
});

test("decrypt happy", () => {
  const c = Number(2790n);  // pow(65, 17, 3233)
  const r = v.decrypt("65", { c, d: 2753, n: 3233 });
  assert.deepEqual(r, { ok: true, value: { m_decrypted: 65 } });
});
```

- [ ] **Step 2: Run to verify failure**

```bash
node --test static/algorithms/rsa/tests/validators.test.js
```

Expected: import error.

- [ ] **Step 3: Write `static/algorithms/rsa/validators.js`**

```javascript
import { isPrime, gcd, modInv, modPow, phi as phiFn } from "./math.js";

function _parseInt(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim();
  if (!/^-?\d+$/.test(t)) return null;
  return BigInt(t);
}

function _ok(value) {
  // Convert BigInts in value to Number for JSON-safe storage in localStorage / DB.
  const out = {};
  for (const [k, val] of Object.entries(value)) {
    out[k] = typeof val === "bigint" ? Number(val) : val;
  }
  return { ok: true, value: out };
}

export function pick_pq(input, _state) {
  const p = _parseInt(input?.p);
  const q = _parseInt(input?.q);
  if (p === null || q === null) return { ok: false, hint: "Enter whole numbers for both p and q." };
  if (p === q) return { ok: false, hint: "p and q must be different primes." };
  if (!(2n <= p && p <= 999n && 2n <= q && q <= 999n)) {
    return { ok: false, hint: "p and q must be at most 3 digits (between 2 and 999)." };
  }
  if (!isPrime(p)) return { ok: false, hint: `${p} is not prime.` };
  if (!isPrime(q)) return { ok: false, hint: `${q} is not prime.` };
  return _ok({ p, q });
}

export function compute_n(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const expected = BigInt(state.p) * BigInt(state.q);
  if (got !== expected) return { ok: false, hint: `n = p · q. With p=${state.p}, q=${state.q}.` };
  return _ok({ n: got });
}

export function compute_phi(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const expected = phiFn(BigInt(state.p), BigInt(state.q));
  if (got !== expected) return { ok: false, hint: `φ(n) = (p-1)(q-1). With p=${state.p}, q=${state.q}.` };
  return _ok({ phi: got });
}

export function pick_e(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  if (!(1n < got && got < BigInt(state.phi))) {
    return { ok: false, hint: `e must satisfy 1 < e < φ(n) = ${state.phi}.` };
  }
  if (gcd(got, BigInt(state.phi)) !== 1n) {
    return { ok: false, hint: `e must be coprime to φ(n). gcd(${got}, ${state.phi}) ≠ 1.` };
  }
  return _ok({ e: got });
}

export function compute_d(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const expected = modInv(BigInt(state.e), BigInt(state.phi));
  if (got !== expected) {
    return { ok: false, hint: `d satisfies (d · e) ≡ 1 (mod φ). With e=${state.e}, φ=${state.phi}.` };
  }
  return _ok({ d: got });
}

export function pick_message(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  if (!(0n <= got && got < BigInt(state.n))) {
    return { ok: false, hint: `Message must satisfy 0 ≤ m < n = ${state.n}.` };
  }
  return _ok({ m: got });
}

export function encrypt(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const expected = modPow(BigInt(state.m), BigInt(state.e), BigInt(state.n));
  if (got !== expected) {
    return { ok: false, hint: `c = m^e mod n. With m=${state.m}, e=${state.e}, n=${state.n}.` };
  }
  return _ok({ c: got });
}

export function decrypt(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const expected = modPow(BigInt(state.c), BigInt(state.d), BigInt(state.n));
  if (got !== expected) {
    return { ok: false, hint: `m = c^d mod n. With c=${state.c}, d=${state.d}, n=${state.n}.` };
  }
  return _ok({ m_decrypted: got });
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}
```

- [ ] **Step 4: Run tests**

```bash
node --test static/algorithms/rsa/tests/validators.test.js
```

Expected: 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/rsa/validators.js static/algorithms/rsa/tests/validators.test.js
git commit -m "feat: JS RSA validators (mirror of Python)"
```

---

## Task 13: JS codegen module

**Files:**
- Create: `static/algorithms/rsa/codegen.js`
- Create: `static/algorithms/rsa/tests/codegen.test.js`

- [ ] **Step 1: Write failing tests**

Create `static/algorithms/rsa/tests/codegen.test.js`:

```javascript
import { test } from "node:test";
import assert from "node:assert/strict";
import * as cg from "../codegen.js";

const STATE_FULL = {
  p: 61, q: 53, n: 3233, phi: 3120, e: 17, d: 2753,
  m: 65, c: 2790, m_decrypted: 65,
};

test("pick_pq", () => assert.equal(cg.pick_pq(STATE_FULL), "p, q = 61, 53"));
test("compute_n", () => assert.equal(cg.compute_n(STATE_FULL), "n = p * q  # n = 3233"));
test("compute_phi", () => assert.equal(cg.compute_phi(STATE_FULL), "phi = (p - 1) * (q - 1)  # phi = 3120"));
test("pick_e", () => assert.equal(cg.pick_e(STATE_FULL), "e = 17  # gcd(e, phi) == 1"));
test("compute_d", () => assert.equal(cg.compute_d(STATE_FULL), "d = pow(e, -1, phi)  # d = 2753"));
test("pick_message", () => assert.equal(cg.pick_message(STATE_FULL), "m = 65"));
test("encrypt", () => assert.equal(cg.encrypt(STATE_FULL), "c = pow(m, e, n)  # c = 2790"));
test("decrypt", () => assert.equal(cg.decrypt(STATE_FULL), "m_decrypted = pow(c, d, n)  # m_decrypted = 65"));
test("info empty", () => assert.equal(cg.info(STATE_FULL), ""));

test("full_script aggregates known steps", () => {
  const s = cg.full_script(STATE_FULL);
  assert.ok(s.startsWith("# RSA lesson — generated by cloak.moosha.org\n"));
  assert.ok(s.includes("p, q = 61, 53"));
  assert.ok(s.includes("m_decrypted = pow(c, d, n)"));
  assert.ok(s.endsWith("\n"));
});
```

- [ ] **Step 2: Run to verify failure**

```bash
node --test static/algorithms/rsa/tests/codegen.test.js
```

Expected: import error.

- [ ] **Step 3: Write `static/algorithms/rsa/codegen.js`**

```javascript
export const pick_pq      = (s) => `p, q = ${s.p}, ${s.q}`;
export const compute_n    = (s) => `n = p * q  # n = ${s.n}`;
export const compute_phi  = (s) => `phi = (p - 1) * (q - 1)  # phi = ${s.phi}`;
export const pick_e       = (s) => `e = ${s.e}  # gcd(e, phi) == 1`;
export const compute_d    = (s) => `d = pow(e, -1, phi)  # d = ${s.d}`;
export const pick_message = (s) => `m = ${s.m}`;
export const encrypt      = (s) => `c = pow(m, e, n)  # c = ${s.c}`;
export const decrypt      = (s) => `m_decrypted = pow(c, d, n)  # m_decrypted = ${s.m_decrypted}`;
export const info         = (_s) => "";

const _ORDER = [
  { fn: pick_pq,      keys: ["p", "q"] },
  { fn: compute_n,    keys: ["n"] },
  { fn: compute_phi,  keys: ["phi"] },
  { fn: pick_e,       keys: ["e"] },
  { fn: compute_d,    keys: ["d"] },
  { fn: pick_message, keys: ["m"] },
  { fn: encrypt,      keys: ["c"] },
  { fn: decrypt,      keys: ["m_decrypted"] },
];

export function full_script(state) {
  const lines = ["# RSA lesson — generated by cloak.moosha.org", ""];
  for (const { fn, keys } of _ORDER) {
    if (keys.every((k) => k in state)) lines.push(fn(state));
  }
  return lines.join("\n") + "\n";
}
```

- [ ] **Step 4: Run tests**

```bash
node --test static/algorithms/rsa/tests/codegen.test.js
```

Expected: 10 tests pass.

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/rsa/codegen.js static/algorithms/rsa/tests/codegen.test.js
git commit -m "feat: JS RSA codegen + full_script aggregator"
```

---

## Task 14: Parity test — JS must match Python byte-for-byte

**Files:**
- Create: `tests/__init__.py`, `tests/test_parity.py`

- [ ] **Step 1: Write the parity test**

Create `tests/__init__.py` (empty), then `tests/test_parity.py`:

```python
import json
import subprocess
import shutil
import pytest

from algorithms.rsa import codegen as py_cg
from algorithms.rsa import validators as py_v


STATE_FULL = {
    "p": 61, "q": 53, "n": 3233, "phi": 3120, "e": 17, "d": 2753,
    "m": 65, "c": pow(65, 17, 3233), "m_decrypted": 65,
}

CODEGEN_KEYS = ["pick_pq", "compute_n", "compute_phi", "pick_e", "compute_d",
                "pick_message", "encrypt", "decrypt", "info"]

VALIDATOR_CASES = [
    ("pick_pq",      {"p": "61", "q": "53"},                                {}),
    ("pick_pq",      {"p": "60", "q": "53"},                                {}),
    ("compute_n",    "3233",                                                {"p": 61, "q": 53}),
    ("compute_n",    "3000",                                                {"p": 61, "q": 53}),
    ("compute_phi",  "3120",                                                {"p": 61, "q": 53}),
    ("pick_e",       "17",                                                  {"phi": 3120}),
    ("pick_e",       "6",                                                   {"phi": 3120}),
    ("compute_d",    "2753",                                                {"e": 17, "phi": 3120}),
    ("pick_message", "65",                                                  {"n": 3233}),
    ("encrypt",      str(pow(65, 17, 3233)),                                {"m": 65, "e": 17, "n": 3233}),
    ("decrypt",      "65",                                                  {"c": pow(65, 17, 3233), "d": 2753, "n": 3233}),
]


def _node_available():
    return shutil.which("node") is not None


def _run_node(script):
    """Run a node ESM snippet and return its stdout, parsed as JSON."""
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, f"node failed: stderr={proc.stderr}, stdout={proc.stdout}"
    return json.loads(proc.stdout.strip())


@pytest.mark.skipif(not _node_available(), reason="node not in PATH")
def test_codegen_parity():
    state_json = json.dumps(STATE_FULL)
    script = f"""
import * as cg from "./static/algorithms/rsa/codegen.js";
const state = {state_json};
const out = {{}};
for (const k of {json.dumps(CODEGEN_KEYS)}) {{
  out[k] = cg[k](state);
}}
out.__full__ = cg.full_script(state);
process.stdout.write(JSON.stringify(out));
"""
    js_out = _run_node(script)
    for k in CODEGEN_KEYS:
        py = getattr(py_cg, k)(STATE_FULL)
        assert js_out[k] == py, f"codegen[{k}] diverged: JS={js_out[k]!r} PY={py!r}"
    assert js_out["__full__"] == py_cg.full_script(STATE_FULL)


@pytest.mark.skipif(not _node_available(), reason="node not in PATH")
def test_validator_parity():
    cases_json = json.dumps(VALIDATOR_CASES)
    script = f"""
import * as v from "./static/algorithms/rsa/validators.js";
const cases = {cases_json};
const out = [];
for (const [name, input, state] of cases) {{
  out.push(v[name](input, state));
}}
process.stdout.write(JSON.stringify(out));
"""
    js_out = _run_node(script)
    for (name, inp, state), js_result in zip(VALIDATOR_CASES, js_out):
        py_result = getattr(py_v, name)(inp, state)
        # Compare ok + value (hints may differ slightly in formatting; we assert on the structured fields)
        assert js_result["ok"] == py_result["ok"], f"{name}: ok diverged"
        if py_result["ok"]:
            assert js_result["value"] == py_result["value"], f"{name}: value diverged"
```

- [ ] **Step 2: Run the parity test**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest tests/test_parity.py -v
```

Expected: 2 tests pass (or skipped if `node` isn't on PATH; install Node 20+ if so).

- [ ] **Step 3: Commit**

```bash
git add tests/
git commit -m "test: parity between JS and Python codegen/validators"
```

---

## Task 15: Base template + static assets

**Files:**
- Create: `core/templates/core/base.html`
- Create: `static/core/style.css`
- Create: `static/vendor/htmx.min.js`, `static/vendor/alpine.min.js` (downloaded)

- [ ] **Step 1: Download HTMX and Alpine into `static/vendor/`**

```bash
mkdir -p static/vendor
curl -sL https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js -o static/vendor/htmx.min.js
curl -sL https://unpkg.com/alpinejs@3.14.8/dist/cdn.min.js -o static/vendor/alpine.min.js
```

Expected: two files downloaded, each > 10 KB.

- [ ] **Step 2: Write `static/core/style.css`**

```css
:root {
  --bg: #0f172a;
  --panel: #1e293b;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --accent: #3b82f6;
  --ok: #22c55e;
  --warn: #f59e0b;
  --bad: #ef4444;
  --code-bg: #0a0f1e;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font-family: ui-sans-serif, system-ui, sans-serif; line-height: 1.5; }
header.site { padding: 16px 24px; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }
header.site a { color: var(--text); text-decoration: none; }
main { max-width: 880px; margin: 0 auto; padding: 24px; }
h1, h2, h3 { color: #f1f5f9; }
.card { background: var(--panel); border-radius: 10px; padding: 20px; margin-bottom: 16px; }
.card.muted { opacity: 0.55; }
.btn { background: var(--accent); color: #fff; border: 0; padding: 10px 18px; border-radius: 6px; font-weight: 600; cursor: pointer; }
.btn:disabled { opacity: 0.4; cursor: not-allowed; }
.btn.secondary { background: transparent; border: 1px solid #475569; }
input[type="text"], input[type="number"], input[type="email"], input[type="password"] {
  background: var(--code-bg); color: var(--text); border: 1px solid #475569; border-radius: 6px; padding: 8px 12px; font-family: ui-monospace, monospace; min-width: 180px;
}
.progress { display: flex; gap: 6px; margin-bottom: 18px; }
.progress > div { flex: 1; height: 4px; border-radius: 2px; background: #475569; }
.progress > div.done { background: var(--ok); }
.progress > div.current { background: var(--accent); }
.hint { color: var(--warn); margin-top: 8px; font-size: 0.95em; }
.code { background: var(--code-bg); border-left: 3px solid #c084fc; border-radius: 4px; padding: 10px 14px; font-family: ui-monospace, monospace; font-size: 0.92em; white-space: pre; overflow-x: auto; }
.banner { background: #1e40af; color: #dbeafe; padding: 10px 16px; border-radius: 6px; margin: 12px 0; }
.modal-bg { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 100; }
.modal { background: var(--panel); border-radius: 10px; padding: 24px; max-width: 720px; width: 90%; max-height: 80vh; overflow: auto; }
```

- [ ] **Step 3: Write `core/templates/core/base.html`**

```django
{% load static %}
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{% block title %}cloak{% endblock %}</title>
  <link rel="stylesheet" href="{% static 'core/style.css' %}">
  <script defer src="{% static 'vendor/htmx.min.js' %}"></script>
  <script defer src="{% static 'vendor/alpine.min.js' %}"></script>
</head>
<body>
  <header class="site">
    <a href="{% url 'landing' %}"><strong>cloak</strong></a>
    <nav>
      {% if user.is_authenticated %}
        <a href="{% url 'dashboard' %}">{{ user.email|default:user.username }}</a>
        <form method="post" action="{% url 'logout' %}" style="display:inline">
          {% csrf_token %}
          <button class="btn secondary" type="submit">Log out</button>
        </form>
      {% else %}
        <a class="btn secondary" href="{% url 'login' %}">Log in</a>
        <a class="btn" href="{% url 'signup' %}">Sign up</a>
      {% endif %}
    </nav>
  </header>
  <main>{% block content %}{% endblock %}</main>
</body>
</html>
```

- [ ] **Step 4: Confirm template loads via `manage.py check`**

```bash
DJANGO_SECRET_KEY=test .venv/bin/python manage.py check
```

Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add static/core/ static/vendor/ core/templates/
git commit -m "feat: base template + theme + vendored htmx/alpine"
```

---

## Task 16: Landing page

**Files:**
- Modify: `core/views.py`
- Modify: `core/urls.py`
- Create: `core/templates/core/landing.html`
- Create: `core/tests/test_views.py`

- [ ] **Step 1: Write failing test**

Create `core/tests/test_views.py`:

```python
import pytest
from django.urls import reverse
from core.models import Algorithm


@pytest.mark.django_db
def test_landing_lists_live_algorithm(client):
    Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    resp = client.get(reverse("landing"))
    assert resp.status_code == 200
    assert b"RSA" in resp.content
    assert b"More algorithms coming soon" in resp.content


@pytest.mark.django_db
def test_landing_dims_coming_soon(client):
    Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    resp = client.get(reverse("landing"))
    # The 'more coming soon' placeholder is rendered with class "muted" — assert it's present.
    assert b'class="card muted"' in resp.content
```

- [ ] **Step 2: Run to verify failure**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_views.py -v
```

Expected: template missing or content mismatch.

- [ ] **Step 3: Replace `core/views.py`**

```python
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404
from .models import Algorithm, Lesson, UserProgress


def landing(request):
    algorithms = list(Algorithm.objects.filter(status="live"))
    return render(request, "core/landing.html", {"algorithms": algorithms})


def algorithm_intro(request, slug):
    algorithm = get_object_or_404(Algorithm, slug=slug, status="live")
    lesson = algorithm.lessons.order_by("order").first()
    return render(request, "core/algorithm_intro.html", {
        "algorithm": algorithm,
        "lesson": lesson,
    })


def lesson_runner(request, algo_slug, lesson_slug):
    algorithm = get_object_or_404(Algorithm, slug=algo_slug, status="live")
    lesson = get_object_or_404(Lesson, algorithm=algorithm, slug=lesson_slug)
    steps = list(lesson.steps.order_by("order"))
    progress = None
    if request.user.is_authenticated:
        progress, _ = UserProgress.objects.get_or_create(
            user=request.user, lesson=lesson,
            defaults={"current_step_order": 1, "state": {}},
        )
    return render(request, "core/lesson.html", {
        "algorithm": algorithm,
        "lesson": lesson,
        "steps": steps,
        "progress": progress,
    })


@login_required
def dashboard(request):
    rows = UserProgress.objects.filter(user=request.user).select_related("lesson__algorithm")
    return render(request, "core/dashboard.html", {"rows": rows})
```

- [ ] **Step 4: Update `core/urls.py`**

```python
from django.urls import path
from . import views

urlpatterns = [
    path("", views.landing, name="landing"),
    path("algorithms/<slug:slug>/", views.algorithm_intro, name="algorithm_intro"),
    path("algorithms/<slug:algo_slug>/learn/<slug:lesson_slug>/", views.lesson_runner, name="lesson_runner"),
    path("me/progress/", views.dashboard, name="dashboard"),
]
```

- [ ] **Step 5: Write `core/templates/core/landing.html`**

```django
{% extends "core/base.html" %}
{% block title %}cloak — learn cryptography by doing it{% endblock %}
{% block content %}
<h1>Learn cryptography by doing the math.</h1>
<p>Pick an algorithm. Walk through it step by step. Get the Python code as you go.</p>

<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;margin-top:24px;">
  {% for algo in algorithms %}
    <a class="card" href="{% url 'algorithm_intro' algo.slug %}" style="text-decoration:none;color:inherit;">
      <h3>{{ algo.name }}</h3>
      <p style="color:var(--muted)">{{ algo.get_family_display }}</p>
    </a>
  {% endfor %}
  <div class="card muted">
    <h3>More algorithms coming soon</h3>
    <p style="color:var(--muted)">DES, Blowfish, post-quantum — once RSA is live.</p>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 6: Run tests**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_views.py -v
```

Expected: 2 tests pass.

- [ ] **Step 7: Commit**

```bash
git add core/views.py core/urls.py core/templates/core/landing.html core/tests/test_views.py
git commit -m "feat: landing page with algorithm picker"
```

---

## Task 17: Algorithm intro page

**Files:**
- Create: `core/templates/core/algorithm_intro.html`
- Modify: `core/tests/test_views.py` (append)

- [ ] **Step 1: Append to `core/tests/test_views.py`**

```python
@pytest.mark.django_db
def test_algorithm_intro_renders(client):
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    from core.models import Lesson
    Lesson.objects.create(algorithm=algo, slug="encrypt-decrypt", title="Encrypt & Decrypt", order=1)
    resp = client.get(reverse("algorithm_intro", args=["rsa"]))
    assert resp.status_code == 200
    assert b"RSA" in resp.content
    assert b"Start the lesson" in resp.content


@pytest.mark.django_db
def test_algorithm_intro_404_for_coming_soon(client):
    Algorithm.objects.create(slug="des", name="DES", family="symmetric", status="coming-soon", order=2)
    resp = client.get(reverse("algorithm_intro", args=["des"]))
    assert resp.status_code == 404
```

- [ ] **Step 2: Run to verify failure**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_views.py -v
```

Expected: template missing.

- [ ] **Step 3: Write `core/templates/core/algorithm_intro.html`**

```django
{% extends "core/base.html" %}
{% block title %}{{ algorithm.name }} — cloak{% endblock %}
{% block content %}
<h1>{{ algorithm.name }}</h1>
<p style="color:var(--muted)">{{ algorithm.get_family_display }} encryption</p>

{% if algorithm.slug == "rsa" %}
  <div class="card">
    <h3>The idea</h3>
    <p>RSA is an <em>asymmetric</em> cipher: anyone can encrypt with your public key, but only you (holding the private key) can decrypt. Its security rests on the difficulty of factoring large numbers.</p>
  </div>
  <div class="card">
    <h3>The cast</h3>
    <ul>
      <li><code>p</code>, <code>q</code> — two primes (your secret)</li>
      <li><code>n = p·q</code> — modulus (public)</li>
      <li><code>φ(n) = (p-1)(q-1)</code> — Euler's totient</li>
      <li><code>e</code> — public exponent (coprime to φ)</li>
      <li><code>d</code> — private exponent (e⁻¹ mod φ)</li>
    </ul>
  </div>
{% endif %}

{% if lesson %}
  <p><a class="btn" href="{% url 'lesson_runner' algorithm.slug lesson.slug %}">Start the lesson</a></p>
{% endif %}
{% endblock %}
```

- [ ] **Step 4: Run tests**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_views.py -v
```

Expected: 4 tests pass total in this file.

- [ ] **Step 5: Commit**

```bash
git add core/templates/core/algorithm_intro.html core/tests/test_views.py
git commit -m "feat: algorithm intro page (RSA concept overview)"
```

---

## Task 18: Lesson wizard template + runtime

**Files:**
- Create: `core/templates/core/lesson.html`
- Create: `static/core/wizard.js`

The wizard renders all steps server-side but Alpine shows only `current_step_order` at a time. JS dynamically imports the algorithm's validator + codegen modules by slug.

- [ ] **Step 1: Write `static/core/wizard.js`**

```javascript
export async function loadAlgorithmModules(slug) {
  const base = `/static/algorithms/${slug}`;
  const [validators, codegen] = await Promise.all([
    import(`${base}/validators.js`),
    import(`${base}/codegen.js`),
  ]);
  return { validators, codegen };
}

export function wizardComponent(initial) {
  // initial = { algorithmSlug, lessonSlug, steps, state, currentStepOrder, loggedIn, csrf }
  return {
    algorithmSlug: initial.algorithmSlug,
    lessonSlug: initial.lessonSlug,
    steps: initial.steps,
    state: initial.state || {},
    currentStepOrder: initial.currentStepOrder || 1,
    inputValue: "",
    multiInput: {},
    hint: "",
    fullScriptOpen: false,
    fullScript: "",
    validators: null,
    codegen: null,
    coprimeOptions: [],
    inlineCode: "",

    async init() {
      const mods = await loadAlgorithmModules(this.algorithmSlug);
      this.validators = mods.validators;
      this.codegen = mods.codegen;
      this.refreshInlineCode();
      this.maybeRefreshCoprimeOptions();
      this.persistLocal();
    },

    get currentStep() {
      return this.steps.find((s) => s.order === this.currentStepOrder);
    },
    get progressBar() {
      return this.steps.map((s) => {
        if (s.order < this.currentStepOrder) return "done";
        if (s.order === this.currentStepOrder) return "current";
        return "pending";
      });
    },
    get isLast() {
      return this.currentStepOrder >= this.steps.length;
    },

    refreshInlineCode() {
      const step = this.currentStep;
      if (!step || !this.codegen) { this.inlineCode = ""; return; }
      const fn = this.codegen[step.codegen_key];
      this.inlineCode = (fn && this.stepValuesPresent(step)) ? fn(this.state) : "";
    },

    stepValuesPresent(step) {
      const map = {
        pick_pq: ["p", "q"], compute_n: ["n"], compute_phi: ["phi"],
        pick_e: ["e"], compute_d: ["d"], pick_message: ["m"],
        encrypt: ["c"], decrypt: ["m_decrypted"], info: [],
      };
      const keys = map[step.codegen_key] || [];
      return keys.every((k) => k in this.state);
    },

    maybeRefreshCoprimeOptions() {
      if (this.currentStep?.kind === "choose-from-list" && this.currentStep.slug === "pick-e" && "phi" in this.state) {
        import(`/static/algorithms/${this.algorithmSlug}/math.js`).then((m) => {
          this.coprimeOptions = m.coprimeCandidates(BigInt(this.state.phi), 12).map((b) => Number(b));
        });
      }
    },

    async check() {
      const step = this.currentStep;
      if (!step) return;
      const input = step.kind === "input-multi" ? { ...this.multiInput } : this.inputValue;
      const fn = this.validators[step.validator_key];
      const result = fn(input, this.state);
      if (!result.ok) { this.hint = result.hint; return; }
      this.hint = "";
      this.state = { ...this.state, ...result.value };
      this.refreshInlineCode();
      this.advance();
    },

    advance() {
      if (this.currentStepOrder < this.steps.length) {
        this.currentStepOrder += 1;
      } else {
        this.currentStepOrder = this.steps.length;
      }
      this.inputValue = "";
      this.multiInput = {};
      this.hint = "";
      this.refreshInlineCode();
      this.maybeRefreshCoprimeOptions();
      this.persistLocal();
      this.syncServer();
    },

    back() {
      if (this.currentStepOrder > 1) {
        this.currentStepOrder -= 1;
        this.hint = "";
        this.refreshInlineCode();
        this.maybeRefreshCoprimeOptions();
      }
    },

    showFullScript() {
      this.fullScript = this.codegen.full_script(this.state);
      this.fullScriptOpen = true;
    },

    copyFullScript() {
      navigator.clipboard.writeText(this.fullScript);
    },

    downloadFullScript() {
      const blob = new Blob([this.fullScript], { type: "text/x-python" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `${this.algorithmSlug}_lesson.py`; a.click();
      URL.revokeObjectURL(url);
    },

    persistLocal() {
      const key = `cloak.progress.${this.algorithmSlug}.${this.lessonSlug}`;
      localStorage.setItem(key, JSON.stringify({
        state: this.state,
        current_step_order: this.currentStepOrder,
        updated_at: new Date().toISOString(),
      }));
    },

    async syncServer() {
      if (!initial.loggedIn) return;
      const csrf = document.querySelector("meta[name=csrf-token]")?.content;
      await fetch(`/api/progress/${this.lessonSlug}/`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
        body: JSON.stringify({ state: this.state, current_step_order: this.currentStepOrder }),
      });
    },
  };
}

window.wizardComponent = wizardComponent;
```

- [ ] **Step 2: Write `core/templates/core/lesson.html`**

```django
{% extends "core/base.html" %}
{% load static %}
{% block title %}{{ algorithm.name }} — {{ lesson.title }}{% endblock %}
{% block content %}
<script type="module" src="{% static 'core/wizard.js' %}"></script>

{{ initial_data|json_script:"cloak-init-data" }}

<div x-data="wizardComponent(JSON.parse(document.getElementById('cloak-init-data').textContent))" x-init="init()">

  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
    <h2 style="margin:0">{{ algorithm.name }} — {{ lesson.title }}</h2>
    <button class="btn secondary" @click="showFullScript()">Show full script</button>
  </div>

  <div class="progress">
    <template x-for="(state, idx) in progressBar" :key="idx">
      <div :class="state"></div>
    </template>
  </div>

  <template x-for="step in steps" :key="step.order">
    <div x-show="step.order === currentStepOrder" class="card">
      <div x-html="step.prompt_html"></div>

      <template x-if="step.kind === 'input-numeric'">
        <div style="margin-top:12px;">
          <input type="text" x-model="inputValue" placeholder="your answer" @keydown.enter="check()">
          <button class="btn" @click="check()">Check</button>
        </div>
      </template>

      <template x-if="step.kind === 'input-multi'">
        <div style="margin-top:12px;display:flex;gap:8px;align-items:center;">
          <span>p =</span><input type="text" x-model="multiInput.p" style="min-width:90px">
          <span>q =</span><input type="text" x-model="multiInput.q" style="min-width:90px">
          <button class="btn" @click="check()">Check</button>
        </div>
      </template>

      <template x-if="step.kind === 'choose-from-list'">
        <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:8px;">
          <template x-for="opt in coprimeOptions" :key="opt">
            <button class="btn secondary" @click="inputValue = String(opt); check()" x-text="opt"></button>
          </template>
        </div>
      </template>

      <template x-if="step.kind === 'info'">
        <div style="margin-top:12px;">
          <button class="btn" @click="advance()" x-text="isLast ? 'Done' : 'Continue'"></button>
        </div>
      </template>

      <div x-show="hint" x-text="hint" class="hint"></div>

      <div x-show="inlineCode" style="margin-top:14px;">
        <div style="color:var(--muted);font-size:0.8em;margin-bottom:4px;">Python for this step</div>
        <div class="code" x-text="inlineCode"></div>
      </div>
    </div>
  </template>

  <div style="display:flex;justify-content:space-between;margin-top:8px;">
    <button class="btn secondary" @click="back()" :disabled="currentStepOrder === 1">← Back</button>
    <span style="color:var(--muted)" x-text="`Step ${currentStepOrder} of ${steps.length}`"></span>
  </div>

  <template x-if="!{{ user.is_authenticated|yesno:'true,false' }} && currentStepOrder >= 3">
    <div class="banner">
      Save your progress: <a href="{% url 'signup' %}" style="color:#fff;text-decoration:underline">sign up</a> or
      <a href="{% url 'login' %}" style="color:#fff;text-decoration:underline">log in</a>.
    </div>
  </template>

  <div class="modal-bg" x-show="fullScriptOpen" @click.self="fullScriptOpen = false">
    <div class="modal">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <h3 style="margin:0">{{ algorithm.slug }}_lesson.py</h3>
        <div>
          <button class="btn secondary" @click="copyFullScript()">Copy</button>
          <button class="btn" @click="downloadFullScript()">Download</button>
          <button class="btn secondary" @click="fullScriptOpen = false">Close</button>
        </div>
      </div>
      <pre class="code" style="margin-top:12px;" x-text="fullScript"></pre>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 3: Update `core/views.py:lesson_runner` to pass steps as JSON-safe data**

Replace the `lesson_runner` function in `core/views.py` with:

```python
def lesson_runner(request, algo_slug, lesson_slug):
    import json
    from django.utils.html import escape
    import markdown as md_lib  # added in step 4
    algorithm = get_object_or_404(Algorithm, slug=algo_slug, status="live")
    lesson = get_object_or_404(Lesson, algorithm=algorithm, slug=lesson_slug)
    db_steps = list(lesson.steps.order_by("order"))
    progress = None
    state = {}
    current = 1
    if request.user.is_authenticated:
        progress, _ = UserProgress.objects.get_or_create(
            user=request.user, lesson=lesson,
            defaults={"current_step_order": 1, "state": {}},
        )
        state = progress.state or {}
        current = progress.current_step_order or 1

    def render_prompt(template_str, state_for_render):
        from django.template import Context, Template
        rendered = Template(template_str).render(Context({"state": state_for_render}))
        return md_lib.markdown(rendered)

    steps_payload = [
        {
            "order": s.order,
            "slug": s.slug,
            "kind": s.kind,
            "validator_key": s.validator_key,
            "codegen_key": s.codegen_key,
            "prompt_html": render_prompt(s.prompt_template, state),
        }
        for s in db_steps
    ]

    return render(request, "core/lesson.html", {
        "algorithm": algorithm,
        "lesson": lesson,
        "progress": progress,
        "initial_data": {
            "algorithmSlug": algorithm.slug,
            "lessonSlug": lesson.slug,
            "steps": steps_payload,
            "state": state,
            "currentStepOrder": current,
            "loggedIn": request.user.is_authenticated,
        },
    })
```

- [ ] **Step 4: Add `markdown` to `requirements.txt` and install**

```
markdown>=3.6
```

Then:

```bash
.venv/bin/pip install -r requirements.txt
```

- [ ] **Step 5: Manual smoke test**

```bash
DJANGO_SECRET_KEY=test .venv/bin/python manage.py migrate
DJANGO_SECRET_KEY=test .venv/bin/python manage.py loaddata algorithms/rsa/fixtures.json
DJANGO_SECRET_KEY=test .venv/bin/python manage.py runserver 0.0.0.0:8000 &
sleep 2
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/algorithms/rsa/learn/encrypt-decrypt/
kill %1
```

Expected: `200`.

- [ ] **Step 6: Commit**

```bash
git add core/templates/core/lesson.html static/core/wizard.js core/views.py requirements.txt
git commit -m "feat: lesson wizard with Alpine runtime + per-step inline Python"
```

---

## Task 19: Progress API + defensive validation

**Files:**
- Create: `core/api.py`, `core/api_urls.py`, `core/serializers.py`
- Create: `core/progress_service.py`
- Create: `core/tests/test_api.py`

- [ ] **Step 1: Write failing API tests**

Create `core/tests/test_api.py`:

```python
import json
import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from core.models import Algorithm, Lesson, Step, UserProgress


@pytest.fixture
def rsa_lesson(db):
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    lesson = Lesson.objects.create(algorithm=algo, slug="encrypt-decrypt", title="t", order=1)
    for i, slug in enumerate(["pick-pq", "compute-n"], start=1):
        Step.objects.create(lesson=lesson, order=i, slug=slug, kind="info",
                            prompt_template="x", validator_key=slug.replace("-", "_"), codegen_key=slug.replace("-", "_"))
    return lesson


@pytest.fixture
def logged_in_client(client, db):
    User = get_user_model()
    user = User.objects.create_user(username="u", email="u@e.com", password="pw")
    client.force_login(user)
    return client, user


@pytest.mark.django_db
def test_post_progress_creates_row(logged_in_client, rsa_lesson):
    client, user = logged_in_client
    resp = client.post(
        f"/api/progress/{rsa_lesson.slug}/",
        data=json.dumps({"state": {"p": 61, "q": 53}, "current_step_order": 2}),
        content_type="application/json",
    )
    assert resp.status_code == 200, resp.content
    progress = UserProgress.objects.get(user=user, lesson=rsa_lesson)
    assert progress.state == {"p": 61, "q": 53}
    assert progress.current_step_order == 2


@pytest.mark.django_db
def test_post_progress_rejects_tampered_state(logged_in_client, rsa_lesson):
    client, _ = logged_in_client
    # Claim phi inconsistent with p, q
    resp = client.post(
        f"/api/progress/{rsa_lesson.slug}/",
        data=json.dumps({"state": {"p": 61, "q": 53, "n": 9999}, "current_step_order": 3}),
        content_type="application/json",
    )
    assert resp.status_code == 400


@pytest.mark.django_db
def test_get_progress(logged_in_client, rsa_lesson):
    client, user = logged_in_client
    UserProgress.objects.create(user=user, lesson=rsa_lesson, current_step_order=2, state={"p": 7, "q": 11})
    resp = client.get(f"/api/progress/{rsa_lesson.slug}/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == {"p": 7, "q": 11}
    assert body["current_step_order"] == 2


@pytest.mark.django_db
def test_anonymous_blocked(client, rsa_lesson):
    resp = client.get(f"/api/progress/{rsa_lesson.slug}/")
    assert resp.status_code in (401, 403)


@pytest.mark.django_db
def test_import_merges_localstorage(logged_in_client, rsa_lesson):
    client, user = logged_in_client
    payload = {
        "items": [
            {"lesson_slug": rsa_lesson.slug, "state": {"p": 61, "q": 53}, "current_step_order": 2},
        ]
    }
    resp = client.post("/api/progress/import/", data=json.dumps(payload), content_type="application/json")
    assert resp.status_code == 200
    progress = UserProgress.objects.get(user=user, lesson=rsa_lesson)
    assert progress.current_step_order == 2
```

- [ ] **Step 2: Write `core/serializers.py`**

```python
from rest_framework import serializers
from .models import UserProgress


class ProgressPayloadSerializer(serializers.Serializer):
    state = serializers.JSONField()
    current_step_order = serializers.IntegerField(min_value=1)


class ImportItemSerializer(serializers.Serializer):
    lesson_slug = serializers.SlugField()
    state = serializers.JSONField()
    current_step_order = serializers.IntegerField(min_value=1)


class ImportPayloadSerializer(serializers.Serializer):
    items = ImportItemSerializer(many=True)
```

- [ ] **Step 3: Write `core/progress_service.py`**

```python
from .algorithm_loader import get_validators, AlgorithmNotFound


# Mapping of state-key dependencies for re-validating arrived state.
# Each entry: validator_key -> list of (input_extractor, state_keys_required)
# For simplicity we re-run a known sequence per algorithm.
_RSA_SEQUENCE = [
    # (validator_key, lambda state -> input, required_state_keys_for_check)
    ("pick_pq",      lambda s: {"p": s.get("p"), "q": s.get("q")}, ["p", "q"]),
    ("compute_n",    lambda s: str(s.get("n", "")),                 ["n", "p", "q"]),
    ("compute_phi",  lambda s: str(s.get("phi", "")),               ["phi", "p", "q"]),
    ("pick_e",       lambda s: str(s.get("e", "")),                 ["e", "phi"]),
    ("compute_d",    lambda s: str(s.get("d", "")),                 ["d", "e", "phi"]),
    ("pick_message", lambda s: str(s.get("m", "")),                 ["m", "n"]),
    ("encrypt",      lambda s: str(s.get("c", "")),                 ["c", "m", "e", "n"]),
    ("decrypt",      lambda s: str(s.get("m_decrypted", "")),       ["m_decrypted", "c", "d", "n"]),
]

_SEQUENCES = {"rsa": _RSA_SEQUENCE}


def validate_state(algorithm_slug: str, state: dict) -> tuple[bool, str]:
    """Re-run the algorithm's validator sequence against the claimed state.
    Returns (ok, error_message). Skips validators whose state keys aren't all present.
    """
    try:
        validators = get_validators(algorithm_slug)
    except AlgorithmNotFound as e:
        return False, str(e)
    seq = _SEQUENCES.get(algorithm_slug)
    if not seq:
        return True, ""  # no sequence defined: accept
    for key, input_fn, required in seq:
        if not all(k in state for k in required):
            continue
        result = getattr(validators, key)(input_fn(state), state)
        if not result["ok"]:
            return False, f"step {key}: {result['hint']}"
    return True, ""
```

- [ ] **Step 4: Write `core/api.py`**

```python
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import Lesson, UserProgress
from .serializers import ProgressPayloadSerializer, ImportPayloadSerializer
from .progress_service import validate_state


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def progress_detail(request, lesson_slug):
    lesson = get_object_or_404(Lesson, slug=lesson_slug)
    if request.method == "GET":
        progress, _ = UserProgress.objects.get_or_create(
            user=request.user, lesson=lesson,
            defaults={"current_step_order": 1, "state": {}},
        )
        return Response({
            "state": progress.state,
            "current_step_order": progress.current_step_order,
        })

    serializer = ProgressPayloadSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    state = serializer.validated_data["state"]
    current = serializer.validated_data["current_step_order"]

    ok, err = validate_state(lesson.algorithm.slug, state)
    if not ok:
        return Response({"detail": err}, status=status.HTTP_400_BAD_REQUEST)

    progress, _ = UserProgress.objects.update_or_create(
        user=request.user, lesson=lesson,
        defaults={"state": state, "current_step_order": current},
    )
    return Response({"state": progress.state, "current_step_order": progress.current_step_order})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def progress_import(request):
    serializer = ImportPayloadSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    imported = []
    skipped = []
    for item in serializer.validated_data["items"]:
        try:
            lesson = Lesson.objects.get(slug=item["lesson_slug"])
        except Lesson.DoesNotExist:
            skipped.append(item["lesson_slug"])
            continue
        ok, _ = validate_state(lesson.algorithm.slug, item["state"])
        if not ok:
            skipped.append(item["lesson_slug"])
            continue
        existing = UserProgress.objects.filter(user=request.user, lesson=lesson).first()
        if existing and existing.current_step_order >= item["current_step_order"]:
            continue
        UserProgress.objects.update_or_create(
            user=request.user, lesson=lesson,
            defaults={"state": item["state"], "current_step_order": item["current_step_order"]},
        )
        imported.append(item["lesson_slug"])
    return Response({"imported": imported, "skipped": skipped})
```

- [ ] **Step 5: Write `core/api_urls.py`**

```python
from django.urls import path
from . import api

urlpatterns = [
    path("progress/import/", api.progress_import, name="api_progress_import"),
    path("progress/<slug:lesson_slug>/", api.progress_detail, name="api_progress_detail"),
]
```

- [ ] **Step 6: Run tests**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_api.py -v
```

Expected: 5 tests pass.

- [ ] **Step 7: Commit**

```bash
git add core/api.py core/api_urls.py core/serializers.py core/progress_service.py core/tests/test_api.py
git commit -m "feat: progress API + defensive backend validation"
```

---

## Task 20: Signup view + guest progress import on login

**Files:**
- Create: `accounts/forms.py`, `accounts/views.py`, `accounts/urls.py`
- Create: `accounts/templates/registration/login.html`, `signup.html`, `logged_out.html`
- Create: `accounts/tests/__init__.py`, `accounts/tests/test_signup.py`
- Create: `static/core/import-on-login.js`
- Modify: `core/templates/core/base.html` (include import-on-login.js)

- [ ] **Step 1: Write failing signup test**

Create `accounts/tests/__init__.py` (empty), then `accounts/tests/test_signup.py`:

```python
import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse


@pytest.mark.django_db
def test_signup_creates_user(client):
    resp = client.post(reverse("signup"), {
        "username": "alice",
        "email": "alice@example.com",
        "password1": "correcthorsebattery",
        "password2": "correcthorsebattery",
    })
    assert resp.status_code in (302, 200)
    User = get_user_model()
    assert User.objects.filter(username="alice").exists()


@pytest.mark.django_db
def test_signup_rejects_mismatched_passwords(client):
    resp = client.post(reverse("signup"), {
        "username": "alice", "email": "a@b.com",
        "password1": "correcthorsebattery", "password2": "wrong",
    })
    User = get_user_model()
    assert not User.objects.filter(username="alice").exists()
    assert resp.status_code == 200
```

- [ ] **Step 2: Write `accounts/forms.py`**

```python
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model


class SignupForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta(UserCreationForm.Meta):
        model = get_user_model()
        fields = ("username", "email")
```

- [ ] **Step 3: Write `accounts/views.py`**

```python
from django.contrib.auth import login
from django.shortcuts import redirect, render
from .forms import SignupForm


def signup(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect("dashboard")
    else:
        form = SignupForm()
    return render(request, "registration/signup.html", {"form": form})
```

- [ ] **Step 4: Write `accounts/urls.py`**

```python
from django.urls import path
from . import views

urlpatterns = [
    path("signup/", views.signup, name="signup"),
]
```

- [ ] **Step 5: Write templates**

`accounts/templates/registration/login.html`:

```django
{% extends "core/base.html" %}
{% block title %}Log in — cloak{% endblock %}
{% block content %}
<h1>Log in</h1>
<form method="post">
  {% csrf_token %}
  {{ form.as_p }}
  <button type="submit" class="btn">Log in</button>
</form>
<p>No account? <a href="{% url 'signup' %}">Sign up</a>.</p>
{% endblock %}
```

`accounts/templates/registration/signup.html`:

```django
{% extends "core/base.html" %}
{% block title %}Sign up — cloak{% endblock %}
{% block content %}
<h1>Sign up</h1>
<form method="post">
  {% csrf_token %}
  {{ form.as_p }}
  <button type="submit" class="btn">Create account</button>
</form>
{% endblock %}
```

`accounts/templates/registration/logged_out.html`:

```django
{% extends "core/base.html" %}
{% block content %}
<h1>Logged out.</h1>
<p><a href="{% url 'landing' %}">Back to home</a></p>
{% endblock %}
```

- [ ] **Step 6: Write `static/core/import-on-login.js`**

```javascript
(function () {
  if (!window.CLOAK_LOGGED_IN) return;
  if (sessionStorage.getItem("cloak.import_attempted")) return;
  const items = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (!key.startsWith("cloak.progress.")) continue;
    const [, , algo, lesson] = key.split(".");
    try {
      const parsed = JSON.parse(localStorage.getItem(key));
      items.push({ lesson_slug: lesson, state: parsed.state, current_step_order: parsed.current_step_order });
    } catch {}
  }
  if (items.length === 0) {
    sessionStorage.setItem("cloak.import_attempted", "1");
    return;
  }
  const csrf = document.querySelector("meta[name=csrf-token]")?.content;
  fetch("/api/progress/import/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
    body: JSON.stringify({ items }),
  }).then((r) => {
    if (r.ok) {
      for (const it of items) localStorage.removeItem(`cloak.progress.rsa.${it.lesson_slug}`);
    }
    sessionStorage.setItem("cloak.import_attempted", "1");
  });
})();
```

- [ ] **Step 7: Inject CSRF meta + import script into `base.html`**

In `core/templates/core/base.html`, replace the `<head>` block's contents with:

```django
{% load static %}
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="csrf-token" content="{{ csrf_token }}">
  <title>{% block title %}cloak{% endblock %}</title>
  <link rel="stylesheet" href="{% static 'core/style.css' %}">
  <script defer src="{% static 'vendor/htmx.min.js' %}"></script>
  <script defer src="{% static 'vendor/alpine.min.js' %}"></script>
  <script>window.CLOAK_LOGGED_IN = {{ user.is_authenticated|yesno:'true,false' }};</script>
  <script defer src="{% static 'core/import-on-login.js' %}"></script>
</head>
```

- [ ] **Step 8: Run tests**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest accounts/tests/ -v
```

Expected: 2 tests pass.

- [ ] **Step 9: Commit**

```bash
git add accounts/ static/core/import-on-login.js core/templates/core/base.html
git commit -m "feat: signup + auto-import of localStorage progress on login"
```

---

## Task 21: Dashboard

**Files:**
- Create: `core/templates/core/dashboard.html`
- Modify: `core/tests/test_views.py` (append)

- [ ] **Step 1: Append dashboard test**

Add to `core/tests/test_views.py`:

```python
@pytest.mark.django_db
def test_dashboard_lists_progress(client):
    from django.contrib.auth import get_user_model
    from core.models import Lesson, UserProgress
    User = get_user_model()
    user = User.objects.create_user(username="u", email="u@e.com", password="pw")
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    lesson = Lesson.objects.create(algorithm=algo, slug="encrypt-decrypt", title="Encrypt & Decrypt", order=1)
    UserProgress.objects.create(user=user, lesson=lesson, current_step_order=4, state={"p": 61})
    client.force_login(user)
    resp = client.get(reverse("dashboard"))
    assert resp.status_code == 200
    assert b"RSA" in resp.content
    assert b"Encrypt &amp; Decrypt" in resp.content


@pytest.mark.django_db
def test_dashboard_redirects_anonymous(client):
    resp = client.get(reverse("dashboard"))
    assert resp.status_code == 302
```

- [ ] **Step 2: Write `core/templates/core/dashboard.html`**

```django
{% extends "core/base.html" %}
{% block title %}Your progress — cloak{% endblock %}
{% block content %}
<h1>Your progress</h1>

{% if rows %}
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;">
    {% for row in rows %}
      <a class="card" href="{% url 'lesson_runner' row.lesson.algorithm.slug row.lesson.slug %}" style="text-decoration:none;color:inherit;">
        <h3>{{ row.lesson.algorithm.name }} — {{ row.lesson.title }}</h3>
        <p style="color:var(--muted)">Step {{ row.current_step_order }}{% if row.completed_at %} · completed{% endif %}</p>
      </a>
    {% endfor %}
  </div>
{% else %}
  <p>You haven't started any lessons yet. <a href="{% url 'landing' %}">Pick one to start.</a></p>
{% endif %}

<h2 style="margin-top:32px;">Coming soon</h2>
<div class="card muted">
  <p>More algorithms after RSA — pick the next direction once we're live.</p>
</div>
{% endblock %}
```

- [ ] **Step 3: Run tests**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_views.py -v
```

Expected: 6 tests pass total in this file.

- [ ] **Step 4: Commit**

```bash
git add core/templates/core/dashboard.html core/tests/test_views.py
git commit -m "feat: user dashboard listing progress"
```

---

## Task 22: End-to-end smoke test

**Files:**
- Create: `core/tests/test_e2e.py`

- [ ] **Step 1: Write the e2e test**

```python
import json
import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.urls import reverse
from core.models import UserProgress


@pytest.fixture
def rsa_loaded(db):
    call_command("loaddata", "algorithms/rsa/fixtures.json")


@pytest.mark.django_db
def test_landing_intro_lesson_chain(client, rsa_loaded):
    assert client.get(reverse("landing")).status_code == 200
    assert client.get(reverse("algorithm_intro", args=["rsa"])).status_code == 200
    resp = client.get(reverse("lesson_runner", args=["rsa", "encrypt-decrypt"]))
    assert resp.status_code == 200
    assert b"RSA" in resp.content
    assert b"steps:" in resp.content or b'"order":' in resp.content  # JSON-embedded steps present


@pytest.mark.django_db
def test_logged_in_progress_full_rsa_flow(client, rsa_loaded):
    User = get_user_model()
    user = User.objects.create_user(username="u", email="u@e.com", password="pw")
    client.force_login(user)
    # Walk through each step via the API, posting consistent state.
    p, q = 61, 53
    n, phi_n = p * q, (p - 1) * (q - 1)
    e, d = 17, pow(17, -1, phi_n)
    m = 65
    c = pow(m, e, n)
    states = [
        {"p": p, "q": q},
        {"p": p, "q": q, "n": n},
        {"p": p, "q": q, "n": n, "phi": phi_n},
        {"p": p, "q": q, "n": n, "phi": phi_n, "e": e},
        {"p": p, "q": q, "n": n, "phi": phi_n, "e": e, "d": d},
        {"p": p, "q": q, "n": n, "phi": phi_n, "e": e, "d": d, "m": m},
        {"p": p, "q": q, "n": n, "phi": phi_n, "e": e, "d": d, "m": m, "c": c},
        {"p": p, "q": q, "n": n, "phi": phi_n, "e": e, "d": d, "m": m, "c": c, "m_decrypted": m},
    ]
    for i, state in enumerate(states, start=2):
        resp = client.post(
            "/api/progress/encrypt-decrypt/",
            data=json.dumps({"state": state, "current_step_order": i}),
            content_type="application/json",
        )
        assert resp.status_code == 200, f"step {i}: {resp.content}"
    final = UserProgress.objects.get(user=user, lesson__slug="encrypt-decrypt")
    assert final.current_step_order == 9
    assert final.state["m_decrypted"] == m
```

- [ ] **Step 2: Run the test**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest core/tests/test_e2e.py -v
```

Expected: 2 tests pass.

- [ ] **Step 3: Commit**

```bash
git add core/tests/test_e2e.py
git commit -m "test: end-to-end RSA flow through public URLs and API"
```

---

## Task 23: README runbook + final checks

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace `README.md`**

```markdown
# cloak

Teaching site for encryption algorithms. RSA first; more coming. Live at https://cloak.moosha.org.

## Local development

```
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp .env.example .env
# edit .env if needed

.venv/bin/python manage.py migrate
.venv/bin/python manage.py loaddata algorithms/rsa/fixtures.json
.venv/bin/python manage.py runserver
```

Visit http://localhost:8000/.

## Tests

```
.venv/bin/pytest             # Python tests
node --test static/algorithms/*/tests/*.test.js   # JS tests
```

JS-Python parity is enforced in `tests/test_parity.py`.

## Deploy (host with Caddy in front)

The artifact is `docker-compose.yml` + the `web` image (built from `Dockerfile`).

1. On the server, clone the repo and write `.env` (set `DJANGO_DEBUG=False`, real `DJANGO_SECRET_KEY`, real Postgres credentials).
2. `make up` → web container binds `127.0.0.1:8000`; Postgres lives in a sibling container.
3. Add a stanza to the host's Caddyfile:

   ```
   cloak.moosha.org {
       reverse_proxy 127.0.0.1:8000
   }
   ```

4. Reload Caddy.

The web container handles `migrate`, `loaddata algorithms/*/fixtures.json`, `collectstatic`, then runs gunicorn — see `entrypoint.sh`.

## Adding a new algorithm

The framework is data-driven. To add `foo`:

1. Create `algorithms/foo/{logic.py, validators.py, codegen.py, fixtures.json}`.
2. Create `static/algorithms/foo/{math.js, validators.js, codegen.js}` plus tests under `tests/`.
3. The validator + codegen keys named in `fixtures.json` must exist in both Python and JS modules.
4. `make loadalgos` (or rebuild the image).

No core code changes needed.

## Spec & plan

- Spec: [docs/superpowers/specs/2026-05-21-cloak-rsa-design.md](docs/superpowers/specs/2026-05-21-cloak-rsa-design.md)
- Plan: [docs/superpowers/plans/2026-05-21-cloak-rsa-mvp.md](docs/superpowers/plans/2026-05-21-cloak-rsa-mvp.md)
```

- [ ] **Step 2: Run the full test suite**

```bash
DJANGO_SECRET_KEY=test .venv/bin/pytest -v
node --test static/algorithms/*/tests/*.test.js
```

Expected: all tests pass.

- [ ] **Step 3: Confirm `manage.py check --deploy` flags only expected issues**

```bash
DJANGO_SECRET_KEY=test DJANGO_DEBUG=False .venv/bin/python manage.py check --deploy
```

Expected: warnings only about HSTS / SSL (those live in Caddy, not Django).

- [ ] **Step 4: Final commit**

```bash
git add README.md
git commit -m "docs: README runbook for local dev, tests, deploy, adding algorithms"
```

- [ ] **Step 5: Tag MVP**

```bash
git tag -a v0.1.0-rsa-mvp -m "RSA teaching site MVP — landing, lesson wizard, signup, dashboard, deploy artifact"
```

- [ ] **Step 6: Manual UI walk-through**

In a browser:
1. Visit `/` — confirm RSA card + "More algorithms coming soon" card visible
2. Click RSA → intro page renders
3. Click "Start the lesson" → wizard appears at step 1 (intro)
4. Click Continue → step 2 (pick p, q); enter 61 and 53 → advances; inline code shows `p, q = 61, 53`
5. Advance through all 9 steps using correct math
6. Open "Show full script" → modal shows full `.py`; Copy + Download work
7. Reload page → state persists (localStorage)
8. Sign up → progress imports to DB; visit `/me/progress/` → row appears
9. Log out, log in → progress remains in DB
