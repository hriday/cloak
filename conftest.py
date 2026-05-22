"""
Root conftest: patches Django settings before the test session starts.
- Swaps CompressedManifestStaticFilesStorage for plain StaticFilesStorage so
  templates with {% static %} tags work without a prior collectstatic run.
"""
from django.conf import settings as _django_settings


def pytest_sessionstart(session):
    _django_settings.STORAGES = {
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
