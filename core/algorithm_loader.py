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
