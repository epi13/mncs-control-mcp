from __future__ import annotations

import os
import re
from collections.abc import Iterable
from pathlib import Path

from .config import ControlConfig
from .errors import ControlError

_SENSITIVE_NAME = re.compile(
    r"(^|/)(\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|.*(?:token|secret|credential|password|cookie).*)$",
    re.IGNORECASE,
)
_SECRET_TEXT = re.compile(
    r"(?i)(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|(?:token|password|secret|api[_-]?key)\s*[=:]\s*)[^\s,;]+"
)
_SAFE_ENVIRONMENT = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "VIRTUAL_ENV",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "PYTHONUNBUFFERED",
    }
)


def canonical_projects_root(config: ControlConfig) -> Path:
    return config.projects_root.expanduser().resolve()


def resolve_repository(config: ControlConfig, repository: str) -> tuple[str, Path]:
    if not isinstance(repository, str) or not repository or len(repository) > 100:
        raise ControlError("INVALID_REPOSITORY", "repository must be an approved registry key")
    if repository not in config.repositories:
        raise ControlError("UNAUTHORIZED_REPOSITORY", f"repository is not approved: {repository}")
    name = config.repositories[repository]
    if Path(name).is_absolute() or ".." in Path(name).parts:
        raise ControlError("CONFIG_INVALID", f"approved repository escapes projects root: {repository}")
    root = canonical_projects_root(config)
    candidate = (root / name).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ControlError("PATH_ESCAPE", "repository path escapes the configured projects root") from exc
    return repository, candidate


def is_sensitive_name(value: str) -> bool:
    normalized = value.replace("\\", "/")
    return bool(_SENSITIVE_NAME.search(normalized) or normalized.startswith(".ssh/"))


def public_relative_path(root: Path, value: str) -> str | None:
    try:
        relative = Path(value).resolve().relative_to(root.resolve())
    except ValueError:
        return None
    rendered = relative.as_posix()
    return None if is_sensitive_name(rendered) else rendered


def filtered_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key in _SAFE_ENVIRONMENT}


def redact_text(value: str) -> str:
    return _SECRET_TEXT.sub("[REDACTED]", value)


def bounded_text(value: str, maximum: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= maximum:
        return redact_text(value), False
    clipped = encoded[:maximum].decode("utf-8", errors="ignore")
    return redact_text(clipped), True


def validate_component(component: str | None) -> str | None:
    if component is None or component == "":
        return None
    if not isinstance(component, str) or len(component) > 128 or component.startswith("-"):
        raise ControlError("INVALID_INPUT", "component must be a bounded test name")
    if any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-" for char in component):
        raise ControlError("INVALID_INPUT", "component contains unsupported characters")
    return component


def safe_names(values: Iterable[str]) -> tuple[list[str], int]:
    visible: list[str] = []
    omitted = 0
    for value in values:
        if is_sensitive_name(value):
            omitted += 1
        else:
            visible.append(value)
    return visible, omitted
