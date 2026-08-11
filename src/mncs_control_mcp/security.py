from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path

from .config import ControlConfig
from .errors import ControlError

_SENSITIVE_NAME = re.compile(
    r"(^|/)(\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|.*(?:token|secret|credential|password|cookie).*)$",
    re.IGNORECASE,
)
_SECRET_TEXT = re.compile(
    r"(?i)(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|"
    r"(?:token|password|secret|api[_-]?key|authorization)\s*[=:]\s*)[^\s,;]+"
)
_AUTH_TEXT = re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s'\"]+")
_SECRET_ENV = re.compile(r"(?i)(token|secret|password|credential|cookie|authorization|api[_-]?key|private[_-]?key)")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SAFE_HOST_ENVIRONMENT = frozenset({"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR"})


def canonical_projects_root(config: ControlConfig) -> Path:
    return config.workspace_root.expanduser().resolve()


def resolve_repository(config: ControlConfig, repository: str) -> tuple[str, Path]:
    """Resolve an MNCS alias. General workspace authorization lives in WorkspacePolicy."""
    if not isinstance(repository, str) or not repository or len(repository) > 100:
        raise ControlError("INVALID_REPOSITORY", "repository must be an MNCS registry key")
    if repository not in config.repositories:
        raise ControlError("UNAUTHORIZED_REPOSITORY", f"repository alias is unknown: {repository}")
    name = config.repositories[repository]
    root = canonical_projects_root(config)
    candidate = (root / name).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ControlError("PATH_ESCAPE", "MNCS repository path escapes the workspace") from exc
    return repository, candidate


def is_sensitive_name(value: str) -> bool:
    normalized = value.replace("\\", "/")
    return bool(_SENSITIVE_NAME.search(normalized) or normalized.startswith((".ssh/", ".gnupg/")))


def public_relative_path(root: Path, value: str) -> str | None:
    try:
        relative = Path(value).resolve().relative_to(root.resolve())
    except ValueError:
        return None
    rendered = relative.as_posix()
    return None if is_sensitive_name(rendered) else rendered


def filtered_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key in _SAFE_HOST_ENVIRONMENT}


def validate_environment(overrides: Mapping[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in overrides.items():
        if not _ENV_NAME.fullmatch(key) or _SECRET_ENV.search(key):
            raise ControlError("UNSAFE_ENVIRONMENT", f"environment override is not allowed: {key}")
        if len(value) > 8192 or "\x00" in value:
            raise ControlError("UNSAFE_ENVIRONMENT", f"environment value is invalid: {key}")
        result[key] = value
    return result


def redact_text(value: str) -> str:
    return _SECRET_TEXT.sub("[REDACTED]", _AUTH_TEXT.sub(r"\1[REDACTED]", value))


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
    if any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-/" for char in component):
        raise ControlError("INVALID_INPUT", "component contains unsupported characters")
    if ".." in Path(component).parts:
        raise ControlError("INVALID_INPUT", "component cannot traverse directories")
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
