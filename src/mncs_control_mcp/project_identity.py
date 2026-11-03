"""Resolve physical project directories to their manifest repository IDs."""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path

from .errors import ControlError

PROJECT_MANIFEST_MAX_BYTES = 512 * 1024
_REPOSITORY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}")
_PROJECT_SELECTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def project_repository_identity(
    project_root: Path, *, require_manifest: bool = False,
) -> str:
    """Read one bounded project manifest, retaining exact-name legacy roots."""
    try:
        root = project_root.expanduser().resolve(strict=True)
    except OSError as error:
        raise ControlError(
            "ENVIRONMENT_PROJECT_UNKNOWN", "project repository root is unavailable",
        ) from error
    if not root.is_dir():
        raise ControlError(
            "ENVIRONMENT_PROJECT_UNKNOWN", "project repository root is not a directory",
        )

    metadata = root / ".mncs"
    try:
        metadata_stat = metadata.lstat()
    except FileNotFoundError:
        if require_manifest:
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "a case-variant project selector requires a repository manifest",
                details={"path": str(root)},
            )
        return root.name
    except OSError as error:
        raise ControlError(
            "ENVIRONMENT_PROJECT_UNKNOWN", "project metadata could not be inspected",
        ) from error
    if not stat.S_ISDIR(metadata_stat.st_mode):
        raise ControlError(
            "ENVIRONMENT_WORKSPACE_ESCAPE", "project metadata must be a real directory",
        )

    manifest_path = metadata / "project.json"
    try:
        manifest_stat = manifest_path.lstat()
    except FileNotFoundError:
        if require_manifest:
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "a case-variant project selector requires a repository manifest",
                details={"path": str(root)},
            )
        return root.name
    except OSError as error:
        raise ControlError(
            "ENVIRONMENT_PROJECT_UNKNOWN", "project manifest could not be inspected",
        ) from error
    if not stat.S_ISREG(manifest_stat.st_mode):
        raise ControlError(
            "ENVIRONMENT_WORKSPACE_ESCAPE", "project manifest must be a regular file",
        )
    if manifest_stat.st_size > PROJECT_MANIFEST_MAX_BYTES:
        raise ControlError(
            "ENVIRONMENT_DEFINITION_INVALID", "project manifest exceeds the bounded identity read limit",
        )
    try:
        with manifest_path.open("rb") as handle:
            manifest_bytes = handle.read(PROJECT_MANIFEST_MAX_BYTES + 1)
        if len(manifest_bytes) > PROJECT_MANIFEST_MAX_BYTES:
            raise ControlError(
                "ENVIRONMENT_DEFINITION_INVALID",
                "project manifest exceeds the bounded identity read limit",
            )
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except ControlError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError(
            "ENVIRONMENT_DEFINITION_INVALID", "project manifest is not readable JSON",
        ) from error
    if not isinstance(manifest, dict):
        raise ControlError(
            "ENVIRONMENT_DEFINITION_INVALID", "project manifest must be an object",
        )
    if "repository" not in manifest:
        if require_manifest:
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "a case-variant project selector requires a declared repository identity",
                details={"path": str(root)},
            )
        return root.name
    repository = manifest["repository"]
    if not isinstance(repository, str) or _REPOSITORY_ID.fullmatch(repository) is None:
        raise ControlError(
            "ENVIRONMENT_DEFINITION_INVALID", "project manifest repository identity is invalid",
        )
    if root.name.casefold() != repository.casefold():
        raise ControlError(
            "ENVIRONMENT_WORKSPACE_ESCAPE",
            "project directory does not match its declared repository identity",
            details={"repository": repository, "path": str(root)},
        )
    return repository


def resolve_workspace_project_identity(
    workspace_root: Path, repository: str,
) -> tuple[str, Path]:
    """Resolve one immediate folder by case-insensitive name and exact manifest identity."""
    if not isinstance(repository, str) or _PROJECT_SELECTOR.fullmatch(repository) is None:
        raise ControlError(
            "ENVIRONMENT_PROJECT_INVALID", "repository selector must name one immediate project",
        )
    try:
        root = workspace_root.expanduser().resolve(strict=True)
        candidates = [
            child for child in root.iterdir()
            if child.name.casefold() == repository.casefold()
            and not child.is_symlink()
            and child.is_dir()
        ]
    except OSError as error:
        raise ControlError(
            "ENVIRONMENT_PROJECT_UNKNOWN", "configured workspace projects could not be inspected",
        ) from error
    if len(candidates) != 1:
        raise ControlError(
            "ENVIRONMENT_PROJECT_UNKNOWN",
            "repository selector must resolve to one immediate project directory",
            details={"repository": repository, "matches": len(candidates)},
        )
    try:
        project_root = candidates[0].resolve(strict=True)
    except OSError as error:
        raise ControlError(
            "ENVIRONMENT_PROJECT_UNKNOWN", "configured project directory is unavailable",
        ) from error
    if project_root.parent != root:
        raise ControlError(
            "ENVIRONMENT_PROJECT_UNKNOWN",
            "repository selector is not an immediate real project directory",
        )
    identity = project_repository_identity(
        project_root, require_manifest=project_root.name != repository,
    )
    if identity.casefold() != repository.casefold():
        raise ControlError(
            "ENVIRONMENT_WORKSPACE_ESCAPE",
            "configured project directory does not match its canonical repository identity",
            details={"repository": repository, "path": str(project_root)},
        )
    return identity, project_root
