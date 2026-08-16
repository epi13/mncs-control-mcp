from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DeploymentPaths:
    """Stable paths used by the user-service installer and health checker."""

    repository: Path
    home: Path
    profile: str = "mncs-fedora"

    @classmethod
    def for_repository(cls, repository: Path, *, home: Path | None = None, profile: str = "mncs-fedora") -> DeploymentPaths:
        resolved = repository.expanduser().resolve()
        return cls(resolved, (home or Path.home()).expanduser().resolve(), profile)

    @property
    def python(self) -> Path:
        return self.repository / ".venv" / "bin" / "python"

    @property
    def mcp_executable(self) -> Path:
        return self.repository / ".venv" / "bin" / "mncs-control-mcp"

    @property
    def control_config(self) -> Path:
        return self.repository / "control.toml"

    @property
    def config_directory(self) -> Path:
        return self.home / ".config" / "mncs-control-mcp"

    @property
    def tunnel_environment(self) -> Path:
        return self.config_directory / "tunnel.env"

    @property
    def state_directory(self) -> Path:
        return self.home / ".local" / "state" / "mncs-control-mcp"

    @property
    def share_directory(self) -> Path:
        return self.home / ".local" / "share" / "mncs-control-mcp"

    @property
    def user_unit_directory(self) -> Path:
        return self.home / ".config" / "systemd" / "user"

    @property
    def user_unit(self) -> Path:
        return self.user_unit_directory / "mncs-control-tunnel.service"

    @property
    def update_path_unit(self) -> Path:
        return self.user_unit_directory / "mncs-control-update.path"

    @property
    def update_service_unit(self) -> Path:
        return self.user_unit_directory / "mncs-control-update.service"

    @property
    def tunnel_runner(self) -> Path:
        return self.repository / "scripts" / "run-tunnel.sh"


def render_user_service(*, repository: Path, profile: str = "mncs-fedora") -> str:
    """Render the checked-in service using systemd's home-relative specifier."""

    repo = repository.expanduser().resolve()
    escaped_repo = str(repo).replace("%", "%%")
    return f"""[Unit]
Description=OpenAI Secure MCP Tunnel for MNCS Control
Documentation=https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
After=network-online.target graphical-session.target
Wants=network-online.target
StartLimitIntervalSec=10min
StartLimitBurst=10

[Service]
Type=simple
EnvironmentFile=-%h/.config/mncs-control-mcp/tunnel.env
Environment=HOME=%h
Environment=PATH=%h/.local/bin:%h/Documents/Projects/mncs-control-mcp/.venv/bin:%h/.cargo/bin:/usr/local/bin:/usr/bin:/bin
Environment=MNCS_CONTROL_REPOSITORY={escaped_repo}
Environment=MNCS_CONTROL_TUNNEL_PROFILE={profile}
ExecStart=%h/Documents/Projects/mncs-control-mcp/scripts/run-tunnel.sh
Restart=always
RestartSec=10s
TimeoutStopSec=20s
KillMode=control-group
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/Documents/Projects %h/.config/mncs-control-mcp %h/.config/tunnel-client %h/.local/state/mncs-control-mcp %h/.local/state/tunnel-client %h/.local/share/mncs-control-mcp %h/.local/share/tunnel-client
UMask=0077
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
"""


def render_update_path(*, repository: Path) -> str:
    """Watch the checked-out main ref so a fast-forward pull reloads Control.

    The tunnel process is intentionally long-lived. An editable Python install
    therefore makes new source available after ``git pull`` but does not make
    the already-imported MCP process execute it. The path unit closes that gap
    without granting the MCP sandbox access to the user systemd bus.
    """

    repo = repository.expanduser().resolve()
    escaped_repo = str(repo).replace("%", "%%")
    return f"""[Unit]
Description=Watch MNCS Control source revision

[Path]
PathChanged={escaped_repo}/.git/refs/heads/main
PathChanged={escaped_repo}/.git/packed-refs
Unit=mncs-control-update.service

[Install]
WantedBy=default.target
"""


def render_update_service() -> str:
    """Render the narrow systemd action used by the source revision watcher."""

    return """[Unit]
Description=Reload MNCS Control after source update
After=mncs-control-tunnel.service

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl --user try-restart mncs-control-tunnel.service
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
"""


def repository_revision(repository: Path) -> str | None:
    """Read a normal Git worktree revision without invoking Git."""

    repo = repository.expanduser().resolve()
    git_dir = repo / ".git"
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None
    if head.startswith("ref: "):
        ref_name = head[5:].strip()
        if not ref_name or ref_name.startswith("/") or ".." in Path(ref_name).parts:
            return None
        ref_path = git_dir / ref_name
        try:
            value = ref_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            value = ""
        if value:
            return value
        try:
            for line in (git_dir / "packed-refs").read_text(encoding="utf-8").splitlines():
                if not line or line.startswith(("#", "^")):
                    continue
                revision, _, packed_ref = line.partition(" ")
                if packed_ref == ref_name and revision:
                    return revision
        except (OSError, UnicodeError):
            return None
        return None
    return head or None


def ensure_private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def ensure_private_file(path: Path, content: str | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    if not path.exists():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(path, flags, 0o600)
        try:
            if content is not None:
                os.write(descriptor, content.encode("utf-8"))
        finally:
            os.close(descriptor)
    os.chmod(path, 0o600)
    return path


def configured_runtime_key(path: Path) -> bool:
    """Check a dotenv-style file without returning or logging its value."""

    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() != "CONTROL_PLANE_API_KEY":
                continue
            value = value.strip().strip("\"'")
            return bool(value and value not in {"replace-me", "<runtime-key>", "sk-..."})
    except (OSError, UnicodeError):
        return False
    return False


def configured_organization_id(path: Path) -> bool:
    """Check for a configured OpenAI organization context without exposing its value."""

    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() != "CONTROL_PLANE_ORGANIZATION_ID":
                continue
            value = value.strip().strip("\"'")
            return bool(value and value not in {"replace-me", "<organization-id>", "org-..."})
    except (OSError, UnicodeError):
        return False
    return False

def runtime_environment(path: Path) -> dict[str, str]:
    """Return a filtered environment with the local tunnel key for tunnel-client only."""
    from .security import safe_host_probe_environment

    values: dict[str, str] = {}
    allowed = {"CONTROL_PLANE_API_KEY", "CONTROL_PLANE_ORGANIZATION_ID"}
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            if key in allowed:
                value = raw_value.strip().strip("\"'")
                if value:
                    values[key] = value
    except (OSError, UnicodeError):
        pass
    environment = safe_host_probe_environment()
    environment.update(values)
    return environment
