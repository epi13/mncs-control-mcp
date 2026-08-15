from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .security import redact_text, safe_host_probe_environment

_DEFAULT_CONFIG_DIR = Path.home() / ".config" / "mncs-control-mcp"


@dataclass(frozen=True)
class GitHubAuthStatus:
    """Public GitHub authentication observation. Never includes secrets."""

    available: bool
    state: str
    source: str | None
    account: str | None
    git_protocol: str | None
    scopes: tuple[str, ...]
    can_git_https: bool
    can_pull_request: bool
    ssh_agent: bool
    ssh_identities: int
    ssh_github: str
    detail: str

    def public(self) -> dict[str, object]:
        return {
            "available": self.available,
            "state": self.state,
            "source": self.source,
            "account": self.account,
            "git_protocol": self.git_protocol,
            "scopes": list(self.scopes),
            "can_git_https": self.can_git_https,
            "can_pull_request": self.can_pull_request,
            "ssh_agent": self.ssh_agent,
            "ssh_identities": self.ssh_identities,
            "ssh_github": self.ssh_github,
            "detail": self.detail,
        }


def github_config_dir() -> Path:
    override = os.environ.get("MNCS_CONTROL_GITHUB_DIR")
    return Path(override).expanduser() if override else _DEFAULT_CONFIG_DIR


def github_token_file() -> Path:
    override = os.environ.get("MNCS_CONTROL_GITHUB_ENV")
    if override:
        return Path(override).expanduser()
    return github_config_dir() / "github.env"


def _capture(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 12.0,
) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env if env is not None else safe_host_probe_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", redact_text(str(exc))
    return result.returncode, result.stdout or "", result.stderr or ""


def _gh_executable() -> str | None:
    return shutil.which("gh")


def _read_token_file(path: Path) -> str | None:
    try:
        if not path.is_file() or path.is_symlink():
            return None
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            return None
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() in {"GH_TOKEN", "GITHUB_TOKEN"}:
                token = value.strip().strip("'\"")
                if token and token not in {"replace-me", "<token>"}:
                    return token
    except OSError:
        return None
    return None


def _host_gh_token() -> str | None:
    gh = _gh_executable()
    if gh is None:
        return None
    code, stdout, _stderr = _capture([gh, "auth", "token", "-h", "github.com"])
    token = stdout.strip()
    if code == 0 and token and " " not in token and len(token) >= 20:
        return token
    return None


@lru_cache(maxsize=1)
def sandbox_github_token() -> str | None:
    """Return a GitHub token for authorized networked sandboxes only.

    Preference order is the dedicated Control env file, then the host `gh`
    keyring/login. Callers must not log, persist into the workspace, or return
    this value through MCP.
    """

    file_token = _read_token_file(github_token_file())
    if file_token:
        return file_token
    return _host_gh_token()


def clear_github_token_cache() -> None:
    sandbox_github_token.cache_clear()


def git_identity() -> dict[str, str]:
    identity: dict[str, str] = {}
    for key, args in (
        ("name", ["git", "config", "--global", "--get", "user.name"]),
        ("email", ["git", "config", "--global", "--get", "user.email"]),
    ):
        code, stdout, _stderr = _capture(args)
        value = stdout.strip()
        if code == 0 and value and "\x00" not in value and len(value) <= 256:
            identity[key] = value
    return identity


def ssh_agent_status() -> tuple[bool, int, str]:
    candidates: list[Path] = []
    if os.environ.get("SSH_AUTH_SOCK"):
        candidates.append(Path(os.environ["SSH_AUTH_SOCK"]))
    candidates.append(Path(f"/run/user/{os.getuid()}/ssh-agent.socket"))
    socket = next((item for item in candidates if item.is_socket()), None)
    if socket is None:
        return False, 0, "SSH_AUTH_SOCK is not available"
    env = safe_host_probe_environment({"SSH_AUTH_SOCK": str(socket)})
    code, stdout, stderr = _capture(["ssh-add", "-l"], env=env)
    if code == 0:
        count = len([line for line in stdout.splitlines() if line.strip()])
        return (
            True,
            count,
            f"socket={socket} (key metadata available; private keys remain agent-only)",
        )
    if code == 1:
        return True, 0, f"socket={socket}, no loaded identities"
    return False, 0, redact_text(stderr or stdout or f"socket={socket}")


def ssh_github_status() -> str:
    env = safe_host_probe_environment()
    socket = os.environ.get("SSH_AUTH_SOCK")
    fallback = Path(f"/run/user/{os.getuid()}/ssh-agent.socket")
    if socket:
        env["SSH_AUTH_SOCK"] = socket
    elif fallback.is_socket():
        env["SSH_AUTH_SOCK"] = str(fallback)
    else:
        return "unavailable"
    code, stdout, stderr = _capture(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "IdentitiesOnly=no",
            "-T",
            "git@github.com",
        ],
        env=env,
        timeout=15,
    )
    text = f"{stdout}\n{stderr}"
    if "successfully authenticated" in text.lower():
        return "authenticated"
    if "permission denied" in text.lower():
        return "publickey_rejected"
    if "host key verification failed" in text.lower():
        return "unknown_host"
    return "unavailable" if code != 0 else "authenticated"


def _parse_gh_status(output: str) -> tuple[str | None, str | None, tuple[str, ...]]:
    account = None
    protocol = None
    scopes: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if "logged in to github.com account" in lower:
            parts = stripped.split()
            if "account" in parts:
                account = parts[parts.index("account") + 1]
        if lower.startswith("- git operations protocol:"):
            protocol = stripped.split(":", 1)[1].strip() or None
        if "token scopes:" in lower:
            raw = stripped.split(":", 1)[1]
            scopes = [item.strip().strip("'\"") for item in raw.split(",") if item.strip()]
    return account, protocol, tuple(scopes)


def github_auth_status() -> GitHubAuthStatus:
    file_token = _read_token_file(github_token_file()) is not None
    host_token = _host_gh_token() is not None
    source = "control-env" if file_token else ("host-gh" if host_token else None)
    gh = _gh_executable()
    account = None
    protocol = None
    scopes: tuple[str, ...] = ()
    detail = "GitHub CLI is not authenticated in this environment"
    if gh is not None:
        code, stdout, stderr = _capture([gh, "auth", "status", "-h", "github.com"])
        account, protocol, scopes = _parse_gh_status(stdout + "\n" + stderr)
        if code == 0:
            detail = "host gh reports an authenticated github.com login"
        elif source:
            detail = "a Control GitHub token is available even though host gh status failed"
        else:
            detail = redact_text((stderr or stdout).strip() or "gh auth status failed")
    elif source:
        detail = "dedicated Control GitHub token is configured; host gh is missing"
    else:
        detail = "gh is not installed and no Control GitHub token file is present"

    token_present = bool(source)
    required = {"repo"}
    pr_scopes = {"repo"}
    have = set(scopes)
    if token_present and not have:
        # File-sourced tokens may not expose scope metadata. Treat them as
        # sufficient for the declared development operations until a live
        # command proves otherwise.
        can_git = True
        can_pr = True
        state = "available"
    elif token_present and required <= have:
        can_git = True
        can_pr = pr_scopes <= have
        state = "available" if can_pr else "authenticated_insufficient"
    elif token_present:
        can_git = False
        can_pr = False
        state = "authenticated_insufficient"
    else:
        can_git = False
        can_pr = False
        state = "unavailable"

    agent, identities, agent_detail = ssh_agent_status()
    ssh_github = ssh_github_status() if agent and identities else "unavailable"
    if state == "unavailable" and ssh_github == "authenticated":
        state = "degraded"
        detail = "SSH GitHub authentication works; gh API token is unavailable"
    elif state == "available" and source == "host-gh":
        detail = f"{detail}; sandbox uses host gh credentials without mounting the keyring"
    if agent:
        detail = f"{detail}; {agent_detail}"

    return GitHubAuthStatus(
        available=state == "available",
        state=state,
        source=source,
        account=account,
        git_protocol=protocol,
        scopes=scopes,
        can_git_https=can_git,
        can_pull_request=can_pr,
        ssh_agent=agent,
        ssh_identities=identities,
        ssh_github=ssh_github,
        detail=redact_text(detail),
    )


def sandbox_github_environment(network_enabled: bool) -> dict[str, str]:
    """Non-secret Git/GitHub environment for a sandbox child."""

    env = {
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GH_PROMPT_DISABLED": "1",
        "SSH_ASKPASS_REQUIRE": "never",
    }
    identity = git_identity()
    if "name" in identity:
        env["GIT_AUTHOR_NAME"] = identity["name"]
        env["GIT_COMMITTER_NAME"] = identity["name"]
    if "email" in identity:
        env["GIT_AUTHOR_EMAIL"] = identity["email"]
        env["GIT_COMMITTER_EMAIL"] = identity["email"]
    if not network_enabled:
        return env
    env.update(
        {
            "GIT_CONFIG_COUNT": "4",
            "GIT_CONFIG_KEY_0": "credential.https://github.com.helper",
            "GIT_CONFIG_VALUE_0": "",
            "GIT_CONFIG_KEY_1": "credential.https://github.com.helper",
            "GIT_CONFIG_VALUE_1": "!gh auth git-credential",
            "GIT_CONFIG_KEY_2": "credential.https://gist.github.com.helper",
            "GIT_CONFIG_VALUE_2": "",
            "GIT_CONFIG_KEY_3": "credential.https://gist.github.com.helper",
            "GIT_CONFIG_VALUE_3": "!gh auth git-credential",
        }
    )
    return env


def materialize_sandbox_gh_config(sandbox_home: Path) -> bool:
    """Write a 0600 gh hosts file into the dedicated sandbox home.

    Putting the token in ``bwrap --setenv`` would expose it on the process
    command line. The sandbox home is outside the workspace and is not the
    real user home.
    """

    token = sandbox_github_token()
    if not token:
        return False
    status = github_auth_status()
    account = status.account or "github-user"
    config_dir = sandbox_home / ".config" / "gh"
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(config_dir, 0o700)
    except OSError:
        pass
    hosts = config_dir / "hosts.yml"
    content = (
        f"github.com:\n    user: {account}\n    git_protocol: https\n    oauth_token: {token}\n"
    )
    tmp = config_dir / ".hosts.yml.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, hosts)
        os.chmod(hosts, 0o600)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False
    return True
