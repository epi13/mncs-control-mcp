from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from .config import ControlConfig
from .errors import ControlError
from .security import bounded_text, validate_environment
from .workspace import ScopeResolution, WorkspacePolicy


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class SandboxResult:
    command: str
    cwd: str
    scope: str
    project: str | None
    started_at: str
    completed_at: str
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool
    duration_seconds: float
    sandbox_backend: str
    network: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "command": self.command,
            "cwd": self.cwd,
            "scope": self.scope,
            "project": self.project,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "output_truncated": self.output_truncated,
            "duration_seconds": round(self.duration_seconds, 3),
            "sandbox_backend": self.sandbox_backend,
            "network": self.network,
        }


class Sandbox:
    def __init__(self, config: ControlConfig, policy: WorkspacePolicy) -> None:
        self.config = config
        self.policy = policy
        discovered = shutil.which("bwrap")
        requested = config.sandbox_backend
        if requested == "bwrap" and discovered is None:
            raise ControlError("SANDBOX_UNAVAILABLE", "bubblewrap was explicitly requested but is not installed")
        self.executable = discovered if requested in {"auto", "bwrap"} else None
        if config.require_real_sandbox and self.executable is None:
            raise ControlError("SANDBOX_UNAVAILABLE", "a real terminal sandbox is required")
        self.backend = "bwrap" if self.executable else "none"
        config.sandbox_home.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(config.sandbox_home, 0o700)
        except OSError:
            pass

    @property
    def available(self) -> bool:
        return self.executable is not None

    def _network(self, requested: bool | None) -> bool:
        enabled = self.config.terminal_network_default if requested is None else requested
        if enabled and not self.config.terminal_network_allowed:
            raise ControlError("NETWORK_DISABLED", "network-enabled terminal sessions are disabled")
        return enabled

    def _tool_paths(self) -> tuple[Path, ...]:
        if self.config.sandbox_tool_paths:
            return tuple(path for path in self.config.sandbox_tool_paths if path.exists())
        home = Path.home()
        defaults = (
            *((Path(sys.prefix),) if sys.prefix != sys.base_prefix else ()),
            home / ".local" / "bin",
            home / ".local" / "lib",
            home / ".cargo" / "bin",
            home / ".rustup",
        )
        return tuple(path for path in defaults if path.exists())

    def _project_harness_runtime(
        self, argv: list[str], safe_overrides: dict[str, str]
    ) -> None:
        """Project deliberate Harness config and consumer sockets read-only."""

        def mountpoint(target: Path) -> None:
            relative = target.relative_to("/home/developer")
            parent = self.config.sandbox_home
            for part in relative.parent.parts:
                parent /= part
                try:
                    parent.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                entry = os.lstat(parent)
                if (
                    stat.S_ISLNK(entry.st_mode)
                    or not stat.S_ISDIR(entry.st_mode)
                    or entry.st_uid != os.getuid()
                ):
                    raise ControlError(
                        "SANDBOX_MOUNTPOINT_UNSAFE",
                        "sandbox integration mountpoint parent is unsafe",
                    )
            host_target = self.config.sandbox_home / relative
            try:
                entry = os.lstat(host_target)
            except FileNotFoundError:
                descriptor = os.open(
                    host_target,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.close(descriptor)
            else:
                if (
                    stat.S_ISLNK(entry.st_mode)
                    or not stat.S_ISREG(entry.st_mode)
                    or entry.st_uid != os.getuid()
                ):
                    raise ControlError(
                        "SANDBOX_MOUNTPOINT_UNSAFE",
                        "sandbox integration mountpoint is unsafe",
                    )

        harness_config = self.config.harness_config_path
        if harness_config.exists():
            entry = os.lstat(harness_config)
            if stat.S_ISLNK(entry.st_mode) or not stat.S_ISREG(entry.st_mode):
                raise ControlError(
                    "HARNESS_CONFIG_UNSAFE",
                    "Harness configuration must be a regular non-symlink file",
                )
            target = Path("/home/developer/.config/epi13-local-harness/config.toml")
            mountpoint(target)
            argv.extend(("--ro-bind", str(harness_config), target.as_posix()))
            safe_overrides["EPI13_HARNESS_CONFIG"] = target.as_posix()
            safe_overrides["PYTHONPATH"] = ":".join(
                (
                    "/workspace/"
                    + self.config.repositories.get("local_harness", "epi13-local-harness")
                    + "/src",
                    "/workspace/"
                    + self.config.repositories.get("fabric", "mncs-fabric")
                    + "/src",
                    "/workspace/"
                    + self.config.repositories.get("commons", "MNCS-Commons")
                    + "/src",
                )
            )

        for source, target in (
            (
                self.config.fabric_socket,
                Path("/home/developer/.local/state/mncs-fabric/controller.sock"),
            ),
            (
                self.config.commons_socket,
                Path("/home/developer/.local/state/mncs-commons/commons.sock"),
            ),
        ):
            try:
                entry = os.lstat(source)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(entry.st_mode) or not stat.S_ISSOCK(entry.st_mode):
                raise ControlError(
                    "INTEGRATION_SOCKET_UNSAFE",
                    "persistent integration endpoint must be a real Unix socket",
                )
            if entry.st_uid != os.getuid():
                raise ControlError(
                    "INTEGRATION_SOCKET_UNSAFE",
                    "persistent integration endpoint is owned by another account",
                )
            parent = os.lstat(Path(source).parent)
            if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
                raise ControlError(
                    "INTEGRATION_SOCKET_UNSAFE",
                    "persistent integration endpoint parent permissions are unsafe",
                )
            mountpoint(target)
            argv.extend(("--ro-bind", str(source), target.as_posix()))

    def command_argv(
        self,
        command: str,
        resolution: ScopeResolution,
        *,
        network: bool | None,
        environment: dict[str, str] | None = None,
        use_ssh_agent: bool = False,
        runtime_mounts: tuple[tuple[Path, str], ...] = (),
    ) -> tuple[list[str], bool]:
        if not isinstance(command, str) or not command.strip() or len(command) > 131072 or "\x00" in command:
            raise ControlError("INVALID_COMMAND", "command must be non-empty bounded text")
        network_enabled = self._network(network)
        safe_overrides = validate_environment({**self.config.safe_environment, **(environment or {})})
        if self.executable is None:
            raise ControlError("SANDBOX_UNAVAILABLE", "terminal execution requires bubblewrap")

        argv = [
            self.executable,
            "--die-with-parent",
            "--new-session",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--unshare-user",
            "--uid",
            str(os.getuid()),
            "--gid",
            str(os.getgid()),
            "--disable-userns",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/etc",
            "/etc",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/var",
            "--dir",
            "/run",
            "--dir",
            "/workspace",
            "--dir",
            "/home",
            "--bind",
            str(self.config.sandbox_home),
            "/home/developer",
        ]
        if not network_enabled:
            argv.append("--unshare-net")
        else:
            try:
                resolver = Path("/etc/resolv.conf").resolve(strict=True)
            except OSError:
                resolver = None
            if resolver is not None and resolver.is_file() and resolver.as_posix().startswith("/run/"):
                current = Path("/run")
                for part in resolver.parent.relative_to("/run").parts:
                    current /= part
                    argv.extend(("--dir", current.as_posix()))
                argv.extend(("--ro-bind", str(resolver), resolver.as_posix()))
        if resolution.scope == "workspace":
            argv.extend(("--bind", str(self.policy.root), "/workspace"))
        else:
            argv.extend(("--ro-bind", str(self.policy.root), "/workspace"))
            argv.extend(("--bind", str(resolution.host_root), f"/workspace/{resolution.project}"))

        self._project_harness_runtime(argv, safe_overrides)

        # Integrations may request narrowly scoped writable runtime mounts.  A
        # caller cannot mount arbitrary host paths: only directories already
        # belonging to the control-plane state tree are accepted.
        allowed_runtime_roots = {
            self.config.fabric_state.parent.resolve(),
            self.config.job_state_path.parent.resolve(),
            self.config.audit_path.parent.resolve(),
        }
        for source, destination in runtime_mounts:
            source_path = Path(source).expanduser().resolve(strict=True)
            if not source_path.is_dir() or not any(
                _is_relative_to(source_path, root) for root in allowed_runtime_roots
            ):
                raise ControlError("INVALID_RUNTIME_MOUNT", "runtime mount must be a control-plane state directory")
            destination_path = Path(destination)
            destination_root = Path("/home/developer/.local/state")
            if (
                not destination_path.is_absolute()
                or ".." in destination_path.parts
                or not _is_relative_to(destination_path, destination_root)
            ):
                raise ControlError("INVALID_RUNTIME_MOUNT", "runtime mount destination must be below the sandbox state directory")
            # Bubblewrap requires the destination's parent to exist in the
            # namespace.  Creating only empty namespace directories does not
            # expose any additional host data.
            parent = Path("/")
            existing = {"/", "/home", "/home/developer", "/run", "/tmp", "/workspace", "/opt", "/opt/mncs-tools"}
            for part in destination_path.parent.parts[1:]:
                parent /= part
                if parent.as_posix() not in existing:
                    argv.extend(("--dir", parent.as_posix()))
            argv.extend(("--bind", str(source_path), destination_path.as_posix()))

        path_entries: list[str] = []
        tool_paths = self._tool_paths()
        if tool_paths:
            argv.extend(("--dir", "/opt", "--dir", "/opt/mncs-tools"))
        for index, source in enumerate(tool_paths):
            if source == Path(sys.prefix) and sys.prefix != sys.base_prefix:
                destination = "/opt/mncs-runtime"
                path_entries.append("/opt/mncs-runtime/bin")
                safe_overrides.setdefault("VIRTUAL_ENV", destination)
            elif source == Path.home() / ".local" / "lib":
                destination = "/home/developer/.local/lib"
                argv.extend(("--dir", "/home/developer/.local"))
            else:
                destination = f"/opt/mncs-tools/{index}"
            argv.extend(("--ro-bind", str(source), destination))
            if source.name in {"bin", ".bin"}:
                path_entries.append(destination)
            if source.name == ".rustup":
                safe_overrides.setdefault("RUSTUP_HOME", destination)

        ssh_socket = os.environ.get("SSH_AUTH_SOCK")
        if (
            use_ssh_agent
            and network_enabled
            and self.config.git_use_ssh_agent
            and ssh_socket
            and Path(ssh_socket).exists()
        ):
            argv.extend(("--dir", "/run/mncs-control", "--ro-bind", ssh_socket, "/run/mncs-control/ssh-agent.sock"))
            safe_overrides["SSH_AUTH_SOCK"] = "/run/mncs-control/ssh-agent.sock"
            safe_overrides["GIT_SSH_COMMAND"] = (
                "ssh -F /dev/null -o IdentitiesOnly=no "
                "-o UserKnownHostsFile=/home/developer/.ssh/known_hosts "
                "-o StrictHostKeyChecking=yes"
            )
            known_hosts = Path.home() / ".ssh" / "known_hosts"
            if known_hosts.is_file() and not known_hosts.is_symlink():
                argv.extend(
                    (
                        "--dir",
                        "/home/developer/.ssh",
                        "--ro-bind",
                        str(known_hosts),
                        "/home/developer/.ssh/known_hosts",
                    )
                )

        base_env = {
            "HOME": "/home/developer",
            "PATH": ":".join(path_entries + ["/usr/local/bin", "/usr/bin", "/bin"]),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "TERM": "dumb",
            "TMPDIR": "/tmp",
            "XDG_CACHE_HOME": "/home/developer/.cache",
            "XDG_CONFIG_HOME": "/home/developer/.config",
            "XDG_DATA_HOME": "/home/developer/.local/share",
            "XDG_RUNTIME_DIR": "/tmp/runtime",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        }
        base_env.update(safe_overrides)
        for key, value in base_env.items():
            argv.extend(("--setenv", key, value))
        argv.extend(("--chdir", resolution.sandbox_cwd, "/bin/bash", "-lc", command))
        return argv, network_enabled

    def run(
        self,
        command: str,
        *,
        scope: str | None,
        project: str | None,
        cwd: str,
        timeout_seconds: float | None,
        network: bool | None,
        environment: dict[str, str] | None = None,
        use_ssh_agent: bool = False,
        runtime_mounts: tuple[tuple[Path, str], ...] = (),
    ) -> SandboxResult:
        if not self.config.allow_terminal:
            raise ControlError("TERMINAL_DISABLED", "terminal execution is disabled")
        resolution = self.policy.resolve_scope(scope=scope, project=project, cwd=cwd)
        timeout = self.config.default_timeout_seconds if timeout_seconds is None else float(timeout_seconds)
        if timeout <= 0 or timeout > self.config.max_timeout_seconds:
            raise ControlError("INVALID_TIMEOUT", "timeout exceeds the configured terminal limit")
        argv, network_enabled = self.command_argv(
            command,
            resolution,
            network=network,
            environment=environment,
            use_ssh_agent=use_ssh_agent,
            runtime_mounts=runtime_mounts,
        )
        started_at = utc_now()
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                argv,
                cwd=None,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={},
                start_new_session=True,
            )
        except OSError as exc:
            raise ControlError("COMMAND_START_FAILED", str(exc)) from exc
        stdout, stderr, truncated = _communicate_bounded(process, self.config.max_output_bytes, timeout)
        timed_out = process.poll() is None
        if timed_out:
            _terminate_group(process)
        process.wait()
        return SandboxResult(
            command=command,
            cwd=resolution.sandbox_cwd,
            scope=resolution.scope,
            project=resolution.project,
            started_at=started_at,
            completed_at=utc_now(),
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            output_truncated=truncated,
            duration_seconds=time.monotonic() - started,
            sandbox_backend=self.backend,
            network=network_enabled,
        )


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=2)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _communicate_bounded(
    process: subprocess.Popen[bytes], maximum: int, timeout: float
) -> tuple[str, str, bool]:
    buffers = [bytearray(), bytearray()]
    truncated = [False]

    def drain(stream: BinaryIO, target: bytearray) -> None:
        reader = getattr(stream, "read1", stream.read)
        while chunk := reader(8192):
            remaining = maximum - len(target)
            if remaining > 0:
                target.extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                truncated[0] = True

    assert process.stdout is not None and process.stderr is not None
    threads = [
        threading.Thread(target=drain, args=(process.stdout, buffers[0]), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, buffers[1]), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    for thread in threads:
        thread.join(timeout=2)
    stdout, stdout_cut = bounded_text(buffers[0].decode("utf-8", errors="replace"), maximum)
    stderr, stderr_cut = bounded_text(buffers[1].decode("utf-8", errors="replace"), maximum)
    return stdout, stderr, truncated[0] or stdout_cut or stderr_cut
