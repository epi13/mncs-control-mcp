from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import ControlConfig, load_config
from .deployment import DeploymentPaths, configured_runtime_key, runtime_environment
from .security import redact_text, safe_host_probe_environment

_REQUIRED_TOOLS = {
    "workspace_info", "list_projects", "file_read", "terminal_exec", "git_status",
    "system_status", "fabric_status", "control_capabilities", "project_review",
    "project_check", "laboratory_status",
}


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    required: bool = False

    @property
    def ok(self) -> bool:
        return self.status == "OK"


def _capture(
    argv: list[str], *, timeout: float = 8.0, env: dict[str, str] | None = None, max_chars: int = 1000
) -> tuple[int, str]:
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
        return 127, redact_text(str(exc))
    output = (result.stdout or result.stderr or "").strip()
    return result.returncode, redact_text(output[:max_chars])


def _first_line(value: str) -> str:
    return value.splitlines()[0][:160] if value else "no version output"


def _read_json_response(stream: Any, process: subprocess.Popen[str], request_id: int, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = max(0.05, deadline - time.monotonic())
        ready, _, _ = select.select([stream], [], [], remaining)
        if not ready:
            continue
        line = stream.readline()
        if not line:
            break
        try:
            response = json.loads(line)
        except json.JSONDecodeError:
            continue
        if response.get("id") == request_id:
            return response
    stderr = ""
    if process.stderr is not None and process.poll() is not None:
        try:
            stderr = process.stderr.read(2000)
        except OSError:
            pass
    raise RuntimeError(redact_text(stderr.strip() or "no MCP response"))


def probe_mcp_stdio(executable: Path, config_path: Path, *, timeout: float = 20.0) -> dict[str, Any]:
    """Perform a real initialize/tools-list exchange against the local executable."""

    environment = safe_host_probe_environment()
    if executable.is_file():
        command = [str(executable), "--config", str(config_path)]
        cwd = None
    else:
        # A project test can run inside /workspace where the host's .venv path
        # is not mounted.  Use the interpreter that is actually executing the
        # probe and expose the checked-out source, rather than inventing a
        # host/sandbox path.
        command = [sys.executable, "-m", "mncs_control_mcp", "--config", str(config_path)]
        cwd = Path.cwd()
        environment["PYTHONPATH"] = str(cwd / "src")
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        cwd=cwd,
        start_new_session=True,
    )
    try:
        assert process.stdin is not None and process.stdout is not None
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "mncs-control-doctor", "version": "1"},
            },
        }
        process.stdin.write(json.dumps(initialize) + "\n")
        process.stdin.flush()
        init_response = _read_json_response(process.stdout, process, 1, timeout)
        if "error" in init_response:
            raise RuntimeError("initialize returned an MCP error")
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n")
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n")
        process.stdin.flush()
        tools_response = _read_json_response(process.stdout, process, 2, timeout)
        if "error" in tools_response:
            raise RuntimeError("tools/list returned an MCP error")
        tools = tools_response.get("result", {}).get("tools", [])
        names = {item.get("name") for item in tools if isinstance(item, dict)}
        missing = sorted(_REQUIRED_TOOLS - names)
        if missing:
            raise RuntimeError("missing tools: " + ", ".join(missing))
        return {"tool_count": len(names), "required_tools": sorted(_REQUIRED_TOOLS)}
    finally:
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _service_state() -> tuple[str, str]:
    if shutil.which("systemctl") is None:
        return "UNAVAILABLE", "systemctl not found"
    enabled_code, enabled = _capture(["systemctl", "--user", "is-enabled", "mncs-control-tunnel.service"])
    active_code, active = _capture(["systemctl", "--user", "is-active", "mncs-control-tunnel.service"])
    if active_code == 0:
        return "OK", f"enabled={enabled or 'unknown'}, active={active or 'unknown'}"
    return "WARNING", f"enabled={enabled or 'unknown'}, active={active or 'unknown'}"


def _tunnel_process_running(profile: str) -> bool:
    """Detect an already-running profile without exposing its environment."""
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                command = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="ignore")
            except OSError:
                continue
            if "tunnel-client" in command and " run " in f" {command} " and f"--profile {profile}" in command:
                return True
    except OSError:
        pass
    return False


def _ssh_state() -> tuple[str, str]:
    candidates = []
    if os.environ.get("SSH_AUTH_SOCK"):
        candidates.append(Path(os.environ["SSH_AUTH_SOCK"]))
    candidates.append(Path(f"/run/user/{os.getuid()}/ssh-agent.socket"))
    socket = next((candidate for candidate in candidates if candidate.is_socket()), None)
    if socket is None:
        return "WARNING", "SSH_AUTH_SOCK is not available"
    code, output = _capture(["ssh-add", "-l"], env=safe_host_probe_environment({"SSH_AUTH_SOCK": str(socket)}))
    if code == 0:
        return "OK", f"socket={socket} (key metadata available; private keys remain agent-only)"
    return "WARNING", f"socket={socket}, no loaded identities"


def run_doctor(config_path: Path, *, profile: str = "mncs-fedora", json_output: bool = False) -> int:
    paths = DeploymentPaths.for_repository(config_path.parent, profile=profile)
    checks: list[Check] = []
    try:
        config: ControlConfig = load_config(config_path)
        workspace = config.workspace_root
        if workspace.is_dir() and os.access(workspace, os.W_OK):
            checks.append(Check("Workspace", "OK", str(workspace), required=True))
        else:
            checks.append(Check("Workspace", "FAIL", f"missing or not writable: {workspace}", required=True))
    except Exception as exc:
        config = None  # type: ignore[assignment]
        checks.append(Check("Configuration", "FAIL", redact_text(str(exc)), required=True))

    if config is not None:
        checks.append(Check("Configuration", "OK", str(config_path), required=True))
    bwrap = shutil.which("bwrap")
    checks.append(Check("Bubblewrap", "OK", f"{bwrap} ({_first_line(_capture([bwrap, '--version'])[1])})", required=True) if bwrap else Check("Bubblewrap", "FAIL", "not found; install with: sudo dnf install bubblewrap", required=True))

    if paths.mcp_executable.is_file() and os.access(paths.mcp_executable, os.X_OK):
        checks.append(Check("MCP executable", "OK", str(paths.mcp_executable), required=True))
        try:
            probe = probe_mcp_stdio(paths.mcp_executable, config_path)
            checks.append(Check("Local MCP protocol", "OK", f"tools={probe['tool_count']}", required=True))
        except Exception as exc:
            checks.append(Check("Local MCP protocol", "FAIL", redact_text(str(exc)), required=True))
    else:
        checks.append(Check("MCP executable", "FAIL", f"missing: {paths.mcp_executable}", required=True))

    tunnel = Path.home() / ".local" / "bin" / "tunnel-client"
    if not tunnel.is_file():
        discovered = shutil.which("tunnel-client")
        tunnel = Path(discovered) if discovered else tunnel
    if tunnel.is_file() and os.access(tunnel, os.X_OK):
        code, version = _capture([str(tunnel), "--version"])
        if code == 0:
            checks.append(Check("Tunnel client", "OK", f"{tunnel} ({_first_line(version)})", required=True))
        else:
            checks.append(Check("Tunnel client", "FAIL", f"{tunnel} did not pass --version", required=True))
    else:
        tunnel = None
        checks.append(Check("Tunnel client", "FAIL", "not found; install the official binary from Platform tunnel settings or the latest openai/tunnel-client release", required=True))

    key_configured = configured_runtime_key(paths.tunnel_environment)
    key_mode_ok = paths.tunnel_environment.is_file() and (paths.tunnel_environment.stat().st_mode & 0o777) == 0o600
    if key_configured and key_mode_ok:
        checks.append(Check("Runtime key", "OK", f"configured in {paths.tunnel_environment} (value hidden)", required=True))
    elif key_configured:
        checks.append(Check("Runtime key", "FAIL", f"configured but permissions are not 0600: {paths.tunnel_environment}", required=True))
    else:
        checks.append(Check("Runtime key", "FAIL", f"CONTROL_PLANE_API_KEY is not configured in {paths.tunnel_environment}", required=True))

    if tunnel is not None and key_configured:
        code, output = _capture([str(tunnel), "doctor", "--profile", profile, "--explain"], timeout=30, env=runtime_environment(paths.tunnel_environment), max_chars=8000)
        if code == 0:
            checks.append(Check("Tunnel profile", "OK", f"{profile}; { _first_line(output) or 'doctor passed'}", required=True))
        elif "health_listener" in output and "address already in use" in output and _tunnel_process_running(profile):
            checks.append(Check("Tunnel profile", "OK", f"{profile}; an existing tunnel-client already owns the health listener", required=True))
        else:
            checks.append(Check("Tunnel profile", "FAIL", f"{profile}; {_first_line(output) or 'doctor failed'}", required=True))
    else:
        checks.append(Check("Tunnel profile", "WARNING", f"{profile} not checked until tunnel-client and runtime key are configured"))

    ssh_status, ssh_detail = _ssh_state()
    checks.append(Check("SSH agent", ssh_status, ssh_detail))

    if config is not None:
        checks.append(Check("Fabric registry", "OK" if config.fabric_registry.is_file() else "WARNING", str(config.fabric_registry)))
        checks.append(Check("Harness", "OK" if config.harness_path.is_dir() else "WARNING", str(config.harness_path)))
        checks.append(Check("Forge", "OK" if config.forge_path.is_dir() else "WARNING", str(config.forge_path)))
        ollama = shutil.which("ollama")
        if ollama:
            code, _ = _capture([ollama, "list"], timeout=8)
            checks.append(Check("Ollama", "OK" if code == 0 else "WARNING", ollama))
        else:
            checks.append(Check("Ollama", "WARNING", "not installed or unavailable"))
        nvidia = shutil.which("nvidia-smi")
        if nvidia:
            code, output = _capture([nvidia, "--query-gpu=name,driver_version", "--format=csv,noheader"], timeout=8)
            checks.append(Check("CUDA", "OK" if code == 0 else "WARNING", _first_line(output) if code == 0 else "nvidia-smi unavailable"))
        else:
            checks.append(Check("CUDA", "WARNING", "nvidia-smi not found"))

    service_status, service_detail = _service_state()
    checks.append(Check("systemd service", service_status, service_detail))

    result = {"profile": profile, "checks": [asdict(check) for check in checks], "ok": all(check.ok for check in checks if check.required)}
    if json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"MNCS Control doctor ({profile})")
        for check in checks:
            print(f"{check.name:<20} {check.status:<8} {check.detail}")
        print("Overall              " + ("OK" if result["ok"] else "ACTION REQUIRED"))
    return 0 if result["ok"] else 1


def doctor_main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="mncs-control-mcp doctor")
    parser.add_argument("--config", default="control.toml", help="path to control TOML")
    parser.add_argument("--profile", default="mncs-fedora", help="tunnel-client profile name")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args(argv)
    return run_doctor(Path(args.config).expanduser().resolve(), profile=args.profile, json_output=args.json)
