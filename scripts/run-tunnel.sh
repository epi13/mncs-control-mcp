#!/usr/bin/env bash
set -euo pipefail

repository="${MNCS_CONTROL_REPOSITORY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
profile="${MNCS_CONTROL_TUNNEL_PROFILE:-mncs-fedora}"
tunnel_client="${MNCS_CONTROL_TUNNEL_CLIENT:-$HOME/.local/bin/tunnel-client}"

if [[ ! -x "$tunnel_client" ]]; then
    tunnel_client="$(command -v tunnel-client || true)"
fi
if [[ -z "$tunnel_client" || ! -x "$tunnel_client" ]]; then
    echo "mncs-control-mcp: tunnel-client is missing; install the official OpenAI binary and retry" >&2
    exit 127
fi

mcp_executable="$repository/.venv/bin/mncs-control-mcp"
control_config="$repository/control.toml"
if [[ ! -x "$mcp_executable" ]]; then
    echo "mncs-control-mcp: MCP executable is missing: $mcp_executable" >&2
    exit 127
fi
if [[ ! -f "$control_config" ]]; then
    echo "mncs-control-mcp: configuration is missing: $control_config" >&2
    exit 78
fi
if [[ "${CONTROL_PLANE_API_KEY:-}" == "" || "${CONTROL_PLANE_API_KEY:-}" == "replace-me" || "${CONTROL_PLANE_API_KEY:-}" == "<runtime-key>" ]]; then
    echo "mncs-control-mcp: CONTROL_PLANE_API_KEY is not configured in the service environment" >&2
    exit 78
fi

# KDE and other desktop sessions normally expose this socket through the user
# manager. The fallback helps a lingered service find the existing session
# agent without creating a competing agent or exposing private key files.
if [[ -z "${SSH_AUTH_SOCK:-}" || ! -S "$SSH_AUTH_SOCK" ]]; then
    session_socket="/run/user/$(id -u)/ssh-agent.socket"
    if [[ -S "$session_socket" ]]; then
        export SSH_AUTH_SOCK="$session_socket"
    else
        echo "mncs-control-mcp: SSH agent unavailable; remote Git authentication may fail" >&2
    fi
fi

exec "$tunnel_client" run --profile "$profile"
