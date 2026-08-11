#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
profile="mncs-fedora"
tunnel_id="${TUNNEL_ID:-}"
start_service=true
repair_profile=false

usage() {
    cat <<'EOF'
Install the mncs-control-mcp Fedora user service.

Usage: ./scripts/install-user-service.sh [options]

Options:
  --tunnel-id ID       Initialize the named tunnel profile when it is absent.
  --profile NAME       Use a different tunnel-client profile (default: mncs-fedora).
  --repair-profile     Re-run tunnel-client init for an existing profile.
  --no-start           Enable and install the unit without starting it.
  -h, --help           Show this help.

The runtime key is read from ~/.config/mncs-control-mcp/tunnel.env or the
CONTROL_PLANE_API_KEY environment. The key and tunnel ID are never committed.
EOF
}

warn() { printf 'WARNING: %s\n' "$*" >&2; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

while (($#)); do
    case "$1" in
        --tunnel-id) (($# >= 2)) || fail "--tunnel-id requires a value"; tunnel_id="$2"; shift 2 ;;
        --profile) (($# >= 2)) || fail "--profile requires a value"; profile="$2"; shift 2 ;;
        --repair-profile) repair_profile=true; shift ;;
        --no-start) start_service=false; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[[ "$profile" =~ ^[A-Za-z0-9._-]+$ ]] || fail "profile must contain only letters, numbers, dot, underscore, and hyphen"
if [[ -n "$tunnel_id" && ! "$tunnel_id" =~ ^tunnel_[A-Za-z0-9._-]+$ ]]; then
    fail "tunnel ID must look like tunnel_..."
fi

command -v systemctl >/dev/null 2>&1 || fail "systemctl is required"
user_manager_state="$(systemctl --user is-system-running 2>/dev/null || true)"
case "$user_manager_state" in
    running|degraded) ;;
    *) warn "systemd user manager state is ${user_manager_state:-unavailable}; unit installation will continue" ;;
esac

bwrap_path="$(command -v bwrap || true)"
[[ -n "$bwrap_path" ]] || fail "Bubblewrap is missing. Install it with: sudo dnf install bubblewrap"
printf 'Bubblewrap: %s\n' "$bwrap_path"

python_bin="${PYTHON_BIN:-$(command -v python3 || true)}"
[[ -n "$python_bin" && -x "$python_bin" ]] || fail "python3 is required"
"$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || fail "Python 3.11 or newer is required"

venv_python="$repository/.venv/bin/python"
if [[ ! -x "$venv_python" ]]; then
    printf 'Creating virtual environment: %s\n' "$repository/.venv"
    "$python_bin" -m venv "$repository/.venv"
fi
[[ -x "$venv_python" ]] || fail "virtual environment creation failed: $venv_python"
"$venv_python" -m pip --version >/dev/null 2>&1 || fail "pip is missing from $repository/.venv"
printf 'Installing editable MCP package...\n'
"$venv_python" -m pip install -e "$repository" >/dev/null

if [[ ! -f "$repository/control.toml" ]]; then
    install -m 0644 "$repository/config/control.example.toml" "$repository/control.toml"
    printf 'Created %s\n' "$repository/control.toml"
else
    printf 'Preserving existing %s\n' "$repository/control.toml"
fi

config_directory="$HOME/.config/mncs-control-mcp"
state_directory="$HOME/.local/state/mncs-control-mcp"
share_directory="$HOME/.local/share/mncs-control-mcp"
unit_directory="$HOME/.config/systemd/user"
install -d -m 0700 "$config_directory" "$state_directory" "$share_directory" "$unit_directory" \
    "$HOME/.config/tunnel-client" "$HOME/.local/state/tunnel-client" "$HOME/.local/share/tunnel-client"
if [[ ! -f "$config_directory/tunnel.env" ]]; then
    install -m 0600 "$repository/deploy/systemd/tunnel.env.example" "$config_directory/tunnel.env"
    printf 'Created %s\n' "$config_directory/tunnel.env"
else
    chmod 0600 "$config_directory/tunnel.env"
    printf 'Preserving existing %s\n' "$config_directory/tunnel.env"
fi

install -m 0644 "$repository/deploy/systemd/mncs-control-tunnel.service" "$unit_directory/mncs-control-tunnel.service"
chmod 0755 "$repository/scripts/run-tunnel.sh"

if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
    systemctl --user import-environment SSH_AUTH_SOCK >/dev/null 2>&1 || warn "could not import SSH_AUTH_SOCK into the user manager"
    printf 'SSH agent: imported current socket into the user manager\n'
else
    warn "SSH_AUTH_SOCK is not set; remote Git authentication may require a later session import"
fi

tunnel_client="$HOME/.local/bin/tunnel-client"
if [[ ! -x "$tunnel_client" ]]; then
    tunnel_client="$(command -v tunnel-client || true)"
fi
runtime_key="${CONTROL_PLANE_API_KEY:-}"
if [[ -z "$runtime_key" && -f "$config_directory/tunnel.env" ]]; then
    runtime_key="$(sed -n 's/^CONTROL_PLANE_API_KEY=//p' "$config_directory/tunnel.env" | head -n 1)"
    runtime_key="${runtime_key#\"}"
    runtime_key="${runtime_key%\"}"
    runtime_key="${runtime_key#\'}"
    runtime_key="${runtime_key%\'}"
fi

if [[ -z "$tunnel_client" || ! -x "$tunnel_client" ]]; then
    warn "tunnel-client is not installed"
    warn "Use the official Platform download or latest release, then install it as: $HOME/.local/bin/tunnel-client"
    warn "Official guide: https://developers.openai.com/api/docs/guides/secure-mcp-tunnels"
else
    printf 'Tunnel client: %s\n' "$tunnel_client"
    profile_dir="${XDG_CONFIG_HOME:-$HOME/.config}/tunnel-client"
    profile_present=false
    if [[ -d "$profile_dir" ]] && grep -RIl --exclude='*.log' -- "$profile" "$profile_dir" >/dev/null 2>&1; then
        profile_present=true
    fi
    if [[ "$repair_profile" == true || "$profile_present" == false ]]; then
        if [[ -z "$tunnel_id" ]]; then
            warn "tunnel profile $profile is not initialized; provide --tunnel-id tunnel_..."
        elif [[ -z "$runtime_key" || "$runtime_key" == replace-me || "$runtime_key" == '<runtime-key>' ]]; then
            warn "CONTROL_PLANE_API_KEY is not configured; add it to $config_directory/tunnel.env before profile initialization"
        else
            printf 'Initializing tunnel profile %s...\n' "$profile"
            CONTROL_PLANE_API_KEY="$runtime_key" "$tunnel_client" init \
                --sample sample_mcp_stdio_local \
                --profile "$profile" \
                --tunnel-id "$tunnel_id" \
                --mcp-command "$repository/.venv/bin/mncs-control-mcp --config $repository/control.toml" \
                || warn "tunnel-client profile initialization failed; run tunnel-client doctor --profile $profile --explain"
        fi
    else
        printf 'Preserving existing tunnel profile %s\n' "$profile"
    fi
fi

systemctl --user daemon-reload
systemctl --user enable mncs-control-tunnel.service >/dev/null
printf 'Enabled: mncs-control-tunnel.service\n'

if [[ "$start_service" == true ]]; then
    if [[ -n "$tunnel_client" && -x "$tunnel_client" && -n "$runtime_key" && "$runtime_key" != replace-me && "$runtime_key" != '<runtime-key>' ]]; then
        systemctl --user restart mncs-control-tunnel.service || warn "service did not start; inspect: journalctl --user -u mncs-control-tunnel.service -e"
    else
        warn "service was not started because tunnel-client or CONTROL_PLANE_API_KEY is missing"
    fi
else
    printf 'Not starting service (--no-start).\n'
fi

printf '\nRun health checks with:\n  %s/scripts/doctor.sh --profile %s\n' "$repository" "$profile"
printf 'Service status:\n  systemctl --user status mncs-control-tunnel.service\n'
printf 'Service logs:\n  journalctl --user -u mncs-control-tunnel.service -f\n'

if [[ -x "$repository/.venv/bin/mncs-control-mcp" ]]; then
    set +e
    "$repository/.venv/bin/mncs-control-mcp" doctor --config "$repository/control.toml" --profile "$profile"
    doctor_status=$?
    set -e
    exit "$doctor_status"
fi
exit 1
