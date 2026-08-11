#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
unit="mncs-control-tunnel.service"

usage() {
    printf '%s\n' "Usage: $0 {status|start|stop|restart|logs|doctor} [doctor args...]"
}

action="${1:-status}"
if [[ $# -gt 0 ]]; then
    shift
fi
case "$action" in
    status) exec systemctl --user status "$unit" "$@" ;;
    start) exec systemctl --user start "$unit" "$@" ;;
    stop) exec systemctl --user stop "$unit" "$@" ;;
    restart) exec systemctl --user restart "$unit" "$@" ;;
    logs) exec journalctl --user -u "$unit" -f "$@" ;;
    doctor) exec "$repository/scripts/doctor.sh" "$@" ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac
