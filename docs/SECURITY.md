# Security model

The protected asset boundary is the Fedora user account outside the configured developer workspace. MCP callers and repository content may be adversarial. Normal developer mutations are allowed inside the authorized project or workspace scope.

## Enforced boundaries

`WorkspacePolicy` accepts relative POSIX paths only, canonicalizes existing ancestors and targets, verifies containment, and refuses workspace-root mutation. Structured writes use `O_NOFOLLOW`; recursive traversals do not follow symlink directories. Patch headers and Git paths are validated before execution.

Arbitrary commands run only through Bubblewrap. The real home is absent. `/usr` and `/etc` are read-only; `/tmp` is an ephemeral tmpfs; `/dev` is a new minimal device tree. Project scope mounts Projects read-only and overlays only the selected immediate project read-write. Workspace scope binds all Projects read-write. The sandbox preserves the invoking UID/GID, drops capabilities, disables nested user namespaces, and creates PID/IPC/UTS/cgroup namespaces.

No string allowlist is presented as a sandbox. If Bubblewrap is unavailable, terminal execution fails.

## Network and authentication

No-network commands receive a new network namespace. Network-enabled commands retain host networking. There is no domain allowlist. Remote Git can receive an SSH-agent socket and regular known-hosts data; it never receives the real `.ssh` directory or token environment. The agent can sign, so networked Git remains high-impact.

## Environment

The child environment is constructed from fixed essentials and configured non-secret overrides. The host environment is not copied. Secret-like override names are rejected. Generic environment inspection is not exposed.

There are two deliberate environment boundaries. `run_bounded()` defaults to a
minimal command environment containing only fixed locale/temp/path essentials;
it does not discover the real HOME or XDG directories. Narrow, read-only host
adapters such as Ollama, NVIDIA inventory, tool inventory, and the doctor may
explicitly use `safe_host_probe_environment()`, which supplies controlled HOME
and selected XDG paths after secret filtering. No API tokens, cloud credentials,
SSH private-key data, shell startup files, or arbitrary host variables are
forwarded.

## Process and response controls

The service bounds timeout, concurrent jobs, retained stdout/stderr, file and response sizes, directory/search results, and stdin writes. Asynchronous children use dedicated process groups and are terminated on stop, timeout, and orderly server shutdown. Metadata is persisted mode 0600; prior running records become `orphaned` after restart and are not trusted as live PIDs.

There is currently no per-job CPU or memory cgroup quota and no GPU device passthrough. These are explicit limitations, not claimed controls.

Control jobs distinguish local terminal processes from upstream records. External
adapter calls run behind a supervised process boundary with a real wall-clock
deadline. `queued` can be stopped before execution, `timed_out` means Control
terminated its adapter process, and `upstream_detached` means Control stopped
waiting/owning the adapter while an upstream request may remain authoritative.
Fabric, Forge, and Harness identifiers are recorded without pretending that an
upstream job has a local PID. A restart marks incomplete upstream metadata as
`upstream_detached` rather than guessing that work completed.

## Integration runtime state

Mutable integration state is not placed in the real home directory. In explicit
embedded/transitional compatibility mode, the legacy Fabric registry, lock,
network ledger, and bundle staging use the private
`~/.local/state/mncs-control-mcp/fabric/` tree, which is one of the narrowly
allowed service write paths. Service mode does not create or migrate that
registry: the persistent Fabric controller owns it. A legacy registry is copied
only when compatibility mode is explicitly selected, under an exclusive file
lock, a unique fsynced temporary file, and atomic replacement.
The sandbox also has an internal runtime-mount hook restricted to control-plane
state directories, so future approved integrations can receive one writable
directory without making `$HOME`, `.ssh`, `.config`, or `/run/user` writable.
Podman and other tools that require host daemon sockets may remain degraded
until an explicit, least-privilege adapter exists.

## Audit

Audit JSONL lives outside the workspace, mode 0600 under a 0700 directory. It contains bounded/redacted metadata, not full file contents or environment data. Generic workspace tools cannot address it.

## Persistent service boundary

### Fabric consumer boundary

MNCS Control is an ordinary persistent Fabric consumer. It connects only to
the configured consumer socket and never imports or connects to
`FabricAdminClient` or the operator/admin socket. MCP access therefore does not
grant enrollment-token creation, enrollment approval/denial, worker revocation,
or other Fabric administrative authority. Service mode requires neither worker
certificates nor private keys. Fabric owns fleet membership, presence, trust,
and registry state; Control reports those observations without copying them into
private Control state.

The current Fabric service exposes fleet reads but not execution dispatch.
Control fails closed with `FABRIC_SERVICE_EXECUTION_UNSUPPORTED`. Direct
execution is available only under an explicit `embedded` or `transitional`
configuration and is labeled in returned results.

`scripts/mcp-smoke.py` tests the local stdio protocol and read-only deployment
identity without testing ChatGPT-side connector reachability. `doctor` reports
the MCP executable, stdio protocol, tunnel client/profile/systemd layers,
consumer socket/controller state, and an explicit `UNKNOWN` remote connector
state when external verification is required.

The user service runs `tunnel-client`, which owns the MCP stdio child. It uses
absolute repository/virtualenv paths, a filtered PATH, `ProtectSystem=strict`,
`ProtectHome=read-only`, `PrivateTmp`, `NoNewPrivileges`, a control-group kill
boundary, and narrowly scoped writable paths for the workspace, MCP state, and
tunnel-client state. The service environment file is
outside the workspace and must be mode 0600. The service wrapper never prints the
runtime key and only discovers an existing `SSH_AUTH_SOCK`; it does not create an
agent or mount private keys.

The installer deliberately does not download an unverified tunnel binary, invent
a tunnel ID, enable lingering, or run `sudo`. It creates/enables the user unit and
reports the exact operator action for missing Bubblewrap, tunnel-client, keys,
profiles, or lingering. A service can start at login without an SSH agent; remote
Git authentication is an optional capability and is reported separately by the
doctor.

## Demonstrated test properties

The automated tests exercise direct `..` and absolute paths, direct and nested symlink escapes, write-through-symlink refusal, root deletion, project sibling redirection, real-home and SSH-key probes from Bash and Python, subprocess inheritance, workspace-scope cross-project writes, asynchronous process groups, and the actual Bubblewrap backend when available.

`/etc/passwd` may be read because `/etc` is deliberately mounted read-only for normal tooling. `/tmp` is writable but ephemeral and outside the host filesystem. Network isolation is namespace-level only.
