# Journal context security

The Atlas journal context tools are read-only at the MCP surface but may create
short-lived, mode-0600 bundle files under the private Control state directory.
Bundles are immutable collection snapshots with explicit retention configuration;
they are not stored in repositories or Commons. Collection stays below the
configured workspace root and journal project allow-list. Sensitive path names,
credential material, raw commands, arbitrary environments, browser data, and
unrelated project activity are excluded or redacted. All bundle fields are
untrusted inert data and cannot be interpreted as instructions by Control.

# Security model

The protected asset boundary is the Fedora user account outside the configured developer workspace. MCP callers and repository content may be adversarial. Normal developer mutations are allowed inside the authorized project or workspace scope.

## Enforced boundaries

`WorkspacePolicy` accepts relative POSIX paths only, canonicalizes existing ancestors and targets, verifies containment, and refuses workspace-root mutation. Structured writes use `O_NOFOLLOW`; recursive traversals do not follow symlink directories. Patch headers and Git paths are validated before execution.

Arbitrary commands run only through Bubblewrap. The real home is absent. `/usr` and `/etc` are read-only; `/tmp` is an ephemeral tmpfs; `/dev` is a new minimal device tree. Project scope mounts Projects read-only and overlays only the selected immediate project read-write. Workspace scope binds all Projects read-write. The sandbox preserves the invoking UID/GID, drops capabilities, disables nested user namespaces, and creates PID/IPC/UTS/cgroup namespaces.

No string allowlist is presented as a sandbox. If Bubblewrap is unavailable, terminal execution fails.

## Network and authentication

No-network commands receive a new network namespace. Network-enabled commands retain host networking. There is no domain allowlist. Remote Git can receive an SSH-agent socket and regular known-hosts data; it never receives the real `.ssh` directory. The agent can sign, so networked Git remains high-impact.

Network-enabled sandboxes may receive a GitHub CLI hosts file in the dedicated
sandbox home so HTTPS remotes and `gh` can operate non-interactively. The token
is taken from `~/.config/mncs-control-mcp/github.env` or the host `gh` login and
written mode `0600` under the sandbox home, never onto the `bwrap` command line
or into the workspace. It is not accepted from agent-supplied environment
overrides. `developer_readiness` can observe that this capability exists; it
cannot create or widen it.

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

### Environment persistence transport

Control owns a private AF_UNIX Environment endpoint beside its service state.
For each protected terminal run it issues an unguessable short-lived grant,
mounts only that grant and the endpoint socket into the sandbox, and revokes the
grant when the run exits. The endpoint checks Unix peer credentials and the
grant, then admits a bounded Environment CLI operation against the configured
canonical Store. It does not accept Store paths, pass file descriptors, or
expose a general filesystem proxy. Environment still validates campaign
ownership, rights, claims, and Store generations. The default endpoint can be
overridden with the Control integration setting `environment_rpc_socket`.

Endpoint status reports IPC availability separately from the configured Store
mount's mutation state. The read-only mount check does not attempt a write or
claim Store integrity; `direct-filesystem-read-only` means that this service
process still needs an authorized Store persistence transport. The endpoint
never exposes Store paths or file descriptors to the sandbox.
`env_status` and `system_status` report its live availability; a missing
endpoint does not trigger file persistence or direct Store writes.
The project-scoped CLI bridge permits `complete` only for a session owned by
the grant's authenticated principal. Environment records completion intent
before lifecycle transition and claim release; `--retry-pending` reconciles
that intent after a caller or service interruption.
The bridge also permits only the exact read-only invocation
`store --session <session-id> --verify`. Control verifies that the session
belongs to the grant's authenticated principal, fixes the configured state
directory and Store persistence provider, and forwards no Store path or file
handle. Bare Store inspection, alternate persistence roots, and other Store
operations remain unavailable through this endpoint.
The bridge additionally exposes Environment's retirement inventory only in
`--inventory --dry-run` mode. It requires the authenticated session principal,
maps the repository through the current execution grant, rejects branch,
worktree, and prune mutation targets, and supplies the grant root as the
inspection boundary. Registered checkouts outside that root are reported as
out of scope without probing their paths.

The typed `env_campaign_continuation` operation is a read-only projection over
canonical Environment snapshots. It requires Control's authenticated
principal and an immediate project name under the configured workspace. The
project must appear in the campaign's recorded work intent, checkout facts,
repository references, or live claims. Results contain only same-principal
sessions and only the requested project's checkout and claim details; foreign
owner session identities are not returned. Duplicate sessions remain explicit
and must be selected by exact session identity before `env_resume`. If the
campaign identity is omitted, Control discovers same-principal campaigns
recorded against that project; multiple campaigns remain explicit choices.
Persisted checkout references are labeled as snapshot facts because their
heads may be stale. The response also includes a fresh, bounded, read-only
Environment workspace observation for the selected project. Registered
worktree paths are reported as Git metadata only; registration does not prove
that a physical checkout is currently available or clean. Incomplete or
unavailable discovery remains `unknown` instead of reusing stored facts as
current. The capsule compares persisted branch/head/path facts to the bounded
live checkout and registration set when possible, while retaining `unknown`
when the registration list is truncated or the facts cannot be matched.
Nonterminal setup or handed-off lifecycles return a reconciliation result
instead of being labeled resumable; handed-off sessions continue through
Environment's recipient-bound accept operation.
`env_enter` accepts an explicit campaign identity so a new process can ask
Environment to reuse that durable campaign without relying on its consumer
label.
For a project grant, an `enter` request without `--definition` uses the
project's `.mncs/project-environment.json` when present. That definition must
select exactly the granted repository and leave `workspace_root` at its
default; Control passes the configured host workspace root to Environment,
which then applies the definition's one-repository selection. Explicit
definitions remain caller-selected and receive the same grant checks. This
lets a protected project process resume its recorded Environment identity
without granting the sandbox access to sibling repositories.

After successful project-scoped CLI entry, Control also attaches a
`control_project_continuation` projection to the Environment JSON response.
It uses the grant's immediate project and the authenticated Control principal
to expose same-campaign sessions from other Environment contexts. After entry,
Control uses the exact definition identity and workspace returned by Environment;
for a direct project continuation query it uses the canonical project
definition. When that context identifies exactly one project-linked session,
Control marks it as selected while
keeping every other capsule visible. It declines selection when the result is
truncated, the exact context is duplicated, or another same-campaign session
holds a claim on the project. The projection is read-only and never changes
claims. If the lookup fails after Environment entry succeeds, the response
retains the successful entry and marks the supplementary projection `unknown`.

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

The Fabric service advertises execution only when its controller-owned,
authenticated worker backend is configured and reachable. Control fails closed
with `FABRIC_SERVICE_EXECUTION_UNSUPPORTED` when the connected service does not
advertise it; it never silently constructs an embedded client. Direct
execution remains available only under an explicit `embedded` or `transitional`
configuration and is labeled in returned results. The current service
execution backend, including authenticated worker-initiated rendezvous, remains
owned by Fabric and is visible to Control only through the live public feature
projection.

### Commons consumer boundary

MNCS Control connects only to the configured Commons consumer AF_UNIX socket
through the public `CommonsClient`. It does not import `CommonsAdminClient`,
connect to the operator socket, open store files, launch a Commons process, or
route through Harness. The adapter whitelist contains only bounded read/status
operations. Publication and recovery are therefore unavailable from MCP. A
same-UID local socket is not isolation between mutually untrusted processes
running as the same account; Commons record content remains untrusted inert data.

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
