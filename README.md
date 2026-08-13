# mncs-control-mcp

`mncs-control-mcp` exposes a protected Fedora development workspace through MCP. It provides filesystem, terminal, Git, project-management, tooling, and MNCS-specific orchestration while using a real Bubblewrap boundary to keep commands out of the rest of the user account.

The default workspace is `$HOME/Documents/Projects`. MNCS repositories retain aliases and specialized adapters, but any real project below the workspace can use the general development tools.

## Architecture

```text
ChatGPT / Codex / MCP clients
              |
           MCP stdio
              v
      mncs-control-mcp
       /             \
developer workspace   MNCS adapters
 |  |  |  |           |-- epi13-local-harness
 |  |  |  +-- tools   |-- mncs-fabric
 |  |  +----- Git     |-- mncs-forge-mcp
 |  +-------- Bash    |-- MNCS-Commons
 `----------- files   `-- Ollama/models
              |
         Bubblewrap
              |
         /workspace only
```

Fabric integration is a consumer boundary: the persistent
`mncs-fabric-controller.service` owns fleet lifecycle and worker presence;
Control reads the same consumer AF_UNIX socket as Local Harness. Service mode
does not copy a worker registry or trust material and does not expose Fabric
administration. Control derives execution support from the connected service's
live feature projection, using persistent dispatch only when it is advertised
and reporting `FABRIC_SERVICE_EXECUTION_UNSUPPORTED` otherwise. Select
`transitional` only when bounded embedded-direct execution compatibility is
intentionally configured.

The MCP registration layer is intentionally thin. `WorkspacePolicy` owns path authorization; `Sandbox` constructs the Linux namespace; `FileService`, `GitService`, `ProcessManager`, `ProjectService`, `ToolInventory`, and `AuditLog` own cohesive capabilities. Harness remains the agent/model layer, Fabric remains the distributed execution and routing authority, and Forge remains the evaluation/evidence authority.

## Installation

Fedora needs Bubblewrap and normal developer tools installed by the operator. No tool exposes `sudo` or `dnf`.

```bash
cd ~/Documents/Projects/mncs-control-mcp
./scripts/install-user-service.sh --no-start
./scripts/doctor.sh
```

The installer creates or updates `.venv`, installs the editable package, preserves an existing `control.toml`, creates private state/config directories, installs the user unit under `~/.config/systemd/user/`, and enables it. It is safe to rerun after `git pull`.

For a normal operator setup, install the official `tunnel-client`, put `CONTROL_PLANE_API_KEY` in `~/.config/mncs-control-mcp/tunnel.env` with mode 0600, create a real tunnel in Platform settings, and initialize the profile:

```bash
./scripts/install-user-service.sh --tunnel-id tunnel_...
```

The server uses stdio and does not open a listener. `MNCS_CONTROL_WORKSPACE_ROOT` overrides configuration; the older `MNCS_PROJECTS_ROOT` remains supported at lower precedence. See [docs/CHATGPT-SETUP.md](docs/CHATGPT-SETUP.md) for persistent service, SSH-agent, reboot, and browser setup.

Service operation:

```bash
systemctl --user status mncs-control-tunnel.service
journalctl --user -u mncs-control-tunnel.service -f
./scripts/service.sh restart
```

## Workspace and scope model

All MCP filesystem paths are POSIX-style paths relative to the workspace:

```text
mncs-language/src/main.rs
some-project/README.md
new-project/
```

Absolute paths, `..`, NUL bytes, backslash path syntax, resolved symlink escapes, workspace-root deletion, and writes through symlinks are rejected.

Terminal tools have two scopes:

- `project` is the default. The selected immediate child is writable at `/workspace/<project>` and siblings are mounted read-only.
- `workspace` makes the whole Projects tree writable. It is intentionally powerful and separately configurable.

Workspace-wide arbitrary shell is destructive-capable. MCP annotations reflect that; clients should keep approval prompts enabled for mutating tools.

## Sandbox design

The Fedora backend is Bubblewrap (`bwrap`). A terminal process receives:

- the authorized workspace mount at `/workspace`;
- `/usr` and `/etc` read-only, plus merged-`/usr` compatibility links;
- a new `/proc`, minimal `/dev`, tmpfs `/tmp`, and empty `/var` and `/run`;
- a dedicated writable `HOME` at `~/.local/share/mncs-control-mcp/sandbox-home`;
- optional read-only user tool trees such as `~/.local/bin`, Python packages in `~/.local/lib`, `~/.cargo/bin`, and `~/.rustup`;
- no mount of the real home directory, `.ssh`, `.gnupg`, `.aws`, `.kube`, browser profiles, or credential configuration.

The sandbox creates mount, PID, IPC, UTS, and user namespaces, attempts a separate cgroup namespace where supported, preserves the caller UID/GID, drops all capabilities, disables nested user namespaces, starts a new session, and dies with its parent. If a real sandbox is unavailable, terminal calls fail; the implementation never falls back to an unsandboxed shell.

`/etc/passwd` and other deliberately mounted system configuration can be read. The minimal `/dev` does not currently pass GPU devices into arbitrary terminal jobs; host GPU inventory remains available through `system_status`.

## Network and credentials

Ordinary terminal calls default to `network=false`, which adds a new network namespace. `network=true` retains host networking when `terminal_network_allowed` is enabled. This is a binary network policy, not domain-level egress filtering.

Remote Git tools request network access explicitly. When `use_ssh_agent=true`, only the existing `SSH_AUTH_SOCK` and, if present, the regular `~/.ssh/known_hosts` file are mounted into that authorized networked Git sandbox. Private key files are never mounted. HTTPS token helpers or tokens in the real home are intentionally unavailable; configure an SSH agent before starting the MCP/tunnel:

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
ssh -T git@github.com
```

The socket lets Git ask the agent to sign without reading key material. `git push` has no force option, and hard reset is not exposed.

Host HTTPS credential helpers and keyring tokens are intentionally unavailable inside the sandbox. For an existing HTTPS remote, add a GitHub-authorized key to the agent and switch the remote before using `git_fetch` or `git_push`:

```bash
ssh-add ~/.ssh/<github-key>
ssh -T git@github.com
git remote set-url origin git@github.com:OWNER/REPOSITORY.git
```

The normal host-side GitHub CLI login is compatible with host Git, but its keyring
token is deliberately not mounted into MCP sandboxes. To authorize the agent-backed
path, register the matching public key once through GitHub CLI (the account login
may require the `admin:public_key` scope), then use SSH remotes:

```bash
gh auth status
gh auth refresh -h github.com -s admin:public_key
gh ssh-key add ~/.ssh/id_ed25519.pub --title "fedora mncs-control"
git remote set-url origin git@github.com:OWNER/REPOSITORY.git
ssh -T git@github.com
```

Only the session `SSH_AUTH_SOCK` is made available to the authorized networked Git
sandbox; private key files and GitHub tokens are never copied into control-plane
state or repository files. The user service recognizes Fedora's
`/run/user/<uid>/ssh-agent.socket` and reports missing agent identities without
weakening the service sandbox.

## MCP tools

### Workspace and files

- `workspace_info`, `list_projects`, `project_info`, `project_create`
- `file_stat`, `file_list`, `file_tree`, `file_read`, `file_write`
- `file_patch`, `file_mkdir`, `file_move`, `file_copy`, `file_delete`
- `file_glob`, `file_search`

Text reads are UTF-8; binary reads use base64. File sizes, listings, trees, search matches, patches, and responses are bounded. Unified patches are path-validated and checked before application.

### Terminal and processes

- `terminal_exec`
- `terminal_start`, `terminal_status`, `terminal_output`, `terminal_write`, `terminal_stop`, `terminal_jobs`, `control_jobs`
- backward-compatible `job_status`, `job_result`

Synchronous results include command, sandbox cwd, scope, project, timestamps, exit code, stdout, stderr, timeout/truncation state, duration, backend, and network state. Asynchronous jobs use random service-owned IDs, process groups, incremental bounded logs, stdin, termination, configurable concurrency/time limits, shutdown cleanup, and local restart metadata. A restarted server marks previously running metadata `orphaned`; it never signals a PID merely read from disk.

### Git

- `git_status`, `git_diff`, `git_log`, `git_show`, `git_branches`
- `git_create_branch`, `git_checkout`, `git_add`, `git_commit`
- `git_fetch`, `git_pull`, `git_push`, `git_clone`
- `git_remotes`, `git_restore`, `git_stash`
- backward-compatible MNCS-alias `repo_status`

Every Git command runs inside the same project sandbox, including repository hooks. Repository and path inputs resolve inside the workspace. Clone destinations cannot escape. Remote failures return bounded diagnostics without exposing host credential variables.

### System and MNCS

- `tool_inventory`, `system_status`, `control_capabilities`, `laboratory_status`, `list_repositories`
- `project_review`, `test_discover`, `test_run`, `project_check`, `control_run`
- `fabric_status`, `model_status`, `run_tests`, `run_mncs_evaluation`, `dispatch_fabric_job`
- `commons_status`, `commons_work`, `commons_query`, `commons_get`, `commons_conversation`, `commons_evidence`, `commons_sync`
- `control_job_status`, `control_job_result`, `control_job_stop`

`tool_inventory` reports safe executable paths and first-line versions for common Python, Rust, Node, C/C++, Go, Java, container, shell, search, Ollama, NVIDIA/CUDA, and sandbox tools. Each entry distinguishes absent, broken, healthy, and project-local candidates; a broken global wrapper does not hide a usable project virtualenv. It does not return the environment.

`project_review` provides bounded project/Git/test/CI/documentation context. `test_discover`, `test_run`, and `project_check` cover detected pytest, Cargo, Node, Go, and CTest workflows; the legacy `run_tests` name remains supported. Test operations report a structured toolchain choice: Python prefers a safe project `.venv/bin/python`/`python3`, then an explicitly declared bounded path, then the approved system interpreter; Rust, Node, Go, and CMake use the same resolver shape with approved system tools. Runner-aware parsers annotate supported output, but process exit status remains authoritative. When the control repository tests itself, Bubblewrap integration tests are marked `requires_bwrap_namespace` and reported as an explicit skip because the outer production sandbox is already the security boundary; they are not falsely reported as passing. `control_capabilities` and `laboratory_status` expose the current dependency graph and compute topology for agent planning. Their Forge entry reports `configuration_missing`, `executable_missing`, `process_start_failed`, `mcp_initialization_failed`, `capability_unavailable`, or `healthy` after a real stdio MCP probe. `control_run` composes only named workflows, including `review_and_check_project` and the opt-in `review_check_and_fabric_test`; each returns bounded step records and a persisted control ID. `run_mncs_evaluation` uses Forge's current typed operation registry for declared development workflows. `dispatch_fabric_job` negotiates the connected controller's public service feature projection; when the controller-owned authenticated worker backend is configured it uses `FabricClient.connect()` and reports `execution_transport=persistent-service`, otherwise service mode returns `FABRIC_SERVICE_EXECUTION_UNSUPPORTED` and never silently creates an embedded client. Fabric owns fleet authority; Harness owns model/agent routing.

Service mode configures `integration.fabric_socket` and an ordinary consumer identity. It does not require a Control-owned registry, controller lifecycle, or worker trust material. `fabric_controller_id` remains only for explicit embedded compatibility.

Commons integration is also a consumer boundary. Control connects directly to
the configured persistent Commons consumer socket through the public
`CommonsClient`; it neither launches a Harness subprocess nor opens the Commons
store. The exposed operations are the fixed read-only status/work/query/get/
conversation/evidence/sync set. Publication and recovery are absent, and record
content is always returned as untrusted inert data.

Use `./scripts/mcp-smoke.py --config control.toml` for a local, read-only
protocol/deployment check. It cannot verify ChatGPT-side connector reachability;
the doctor reports that layer as `UNKNOWN`.

`dispatch_fabric_job` waits for the upstream receipt by default. Set `wait=false`
for a stable `ctrl-...` job ID, then use `control_job_status` and
`control_job_result`; Control propagates the bounded job timeout into Fabric's
validated job plan. Blocking adapters run in a supervised process, so a local
deadline frees Control executor capacity. `control_job_stop` reports `stopped`
before the adapter starts and `upstream_detached` after it has started; Fabric's
current public API exposes no abort operation, so a remote request is never
described as cancelled when Control cannot prove that. After restart,
incomplete upstream records become `upstream_detached`. External jobs never
expose a fabricated local PID.

Only explicit embedded/transitional compatibility uses the private Control
Fabric state tree for registry migration, network ledger, and bundle staging.
Service mode reads the Fabric-owned consumer socket and leaves those files under
the persistent Fabric controller's authority.

`file_patch` intentionally accepts standard Git-style unified diffs. Include
both `--- a/path` and `+++ b/path` headers; an error response explains this
format when they are absent. Patch paths are still validated against the
workspace before Git applies the patch.

## Audit and limits

The default audit log is `~/.local/state/mncs-control-mcp/audit.jsonl`, outside the exposed workspace, with directory mode 0700 and file mode 0600. It records tool, timestamps, success/failure, duration, scope/project/cwd/network, exit status, and job ID where relevant. Commands are bounded and obvious token/password forms are redacted.

Configurable safeguards include synchronous/asynchronous timeouts, output and response sizes, file/list/search limits, job concurrency, and job metadata retention. Bubblewrap provides namespace and capability isolation. Per-job memory and CPU quotas are not yet enforced; long builds are bounded by time and concurrency, and this limitation should inform client approvals.

## Secure MCP Tunnel and ChatGPT Developer Mode

OpenAI's current Secure MCP Tunnel supports local stdio commands over outbound-only HTTPS. Create a tunnel in Platform tunnel settings, associate both the intended Platform organization and ChatGPT workspace, and obtain `Tunnels Read + Use` (plus `Manage` to create/edit). ChatGPT Developer Mode is a separate workspace permission.

```bash
export CONTROL_PLANE_API_KEY="<runtime-key>"

tunnel-client init \
  --sample sample_mcp_stdio_local \
  --profile mncs-fedora \
  --tunnel-id tunnel_... \
  --mcp-command "$HOME/Documents/Projects/mncs-control-mcp/.venv/bin/mncs-control-mcp --config $HOME/Documents/Projects/mncs-control-mcp/control.toml"

tunnel-client doctor --profile mncs-fedora --explain
tunnel-client run --profile mncs-fedora
```

Keep the runtime key out of this repository. In ChatGPT, create a developer-mode app, choose **Tunnel** as the connection, and select the associated tunnel. The official guide is: <https://developers.openai.com/api/docs/guides/secure-mcp-tunnels>.

The checked-in user-systemd unit is installed automatically by the installer. The environment template is `deploy/systemd/tunnel.env.example`; never commit the real key. The current OpenAI instructions use the Platform download or latest official `openai/tunnel-client` release rather than an arbitrary third-party binary: <https://developers.openai.com/api/docs/guides/secure-mcp-tunnels>.

## Tests

```bash
pytest
ruff check .
python -m compileall -q src
uv lock --check
git diff --check
```

CI runs the Python 3.11/3.12/3.13 matrix, lockfile and diff checks, and a
separate Bubblewrap namespace subset when the hosted kernel permits user
namespaces. A hosted skip is printed explicitly; it does not claim to validate
the Fedora kernel/security integration, which remains a local or self-hosted
responsibility.

The operational tests also cover unit rendering, private environment-file permissions and preservation, idempotent deployment helpers, and the real local MCP stdio doctor handshake. The installer itself can be rerun safely; it returns a nonzero doctor result until required tunnel credentials and profile configuration exist.

The suite uses temporary workspaces. Bubblewrap integration tests skip cleanly where the binary is absent. Coverage includes path and nested-symlink escapes, root protection, file operations, output/time bounds, secret environment filtering, real project/workspace mounts, Bash/Python/subprocess home probes, asynchronous input/output/stop, local Git branch/add/commit/diff/log, dynamic discovery, annotations, and a full stdio MCP workflow.

## Security assumptions and limitations

- The MCP/tunnel identity is authorized to act as the local Fedora user inside the configured workspace.
- Workspace content is untrusted. The sandbox boundary, not command filtering, contains arbitrary commands.
- Network-enabled commands can exfiltrate anything visible inside their sandbox, including workspace content and SSH-agent signing capability. Enable them deliberately.
- The SSH agent protects key files but will honor signing requests according to its own confirmation/lifetime policy. Consider `ssh-add -c` or short lifetimes.
- `/usr` and `/etc` are intentionally readable; the real user home is not.
- The minimal device mount does not expose CUDA devices to general commands.
- No domain egress filter, per-project access-control identity, seccomp profile beyond Bubblewrap defaults, or memory/CPU cgroup quota is claimed.
- Forge local results do not establish independent evaluation, custody, certification, or promotion.

See `docs/SECURITY.md` and `docs/UPSTREAM-INTERFACES.md` for the detailed boundaries.
