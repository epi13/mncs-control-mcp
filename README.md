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
 |  +-------- Bash    `-- Ollama/models
 `----------- files
              |
          Bubblewrap
              |
         /workspace only
```

The MCP registration layer is intentionally thin. `WorkspacePolicy` owns path authorization; `Sandbox` constructs the Linux namespace; `FileService`, `GitService`, `ProcessManager`, `ProjectService`, `ToolInventory`, and `AuditLog` own cohesive capabilities. Harness remains the agent/model layer, Fabric remains the distributed execution and routing authority, and Forge remains the evaluation/evidence authority.

## Installation

Fedora needs Bubblewrap and normal developer tools installed by the operator. No tool exposes `sudo` or `dnf`.

```bash
cd ~/Documents/Projects/mncs-control-mcp
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

cp config/control.example.toml control.toml
pytest
ruff check .

mncs-control-mcp --config control.toml
```

With `uv`:

```bash
uv venv
source .venv/bin/activate
uv pip install -e '.[dev]'
pytest
```

The server uses stdio and does not open a listener. `MNCS_CONTROL_WORKSPACE_ROOT` overrides configuration; the older `MNCS_PROJECTS_ROOT` remains supported at lower precedence.

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

## MCP tools

### Workspace and files

- `workspace_info`, `list_projects`, `project_info`, `project_create`
- `file_stat`, `file_list`, `file_tree`, `file_read`, `file_write`
- `file_patch`, `file_mkdir`, `file_move`, `file_copy`, `file_delete`
- `file_glob`, `file_search`

Text reads are UTF-8; binary reads use base64. File sizes, listings, trees, search matches, patches, and responses are bounded. Unified patches are path-validated and checked before application.

### Terminal and processes

- `terminal_exec`
- `terminal_start`, `terminal_status`, `terminal_output`, `terminal_write`, `terminal_stop`, `terminal_jobs`
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

- `tool_inventory`, `system_status`, `list_repositories`
- `fabric_status`, `model_status`, `run_tests`, `run_mncs_evaluation`, `dispatch_fabric_job`

`tool_inventory` reports safe executable paths and first-line versions for common Python, Rust, Node, C/C++, Go, Java, container, shell, search, Ollama, NVIDIA/CUDA, and sandbox tools. It does not return the environment.

`run_tests` works for any immediate project and executes detected pytest or Cargo tests inside project scope. `run_mncs_evaluation` uses Forge's current typed operation registry for declared development workflows. `dispatch_fabric_job` now builds a Fabric artifact manifest, validated `mncs-fabric.job-plan.v0.1`, deterministic EA-NEXT-002 bundle, and calls `FabricClient.execute`; supported task types are `pytest`, `python`, and `cargo_test`. `artifact_path` can select a bounded artifact subtree. Fabric still owns worker discovery, admission, routing, transfer, execution, and receipts. Raw model routing is not invented at this layer; Harness remains responsible for model/agent execution.

`integration.fabric_controller_id` must equal the controller identity recorded by the chosen Fabric worker registry. The example uses `epi13-local-harness`, which is the normal Harness-owned registry identity. A mismatch is reported as unavailable rather than silently assuming another controller identity.

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

Example user-systemd templates are in `deploy/systemd/`. Copy and edit them manually; installation is not automatic.

## Tests

```bash
pytest
ruff check .
python -m compileall -q src
```

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
