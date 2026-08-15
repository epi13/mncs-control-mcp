# ChatGPT and Secure MCP Tunnel setup

This repository runs a private stdio MCP server. The persistent Fedora unit runs
`tunnel-client`, and the tunnel client owns the MCP child process. No inbound HTTP
listener is opened.

The current official reference is the [Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).
It requires a real `tunnel_id`, a runtime API key, and an MCP command reachable
over stdio. Tunnel permissions and ChatGPT Developer Mode access are separate.

## Fedora setup

From the repository:

```bash
cd ~/Documents/Projects/mncs-control-mcp
./scripts/install-user-service.sh --no-start
```

The installer is idempotent. It creates or updates `.venv`, installs the editable
package, preserves an existing `control.toml`, installs the user unit, creates
private state/config directories, and imports the current `SSH_AUTH_SOCK` when one
is available.

If Bubblewrap is missing, install it as an operator and rerun:

```bash
sudo dnf install bubblewrap
```

Install `tunnel-client` only from the download link in OpenAI Platform tunnel
settings or the latest official `openai/tunnel-client` release. The repository
does not download an unverified binary. Place it at:

```text
~/.local/bin/tunnel-client
```

Create the runtime environment file with mode 0600:

```bash
nano ~/.config/mncs-control-mcp/tunnel.env
```

Set only:

```text
CONTROL_PLANE_API_KEY=<runtime-key>
```

Do not put the key in Git, `control.toml`, the tunnel profile command, or a shell
argument. The installer never prints an existing key.

Create or manage the tunnel in Platform tunnel settings, associate the target
Platform organization and ChatGPT workspace, then initialize the local profile:

```bash
./scripts/install-user-service.sh --tunnel-id tunnel_...
```

This uses the official local stdio profile shape:

```bash
tunnel-client init \
  --sample sample_mcp_stdio_local \
  --profile mncs-fedora \
  --tunnel-id tunnel_... \
  --mcp-command "$HOME/Documents/Projects/mncs-control-mcp/.venv/bin/mncs-control-mcp --config $HOME/Documents/Projects/mncs-control-mcp/control.toml"
```

Existing profiles are preserved. Use `--repair-profile --tunnel-id tunnel_...`
only when you intentionally want to regenerate the named profile.

## Health and service operation

```bash
./scripts/doctor.sh
systemctl --user status mncs-control-tunnel.service
journalctl --user -u mncs-control-tunnel.service -f
```

The doctor performs a real MCP `initialize` and `tools/list` exchange and checks
the required tool set. It reports missing tunnel-client, missing keys, profile
doctor failures, SSH-agent state, Fabric/Harness/Forge, Ollama, CUDA, and the
systemd unit without printing secrets.

For a repeatable local protocol check independent of ChatGPT, run:

```bash
./scripts/mcp-smoke.py --config control.toml
```

It performs only initialize, tools/list, and read-only calls. A passing local
smoke or doctor result does not prove that the ChatGPT connector is registered
or reachable; that remains an external verification step.

In the intended service configuration, Control connects to the Fabric-owned
consumer socket at `~/.local/state/mncs-fabric/controller.sock`. It does not
copy a registry or trust ledgers, does not need worker certificates, and does
not connect to the admin socket. `fabric_status` reports controller connection,
fleet authority, worker observations, and the current execution transport.
The controller-owned service status advertises execution support only when its
authenticated worker backend is configured and reachable. In that case
`dispatch_fabric_job` uses `FabricClient.connect()` and reports
`execution_transport=persistent-service`. If the connected controller does not
advertise execution, Control reports `FABRIC_SERVICE_EXECUTION_UNSUPPORTED`;
select transitional mode only when direct embedded execution compatibility is
intended. A configured controller backend, including authenticated worker
rendezvous, advertises support through the same live feature projection.

Convenience commands are available through:

```bash
./scripts/service.sh status
./scripts/service.sh restart
./scripts/service.sh logs
./scripts/service.sh doctor
```

The service is enabled for `default.target`, uses absolute paths, restarts on
failure, and retries after temporary network loss through tunnel-client's own
reconnection behavior. If the MCP or tunnel process exits, systemd restarts the
service chain. A missing configuration or executable fails clearly in the
journal.

## SSH agent behavior

The service does not create a competing SSH agent or mount private keys. It
inherits/imports the session `SSH_AUTH_SOCK`; the wrapper also recognizes the
standard Fedora session socket at `/run/user/<uid>/ssh-agent.socket`. If no agent
exists, the tunnel still starts, but authenticated remote Git operations may
fail. Loading a passphrase-protected key may still require an interactive login.

Optional hardening includes short key lifetimes or confirmation mode:

```bash
ssh-add -c -t 8h ~/.ssh/<github-key>
```

For GitHub, host `gh auth` may legitimately use the desktop keyring, but that token
is intentionally unavailable inside MCP sandboxes. Register the public key that is
already loaded in the session agent, switch the repository remote to SSH, and verify
the same agent-backed path:

```bash
gh auth refresh -h github.com -s admin:public_key
gh ssh-key add ~/.ssh/id_ed25519.pub --title "fedora mncs-control"
git remote set-url origin git@github.com:OWNER/REPOSITORY.git
ssh -T git@github.com
```

This keeps private keys in the agent and avoids placing tokens in `tunnel.env`, Git
configuration, the workspace, or MCP sandbox state. If `gh ssh-key add` reports a
missing scope, complete the one-time browser/device authorization requested by
`gh auth refresh` and retry it.

## Reboot and lingering

With the normal graphical login, the user unit starts from `default.target` after
the user manager is available. The current workstation reports `Linger=no`, so
the service is not expected to run before login. To start user services at boot,
an operator may enable lingering:

```bash
sudo loginctl enable-linger "$USER"
```

Lingering does not manufacture an SSH agent or unlock a private key. Fully
unattended remote Git authentication therefore still depends on the chosen agent
and key policy.

Fabric workers have the same systemd user-session consideration. For example,
a representative Linux worker can remain available after the enrollment
SSH session closes only after an administrator enables lingering for its
dedicated `fabric` account, then enables its worker unit as that account:

```bash
sudo loginctl enable-linger fabric
systemctl --user daemon-reload
systemctl --user enable --now mncs-fabric-worker.service
```

Do not expose the worker's user bus to arbitrary jobs or copy its private key to
the controller. Verify the result with `loginctl show-user fabric -p Linger` and
`systemctl --user is-active mncs-fabric-worker.service`; the controller still
requires the enrolled mTLS certificate and current trust ledger.

## ChatGPT browser steps

After `./scripts/doctor.sh` reports tunnel-client, runtime key, profile, and
service health as OK:

1. Ensure ChatGPT Developer Mode is enabled for the account/workspace. Availability and write-tool permissions depend on the ChatGPT plan/workspace policy.
2. Open the ChatGPT developer-mode app/plugin creation flow.
3. Choose **Tunnel** under **Connection**.
4. Select the tunnel associated with the correct ChatGPT workspace, or provide the valid tunnel ID.
5. Name the app **MNCS Control**.
6. Save/discover the MCP tools and enable the app in a chat.
7. Test with: `Use MNCS Control and call workspace_info.`
8. Then test: `Use MNCS Control and list my projects.`
9. Then test: `Use MNCS Control and run system_status.`
10. Finally create a disposable project and perform a harmless write/read test.

For a useful orchestration smoke test, ask the app to `review mncs-language`,
`show laboratory_status`, or run a bounded `dispatch_fabric_job` with
`wait=false`; retrieve its `ctrl-...` result using `control_job_status` and
`control_job_result`.

For the physical worker/model path, refresh the Harness inventory from the host and
use an exact pin so unavailable workers fail closed:

```bash
"$HOME/Documents/Projects/mncs-harness/.venv/bin/mncs-harness" fabric refresh
"$HOME/Documents/Projects/mncs-harness/.venv/bin/mncs-harness" models --worker worker-01-windows --json
"$HOME/Documents/Projects/mncs-harness/.venv/bin/mncs-harness" ask \
  'Compute 17 + 25 and reply with RESULT=42 plus one short explanation.' \
  --worker worker-01-windows --model-name "$WINDOWS_MODEL"
"$HOME/Documents/Projects/mncs-harness/.venv/bin/mncs-harness" models --worker worker-01-linux --json
"$HOME/Documents/Projects/mncs-harness/.venv/bin/mncs-harness" ask \
  'Compute 17 + 25 and reply with RESULT=42 plus one short explanation.' \
  --worker worker-01-linux --model-name "$LINUX_MODEL"
"$HOME/Documents/Projects/mncs-harness/.venv/bin/mncs-harness" residency status
```

The expected evidence is `AVAILABLE`, a current worker observation, the selected
worker/model, `execution_source=remote`, Fabric request/record/receipt identities,
and residency still reporting the configured resident model. Do not add
`--allow-fallback` for an exact routing smoke test.
A representative Linux worker should keep the operator-configured model pin;
Harness disables an incompatible thinking option while preserving the exact
worker/model pin. The `elh` command remains a compatibility alias.

If the tunnel is not listed, verify the workspace association and Tunnels Read +
Use permission. If discovery fails, confirm the service is active and rerun
`tunnel-client doctor --profile mncs-fedora --explain`.

## Updates

```bash
cd ~/Documents/Projects/mncs-control-mcp
git pull
./scripts/install-user-service.sh
```

The update flow preserves `control.toml`, `tunnel.env`, and the existing tunnel
profile, reloads the user manager, restarts only when prerequisites are present,
and reruns the doctor. It does not commit or overwrite secrets.
