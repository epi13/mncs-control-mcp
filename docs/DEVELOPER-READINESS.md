# Journal context readiness

`journal_context_status` reports the bounded local evidence classes available to
the Atlas editor. The same projection is included in `developer_readiness` when
the full server is running. States are explicit (`AVAILABLE`, `PARTIAL`,
`EMPTY`, `UNAVAILABLE`, `UNKNOWN`, `MALFORMED`) so no records and inaccessible
records remain distinguishable.

# Developer readiness

`mncs-control-mcp doctor` and the MCP tool `developer_readiness` observe whether
an authorized agent can complete:

inspect → edit → analyze → test → Forge verify → commit → push → PR

They do not grant those capabilities.

## How to run

```bash
cd ~/Documents/Projects/mncs-control-mcp
./scripts/doctor.sh
./scripts/doctor.sh --json
```

From an MCP client, call `developer_readiness`. Optional `repository` adds a
Forge candidate-freshness check for that project.

## What is checked

| Area | States |
| --- | --- |
| Project root / workspace write | available, unavailable |
| Git read/write | available, unavailable |
| GitHub authentication | available, authenticated_insufficient, misconfigured, unavailable |
| GitHub push and PR write | available, authenticated_insufficient, degraded, unavailable |
| SSH agent | available, degraded, optional |
| Forge evaluate / candidate freshness | available, degraded, optional |
| Fabric execute | available, degraded, unavailable |
| Commons read / publish | available, optional |
| ELH / Ollama | optional |

JSON includes a `capabilities` object with names such as `git.read`,
`github.push`, `github.pull_request.write`, `forge.evaluate`,
`fabric.execute`, `commons.read`, and `commons.publish`. `authorized` means the
capability was observed, not that the doctor created it.

## GitHub authentication

Authority comes from the operator's GitHub CLI login or from
`~/.config/mncs-control-mcp/github.env`. Control materializes a 0600 `gh`
hosts file in the dedicated sandbox home and configures
`gh auth git-credential` for HTTPS remotes. The desktop keyring, private keys,
and real home are not mounted, and the token is not placed in process
arguments.

Rotate by replacing the env file, running `gh auth login` again, or revoking the
GitHub token, then restarting `mncs-control-tunnel.service`.

## Forge candidates

`forge_candidate_status` reports whether the bound candidate still matches the
working tree. `forge_candidate_refresh` registers a successor when it does not.
`run_mncs_evaluation` refreshes automatically for candidate-scoped workflows.
Historical evidence stays attached to the previous identity.

## Troubleshooting

- `ksshaskpass` / `No such device or address`: the askpass guard should prevent
  this. If it reappears, confirm you are using the updated Control server.
- `Permission denied (publickey)`: the session SSH key is not registered with
  GitHub. HTTPS + `gh` is the supported path; SSH is optional.
- `You are not logged into any GitHub hosts` inside the sandbox: host `gh auth
  status` must succeed, or `github.env` must exist with mode `0600`.
- `candidate no longer matches current content`: call `forge_candidate_refresh`
  or let `run_mncs_evaluation` rebind, then evaluate again.
