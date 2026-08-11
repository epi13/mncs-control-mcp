# Security notes

This service is a control boundary, not a general-purpose terminal. Its threat model assumes an MCP caller may deliberately send malformed or adversarial structured input.

Implemented controls:

- approved repository registry only;
- canonical path resolution and Projects-root containment;
- no caller-supplied filesystem paths for repository operations;
- fixed subprocess argv arrays and `shell=False`;
- filtered child-process environment;
- bounded execution time and stdout/stderr capture;
- output redaction and sensitive Git filename omission;
- structured error responses;
- loopback-only/local Ollama discovery through a fixed `ollama list` action;
- stdio transport with no public HTTP listener.

Do not put secrets in `control.toml`, source, test fixtures, MCP arguments, or logs. The tunnel runtime key belongs in the environment used to start `tunnel-client`, never in this repository.

The current service has no user authentication of its own. In the initial deployment, the local process boundary plus Secure MCP Tunnel organization/workspace permissions are part of the trust boundary. Before enabling mutating or long-running operations, add explicit operator authorization, persistent job ownership, rate limits, and a reviewable audit sink.
