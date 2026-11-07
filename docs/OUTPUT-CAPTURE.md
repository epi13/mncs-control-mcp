# Bounded terminal output availability

Terminal job status, inventory, persistence and output responses carry
`output_capture`, schema `mncs.control.output-capture/1`. Each stream reports:

| Status | Meaning |
| --- | --- |
| `available-empty` | A live buffer exists and has captured zero bytes so far. |
| `available-content` | A buffer exists with content and no discarded prefix. An incremental read may still return empty. |
| `truncated` | A bounded buffer discarded a prefix; its retained raw byte range is explicit. |
| `unavailable-restored` | Metadata identifies a known capture lifecycle, but restart did not retain its buffers. |
| `expired` | The owner explicitly recorded capture removal; no bytes are available. This is reserved for an explicit removal record, never inferred from age. |
| `unknown` | Legacy/unsupported metadata or an operation without known stream capture. |

`available` and raw `start_offset`, `end_offset`, `retained_bytes`, `limit_bytes`
distinguish known zero from unavailable (`null`). Offsets describe capture bytes
before decoding/redaction. Each stream's output text, offset and capture metadata
come from the same locked read. Streams remain independently observed.
`process_complete` concerns terminal process status, not verified work or stream
usefulness. An empty running buffer does not establish empty completed output.

Existing text, offsets and `output_truncated` remain compatible. The latter
reports whether the requested read offset lost bytes, not whether capture exists.
Reading at the end of a truncated buffer can return empty text and false while
the capture status correctly remains `truncated`.

No historical output is reconstructed. Storage remains two bounded in-memory
buffers per live terminal job plus the existing maximum 100 persisted job rows.
Persistence adds metadata, never raw terminal output. After restart, known live
lifecycle records become `unavailable-restored`; legacy rows remain `unknown`,
including across another persistence/restart cycle. No new retention daemon,
output database, expiry tool or authorization path is introduced. Existing job
ownership, redaction and input/offset limits remain authoritative.

`schemas/output-capture.schema.json` is the machine-facing transport shape.
Lifecycle semantics stay in Control's canonical process boundary. Environment
may consume source references and availability, but cannot reconstruct diagnostics
from the exit status. The nine new capture tests exercise actual fixed empty and
nonempty processes, retention, truncation, restart, legacy/explicit expiry records,
and refusal boundaries. These prove mechanics, not saved agent effort.
