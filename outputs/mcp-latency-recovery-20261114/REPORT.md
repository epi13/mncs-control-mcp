# Control MCP latency recovery — workstream B

The recovered Slice A implementation now reuses exclusively leased Store handles, skips unchanged historical snapshot revisions during continuation lookup, and avoids redundant Environment source hashing. Public response schemas, authentication, principal isolation, scope grants, claim recovery and claim-version fencing are unchanged. No persistent index, permission cache, response cache or additional projection file was introduced.

Workstream A is delivered separately in `mncs-store/outputs/test-throughput-20261114/REPORT.md`: Store main contains `0d08e35` and `5464f04`; Language main contains `f8742e9`. The complete Store suite passed 292 tests in 221.88 seconds, and the three touched Language crates passed 392 tests. The original blob-boundary workload completes all 1,734 batches / 4,330 cases in 16.64 seconds cold and 13.42 seconds warm. Debug compilation contributed to the pathological run, but repeated compilation, experiment preparation and multi-megabyte serialization remained expensive with release builds. The retained native reference path preserves independent body/SSA/backend agreement and real research-bytecode execution. Compiled backends remain separate conformance checks, not replacements for that oracle.

## Recovered work and verified causes

The existing `fix/mcp-latency-recovery-20261114` worktree contained 351 insertions and 42 deletions across `environment_sessions.py` and `environment_rpc.py`, based on `94ccc45`. That implementation was retained and completed. Its original diff SHA-256 was `100586e149af86b248db7b5b587a2763c37b58354ee674f6b5723f25372b2474`. No previous Store-index implementation was found to adopt.

Three costs were verified:

1. Each package admission started seven Git processes and read/hash-processed 7,584,338 bytes from 112 Python source reads, even when source was unchanged. Git-state verification is useful; separately spawning overlapping probes and hashing identical bytes twice are unnecessary.
2. Each continuation query opened and closed an EmbeddedStore-backed Environment provider, losing useful immutable generation/binding caches. Multiple passes also loaded the same snapshots. In the actual 615-session workspace, the baseline made 762 snapshot loads and 161 measured native batch calls per request.
3. The recovered implementation improved warm lookup but retained full historical and foreign snapshots in an operation-local catalog. Its observed process peak was 1,049,300 KiB, versus 548,448 KiB in the original baseline. Restricting retention to owned nonterminal candidates brought the final two-request process peak to 545,948 KiB. This is measured peak process RSS, not a proof of a universal memory bound.

## Changes and authority

- Combine overlapping `git rev-parse` probes: four Git processes per admission. Repository root, common-directory identity, registered worktree, local main revision and clean-source checks still run on every request. There is no cross-request Git-result TTL.
- Reuse the exact source-content digest only when the complete sorted source inventory and each file's device, inode, mode, size, nanosecond modification time and change time are unchanged. Recheck metadata after hashing, reject source symlinks, and fail rather than cache an interrupted fingerprint. The bounded in-memory LRU holds at most 32 package fingerprints. The existing before/after import identity checks remain.
- Retain at most four idle Store providers per service; concurrent borrowers receive distinct handles. The key retains the actual package module plus canonical state path, preventing module-object-ID reuse across reloads. Package/state changes close stale idle handles and clear metadata. Failed or interrupted borrowers are discarded; shutdown closes idle handles and closes outstanding ones when returned. RPC shutdown now also closes its Environment service.
- Obtain snapshot heads from authoritative bindings at the observed Store generation. Cache only immutable revision metadata, at most 16,384 entries, keyed by state path, session ID and revision. Reject cache insertion unless the loaded snapshot's integer sequence exactly matches the head, avoiding mislabeling a read that races an advance. Missing binding support uses the established compatibility path.
- Skip unchanged terminal/nonmatching revisions and reuse owned active candidates within an operation. Current candidates and claims are still read; authenticated principal, checkout, scope-grant and task-selector checks still apply. Unavailable reads and permission decisions are not cached. UNKNOWN readiness and incomplete operations remain visible.

No canonical snapshot, Store generation, transaction recovery, source authority or historical-data format changed. Control does not parse Environment's decomposed snapshot envelopes or take over Store indexing. The existing complete context/detail interfaces remain available, with unchanged response contracts.

## Measured behavior

`pkg_probe.py` and `context_probe.py` are optional bounded reproductions, not installed interfaces. Measurements use separate fresh Python processes, sequential execution and explicit external 180-second budgets for the real-context batches. “Cold” means fresh service/provider caches with ordinary filesystem caching; the host page cache was not flushed. Query instrumentation observes calls without changing their results. Source admission measurements exclude Store access.

| Package admission | Before | Final |
| --- | ---: | ---: |
| Fresh process | 69 ms | 55.7 ms |
| Subsequent calls | 30.3–32.6 ms | 11.5–12.1 ms |
| Git processes per call | 7 | 4 |
| Source reads / bytes, first call | 112 / 7,584,338 | 56 / 3,792,169 |
| Source reads / bytes, warm call | 112 / 7,584,338 | 0 / 0 |

The actual continuation query uses the authenticated session's recorded checkout, definition and workspace against the real 615-session state. It returns the same owned active continuation, readiness/claim context and actionable next step. All measured responses are 19,033 JSON bytes. Whole-response hashes differ because observations include live timestamps; no byte-for-byte equality claim is made. The response-size work had already been delivered in `94ccc45`; this slice reduces assembly work while retaining that information.

| Continuation query | Baseline | Final |
| --- | ---: | ---: |
| Fresh service | 49.27 s | 49.78 s |
| Second query | 49.59 s | 21.66 s |
| Snapshot loads, cold / warm | 762 / 762 | 762 / 318 |
| Measured native batches, cold / warm | 161 / 161 | 161 / 48 |
| Store opens, cold / warm | 1 / 1 | 1 / 0 |
| Claim reads, every request | 2 | 2 |
| Git processes, every request | 7 | 4 |
| CPU, cold / warm | 49.021 / 49.425 s | 49.590 / 21.571 s |
| Peak RSS, two-request process | 548,624 KiB | 545,948 KiB |

The original baseline and the recovered intermediate are also retained as `context-baseline.json` and `context-recovered.json`. Their generation was 131789. The final measurement and repeated current baseline use generation 131795; both start and end at that generation. There were six intervening own-claim bookkeeping generations, not a production migration. All three inventories contain 615 sessions. The measured read paths publish no Store generation.

Cold continuation remains expensive and is not claimed improved. Warm operation removes repeated preparation and historical payload work without constructing a complete cached response. Native batch counters cover the instrumented Store session calls, not every provider in MNCS. Raw JSON measurements contain wall/user/system time, provider-call counts, output bytes and process RSS.

## Verification

The targeted integration command ran the six suites `test_environment_sessions`, `test_environment_rpc`, `test_local_environment_mcp`, `test_environment_response_views`, `test_environment_mcp_client` and `test_environment_read_efficiency` under a 600-second external limit. Result: **222 passed, one skipped, 40.11 seconds**. The skip explicitly reports the unavailable optional Rights library for gate enforcement; it is not a PASS. Command wall time was 40.49 seconds, user/system CPU 36.40/1.41 seconds, peak RSS 664,640 KiB. No full-Control-suite PASS is asserted.

The new bounded tests cover 0/100 historical sessions, exclusive leases, idle bounds, shutdown with outstanding borrowers, I/O failure and interruption, package/state invalidation, module lifetime, metadata eviction and revision races, unchanged-source reuse, same-length source edits with restored mtime, source addition/removal and symlink refusal. Warm selection preserves unknown readiness and incomplete operations, observes provider loss/recovery, rejects another principal, observes a newly linking claim and its removal, and excludes a newly completed revision.

The real isolated-Store integration additionally advances the generation from a separate service: the warmed reader observes session completion and claim acquisition/release. Two intervening read-only queries leave the generation unchanged. Existing integration tests exercise selected checkout and main-source changes, source reloads, unregistered lookalike rejection, task-selector conflicts, foreign ownership, authenticated grant routing, exact claim-recovery generation/session checks, fresh-process continuation and real MCP provider loss. Ruff on all four changed Python files and `git diff --check` pass.

The first integration attempt exposed an incorrect new test assertion: an explicitly named campaign with one candidate returns `ready` and a continuation list but need not expose `selected_session_id`. The assertion now verifies the exact candidate list, preserving the established schema. The implementation was not altered to satisfy that mistaken assertion. The corrected full targeted run above passed.

## Remaining Store investigation — workstream C deferred

`mncs-environment/mncs_env/store_backend.py:MncsStoreBackend.read_snapshot` enumerates the current generation's complete binding inventory separately for each session, then reconstructs that session's complete snapshot. This compounds session count with binding count during cold discovery. Even the final warm query still loads 318 active/candidate snapshots and makes 48 measured native batches. The remaining cold cost is approximately 50 seconds. This is the highest-priority continuation, supported by actual data rather than a speculative new index.

A later correction should remain with the owning Environment/Store read API, consider generation-keyed snapshot-head lookup or selective authoritative metadata, and measure current and historical lookup separately. Store's `current_generation` is a live property reading authoritative head state, not a frozen value in a pooled handle; the external-writer test confirms visibility. No new Store indexing, migration, reclamation or historical garbage collection was implemented in this assignment. This deferral follows the user's stated scope after the completed test and MCP repairs.

The reference CLI also still eagerly prepares stateful layers for experiments with no stateful cases; workstream A measured 344 ms on a manifest sample. The retained test path avoids that repeated preparation without broad compiler redesign.

## Separate Environment retirement finding

During workstream A cleanup, combined branch/worktree retirement attempted the branch before removing its checkout, returned pending/UNKNOWN, then removed the worktree. Retrying the exact request failed with `request identity was already used for a different Environment operation`. A subsequent branch-only attempt from a session whose selected checkout was gone failed authority revalidation. Fresh cleanup authority from the canonical checkout completed physical retirement; all own A branches/worktrees and claims were removed/released. Small original diagnostics are retained alongside this report. This is a reproducible, separate Environment lifecycle problem, not silently represented as successful initial retirement and not expanded into this repair.

## Delivery and activation

Source commit `03f47e2` is merged into Control main and pushed; remote-ref readback agrees. Connected `system_status` confirmed runtime and source both at `03f47e2`, with `restart_required=false`, after the configured watcher recycled the service. See `delivery.json` for the recorded details. Language's remote main has badge-only successor `ca71830`, whose ancestry includes `f8742e9`; its local checkout remains at the activated source commit. Store remote main is `5464f04`. The pre-existing modification to Control main's `.mncs/project-view.json` is preserved byte-for-byte (SHA-256 `0e87ef563e47a8c60c3f1b3e72b67f2f65748dc41f899d00439dc1c45bd41d94`). Foreign worktrees and Language's pre-existing `.mncs/cache/` are preserved.

New EnvironmentService instances use the change immediately. Existing Control processes load it on their normal source-update recycle; the installed `mncs-control-update.path` watcher was observed active and watches main. No additional state/cache migration or new agent maintenance step is required. The release Language CLI/embed pair was rebuilt and activated for workstream A, followed by 137 canonical-checkout smoke tests. This work does not manually stop shared services or claim that a stale caller's captured tool registration has refreshed.
