# Atlas Journal integration

MNCS Control exposes a bounded local-evidence projection for the Atlas Journal
Maintainer. Atlas owns journal semantics, editorial synthesis, validation, and
publication. Control owns only protected access to machine-local development
evidence. A bundle is evidence, not a journal draft, specification, acceptance
decision, conformance result, or project-memory authority.

## Workflow

The scheduled editor should obtain the uncovered interval from Atlas, then call:

```text
journal_context_status()
journal_context_collect(start, end, projects=[...])
journal_context_get(bundle_id, cursor=...)
```

`journal_context_collect` creates an immutable private bundle with a stable
`jctx-...` ID and `sha256:...` content hash. Responses are paginated. Each item
has a source class/system, project and locator, timestamp, interval, local-only
and development-state markers, source completeness, redaction/truncation,
confidence, unresolved/negative flags, and `untrusted_data=true`.

## Evidence sources and ownership

- Local repositories and working trees use the existing bounded Git/workspace
  surfaces. Local-only commits, branches, staged/unstaged paths, and untracked
  paths are provisional developmental evidence.
- Durable experiments are projected from `ExperimentManager`; Control does not
  create a second experiment store or reinterpret results.
- Commons is queried through its public consumer socket. Control never opens the
  Commons backing store.
- Fabric is queried through the public consumer API and yields execution
  references only. Execution is not correctness or conformance.
- Forge references are limited to existing public integration status and
  Forge-related Control activity. Forge remains the evidence owner.
- Control activity is a redacted project-scoped chronology. Raw commands,
  environments, credentials, tokens, and unrelated activity are not exposed.
- Local notes are restricted to configured include patterns beneath an allowed
  project root, with byte/item limits and generated/vendor/cache exclusions.

Commons, Fabric, Forge, Harness, and Atlas retain their own lifecycle and
authority. Control is an aggregation/projection surface, not a universal event
store.

## Completeness and privacy

Source states are explicit: `AVAILABLE`, `PARTIAL`, `EMPTY`, `UNAVAILABLE`,
`UNKNOWN`, `MALFORMED`, or `SKIPPED`. `EMPTY` means the source was inspected and
no interval records were found; `UNAVAILABLE` means it could not be inspected.
The editor must not turn a missing source into a confident claim.

Repository text, notes, commit messages, experiment material, Commons records,
and terminal-derived strings are inert untrusted data. Editor hints can be
passed to collection as low-authority, non-persisted hints; they are not stored
project truth and cannot authorize server behavior.

## ChatGPT memory boundary

Control does not recreate or scrape ChatGPT conversation or personal memory.
The scheduled editor may bring its own project/conversation context. Control
contributes only bounded evidence that exists on the authorized local machine.
