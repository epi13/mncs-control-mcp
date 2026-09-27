# Workspace storage stewardship

`mncs-control-mcp` owns this capability because it is the existing host boundary
for workspace filesystem authorization, process visibility, and file mutation.
The control-engineering repository owns dynamical controllers; Actions owns
GitHub verification transport; Doctor diagnoses repository state; Store owns
durable records; and Automation owns when declared work runs. None of those
boundaries currently provides a local, process-aware workspace reclamation
operation.

## Workflow

Use these tools in order:

1. `workspace_storage_inventory` reports filesystem capacity, workspace size,
   largest immediate projects, and categorized generated-data roots.
2. `workspace_storage_plan` classifies Cargo target roots against repository,
   worktree, filesystem, and live-process evidence. A plan never removes data.
3. Review the candidate paths and reasons. Only entries with state
   `reclaimable` are eligible.
4. `workspace_storage_reclaim` requires the fresh `plan_id` and
   `confirm=true`. It repeats the checks before deleting any entry and checks
   process references again before each deletion.
5. Run a new inventory to verify the result.

Plan IDs are held by the running Control process and expire after 15 minutes.
Restarting the MCP server invalidates them. A changed repository head, dirty
worktree, changed target tree, new process reference, incomplete process scan,
or failed measurement invalidates the plan before deletion. A second inventory
and plan after successful cleanup is safe and reports the removed target as
absent.

## Classification and safety

The first supported reconstructable class is a Cargo target directory, detected
from Cargo's `.rustc_info.json`, valid `CACHEDIR.TAG`, and a
`debug/.fingerprint` or `release/.fingerprint` tree. Reclamation delegates to
`cargo clean` with the planned target path; it never falls back to recursive
deletion. The plan requires all of these conditions:

- the target is inside the configured workspace and a Git worktree;
- the worktree is clean and on the repository's default branch;
- Git reports exactly one registered worktree for that repository;
- Git tracks no files below the target;
- the target is not a mountpoint and has no symlink, special file, nested
  mount, or hardlink whose other link is outside the target;
- the complete target-tree metadata fingerprint still matches the plan;
- the process scan is complete and no process command, environment, working
  directory, executable, mapped file, or open descriptor refers to the target;
- the target's size measurement and repository identity are available.

Dirty repositories, feature branches, multi-worktree repositories, and active
processes remain protected. The tool does not use path names or age by
themselves as evidence. Cargo outputs can be recreated from their project
sources and dependency declarations; build cache loss may require recompiling
or downloading dependencies again.

Other recognized roots are reported without deletion support: `.mncs` runtime
state, Python environments, `node_modules`, generic build directories,
execution runs, snapshots, traces, logs, test output, and unrecognized `target`
trees. They may contain unique or owner-specific state. In particular,
content-addressed MNCS application artifacts remain under their producing
subsystem's lifecycle policy, not a generic workspace deletion rule.

The workspace size and candidate sizes use GNU `du` allocated-block
measurements. Btrfs compression and shared extents mean allocated directory
bytes can differ from physical free space after deletion; the reclaim result
reports both allocated bytes removed and the measured available-space delta.

## Initial workspace investigation (2026-09-26)

The measured workspace tree was 261,249,110,016 bytes (261.25 GB / 243.31
GiB). An initial scan attributed 213,074,001,920 bytes (213.07 GB / 198.44
GiB) to 48 Cargo target roots. The later marker-based inventory classified 30
roots as Cargo targets (203.88 GB) and kept 16 unrecognized `target` trees
(1.22 GB) separate. Root counts and sizes can change as active worktrees build
or remove outputs. Cargo's default target location is inside each project or
worktree; no workspace-level target directory or retention policy was
configured. Campaign and linked worktrees therefore accumulated separate
build trees. `.gitignore` kept these files out of Git but did not give them a
lifecycle.

Other measured categories included about 18.88 GB of Python environments, 1.33
GB of `node_modules`, 3.92 GB of run/test output, 7.01 GB of other build trees,
and 2.66 GB of `.mncs` runtime state. The latter included Forge's 1.37 GB
native-application cache, whose content-addressed entries currently have no
bounded retention policy. That cache was kept because Forge was running and its
entry reachability is owned by Forge. SenseTrace run output and other snapshots
were kept as unique or unclassified state. `mncs-compiler/.bootstrap` was also
kept because the compiler repository was active.

The largest Cargo tree, `mncs-language/target` at 64.17 GB, was explicitly
preserved: its repository was dirty and on a campaign branch, it had multiple
registered worktrees, and a running MNCS process used its binary. The language,
compiler, and memory repositories and their active worktrees were not cleaned.

Only four clean, sole-worktree repositories on their default branch had Cargo
targets with no tracked files, unsafe filesystem entries, or process references:
`mncs-system-monitor`, `mncs-tui`, `mncs-validator-rs`, and `mncs-vm`. Cargo's
own cleanup removed those targets. Their planned allocated size was 7.89 GB;
the workspace `du` measurement fell by 7.86 GB, from 261.25 GB to 253.39 GB.
Btrfs' measured exclusive usage fell by 7.85 GB, while filesystem available
space increased by 3.60 GB over the same interval. The latter is a system-wide
net measurement while other workspace processes remained active. Remaining
storage includes protected build trees, environments, Forge cache state, and
unique run data; the inventory and plan keep those visible without treating
their names or age as permission to delete them.

The strict post-cleanup inventory classified 29 marker-confirmed Cargo target
roots at 191.35 GB, plus 16 unrecognized `target` roots at 1.22 GB. It also
found 17 other build roots at 6.32 GB, 17 Python environments at 18.88 GB, 107
Python cache roots at 287 MB, 2 generic cache roots at 685 MB, and 4 execution
output roots at 3.85 GB. It reported 81 `.mncs` roots at 2.29 GB. No workspace
`.npm` or `.pnpm-store` roots were found.

One further 12.53 GB Cargo-shaped tree, `.mnel-recon-target`, lacked Cargo's
`CACHEDIR.TAG`, so it is classified as unknown and not eligible for cleanup.
Its `.d` files refer to a temporary MNEL reconstruction checkout under `/tmp`
that is now absent and is not a registered `mncs-language` worktree. The old
`mncs`/`mncs-mcp`/`mncs-lsp` binaries were not open in the process check; no
Cargo or rustc build process referenced the tree. Because its cache marker and
source checkout are missing, its contents were preserved. The remaining seven
directories literally named `debug` totaled 221 KB, including the MNCS Debug
subsystem snapshots at about 45 KB. These unknown categories remain
inventory-only until ownership and reconstructability are established.

## Ownership and maintenance

This is a host capability, not a second storage database or a project-specific
`clean_mncs_projects` operation. It measures only the configured workspace and
does not persist every observation. A deliberate reclaim call is destructive
and is marked as such in the MCP tool annotations.

There is no unattended deletion timer. The current Automation target model has
no filesystem-pressure condition or storage-reclaim target, and an ephemeral
plan ID is unsuitable as a recurring authorization. When Automation gains a
typed storage observation target, it can run inventory and plan checks on a
schedule or disk-pressure trigger. That integration should report pressure and
proposed reclaimable bytes; it must not bypass the explicit, fresh plan and
confirmation boundary. Do not add a second scheduler in Control to work around
that missing Automation surface. Until then, maintenance is an explicit
inventory/plan/review/reclaim operation; this release adds safe capability and
removes repeated manual classification, but does not claim unattended cleanup
or a hard cache-size bound.

The current bounds are therefore operational and explicit: source work,
registered multi-worktree builds, active builds/tests, and unknown state are
never reclaimed by this capability; known idle Cargo outputs can be reviewed
and removed without repeated filesystem archaeology.
