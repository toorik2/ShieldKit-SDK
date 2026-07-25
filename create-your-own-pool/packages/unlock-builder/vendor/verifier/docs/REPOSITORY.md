# Repository lifecycle and concurrency

The repository has three persistence classes:

- **Durable source** is tracked under a declared root in `repo.layout.json`.
- **Evidence under migration** remains path-stable until a lane-owned or generated replacement reaches parity.
- **Ephemeral execution state** lives under ignored `.vc/` and is subject to `control-plane.json` retention.

`npm run check:architecture` rejects undeclared tracked roots and undeclared local checkout entries. This keeps historical paths usable without allowing new top-level dumping grounds.

## Parallel agent rule

Never run two writing agents in one checkout. Create an arena from the primary checkout:

```bash
npm run vc -- arena create sub75-r1 --workers close,packing --target-lane bn254-onetx
npm run vc -- arena status sub75-r1
npm run vc -- arena check sub75-r1
npm run vc -- arena close sub75-r1 --yes
```

Each worker receives a branch, worktree, lane-derived write scope, local `.vc/` output tree, shared dependency links, and a worktree-local LeanBCH path. A worktree-specific pre-commit hook rejects out-of-scope changes. Closing repeats that check, refuses dirty worktrees, creates an incremental branch bundle when divergent commits exist, removes the worktrees, and retains the branches.

Branches are deleted only by finalization after every worker tip is reachable from a durable integration ref:

```bash
npm run vc -- arena finalize sub75-r1 --integrated-into master --yes
```

Finalization requires the integration commit to be reachable from a remote-tracking ref. Push and fetch through the normal repository workflow first. `--allow-local` is an explicit escape hatch for tests or repositories intentionally lacking a remote; it is not machine-loss durable. Arena bundles under `.vc/` are local recovery aids, not remote backups.

Core work can use an explicit common scope instead of a target lane:

```bash
npm run vc -- arena create control-r1 --workers contracts,cli --scope packages/contracts,packages/cli
```

## Retention

Inspect cleanup without deleting:

```bash
npm run vc -- gc
```

Apply the checked-in policy:

```bash
npm run vc -- gc --yes
```

GC removes only expired run/check directories and finalized arenas. Active and closed-unfinalized arenas are never eligible. Place a `.keep` file in an ephemeral directory to pin it.

Historical commands that write fixed `generated/` or `/tmp/` paths run inside a worktree through:

```bash
npm run vc -- exec -- node build/chunked/pairing/example.mjs
```

The wrapper creates a collision-resistant `.vc/runs/<id>/` root, redirects known generator variables, and mounts a private run directory over `/tmp` with Bubblewrap.

## Naming

Live entry points follow `docs/NAMING.md`:

- lane directory == `lane.id`
- candidate filename == `{candidate.id}.json` with id prefixed by the lane id
- ephemeral runs/arenas under `.vc/` use `{topic}-r{n}` style ids

Architecture checks enforce the lane and candidate filename rules.

## Legacy roots

`build/`, `fri_stark/`, `fri_stark55/`, `tools/`, `intel/`, `catalogue/`, and `artifacts/` are classified migration surfaces. Each has a checked tracked-file ceiling and explicit destination in `repo.layout.json`; these roots may shrink but cannot silently grow. Classification is not promotion: direct legacy generators may still use historical output conventions and must run in an isolated worktree. New verifier implementation belongs in a lane; new shared mechanics belong in `packages/`.
