# Beta-local integration

This runbook builds and re-verifies one private V2 Direct beta evidence root
from a completed single-contributor beta ceremony and its exact B-01-pre
runtime. It is an integration and custody exercise only. Its completion status
is `beta-single-contributor-local-integration-verified-unqualified`, and its
eligibility is `beta-single-contributor-unqualified`.

It is not an instance descriptor, pool launcher, broadcaster, network client,
release root, production profile, clean-host qualification, or a route to
promotion. The integration runner has no network or broadcasting interface and
does not resolve an instance descriptor or fetch remote data. That boundary
does not make its local artifacts suitable for a networked environment.

Every completion record retains the fixed false-claim set. In particular,
`finalKey`, `ceremonyQualified`, `d01Qualified`, `d02Qualified`, `b02Qualified`,
`bchVm`, all `q01` through `q09` qualification claims, `production`, and
`releaseQualified` are false. `betaSingleContributor:true` identifies the
limited assurance class; it is not a qualification result.

## Preconditions

Run from the root of a clean ShieldKit checkout. `prepare` and `contribute` in
the beta ceremony, and the integration build itself, reject staged changes,
unstaged changes, and non-ignored untracked paths. The build records the exact
Git commit and tree only after this check, so do not use a working checkout
which is also being edited.

The required inputs are:

- a completed and independently re-verified beta ceremony directory produced
  by [BETA_SINGLE_CONTRIBUTOR_CEREMONY.md](BETA_SINGLE_CONTRIBUTOR_CEREMONY.md);
- the exact canonical B-01-pre `manifest.json` which that ceremony binds; and
- the exact private B-01 runtime directory named by that manifest. Its
  `runtime-build-manifest.json`, complete inventory, and every required proof
  artifact must match the manifest.

Use direct, non-symlinked, private directories (mode `0700`) and regular
single-link private files (mode `0600`). The output must be a new path strictly
below this checkout's `.codex-build/` directory; the runner refuses an existing
output. `--temporary-root` is an absolute, normalized local path used by the
local sub-runners. Keep it private and dedicated to this run.

Before integration, re-verify the ceremony rather than treating the presence
of a result directory as proof:

```text
npm run ceremony:v2:beta-single -- verify \
  --ceremony-dir <absolute-beta-custody-directory>
```

This still reports an unqualified beta result. It does not establish unknown
toxic waste, contributor independence, destruction, final-key provenance, or
permission to use the key outside this local lane.

## Build one private evidence root

From the ShieldKit checkout root, use the beta-only package entrypoint:

```text
npm run qualification:v2:beta-local-integration -- \
  --ceremony-dir <absolute-beta-custody-directory> \
  --b01-manifest <absolute-b01-pre-manifest.json> \
  --b01-runtime <absolute-b01-pre-runtime-directory> \
  --output "$PWD/.codex-build/beta-local/<new-run-id>" \
  --temporary-root <absolute-private-temporary-directory>
```

All five option/value pairs are required exactly once. The supplied B-01
manifest must match the ceremony's bound B-01 manifest hash. The runner refuses
non-private, symlinked, incomplete, altered, or inventory-inconsistent runtime
inputs; it also refuses Node preloads, loaders, inspectors/evaluators, and
ambient loader controls such as `NODE_OPTIONS`, `NODE_PATH`, `LD_*`, or
`DYLD_*`.

The build copies the complete ceremony and the exact required B-01 manifest,
profile, witness WASM, and circuit-symbol artifacts into private custody. It
validates the supplied B-01 runtime's complete manifest and exhaustive
inventory before taking those copies; it does not copy unrelated B-01 runtime
files. It then derives a beta-only profile and instance binding and creates and
independently checks local proof, PF10 runtime, Libauth, and
persistence/recovery evidence. It writes a canonical completion record at:

```text
<output>/beta-local-complete.json
```

The record binds the recorded Git commit/tree, ceremony/B-01 custody hashes,
beta profile and provenance hashes, sub-verifier results, and an exhaustive
private inventory (`private-inventory.json`). It is the source of any values
for this run: report its generated hashes, profile/instance IDs, and verifier
statuses only after a real build, never by copying illustrative values into a
document.

## Independent local re-verification

Re-run the verifier with the output directory and a private absolute temporary
directory:

```text
npm run qualification:v2:beta-local-integration -- \
  --verify "$PWD/.codex-build/beta-local/<run-id>" \
  --temporary-root <absolute-private-temporary-directory>
```

Verification re-inventories the private tree; resolves and rechecks the copied
ceremony; checks the copied B-01 manifest, runtime, profile, provenance, and
identity bindings; and repeats proof, runtime, Libauth, and persistence/recovery
verification. It compares each fresh result to the completion record and
returns the same unqualified beta status only on exact agreement.

The verifier accepts the recorded Git commit/tree if the current checkout is
not that clean checkout, provided the historical commit and tree still resolve.
That is a reproducibility aid, not validation of any dirty bytes. For a
portable re-check, use a clean checkout at the recorded commit/tree and retain
the private output unchanged.

## Custody and handoff rules

Treat the whole output tree as private local custody, including copied ceremony
materials, proving material, runtime data, prepared action records, SQLite
state, proof evidence, and the inventory. Do not move individual files into a
final descriptor, signed final manifest, release artifact, normal wallet or
runtime path, external qualification bundle, broadcast workflow, or ticket
attachment. Do not publish the output merely because its public hashes are
available.

An altered file, extra file, unsafe link, changed file mode, changed source
binding, or disagreement among the re-verifiers is a failed re-verification,
not a reason to patch the completion record. Preserve enough diagnostics for a
local investigation, keep secrets out of logs and chat, and start a fresh beta
run if a new build is needed.

## What comes next

This lane can support only local integration development. It does not satisfy
or shorten B-01-pre review, D-01, B-02-final, Q-01 final replay, Q-02/Q-03/Q-07,
D-02, Q-08, or Q-09. Production work must begin from the separately authorized
final lineage: a fresh D-01 ceremony with at least five independent
contributors, a public beacon, two independent transcript checks, and two
independent clean-host artifact reproductions. Beta proving-key, receipt,
transcript, and output artifacts must not be reused in that final lineage.
