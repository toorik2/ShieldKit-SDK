# Naming conventions

Names should say **what the construction is**, not how it scored or which experiment nickname was used that week.

Canonical example (from the PairFold research identity):

| Field | Example |
|-------|---------|
| Human | **BN254 PairFold-7** — Authenticated P2SH Chain |
| Slug | `bn254-pairfold-7-p2shchain-pf1` |
| Candidate id | `bn254-onetx-pairfold-7-p2shchain-pf1` |
| Filename | `bn254-onetx-pairfold-7-p2shchain-pf1.json` |

Same shape for other constructions: **DirectState-10**, **GenPow-1**, **NativeCovenant** (multi-tx), future **OctaMiller-8** / raw-chain eight-input, etc.

## Construction identity (required for new candidates)

Decompose the name as:

```text
{curve}-{construction}-{topology}-{stateModel}-{revision}
```

| Segment | Meaning | Examples |
|---------|---------|----------|
| `curve` | Field / curve family | `bn254`, `bls12-381` |
| `construction` | Algebraic / packaging idea | `pairfold`, `directstate`, `genpow`, `covenant`, `rawchain`, `octamiller` |
| `topology` | Input count, or `mtx` for multi-tx chains | `1`, `7`, `8`, `10`, `mtx` |
| `stateModel` | How state is carried / which track | `p2shchain`, `public`, `source`, `frozen` |
| `revision` | Short stable series tag | `pf1`, `ds1`, `gp1`, `pa1`, `r25` |

Rules:

1. Prefer **PairFold-7** style human names (construction + topology) over score-in-the-name (`…-83294`) or role nicknames (`frontier-public`).
2. Score, wire, and op-cost are **evidence**, not identity. Put them in `judge.expected` / run metrics.
3. Experiment slogans (`terminal-fusion9-exact-defermod-…`) are allowed only while research-only; rename to the construction scheme before treating as a frontier or public entry.
4. Optional manifest field `identity` may mirror the slug parts for display; `candidate.id` remains authoritative for tooling.

## Lanes

| Kind | Pattern | Example |
|------|---------|---------|
| Directory + `lane.id` | `{field}-{track}` | `bn254-onetx`, `bls12-381-singleton` |
| Lane agents | `lanes/<lane>/AGENTS.md` | must match directory |

`lane.id` **must equal** the directory name under `lanes/`.

## Candidates (repository manifests)

| Kind | Pattern | Example |
|------|---------|---------|
| Manifest id | `{lane}-{construction}-{topology}-{stateModel}-{revision}` | `bn254-onetx-directstate-10-public-ds1` |
| Filename | `{id}.json` | same stem as id |
| Human (docs / identity) | `{Field} {Construction}-{N}` | `BN254 DirectState-10`, `BN254 PairFold-7` |

Rules enforced by architecture check:

1. `candidate.id` starts with `{lane}-`.
2. Filename stem **equals** `candidate.id`.
3. Prefer the construction slug shape above after the lane prefix.

### Live candidates (after rename)

| Human | Candidate id |
|-------|----------------|
| BN254 DirectState-10 | `bn254-onetx-directstate-10-public-ds1` |
| BN254 DirectState-10 (source r25) | `bn254-onetx-directstate-10-source-r25` |
| BN254 NativeCovenant Path A (frozen) | `bn254-native-covenant-mtx-frozen-pa1` |
| BLS12-381 NativeCovenant (frozen) | `bls12-381-native-covenant-mtx-frozen-lc1` |
| BN254 GenPow-1 | `bn254-singleton-genpow-1-public-gp1` |
| BLS12-381 GenPow-1 | `bls12-381-singleton-genpow-1-public-gp1` |
| BN254 PairFold-7 (research / public bench) | `bn254-onetx-pairfold-7-p2shchain-pf1` (when landed) |

## Runs and arenas (ephemeral under `.vc/`)

| Kind | Pattern | Example |
|------|---------|---------|
| Run id | `{construction}{N}-{purpose}-r{k}` or lane-topic | `pairfold7-r24`, `directstate10-rebuild-r3` |
| Arena id | `{construction}{N}-r{k}` or campaign topic | `bn254-pairfold7-r4`, `sub75-r1` |
| Worker branch | `arena/<arena-id>/<worker>` | `arena/bn254-crown7-r4/implementation` |

Prefer construction+topology in run names once known (`pairfold7-…`) over generic `crown7-…` for new work.

## Public maintainer bench (zk-verifier-bench)

| Kind | Pattern | Example |
|------|---------|---------|
| Implementation id | `bch-{proof}-{structure}-{construction}{N}` | `bch-groth16-intratx-pairfold7` |
| Vectors | `groth16-intratx-pairfold7-vectors.json` | under `src/bch/` |
| Module | `bch-groth16-intratx-pairfold7.ts` | under `src/implementations/` |

Lane id and public-bench id stay related: same construction+topology token (`pairfold7`, `directstate` / `direct-state-public`).

## Artifacts / catalogue / intel (migration)

Historical artifact dirs (`artifacts/bn254-one-tx-standard/83294`) and catalogue keys (`E-…`) keep their held paths. Do not rewrite frozen evidence trees for cosmetics. New durable reports go under `lanes/<lane>/reports/` using the construction name.
