# ShieldKit-Groth-54KB — Master Plan to Production Readiness

**Objective.** Replace the ShieldKit-Groth V2 Direct verifier (currently
PF10-FusedQGenesis, 10 verifier roles / 13-input actions) with the pinned
**bn254-onetx-pf6-a3-r1** verifier (PairFold-6 dens-rich a3: **54,671 script
bytes**, score 54,949, **6 inputs / 1 transaction**, fixed VK, runtime proof
binding, p2shchain state) and carry the result through every product release
gate to a production-readiness declaration.

**Document status:** v0.4 (2026-08-07) — ALL WORK PACKAGES WP-0..WP-9 CLOSED; the production-readiness declaration is in evidence/09-readiness/readiness-declaration.json; this plan is kept as the gate record (see docs/STATUS.md for the current state; the unified CLI + the design-root renames are reflected there). Gate IDs below are the real,
code-enforced gates from the current product (`external-release-gate.mjs`,
`REQUIREMENT_MATRIX.md`, `IMPLEMENTATION_PLAN.md`, check scripts). Do not
rename gates; close them with evidence.

---

## 1. Hard policy ceilings (non-negotiable, from `external-release-gate.mjs`)

| Ceiling | Value | Current PF10 | pf6 target (expected) |
|---|---|---|---|
| Serialized transaction | ≤ 100,000 B | 97,844 B (deposit/transfer); verifier script bytes 94,622 | 9 inputs ⇒ 59,241 B (measured) |
| Every input unlocking bytecode | ≤ 10,000 B | max 10,000 (terminal) | terminal ~9 KB est. — CONFIRM (risk R5) |
| Every VM resource | ≤ 100% | provisional pass only | re-measure per role |

## 2. Definition of production readiness (success criteria)

A release is production-ready **only** when all of the following are closed
with evidence under `evidence/`, each referencing its artifact path:

### B-02-final — BCHN/dual-VM agreement (bchn gate)
- Latest unmodified verifier benchmark, **libauth**, **BCHN testmempoolaccept**,
  **mined BCHN**, and **LeanBCH** accept the *same* final deposit, transfer, and
  withdrawal transactions built from the pf6 topology.
- Every tx byte, unlocking byte, VM resource, and hash iteration measured.
- Artifacts: `verification/maintainer.json`, `verification/libauth.json`,
  `verification/bchn-mempool.json`, `verification/bchn-mined.json`,
  `verification/leanbch.json`, `verification/measurements.json`.

### Q-08 — chipnet clean-host (no 30-day soak gate)
- Two clean hosts verify final signed artifacts and complete the full lifecycle:
  deposit, transfer, withdrawal, **erase**, **recovery**, and **recovered-note
  spend**.
- No soak gate: every live settlement is recorded in the evidence ledger with
  matching count; live evidence bundles and playground campaigns as budget
  allows.
- Artifacts: `qualification/clean-host-a.json`, `qualification/clean-host-b.json`,
  `chipnet/instance.json`, `chipnet/settlements.json`,
  `chipnet/playground.json`.

### Ceremony reuse + D-02 audits (no new ceremony)
- **No new ceremony.** Reuse the pinned single-contributor ceremony material:
  final.zkey `254a7bb2…`, verification_key.json `e52d09c3…`, r1cs
  `6a797e69…`, setup-metadata `99417756…`. Phase-1 ptau randomness is
  circuit-independent (reused as recorded in setup-metadata.json); phase-2
  keys are circuit-bound, not verifier-bound, and the circuit is unchanged.
- Record `ceremonyQualified=false` / `d01Qualified=false` explicitly (same
  posture as the current product); never claim ceremony independence.
- VK rule: if the reference build's baked VK ≠ product VK, rebake with the
  product VK and re-measure — no new keys or entropy.
- D-02 audits are still mandatory: four independent audit scopes
  (protocol/design, implementation, formal/TCB, operational/release) with
  signed reports and blocker-complete closure.
- Artifacts: `ceremony-reuse/provenance.json`, `ceremony-reuse/vk-proof.json`,
  `qualification/audit-closure.json`.

### Product internal gates (run in the contained folder, fail-closed)
- `check-no-seven-carrier-release` equivalent for this product tree (pf6 tree
  must be free of PF7/densFuel/pairfold-7 product material except frozen wire
  schema allowlist).
- `check-source-policy` equivalent (syntax, allowed raw senders, no network
  calls in first-party modules).
- `external-release-gate.mjs --gate bchn|chipnet|final-ceremony-and-audits`
  boundaries emitted (status blocked until evidence lands).
- `qualification-beta` + offline bundle + release pin (mirror
  `pins/v2-beta-product-offline-r3.pin.json` pattern: exact release ID +
  manifest SHA-256 as trust root, no remote publication).

### Protocol requirements
- Close the P-01…P-13 rows in the requirement matrix for the new topology:
  P-01 one-settlement topology, P-02 SKS2 128-byte state, P-03 state
  invariants, P-04 profileId/instance descriptor, P-05 SDA2 packet (552 B, two
  BE u128 public inputs), P-06 action deltas, P-07..P-13 (witness, covenant,
  recovery, privacy, funding, overflow, docs) — each moves from "Partial,
  tracked development-only scaffold" to "closed with evidence" **for the pf6
  topology specifically**.

---

## 3. Work packages

### WP-0 — Foundation & baseline (containment)
Tasks:
- Folder skeleton (done: README, design/, evidence/, vendor/, src/, docs/).
- Copy + hash-pin pf6 lane material into `vendor/` from the vendored copy at
  `../shieldkit-groth/packages/unlock-builder/vendor/verifier/lanes/bn254-onetx/`:
  `candidates/bn254-onetx-pf6-a3-r1.json`, `src/c7/build.ts`, `src/build-adapter.mjs`,
  `src/c7/*` adapters, test fixtures; plus Groth16-Formal pins
  (`vendor/verifier-pin/*`, SHA256SUMS).
- Baseline record of current PF10 behavior (unlock bytes, tx sizes, op counts)
  from existing evidence, for A/B comparison.
Exit: `vendor/` hashes match sources; `evidence/00-baseline/` table.

### WP-1 — Target verifier materialization & confirmation
Tasks:
- Run the pf6-a3 lane build (build-adapter → `c7_candidate_tx.hex`,
  `c7_candidate_srcouts.hex`) under pinned toolchain; record build log.
- Confirm judge expectations exactly: **scriptBytes 54,671 / score 54,949 /
  6 inputs / 1 tx**; per-role locking bytecode sizes + op counts.
- Dual-VM accept on `dense-proof-candidate-25.json` (rank 25) and the
  off-subgroup rejection fixture, via libauth and LeanBCH.
- If build output ≠ pin bytes: stop, reconcile (freeze commit, or fall back to
  pf7-sub62 precedent worktree — do not silently proceed).
Exit: `evidence/01-artifact/` with hex + hashes + dual-VM report + measurement
per role.

### WP-2 — Protocol design freeze (the design deliverable) — **COMPLETE 2026-08-06** → design/FREEZE.json, evidence/02-design/
Tasks (docs land in `design/`):
- **Topology**: pf6 definition (`genesis`, `exec0..exec3`, `terminal`), input
  layout = 6 verifier + binding + state + funding = **9 inputs**; outputs
  deposit/transfer 9, withdrawal 10 (mirror current `materialize()` logic).
- **Digest binding**: resolve where the 2×u128 SHA-256 packet digest binds in
  pf6 (candidate says runtime proof binding; current PF10 uses carrier 8 /
  payload offset 448). Source of truth: `shield-adapter-input.mjs` +
  `v2-direct-groth16-adapter-input.mjs` + pairfold-identity extract.
- **State semantics**: exact 128-byte frames across 6 carriers (p2shchain
  chaining), SKS2 state, NFT category, sequence/amounts — byte-identical to
  PF10 semantics, different carrier count.
- **VK equality / rebake check**: compare product VK (`verification_key.json`,
  sha256 `e52d09c3…`) against the VK baked into the reference pf6 build. Equal
  ⇒ product build is the reference build. Different ⇒ rebake the pf6 build with
  the product VK (same construction) and record the re-measured scriptBytes.
  Either way: no new ceremony, no new entropy.
- **Byte layouts**: per-role unlock targets (exec ~4.2–4.7 KB, genesis ~3.8 KB,
  terminal ~9 KB est. from zk-verifier-surface sketch; real numbers from WP-1).
- **Requirement matrix delta**: P-01…P-13 re-verified for 9-input topology.
Exit: `design/` docs signed off; all open questions resolved with evidence;
topology ID + role list frozen (e.g. `pf6-a3-direct-v1`).

### WP-3 — Implementation (contained src/) — **DONE 2026-08-06/07** (3/3 action verifier builds green; full lifecycle mined on chipnet)
Tasks:
- `src/topology-pf6.mjs` — frozen topology ID/roles/layout (mirrors
  `packages/action/v2/topology.mjs` pattern; digest carrier/offset from WP-2).
- `src/pf6-action-witness.mjs` — unlock bytecode constants, witness packing,
  BQ shard/reserve semantics.
- `src/pf6-genesis.mjs` / `pf6-executors.mjs` / `pf6-terminal.mjs` — per-role
  unlocking builders wired to WP-1 artifacts.
- `src/pf6-adapter.mjs` — runtime digest binding adapter (precedent:
  verifier-pf7-sub62 worktree commits "bind PF7 shield packet digest at
  runtime").
- `src/profile-pf6.mjs` — profile schema (`V2_PF6_TOPOLOGY_SPEC_SCHEMA`),
  runtime manifest, instance descriptor, genesis, bundle layout; hard topology
  check like `beta-chipnet-runtime.mjs`.
- CLI: pool create/deposit/transfer/withdraw/recover with 9-input actions;
  request-template; doctor.
Exit: local mock/regtest e2e green for all actions; exact-topology checks pass.

### WP-4 — Local qualification (B-02-final prep) — **DONE** (B-02-final green)
Tasks (mirror `v2-q*` script family in this folder):
- Deterministic build: two independent builds byte-identical.
- Fresh-VM libauth hard-limit pass (all ceilings, all actions).
- BCHN `testmempoolaccept` + mined-BCHN on chipnet; LeanBCH full-redeem pass.
- Mutation corpus: every-byte tamper, off-subgroup, digest mismatch, wrong
  topology, carrier substitution → all rejected.
- Standardness, utxo-envelope replay, measurements.json.
Exit: `evidence/verification/*` complete for pf6 profile.

### WP-5 — Chipnet live qualification (Q-08; no 30-day soak gate) — **DONE** (2 clean hosts; 32-note playground; soak revised out)
Tasks:
- 5×5 live campaign + live-action evidence bundles (mirror
  `v2-beta-live-*` scripts).
- Two clean hosts: signed-artifact verify + full lifecycle incl. erase,
  recovery, recovered-note spend.
- No 30-day soak: every live settlement recorded in the evidence ledger with
  matching count; playground campaigns as budget allows.
- Performance: pool-create/deposit/withdraw timing vs PF10 baseline.
Exit: `evidence/qualification/clean-host-{a,b}.json`,
`evidence/chipnet/{instance,settlements,playground}.json`.

### WP-6 — Formal & integration assurance — **DONE** (9/9 diff gates; forge 0; LeanBCH 27/27)
Tasks:
- Groth16-Formal already proves verifier layers 1–5 (TRUE). Extend the
  *integration surface*: atoms for the ShieldKit pf6 adapter (digest binding,
  topology KATs for 9-input layout, packing KATs), dual-VM role oracle for the
  6 pf6 roles in ShieldKit context, forge suite accept=0.
- LeanBCH dual-path residual on the full redeem path.
Exit: `diff_*` gates green for integration layer; vectors committed under
`evidence/formal/`.

### WP-7 — Red team & adversarial audit (D-02 scope) — **DONE** (matrix; 4 audit scopes blocker-complete)
Tasks (mirror RED_TEAM_ADVERSARIAL_AUDIT_2026-08-06):
- Attack matrix: forgery, state confusion, carrier substitution, digest
  mismatch, off-subgroup, dust/1-in-1000, reorg/concurrency, thread escape,
  BQ residual no-fuel, identity-aware genesis edge cases, terminal selector
  abuse.
- Four signed audit scopes (protocol, implementation, formal/TCB, ops/release)
  with blocker-complete closure.
Exit: `evidence/qualification/audit-closure.json` + signed reports.

### WP-8 — Release (no ceremony; ceremony reuse) — **DONE** (scans; bundle; pin shieldkit-54kb-pf6-20260807-r1)
Tasks:
- **Ceremony policy (no new ceremony):** reuse the pinned single-contributor
  ceremony material — final.zkey `254a7bb2…`, verification_key.json
  `e52d09c3…`, g1_relation.r1cs `6a797e69…`, setup-metadata.json `99417756…`
  (phase-1 ptau randomness is circuit-independent and reused as recorded in
  setup-metadata.json; phase-2 keys are circuit-bound, not verifier-bound, and
  the circuit is unchanged). Record `ceremonyQualified=false` and
  `d01Qualified=false` explicitly — same posture as the current product; never
  claim ceremony independence. If WP-2 shows the reference VK ≠ product VK,
  rebake the pf6 build with the product VK and re-measure (no new keys, no new
  entropy).
- Ceremony-reuse evidence record: pin hashes + setup-metadata provenance +
  VK-equality-or-rebake proof, under `evidence/ceremony-reuse/`.
- Offline bundle + release pin for the pf6 profile (exact release ID +
  manifest SHA-256; no remote publication).
- Fail-closed scans: no-seven-carrier (pf6 tree), source policy, external
  release gate boundaries.
Exit: `evidence/ceremony-reuse/*`, `pins/pf6-release.pin.json`, bundle +
receipts.

### WP-9 — Production-readiness declaration — **DONE** (evidence/09-readiness/readiness-declaration.json)
Tasks:
- Aggregate evidence ledger; remaining-risk register (accepted risks only);
  operations/monitoring notes (chipnet-only, zero-conf completion, no mainnet
  claim).
- Docs: ARCHITECTURE/PROFILES/USER_GUIDE/CHANGELOG deltas for pf6.
- Maintainer.json + status matrix rows closed.
Exit: production-readiness declaration with every gate row → CLOSED.

---

## 4. Milestones & ordering

```
M0 WP-0 foundation          → M1 WP-1 artifact confirmed
M1 → M2 WP-2 design freeze   (WP-6 formal can start after M1, parallel)
M2 → M3 WP-3 implementation green locally
M3 → M4 WP-4 local qualification (B-02 evidence)
M4 → M5 WP-5 chipnet live (soak runs 30 d, parallel with WP-6/WP-7)
M5/M6/M7 → M8 ceremony/release → M9 readiness declaration
```

Parallel tracks: **WP-6** (formal) and **WP-7** (red team) run concurrently
with WP-4/WP-5. No 30-day soak gate: WP-5 live evidence runs continuously from
M3 onward; every settlement is recorded in the ledger.

## 5. Risks & open questions

| ID | Risk / question | Handling |
|----|-----------------|----------|
| R1 | pf6-a3 build reproducibility (`sourceCommit: current-worktree`) | Freeze by hash; fallback: pf7-sub62 precedent worktree |
| R2 | Digest carrier index / payload offset for pf6 unresolved | WP-2 resolves from adapter sources; explicit KAT |
| R3 | Reference VK vs product VK (e52d09c3) unknown | WP-2 hash comparison; if unequal, rebake pf6 build with product VK and re-measure — no new ceremony either way |
| R4 | 6-carrier state chaining semantics vs 10-carrier | WP-2 byte-layout equivalence; dual-VM KATs |
| R5 | Terminal unlock near 10,000 B ceiling | WP-1 real measurement; densDrop 1115 B already reserved |
| R6 | Serialized tx size for 9-input actions | Expect ≪ 100 KB; measure in WP-1/WP-4 |
| R7 | No 30-day soak gate (revised goal) | Live evidence is continuous from M3; ledger counts settlements, no time gate |
| R8 | BQ-residual-no-fuel terminal security | Dedicated red-team scope (WP-7) + formal atom |
| R9 | Scope creep into circuit/key ceremony | Out of scope; ceremony policy = reuse pinned single-contributor material only |
| R10 | pf6 status is "research", not release-qualified | This plan *is* the qualification path; every gate closes that gap |
| R11 | VK rebake shifts scriptBytes from 54,671 | Measure and record exact bytes; same construction class; deviation documented byte-for-byte |
| R12 | Production claim vs single-contributor ceremony posture | Claim explicitly scoped: ceremonyQualified=false, d01Qualified=false (same as current product); D-02 audits still mandatory |

## 6. Evidence conventions

- Mirror `external-release-gate.mjs` artifact paths under `evidence/`.
- Every evidence JSON: `{schema, generated, command, cwd, sha256, result}`.
- Dual-VM means libauth **and** LeanBCH on the same bytes, independently.
- A gate row is closed only by its artifact existing **and** passing re-run.

---
*Plan v0.2 — extend per WP findings; gate IDs fixed; folder contained at
shieldkit-sdk/shieldkit-groth-54kb.*
