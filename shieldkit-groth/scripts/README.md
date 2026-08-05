# Scripts

| File | Role |
|------|------|
| `shieldkit.mjs` | CLI |
| legacy pool-act spine | moved to `legacy-research/v1-seven-carrier/` |
| `create-pool.mjs` | scaffold / genesis |
| legacy unlock-toolchain scripts | moved to `legacy-research/v1-seven-carrier/` |
| `fetch-playground-bundle.mjs` / `fetch-pin-artifacts.mjs` | profile arts |
| `run-domain-tests.mjs` | `npm test`; it prints every selected and explicitly excluded test file, rejects skips/todos, and keeps artifact/external suites separate. Portable files have a 180-second supervisor deadline; the mandatory `test:v2:campaign:depth4` suite has an explicit 360-second per-file deadline for its production state-space test's 300-second Node timeout plus teardown. |
| `v2-crash-qualification.mjs` | Explicit 10,000-case local durability campaign: `npm run qualification:v2:crash10k -- --output <new-evidence.json>` |
| `v2-reorg-concurrency-qualification.mjs` | Explicit local reorg/contention campaign: `npm run qualification:v2:reorg-concurrency -- --output <new-evidence.json>` |
| `v2-pf10-libauth-qualification.mjs` | Explicit local PF10 Libauth evidence run; requires its complete coherent artifact arguments |
| `v2-pf10-development-runtime.mjs` | Builds a development-only PF10 runtime bundle and requires the canonical pinned local Libauth evidence (`--libauth-evidence`); it does not claim final, production, live-chain, BCHN, or LeanBCH qualification. |
| `v2-q07-*.test.mjs` | Mandatory portable Q-07 support tests for its evidence contract, deterministic dataset, bundle verifier, worker boundaries, and small-fixture harness. They do not run or qualify a 100,000-action performance campaign. |
| `v2-q07-indexed-microbenchmark.mjs` | Deliberate 100,000-action indexed-nullifier-store auxiliary measurement. It is never run by `npm test`/CI and is explicitly non-qualifying Q-07 support evidence. |
| `v2-q08-lane-evidence.mjs` | Replays one exact action through canonical local Libauth evidence and manifest-authorized signed maintainer, BCHN mempool, mined BCHN, and LeanBCH artifacts. It derives evidence only and never emits qualification. |
| `v2-clean-machine-qualification.mjs` | Runs one release-root-authorized clean-host journey, replays every SHA-256-pinned action-lane bundle before signing, and writes an exact canonical Ed25519-signed host transcript. One host transcript never claims Q-08 qualification. |
| `v2-q08-pair-qualification.mjs` | Independently replays every referenced lane bundle and verifies the two release-root-authorized host signatures, distinct authorities/funding/transactions, final PF10 bindings, and complete journey chains before writing the canonical Q-08 pair record. |
| `v2-chipnet-soak.mjs` | Offline, fail-closed Q-09 validator for signed high-capacity and separate 32-note descriptors, final-key/Q-08 records, a source-pinned two-Ed25519-observer set, raw-header linkage/PoW/chainwork, exact-count Merkle proofs, state-lineage replay, and signed recovery/contention journals. It never contacts a network or turns fixtures/summaries into rollout evidence. |

Portable CI runs `npm test`, strict TypeScript checking, and the locked Rust tests. It does not run the explicit V2 mutation/stress campaigns, ignored-artifact verifier lane, external fixtures, external verifier-source suite, or release gates.

Q-07 support tests are a named portable classification: they run in `npm test`
and can be run alone with `npm run test:v2:q07:support`. They exercise only
the fail-closed support surface; a pass is not a Q-07 performance result. The
separate 100,000-action indexed-store measurement is deliberate and requires
both a new private output parent and a verified Q-04 artifact:

```sh
npm run qualification:v2:q07:indexed-microbenchmark -- \
  --output-parent /absolute/new-private-output-parent \
  --q04-verification /absolute/q04-verification.json
```

That auxiliary measurement is labelled `indexed-nullifier-store-microbenchmark-only`
and must never be supplied as a V2 Q-07 recovery/performance phase. Its
reopened-handle samples deliberately retain the operating-system page cache;
they are not cold SQLite I/O and cannot satisfy Q-07's separate cold-I/O lane.

Run the deterministic local campaigns only when deliberately requested:

```sh
npm run test:v2:campaign:strict-codec
npm run test:v2:campaign:depth4
```

The depth-4 command is the bounded structural campaign only. It is not the forbidden million-entry run and does not claim production qualification.

## V2 Direct developer operation recovery

V2 Direct internals are an explicit, development-only surface; final
qualification remains blocked. They are intentionally absent from normal
product help and are available only through `shieldkit dev`. The namespace
implies V2 Direct and rejects `--protocol`. Every recovery command requires a
configured V2 data directory (use `--data-dir <directory>` when it is not the
default) and an operation id of the form `v2op:<64 lowercase hexadecimal
characters>`.

```sh
# Resume durable local work. It proves/signs as needed, but sends nothing
# unless --broadcast is supplied.
node scripts/shieldkit.mjs dev operation resume <operation-id>
node scripts/shieldkit.mjs dev operation resume <operation-id> --broadcast

# Observe a prior broadcast and delivery record; this never resends a transaction.
node scripts/shieldkit.mjs dev operation reconcile <operation-id>

# Resubmit only the exact persisted transaction. Use the prior attempt token
# reported by reconciliation/the durable delivery record, and acknowledge it verbatim.
node scripts/shieldkit.mjs dev operation rebroadcast <operation-id> \
  --broadcast --attempt-token <prior-attempt-token> \
  --acknowledgement resubmit-exact-persisted-transaction

# Observe confirmation/settlement, explicitly rebase for a manual retry, or
# terminate the local operation with an operator-provided reason.
node scripts/shieldkit.mjs dev operation confirm <operation-id>
node scripts/shieldkit.mjs dev operation rebase <operation-id>
node scripts/shieldkit.mjs dev operation abandon <operation-id> \
  --reason 'operator cancelled after review'
```

`resume` never sends without its explicit `--broadcast`; `reconcile` is observation-only; and exact rebroadcast requires all three of `--broadcast`, the prior attempt token, and acknowledgement `resubmit-exact-persisted-transaction`. The CLI provides no automatic resend, sponsor, faucet, or batching behavior. These commands do not make a final, production, live-chain, BCHN, or LeanBCH qualification claim.
