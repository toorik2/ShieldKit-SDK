# ShieldKit-Groth-54KB — Design 04: Runtime Integration Spec (v1)

Status: spec (WP-3 remainder). Defines how the pf6 verifier material becomes
working pool actions. All evidence-backed; no placeholders.

## 1. Architecture (proven pattern)

The product kit (`packages/kit/v2/action-lifecycle.mjs`) calls a witness
builder (`buildDirectV2Pf10ActionWitness`) + circuit-input builder
(`buildDirectV2CircuitInput`). The pf6 swap replaces the witness builder with
a **pf6 action build** that re-runs the lane build machinery per action — the
pattern proven by the verifier-pf7-sub62 worktree test
(`shield-adapter-active-instance.test.mjs`: snapshot program importing
`_millermath`/`_szmath`/`_residuemath` with `C7_SHIELD_ADAPTER_FILE` set, then
parsing the resulting unlocking back into proof limbs).

Per action (deposit / transfer / withdrawal / recovered-note spend):

```
SDA2 packet (552 B, product codec)
  -> digest = sha256(packet) -> in0/in1 (2x u128 BE)
  -> circuit input (buildDirectV2CircuitInput equivalent, main-chipnet circuit)
  -> snarkjs: witness (main-chipnet.wasm) + prove (beta.zkey 61683ef2)
  -> proof.json + public.json
  -> adapter JSON (schema shieldkit-v2-direct-groth16-adapter-v1;
     source refs = proof/public/VK d38f3cfc; verifierCashVk + verifierCashFixture)
  -> lane product build (pf6-a3-shieldkit candidate; structuralRoleCount=3,
     shieldAdapter, shieldActionPacket=packet.bin, abi sda2-v2-direct,
     stabilization ON)  [~50 s, real-gate green]
  -> 6 verifier unlocks + 3 structural slots
  -> 9-input settlement tx (product assembler; binding/state/fee real inputs)
  -> real-gate replay (evaluatePair, full context) + BCHN testmempoolaccept
```

## 2. Proven data (already measured; no re-derivation needed)

- Verifier locks+unlocks: `src/verifier-material/pf6-material.json` (9 inputs).
- Program sources (compile inputs): `_c7_merged.cash` (genesis), 
  `_sb_composed-executor.cash` (exec0-3 shared body), `_sb_terminal.cash`.
- VK `d38f3cfc`; circuit r1cs `077f58f5` / wasm `87f5878e` / zkey `61683ef2`
  (current product; vendor from the runtime dir, hash-pinned).
- Packet + proof + public + adapter for the DEPOSIT action: 
  `vendor/product-current/` (runtime qualification set, hashes verified).
- Stabilized unlock targets: genesis 7,600 / terminal 9,350; exec lengths
  measured per build.

## 3. Remaining implementation (WP-3 remainder, in src/)

1. `src/prove-pf6.mjs` — witness + prove wrapper (snarkjs child process,
   pinned wasm/zkey paths, SDA2-packet circuit input from
   `buildDirectV2CircuitInput` logic ported from the product's
   `packages/prove/v2/`).
2. `src/pf6-adapter-builder.mjs` — adapter JSON assembly (proof/public/VK
   refs + verifierCashVk conversion + verifierCashFixture from the proof).
3. `src/pf6-action-build.mjs` — per-action lane build invocation (runner
   pattern from `run-pf6-product-build.mjs`; candidate per action; collect
   the 9 unlocks; assert gateOk + packet sha + digest offset).
4. `src/settlement-pf6.mjs` — 9-input tx assembler: verifier inputs from the
   build; packet input = PUSHDATA2(packet); state input = SKS2 state unlock
   (product codec); fee input = wallet funding; outputs per topology (9/10);
   NFT category + covenant wiring per product patterns.
5. `src/cli-pf6.mjs` — pool create / deposit / transfer / withdraw / recover
   (mirrors `scripts/shieldkit.mjs` surface; chipnet-only; zero-conf).
6. Tests: exact-topology hard checks (done in topology-pf6.mjs), material
   load (done), replay gate (done), per-action e2e on mock network.

## 4. Hard gates for the integration

- Every action tx: <= 100,000 B; every unlock <= 10,000 B; VM <= 100%
  (measured per action; the verifier roles are already measured).
- Digest binding KAT: terminal hashes packet == genesis digest at offset 451
  (build enforces; replay re-verifies).
- Proof validity: the VM accept of all 6 verifier inputs IS the proof check;
  a tampered proof must reject (WP-4 tamper corpus).
- Chipnet-only; no mainnet claim; zero-conf completion (product policy).

## 5. Why not "port the PF10 kit directly"

The PF10 witness modules (identity-aware-miller, exact-msm, total-pairfold)
implement the PF10 role split (10 roles). pf6 has a different split (4
executors + fused genesis + terminal) with the lane's composed/fixed-G2
construction. The lane build IS the witness generator for pf6 — reusing it
per action avoids reimplementing ~10k lines of pairing/stack logic and keeps
the TCB (Groth16-Formal) aligned with the exact built programs.


## v2 (2026-08-06): settlement formats extracted from the LIVE product (evidence/03-implementation/settlement-formats.json)

- Extracted from the live PF10 deposit on chipnet (txid a2004161..., 97,852 B)
  + its source UTXOs (the pool's covenant tree).
- pf6 packet input: unlock = exactly 555 B (terminal guard), lock = bare OP_1
  carrier (design/01 v2) — the PF10 binding-redeem input (2,753 B unlock) does
  NOT exist in pf6; binding moved into the terminal.
- state input: product state covenant unchanged (88 B lock class, 2,677 B
  unlock = PUSHDATA2 + 2,674 B SKS2 payload).
- fee input: P2PKH (100 B signature, hot wallet qq3ncrumwkf6aj...).
- pool-create outputs: 6 pf6 verifier P2SH32 locks + OP_1 carrier + state
  covenant + change (src/settlement-pf6.mjs v2).
- Deployment feasibility: hot wallet 9.42 BCH / 345 UTXOs on chipnet.

## v2 deployment plan (WP-3 exit / WP-4 entry)

1. Pool-create: fund from hot wallet; write 6 verifier locks + OP_1 carrier +
   state covenant (state covenant built with the product's pool-create
   machinery — the NFT/category commitment + initial SKS2 state).
2. Deposit: 9-input tx (6 pf6 unlocks + packet + state + fee) ->
   testmempoolaccept -> broadcast (zero-conf).
3. Transfer / withdrawal: same pipeline with their adapters/material.
4. B-02: dual-VM (libauth + LeanBCH) on the identical txs + measurements.


## v3 (2026-08-06): pf6 pool deployment flow (machinery ported + validated)

- Instance id = reversed funding-tx txid (product genesis.mjs); stateNftCategory
  = instanceId. Initial SKS2 state = encodeStateNftCommitment (profileId,
  empty roots, counts 0, reserve = pool value, sequence 0).
- State covenant: buildDirectV2StateHelper + buildDirectV2StateTrampolineLock
  with pf6 topology -> **88 B lock** (matches live PF10's 88 B; prefix
  74519dc0... identical); helper 2,198 B; unlock 2,201 B; rolling base 2,500.
- Genesis (pool-create) outputs: state covenant (88 B) + 6 pf6 verifier locks
  (35 B each) + OP_1 carrier (1 B) + change.
- Deposit/transfer/withdrawal: 9-input settlements per design 01/04 v2.
- Broadcast: source -> genesis -> actions (zero-conf chain, 1 sat/B + 1).
- Evidence: evidence/03-implementation/covenant-port.json.


## v4 (2026-08-06): live-test findings — the unlocks are tx-bound

Seven chipnet deployment attempts (4 pools broadcast) proved the pf6 verifier
construction but exposed the integration requirement:

- The lane build's verifier unlocks are sighash-bound to the build's own
  synthetic tx (1 OP_RETURN output, placeholder structural inputs, synthetic
  outpoints). They cannot be dropped into a real settlement tx — the covenant
  signatures inside the unlocks cover the build's tx, not the real one.
- The real deposit requires the PRODUCT's per-action witness pipeline: the
  unlocks must be computed against the actual 9-input/9-output settlement
  context (the kit's action-lifecycle pattern — design/05). The lane build's
  modules (composed-*/fixed-g2-*) are the witness generators; they must be
  driven with the real context, exactly as the product's pf10 builder does.
- Fixed during the attempts (evidence/03-implementation/live-findings.json):
  carrier lock 75 51; hashed empty-tree roots; token category = source txid
  with the instance = reversed; layout verifier@0-5/carrier@6/state@7;
  the 0x61 sighash includes the source tokens.


## v5 (2026-08-06): output-layout consistency (transfer finding)

- The deposit is LIVE (86420826) with the pool layout verifier@0-5/carrier@6/
  state@7 — its inputs satisfy the txTopologyGuard (vout == i).
- The transfer attempt exposed: the DEPOSIT's outputs used state@0 + verifier@1-6
  (the covenant's i+1 mapping) — the next action's inputs (vouts 1-6) fail the
  guard. EVERY action's outputs must mirror the pool layout: verifier@0-5,
  carrier@6, state@7, change@8 (+withdrawal@9 for withdrawals).
- The covenant port must map output[i] == input[i] (not i+1), state output at 7,
  binding output at 6. The deployed pool's covenant pins the old helper → a new
  pool is required for the corrected cycle.
- Next cycle: fix covenant mapping -> 9th pool -> deposit (new output layout)
  -> transfer -> withdrawal -> recover.
