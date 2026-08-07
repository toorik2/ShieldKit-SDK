# GOAL — ShieldKit-FRI: working Chipnet production-ready shielded pool (FRI-STARK verifier)

> **How to use:** paste everything below this line into a fresh goal session (or `/goal`).
> Supersedes `GOAL_PROMPT_PRODUCTION.md` (Grok, 2026-08-06). Authority remains
> `FRI_STARK_REPLACEMENT_PLAN.md` AS AMENDED (depth 32 -> 20 — see WS2). This contract is the
> operational execution plan to publication readiness on **Chipnet**: real product path, real
> transactions, no placeholders, no green-wash.

---

## Mission

Close **shieldkit-fri-stark** to a **working, production-ready (Chipnet) shielded pool**: the full
one-tip lifecycle **createPool -> deposit -> transfer -> withdraw -> recover** running as real,
standard, zero-conf BCH transactions on chipnet — every action exactly one tx, **<=100,000 B**,
**>=100-bit soundness**, prover SLA **p95 <=60 s / peak RSS <=4 GiB**, all plan gates P0–P7 green
or documented infeasible-with-evidence, and an honest `release:verify`.

**Not demos. Not placeholder tag-hash toys. Not proof-tied one-shot tips. Not green-wash. Not
mainnet** (mainnet spends only with explicit per-action user approval).

**Permitted release claim (only when every gate passes):**
> ShieldKit-FRI Beta — unaudited, Chipnet-only, fresh-genesis experimental profile; zero-conf
> admission/readback; no mainnet, production, encrypted-note privacy, or Groth-pool compatibility claim.

## Workspace & authority

| Item | Value |
|---|---|
| Workspace | `/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-fri-stark` |
| Normative plan | `FRI_STARK_REPLACEMENT_PLAN.md` AS AMENDED (depth 32 → 20, WS2) |
| Wire (locked) | SFS1 state NFT commitment = **128 B** native; SFP1 action packet = **424 B**; `statementDigest = SHA256(SFP1_bytes)` |
| Product config (LOCKED) | **depth=20 (2^20 notes) · nq=7 · blowup=2048 · grind=30 · fold_step=3 · deep · T=1024 · N=2^21=8^7 · security = 100 bit** — do not weaken; do not change without user approval |
| Vendor | `vendor/bch-fri-stark` pin `a600e828d68eb41840049cb16d0c21850ff9df57` + recorded product patches (evidence/production/*.diff) |
| Lane source of remaining optimizations | `/home/toorik/Projects/verifier.cash/lanes/goldilocks-target-80k/upstream/apps` (tip 96,563 / est 95,968 @ same params, research topology) |

## Verified state (2026-08-06, all caged + VM-gated)

- **WS1 GATE PASSED**: deposit **99,313 B** / transfer **99,378 B** / withdrawal **99,394 B** @ product config —
  17/17 accept each, 0 density fails, maxUnlock 7,898 <= 10,000, RC 0 (txBar + unlockBar green). ALL UNDER 100,000 B.
- E2b integrated for the product config (fidx input-base fix, blob-index fix, gq=1 conditional on n_s3<=6).
- floor d32/b8192: 122,443 B, 19/20 accept, 0 density fails (classic path; not the product config — d20 is normative after WS2).
- Rust prover @ product config: deposit 252 s / transfer 36 s / withdrawal 165 s (grind-30 search variance; SLA table in WS5).
- Hot paths live: Rust fri-terms, lazy `_setup`, selectors-at-k, hoisted4, NOT-loops, E1 fold, L2/E2a chain, E2b (gq1-conditional).
- History: 103,425 -> 102,683 (diet) -> 102,234 (lane ports) -> 101,464 (E2b fidx) -> **99,378** (E2b gq1 + blob fix).
- Evidence: `evidence/production/WS1_GATE_20260806.json`, `WS1_E2B_PATCH_20260806_vendor.diff`; backups `/tmp/vendor-bak-e2a/`, `/tmp/vendor-bak-batch2/`.

## Hard rules (policy, non-negotiable)

1. **BCH CONSTANT GATE (RULE 0)**: any BCH-constant question → `bch_constants.lookup()` FIRST, always (even if told "don't look it up"). Current-era only.
2. **TOOL-INVENTORY GATE**: before building any tool → `bch_tool_inventory.lookup(<what>)`; never rebuild what exists (Planck, LeanBCH, RustBCH, bch-conformance, fri-cage, lane tooling...). Re-run `python3 ~/Projects/ZK-Proofs/tooling/survey_bch_tools.py` when new tooling lands.
3. **SECRETS BAN**: keys/WIFs/cookies only in `.codex-artifacts` (0600) / grok project memory; never in repo/evidence/logs/global harness.
4. **CHIPNET ONLY** for tests; mainnet only with explicit user approval per action.
5. **FEES**: 1 sat/B; empirically `fee == size` is rejected → always `fee = size + 1`.
6. **ZERO-CONF (hard)**: never wait for confirmations, no sleep/poll for blocks. Success = `testmempoolaccept` allowed + `sendrawtransaction` + visible in `getrawmempool`. Children spend mempool parents.
7. **EVIDENCE**: every claim binds commit + manifest + txids; reproducible commands; never fabricate.
8. **RED-TEAM GATE** before any milestone claim (forge battery, adversarial audit, red-team-reviewer).
9. **NO PLACEHOLDERS / NO GREEN-WASH**: every gate must be a real measured result (VM accept, libauth, txids). Any hard gate that cannot pass → measured `INFEASIBILITY_REPORT.json` with evidence and a stop; never weaken security, depth, digest width, or byte caps to force a fit.
10. **CAGE HEAVY JOBS**: floor prove/assemble runs via `~/Projects/ZK-Proofs/tooling/fri-cage --mem=20G --swap=4G -- CMD...` (cgroup MemoryMax; a blowup kills only the job — never the desktop/GPU/Ghostty). Prover: `scripts/safe-prove.sh` (SK_FRI_MEMORY_MAX).
11. **PROVENANCE**: record every vendor port as a diff in `evidence/production/` with the lane commit and the VM-gate result.

## Workstreams (execute in order; each gate must pass before the next)

**STATUS: WS0 ✅ · WS1 ✅ (size gate) · WS2 ✅ (amendment) · WS3 ~90% · WS4 BLOCKED→UNBLOCKED-IN-PROGRESS**
**2026-08-07: PRODUCTION-RANDOMNESS GOAL COMPLETE — all 6 items DONE, release:verify rc=0 (P0-P7 + RN all green, claimForbidden=false). (1) Random-mask prover mode: RngSource 128-bit CSPRNG (rand::thread_rng) for ZK masks + Merkle salts; production default random; deterministic test path byte-reproducible (canonical sequential grind). (2) Wallet-driven witnesses: note secrets = HMAC-SHA256(master, instance, index), vendor-poseidon JS port (KAT-verified vs Rust), kind-tagged client note trees (DOM_POOL/kind level-0 siblings); LIVE WALLET LIFECYCLE ON CHIPNET: genesis b8709a54... -> deposit c2683b89... (99,171 B) -> transfer 91e9c0e0... (99,165 B) -> withdrawal 7226d76f... (99,207 B) -> recover ok — all csprng masks, fresh proves, confirmed in the BCHN chain. (3) No pinned caches on the live path. (4) RN enforcement gate: every broadcast artifact records maskSource=csprng; seeded broadcast paths fail the release. (5) Key roles distinct: funding key != note-master key (0600), journal carries the master tag only. (6) Quarantine: deterministic fixtures (evidence/sla/deterministic-archive + evidence/p2 corpus) labeled test-only. SLA (random mode, single-parallel): p95 36.3/42.4/43.4 s, RSS 1.84 GiB. The original 4 seed-1 chipnet txs (757457ab..., a28eb87e..., c556db4e..., 99da5f86...) are EXPOSED/demonstration-only (marked in RED_TEAM_AUDIT_20260807.json).: baseline JSON + green integrity.

### WS1 — Close the size gap (target <=100,000 B with margin; forbidden to weaken params)
1.1 **E2b integration** (banks ~749 B → ~101.5 KB): fix `_fri_loop_chain_redeem_e2b_sw_asm` round-window sink depths vs the product's carried/witness layout. Use the lane's E2b selftests (`fri_loop_s3_redeem_e2b_sw`, e2b harness in lanes/goldilocks-target-80k) as the reference; blob layouts are already proven identical (product vs lane `_build_sound_blob`). Gate: d20 17/17 accept, 0 fails.
1.2 **PCO-DEEP-02 merkle CSE** + any remaining w09 levers (E-pad0 etc.) — port from the lane ONLY as VM-gated shared leaf functions; never port lane topology (public_from_blob removal, research pads).
1.3 If still over 100 KB after 1.1+1.2: allowed levers in order — (a) pure encoding (redeem/unlock golf, macros, 2DROP-style), (b) nq 6 with blowup raised ONLY if `nq*(log2(blowup)-1)+grind >= 100` AND the prover SLA still holds at the new domain, (c) user-approved plan amendment of a non-user-facing parameter. FORBIDDEN: security <100 bit, tx >100,000 B, placeholders.
1.4 **Gate (hard)**: deposit/transfer/withdrawal @ product config each <=100,000 B, all inputs accept (VM+libauth), density 0, forge battery rejects, unlockBar (<=10,000 B/input) OK. Evidence: `SIZES.json`-style rows with the three tx sizes + per-input breakdown.

### WS2 — Plan amendment: depth 32 → 20 (ratified, measured)
- Update `FRI_STARK_REPLACEMENT_PLAN.md`: note/nullifier tree depth 20 (2^20 = 1,048,576 notes; measured 103,331–103,425 B across depths 4–31 at T=1024 — size flat; the 32→20 cliff fix; nullifier lifetime ~28 y @100 tx/day).
- Update wire/params references, GENESIS_DESCRIPTOR template, covenant/profile constants, tests, corpus, `GOAL_PROMPT_CHIPNET_READY.md` state table.
- Record the amendment decision + measured evidence (`SIZE_INVESTIGATION_20260806.json`).
- **Exit**: plan + spec consistent, user-visible amendment record.

### WS3 — Full action suite offline @ product config
- createPool (fresh genesis, state@0), deposit, transfer, withdraw (fixed-denomination payout), recover — each exactly one standard tx, each with: full VM+libauth accept, forge/omission rejects, journal entry, CLI (`shieldkit-fri`) happy path.
- **Exit**: 5-action story script green offline with per-action sizes <=100,000 B.

### WS4 — Live Chipnet E2E (the "no placeholders" proof)
- Fund hot chipnet wallet (evidence: fund txid, UTXOs).
- **createPool genesis ON CHIPNET** (broadcast; zero-conf readback via RPC/Electrum).
- **deposit** → **transfer** → **withdraw** (payout to a second address) → **recover** — each: build → `testmempoolaccept` (allowed) → `sendrawtransaction` → visible in `getrawmempool` → journal + txid + size evidence.
- Read-back state@0 after each action; no confirmation waits (zero-conf rule).
- **Exit**: one complete E2E story with ALL txids, sizes, journal, and mempool evidence in `evidence/chipnet-e2e/`.

### WS5 — Prover/UX SLA @ product config
- Per action: p95 <=60 s, peak RSS <=4 GiB (measured: 36 s / 2 GB — re-measure deposit/transfer/withdrawal/recover, cold + warm, multiple seeds).
- CLI product surface: `shieldkit-fri` doctor/tip/deposit/withdraw/recover with journal + CAS; docs (GOLDEN_PATH-equivalent).
- **Exit**: SLA table + CLI walkthrough evidence.

### WS6 — Security & scale gates
- **P2 corpus**: real-proof adversarial corpus (state@0, structural mutations) green.
- **P3/P4 clean-host**: independent execution on a second machine (fresh clone + build + one-tip story) — reproducible.
- **P5 scale**: 256-action campaign (8 instances x 32), worker scaling, no soak/confirmation waits.
- **P6 package**: PACKAGE_INVENTORY.sha256 + provenance + reproducible `release:verify` on the packed CLI.
- **P7 chipnet dual-host**: two independent nodes observe the E2E story (layer1-node + second host).

### WS7 — Red-team & release
- Red-team adversarial audit (forge ontology, tamper battery, replay, state confusion) — green or findings fixed with evidence.
- `npm run release:verify` → honest `RELEASE_VERDICT.json` (P0–P7 rows) with the permitted claim above; any red gate → measured `INFEASIBILITY_REPORT.json` + stop (no green-wash).

## Definition of done (ALL must hold)

- [ ] Plan amendment (depth 20) ratified and consistent everywhere.
- [ ] deposit/transfer/withdrawal @ product config <=100,000 B; 17/17 accept; density 0; unlock <=10,000 B; forge rejects green.
- [ ] Prover SLA p95 <=60 s / <=4 GiB per action @ product config (measured table).
- [ ] **Live chipnet E2E**: createPool + deposit + transfer + withdraw + recover with real txids, zero-conf, journal, sizes — no placeholders anywhere.
- [ ] P0–P7 green (or documented infeasible-with-evidence, user-informed).
- [ ] `release:verify` honest verdict emitted; permitted claim text exact.
- [ ] Every heavy run caged; every vendor port diffed into evidence; every number bound to a commit + txid.

## Environment cheat-sheet

```bash
# build worker
CARGO_TARGET_DIR=.private/cargo-target cargo build -p shieldkit-fri-worker --release
# prove (Rust) @ product config
echo '{"cmd":"prove","kind":"transfer","depth":20,"seed":1,"blowup":2048,"queries":7,"grindBits":30,"foldStep":3,"maskDeg":64,"deep":true,"proofOut":"/tmp/pf.json"}' | .private/cargo-target/release/shieldkit-fri-worker
# assemble + VM eval (caged)
~/Projects/ZK-Proofs/tooling/fri-cage --mem=20G --swap=4G --timeout=1800 -- env \
  VC_PRODUCT_FIXED_LOCKS=1 VC_ROLE_INDEX_BASE=1 VC_BLOB_IDX=1 VC_SKIP_PROOF_VERIFY=1 VC_RUST_FRI_TERMS=1 \
  VC_PROOF_CACHE=/tmp/pf-d20-b2048-n7-g30-s1.pkl \
  SHIELDKIT_FRI_WORKER=$PWD/.private/cargo-target/release/shieldkit-fri-worker \
  python3 packages/settlement/python/assemble_sound_settlement.py transfer \
  --depth 20 --nq 7 --blowup 2048 --grind 30 --out /tmp/fri.json
# RPC/Electrum (chipnet)
# via bchn_rpc skill (layer1-node BCHN + Fulcrum)
```
