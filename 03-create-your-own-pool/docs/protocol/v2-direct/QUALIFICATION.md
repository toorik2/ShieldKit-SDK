# V2 Direct — QUALIFICATION (remaining human / ceremony gates)

This file lists **what still blocks full plan qualification**. No ceremony transcripts are faked.

## Remaining before “READY TO PUSH TO MAIN” (full product claim)

### Foundation gate (code)

- [x] Expand `PoolActionV2Direct` to depth **32** with note Merkle, indexed-nullifier insert, record sponge, BabyJub encryption (142 297 constraints; dev setup)
- [x] densFuel verifier-carrier re-pin for depth-32 VK (`gateOk`, wire 55307)
- [x] Carrier selection under **full VM power** (LIMITS max tx/unlock/VM=1.0; plan soft 90kB/9500B/90% waived — measure only)
- [x] Binding authenticated SDA2 lock + CashScript `ShieldStateV2Direct` P2SH32 (not bare OP_1)
- [x] Libauth local execute for deposit, transfer, withdrawal rolling bundles
- [x] BCHN `testmempoolaccept` + Chipnet product single-tx D→T→W (depth-32) — full txids in FOUNDATION_GATE / STATUS
- [x] CLI operator path: real `provePoolAction` depth-32; `--broadcast` builds densFuel+binding+CashScript state+P2PKH funding via `operator/product-settle.mjs` (no `V2_SETTLE_HEX` theater)
- [x] Wipe→recover→respend live Chipnet (full txids in EVIDENCE)
- [x] Honest adversarial covenant rejects (Libauth binding OP_VERIFY / empty-stack + live `testmempoolaccept` script-reject on unspent carrier/state)
- [x] If no candidate passes: write `v2-foundation-BLOCKED.md` — **not needed** (foundation green)

### Product lifecycle (code)

- [x] Capacity reject-before-prove (local engines + **live Chipnet** maxLiveNotes=2 fill)
- [x] Contention needs_reproof (local engines + **live Chipnet** two-client race, loser re-prove + settle)
- [x] Genesis-lineage recovery over live G→D→T→W chain txs (`recover/scanner.mjs` + `chipnet-stories-d32.mjs`)
- [x] Adversarial packet + on-chain `testmempoolaccept` script-rejects (not missing-inputs theater)
- [x] Durable tree store (atomic snapshot + WAL, mode 0600) — `trees/durable-store.mjs` (SQLite-equivalent durability contract without native dep)
- [x] Mempool overlay (parent-loss, confirm/conflict, project tip) — `wallet/mempool-overlay.mjs`
- [x] Native recovery scanner path: JS genesis lineage + Rust codec KATs (`rust/` cargo test); N-API packaging optional polish
- [x] Engine-level multi-client tip race / needs_reproof (2-engine); live 2-client densFuel race green; 4/8/16 optional post-merge

### Phase D (human / multi-party)

- [ ] Freeze circuit + packet after foundation green
- [ ] Groth16 phase-2 ceremony ≥5 independent contributors + public beacon
- [ ] Transcript verify on two clean machines; artifact reproduce on two hosts
- [ ] Independent audits: protocol/privacy; circuit/encryption/ceremony; covenants/topology; wallet/recovery/network gate
- [ ] 30-day Chipnet soak ≥1000 settlements (post-merge ok per goal non-goals)
- [ ] Playground maxLiveNotes=32 fill/reject/withdraw/refill under contention
- [ ] Clean-machine qualification sequence from plan §5

## Already acceptable as development milestones

- Strict SKS2/SDA2 codecs + TS/Rust KATs
- Independent transition + tree reference models
- Dev-setup real Groth16 proofs for public counters + limbs
- Journal, FUNDING_UTXO_REQUIRED, CLI, recovery lineage tests
- Chipnet hot-funded digest-commitment broadcast with full 64-char txid

## Non-claims (must remain in product copy)

See IMPLEMENTATION_PLAN permitted privacy claim and required nonclaims. No sponsor/faucet. No mainnet without separate reviewed decision.
