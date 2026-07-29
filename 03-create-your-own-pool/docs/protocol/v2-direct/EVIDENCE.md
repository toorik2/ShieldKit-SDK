# V2 Direct — Chipnet Evidence (depth-32 product)

**Date:** 2026-07-28  
**Network:** BCH Chipnet  
**Circuit:** `PoolActionV2Direct` depth **32**, **142 297** constraints  
**Topology:** single-tx densFuel(0–6) + binding(7) + CashScript SKS2 state(8) + P2PKH funding(9)

## Resource policy

Plan soft caps (tx ≤90 kB, unlock ≤9 500 B, VM ≤90%) are **waived**. Product uses full BCH VM / network standardness limits (`LIMITS.maxVmResourceFraction = 1.0`).

## Qualification bar

**0 conf is enough.** Mempool accept (`testmempoolaccept` allowed=true) + `sendrawtransaction` is the live product bar. Do **not** wait for Chipnet blocks or mine.

## Product D→T→W (full 64-char txids) — 0-conf campaign

| Step | Txid |
|------|------|
| Fund (cold→hot, 0.35 BCH) | `cbf8524d7d6b4eaa973f98ad2f4baac5659a42cedb26ed90506d8089a9df6887` |
| Genesis (carriers+binding+state) | `3bf9a865e965ed3046c641ef4e55059ec8ea566dc4a9286e1d02a0780d31a7ab` |
| Deposit settle | `b4fd8cafc8e946090fd41ef9615beafae838172510c3a54ac42f4a2872237d8b` |
| Transfer settle | `616fa7ecb577e2c8c1c84f364261c95df4798267eaa5eb8dc75f09329d1f429e` |
| Withdraw settle | `26fd21d1a39b99d54666cec239bca4c7c4bcfb3a1505373e296a01559655681f` |

| Action | Packet digest | Wire |
|--------|---------------|-----:|
| Deposit | `da0b0f977ed8c89f1c48ab20822420304994c2d261eeafa079bd3ec057330755` | 56480 |
| Transfer | `a12a23883cd715fc57ad75864d97b7a33b1fc39e3dc0780e40af33e232ca3692` | 56480 |
| Withdraw | `c3abe9fc35ce3a588a6cdabf63a3b0b206677d170f566c53e25494c82f1925b3` | 56514 |

- **profileId:** `81d05348e977f635bf6765f40e6db574249df8ed63a09418191859a2431bdd63`
- **instanceId / category:** `cbf8524d7d6b4eaa973f98ad2f4baac5659a42cedb26ed90506d8089a9df6887`
- **Heights at campaign:** 316538 → 316538 at broadcast (all four settles **conf=0** mempool — qualification bar met). Later observed conf=1 in block `00000000d73eea020098b3af3233ca144a28d159ee991fe3c8de819387ba8a44` at height 316539 without waiting/mining.
- densFuel: `gateOk=true`, wire **55307**, maxUnlock **9350** (re-prove on densFuel gate fail)
- Libauth local VM: deposit/transfer/withdraw all `ok=true`; bindingEval/stateEval true
- Engine probes: `capacityRejectBeforeProve=true`, `recoverRespendRootsMatch=true`, `adversarialPacketRejected=true`

Final tip after withdraw:

```text
noteCount=2 nullifierCount=2 live=0 reserve=0 seq=3
noteRoot      = 047a3444468e68be44670884f8dadf53cde9ab638e842c874e878441b7d66626
nullifierRoot = 28578bc02b60a4cc524fabee4c035030c79b05816b72299e18f0b661e9c89dec
```

Artifacts:

- `.cache/v2-direct-product-1tx/evidence.json`
- `/tmp/grok-goal-27ffd0a735ef/implementer/v2-product-e2e-final6.log`
- Script: `packages/v2-direct/scripts/chipnet-product-1tx-e2e.mjs`

## Mandatory stories (depth-32)

### Operator CLI (real prove + product settle — no V2_SETTLE_HEX theater)

- Modules: `operator/prove-local.mjs`, `operator/densfuel-build.mjs`, `operator/product-settle.mjs`, `operator/withdraw-payout.mjs`
- Depth **32** always; `provePoolAction` before journal `proved`
- `--broadcast` with `V2_CHIPNET_LIVE=1`: builds densFuel unlocks + binding + CashScript state + P2PKH funding, signs, broadcasts
- Requires `pool.liveTip` / `V2_LIVE_TIP_JSON` (carriers+binding+state outpoints); refuses without live tip (no fake packet txid)
- **Withdraw payout invariant:** `resolveWithdrawalPayout` owns lock↔hash — packet field = `sha256(payout lockingBytecode)` only (never cashaddr text / `default-payout` string). `assembleProductSettle` pays DENOMINATION to that same lock and asserts packet match before local VM.
- Tests: `cli/cli.test.mjs` + `operator/withdraw-payout.test.mjs` (offline regression for text-hash anti-pattern)

### Chipnet stories

Script: `packages/v2-direct/scripts/chipnet-stories-d32.mjs`  
Evidence: `.cache/v2-direct-stories-d32/stories.json`

| Story | Result | Notes |
|-------|--------|-------|
| Capacity reject-before-prove (local) | **PASS** | `maximumLiveNotes=1` second deposit throws before prove |
| **Capacity live Chipnet** | **PASS** | `chipnet-live-capacity.mjs` maxLiveNotes=**2** fill + reject-before-prove (below) |
| Contention / needs_reproof (local) | **PASS** | Two engines same pre-root; loser needs_reproof |
| **Contention live Chipnet** | **PASS** | Two-client deposit race; loser stale reject + re-prove settle (below) |
| Adversarial packet mutation | **PASS** | Codec one-byte magic flip |
| Adversarial covenant (honest) | **PASS** | Libauth OP_VERIFY/empty-stack + **live** `testmempoolaccept` script-reject on unspent carrier0 + state (not missing-inputs) |
| Recover genesis lineage | **PASS** | Chain G→D→T→W tip match + reorg undo |
| **Wipe → recover → respend** | **PASS** | Live Chipnet (below) |

### Live capacity (maxLiveNotes=2) — full txids

Script: `packages/v2-direct/scripts/chipnet-live-capacity.mjs`  
Evidence: `.cache/v2-direct-live-capacity/capacity.json`

| Step | Txid |
|------|------|
| Genesis | `5174ba89f2e3d76104cb5428fd11d9422412833dc554831414bfd176ba7043ca` |
| Deposit 1 | `0c1393de7e9090feaeeb76a6cfd4203125e8b75d928a61f96fcfc50eefc87fe7` |
| Deposit 2 (full) | `ac65f7f865f1b6f8397bd12261b92b9cf044275b3e3f7541ed268d06db6554ff` |

- **Reject before prove:** `FUNDING_OR_CAPACITY: deposit would exceed maximumLiveNotes` at liveNoteCount=2
- Height **316543**, 0-conf bar

### Live contention (two-client race) — full txids

Script: `packages/v2-direct/scripts/chipnet-live-contention.mjs`  
Evidence: `.cache/v2-direct-live-contention/contention.json`

| Step | Txid |
|------|------|
| Genesis | `33ed1570a02abacdfde0f5d59bc9fd81406d635bc7315138d464142cb23881db` |
| Winner deposit (client A) | `c4f5b53e8dca8780bd566763fd4911f85ead5a38229684c9926b7dbe48d482b7` |
| Loser stale | rejected `txn-mempool-conflict` |
| Loser re-prove + settle | `71465da818d37f086d7c307ce60d256bbfc95d3811ad0136da268dffc3b5b3b8` |

- Height **316544**, `needsReproof=true`, `liveOnChain=true`

### Wipe → recover → respend (story 5) — full txids

Script: `V2_STOP_AFTER=deposit-respend` product e2e / `chipnet-recover-respend.mjs`  
Evidence: `.cache/v2-direct-recover-respend/`

| Step | Txid |
|------|------|
| Genesis | `f1eb8364348baa6a8c7697f253e34dc6724c0a9d88c47ae243fcce1e97b30ac3` |
| Deposit | `54c55353ca94a3bd4f5701fea7aa9a2136aa8d4842c6cd653260a78613a5c223` |
| Respend withdraw | `35f16271830890413cadb36ea6092d14675e59b28c6d2de1c07b01d54a7d1c00` |

Height at campaign: **316532**. Local wipe, replay deposit secrets, tip match, withdraw of recovered note on-chain.

## Covenants vs plan

| Role | Implementation | Status |
|------|----------------|--------|
| Verifier carriers (0–6) | densFuel PF7 Groth16 + packet digest | **On-chain** |
| Binding (7) | Authenticated bare script: SIZE 552 + SDA2 magic + flags=0 | **On-chain** (not OP_DROP OP_1) |
| State (8) | CashScript `ShieldStateV2Direct` P2SH32: pre/post SKS2, category LE, reserve, kind deltas, withdraw payout hash | **On-chain** |
| Transaction context hash in binding | Packet field present; full recomputation of every non-unlock field in binding script | **Partial** — densFuel public limbs bind SHA256(packet); binding checks encoding; full tx-context recompute in-script deferred as measurement residual |
| Phase D ceremony keys | Dev setup zkey only | **Human gate** |

## Local prove performance (this host)

| Action | Prove+verify |
|--------|-------------:|
| Deposit | ~3.2 s |
| Transfer | ~2.9 s |
| Withdraw | ~2.8 s |

Well under plan p95 ≤ 60 s.

## Remaining human / Phase D gates

See [QUALIFICATION.md](./QUALIFICATION.md): multi-party ceremony, independent audits, soak, clean-machine qualification after freeze. **Not faked.**

## Mined status

### Depth-32 campaign (this pin)

Gate: **mempool-accepted + `testmempoolaccept` allowed** is sufficient (0-conf OK). Later inclusion is bonus.

| Tx | conf @ height 316526 |
|----|---------------------:|
| Genesis `1fdad90a58e020f193ad2221cf8c146a0d625679b7280c469f0171016389de53` | **2** |
| Deposit `fc726d8cf1d3e92690561a7252443f9bff8a8c54f35a1941b6e7e660418f40b0` | **1** (block `00000000a2724d5e548c23bb01fd0f47976a17d002dac53117dc76c32eb7a363`) |
| Transfer `7f84086386b6c087c43f3137e4f1d77efe2e3b952e03f0ac95ab24aa8befe910` | **1** |
| Withdraw `263347cb75e8488bd509b53b732561728efec6b83eb2d253baac19528e42d2d1` | **1** |

Re-scan:

```bash
node 03-create-your-own-pool/packages/v2-direct/scripts/chipnet-stories-d32.mjs
```

### Prior single-tx product topology (depth-16 VK pin) — **mined conf=6**

Same densFuel+binding+CashScript state topology on Chipnet (full txids):

| Step | Txid | conf |
|------|------|-----:|
| Genesis | `0a3ab50c4021c4ae8247980ed94d9e8cdb3996ad251b3d1991b2bfe845fe7ff2` | 6 |
| Deposit | `b89eb3b70bed989494a9c2e1f4e4e266be455b1a5c0f6785e898cedbc6b752ab` | 6 |
| Transfer | `94c4d5d6ac4c2b0640d8d336623843e2dbb1ac0db24b95ddbb4ce960f857bb53` | 6 |
| Withdraw | `dbac58e839da067b475d11a63f2c7df1ed3269d9c5b3215ff5422f755c6ec5c8` | 6 |

This proves the **on-chain covenant DAG mines cleanly**. Depth-32 replaces only the Groth16 relation (expanded circuit + densFuel re-pin); settlement shape is identical.
