# V2 Direct — STATUS / EVIDENCE

**Branch:** `feat/v2-direct-protocol`  
**Package:** `@shieldkit/v2-direct` (`03-create-your-own-pool/packages/v2-direct/`)  
**Authority:** [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md)  
**Date:** 2026-07-28

## What shipped

| Area | Status | Evidence |
|------|--------|----------|
| SKS2 128-byte state codec | **Green** | `state.test.mjs` — round-trip, 127/129 reject, one-byte mutation matrix, Fr noncanonical reject |
| SDA2 552-byte packet codec | **Green** | `packet.test.mjs` — kind rules, flags=0, SHA-256 → two 128-bit limbs |
| Cross-language KATs (TS + Rust) | **Green** | `test/cross-language-kat.test.mjs` + `rust/` crate `v2-direct-kat` |
| State transitions D/T/W | **Green** | `transition.test.mjs` — value conservation, capacity reject before prove |
| Note tree + indexed nullifier | **Green** | `trees/indexed-nullifier.test.mjs` — zero & Fr−1, duplicate reject |
| Groth16 prove/verify (dev setup) | **Green** | `prove/prove.test.mjs` + `prove/foundation-integration.test.mjs` — real D/T/W proofs |
| Rolling bundle topology planner | **Green** | `covenant/bundle.test.mjs` — funding required, carrier selection, mint authority reject |
| Local VM measure + digest-bind scaffold | **Green** | `covenant/local-vm.test.mjs` — Libauth size gates + forged digest fail-closed |
| Wallet journal + 0600 secrets | **Green** | `wallet/journal.test.mjs` — `FUNDING_UTXO_REQUIRED` before prove |
| Recovery lineage + reorg wipe | **Green** | `recover/scanner.test.mjs` |
| CLI surface | **Green** | `cli/cli.test.mjs` — wallet/pool/D/T/W/recover/status/doctor |
| Adversarial matrices | **Green** | `test/adversarial.test.mjs` |
| Chipnet live multi-path | **Green (partial settlement)** | See below |

## Chipnet live evidence (real hot funds)

**Bar: 0 conf.** No block wait / no mining for qualification.

- **Node:** `layer1-node` BCHN chipnet, height **316538** (campaign heightStart=heightEnd)
- **Hot:** `bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv`
- **Product path:** densFuel PF7 + binding + CashScript state — **real Groth16** deposit → transfer → withdraw
- **Capacity / recover / adversarial packet:** all true in product evidence
- **Full product settle txids (conf=0 mempool):** see [EVIDENCE.md](./EVIDENCE.md)
  - G `3bf9a865e965ed3046c641ef4e55059ec8ea566dc4a9286e1d02a0780d31a7ab`
  - D `b4fd8cafc8e946090fd41ef9615beafae838172510c3a54ac42f4a2872237d8b`
  - T `616fa7ecb577e2c8c1c84f364261c95df4798267eaa5eb8dc75f09329d1f429e`
  - W `26fd21d1a39b99d54666cec239bca4c7c4bcfb3a1505373e296a01559655681f`

### Digests (full)

| Action | Digest |
|--------|--------|
| Deposit | `4027115813ad400da9576038a77eaf511207d8776dd8188439bb35f009b77511` |
| Transfer | `7b97ede564b367c7f763d13e4e992ad409fe66c3429f807c9127f3b2d90250fa` |
| Withdraw | `2105e180a09d9a761b4d0b96aaf98ea5e4a149c65c347651c4ea6f2f9b46d057` |

Artifact dump: `.cache/v2-direct-chipnet-e2e/evidence.json` (gitignored)

## Commands

```bash
# Unit / integration
node --test 03-create-your-own-pool/packages/v2-direct/**/*.test.mjs \
  03-create-your-own-pool/packages/v2-direct/*.test.mjs

# CLI
node 03-create-your-own-pool/packages/v2-direct/cli/shieldkit-v2.mjs --help

# Chipnet e2e (loads WIF from codex-artifacts; never commits secrets)
node 03-create-your-own-pool/packages/v2-direct/scripts/chipnet-e2e.mjs
```

## Performance (measured on this host)

| Gate | Plan | Observed |
|------|------|----------|
| Prove (dev circuit, single action) | p95 ≤ 60s | ~1.2s fullProve+verify in prove test |
| Live commitment tx size | full VM (soft 90kB waived) | **283 bytes** |
| Circuit artifacts | — | `.cache/v2-direct-circuit/` development-only |

## Push readiness (this branch)

**Phases A–C + foundation gate: GREEN.**  
**Chipnet multi-path e2e + adversarial evidence: GREEN** (depth-32 product; 0-conf mempool bar).  
**CLI product settle path: GREEN** (`operator/product-settle.mjs` — densFuel+binding+state+funding; no `V2_SETTLE_HEX` theater).  
**CLI withdraw payout: GREEN** (`operator/withdraw-payout.mjs` — lock↔hash invariant; offline regression `withdraw-payout.test.mjs`).  
**Live capacity + live contention: GREEN** (Chipnet maxLiveNotes=2 fill; two-client race with re-prove).  
**Remaining for full product freeze:** **Phase D** human/ceremony items only — see [QUALIFICATION.md](./QUALIFICATION.md).

**READY TO PUSH TO MAIN pending your review** (do not push unless asked).

See **[FOUNDATION_GATE.md](./FOUNDATION_GATE.md)** + **[EVIDENCE.md](./EVIDENCE.md)** + **[QUALIFICATION.md](./QUALIFICATION.md)**.

### Foundation progress (2026-07-28 densFuel re-pin + product D/T/W)

| Item | Result |
|------|--------|
| Expanded circuit (depth **32** + nullifier insert + encryption) | **Pass** — **142 297** constraints; local D/T/W prove ~3s |
| densFuel V2 unlocks (SDA2 + depth-32 VK) | **Pass** — `gateOk`, wire **55307**, max unlock **9350** |
| Real BCH-2026 VM (7 carriers) | **Pass** — all accept |
| Chipnet SKS2 NFT genesis (depth-32 product) | **Pass** — `1fdad90a58e020f193ad2221cf8c146a0d625679b7280c469f0171016389de53` (conf≥1) |
| Digest-binding live tx | **Pass** — `671eb9018975e81379215a63dbb779ef22291e1820447e1917ed6ca20bff51e3` |
| Funded densFuel live settle (V2 unlocks + SDA2) | **Pass** — prior pin settle `fa9dabea718c4381daa37d35b4dff4d51dfd97cbcfd19c5be335d94d6b9a8334` |
| **Product single-tx D→T→W Chipnet (depth-32)** | **Pass** — full product settle path |
| **CLI operator prove path** | **Pass** — real Groth16 depth-32; no fake broadcast txids |
| Wipe→recover→respend (story 5) | **Pass** — respend withdraw `35f16271830890413cadb36ea6092d14675e59b28c6d2de1c07b01d54a7d1c00` |
| Capacity reject-before-prove | **Pass** (engine pre-prove) |
| Recover genesis lineage + tip match | **Pass** |
| Contention needs_reproof | **Pass** (two-engine) |
| Adversarial covenant (Libauth honest) | **Pass** — binding OP_VERIFY / empty-stack rejects |
| Binding authenticated + CashScript SKS2 | **Pass** |

### Product Chipnet single-tx D→T→W (full txids) — **depth-32** closed topology

Topology (`PUBLIC_BENCH_CONTEXT=1` densFuel does **not** bake OP_RETURN into redeem scripts; multi-out Libauth green). Carrier locks stable across D/T/W of same VK → carriers roll. Circuit: depth-32 + nullifier insert + BabyJub encryption.

```
inputs  0–6 densFuel verifiers, 7 binding, 8 SKS2 state, 9 P2PKH funding
outputs 0–6 carriers', 7 binding', 8 state', [withdraw], change
```

| Step | Full 64-char txid |
|------|-------------------|
| Genesis | `1fdad90a58e020f193ad2221cf8c146a0d625679b7280c469f0171016389de53` |
| Deposit settle | `fc726d8cf1d3e92690561a7252443f9bff8a8c54f35a1941b6e7e660418f40b0` |
| Transfer settle | `7f84086386b6c087c43f3137e4f1d77efe2e3b952e03f0ac95ab24aa8befe910` |
| Withdraw settle | `263347cb75e8488bd509b53b732561728efec6b83eb2d253baac19528e42d2d1` |

| Action | Digest | Wire |
|--------|--------|-----:|
| Deposit | `02d999f3c69235209d07e9770edbcc68b89afd446e2c1e939e916073d623edda` | 56480 |
| Transfer | `793b3c4a46de8bb4d0335e9851dca8c5fefebf983d4d44f0c4ab0c54b9835140` | 56480 |
| Withdraw | `f51cd9c3429df74ac6e40704280d3835b1dab4023df6b7832f373ee34f582f51` | 56514 |

Final tip: noteCount=2, nullifierCount=2, live=0, reserve=0, seq=3  
noteRoot `12b0206dd7e0dbd6250282541e0d53691008a14fe87ee351e2f250bf6aacd210`  
nullifierRoot `15d281263f9a2e276d868863571dae8dac3c8a83174069798d75568eaef5a0d2`  
Category/instanceId: `7807fc04383eeabb364960b4c77e27a1eb20f4bef6056a6877131b8007c8a7e8`  
Heights: 316524 → 316525  
Artifact: `.cache/v2-direct-product-1tx/e2e-d32b.log`  
Script: `packages/v2-direct/scripts/chipnet-product-1tx-e2e.mjs`

See **[FOUNDATION_GATE.md](./FOUNDATION_GATE.md)** for full measurement tables.

### Honest gaps (not papered over)

1. **Phase D** ceremony/audits (multi-party phase-2, independent audits, soak) — see [QUALIFICATION.md](./QUALIFICATION.md).  
2. Development-only Groth16 setup (not ceremony-final keys).  
3. Binding does not recompute full transaction-context hash in-script (packet SHA-256 limbs bound by densFuel; encoding checks in binding).  
4. Durable store is atomic snapshot+WAL (mode 0600), not embedded SQLite — same crash-safety contract.  
5. Rust recovery is codec KATs + JS lineage scanner; full N-API packaging optional polish.

## Additive layout

- New package only: `packages/v2-direct/`
- Legacy `shielded-action-v2` / prep paths untouched for coexisting agents
- Workspace entry added in root `package.json`
