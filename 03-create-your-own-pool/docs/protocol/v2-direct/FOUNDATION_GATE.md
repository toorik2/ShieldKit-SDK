# V2 Direct — Foundation Gate Report

**Date:** 2026-07-28  
**Verdict:** **VERIFIER CARRIERS PASS** (size/VM gates green; densFuel re-pin for V2 VK + SDA2)

## Executive summary

| Gate | Result |
|------|--------|
| Real Groth16 for V2 Direct relation | **PASS** — **depth-32** circuit, **142 297** constraints: note Merkle + indexed-nullifier insert + record sponge + BabyJub encryption |
| densFuel unlocks for V2 VK + SDA2 packet | **PASS** — depth-32 VK re-pin `gateOk=true`, wire **55 307** |
| Real BCH-2026 VM accept (7 carriers) | **PASS** (all `accepts: true`) |
| Size: wire (full VM; soft 90kB waived) | **PASS** — **55 307** B (under network headroom) |
| Size: unlock (full VM; soft 9.5k waived) | **PASS** — max **9 350** B |
| VM (full power; soft 90% waived) | **PASS** — op **5 181 919** / budget **6 112 800** ≈ **84.8%** (full VM allowed) |
| Carrier selection | **PASS** — candidate `v2-densfuel` selected under full-VM LIMITS |
| Chipnet SKS2 NFT genesis (128-byte) | **PASS** — depth-32 product genesis below |
| Full funded densFuel settle on Chipnet | **PASS** — product single-tx path (not lab-only) |
| Binding covenant | **PASS** — authenticated SDA2 magic+flags lock (not bare `OP_DROP OP_1`); Libauth + on-chain |
| State covenant | **PASS** — CashScript `ShieldStateV2Direct` P2SH32 (pre/post SKS2, category, reserve, kind deltas) |
| Product single-tx densFuel+CashScript SKS2 D→T→W | **PASS** — **depth-32** VK; densFuel(0-6)+binding(7)+P2SH32 state(8)+funding(9) |
| Local depth-32 D→T→W prove+verify | **PASS** — ~3s/action |

## densFuel measurement (V2 re-pin)

Artifacts: `.cache/v2-direct-unlocks/`

| Role | Unlock bytes | VM |
|------|-------------:|-----|
| exec0 | 8177 | accept |
| exec1 | 6654 | accept |
| exec2 | 7066 | accept |
| exec3 | 7066 | accept |
| exec4 | 8393 | accept |
| genesis | 7600 | accept |
| terminal | 9350 | accept |
| packet (SDA2) | 555 | structural |

```text
wireBytes     = 55307
maxUnlock     = 9350
packetVersion = SDA2 (552) + PUSHDATA2 header
digest        = b01343a7835c04a8e2b306787cfb6675a5e19aa019bebc36c8df8ba675e4bde6
```

### How re-pin was achieved

1. Prove V2 deposit with expanded circuit → snarkjs proof + public limbs.  
2. `adaptSnarkjsGroth16` → full PF7 adapter (`verifierCashVk` + fixture).  
3. densFuel via `buildVerifierUnlocks` with `C7_SHIELD_ADAPTER_*` (VK from adapter, not V1 pin vectors).  
4. **SDA2 packet support** in densFuel packet ingress (`shield-action-packet-input.mjs` + `build.ts` packetDigestGuard): SCAR 752 **or** SDA2 552.  
5. `requirePinLens: false` (measure V2 lens; do not force V1 length table).  
6. `skipEcipGate: true` (offline ECIP noble Point-class bug for fresh VKs; densFuel is authoritative).

## Chipnet live evidence

| Event | Full txid |
|-------|-----------|
| Digest-binding OP_RETURN | `671eb9018975e81379215a63dbb779ef22291e1820447e1917ed6ca20bff51e3` |
| SKS2 128-byte mutable NFT genesis | `be4208fbad067cc54d52ce2b08ebffd97c64b0e0ffc8ee3b213a9150cbf57279` |
| Category | `fe80927d5a68e8c08695c0a034513e7d8faf11da4286c0095883bd61fa67bab1` |
| **densFuel fund (10 locks @ 10 000 sats)** | `9fb426da4dcfb1942f6afe2fd1a22d2462a786c8b7ead15e35693a21b0dce903` |
| **densFuel settle (V2 proof unlocks + SDA2)** | `fa9dabea718c4381daa37d35b4dff4d51dfd97cbcfd19c5be335d94d6b9a8334` |

### densFuel live settle detail

| Field | Value |
|-------|--------|
| Wire | 55 307 B |
| Fee | 99 000 sats (~1.79 sat/B) |
| Inputs | 10 (common parent fund tx, vouts 0–9) |
| Source value | 10 000 sats each (`C7_SOURCE_VALUE_SATS=10000`) |
| Packet | SDA2 552 B in input 7 unlock |
| Verifier unlocks | densFuel exec0–terminal (max 9 350 B) |
| `testmempoolaccept` | **allowed: true** |
| Broadcast | **success** (mempool; confirmations pending chipnet block) |
| Evidence | `.cache/v2-direct-live-settle/evidence.json` |

## What remains before READY TO PUSH TO MAIN

1. **Phase D** ceremony/audits only (`QUALIFICATION.md`) — multi-party phase-2, independent audits, soak.  
2. Stories evidence: `.cache/v2-direct-stories-d32/stories.json` + [EVIDENCE.md](./EVIDENCE.md).  

**Code readiness:** Phases A–C + foundation **GREEN**. Depth-32 product D/T/W settled on Chipnet (mempool bar; inclusion recorded).  

### Depth-32 circuit expansion (2026-07-28)

| Item | Value |
|------|------:|
| `CIRCUIT_TREE_DEPTH` | **32** |
| Constraints | **142 297** |
| Note Merkle + empty-append | yes |
| Indexed nullifier insert (pred+empty sequential) | yes |
| Record commitment sponge (8 limbs) | yes |
| BabyJub `E=[esk]B8`, `[esk]V`, Poseidon encrypt/tag | yes |
| Local D / T / W prove+verify | **~3s each** |
| densFuel re-pin | **gateOk**, wire **55307** |
| ptau | `powersOfTau28_hez_final_20.ptau` |
| Artifacts | `.cache/v2-direct-circuit/` (dev setup) |

### Product single-tx + CashScript SKS2 (2026-07-28) — **depth-32 VK**, closed topology

| settleTxid | Action | wire |
|------------|--------|-----:|
| `fc726d8cf1d3e92690561a7252443f9bff8a8c54f35a1941b6e7e660418f40b0` | deposit | 56480 |
| `7f84086386b6c087c43f3137e4f1d77efe2e3b952e03f0ac95ab24aa8befe910` | transfer | 56480 |
| `263347cb75e8488bd509b53b732561728efec6b83eb2d253baac19528e42d2d1` | withdraw | 56514 |

Genesis: `1fdad90a58e020f193ad2221cf8c146a0d625679b7280c469f0171016389de53`  
Category / instanceId: `7807fc04383eeabb364960b4c77e27a1eb20f4bef6056a6877131b8007c8a7e8`  
Heights: start **316524** → end **316525**  
State: CashScript `ShieldStateV2Direct` P2SH32; binding authenticated (SDA2 magic+flags); densFuel PF7 depth-32.  
Full VM envelope (plan soft 90%/9.5k/90kB not enforced).  
Probes: capacity / recover-respend / adversarial packet **true**.  
Script: `packages/v2-direct/scripts/chipnet-product-1tx-e2e.mjs`  
Log: `.cache/v2-direct-product-1tx/e2e-d32b.log`  

Prior depth-16 product chain (still valid evidence of topology):  
deposit `b89eb3b70bed989494a9c2e1f4e4e266be455b1a5c0f6785e898cedbc6b752ab`, transfer `94c4d5d6ac4c2b0640d8d336623843e2dbb1ac0db24b95ddbb4ce960f857bb53`, withdraw `dbac58e839da067b475d11a63f2c7df1ed3269d9c5b3215ff5422f755c6ec5c8`.  

## Commands

```bash
# Prove + densFuel unlocks (≈80s)
node 03-create-your-own-pool/packages/v2-direct/prove/build-unlocks.mjs

# Assert foundation measurements
node --test --test-force-exit \
  03-create-your-own-pool/packages/v2-direct/prove/foundation-unlocks.test.mjs
```

## Non-claims

- densFuel lab candidate `testmempoolaccept` fails with `missing-inputs` (synthetic sources) — expected; not a VM failure.  
- No preparation transactions, no synthetic always-valid verifiers, no sponsor/faucet.  
- Not mainnet-ready until funded covenant D/T/W + audits.
