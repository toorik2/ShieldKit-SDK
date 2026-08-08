# Adversarial red-team audit — on-chain settlement contracts (densFuel + covenants)

**Date:** 2026-07-27  
**Auditor mode:** adversarial (break, do not praise)  
**Scope:** consensus-critical BCH settlement path used by ShieldKit product pool  
**Out of scope for “green” claims:** full formal proof of Groth16 circuit soundness; BCHN miner policy; mainnet economic attack games; network privacy  

**Honest prior status:**  
`docs/SHARED_POOL_REDTEAM.md` covers **product tip rebuild + note wallet only**.  
It is **not** a smart-contract audit. This document is the SC audit.

**Method:**  
1. Map on-chain trust surface (what must pass for a settle to confirm).  
2. For each attack class: attacker model, expected defense layer, evidence path, verdict.  
3. Prefer *falsifiable* findings (code:line, test matrix, pin constants).  
4. Separate **on-chain** (VM) from **off-chain builders** (JS can lie; chain must not accept).

---

## 1. Trust model (what “smart contracts” means here)

Settlement is a **10-input densFuel pin transaction**, not a single Solidity-style contract.

| Input | Role | Lock type | What enforces it |
|------:|------|-----------|------------------|
| 0–4 | PF7 exec carriers | P2SH32 redeem (Groth16 pieces) | densFuel pin redeem; proof public inputs |
| 5 | PF7 genesis / ECIP gate | P2SH32 | `require(nfail ≤ C7_MAXTRY)` (pin: 2) |
| 6 | PF7 terminal | P2SH32 | Final pairing / accept |
| 7 | Binding / SCAR packet | Packet-only binding lock | `buildPacketOnlyBindingLock` — shape + active index 7 |
| 8 | State tip NFT | State **trampoline** P2S (≤190 B) | Unlock carries **hash-authenticated settlement helper** (`buildStateSettlementHelper`) |
| 9 | Fee | P2PKH | Consensus sig verify; helper pins structure + change lock |

**Kernel constants** (`prove/authority.mjs` → `PF7_SETTLEMENT_CONSTANTS`):

- denomination = **10_000_000** sats (0.1 BCH)  
- state carrier base = **1_080**  
- binding base = **1_000**  
- fee rate = **1 sat / wire byte**  
- complete wire limit = **59_000** B  
- topology: prep 10 outs → settle 10 ins; 7 verifier inputs  

**Active state path (live product):**  
`buildStateTrampolineLock` + helper unlock — **not** the archived bare `ShieldStateV1.cash` (that package is a documented **feasibility FAIL**: body ≫ 190 B P2S limit).

**Off-chain mirror (not consensus):**  
`packages/action/settlement.mjs` fail-closed builder; useful for local rejection, **irrelevant if an attacker crafts raw txs**.

---

## 2. What the on-chain helper actually checks (high signal)

Source: `prove/internal/covenants/g2-compressed-covenants/compressed-covenants.mjs`  
`buildStateSettlementHelper` (active input 8 unlock body).

| Check | On-chain? | Notes |
|-------|-----------|--------|
| Loop SCCT reconstruction vs packet digest fields | **Yes** | `buildLoopScctLock` + VERIFY |
| SCAR magic/version/network slice | **Yes** | Fixed `534341520102` + reserved |
| Profile / instance / max-reserve continuity pre↔post packet | **Yes** | Equal slices across states |
| PF7 locks + values pin (inputs 0–6) | **Yes** | SHA256(lock) + UTXOVALUE exact |
| Prep sibling: ins 0–7,9 same parent tx; vouts 0–8 | **Yes** | Blocks foreign PF7 subsidy |
| Fee unlock canonical Schnorr P2PKH ALL\|FORKID | **Yes** | Size 100, sighash/type bytes |
| Change out = fee lock (last output) | **Yes** | `OUTPUTBYTECODE` match |
| State NFT mutable capability + category continuity | **Yes** | in8 / out0 |
| NFT commitment pre/post from packet | **Yes** | SHST-style expected commitments |
| Reserve equation: out0 = in8 ± D by kind | **Yes** | kind∈{1,2,3} |
| Binding value = base (+D on deposit) | **Yes** | |
| Withdrawal: out1 value = D and sha256(lock)=packet | **Yes** | |
| Fee = exact 1 sat/B of serialized wire | **Yes** | `appendExactOneSatPerByteFee` |
| Groth16 proof correctness | **Yes (inputs 0–6)** | densFuel pin — opaque pin, not re-audited source-by-source here |
| Relation witness (note path, nullifier uniqueness math) | **Yes via proof** | Public inputs = packet digest limbs |
| Note secrets / wallet backup | **Off-chain** | Not contracts |

**Binding lock alone** (`buildPacketOnlyBindingLock`) only enforces: active input index 7, unlock = PUSHDATA2(752)||packet shape. It does **not** re-encode full SCCT; state helper + PF7 do the heavy binding.

---

## 3. Attack matrix (adversarial)

Severity: **C** critical (theft / mint / forge tip) · **H** high · **M** medium · **L** low · **R** residual accepted.

### 3.1 Value / reserve theft

| ID | Attack | Expected defense | Verdict |
|----|--------|------------------|---------|
| V1 | Withdraw more than D (inflate out1) | Helper: out1 == 10_000_000; packet boundary | **Blocked** (on-chain) |
| V2 | Shrink tip reserve without proof of spend | Reserve equation + proof must match packet postState | **Blocked** |
| V3 | Deposit without adding D to tip | Binding value + reserve delta kind=1 | **Blocked** |
| V4 | Drain tip by replacing state lock | Successor lock must equal activeBytecode / trampoline | **Blocked** |
| V5 | Steal PF7 carrier dust as attacker output | Fee exact 1 sat/B + fixed outs; leftover → fee-key change only | **Blocked** (change must match fee P2PKH) |
| V6 | Fee underpay / overpay | Helper EQUALVERIFY wire fee | **Blocked** |
| V7 | Zero-value change output | Positive change required (builder + helper change lock path); fee accounting needs leftover slot for PF7 dust | **Blocked / residual UX** — change always exists on withdraw (3 outs) |

### 3.2 State NFT / tip forgery

| ID | Attack | Defense | Verdict |
|----|--------|---------|---------|
| S1 | Fake tip commitment without valid pre-state | NFT pre must match packet pre; SCCT | **Blocked** |
| S2 | Advance seq without proof | Proof + packet digest public inputs | **Blocked** (assuming pin/circuit) |
| S3 | Duplicate state NFT on other inputs/outs | Helper / SCCT token rules; category only on 8/0 | **Blocked** (mutation matrix family) |
| S4 | Category swap / capability none | Mutable capability + category pin | **Blocked** |
| S5 | Replay old tip into new pool instance | instanceId in packet + NFT | **Blocked** across instances |
| S6 | Cross-profile settle | profileId continuity + proof profile | **Blocked** |

### 3.3 Topology / prep / subsidy

| ID | Attack | Defense | Verdict |
|----|--------|---------|---------|
| T1 | Mix PF7 carriers from another prep/wallet | Outpoints: 0–6,7,9 same parent; fixed vouts | **Blocked** |
| T2 | Substitute one PF7 redeem for alternate | Lock SHA256 pin in helper | **Blocked** |
| T3 | Change PF7 source values (underfund carriers) | UTXOVALUE pin per index | **Blocked** |
| T4 | Wrong input order / role swap | Fixed 10 roles; SCCT + pins | **Blocked** (matrix) |
| T5 | Reuse settle as prep for next without new prep | Each act needs fresh prep siblings for 0–7,9; tip is in8 chain | **Blocked** for illegal mix; concurrent tip race is chain-serialized |

### 3.4 Proof / densFuel pin / ECIP

| ID | Attack | Defense | Verdict |
|----|--------|---------|---------|
| P1 | Invalid Groth16 / wrong public inputs | PF7 OP_VERIFY chain | **Blocked** if pin correct (trust: pin + ceremony/dev keys) |
| P2 | Valid proof for different packet | Public inputs = SHA-256 limbs of packet | **Blocked** (relation design) |
| P3 | ECIP nfail > pin maxTry thrash | Genesis `nfail≤2`; client ECIP preflight + fee diversity | **DoS residual** on client; **not** theft |
| P4 | Binary-patch densFuel topology (feeReserve experiments) | Product freezes stock pin; archive only | **Process residual** — patched pin is different trust |
| P5 | Trusted setup / toxic waste (dev profiles) | Development-only local init | **R / product** — not production ceremony claim |
| P6 | Circuit bug (soundness): forge nullifier / fake membership | Requires full circuit audit + formal verification | **R — NOT closed by this audit** |

### 3.5 Packet / SCAR field attacks

| ID | Attack | Defense | Verdict |
|----|--------|---------|---------|
| K1 | Mutate SCAR slices (roots, seq, cm, nf) | SCCT + proof | **Blocked** (matrix covers field ranges) |
| K2 | Wrong kind / output cardinality | Helper kind∈1..3 + out counts | **Blocked** |
| K3 | Withdraw to attacker script | out1 sha256 must match packet; proof binds digest | **Blocked** without knowing note secrets |
| K4 | Binding unlock not pure 752 packet | Binding lock SIZE+PUSHDATA shape | **Blocked** |

### 3.6 Binding / SCCT gaps (honest edge)

| ID | Attack | Defense | Verdict |
|----|--------|---------|---------|
| B1 | Rely on binding lock alone | Binding is intentionally minimal | **By design** — state helper + PF7 carry SCCT |
| B2 | Helper unlock substitution (wrong helper body) | Trampoline hashes helper; must match | **Blocked** (trampoline test suite) |
| B3 | Libauth VM ≠ BCHN edge cases | Mutation matrix is Libauth BCH-2026 standard | **R** — no BCHN peer/miner claim in matrix README |

### 3.7 Client / product path (contracts don’t save you)

| ID | Attack | Defense | Verdict |
|----|--------|---------|---------|
| C1 | Tip rebuild from forged history | Client NFT check | **Product** (SHARED_POOL_REDTEAM) |
| C2 | Incomplete electrum history | DoS / stuck client | **R** |
| C3 | Lost wallet without backup | Funds unspendable | **Expected** |
| C4 | Fee UTXO / change metadata linking | Public | **Privacy R** (PRIVACY.md) |
| C5 | Concurrent tip: stale local tip | Chain serializes; client resync | **R** race UX |

### 3.8 Archived / non-product surfaces

| ID | Item | Verdict |
|----|------|---------|
| A1 | `ShieldStateV1.cash` bare P2S | **Feasibility FAIL** (833 ≫ 190); **not** product path — do not audit as live |
| A2 | Tip feeReserve densFuel topology patch | **Archived / frozen out** of product |
| A3 | LeanBCH VM model | Separate audit (`vendor/lean/RED_TEAM_AUDIT.md`); soundness for *model*, not densFuel pin content |

---

## 4. Evidence already in-repo (reused, not re-invented)

| Evidence | Path | Claim boundary |
|----------|------|----------------|
| Real Chipnet 10-input mutation matrix | `g2-compressed-covenants/real-action-mutation-matrix.*` | Libauth VM; **0 false accepts** on fixture mutations; not BCHN |
| Compressed covenant unit tests | `compressed-covenants.test.mjs` | Trampoline rejects helper/PF7/state/category swaps |
| Settlement builder fail-closed | `action/settlement.test.mjs` | JS builder only |
| densFuel ECIP gate | `unlock-builder/ecip-pin-gate.mjs` | Client thrash prevention |
| LeanBCH adversarial audit | `unlock-builder/vendor/lean/RED_TEAM_AUDIT.md` | VM cost/model, not pool economy |
| Product tip/wallet red-team | `docs/SHARED_POOL_REDTEAM.md` | Off-chain product |

**This audit did not re-prove Groth16 pairings or recompile densFuel redeem scripts instruction-by-instruction.** densFuel is treated as a **frozen black-box pin** with known public topology constraints (wire ≤59k, 10-in, ECIP maxTry=2).

---

## 5. Findings summary

### No new critical theft vectors found in the *covenant helper + topology* layer

Against the stated trust model (honest densFuel pin + sound circuit + standard BCH VM):

- Cannot arbitrary-mint reserve or steal tip sats without a valid proof and packet-consistent SCCT.  
- Cannot redirect withdrawal value without controlling the proven script hash / note secrets.  
- Cannot subsidize a proof with foreign PF7 carriers.  
- Cannot underpay fees or detach change to a third party under the helper rules.

### High / structural residuals (accepted or deferred)

| # | Severity | Residual | Why accepted / next step |
|---|----------|----------|---------------------------|
| R1 | **H** | **Circuit / setup soundness not re-audited here** | Needs dedicated ZK audit + production ceremony; dev profiles are toxic-waste-unsafe |
| R2 | **M** | **densFuel pin opacity** | Frozen binary/redeem pin; topology patches are a different product; keep stock pin |
| R3 | **M** | **Libauth ≠ full BCHN claim** | Mutation matrix disclaimer; optional BCHN re-verify campaign |
| R4 | **M** | **ECIP maxTry=2 liveness** | Can force client re-prove (fee/seed diversity); not theft |
| R5 | **L** | **Forced change output + fee dust** | Privacy/UX leak; protocol requires positive change + exact fee |
| R6 | **L** | **Fixed denomination / public shape** | Linking surface (PRIVACY.md) |
| R7 | **L** | **Electrum incomplete history** | Client DoS; NFT still unforgeable |

### Explicit non-claims

- Not a “bulletproof private pool.”  
- Not mainnet-ready ceremony.  
- Not a formal verification of the shielded relation.  
- Not proof that every densFuel internal opcode is optimal or free of implementation bugs outside the pin’s tested accept path.

---

## 6. Recommendations (priority)

1. **Keep densFuel frozen** in product; any topology change requires a **new pin + full re-matrix**.  
2. Schedule **independent ZK circuit + setup audit** before any mainnet value claim (closes R1).  
3. Optional: **BCHN-level** re-execution of the real-action mutation fixtures (closes part of R3).  
4. Product: continue **ECIP preflight** so liveness issues stay off the critical path (R4).  
5. Do **not** revive bare `ShieldStateV1.cash` as a live lock.  
6. Keep product red-team (`SHARED_POOL_REDTEAM.md`) separate from this SC audit; link both from operator docs.

---

## 7. Verdict

| Layer | Status |
|-------|--------|
| **State trampoline + settlement helper (on-chain value rules, SCCT, PF7 pin, prep siblings, exact fee)** | **Hardened under adversarial review of source + existing mutation evidence** — no C-severity open bug found in this pass |
| **densFuel Groth16 pin internals + circuit soundness + ceremony** | **Not cleared** — residual R1/R2 |
| **Product tip rebuild / wallet** | Covered separately in `SHARED_POOL_REDTEAM.md` |

**Bottom line for operators:**  
On-chain settlement **value safety** is driven by the **hash-authenticated state helper + PF7 pin + exact fee rule**, and those checks look tight against the attack classes above.  
Do **not** treat that as a full smart-contract *and* ZK security certification. The highest remaining risk is **cryptographic / setup / pin-opacity (R1–R2)**, not “missing change output” or client tip rebuild.

---

## 8. Appendix — key file index

| Component | Path |
|-----------|------|
| State helper builder | `packages/prove/internal/covenants/g2-compressed-covenants/compressed-covenants.mjs` |
| Archived bare state (FAIL) | `packages/prove/internal/covenants/g2-state-p2s/ShieldStateV1.cash` |
| PF7 authority / kernel | `packages/prove/authority.mjs` |
| Settlement JS builder | `packages/action/settlement.mjs` |
| Transition / relation reference | `packages/action/transition.mjs` |
| densFuel unlock / ECIP | `packages/unlock-builder/` |
| Mutation matrix | `.../g2-compressed-covenants/real-action-mutation-matrix.mjs` |
| Product red-team | `docs/SHARED_POOL_REDTEAM.md` |
