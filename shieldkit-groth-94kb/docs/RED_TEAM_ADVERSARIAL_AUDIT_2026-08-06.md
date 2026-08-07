# Red-team adversarial audit — ShieldKit V2 Direct shielded pool (beta)

| Field | Value |
| --- | --- |
| Date | 2026-08-06 |
| Product | ShieldKit-Groth Beta 0.3.0-beta.1 |
| Tree | `shieldkit-sdk` @ `9b8e4ee9107c1bdab8a2dbcb064335d074b056d8` |
| Scope | Chipnet PF10 product path: crypto claim, ops privacy, product CLI, zero-conf, funding, recovery, artifacts |
| Method | Code + docs review; passive on-chain rechecks (packed-live + blank 5×5 dumps); prior Chipnet live evidence |
| Status | **Unaudited product.** This is an internal adversarial review, not a paid third-party formal audit |

---

## Executive summary

**Bottom line:** The note-level design (domain-separated Poseidon nullifiers, no published spent commitment, leaf ≠ nullifier by construction) is **coherent** and matches the narrow documented claim. Practical “privacy” on live Chipnet beta is **dominated by non-crypto surfaces**: single-contributor setup, zero-conf finality, fee/tip graphs, live occupancy, self-only transfer, and payout/fee identity.

| Layer | Verdict |
| --- | --- |
| Note leaf ↔ nullifier unlink (crypto claim) | **Holds by design** under Poseidon/ECDH assumptions when live set > 1; **not** production-sound under beta keys |
| Operational identity | **Broken by design** for lab single-operator fee fanout; **mitigated** for withdraw-to-local-fee after `1a06a41` |
| Soundness vs setup party | **CRITICAL gap** — single-contributor toxic waste can forge proofs |
| Fund finality (zero-conf) | **CRITICAL residual** — Fulcrum quorum ≠ BCH finality |
| Availability | **HIGH** tip griefing + fee-independence brick + unlock size cliff |
| Product labeling honesty | **Mostly good** (docs nonclaims are accurate if operators read them) |

**Do not treat this beta pool as production privacy or production fund safety.**

---

## Threat model

### In scope

- Passive BCH observer (full tip chain, SDA2 unlocks, fees, payouts)
- Active Chipnet participant racing tip / fee UTXOs
- Malicious or colluding public Fulcrum (2-of-3 product quorum)
- Compromised single-contributor / pin holder
- Honest-but-confused operator (wrong `--to`, solo pool, shared fee wallet)
- Local same-UID attacker on data-home (DB rewrite)

### Out of scope (explicit product nonclaims)

- Network / IP / RPC query privacy
- Hosted multi-tenant service security
- Mainnet deployment
- Formal Lean/Q-gates completion (publication gates)

### Assets

1. Shielded note secrets (`sk` / `ivk` / note material)
2. Transparent BCH in reserve + fee wallets
3. Integrity of tip / nullifier set / note tree
4. Operator identity / session unlinkability (marketing expectation)

---

## Severity legend

| Level | Meaning |
| --- | --- |
| **CRITICAL** | Breaks core soundness, finality, or privacy *if* product is treated as production |
| **HIGH** | Reliable attack or major claim/ops failure under realistic beta use |
| **MEDIUM** | Significant residual; requires conditions or degrades security posture |
| **LOW** | Limited impact or edge case |
| **INFO** | Design constraint / positive finding |

---

## CRITICAL findings

### C1 — Single-contributor setup toxic waste voids soundness and privacy

**Evidence:** `docs/protocol/v2-direct/BETA_SINGLE_CONTRIBUTOR_CEREMONY.md`; pin `pins/v2-beta-product-offline-r3.pin.json`; `docs/SECURITY.md` (development-only / local-contribution-simulation).

**Attack:** Holder of residual toxic waste forges Groth16 proofs for arbitrary public inputs → fake deposits/spends/state transitions that still verify under the pin.

**Impact:** Total break of integrity and of any privacy claim that assumes only honest provers.

**Status:** Documented; **not cryptographically mitigated**. Multi-party ceremony + independent audits are publication gates (`PRIVACY_AND_ROLLOUT.md`), not met for this pin.

---

### C2 — Zero-conf Fulcrum quorum is not double-spend resistance

**Evidence:** `packages/kit/chipnet-rpc.mjs` (2-of-3 exact raw+state readback; sole broadcast role); product results `confirmed: false`, `productionQualified: false`.

**Attacks:**

1. Race double-spend of tip NFT or fee UTXO after quorum accepts exact bytes but before mined finality.
2. Colluding 2/3 indexers: false-accept (local commit of non-chain state) or false-deny (indeterminate / grief).
3. Reorg / visibility lag: agreement ≠ consensus finality.

**Impact:** Local “accepted-zero-conf” can diverge from eventual chain tip; notes/fees can be orphaned.

**Status:** Intentional beta policy. Safe only as **lab** semantics.

---

### C3 — Live set size 1 makes note-unlink trivial without crypto break

**Evidence:** Public `noteCount` / `nullifierCount` → `live = note − nullifier` (`SKS2`); `docs/PRIVACY.md` candidate-set collapse; circuit capacity checks.

**Attack:** When `live = 1`, any transfer/withdraw nullifier **must** map to the only unspent note. Solo empty-pool “deposit then withdraw” fully de-anonymizes at note layer.

**Impact:** Crypto claim holds only when concurrent live notes > 1 (and ideally multi-user).

**Evidence on live runs:** Lab 5×5 / solo sessions routinely operate with small live sets; occupancy is public on every tip.

---

## HIGH findings

### H1 — Fee graph + serial tip NFT collapse session identity (ops nonclaim)

**Evidence:** Bootstrap SOURCE fanout (`beta-product-pool-funding.mjs`); tip NFT single writer; `docs/PRIVACY.md` fee nonclaim; passive attack on blank instance `59c6e187…` (all fees → shared fanout → hot).

**Attack (no keys):** Walk tip chain → fee vin → prevout parents → cluster operator; cold→hot top-ups extend identity.

**Impact:** Identity/session privacy fully broken even when nullifier ↛ leaf.

**Mitigation:** Fee redesign is **out of product control surface** (deferred). Docs are honest.

---

### H2 — Withdraw-to-funder was a product footgun; local reject is partial

**Evidence:** `assertWithdrawalPayoutNotLocalFeeOrChange` / `BETA_WITHDRAWAL_TO_FEE_WALLET_REJECTED` (`beta-product-action-lifecycle.mjs`); `localFeeAndChangeLockingBytecodeHexes()` (funding_keyring ∪ change_wallets only).

**Fixed (shipped `1a06a41`):** Product refuses payout locks known as **this data-home’s** fee/change wallets; harnesses use dedicated payout wallets; `privacy-passive-payout-check.mjs` gate.

**Recheck (2026-08-06):**

| Corpus | Gate |
| --- | --- |
| Packed-live 5×5 with external payout | **PASS** (no payout ≡ funding-like lock) |
| Old blank hot-in/hot-out dump | **FAIL** (negative control; still detects collapse) |

**Residual:**

- Does **not** stop withdraw to an external address that is still operator-controlled but not in local DB.
- Does **not** stop all five withdraws to the **same** external payout (payout identity clusters; packed-live `singlePayoutAddress: true`).
- Fee fanout clustering remains public.

---

### H3 — Transfer is self-renote, not private third-party payment

**Evidence:** Product `executeTransfer` stages new note to **same** local shield account; `docs/PRIVACY.md` checklist item 4.

**On-chain:** kind=2 publishes **both** `publicNullifier` and `outputNoteLeaf` + ciphertext (explicit spend→create edge).

**Impact:** Marketing as “private transfer between users” is false. Useful for note rotation; does **not** grow multi-user anonymity set.

---

### H4 — Single tip writer → re-prove griefing / multi-user DoS

**Evidence:** `STALE_TIP_REPROOF_REQUIRED`; single mutable state NFT (`PROHIBITED_TOPOLOGIES.md`); prove cost ~10s class (live p95 ~10.8s).

**Attack:** Contending writer always spends tip first → victim wastes prove work. Global “first-try / no multi-retry” ops culture makes contention operationally fatal for that attempt.

**Impact:** Availability; multi-user public pools need social coordination or external sequencing.

---

### H5 — Fee parent ≠ tip parent can brick serial operation

**Evidence:** `FUNDING_NOT_INDEPENDENT` (`settlement.mjs`); `#selectFunding` filters `txid !== tipTxid`; CLI requires alternating independent fee UTXOs / `pool add-funding`.

**Attack / ops failure:** Action N’s fee change is on tip N → **ineligible** for N+1. Exhaust independent fee UTXOs → stuck until external `add-funding` (observed: packed-live withdraw-5 needed `add-funding` of SOURCE change).

**Impact:** Availability / operator self-DoS; not silent theft.

---

### H6 — Custom Poseidon-ECDH note record is unaudited

**Evidence:** 128-byte `E ‖ encρ ‖ encr ‖ tag`; Q-05 partial; `IMPLEMENTATION_PLAN.md` requires dedicated crypto audit.

**Impact:** No demonstrated break without keys; residual design risk until external crypto review.

---

## MEDIUM findings

### M1 — Fixed 0.1 BCH denomination

No amount privacy; anonymity is combinatorial over live notes + graph only.

### M2 — `maximumLiveNotes` (e.g. 100000) ≠ anonymity set

Admission capacity only. Practical set ≈ concurrent independent live notes.

### M3 — `withdrawalLockingBytecodeHash` is a public payout fingerprint

Equal hashes across withdraws cluster cash-out identity without inspecting vout (also visible on vout).

### M4 — Exact rebroadcast recovery is safe but brittle

Attempt-token CAS + identical bytes only; flaky providers leave indeterminate until exact resubmit or reconcile. No automatic multi-retry (good for double-send safety).

### M5 — Local store integrity is OS-trust

0700/0600, no symlinks, binding on reopen — good path hygiene. Same-UID rewrite of SQLite is not MAC-protected.

### M6 — Artifact / pin supply chain

Offline pin binds releaseId + manifest SHA-256; evil **first** checkout/custody still wins. No remote transport signature layer.

### M7 — Unlock bytecode exactly 10 000 bytes

Standardness cliff: +1 byte → mempool policy reject. Zero margin disclosed on live evidence.

### M8 — Public Fulcrum sees IP + queried outpoints

Documented nonclaim; still an ops anonymity leak.

---

## LOW / INFO

| ID | Finding |
| --- | --- |
| L1 | Withdraw policy is data-home-local only (by design of residual H2) |
| L2 | Funding selection prefers largest UTXO (solvency over privacy) |
| L3 | Multi-process same data-home relies on SQLite locks |
| I1 | **Positive:** nullifier ≠ any note leaf on packed-live store (intersection empty); no published spent `cm` (V1 leak absent) |
| I2 | **Positive:** inactive SDA2 fields forced zero by kind (JS + circuit + covenant) |
| I3 | **Positive:** domain-separated Poseidon for authority / cm / nf / leaf |
| I4 | Docs claim boundary is narrow and mostly accurate if read |
| I5 | Recovery scanner binds payout hash to packet (integrity, not privacy) |

---

## Passive on-chain rechecks (2026-08-06)

### Packed CLI live pool (external payout)

- Instance: `e5b310e8bdb4e666cf9acfddf5bf5e15a55373f2038b206f7fb53f04d610c6c4`
- Genesis: `dd269eed7c5745f9815709a06b68ce24a286276c2f60d85dfe7c321ec9e56d7d`
- 5 deposit + 1 transfer + 5 withdraw; payout `bchtest:qqtn75vs9ah3tuj40es2y8w7f93zg3hxxug5cvc9pk`
- `privacy-passive-payout-check`: **PASS** (`payoutEqualsFundingLikeLock: false`)
- Libauth BCH_2026_STANDARD re-eval: **11/11** action txs OK; max unlock **10000**
- Store: note leaves ∩ wallet nullifiers = ∅

### Negative control (pre-fix blank hot-out)

- `/tmp/privacy-attack-blank`: gate **FAIL** (payout ≡ hot funding lock) — detector works

### What passive observer still sees on “fixed” packed run

- Serial tip chain, kind, sizes, occupancy steps
- Fee parents still cluster operator (SOURCE / hot ancestry)
- All five withdraws to **one** external payout lock (`singlePayoutAddress: true`)
- Transfer nullifier+leaf pair

---

## Attack playbooks (adversarial)

### A — Passive session deanonymization (no keys)

1. Index tip NFT spends for `instanceId` / category.
2. Decode SDA2: kind, nullifier, leaf, wdHash, pre/post reserve.
3. Trace fee vin → fanout parents → P2PKH clusters.
4. Cluster withdraw payouts / wdHash.
5. Use timing + occupancy to rank candidates; if live=1, declare link.

**Result on solo lab:** identity broken; note links often trivial by occupancy.

### B — Setup compromise

1. Obtain toxic waste / substitute pin with attacker keys.
2. Forge proofs; steal reserve / fake notes.

**Result:** total integrity failure of that pin.

### C — Zero-conf race

1. Observe accepted zero-conf tip spend.
2. Race conflicting spend of tip or fee input to miners.
3. Force victim local tip desync / orphaned notes.

### D — Tip griefing

1. High-rate tip advances on contended public pool.
2. Victims pay prove cost and fail first-try ops policy.

### E — Fee starvation

1. Force or wait until only tip-sibling change remains.
2. Next action fails `FUNDING_NOT_INDEPENDENT` / `INSUFFICIENT_FUNDING` until `add-funding`.

---

## Mitigations status matrix

| Issue | Product status |
| --- | --- |
| Withdraw-to-local-fee/change | **Mitigated** (reject + harness + passive gate) |
| Fee fanout unlink | **Open** (explicit nonclaim / deferred) |
| Multi-party ceremony | **Open** (publication gate) |
| Confirmations / finality | **Open** (zero-conf beta policy) |
| Multi-user anonymity set | **Ops** (not a product default) |
| Third-party shield transfer | **Not in product CLI** |
| Tip contention | **Topology** (documented) |
| Unlock margin | **Zero** (disclosed) |
| package-lock packed install | **Fixed** `9b8e4ee` |

---

## Recommended priority actions

1. **Never** market beta as private/anonymous/production; keep claim text next to every demo.
2. Keep **external payout** + passive gate in every live harness; prefer **fresh payout per withdraw** for higher bar.
3. Treat fee-graph redesign as a separate programme if identity privacy is a product goal.
4. Before any real-value mainnet: multi-party ceremony, external audits (crypto + covenants + wallet), confirmation policy, unlock margin budget.
5. Document operator runbook: two independent fee UTXOs, tip contention behavior, zero-conf risk acceptance.
6. Optional product hardening: warn when live set is 1 at unshield; warn on repeated payout address reuse; doctor privacy notes.

---

## What was **not** found

- Algebraic `publicNullifier ≡ outputNoteLeaf` by construction
- V1-style cleartext spent-`cm` on the V2 packet
- Automatic silent rebroadcast / multi-retry of different packs on product path
- Default product withdraw to hot after privacy fix (policy rejects local fee/change)

---

## Conclusion

ShieldKit V2 Direct’s **note-unlink design is a serious, domain-separated construction** that removes the V1 spent-commitment transcript class of leak. The **beta deployment** still fails a production red-team bar on three independent axes: **setup soundness**, **zero-conf finality**, and **operational identity/graph privacy**. The recent payout isolation work closes a real product-assisted footgun; it does **not** make lab pools “private.”

**Overall red-team grade for production use: FAIL (expected for labeled beta).**  
**Grade for stated Chipnet beta lab claims (narrow crypto + honest nonclaims): CONDITIONAL PASS** if operators obey payout policy and never confuse setup/zero-conf with final security.

---

## Appendix — key paths

```
docs/PRIVACY.md
docs/SECURITY.md
docs/protocol/v2-direct/PRIVACY_AND_ROLLOUT.md
docs/protocol/v2-direct/BYTE_LAYOUTS.md
docs/protocol/v2-direct/BETA_SINGLE_CONTRIBUTOR_CEREMONY.md
packages/action/v2/notes.mjs
packages/action/v2/packet.mjs
circuits/v2-direct/pool-action.circom
packages/kit/v2/beta-product-action-lifecycle.mjs
packages/kit/v2/beta-product-wallet.mjs
packages/kit/chipnet-rpc.mjs
packages/kit/v2/beta-zero-conf-admission.mjs
scripts/privacy-passive-payout-check.mjs
```

## Appendix — live evidence anchors

- Packed evidence: implementer `packed-live/evidence-summary.json`
- Multi-verifier: `packed-live/multi-verifier-report.json`
- Privacy gate: `packed-live/privacy-passive-payout-check.json`
- Privacy fix commit: `1a06a41`
- Pack fingerprint fix: `9b8e4ee`
