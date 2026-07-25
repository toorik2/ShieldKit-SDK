# UX adversarial red team — ShieldKit product surface

Date: 2026-07-25  
Scope: blank-machine operator path after unlock-builder ship  
Method: attack the **user journey**, not crypto hardness.

## Personas

| Persona | Goal |
|---------|------|
| P1 Fresh operator | Clone repo → own pool → deposit → withdraw |
| P2 App integrator | Import `createKit` / `completeAction` into a wallet |
| P3 Adversarial doc-skimmer | Follow README only; refuse research paths |

## Attack findings

### CRITICAL

| ID | Finding | Impact | Status |
|----|---------|--------|--------|
| U-01 | **Pin profile artifacts live under `.cache/profile-build-live`** (~450MB zkey/r1cs). Not in git. | Create-pool genesis blocked on cold clone | **Mitigated:** `npm run pack-pin-artifacts` / `fetch-pin-artifacts` (+ optional URL) |
| U-02 | **`e2e:standalone` hard-depends on SSH host `layer1-node` + local wallets path.** | False “ready” claim | Mitigated in README honesty |
| U-03 | **Scaffold `create-pool` tip wiring** | Stuck after scaffold | **Mitigated:** auto tip from live-battery state when instance matches; `--state-txid`; doctor checks |

### HIGH

| ID | Finding | Impact | Status |
|----|---------|--------|--------|
| U-04 | Dual fee key models (A in-process / B pre-sign) | Key custody | **Mitigated:** assemble A|B; CLI/README document; plan.feeSigning |
| U-05 | Product language still mixes “PF7”, `g2-complete-settlement`, `shield.cash/*` schemas in errors. | Cognitive load | Open (schema freeze) |
| U-06 | Unlock compile ~30s with no progress UX. | Feels hung | **Mitigated:** 5s heartbeat + start/done logs |
| U-07 | Vendor tree still large | Onboarding | Pruned ~82→64MB |

### MEDIUM

| ID | Finding | Impact | Status |
|----|---------|--------|--------|
| U-08 | CLI verbs: `create-pool` is npm script | Discoverability | Documented; npm scripts + help text |
| U-09 | No single `shieldkit deposit --pool` | Act not productized | **Mitigated:** `shieldkit deposit\|withdraw --pool` → pool-act |
| U-10 | Errors from prep/assemble are raw throw messages without `code` for UX mapping. | Hard UI errors | Open |
| U-11 | `PIN_LENS` failure surfaces as unlock-builder throw mid-act after 30s prove. | Late fail | Acceptable if doctor preflight added |
| U-12 | Notes journal directories created empty; transfer/withdraw need history knowledge. | Multi-action UX gap | Open |

### LIVE E2E (2026-07-25) — pool-act unattended D→T→W

| ID | Finding | Status |
|----|---------|--------|
| B1 | `pool-act` hung after `ok:true` (open handles) | **Fixed:** `process.exit(0)` |
| B2/B3 | Mid-cycle `history.push` + extra `kind` → nullifier / exactKeys fail | **Fixed:** push only after full cycle; no `kind` |
| B4 | Fee inventory collapsed (no prep change harvest) | **Fixed:** harvest `prepHotChange` + settle hot outs |
| B7 | Manual fee inject between acts | **Fixed:** auto `scantxoutset` when inventory short; `--scan-fees` |
| B8 | PF7 intermittent OP_VERIFY on genesis deposit | **Fixed:** 4× retry (e2e pattern) |
| B9 | Unlock `tsx` EADDRINUSE under deep `.cache/...` paths | **Fixed:** short `/tmp/sk-ul-*` TMPDIR in unlock-builder |
| B10 | scantxoutset phantom spent UTXOs as fund | **Fixed:** create-pool `--scan-fund` / always gettxout-verify |
| B11 | GATE_FAIL retries stuck on single fee | **Fixed:** scan-fees-on-retry + prefer ≥2 live fees upfront |

**Verify:** `.cache/fix-unattended-d2w/` — D→T→W all `exit 0`, `historyLen=1` only after withdraw, no hand-edited state mid-cycle.  
**Verify B10/B11:** `.cache/fix-scanfund-smoke/` — `staleSkipped:1` on create; transfer GATE_FAIL attempt1 → rescan → ok attempt2.

### LOW

| ID | Finding | Mitigation |
|----|---------|------------|
| U-13 | Topology allows 6 packages; docs still say “5 domains” in places | Update package README |
| U-14 | Playground still parallel path | Keep optional; demote in README |
| U-15 | Fee rate fixed 1 sat/B with no user-facing explanation in CLI help | Doctor should state limits |

## Simulated P1 walkthrough (honest)

```text
1. git clone ShieldKit-SDK && npm i && npm test          → OK
2. npm run unlock-builder:smoke                           → OK if vendor present (in git)
3. npm run create-pool -- --out ./my-pool                 → OK scaffold
4. npm run e2e:standalone                                 → FAIL without layer1-node + wallets + tip state
5. npm run create-pool -- --with-genesis --fund-txid …    → FAIL without pin artifacts in .cache/
```

**Verdict:** Unlock compile is standalone. **Pool birth + live act are not yet one-button blank-machine** without (a) artifact pin release and (b) RPC/wallet operator kit.

## Required product guarantees (acceptance)

| # | Guarantee | Met? |
|---|-----------|------|
| G1 | Unlock build without sibling verifier.cash | **YES** (vendor) |
| G2 | `completeAction` one spine | **YES** |
| G3 | Fee can be signed outside process (B) | **YES** (assemble) |
| G4 | create-pool can birth new on-chain instance | **YES** (`--with-genesis`) if pin art + fund UTXO |
| G5 | Blank clone → deposit without extra downloads | **Partial** — fetch-pin-artifacts + pin tarball; tarball not on npm yet |
| G6 | README does not lie about G5 | **YES** |

## Red-team score (product UX) — re-score after mitigations

| Axis | Score /5 | Note |
|------|----------|------|
| First-run honesty | 4 | README + doctor honest |
| Verb clarity | 4 | deposit --pool / doctor --pool |
| Key custody story | 4 | Policy A+B |
| Standalone toolchain | 5 | Vendor + progress |
| Create-own-pool | 4 | with-genesis live; pin pack path |
| Overall | **4.2** | Expert operators green; release pin tarball for cold clone |
