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
| U-01 | **Pin profile artifacts live under `.cache/profile-build-live`** (~450MB zkey/r1cs). Not in git. Blank `git clone` cannot `create-pool --with-genesis` without a separate artifact distribution step. | Create-pool genesis blocked on cold clone | **Open** — document + pin tarball / release asset required |
| U-02 | **`e2e:standalone` hard-depends on SSH host `layer1-node` + local wallets path.** README implies “npm run e2e:standalone” works after clone; it does not without operator infra. | False “ready” claim | Mitigated in README honesty (this doc + README note) |
| U-03 | **Scaffold `create-pool` does not set a spendable `stateTxid` tip.** Operator can scaffold and still fail first deposit silently if tip not wired. | Stuck after “success” JSON | Partially mitigated: instance README + state tipNote |

### HIGH

| ID | Finding | Impact | Status |
|----|---------|--------|--------|
| U-04 | Dual fee key models (A in-process / B pre-sign) easy to miss; `completeAction` still uses A. | Integrators re-introduce key custody | Policy B now in assemble; completeAction still A (desktop) — document |
| U-05 | Product language still mixes “PF7”, `g2-complete-settlement`, `shield.cash/*` schemas in errors. | Cognitive load / trust erosion | Open (schema freeze) |
| U-06 | Unlock compile ~30s with no progress UX. | Feels hung | Open — log progress |
| U-07 | Vendor tree ~75MB still includes full cashc source + harness; clone heavy for “SDK”. | Onboarding friction | Partially pruned (website/tests/docs) |

### MEDIUM

| ID | Finding | Impact | Status |
|----|---------|--------|--------|
| U-08 | CLI verbs: `create-pool` is npm script, not `shieldkit create-pool`. | Discoverability | Wire into shieldkit.mjs |
| U-09 | No single `shieldkit deposit --pool` verb; standalone e2e is the only full act path. | Act not productized | Open (next CLI) |
| U-10 | Errors from prep/assemble are raw throw messages without `code` for UX mapping. | Hard UI errors | Open |
| U-11 | `PIN_LENS` failure surfaces as unlock-builder throw mid-act after 30s prove. | Late fail | Acceptable if doctor preflight added |
| U-12 | Notes journal directories created empty; transfer/withdraw need history knowledge. | Multi-action UX gap | Open |

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
| G5 | Blank clone → deposit without extra downloads | **NO** (U-01) |
| G6 | README does not lie about G5 | **Partial** |

## Recommended next attacks (not done this pass)

1. Ship `shieldkit-pin-artifacts-v1.tar` release + `npm run fetch-pin-artifacts`
2. `shieldkit deposit|withdraw --pool` wrapping completeAction
3. Preflight `doctor --pool` (tip, fee UTXO, pin lens, unlock root)
4. Progress events on unlock build
5. Strip remaining vendor non-runtime paths

## Red-team score (product UX)

| Axis | Score /5 | Note |
|------|----------|------|
| First-run honesty | 3 | Better than research monorepo; still oversells e2e |
| Verb clarity | 3 | completeAction good; CLI incomplete |
| Key custody story | 4 | Policy B exists |
| Standalone toolchain | 5 | Vendor unlock path proven on Chipnet |
| Create-own-pool | 3 | with-genesis works with pins; not cold-clone |
| Overall | **3.5** | Ship-worthy for expert operators; not consumer onboarding |
