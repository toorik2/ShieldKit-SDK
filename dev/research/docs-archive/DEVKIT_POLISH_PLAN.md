# Plan: Beautiful, narrow app-dev kit (no scope creep)

> **SUPERSEDED** by [`docs/BEAUTIFUL_PLAN.md`](BEAUTIFUL_PLAN.md) (ceremony as first-class domain topology). Kept for history only.

Status: superseded  
Audience: **app developers** who run **their own** development-only shielded pool instance and own frontend — not wallet vendors integrating a shared production pool, not ceremony operators.

## 1. Product thesis (one sentence)

Give an app developer a **clean, honest, offline-first toolkit** to stand up a **development-only** Chipnet shielded pool instance, perform deposit / transfer / withdraw with **local** proving, and wire their **own** UI/backend — without learning the full PF7 research stack.

## 2. Explicit non-goals (scope freeze)

Do **not** add in this track:

| Out | Why |
|-----|-----|
| High-volume battery minima, fuzz campaigns | Already de-scoped; 1–2 txs per class enough |
| Multi-note / multi-hop product features | Protocol V1 is one-note; no expansion here |
| Ceremony / production profiles | Stay development-only forever until a separate track |
| Hosted indexer, relayer, prover, RPC, frontend | App owns those; kit stays offline/local |
| Wallet keystore, seed UX, mobile app shell | App owns product UX |
| Browser proving as required path | Desktop local prove only for the golden path |
| New circuits, VK, PF7 topology changes | Frozen profile; polish only |
| Mainnet volume / funding in polish track | Config readiness only; no mainnet broadcast required |
| “Generic ZK framework” | Charter invariant |

If a task is not on the golden path or the tidy list below, **reject it**.

## 3. Persona & success moment

**Persona:** Full-stack app dev (Node + optional simple backend). Can run BCH Chipnet RPC (or use a public Chipnet node they trust as *data only*). Builds their own frontend.

**Success moment (30–60 min on a clean machine after docs):**

1. Clone repo, install, read one README path.  
2. Generate **development-only** profile + genesis plan (or load a pinned demo profile).  
3. Fund a fee wallet they control.  
4. Run **one** deposit, **one** transfer, **one** withdrawal on Chipnet via a single CLI or thin SDK surface.  
5. Recover notes from raw history they supply.  
6. See exact sizes, fees, txids, and explorer links — and a red banner: **development-only, not production privacy**.

That is the whole product bar for this plan.

## 4. Charter tension (handle once, narrowly)

G0 register **D-002 / D-003** currently prioritize shared-pool wallet integration and de-prioritize “deploy your own pool.”

This polish track **repositions DX** toward: *app-owned development instance*.

- **Do not** silently rewrite the whole charter.  
- **Do** add one short CHANGE_CONTROL / OPEN note:  
  - *Primary DX for this kit: app-owned development-only instance + own frontend.*  
  - *Shared production pools / ceremony remain a later track.*  
- Keep protocol authority rules (no post-genesis admin, local secrets, optional services untrusted).

## 5. What “clean” means (only these layers)

```
┌─────────────────────────────────────────┐
│  App (their FE + optional backend)      │  ← not our code
├─────────────────────────────────────────┤
│  @shieldkit/app-kit  (thin facade)      │  ← NEW thin layer OR slim packages/sdk
│  profile load · notes · plan · prove ·  │
│  prep/settle · recover · measurements   │
├─────────────────────────────────────────┤
│  Existing packages (unchanged contracts)│  ← prep, settlement, recovery, core…
├─────────────────────────────────────────┤
│  Local tools: snarkjs, PF7 dens-drop    │  ← document + pin; don’t redesign
├─────────────────────────────────────────┤
│  BCHN Chipnet (their or public RPC)     │  ← they supply chain I/O
└─────────────────────────────────────────┘
```

**Rule:** Prefer **delete, rename, document, re-export** over new subsystems. One facade, not a platform.

## 6. Work packages (ordered, small)

### P0 — Honesty & identity (1–2 days)

1. **Root README rewrite** (replace G0-era “nothing exists” shield.cash text):  
   - What it is / isn’t  
   - Development-only banner  
   - Golden path link  
   - Explorer example tx  
2. **Rename surface for humans:** ShieldKit-SDK in titles; leave on-chain / domain strings if changing them is protocol-sensitive (document as legacy).  
3. **LICENSE** (choose and add — no public polish without this).  
4. **SECURITY.md:** no mainnet; report issues; never paste seeds.  
5. **Scrub checklist:** confirm HANDOVER / `.cache` / WIFs / battery state never in git; fix any absolute machine paths in committed docs.

### P1 — One golden path (3–5 days)

Deliver **one** supported flow, documented end-to-end:

| Step | Mechanism (prefer existing) |
|------|-----------------------------|
| Install | Root `npm` workspaces or documented per-package install — pick **one** and stick to it |
| Profile | Document using existing `local-setup` + `profile-builder` **or** ship a **pinned Chipnet demo profile** as a downloadable artifact (not rebuild every time) |
| Chain I/O | **App-supplied** RPC callbacks or “you pass raw txs / gettxout JSON” — kit does **not** own a node client product |
| Actions | Thin CLI: `shieldkit demo deposit|transfer|withdraw` calling shipped packages (extract from battery, **no** volume logic) |
| Prove | Desktop snarkjs + documented PF7 dens-drop command (pin worktree/commit or package script) |
| Recover | One command using `packages/recovery` on history the user provides |
| Output | txid, wire, fee, unlock max, explorer URL template |

**Hard limit:** Do not build a second parallel stack. Lift from `run-full-cycle.mjs` → `scripts/demo/` or `packages/app-kit`, delete duplication later.

### P2 — Facade cleanliness (2–4 days)

1. **Single package** `@shieldkit/app-kit` (name TBD) that only:  
   - loads authenticated profile  
   - plans prep / settlement inputs  
   - accepts proof + PF7 unlocks from local tools  
   - returns measurements  
   - recovery helpers  
2. **Does not:** open sockets, store keys, broadcast (unless optional tiny helper that takes a `broadcast(hex)` callback).  
3. **Deprecate-by-docs** deep imports for the golden path (“advanced / internal”).  
4. Keep browser/android packages as **optional experimental**, not in the main README path.

### P3 — Repo hygiene (1–2 days)

1. Move live-battery out of mental “product core”: either `examples/live-battery/` or archive under `dev/research/`; no secrets.  
2. `.gitignore` already covers secrets/cache — audit.  
3. Root `npm test` green on clean clone (CI yaml if missing).  
4. Package READMEs: one-paragraph purpose + “use app-kit for apps” pointer; no novel APIs.  
5. Kill or quarantine dead “nothing exists yet” docs.

### P4 — Optional 1–2 tx smokes (only if cheap)

- 1× deposit-only→withdraw (`transferHops: 0`) if golden path is already green.  
- Skip multi-hop, adversarial volume, recovery-every-N.

## 7. Definition of done (“beautiful”)

| Check | Pass condition |
|-------|----------------|
| Story | README matches reality; development-only unavoidable |
| Path | Clean machine can complete golden path without reading dev/research/ or HANDOVER |
| Surface | App-kit + CLI is the default; internals not required for demo |
| Scope | No new protocol features; no hosted services |
| Hygiene | No secrets in tree; license present; tests green |
| Honesty | Claims match development-only Chipnet only |

## 8. Anti-creep rules (process)

1. **One golden path** — reject second tutorials until the first is boringly solid.  
2. **No new package** unless it only re-exports/simplifies existing ones.  
3. **No new network dependency** in the kit core.  
4. **Time-box dens-drop:** document + wrap; do not rewrite C7 in this track.  
5. **Charter changes** only the D-002/D-003 DX note — not a redesign of kill gates.  
6. If a PR does not make the success moment clearer or the tree cleaner, **don’t merge it**.

## 9. Suggested sequencing

```
Week 1:  P0 honesty + license + scrub
Week 1–2: P1 golden path CLI (extract from battery)
Week 2:  P2 thin app-kit facade
Week 2–3: P3 hygiene + CI green + README polish
Optional: P4 single dep-wd smoke
```

Stop when §7 is true — not when “more features would be nice.”

## 10. Out of this plan (park explicitly)

- Ceremony runner product  
- Production shared pool operations  
- Multi-note, multi-asset, L2  
- Full wallet  
- Public production anonymity-set claims  
- Android/browser proving qualification  

---

## Summary

| Do | Don’t |
|----|--------|
| Clean docs, license, one golden path, thin facade | Volume batteries, new crypto, hosted infra |
| Serve **app dev with own pool + own FE** | Serve full wallet ecosystem |
| Make existing Chipnet truth easy to run | Invent a second architecture |
| Development-only, loudly | Fake production readiness |
