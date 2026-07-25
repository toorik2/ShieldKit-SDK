# Cleanup audit — cleaner / easier / simpler

**Date:** 2026-07-25  
**Scope:** Product repo after playground framing + freeze removal.  
**Lens:** GitHub landing + creator path + mental load (not crypto).

---

## Snapshot (already good)

| Area | State |
|------|--------|
| Root | Thin: packages · scripts · examples · docs · landing files |
| Story | Create your pool; playground = example only |
| CLI | Fail-closed; `playground` sugar |
| Tests | `npm test` = domain suite |

Further cleanup is **polish inside packages/docs**, not more root churn.

---

## Ranked opportunities

### P0 — Product clarity (high impact, small work)

| ID | Opportunity | Why |
|----|-------------|-----|
| **C-01** | **Publish / pin playground bundle** (release asset + sha256), not only env + `.cache` | Example path still fails on clean clone |
| **C-02** | **Fix README JS sample** if still using undefined vars; prefer full literals | Copy-paste trust |
| **C-03** | **Demote or delete dual UX audit docs** (`UX_REDTEAM_AUDIT` + `UX_LANDING_REDTEAM`) → one short `docs/CLEANUP` or archive | Process noise on product shelf |
| **C-04** | **Retitle CHARTER** away from “shield.cash / g0-v3” in first line | Brand/product mismatch |
| **C-05** | **GitHub About description** (one sentence product story) | Empty description today |

### P1 — Package surface simplicity

| ID | Opportunity | Why |
|----|-------------|-----|
| **C-06** | **`prove/` hide lab tools** — move `verifier-generator*`, `corpus`, `budget*` under `prove/lab/` or `prove/internal/` | Product import is mainly `authority` + `groth16` + `unlock` |
| **C-07** | **`prove/bch/g2-*` rename or nest** as `prove/covenants/` without g2- names in browse path | Gate archaeology in product tree |
| **C-08** | **`profile/` public index** — export only `init`, `loadInstance`, `loadProfile`, genesis; leave bridge/replace/compare as non-exported files | `index.mjs` still exposes ceremony/setup internals |
| **C-09** | **Collapse kit dual names** — pick `planAction` *or* `planCompletePreparation` in docs; keep one alias | Cognitive load |
| **C-10** | **`AppKitNetworkError` → `KitNetworkError`** | Dead “AppKit” brand |

### P2 — Docs / naming / hygiene

| ID | Opportunity | Why |
|----|-------------|-----|
| **C-11** | **BEAUTIFUL_PLAN** → short `ARCHITECTURE.md` (1–2 pages); archive rest | 330 lines of transition plan |
| **C-12** | **LICENSE** “ShieldKit-SDK contributors” → “ShieldKit” | Brand |
| **C-13** | **SECURITY** contact channel (email or GH security advisories) | Trust |
| **C-14** | **`.gitignore` node_modules** already global; packages still have local `node_modules/` on disk (not committed) — document `npm install` per package or one workspace later | Install story unclear |
| **C-15** | **Root has no workspace install** — each package pulls own deps; optional single root install later | Harder for new contributors |

### P3 — Explicit non-goals (don’t “clean” yet)

| Leave alone | Why |
|-------------|-----|
| Splitting monorepo into many npm packages | Premature without publish plan |
| Moving everything into `src/` overnight | High churn, low user value |
| Deleting prove/bch without import rewrite | Breaks authority |
| Hosting zkey in git | Size / clone UX |

---

## Mental model targets (simpler)

**Today (correct, a bit wordy):**

```text
try example → create your pool → operate
```

**Even simpler landing:**

```text
1. Create your pool   (primary CTA)
2. Optional: try Chipnet example first
```

Put **create-your-pool** first everywhere (README already almost does; reinforce CLI help order — already “product first” after last framing fix).

**Package story for visitors:**

```text
kit       → only import you need for an app
profile   → init + loadInstance
action    → prep/settle (advanced)
prove     → local prove (advanced)
recover   → notes (advanced)
```

Document: **start at `kit` + `profile`**.

---

## Concrete “beauty” wins if we do one sprint

| Priority | Action | Effort |
|----------|--------|--------|
| 1 | Playground bundle distribution story (download/LFS/release) | M |
| 2 | Nest prove lab files + covenants | S–M |
| 3 | Slim docs to ARCHITECTURE + PLAYGROUND + CHARTER + PRIVACY | S |
| 4 | CHARTER title + LICENSE brand + GH description | S |
| 5 | profile/kit export hygiene | S |

---

## What’s *not* worth cleaning right now

- More root folder renames  
- Re-litigating G0 (already gone)  
- Another full red-team doc (this file is enough; delete old UX audits when acting)

---

## Bottom line

**Structure is fine.** Remaining mess is:

1. **Example still needs offline bundle** (product demo incomplete)  
2. **`prove/` (and some of `profile/`) still look like research**  
3. **Docs shelf has process archaeology** (CHARTER brand, long plan/audit files)

Simplest narrative:

> Create your pool with this kit. Optionally play on our Chipnet example first. Start at `packages/kit`.
