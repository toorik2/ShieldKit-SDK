# UX red-team: GitHub as product landing page

**Date:** 2026-07-25  
**Target:** `toorik2/ShieldKit-SDK` @ `bbf566d` (and local main aligned)  
**Lens:** Adversarial first-time visitor / app-dev. “Does this *feel* and *act* like a product?”  
**Not:** Crypto / protocol soundness.

Evidence: local probes on real CLI/README (this machine).

---

## Executive verdict

| Dimension | Score (0–5) | Note |
|-----------|-------------|------|
| **Tree cleanliness** | **4.5** | Root is product-shaped; best state yet |
| **Landing README clarity** | **4** | Strong pitch + verbs; a few footguns |
| **Time-to-first-success** | **1.5** | No shippable demo profile; install story empty |
| **Honest claims** | **4** | WIP/mainnet messaging good |
| **Onboarding continuity** | **2** | Links to missing lab scripts; demo needs local `.cache` |
| **Package browse UX** | **2.5** | 5 domains good; `prove/` still research-dense |
| **Trust / meta** | **2** | Empty GitHub description; no security contact |

**Overall landing UX: ~3 / 5** — looks like a product; **does not yet deliver a product first win.**

---

## What the landing tree is (good)

```text
README.md · LICENSE · SECURITY.md · package.json · .gitignore
packages/   kit · profile · action · prove · recover
scripts/    shieldkit · run-domain-tests
examples/   demo-profile
docs/       charter · privacy · architecture · UX notes
```

**No** `.github`, `dev/`, freeze root peers, or 25-package sprawl.  
That matches the intended napkin better than any prior revision.

---

## Findings (severity-ordered)

### P0 — No path to “it works” on a clean clone

| ID | Finding | Evidence |
|----|---------|----------|
| **L-01** | **No installable product.** Root `package.json` has **zero dependencies** and is `private: true`. `npm install` installs nothing useful for a consumer. | `package.json` |
| **L-02** | **No demo profile in-repo.** “Success” still needs `.cache/…` (gitignored) or a multi-hour init with R1CS/ptau. | `examples/demo-profile/README.md` Option A |
| **L-03** | **README snippet is not copy-pasteable.** Uses bare `profileId, instanceId` → `ReferenceError`. | Adversarial copy of README block |
| **L-04** | **“Quick start” does not produce a transfer.** doctor/help work; deposit fails closed without a full request object + bundle. Correct, but not a demo. | CLI deposit without inputs |

**Impact:** Visitor reads a polished story, clones, and stalls within minutes.

---

### P1 — Broken or misleading onboarding links

| ID | Finding | Evidence |
|----|---------|----------|
| **L-05** | `examples/README.md` points to **deleted** `scripts/golden-path-cycle.mjs`, `shieldkit-smoke.mjs`, `shieldkit-redteam.mjs` | Files not in tree |
| **L-06** | README lists both `npm test` and `run-domain-tests.mjs` — **duplicate** (same suite) | README Install section |
| **L-07** | `init.example.json` fails with raw **LocalSetupError** path noise for unfilled placeholders (OK fail-closed; weak “next step” UX) | CLI init --config example |
| **L-08** | **GitHub About description is empty** | `gh repo view` → `description: ""` |
| **L-09** | **SECURITY.md** says “report privately to maintainers” with **no email / security policy contact** | SECURITY.md |

---

### P1 — Docs tone vs product landing

| ID | Finding | Evidence |
|----|---------|----------|
| **L-10** | `docs/CHARTER.md` still **shield.cash / g0-v3** framing | First lines of CHARTER |
| **L-11** | `docs/BEAUTIFUL_PLAN.md` + `UX_REDTEAM_AUDIT.md` are **internal process** docs on a product shelf (~500 lines combined) | Word counts |
| **L-12** | LICENSE copyright “ShieldKit-SDK contributors” vs product name **ShieldKit** — minor brand split | LICENSE |

---

### P2 — Inside `packages/` browse UX

| ID | Finding | Evidence |
|----|---------|----------|
| **L-13** | **`prove/`** still exposes research surface: `bch/g2-*`, verifier-generator CLIs, corpus, budget tools | `ls packages/prove` |
| **L-14** | Each domain mixes **public `index.mjs`** with many peer implementation files — no `src/` / `dist/` split; experts fine, product browsers noisy | File counts |
| **L-15** | No published npm packages / workspace install story | private monorepo, relative imports only |

---

### P2 — CLI / GitHub chrome

| ID | Finding | Evidence |
|----|---------|----------|
| **L-16** | CLI fail-closed JSON is good; **exit codes** must be checked without piping (probe hygiene). Verbs correctly refuse empty input. | deposit / init probes |
| **L-17** | GitHub **last-commit column** still shows mixed ages (e.g. old messages on some files) — not a tree bug; **still confuses humans** | Prior user reports |
| **L-18** | Repo is **private** — fine for WIP; public launch would need description, topics, maybe homepage | `isPrivate: true` |

---

## Attack journeys (results)

| Journey | Result |
|---------|--------|
| Clone → read README → run doctor | **Pass** — status/WIP clear |
| Clone → copy README JS | **Fail** — `profileId is not defined` (L-03) |
| Clone → `npm install` → use kit | **Stall** — no deps, no published entry (L-01) |
| Clone → demo profile | **Fail** unless local `.cache` exists (L-02) |
| Clone → follow examples/README golden path | **Dead links** (L-05) |
| Clone → deposit | **Honest fail-closed** — good safety, no demo |
| Browse packages/prove | **Research density** (L-13) |

---

## What works (keep)

1. **Root topology** — product-shaped; no Actions/freeze/dev peers.  
2. **Honesty banner** — Unaudited WIP + mainnet caveats consistent (README + CLI + SECURITY).  
3. **Four-verb model** — readable and repeated.  
4. **Fail-closed CLI** — no fake `ok: true` for empty deposit/init.  
5. **Single facade** — `createKit` / five packages story holds.  
6. **Link integrity** for primary README doc links (CHARTER, PRIVACY, kit README).

---

## Recommended fix order (landing only)

1. **P0 demo:** Ship a **tiny fixture profile bundle** under `examples/demo-profile/bundle/` (dev-only, clearly labeled) *or* a one-command download — so `profile-info` + doctor work on clean clone.  
2. **P0 README:** Fix JS sample (`profileId: 'sha256:…'` literals); single test command line.  
3. **P1:** Fix `examples/README.md` dead paths (point only to live scripts).  
4. **P1:** GitHub About description + SECURITY contact.  
5. **P1:** Demote BEAUTIFUL_PLAN / UX audit to “internals” or one short ARCHITECTURE.md.  
6. **P2:** Hide `prove/bch` and generator CLIs under `prove/internal/` or document “advanced.”  
7. **P2:** Optional root `npm` workspace later — not required for private lab kit.

---

## Scorecard vs prior audits

| Era | Landing feel |
|-----|----------------|
| Pre-consolidation (~25 packages) | Research dump |
| After domains + dev/ | Cleaner but dual story |
| **Now (no freeze/dev/Actions)** | **Real product skeleton** |
| Gap to “beautiful product page” | **First-run success + noise inside prove/docs** |

---

## Bottom line

The **GitHub file list** is finally defensible as a product landing.  
The **experience after clone** is still expert-only: no demo artifact, broken example links, unusable copy-paste sample.

Treat the next UX sprint as **“clean clone → doctor green → one offline plan”**, not more folder moves.
