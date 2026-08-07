# UX adversarial red-team audit — ShieldKit

Date: 2026-07-25  
Scope: app-dev / operator **user experience** (not crypto hardness).  
Method: drive real CLI + `createKit` + `init` + docs; assume a competent full-stack dev new to this monorepo.  
Evidence: `/tmp/grok-goal-247c611ab20c/implementer/ux-redteam/`

## Executive summary

Architecture consolidation (domains + `createKit` + ceremony runner) is real.  
**Product UX is not yet a golden path** — several verbs are **documentation stubs that exit 0**, mainnet config is **split-brain**, and discoverability still dumps users into research-shaped modules.

**Verdict:** Not shippable as “30–60 min clean machine success” without a guided init/act path. Safety gates on mainnet *broadcast* are mostly good; **trust messaging is inconsistent**.

---

## Persona probes

| Persona | Intended path | Observed |
|---------|---------------|----------|
| App-dev, own pool, Chipnet | README → doctor → init → deposit | doctor works; **init/deposit/transfer/withdraw do not perform work** (JSON how-to, exit 0) |
| Operator, ceremony | `init --mode ceremony-production` | CLI does not run ceremony; points at `profile.init` API with no sample input file |
| Careless mainnet | config-check / createKit mainnet | Broadcast refuse OK; **createProfileCoordinates hard-refuses any non-chipnet** before ceremony gates matter |
| Lost importer | `@shieldkit/kit` | Works as relative path; **npm package not publishable** (private, root name still `shield-cash-protocol`) |

---

## Findings (severity-ordered)

### P0 — False success / non-operational verbs

**IDs:** UX-01, UX-02, UX-03

| ID | Finding | Evidence |
|----|---------|----------|
| **UX-01** | `shieldkit deposit\|transfer\|withdraw\|recover\|init` return `"ok": true` without doing the verb | CLI probes: exit 0 + JSON guidance only |
| **UX-02** | No CLI way to run `profile.init` (no flags for r1cs/ptau/entropy/bundle out) | `init` only prints API string |
| **UX-03** | User who follows README four-verb story cannot complete a cycle from CLI alone | README table vs CLI behavior mismatch |

**Impact:** High — looks green, builds false confidence, wastes hours.  
**Fix direction:** Either implement real subcommands (fail closed until inputs present) or rename stubs to `help-init` / print `"ok": false, "implemented": false` and exit ≠ 0.

---

### P0 — Mainnet / network split-brain

**IDs:** UX-04, UX-05

| ID | Finding | Evidence |
|----|---------|----------|
| **UX-04** | `network.mjs` allows mainnet + ceremony + ack; `browser.mjs` `createProfileCoordinates` **hardcodes `network === 'chipnet'`** | createKit mainnet → `UNSUPPORTED_NETWORK: only Chipnet is authorized by this SDK` |
| **UX-05** | Docs/SECURITY claim mainnet-ready-by-config; kit cannot load a mainnet profile identity | SECURITY.md + README vs live error |

**Impact:** Critical honesty/UX — product claims a path that the primary facade cannot take.  
**Fix direction:** Allow `chipnet|mainnet` in `createProfileCoordinates` (still refuse broadcast / development-only on mainnet via existing gates). Align tests.

---

### P1 — Discoverability / cognitive load

**IDs:** UX-06 … UX-11

| ID | Finding | Evidence |
|----|---------|----------|
| **UX-06** | Zero domain package READMEs (`kit/profile/action/prove/recover`) | `NO` for all five |
| **UX-07** | README “Init modes” still lists raw module paths, not `init({mode})` as primary | README §Init modes |
| **UX-08** | `createKit` has no `deposit`/`transfer`/`withdraw` methods — only prep/planning/recovery | methods list from live bundle |
| **UX-09** | Live act path still points at `scripts/golden-path-cycle.mjs` (large research-style runner) | deposit JSON `live` field |
| **UX-10** | `docs/HUMAN_REPORT.md` still documents `app-kit`, old package map | grep hits |
| **UX-11** | Root package name `shield-cash-protocol`; product brand ShieldKit / `@shieldkit/*` | package.json |

**Impact:** High onboarding friction; dual mental models (kit vs golden-path vs profile files).

---

### P1 — Error UX / CLI polish

**IDs:** UX-12 … UX-16

| ID | Finding | Evidence |
|----|---------|----------|
| **UX-12** | Unknown command → full help, **no “unknown: foobar”**, exit 64 but message not explicit | `shieldkit foobar` |
| **UX-13** | `profile-info` bad path dumps **stack trace** to stderr | BundleValidationError stack |
| **UX-14** | `doctor --network testnet` uncaught exception + stack (not JSON like config-check) | AppKitNetworkError stack |
| **UX-15** | Dual flags `--mode` and `--setup-mode`; with both set, **setup-mode wins** (`arg('setup-mode', arg('mode', …))`) — silent, surprising | both orderings → `development-only` when setup-mode is development-only |
| **UX-16** | `doctor` on mainnet+development reports **two different failures** (`gate` vs `broadcastGate` MAINNET_ACK) — noisy priority | doctor mainnet probe |

**Impact:** Medium — users mis-debug; safety still holds if they read carefully.

---

### P2 — Docs / process honesty

**IDs:** UX-17 … UX-20

| ID | Finding | Evidence |
|----|---------|----------|
| **UX-17** | README `npm test` implies product tests; script is **policy check only** | `scripts.test = npm run check` |
| **UX-18** | Domain tests are separate (`scripts/run-domain-tests.mjs`) — undocumented in README | package.json freeze |
| **UX-19** | SECURITY still points at superseded `DEVKIT_POLISH_PLAN.md` | SECURITY.md |
| **UX-20** | No pinned demo profile download / path in README — must hunt `.cache` or rebuild | createKit needs profileId/instanceId |

**Impact:** Medium trust + setup time.

---

### P2 — Residual research surface in “product” tree

**IDs:** UX-21, UX-22

| ID | Finding | Evidence |
|----|---------|----------|
| **UX-21** | `packages/profile` exposes many peer files (`bridge`, `replace`, CLIs) equal weight to `init`/`load` | directory listing |
| **UX-22** | schemas/errors still `shield.cash/*` in user-visible qualification strings | kit/browser schemas |

**Impact:** Low–medium brand/confusion; not functional blockers.

---

## What works well (keep)

| Area | Note |
|------|------|
| Honesty banner | README + doctor honesty block clear |
| Mainnet **broadcast** refuse | config-check exit 2, clear codes |
| `createKit` typed errors | `BUNDLE_REQUIRED`, `NETWORK_MISMATCH`, `INVALID_CONFIG` |
| Domain topology | 6 peers; legacy packages gone (import fails correctly) |
| Ceremony existence | real runner + load test offline (not CLI-exposed) |
| Single facade exports | no `createAppKit` / `createDesktopWalletSdk` on kit index |

---

## Attack-style user journeys (results)

1. **“Just deposit”** — runs `shieldkit deposit` → **false OK** (UX-01).  
2. **“Mainnet with ceremony flag”** — config-check passes with ack; createKit with mainnet coords → **Chipnet hard deny** (UX-04).  
3. **“Wrong network name”** — doctor crashes with stack (UX-14).  
4. **“Import app-kit like HUMAN_REPORT says”** — module not found (doc rot UX-10).  
5. **“npm test before PR”** — green without domain/ceremony tests (UX-17).

---

## Recommended fix order (UX-only, no scope creep)

1. **P0:** Make CLI verbs fail closed unless implemented; or implement minimal `init`/`profile-info`/`deposit-plan` that call real APIs.  
2. **P0:** Lift Chipnet-only lock in `createProfileCoordinates`; keep broadcast + development-on-mainnet gates.  
3. **P1:** One package README each domain (5 lines); README primary path = `init` + `createKit` methods table.  
4. **P1:** JSON error envelope for all CLI failures (no raw stacks); explicit unknown-command.  
5. **P1:** Collapse `--mode` / `--setup-mode` to one flag.  
6. **P2:** Supersede HUMAN_REPORT / SECURITY polish pointers; document `run-domain-tests.mjs`.  
7. **P2:** Optional: ship pinned Chipnet demo profile path for `profile-info` + createKit smoke.

---

## Scorecard (user success)

| Criterion | Score (0–5) |
|-----------|-------------|
| First 5 minutes orientation | 3 |
| Can init without reading research | 1 |
| Can deposit via documented path | 1 |
| Error messages help recovery | 2 |
| Honesty of claims vs behavior | 2 (mainnet split-brain hurts) |
| Safety (no silent mainnet send) | 4 |
| Brand/naming consistency | 2 |

**Overall UX readiness (pre-fix):** **1.5 / 5** for “beautiful app-dev kit success moment”; **3.5 / 5** for expert agents who already know the packages.

---

## Remediation status (2026-07-25 follow-up)

| ID | Status |
|----|--------|
| UX-01–03 false success verbs | **Fixed** — fail-closed `ok:false` + nonzero exit; act/init require real inputs |
| UX-04–05 chipnet hard lock | **Fixed** — `chipnet\|mainnet` in coordinates + loader; mainnet WIP warnings |
| UX-06 domain READMEs | **Fixed** |
| UX-12–15 CLI errors / dual mode | **Fixed** — JSON errors; single `--mode` |
| UX-17 npm test honesty | **Fixed** in README (policy vs `run-domain-tests.mjs`) |
| UX-20 demo profile | **Fixed** — `examples/demo-profile/` |

Remaining longer-term: full CLI live prove/settle (still multi-step by design); HUMAN_REPORT deeper rewrite.

---

## Artifacts

- `cli-probes.txt` — help, verbs, mainnet gates, bad paths  
- `lib-probes-run.txt` / `lib-probes.txt` — createKit/init exports  
- `docs-consistency.txt` — flags, HUMAN_REPORT rot  

All under implementer scratch `ux-redteam/`.
