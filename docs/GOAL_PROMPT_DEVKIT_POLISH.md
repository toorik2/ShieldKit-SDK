# Goal prompt: App-dev kit polish → mainnet-ready config → red-team testing

Paste as one message (or `/goal` with this body):

```text
/goal Polish ShieldKit-SDK into a clean, narrow **app-developer kit** for spinning up an **own** shielded pool instance + own frontend; make the stack **mainnet-ready by configuration** (not ceremony); then switch to **testing mode** and run focused adversarial / red-team drills. Prefer delete/rename/document over new subsystems. No scope creep.

## Naming
Product/repo = **ShieldKit-SDK**. `shield.cash` = sunsetting brand debt only — do not reintroduce product branding. Frozen g0-v3 binds; DX may note app-owned instances via CHANGE_CONTROL (do not reopen full G0).

## Binding
AGENTS.md, policy/g0-lock.json (g0-v3), docs/CHARTER.md, docs/KILL_GATES.md, docs/PRIVACY.md, docs/CHANGE_CONTROL.md, docs/DEVKIT_POLISH_PLAN.md. Never commit HANDOVER.md, keys, WIFs, seeds, `.grok/` secrets, or battery run state. Worktrees only under `.worktrees/`. Mainnet **broadcast** requires explicit user authorization + explicit CLI flag; default network remains Chipnet.

## Persona (primary)
App developer who:
- runs **their own** pool instance (development-only profile today);
- owns **frontend + optional backend**;
- supplies chain I/O (RPC / raw txs) themselves;
- wants deposit / transfer / withdraw + recovery without learning PF7 research internals.

Not: full wallet vendor platform, ceremony operator, hosted privacy SaaS.

## Invariants (do not weaken)
Local secrets + local proving; no hosted authority; fee+change @ **1 sat/B**; no pool fee subsidy; no post-genesis admin/pause/upgrade; typed verifier-profile bundles; local setup = **development-only** forever; ceremony → **new profile + new genesis only** (no hot-swap). Verifier = `bn254-onetx-pf7-sub62-r1` (7 PF7). Settlement = 10 inputs. Unlock ≤10k B; complete tx ≤59k B. No placeholders / OP_TRUE / projections-as-measurements.

## Mainnet-ready (narrow meaning)
**Ready** = same code path works for mainnet **when** network + profile + addresses are configured — not “fake a ceremony” or “broadcast mainnet now.”

1. Kill **Chipnet hardcodes** in the golden path / app-kit / demo CLI (network id, explorers, address prefixes, demo profile paths).
2. Single config surface, e.g. `network: chipnet | mainnet` (+ profile bundle path, RPC/broadcast callbacks, fee wallet).
3. Mainnet **refuse-by-default**: require `--i-understand-mainnet` (or equivalent) before any mainnet `sendraw`; refuse development-only profiles on mainnet unless `--allow-development-on-mainnet` (lab only — never document as production).
4. Document production path honestly: mainnet needs a **ceremony-backed profile** + new genesis; development-only setup is not production privacy.
5. Do **not** add mainnet volume batteries or require mainnet funds in this goal unless user explicitly funds and authorizes.

## Non-goals (reject if proposed)
High-volume batteries (≥20/≥10/≥10); multi-note / multi-hop product; ceremony runner product; indexer/relayer/prover service; wallet keystore/seed UX shell; browser/Android proving as required path; new circuits/VK/PF7 topology; generic ZK framework; rewriting densFuel C7; calendar G1–G6 close theater.

## Phase A — Polish (ship first)
Follow docs/DEVKIT_POLISH_PLAN.md; stop when §7 there is true.

### A0 — Honesty
- Rewrite root README for ShieldKit-SDK reality + development-only banner + golden path.
- LICENSE + SECURITY.md.
- Scrub: no secrets/paths in commits; HANDOVER/.cache/battery state stay private.

### A1 — Golden path
- One CLI (or thin entry): load profile → prep/prove/PF7/settle deposit, transfer, withdraw (1 each).
- Extract from battery scripts; **no** volume loop, no research-only worktree hardcodes in the public path (pin tool versions/docs instead).
- App supplies: keys (local), RPC/broadcast, fee UTXOs.
- Output: txids, wire, fee, max unlock, explorer URL template for selected network.

### A2 — Thin facade
- One package (e.g. app-kit): profile load, plan, attach proof/PF7, measurements, recovery helpers.
- No sockets, no key custody; optional `broadcast(hex)` callback only.
- Deep packages remain internal/advanced.

### A3 — Hygiene
- Demo/battery not presented as core product; examples/ or research/ only.
- Root `npm test` green on clean clone; CI if missing.
- Short CHANGE_CONTROL note: primary DX = app-owned instance + own FE.

## Phase B — Testing mode (only after A done)
Switch mindset: break it, don’t expand it. Prefer **1–2** cases per class unless a class is free/fast.

1. **Happy smoke:** 1 full dep→xfer→wd on Chipnet via golden path (not volume).
2. **Optional cheap:** 1 deposit→withdraw (transferHops=0) if already wired.
3. **Adversarial / red-team (must reject, never broadcast bad):**
   - Flip PF7 unlock / packet / fee sig / state commitment bytes.
   - Cross-action packet/proof mismatch; wrong profile/instance/category.
   - Oversized unlock/tx if produced → local gate fail.
   - Mainnet-safety: attempt mainnet path without flag → hard refuse; development-only profile on mainnet without override → refuse.
4. **Recovery:** one seed+chain recovery from BCHN-sourced history (already exists — re-verify via golden path docs).
5. **Fix loop:** any honest-path fail → repro + shipped fix + **1–2** green re-runs (not ≥3 volume).
6. Evidence: short REPORT under evidence/ (txids, reject logs, config surface) — no secrets.

## Phase C — Close
- Evidence index + npm test green.
- README claims match reality (dev-only Chipnet default; mainnet = config + ceremony profile).
- Honest OPEN rows only where truly open.

## Execution style
Root agent = integrator. Prefer existing packages; delete dead docs. Subagents for disjoint tidy/test. Desktop proving only for live path. Zero-conf Chipnet when testing live. Cold floor ≥95 BCH if using project treasury. Continue until Phase A complete **and** Phase B red-team minima done, or true external blocker (document exact handoff).

## Resume checklist
1. Read docs/DEVKIT_POLISH_PLAN.md + this prompt.
2. P0 README/license/scrub first — no facade until honesty lands.
3. Golden path CLI from battery extraction.
4. Mainnet config + refuse-by-default gates.
5. Only then Phase B red-team.
```

## Notes for humans

- **Mainnet-ready ≠ mainnet-live.** Code/config must not be Chipnet-only; production still needs a ceremony profile.
- **Volume is out.** Red-team is quality, not count.
- Detail plan: [DEVKIT_POLISH_PLAN.md](./DEVKIT_POLISH_PLAN.md).
