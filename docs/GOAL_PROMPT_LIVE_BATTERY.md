# Live Chipnet finalize + extensive battery goal

Paste as one message (or `/goal` with this body):

```text
/goal Finalize the open ShieldKit-SDK Chipnet single-cycle E2E, then run an extensive live Chipnet interaction battery against the real pool: high-volume deposit / one-note transfer / withdrawal cycles, concurrent zero-conf mempool stress, adversarial reject drills, and recovery batteries. Analyse every failure, fix root causes in shipped code/profile tooling, re-prove/re-broadcast, and leave a durable evidence ledger. Desktop/local proving only. Browser and Android out of scope.

## Naming
Product/repo = **ShieldKit-SDK**. `shield.cash` is sunsetting — legacy strings are identity debt only; do not reintroduce branding. Frozen g0-v3 still binds; rename ≠ reopen G0 without CHANGE_CONTROL.md.

## Binding
AGENTS.md, policy/g0-lock.json (g0-v3), docs/CHARTER.md, docs/KILL_GATES.md, docs/PRIVACY.md, docs/BUILD_PLAN.md, docs/CHANGE_CONTROL.md. Sibling archives read-only without provenance. Mainnet unauthorized. Never commit HANDOVER.md, keys, WIFs, seeds, or `.grok/` secrets. Worktrees only under repo `.worktrees/`. Prefer `isolation:none` for subagents; if worktree needed: `git worktree add .worktrees/<label> <ref>` inside this repo only.

## Invariants
Wallet-first; local secrets/proving; no hosted authority; fee + change @ **1 sat/B**; no pool subsidy; no post-genesis admin/pause/upgrade; typed verifier-profile bundles; local setup = development-only forever; ceremony replacement = new profile + new genesis only. Verifier = exact `bn254-onetx-pf7-sub62-r1` (7 PF7 inputs). Settlement = 10 inputs (PF7 0–6, binding 7, state 8, fee 9). Unlock ≤10k B; complete tx ≤59k B; no ~82k generic fallback; no fabricated % headroom.

## Ops facts (load from project memory; do not re-discover)
- **BCHN v29 Chipnet node:** SSH `layer1-node` / `node.layer1.cash`.
  `ssh -o BatchMode=yes layer1-node 'sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf <cmd>'`
  Do not copy config/cookie/RPC password/SSH keys into repo or evidence.
- **Zero-conf posture (mandatory):** Do **not** wait for block confirmations. Sufficient to proceed: `testmempoolaccept` allowed + `sendrawtransaction` success + mempool/`gettxout` visibility. Child may spend parent still in mempool.
- **libauth outpoint order:** Use **display-order** txids (RPC/explorer), not internal reverse-byte/LE, when selecting UTXOs and building spends.
- **Cold wallet (treasury):** `bchtest:qpk2qu5l5zsd4z8l2z95syl3d6gzmn997gyqtl8w9v` — top-ups + change-to-cold. Keys in local project memory / HANDOVER / `.codex-artifacts/chipnet-wallet-019f8ed4/` only (never git). Keep cold ≥ **95 BCH** unless user overrides.
- **Hot wallet (ops):** `bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv` — genesis/prep/settlement fees. Same secret locations.
- **Unlock length stabilize:** densFuel-DROP targets genesis=7600, terminal=9350 (`C7_UNLOCK_LENGTH_STABILIZE` on; worktree `build.ts`). Exec pins: `[8177,6654,7066,7066,8393,7600,9350]`.
- **Active live profile (development-only):**
  profileId `sha256:79782441a9d56f7d8199d9812ba566daddad63e20142fc9e7d2a33c7a66e5bf7`
  instanceId `sha256:d96968b889dfdcfd65f0e89953d94a2ac2f0ca60c03bfa23867ce4293b8bc1aa`
  category `c54c3bfee893dda33a0a8b1f0e1408aa95e0b0bfb31bb9a057ffeb085b3bdbcc`
  bundle `.cache/profile-build-live/profile-bundle`
  PF7 set `.cache/pf7-verifier-set-stabilize/`
- **Witness seed (live single-cycle):** `42` repeated 32 bytes (hex `42`×32). Battery may use deterministic per-cycle seeds derived from `run-id || cycle` but record each seed hash in the ledger (never commit raw seeds if they differ from test constants).

## Already on Chipnet (resume; do not redo unless broken)
| Step | txid |
|------|------|
| Category consolidate (vout0) | `c54c3bfee893dda33a0a8b1f0e1408aa95e0b0bfb31bb9a057ffeb085b3bdbcc` |
| Genesis (state NFT) | `980f075fdc3bc807675fbcd31454e5108765715e7bb30a6adc7a3af27d1004a5` |
| Deposit prep | `9e40d9f1e031ced21f9f52516831027dafd6191013e5fde27162ec533570f69f` |
| Deposit settlement (0.1 BCH note) | `0d7cf1cefb38ed1850d33b6c4b0edb905390e8f08f9e785fa93397b9c6708944` |
| Cold→hot top-up 0.02 BCH | `3ef8c67760be9f694bd5c152ff2446ae443850d4f4732cbab321abd399fa4f71` |
| Transfer prep | `b53e34ecf191d221c904892926fa858cdfaf2d43fd043decfe07f22ebef69064` |
| Transfer settlement (libauth 10/10, wire 56964) | `3f6f164b63f80d07fd248205e9ff2ede8dff0d8e7327781046a5558d29d5fb6c` |
| Cold→hot top-up2 0.02 BCH | `60d84cc481759f7dd2cdbd5ee9164b9c68cd8d56fd10809de7ceb1c8a4ed22be` |

**Offline staged (not yet fully closed on-chain):**
- Artifacts: `.cache/live-chipnet-e2e/` — deposit/transfer/withdrawal packet+proof+public+adapter+plan all present.
- Scratch (if still live): `/tmp/grok-goal-08db704b1f2c/implementer/` — transfer settlement hex/meta; `phase-a/withdrawal-prep.hex` + meta with planned prepTxid `c9b3b94e85593b4f7f387130a58eadd3d88928c49f01a0c437d286750fd6d130` funded from TOPUP2; withdrawal plan digest `ac017b36…`, state tip = transfer settlement, withdraw lock = hot p2pkh.
- **State tip for withdrawal settlement:** transfer settlement `3f6f164b…` vout0 (state carrier).
- If scratch wiped: rebuild prep from TOPUP2/hot UTXOs + `.cache/live-chipnet-e2e/withdrawal.*` + transfer plan digests; never invent txids.

## Phase A — Finish the open single-cycle E2E (blocking; do first)
Goal: one complete live path deposit→transfer→withdrawal→recovery with evidence. Deposit+transfer already live.

1. **Verify tip before spend:** On `layer1-node`, confirm transfer settlement + TOPUP2 still usable (`gettxout` / mempool). Rescan hot+cold balances. If transfer state spent elsewhere, recover tip from chain and abort re-broadcast of stale prep.
2. **Withdrawal prep broadcast:** If planned prep not yet in mempool/chain, `testmempoolaccept` → `sendrawtransaction` withdrawal prep (from TOPUP2 or current hot fee UTXO; change-to-cold). Record prep txid.
3. **Withdrawal PF7 dens-drop:** Against live withdrawal adapter/packet + prep settlement outpoints; pins `[8177,6654,7066,7066,8393,7600,9350]`; max unlock ≤10k; no oscillation. Use stabilize worktree build path already proven for deposit/transfer.
4. **Withdrawal settlement:** Assemble complete G2 settlement (10 inputs) spending transfer state outpoint + PF7 carriers + binding + fee; libauth 10/10 + classify VM; wire ≤59k; fee 1 sat/B; `testmempoolaccept` → `sendrawtransaction`. Fix any reject before recovery.
5. **Recovery:** From raw history only (BCHN `getrawtransaction` + ordered mempool/block extracts): decrypt notes for this profile/instance, rebuild spendable state, exercise reorg-rollback path and provider-absent path if packages support them. Evidence with real txids only.
6. **Close single-cycle ledger:** `evidence/G2/live-chipnet-e2e-v1/` (or next free slot): full txid table, raw hex or hashes of raw, mempoolaccept JSON, wire sizes, max unlock lengths, proof/VK/adapter SHA-256, profile/instance/category, hot/cold balance snapshots. **No keys/WIFs/seeds in evidence.**

Phase A exit criteria: withdrawal settlement accepted on Chipnet + recovery evidence row green + ledger written.

## Phase B — Extensive live battery (after A is green)
Run a high-volume Chipnet campaign against the **same frozen live profile/instance** unless a kill-gate forces new profile+genesis (then document CHANGE_CONTROL / new instance + new category). Prefer automation: scripts under `.cache/live-battery/scripts/` (or `scripts/live-battery/`) calling shipped packages only (`preparation-transaction`, `g2-complete-assembler`, `fresh-witness-inputs`, `snarkjs-adapter`, PF7 worktree build, recovery).

**Run ledger (mandatory):** `.cache/live-battery/<run-id>/ledger.jsonl` one row per action:
`ts, cycle, kind, phase, prepTxid, settleTxid, wire, maxUnlock, fee, proveMs, pf7Ms, vmOk, mempoolOk, errorClass, notes`
Plus `summary.json` aggregates and `failures/` minimal repros.

### B1 — Happy-path volume (minimums; exceed if funds/time allow)
- ≥ **20** full cycles: deposit → one-note transfer → withdrawal (each real prep+settlement on Chipnet).
- ≥ **10** deposit-only then withdraw (skip transfer) — stress reserve/note-root edges.
- ≥ **10** sequential transfer chains length 2–3 on the live note before withdraw (one-in-one-out protocol).
- Mix fee UTXO shapes: consolidated hot, dusty multi-input prep funding, cold→hot top-ups mid-campaign; always change-to-cold when topping up.

### B2 — Concurrent / mempool stress (zero-conf)
- Chain child spends while parents still in mempool (prep→settlement→next prep).
- Parallel non-conflicting hot fee paths when safe; **never** double-spend.
- Record mempool package depth, reject reasons, any rebuild (no fee bumping that violates 1 sat/B — rebuild exact fee instead).

### B3 — Adversarial live checks (must reject on libauth and/or BCHN)
For sampled cycles, before honest broadcast:
- Flip bytes in PF7 unlocks, packet, fee sig, state commitment → expect reject.
- Cross-action packet/proof mismatch → expect reject.
- Wrong profile/instance or wrong category state NFT → expect reject.
- Oversized unlock/tx if ever produced → local gate fail (never broadcast).
Log expected-reject as pass; unexpected accept = critical defect → stop volume, fix, re-run class ≥3× green.

### B4 — Recovery battery
- Every **5** full cycles: full seed+chain recovery from BCHN raw history only; compare reconstructed spendable set to in-memory tip.
- At least **3** deliberate fault recoveries: omit provider path, reorder extracts, and/or drop tip then reorg-rollback where environment allows.
- Dual-path check if recovery package supports it.

### B5 — Economics / privacy / ops telemetry (measure, do not invent)
Per action and aggregate:
- wire bytes, max unlock, fee, RSS/time for prove, PF7 build time.
- Pool reserve, live note count, nullifier/note roots (from packets/state).
- Hot/cold balances via `scantxoutset` (not projections).
- Failure taxonomy counts: prove fail, PF7 dens fail, SCCT digest drift, libauth reject, BCHN reject, recovery miss, funding shortfall.

### B6 — Fix loop (non-negotiable)
On any failure:
1. Capture raw reject + minimal repro under `.cache/live-battery/<run-id>/failures/<id>/`.
2. Fix **shipped** code or build/ops scripts (no one-off hand patches that leave the tree broken).
3. Re-run the failing class ≥ **3** times green before resuming volume.
4. If fix changes relation/VK/PF7 locks: new development-only profile + genesis only (no hot-swap); invalidate dependent artifacts; document CHANGE_CONTROL touchpoints.
5. Update project memory only with durable ops facts (not secrets in git-tracked files beyond existing memory rules).

### B7 — Funding discipline during battery
- Prefer hot for prep/settlement fees; cold→hot top-up when hot change < next prep budget.
- Change-to-cold on top-ups and large leftovers.
- Stop and report if cold would drop below **95 BCH** without user override.
- Typical note size may stay ~0.1 BCH class or smaller dust-safe notes if policy allows — record actual amounts; do not invent pool subsidy.

## Phase C — Close gates
- Evidence packages: Phase A live E2E + Phase B battery summary (G2/G3/G5 as applicable; G4 desktop metrics if remeasured).
- Root `npm test` + touched package suites green.
- Policy/evidence ledgers: honest OPEN rows only where truly open.
- Opportunistic ShieldKit-SDK naming on touched surfaces.
- Final report: cycle counts vs minima, failure taxonomy, fixes landed, remaining OPEN items with exact handoff.

## Hard bans
Placeholders; OP_TRUE/synthetic accept; digest-only “proofs”; projections as measurements; silent G0 edits; hash rewrites to silence policy; mainnet; browser/Android stretch; weakening kill gates; new shield.cash product branding; committing secrets; waiting on confs as a gate; draining cold below treasury floor; double-spends; broadcasting known-invalid adversarial txs after the reject sample (adversarial is local/testmempool only unless intentionally probing reject — never leave broken spends that brick the pool tip).

## Execution style
Root agent = architect/integrator. Bounded subagents for disjoint work (prove vs PF7 vs broadcast vs recovery analysis). Prefer durable scripts over one-shot REPL once Phase A path is known. Every broadcast: **libauth 10/10 first**, then BCHN `testmempoolaccept`, then `sendrawtransaction`. Continue until:
- Phase A complete, **and**
- Phase B minima (B1–B4) met with failure rate analysed and critical defects fixed,
or a true external blocker (document exact handoff: command, txid, reject JSON, next action).

## Resume checklist (first actions this session)
1. Read `.grok/rules/project-memory.md` + this prompt; rescan hot/cold on `layer1-node`.
2. Verify transfer settlement `3f6f164b…` state UTXO still unspent; TOPUP2 `60d84cc4…` or planned withdrawal prep status.
3. Close Phase A: withdrawal prep (if needed) → PF7 dens-drop → settlement broadcast → recovery → `evidence/G2/live-chipnet-e2e-v1/`.
4. Scaffold `.cache/live-battery/<run-id>/` ledger + driver script from the Phase A pipeline.
5. Execute Phase B volume with continuous analyse→fix→re-prove→re-broadcast loop; do not stop at a single green cycle.
6. Phase C evidence + tests + summary report.
```

## Agent notes (not part of paste)

- Prior goal already closed deposit+transfer live; this prompt is the **continuation** that finishes withdrawal and pivots to volume testing.
- Background prove tasks from earlier sessions may still hold withdrawal proof/adapter in `.cache/live-chipnet-e2e/`; prefer those over re-prove if digests match staged prep.
- InstanceId in live path is `d96968b8…` (`.cache/profile-build-live`); stabilize bundle instance `74770b7d…` is offline-only — do not mix.
