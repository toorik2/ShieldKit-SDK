# Copyable Codex goal

Paste the following as one message:

```text
/goal Build shield.cash all the way from the frozen g0-v1 charter to a working end-to-end BCH Chipnet protocol: normative standard, real fixed-0.1-BCH deposit/transfer/withdraw relations, reproducible proof artifacts, complete BCH preparation and settlement transactions, local desktop/browser/Android wallet-prover SDK, chain-only recovery, a rigorous conformance/adversarial lab, and a live authenticated Chipnet instance with successful real flows.

Treat AGENTS.md, policy/g0-lock.json, docs/CHARTER.md, docs/KILL_GATES.md, docs/PRIVACY.md, and docs/BUILD_PLAN.md as binding. Preserve the evidence archive as read-only. No placeholders, toy circuits, synthetic acceptance, projections presented as measurements, patched policy, hosted-service dependencies, protocol fees, or post-genesis admin/pause/rescue/upgrade authority. Use the 54,949 score / 54,739 wire verifier baseline and the transparent fee-input plus canonical-change model, but qualify every claim using complete transactions and current evidence. Chipnet is the deployment target; mainnet is not authorized.

Work gate-by-gate without stopping at plans, scaffolds, compile success, or one happy path. When a candidate fails, record the falsifier and pursue the next bounded design unless the charter itself is disproved. Keep G0 frozen; follow CHANGE_CONTROL.md for any semantic change. Do not claim mainnet/release/legal qualification or perform externally consequential deployment without my explicit authorization.

Use all available concurrency productively. Whenever two or more concrete tasks are independent, proactively spawn gpt-5.6-terra subagents with bounded scopes for exploration, implementation, tests, adversarial review, measurements, or documentation; keep the root agent as architect and integrator. Prefer isolated worktrees or non-overlapping write ownership, give every subagent explicit evidence and validation requirements, refill free slots as work completes, wait for and independently verify important results, and close every child/descendant with lifecycle records. Keep noisy logs in subagent threads and return distilled evidence to root.

Maintain a live plan and evidence ledger. Commit coherent, validated increments. Continue across goal turns until every in-scope deliverable in docs/BUILD_PLAN.md exists, all locally executable gates pass for the same frozen artifacts, npm test and the full conformance suite are green, and no in-scope engineering work remains. A blocker is terminal only when it genuinely requires user authority or external state; document the exact blocker and the strongest completed handoff instead of lowering a gate.

When and only when the exact Chipnet candidate, wallet, scripts, expected transactions, and funding calculation are ready, generate a fresh locally controlled Chipnet address and ask me to fund it. State the exact amount and purpose, wait for confirmation, then continue automatically through live deployment and end-to-end testing. Never reveal the seed or private keys.
```
