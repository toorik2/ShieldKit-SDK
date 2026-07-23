# shield.cash agent rules

Read `policy/g0-lock.json`, `docs/CHARTER.md`, `docs/KILL_GATES.md`, and
`docs/BUILD_PLAN.md` before changing implementation.

- Run `npm test` before and after every coherent change.
- Never weaken a gate, replace real cryptography with a placeholder, or present
  a projection as measured evidence.
- Treat `/home/toorik/Projects/ZK-Proofs/shield.cash-evidence-20260723T121421Z`
  as read-only evidence. Import only through a provenance record.
- Preserve the `g0-v1` direction: wallet-first, 0.1 BCH, shared instances, local
  proving, transparent fee funding, publisher-only operations, and no
  post-genesis authority.
- The target is a working end-to-end BCH Chipnet instance. Ask the user for
  Chipnet funding only after a fresh local address, exact amount, and transaction
  plan are ready. Never expose wallet secrets. Mainnet is not authorized.
- Locked-direction changes must follow `docs/CHANGE_CONTROL.md`; never update
  hashes merely to silence the policy check.
- Keep the root agent as architect and integrator. Use `gpt-5.6-terra`
  subagents aggressively for concrete, disjoint exploration, implementation,
  test, adversarial, and documentation work. Use isolated worktrees or
  non-overlapping ownership for parallel writes.
- Give each subagent a bounded scope, expected evidence, and validation command.
  Reuse live agents when appropriate, wait for results, independently validate
  important conclusions, and close every child and descendant.
- Do not stop at scaffolding or a partial gate. Continue through the next
  highest-value unblocked work package until the active goal's completion
  condition is actually met.
