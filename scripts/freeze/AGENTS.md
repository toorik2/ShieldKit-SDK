# shield.cash agent rules

Read `scripts/freeze/g0-lock.json`, `docs/CHARTER.md`, `scripts/freeze/docs/KILL_GATES.md`, and
`scripts/freeze/docs/BUILD_PLAN.md` before changing implementation.

- Run `npm test` before and after every coherent change.
- Never weaken a gate, replace real cryptography with a placeholder, or present
  a projection as measured evidence.
- Treat `/home/toorik/Projects/ZK-Proofs/shield.cash-evidence-20260723T121421Z`
  as read-only evidence. Import only through a provenance record.
- Preserve the `g0-v3` direction: wallet-first, 0.1 BCH, shared instances, local
  proving, transparent fee funding, publisher-only operations, and no
  post-genesis authority.
- Preserve the selected seven-input `bn254-onetx-pf7-sub62-r1` verifier
  topology. Qualify it under actual BCH limits: each unlocking bytecode is at
  most 10,000 bytes, no percentage headroom is required, and complete
  transactions target at most 59,000 serialized bytes. Do not substitute the
  approximately 82-kilobyte generic adapter.
- Keep verifier material profile-pluggable. A locally initialized setup is
  allowed only in a bundle permanently labeled `development-only`. A later
  multi-party-randomness ceremony must emit the same typed bundle interface and
  create a new profile and genesis. Never hot-swap an existing instance or
  present development setup as ceremony or production evidence.
- The target is a working end-to-end BCH Chipnet instance. Ask the user for
  Chipnet funding only after a fresh local address, exact amount, and transaction
  plan are ready. Never expose wallet secrets. Mainnet is not authorized.
- Locked-direction changes must follow `scripts/freeze/docs/CHANGE_CONTROL.md`; never update
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
