# shield.cash

Status: Gate G0 frozen; Phase B feasibility work may begin. No pool, circuit,
covenant, SDK, service, deployment, or release artifact exists yet.

## Mission

Define a narrow, auditable Bitcoin Cash shielded-transfer standard that wallets
and applications integrate into, backed by:

- a local wallet and prover SDK;
- deterministic BCH transaction construction;
- independently verifiable protocol profiles;
- a rigorous conformance and adversarial-testing lab; and
- optional, replaceable infrastructure with no protocol authority.

The primary developer workflow is integration with compatible shared pool
instances. Launching a new pool, supplying a custom circuit, or depending on a
shield.cash-operated service is not the primary workflow.

## Current phase

The product boundary is frozen by Gate G0. Work now proceeds through the
evidence-first feasibility and protocol gates in
[the kill-gate specification](docs/KILL_GATES.md). Passing G0 permits Phase B
experiments; it is not a protocol, safety, or release qualification.

The governing documents are:

- [Protocol charter](docs/CHARTER.md) — mission, invariants, scope, roles, and
  authority.
- [Kill gates](docs/KILL_GATES.md) — quantitative evidence required to continue
  or promote.
- [Open decisions](docs/OPEN_QUESTIONS.md) — locked, provisional, and unresolved
  architectural choices.
- [Privacy claim](docs/PRIVACY.md) — the exact V1 blockchain-unlinkability claim
  and its public leakage matrix.
- [Roadmap](docs/ROADMAP.md) — dependency-driven work plan without
  calendar-based promotion.
- [Build plan](docs/BUILD_PLAN.md) — executable work packages and completion
  conditions.
- [Change control](docs/CHANGE_CONTROL.md) — the mandatory process for changing
  frozen decisions.

## Evidence boundary

The previous implementation was preserved intact at:

`/home/toorik/Projects/ZK-Proofs/shield.cash-evidence-20260723T121421Z`

That directory is an evidence laboratory, not a source tree or protocol
authority. No code or artifact may be copied from it into this repository
without:

1. an accepted protocol requirement;
2. an explicit provenance record;
3. independent reproduction against the current BCH network rules; and
4. the same conformance treatment as a new implementation.

Historical results, projections, synthetic fixtures, digest-only circuits,
incomplete ceremonies, or locally patched harnesses cannot satisfy a gate.

## Non-negotiable product boundary

- No generic privacy framework in V1.
- No “deploy your own pool” hero workflow.
- No mandatory shield.cash indexer, relayer, prover, broadcaster, coordinator,
  artifact server, frontend, or RPC endpoint.
- shield.cash publishes specifications, SDKs, artifacts, conformance tooling,
  documentation, and reference source; it does not operate public transaction
  infrastructure or a consumer transaction application.
- No server receives wallet spending secrets in the required protocol flow.
- No implementation is protocol authority.
- No safety, privacy, standardness, or release claim without exact evidence
  required by the relevant gate.

## Immediate objective

Execute Phase B: reproduce the BCH and verifier envelope, define the exact
protocol kernel, and kill or promote one complete candidate using real evidence.
The engineering target is a working end-to-end protocol instance on BCH
Chipnet. Mainnet deployment is outside the current authorization.
