# Protocol kill-gate specification

Document version: 0.2

Status: binding; Gate G0 passed under `g0-v2`

Applies to: every shield.cash standard, profile, implementation, and release claim

## 1. Purpose

These gates prevent implementation momentum, sunk cost, or local success from
overriding the protocol charter.

A gate is a stop/go boundary, not a milestone label. A gate passes only when
every required item has reproducible evidence for the exact candidate under
review. Partial success leaves the gate open.

If a gate fails:

1. promotion stops;
2. the failure and affected assumptions are recorded;
3. the candidate is redesigned, narrowed, or abandoned; and
4. all downstream evidence invalidated by the change is rerun.

No schedule, funding event, announcement, or implementation dependency may
waive a gate.

## 2. Evidence rules

Every gate record must include:

- candidate/profile identifier;
- source commits and dirty-state report;
- exact toolchain, node, VM, dependency, and hardware versions;
- commands or machine-readable runner configuration;
- raw inputs and outputs;
- SHA-256 hashes for every material artifact;
- expected and observed verdicts;
- exact byte, operation, time, and memory measurements where applicable;
- negative and adversarial results, including unexpected passes;
- evidence limitations and untested assumptions;
- independent reproduction status; and
- reviewer identity and review scope.

The following are never promotable evidence:

- projections or lower-bound models;
- synthetic accepting scripts;
- `OP_TRUE` or equivalent verifier substitutes;
- digest-only circuits presented as transition circuits;
- missing or unavailable proof execution;
- patched policy, scorer, node, or benchmark behavior;
- fixed fixtures presented as arbitrary-input support;
- artifact hashes without reproducible provenance;
- incomplete setup transcripts;
- tests that assert only that execution occurred;
- simulator-only results presented as peer relay or chain inclusion; or
- evidence produced for a different circuit, VK, topology, profile, or network.

All byte accounting must cover complete transactions and every source output
needed to evaluate them. No detached or unscored acceptance channel is allowed.

## 3. Gate status vocabulary

- **OPEN**: required work or decisions remain.
- **PASS**: every requirement passed for the exact candidate.
- **FAIL**: at least one kill criterion was disproved.
- **INVALIDATED**: a later change made the evidence non-applicable.
- **NOT ENTERED**: prerequisite gates have not passed.

“Mostly passed,” “conditionally passed,” and “green except” are not statuses.

## 4. Gate overview

| Gate | Decision protected | Entry dependency |
| --- | --- | --- |
| G0 | Product and protocol direction | None |
| G1 | BCH and proof-system feasibility baseline | G0 |
| G2 | Complete standard transaction envelope | G1 |
| G3 | Relation and settlement soundness | G2 |
| G4 | Local wallet and prover viability | G2 |
| G5 | Chain-only recovery and data availability | G2 |
| G6 | Liveness, contention, preparation, and fees | G2 |
| G7 | Privacy and cross-integrator interoperability | G3, G4, G5, G6 |
| G8 | Operational independence and supply chain | G3, G4, G5, G6 |
| G9 | Profile release qualification | G7, G8 |

G3 through G6 may run in parallel only after the exact G2 candidate is frozen.

## 5. G0 — direction freeze

### Question

Is there one narrow product and threat model worth testing before implementation?

### Pass requirements

1. The charter is ratified with wallet/application integrators as the primary
   developer.
2. Integration with shared instances remains the primary workflow.
3. V1 asset, note-value model, action set, and required client platforms are
   explicitly selected.
4. The privacy adversary and public leakage matrix are written.
5. Required and optional roles are mapped; no optional role has protocol
   authority.
6. Fee funding, contention, recovery, setup, upgrade, and failure-containment
   decisions have documented defaults.
7. Target resource budgets are ratified or replaced with stricter explicit
   budgets.
8. The maintainer operational boundary is explicit. Jurisdiction-specific legal
   review is a release gate under G9, not a G0 implementation prerequisite.
9. All `LOCKED` decisions and every remaining `OPEN` decision in
    [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md) have an owner and resolution gate.

### Kill criteria

G0 fails if any of the following is required for the intended product:

- each application needs a distinct pool to express its logic;
- a shield.cash service must possess user secrets or authorize transfers;
- the primary value proposition is generic circuit or pool deployment;
- the protocol requires private data that cannot be recovered independently;
- the primary integrations cannot share transaction shapes and instances; or
- the resource target is intentionally left undefined until after
  implementation.

### Ratified resource budgets

G0 uses these accepted limits:

- required local targets: Linux/macOS desktop, desktop browser, and a current
  64-bit Android device;
- compressed profile artifacts required for proving: at most 512 MiB;
- desktop proving: p95 at most 30 seconds, peak RSS at most 4 GiB;
- desktop-browser proving: p95 at most 60 seconds, peak process memory at most
  2 GiB;
- Android proving: p95 at most 120 seconds, peak app RSS at most 1.5 GiB; and
- local proof verification: p95 at most 2 seconds on desktop.

Exact hardware fixtures and benchmark isolation rules must be fixed before G4
measurement. G0 fixes the required platforms and pass budgets.

## 6. G1 — feasibility baseline and proof-system selection

### Question

Can current BCH policy and VM behavior support any credible proof-verification
profile without relying on stale or synthetic assumptions?

The starting research baseline is verifier.cash candidate
`bn254-onetx-pf6-a3-r1` at commit
`26468ae29004d2401619032de2a6ec8de269a4d6`: 54,949 scored bytes and an
implied 54,739-byte serialized transaction. This fixes the initial fee-sizing
reference; it does not pass G1 or reserve any bytes for the protocol envelope.
The research fixture encodes only a 5,000-satoshi fee and is not itself evidence
of default-fee peer relay.

Its fixed, hardcoded verifier material is a development sizing reference only.
The build must generate and authenticate verifier material through the
versioned profile-bundle interface.

### Pass requirements

1. Current mainnet and Chipnet activation rules, standardness, VM limits, P2S,
   token commitment, transaction size, and input bytecode limits are recorded
   from primary specifications and live nodes.
2. At least two independent current BCHN v29 peers reproduce the relevant
   standard and consensus behavior.
3. Every candidate verifier is built from pinned source and a reproducible
   compiler/toolchain.
4. A real valid-proof corpus and invalid/tampered corpus execute in complete
   standard transactions.
5. All bytes, source locking bytecodes, per-input unlocking bytecodes, operation
   metrics, and policy verdicts are recorded.
6. At least one independent VM or formal implementation cross-checks the
   accepted and rejected cases.
7. Groth16/BN254 and any claimed alternative are compared using real artifacts,
   not proof-size or opcode-count projections.
8. The selected proof system has an explicit setup, upgrade, and failure model.
9. One verifier-bundle manifest binds the relation, public-input ABI, circuit,
   setup provenance, verification key, proving artifacts, BCH verifier scripts,
   and toolchain by hash.
10. A second independently generated development bundle replaces the first
    through the typed profile build without changing wallet or conformance
    semantics, and produces a distinct profile identifier and genesis.

### Kill criteria

G1 fails if no verifier profile leaves a credible measured budget for state,
action data, encryption data, reserve enforcement, and transaction binding
under the current standard transaction envelope.

A fixed-VK verifier passing G1 does not establish a pool profile.

## 7. G2 — complete settlement envelope

### Question

Does one exact, cryptographically complete protocol action fit and execute as a
standard BCH transaction with engineering margin?

### Candidate freeze

G2 evidence must use one exact set of:

- circuit relation and compiler output;
- verifying and proving keys;
- setup parameters;
- verifier-bundle manifest and setup mode;
- action encoding;
- profile and instance parameters;
- state, verifier, binding, and preparation scripts;
- source-output topology;
- encrypted note records;
- transaction builder; and
- node and VM versions.

Changing any item invalidates G2 and every downstream gate. Changing setup,
keys, circuit, public-input ABI, or verifier scripts also requires a distinct
profile identifier and genesis and cannot affect any existing instance.

### Pass requirements

1. Deposit, private transfer, and withdrawal each execute the full relation with
   real proofs and their real public inputs.
2. Every required preparation transaction and settlement transaction is
   included in the evidence package.
3. Each transaction is at most 95,000 serialized bytes.
4. The project’s all-bytes evidence score for each transaction is at most
   95,000 bytes.
5. Each unlocking bytecode is at most 9,500 bytes.
6. Each P2S locking bytecode is at most 190 bytes.
7. Each state NFT commitment is at most 120 bytes.
8. Every applicable operation-density and stack budget retains at least five
   percent measured headroom.
9. Two unmodified BCHN v29 peers accept the transactions as standard.
10. An unmodified Chipnet peer relays them and a miner includes them.
11. Libauth’s standard and consensus VMs agree with node verdicts.
12. LeanBCH or another independent formal model agrees on all supported
    execution paths.
13. At least 256 distinct valid cases cover action types, tree positions,
    boundary counters, reserve boundaries, dummy/real slots, and fee cases.
14. Every serialized action field, input role, source output, successor field,
    proof element, and relevant transaction field has a negative mutation case.
15. The corpus reports zero false accepts, zero unexecuted mutation cases, and
    zero unscored bytes.

### Kill criteria

G2 fails if:

- any complete action exceeds a budget;
- a required action needs non-standard relay;
- proof verification and state enforcement cannot be exactly coupled;
- encrypted recovery data requires a mandatory off-chain availability service;
- preparation requires a privileged UTXO supplier; or
- passing requires reducing the relation below charter invariants.

## 8. G3 — relation and settlement soundness

### Question

Does the frozen G2 candidate enforce the claimed asset, authorization, state,
and binding invariants against malicious witnesses and transactions?

### Pass requirements

1. A normative relation document defines every public and private signal.
2. Every encoded bit is constrained or explicitly non-consensus metadata.
3. Circuit inspection reports no unconstrained signals or underconstrained
   branches.
4. Canonical encodings and invalid field/point/key cases reject.
5. Spend authority and nullifier derivation use one bound secret relation.
6. Membership, non-membership, tree update, conservation, dummy-slot, and
   boundary-action invariants have independent reference checks.
7. Pre-state, post-state, profile, pool, network, action, artifact, and actual
   BCH transaction data are transitively bound.
8. Whole-transaction tests replace every accepting carrier or covenant with a
   distinct accepting script; every substitution rejects.
9. Duplicate, reordered, omitted, aliased, oversized, and non-canonical roles
   reject.
10. Differential property tests compare circuit witnesses, reference
    transition logic, BCH VM results, and formal-model results.
11. Coverage-guided fuzzing reaches every parser and transition branch with no
    crash, ambiguity, or false accept.
12. Independent cryptographic and BCH covenant reviewers resolve all critical
    and high-severity findings.

### Kill criteria

Any unexplained false accept, unverifiable binding edge, ambiguous encoding, or
authorization path fails G3. Statistical testing cannot waive a structural
soundness defect.

## 9. G4 — local wallet and prover viability

### Question

Can ordinary target wallets privately create valid actions without a hosted
prover?

### Pass requirements

1. The wallet derives addresses, spend authority, viewing capability, note
   encryption keys, and recovery state from the specified seed hierarchy.
2. Spending secrets and witnesses never leave the wallet in the required flow.
3. Proving passes every G0 time, memory, and artifact-download budget.
4. Benchmarks include cold start, warm start, artifact verification, witness
   generation, proof generation, and local verification.
5. Browser and Android tests use production packaging, not native-only or
   unlimited-memory substitutes.
6. Interrupted artifact downloads and proving operations resume or fail
   without corrupting wallet state.
7. Concurrent wallet operations cannot reuse randomness, nullifiers, notes, or
   fee inputs.
8. Wallet storage is encrypted and rollback/reorg safe.
9. A malicious application cannot obtain raw spending secrets through the
   supported SDK interface.
10. At least two independent client implementations decode and verify the same
    profile and action vectors.

### Kill criteria

G4 fails if any required target needs ordinary witness upload, exceeds the
ratified budget, cannot safely persist state, or cannot recover from
interruption. Narrowing supported platforms requires returning to G0.

## 10. G5 — chain-only recovery and data availability

### Question

Can a user recover ownership and spendability without trusting an indexer or
shield.cash data service?

### Pass requirements

1. Starting with only seed, authenticated profile, genesis identity, and BCH
   history recovers every owned note and correct spent/unspent status.
2. The recovery path uses raw BCH blocks/transactions from a self-hosted node.
3. All recipient discovery and note reconstruction data is available on-chain
   and integrity-bound to its action and output slot.
4. A 10,000-transition deterministic history restores identically across two
   independent implementations.
5. Reorg depths 1, 2, 10, and 100 correctly roll back and replay notes,
   witnesses, nullifiers, balances, and pending transactions.
6. Missing, duplicated, reordered, truncated, or equivocated provider responses
   are detected.
7. Indexer acceleration is verified against authenticated chain data.
8. A user can reconstruct or retrieve every artifact required to spend from
   content-addressed public data without maintainer authorization.
9. Pruned-node limitations and archival requirements are explicit in the
   profile and SDK.

### Kill criteria

Any owned note that depends on an unavailable ciphertext, indexer-only record,
provider-private mapping, or non-reconstructible artifact fails G5.

## 11. G6 — liveness, contention, preparation, and fees

### Question

Can users make progress permissionlessly despite the serialized state UTXO,
competing proofs, and verifier-carrier preparation?

### Pass requirements

1. The protocol publishes a measured concurrency and throughput model.
2. In a 100-client same-pre-state test, at most one conflicting state successor
   confirms and every losing client safely detects staleness.
3. Losing clients can re-plan without fund loss, note loss, randomness reuse,
   or invalid local balances.
4. Coordinator disappearance or censorship cannot block direct valid
   construction and broadcast.
5. Every verifier carrier or prepared UTXO can be constructed permissionlessly
   from published profile data.
6. Preparation cannot be cheaply stolen, substituted, or griefed without an
   explicit bounded cost model.
7. Fee funding is bound into conservation and exact BCH transaction behavior.
8. The required flow supports fees without a mandatory relayer.
9. Transparent fee inputs, change, timing, and broadcaster linkage are included
   in the privacy leakage model.
10. Mempool replacement, conflicting chains, reorgs, and delayed confirmation
    have deterministic wallet behavior.
11. No optional liveness component has custody or safety authority.

### Kill criteria

G6 fails if safe spending requires an exclusive coordinator, privileged
prepared outputs, maintainer authorization, or unbounded retries under ordinary
contention. If the required throughput exceeds the measured serialized design,
the profile must be redesigned rather than hidden behind a service.

## 12. G7 — privacy and interoperability

### Question

Do independent integrations create one protocol-level anonymity set without
vendor fingerprints or misleading privacy claims?

### Pass requirements

1. A public leakage matrix covers chain, timing, amount, denomination, fees,
   preparation, input topology, output topology, wallet queries, network
   metadata, and migration.
2. Supported action types have one canonical encoded shape or explicitly
   quantified distinguishability.
3. Application, wallet, provider, and vendor identifiers are absent from
   action encodings.
4. Two independent integrations produce mutually valid actions for the same
   shared instance.
5. Cross-implementation vectors show identical parsing, hashing, commitments,
   nullifiers, encryption binding, and transaction construction.
6. Wallet defaults avoid deterministic timing, fee, address-reuse, and change
   behaviors that trivially link boundaries.
7. An anonymity analysis uses observed or explicitly simulated population and
   behavior; cryptographic hiding alone is not counted.
8. Empty, low-volume, adversarially dominated, and fragmented-instance cases
   produce explicit warnings rather than anonymity claims.
9. Optional selective-disclosure mechanisms, if any, are profile-separated and
   cannot silently reduce other users’ anonymity.
10. Independent privacy review resolves every critical and high-severity
    finding.

### Kill criteria

G7 fails if integrations require distinguishable protocol variants, if the
primary workflow fragments instances, or if privacy claims cannot be stated
with a measurable adversary and population.

## 13. G8 — operational independence and supply chain

### Question

Does the exact candidate remain usable and verifiable if all shield.cash
infrastructure is offline or malicious?

### Pass requirements

1. A conforming wallet syncs, proves, constructs, verifies, and broadcasts using
   a self-hosted BCH node and local artifacts.
2. At least two independent chain/provider implementations pass the same
   conformance suite.
3. Indexers, relayers, coordinators, broadcasters, and mirrors are individually
   removed and made malicious in fault-injection tests.
4. No provider can forge balances, notes, roots, nullifier status, proofs,
   confirmations, or profile identity without detection.
5. All release artifacts are content-addressed and reproducible from pinned
   source, toolchains, and the verified setup transcript.
6. Required artifacts are available from at least three independently
   controlled distribution paths, while integrity depends only on hashes.
7. Complete offline verification instructions and public conformance vectors
   are included.
8. Maintainers hold no runtime authorization, upgrade, pause, custody,
   sequencing, or fee-collection key.
9. Provider protocols and privacy leakage are documented independently of any
   hosted implementation.
10. Loss of every hosted endpoint changes convenience only, not ownership or
    protocol validity.

### Kill criteria

Any mandatory endpoint, maintainer key, exclusive artifact source, or
unverifiable provider response fails G8.

## 14. G9 — profile release qualification

### Question

Has one exact profile earned a narrowly scoped public qualification?

### Pass requirements

1. G0 through G8 remain PASS for the exact frozen profile.
2. Normative specification, manifest, source, generated artifacts, setup
   transcript, vectors, and conformance release are mutually hash-consistent.
3. The profile uses a `ceremony-production` verifier bundle; its
   circuit-specific multi-party-randomness ceremony is publicly reproducible
   and verified, and no coordinator’s deletion claim is treated as security
   evidence.
4. One independent audit covers the circuit and cryptographic protocol.
5. A separate independent audit covers BCH scripts, transaction construction,
   wallet recovery, and provider boundaries.
6. All critical and high findings are fixed and every affected gate rerun.
7. Chipnet evidence includes at least:
   - 10,000 accepted state transitions;
   - 1,000 deposits;
   - 1,000 private transfers;
   - 1,000 withdrawals;
   - 256 adversarial transaction families;
   - two independent wallet/application integrations;
   - two independent broadcasters; and
   - full recovery by two independent implementations.
8. Exact relay and inclusion evidence is reproduced through multiple
   independently operated current nodes.
9. Incident response, profile deprecation, migration, and reserve-containment
   procedures are published and exercised.
10. A mainnet candidate defines a public reserve/exposure cap and cannot exceed
    it without a new reviewed instance.
11. Jurisdiction-specific legal review covers the actual maintainer and
    infrastructure activities; naming the project a protocol is not accepted as
    analysis.
12. Release notes state exact claims, dates, evidence, audit scopes, residual
    risks, and non-goals.

### Kill criteria

Any artifact drift, unreproduced build, incomplete ceremony, unresolved
critical/high finding, missing integration, failed recovery, or operational
dependency blocks qualification.

G9 PASS permits the label defined by the charter. It does not permit an
unqualified claim that the system is safe, anonymous, production ready, or
legally compliant.

## 15. Current status

| Gate | Status | Reason |
| --- | --- | --- |
| G0 | OPEN | RFC-0002 reopens the verifier input-limit and project-margin boundary |
| G1 | NOT ENTERED | G0 prerequisite |
| G2 | NOT ENTERED | G1 prerequisite |
| G3 | NOT ENTERED | G2 prerequisite |
| G4 | NOT ENTERED | G2 prerequisite |
| G5 | NOT ENTERED | G2 prerequisite |
| G6 | NOT ENTERED | G2 prerequisite |
| G7 | NOT ENTERED | G3–G6 prerequisites |
| G8 | NOT ENTERED | G3–G6 prerequisites |
| G9 | NOT ENTERED | G7–G8 prerequisites |
