# shield.cash protocol charter

Document version: 0.3

Status: ratified under `g0-v3`

Scope: product and protocol authority, not an implementation specification

## 1. Mission

shield.cash defines a narrow, auditable Bitcoin Cash shielded-transfer standard
that wallets and applications can integrate without trusting or depending on
shield.cash-operated infrastructure.

An end user should be able to:

1. derive wallet state from a seed, a protocol profile, and BCH history;
2. construct and prove a supported shielded action locally;
3. verify every untrusted chain, indexer, artifact, and transaction input;
4. broadcast through any compatible path; and
5. retain spend authority if every optional service disappears.

The protocol exists to standardize interoperable shielded transfers. It is not
a hosted privacy service, a general-purpose ZK framework, or a pool-deployment
factory.

## 2. Primary users

### 2.1 Primary developer

The primary developer is a wallet or application integrator adding support for
an existing compatible protocol profile and shared pool instance.

The safe integration API must cover:

- profile discovery and authentication;
- address and key derivation;
- chain synchronization and reorg handling;
- note discovery, storage, and recovery;
- deposit, private-transfer, and withdrawal planning;
- local witness generation and proving;
- deterministic BCH transaction construction;
- local verification and broadcast; and
- explicit privacy and failure diagnostics.

The primary developer must not need to understand circuit signals, verifier
carrier roles, ceremony internals, or raw covenant bytecode.

### 2.2 Advanced developer

Infrastructure operators may provide replaceable acceleration or convenience:
chain access, indexing, broadcasting, relaying, artifact distribution, or
coordination. Their outputs are untrusted and locally verified.

Protocol authors may propose new profiles. This is a security-critical standards
workflow, not ordinary SDK customization.

## 3. Standard, profile, and instance

The following terms are distinct:

- **Standard**: the versioning, manifest, action, recovery, conformance, and
  release rules shared by all compatible profiles.
- **Protocol profile**: one immutable selection of cryptographic primitives,
  circuit relation, verifying key, BCH scripts, action encoding, limits, and
  artifact hashes.
- **Verifier bundle**: one versioned, profile-bound package containing relation
  and public-input ABI identities, setup provenance, verification key, proving
  artifacts, BCH verifier scripts, pinned toolchain, and hashes.
- **Pool instance**: one on-chain state machine created from a profile, with a
  unique genesis outpoint and state identity.
- **Integration**: wallet or application support for a profile and one or more
  compatible instances.
- **Provider**: an optional implementation of a replaceable interface such as
  chain access, indexing, broadcast, relay, or artifact retrieval.

Profiles define compatibility; instances provide anonymity and liquidity.
Creating many instances from the same profile does not combine their anonymity
sets.

## 4. Charter-level principles

### P1. Shared integration is the primary workflow

Wallets and applications should produce protocol-indistinguishable actions
against compatible shared instances. Application identity, provider identity,
or vendor-specific tags must not appear in consensus or action encodings.

### P2. Local control of secrets

The required flow keeps spending keys, note plaintexts, witnesses, Merkle paths,
and proving inputs under user control. Remote proving is optional only if a
separate construction protects witness privacy; ordinary witness upload is not
a conforming required flow.

### P3. BCH is protocol authority

The confirmed BCH transaction history, authenticated genesis profile, and
consensus-valid state transitions define protocol state. Indexers, explorers,
registries, mirrors, APIs, and maintainers do not.

### P4. Chain-recoverable ownership

All data required to discover and reconstruct spendable notes must be committed
to and available from BCH history. Acceleration data may be off-chain; ownership
data may not depend on an off-chain database.

### P5. Exact proof-to-transaction binding

A proof is valid only for the exact profile, pool state, action encoding, BCH
input roles, source outputs, successor outputs, values, tokens, scripts, and
public boundary action executed by the transaction. A proof accepted in one
input and state changed by another is sound only when every dependency is
cryptographically and covenant-bound.

### P6. Permissionless safety and spending

No maintainer, coordinator, relayer, indexer, prover, or artifact host may be
required to authorize a valid transition. Optional components may improve
liveness or performance but cannot become safety authorities.

### P7. Immutable profile semantics

Circuit, verifying key, encodings, domain separators, scripts, artifact hashes,
and setup transcript are immutable within a profile. A change creates a new
profile and an explicit migration; there are no silent upgrades.

### P8. Failure containment

A proof-system, circuit, setup, or wallet failure must be analyzed in terms of
the maximum pool reserve it can affect. The protocol cannot mint BCH. Profile
and instance design should support explicit reserve caps and staged exposure.

### P9. Privacy claims require population and behavior

Cryptographic hiding is not an anonymity guarantee. Privacy claims must include
the observed anonymity set, deposit and withdrawal timing, denomination,
transaction shape, fee source, network metadata, provider queries, and
application fingerprinting.

### P10. Evidence precedes promotion

No projection, synthetic fixture, digest-only relation, unavailable verifier,
patched benchmark, or incomplete provenance may be promoted as protocol,
Chipnet, mainnet, or release evidence.

### P11. “Can’t do evil” after genesis

Genesis fixes the profile, scripts, cryptographic parameters, state rules, and
all authority-bearing data, including an immutable maximum reserve. After
genesis there is no administrator, pause, rescue, sequencing, censorship, fee,
or upgrade key. Maintainers may publish information and new software, but cannot
change whether an existing transition is valid.

A defect may leave an instance unsafe or unusable. That failure cannot create
maintainer authority over the instance. Any successor design is a distinct
profile and instance; participation in it is user-authorized rather than an
upgrade applied to the old instance.

### P12. Verifier material is replaceable only between profiles

Wallet, prover, transaction, and conformance code consume one typed, versioned
verifier-bundle interface. They must not contain unversioned embedded
verification keys, proving keys, circuit artifacts, or verifier scripts.

A local setup may initialize a Chipnet development bundle, but that bundle and
every instance created from it remain permanently labeled `development-only`.
Any profile intended for production qualification requires a documented,
verified multi-party-randomness ceremony and its complete transcript.

Changing the setup, relation, public-input ABI, circuit artifacts, verification
key, proving artifacts, or verifier scripts creates a new profile identifier
and new genesis. “Plug-and-play” means rebuilding and requalifying a new profile
through the stable interface; it never means hot-swapping consensus material in
an existing instance.

## 5. V1 scope

V1 is intentionally narrow:

- Bitcoin Cash only;
- BCH as the only shielded asset;
- fixed 0.1 BCH notes;
- one immutable cryptographic and settlement profile;
- a small number of explicitly authenticated shared instances;
- deposits, shielded-to-shielded transfers, and withdrawals;
- a fixed action shape selected by measured transaction and proving budgets;
- locally generated proofs in the required flow;
- a versioned, authenticated verifier bundle selected at profile genesis;
- chain-available encrypted note records;
- deterministic transaction construction;
- replaceable provider interfaces;
- seed-based wallet recovery and reorg handling; and
- a public conformance and evidence suite.

The first complete implementation and deployment target is BCH Chipnet. This
charter does not authorize a mainnet deployment.

The action cardinality, fee mechanism, state contention strategy, and proof
system remain measured profile decisions. They are enumerated in
[OPEN_QUESTIONS.md](OPEN_QUESTIONS.md).

## 6. Explicit non-goals for V1

V1 does not provide:

- arbitrary private smart contracts;
- developer-supplied circuits or covenant plugins;
- multi-asset or arbitrary CashToken shielding;
- per-application protocol extensions;
- pool deployment as an ordinary SDK call;
- a mandatory sequencer, coordinator, relayer, indexer, or prover;
- a shield.cash custody, wallet, exchange, or money-transmission service;
- unqualified anonymity, compliance, or safety guarantees;
- a governance token or protocol fee;
- hidden administrator, pause, recovery, or upgrade keys;
- cross-chain shielding or bridging;
- private delegated proving unless separately specified and audited; or
- treating a locally generated development setup as ceremony-backed or
  production evidence; or
- backward-compatible mutation of a deployed profile.

Removing a non-goal requires a new charter version and re-entry through the
applicable kill gates.

## 7. Required protocol invariants

Any profile must enforce all of the following.

### 7.1 Asset safety

- Every spend is authorized by knowledge bound to the consumed note.
- Every real input note was committed under an accepted state.
- Every consumed note produces one deterministic nullifier.
- A nullifier can be accepted at most once.
- Shielded value plus public deposits equals new shielded value plus public
  withdrawals and explicitly defined fees.
- The successor reserve matches the proven accounting transition.
- Exactly one authenticated successor state exists.
- No transaction can create BCH or claims beyond the reserve containment model.

### 7.2 Domain and encoding safety

- Every byte encoding is canonical and round-trip defined.
- All field, integer, point, key, and script encodings reject invalid or
  non-canonical values.
- Network, profile, instance, action type, version, and artifact identity are
  domain-separated.
- Relation, public-input ABI, circuit, setup transcript, verification key,
  proving artifacts, and verifier scripts are bound to the profile identity.
- All inactive or dummy fields have one constrained canonical form.

### 7.3 BCH settlement safety

- Every transaction role and exact source locking bytecode is authenticated.
- Actual input values, output values, token data, scripts, indices, version,
  locktime, sequences, and fee behavior are bound where relevant.
- Every V1 action has one transparent fee-funding input and one canonical change
  output; verifier-carrier values may also contribute to the miner fee.
- The pool reserve never subsidizes miner fees, and a relayer is never required.
- The complete standard transaction is validated, not isolated script
  fragments.
- Policy standardness and consensus validity are separately measured.

### 7.4 Recovery and availability

- A wallet can recover from seed, authenticated profile, and BCH history alone.
- Encrypted records are integrity-bound to the exact output and action.
- A malicious or incomplete indexer cannot create false spendable state.
- Reorgs roll back notes, witnesses, nullifiers, and pending actions
  deterministically.

### 7.5 Operational independence

- Provider disappearance cannot transfer authority or invalidate ownership.
- Provider equivocation is detected by local verification.
- Artifact integrity is content-addressed and reproducible.
- A wallet fails closed if any verifier-bundle identity, hash, setup mode, or
  profile binding disagrees.
- No maintainer-controlled runtime key is required for a valid spend.

## 8. Roles and trust boundaries

| Role | May provide | Must not be trusted for |
| --- | --- | --- |
| Wallet engine | keys, notes, witnesses, proofs, plans | external inputs without verification |
| Integrating application | user intent and presentation | direct access to raw spending secrets |
| Chain source | blocks, transactions, UTXOs, headers | canonicality, completeness, or state validity |
| Indexer | discovery and witness acceleration | ownership, balances, nullifier status, or recovery |
| Broadcaster | transaction submission | authorization, mutation, or confirmation |
| Relayer | fee payment and broadcast convenience | custody, note validity, or exclusive access |
| Coordinator | contention reduction and ordering hints | safety, finality, or censorship-free spending |
| Artifact distributor | proving and verification artifacts | identity or integrity of artifacts |
| Maintainers | specifications, releases, advisories | runtime authorization or unilateral upgrades |
| Ceremony participants | setup contributions | retained toxic waste or implementation correctness |
| Auditors | scoped findings | blanket safety or privacy guarantees |

An implementation that requires trust beyond this table is non-conforming until
the charter and profile explicitly add that trust assumption.

## 9. Normative authority

No codebase is the protocol.

A released profile is the mutually consistent set of:

1. versioned normative specification;
2. canonical profile manifest;
3. source and generated artifact hashes;
4. setup transcript and verification record;
5. canonical positive and negative vectors;
6. conformance-suite release; and
7. authenticated genesis parameters.

If any two disagree, the profile is invalid for promotion. Implementations must
fail closed; maintainers must publish an incident record and either correct an
unreleased candidate or create a new profile.

Reference implementations are evidence and developer tools, not an override of
the normative set.

## 10. Versioning and migration

- Standard revisions describe compatibility and process changes.
- Profile revisions are not mutable: changed cryptography or settlement creates
  a new profile identifier.
- Instance creation never implies endorsement.
- Migration is an explicit public boundary action between independently
  authenticated profiles or instances.
- A wallet must display the source, destination, privacy loss, and failure
  assumptions of migration.
- No migration path may depend on a maintainer key hidden from the profile.

## 11. Governance boundary

Maintainers may:

- propose and merge specifications;
- publish content-addressed releases and security advisories;
- coordinate reviews, ceremonies, and test events; and
- publish SDKs, artifacts, conformance tooling, documentation, and reference
  source.

Maintainers may not gain protocol authority through:

- administrator or pause keys;
- exclusive artifact distribution;
- mandatory APIs;
- privileged transaction ordering;
- protocol fees payable to maintainers;
- opaque allowlists or blocklists; or
- the ability to mutate an existing profile.

Governance authenticates information; it does not authorize user funds.
shield.cash does not operate public indexers or RPC services, relayers,
broadcasters, coordinators, hosted provers, artifact servers, Chipnet
endpoints, or a consumer transaction application under the V1 boundary.

## 12. Release language

Allowed maturity labels are:

- **design draft** — charter or specification work only;
- **evidence experiment** — measured research with no profile claim;
- **profile candidate** — internally consistent artifacts, not all gates passed;
- **Chipnet qualified** — every required pre-mainnet gate and Chipnet threshold
  passed for the exact profile;
- **mainnet candidate** — independently reviewed, exposure-bounded candidate;
- **mainnet qualified** — exact released profile passed every gate.

The labels “safe,” “anonymous,” “production ready,” and “audited” are prohibited
without a narrowly scoped statement identifying the profile, evidence, threat
model, audit scope, date, and remaining risks.

## 13. Charter success condition

The charter succeeds when two independent wallet or application integrations
can use the same authenticated shared instance, produce mutually compatible
actions, recover independently from BCH history, and complete valid spends with
all shield.cash-operated infrastructure unavailable.

That success condition is not satisfied by deploying a pool, generating a proof,
passing a local VM fixture, or publishing an SDK package.
