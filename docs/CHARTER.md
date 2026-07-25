# ShieldKit protocol charter

Document version: 0.4

Status: product authority for **ShieldKit** (create-and-run-your-own-pool toolkit)

Scope: product and protocol authority, not an implementation specification.

> **Product story:** Primary path is **create your own pool**.  
> Optional: try the Chipnet playground example first.  
> Start: `packages/kit` (+ `profile` for init/instance).

## 1. Mission

ShieldKit defines a narrow, auditable Bitcoin Cash shielded-transfer toolkit
that wallets and applications can use to **create and operate their own pool
instances** without trusting hosted infrastructure.

An end user / operator should be able to:

1. derive wallet state from a seed, a protocol profile, and BCH history;
2. construct and prove a supported shielded action locally;
3. verify every untrusted chain, indexer, artifact, and transaction input;
4. broadcast through any compatible path; and
5. retain spend authority if every optional service disappears.

The toolkit standardizes interoperable shielded transfers. It is **not** a
hosted privacy service, a general-purpose ZK framework, or a third-party pool
SaaS. The Chipnet playground is an **optional example instance** only.

## 2. Primary users

### 2.1 Pool creator (primary)

The primary user is someone creating and running **their own** pool instance:
init (development-only or ceremony-production), genesis, then operate with the
same kit APIs as the example playground.

### 2.2 Application integrator

Wallets and applications integrate against a chosen profile and one or more
instances (the operator’s own, or a shared authenticated instance). Safe
integration covers profile discovery, keys/notes/recovery, plan/prove/settle,
local verification, and explicit privacy diagnostics — without requiring deep
circuit or ceremony knowledge for ordinary use.

### 2.3 Advanced / infrastructure

Infrastructure operators may provide replaceable acceleration: chain access,
indexing, broadcasting, relaying, artifact distribution. Outputs are untrusted
and locally verified. Protocol authors may propose new profiles (security-critical).

## 3. Standard, profile, and instance

- **Standard**: versioning, manifest, action, recovery, conformance, release rules.
- **Protocol profile**: immutable selection of crypto, circuit, VK, BCH scripts,
  action encoding, limits, artifact hashes.
- **Verifier bundle**: versioned, profile-bound package (relation/ABI, setup
  provenance, VK, proving artifacts, BCH scripts, toolchain, hashes).
- **Pool instance**: on-chain state machine from a profile (unique genesis).
- **Integration**: app support for a profile and compatible instances.
- **Provider**: optional replaceable interface (chain, index, broadcast, …).

Profiles define compatibility; instances provide anonymity and liquidity.
Many instances from one profile do **not** combine anonymity sets.

## 4. Charter-level principles

### P1. Create-your-own-pool is the primary product workflow

ShieldKit’s primary deliverable is the ability to **init, genesis, and operate
your own instance**. Shared-instance integration is supported; hosted multi-tenant
pool service is not the product.

### P2. Local control of secrets

Spending keys, note plaintexts, witnesses, Merkle paths, and proving inputs stay
under user/operator control. Remote proving is optional only if witness privacy
is separately protected.

### P3. BCH is protocol authority

Confirmed BCH history, authenticated genesis profile, and consensus-valid
transitions define state. Indexers, explorers, registries, APIs do not.

### P4. Chain-recoverable ownership

All data required to discover and reconstruct spendable notes must be committed
to and available from BCH history.

### P5. Exact proof-to-transaction binding

A proof is valid only for the exact profile, pool state, action encoding, BCH
roles, I/O, values, tokens, scripts, and public boundary executed.

### P6. Permissionless safety and spending

No maintainer, coordinator, relayer, indexer, prover, or artifact host may be
required to authorize a valid transition.

### P7. Immutable profile semantics

Circuit, VK, encodings, domain separators, scripts, artifact hashes, and setup
transcript are immutable within a profile. Change ⇒ new profile + migration.

### P8. Failure containment

Failures analyzed by maximum pool reserve affected. Protocol cannot mint BCH.
Reserve caps and staged exposure are first-class.

### P9. Privacy claims require population and behavior

Cryptographic hiding ≠ anonymity guarantee. Claims must include anonymity set,
timing, denomination, shape, fees, network metadata, provider queries, fingerprinting.

### P10. Evidence precedes promotion

No synthetic fixture, digest-only relation, or incomplete provenance may be
promoted as Chipnet/mainnet/release evidence.

### P11. “Can’t do evil” after genesis

Genesis fixes profile, scripts, crypto, state rules, and max reserve. No admin,
pause, rescue, upgrade, or fee key. Successors are new profiles/instances.

### P12. Verifier material is replaceable only between profiles

Code consumes one typed verifier-bundle interface. Local setup ⇒ permanently
`development-only`. Production claims require ceremony + full transcript.
Hot-swap of consensus material in an existing instance is forbidden.

## 5. V1 scope

- Bitcoin Cash only; BCH as sole shielded asset; fixed 0.1 BCH notes
- One immutable crypto/settlement profile shape
- Deposits, shielded transfers, withdrawals
- Local proofs in the required flow
- Versioned authenticated verifier bundle at genesis
- Chain-available encrypted note records
- Deterministic transaction construction; replaceable providers
- Seed-based recovery; public conformance/evidence suite

First complete target: **BCH Chipnet**. Charter does **not** authorize mainnet
as production-qualified. Mainnet code path may exist with explicit WIP gates.

## 6. Explicit non-goals for V1

- Arbitrary private smart contracts / developer-supplied circuits
- Multi-asset or arbitrary CashToken shielding
- Hosted pool SaaS for third-party apps
- Mandatory sequencer/coordinator/relayer/indexer/prover
- Custody, exchange, or money-transmission service
- Unqualified anonymity/compliance/safety guarantees
- Governance token or protocol fee; hidden admin keys
- Treating local development setup as ceremony/production evidence
- Backward-compatible mutation of a deployed profile

## 7. Required protocol invariants

### 7.1 Asset safety

Spend authorization bound to notes; nullifiers once; reserve accounting exact;
one authenticated successor state; no minting BCH.

### 7.2 Domain and encoding safety

Canonical encodings; domain separation of network/profile/instance/action;
profile-bound relation/VK/artifacts; constrained dummy fields.

### 7.3 BCH settlement safety

Authenticated roles and locking bytecode; bound values/tokens/scripts; fee
model with transparent fee input; complete standard tx validation.

### 7.4 Recovery and availability

Recover from seed + profile + BCH history; integrity-bound encrypted records;
reorgs roll back deterministically.

### 7.5 Operational independence

Provider disappearance cannot transfer authority; fail closed on identity/hash/
setup disagreement; no maintainer runtime key for spends.

## 8. Roles and trust boundaries

| Role | May provide | Must not be trusted for |
| --- | --- | --- |
| Wallet engine | keys, notes, witnesses, proofs, plans | external inputs without verification |
| Integrating application | user intent and presentation | raw spending secrets |
| Chain source | blocks, txs, UTXOs | canonicality without local check |
| Indexer | discovery acceleration | ownership / balances / recovery |
| Broadcaster | submission | authorization |
| Relayer | fee/broadcast convenience | custody |
| Artifact distributor | artifacts | integrity without hashes |
| Maintainers | specs, releases, advisories | runtime authorization |
| Ceremony participants | setup contributions | toxic waste retention |
| Auditors | scoped findings | blanket guarantees |

## 9. Normative authority

No codebase is the protocol. A released profile is the consistent set of:
versioned spec, manifest, artifact hashes, setup transcript, vectors,
conformance suite, genesis parameters. Disagreement ⇒ fail closed.

## 10. Versioning and migration

- Profile revisions are not mutable (crypto/settlement change ⇒ new id).
- Instance creation ≠ endorsement.
- Migration is explicit public boundary action; no hidden maintainer keys.

## 11. Governance boundary

Maintainers may publish specs, releases, advisories, SDKs, and tooling.
Maintainers may **not** gain protocol authority via admin keys, exclusive
artifact distribution, mandatory APIs, privileged ordering, protocol fees, or
profile mutation. Governance authenticates information; it does not authorize funds.

## 12. Release language

Allowed labels: design draft · evidence experiment · profile candidate ·
Chipnet qualified · mainnet candidate · mainnet qualified.

Prohibited without scoped evidence: “safe,” “anonymous,” “production ready,”
“audited.”

## 13. Charter success condition

Success when independent operators can create and run their own instances (and/or
integrate against authenticated shared instances), recover from BCH history, and
complete valid spends with all optional infrastructure unavailable.

Not sufficient: deploying a demo pool, generating one proof, or publishing an SDK alone.
