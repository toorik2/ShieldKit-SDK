# Open decisions

Document version: 0.2

Status: Gate G0 decision register

## 1. Decision vocabulary

- **LOCKED**: accepted as part of the current charter. Changing it requires a
  charter revision and gate invalidation.
- **DEFAULT**: the current choice; G0 must ratify or replace it.
- **OPEN**: no choice is yet justified.
- **MEASURED**: the choice may be made only from evidence at the listed gate.
- **DEFERRED**: explicitly outside the current gate; it cannot silently become a
  requirement of the frozen build.

## 2. Locked direction

| ID | Status | Decision |
| --- | --- | --- |
| D-001 | LOCKED | Build a narrow BCH shielded-transfer standard, not a generic privacy framework |
| D-002 | LOCKED | Wallet/application integration with shared instances is the primary workflow |
| D-003 | LOCKED | “Deploy your own pool” is not the primary SDK workflow |
| D-004 | LOCKED | Required proving and secret handling are local |
| D-005 | LOCKED | BCH history and authenticated genesis data are protocol authority |
| D-006 | LOCKED | Indexers, relayers, coordinators, provers, broadcasters, and artifact hosts are optional and untrusted |
| D-007 | LOCKED | No maintainer runtime, pause, custody, sequencing, fee, or upgrade authority |
| D-008 | LOCKED | Specification, profile manifest, artifacts, vectors, and conformance evidence jointly define a release |
| D-009 | LOCKED | Existing implementation code is evidence only and receives no grandfathered authority |
| D-010 | LOCKED | Promotion is gate-driven rather than calendar-driven |
| D-011 | LOCKED | Initial fee sizing uses verifier.cash candidate `bn254-onetx-pf6-a3-r1`: 54,949 all-bytes score and 54,739 serialized settlement bytes |
| D-012 | LOCKED | “Can’t do evil”: after authenticated genesis, no maintainer, key, service, or governance process can pause, rescue, upgrade, reorder, censor, or otherwise authorize protocol transitions |
| D-013 | LOCKED | Every V1 action uses one transparent fee input and one canonical change output; the pool reserve never subsidizes miner fees |
| D-014 | LOCKED | The engineering target is a working end-to-end protocol instance on BCH Chipnet; mainnet deployment is not authorized |
| D-015 | LOCKED | Verifier material is supplied through a versioned profile bundle: local setup is development-only; a multi-party-ceremony replacement creates a new immutable profile and instance |

## 3. G0 defaults requiring ratification

| ID | Status | Default | Why it is the default | What would change it |
| --- | --- | --- | --- | --- |
| Q-001 | LOCKED | BCH is the only V1 asset | Smallest reserve, circuit, wallet, and privacy surface | A charter revision |
| Q-002 | LOCKED | Fixed-denomination notes | Removes private amount arithmetic and simplifies containment | A charter revision |
| Q-003 | LOCKED | Deposit, private transfer, withdrawal | A developer standard needs more than mixer-style exits | G2 may kill private transfer as infeasible |
| Q-004 | LOCKED | One profile and a small authenticated set of shared instances | Concentrates review and anonymity | G6 evidence may require a charter revision |
| Q-005 | LOCKED | On-chain encrypted note data | Enables independent recovery | A charter revision backed by G5 evidence |
| Q-006 | LOCKED | No protocol fee | Avoids maintainer incentives and control | A charter revision |
| Q-007 | LOCKED | Immutable profiles; changes create a new profile | Prevents hidden upgrades | A charter revision |
| Q-008 | LOCKED | Desktop, browser, and Android are required local targets | Wallet integration should not imply a desktop-only service | A charter revision |
| Q-009 | LOCKED | Profile artifacts at most 512 MiB compressed | Larger downloads materially damage wallet integration | A charter revision with stricter or explicitly re-ratified budgets |
| Q-010 | LOCKED | At least five percent BCH envelope headroom | Avoids qualifying a boundary-only construction | A charter revision with stricter headroom |

## 4. Open product decisions

### Q-011 — primary integration persona

**Status:** LOCKED

The first reference integrator is a developer building a user-facing BCH wallet
or application. Infrastructure-library developers are supported secondarily,
but their workflow does not define the product boundary.

This choice fixes the required local secret, sync, proving, transaction-building,
recovery, and failure-diagnostic interfaces.

### Q-013 — denomination

**Status:** LOCKED

V1 uses one fixed denomination: **0.1 BCH (10,000,000 satoshis)**.

Multiple denominations are multiple anonymity sets unless the protocol proves a
different construction.

### Q-014 — privacy claim

**Status:** LOCKED

V1 claims blockchain unlinkability only: against a passive observer using BCH
consensus-visible data, the link between qualifying 0.1 BCH deposits or notes,
private transfers, and withdrawals should be computationally hidden within the
compatible candidate set. Network anonymity and deductions from small candidate
sets or external information are explicitly excluded.

The precise claim, conditions, non-claims, and leakage matrix are normative in
[PRIVACY.md](PRIVACY.md).

### Q-015 — selective disclosure

**Status:** DEFERRED, owner: future profile work

Selective disclosure is not a requirement of the initial build. If pursued, it
must enter through a separately versioned profile decision; it cannot be added
to the frozen V1 relation by implementation drift.

## 5. Measured protocol decisions

### Q-016 — proof system

**Status:** MEASURED, owner: Gate G1

Default candidate: BN254 Groth16 because it is the only locally evidenced
standard-transaction verifier family. It is not selected until current,
reproducible, full-byte evidence establishes the remaining pool budget.

The initial fee and envelope baseline is verifier.cash research candidate
`bn254-onetx-pf6-a3-r1` at commit
`26468ae29004d2401619032de2a6ec8de269a4d6`:

- 54,671 script bytes;
- 278 transaction-overhead bytes;
- 54,949 all-bytes verifier score;
- six 35-byte P2SH32 source locking bytecodes; and
- 54,739 implied serialized transaction bytes.

A local reproduction on 2026-07-23 produced `gateOk=true`, six of six accepting
real VM inputs, result SHA-256
`98436d26947015206f28f9dca870422f8a60391382fa8c501b9856f947baffca`,
and transaction-hex SHA-256
`6b19b26edf22477f50fb27fdd9182f6cc1505d3062451abfc00f5a789270570a`.

The manifest labels the candidate `research`. Its fixture spends six 1,000-sat
source outputs to one 1,000-sat output, encoding only a 5,000-sat fee. It is not
evidence of default-fee peer relay, a complete protocol action, or a qualified
verifier release.

The initial Chipnet profile may use a freshly generated local Groth16 setup, but
only through the standard verifier-bundle interface and only with
`setupMode: development-only`. Its manifest must bind the relation, constraint
system, public-input ABI, verification key, proving artifacts, and BCH verifier
scripts by hash; record the exact generation command and pinned toolchain; and
prohibit ceremony-backed or production claims.

A later `ceremony-production` bundle must implement the same interface and add
the complete multi-party-randomness transcript and contribution-verification
evidence. It necessarily has a new profile identifier and genesis. Compatibility
means wallet and conformance semantics do not require a rewrite; it does not
permit mutation of an existing instance.

Required comparison dimensions:

- complete transaction bytes;
- operation-density headroom;
- number and type of setup assumptions;
- proving-key size;
- target-device proving time and memory;
- public-input and profile binding;
- circuit upgrade cost; and
- independent implementation maturity.

### Q-017 — action cardinality

**Status:** MEASURED, owner: Gate G2

The action shape must be fixed or canonically padded, but exact input/output
cardinality is not chosen in the charter.

Selection must jointly optimize:

- note consolidation and change;
- arity privacy;
- circuit constraints;
- encrypted data size;
- proving performance; and
- complete BCH transaction size.

### Q-018 — state representation

**Status:** MEASURED, owner: Gate G2

Default candidate:

- unique mutable CashToken NFT identifies the instance;
- visible P2S locking bytecode pins the profile;
- up to 120 commitment bytes encode note root, nullifier root, counters, and
  versioned state; and
- the reserve and successor state are enforced in the same transaction.

The measured alternative must improve binding, availability, liveness, or byte
cost without adding off-chain authority.

### Q-019 — exact binding topology

**Status:** MEASURED, owner: Gates G2 and G3

How does successful proof verification authenticate the exact state transition
across independently executed BCH inputs?

The answer must cover:

- exact source scripts and values;
- verifier carriers;
- binding/action data;
- state input and successor;
- withdrawal outputs;
- fees and change;
- input/output indices; and
- substitution with distinct accepting scripts.

Naming or ordering an input is not authentication.

### Q-020 — state contention

**Status:** MEASURED, owner: Gate G6

Default candidate: one canonical state UTXO, permissionless direct actions, and
an optional untrusted coordinator that only reduces races.

Measure:

- stale-proof rate;
- proof reuse or rebase feasibility;
- mempool chaining;
- adversarial conflict and pinning;
- retry cost;
- confirmation throughput; and
- privacy effects of coordination.

If target throughput exceeds the serialized design, the project must decide
between batching, lanes, a new accumulator design, or stopping.

### Q-021 — fee funding

**Status:** LOCKED default; MEASURED at Gate G6

Every V1 action carries one ordinary, user- or sponsor-controlled transparent
BCH fee input and one canonically positioned change output. Verifier-carrier
input values also contribute to the transaction fee. The pool reserve does not
subsidize miner fees, no protocol fee exists, and no relayer is required.

The exact fee input, carrier values, change, and resulting miner fee are bound to
the action transaction. The fee payer need not be the note owner. Wallets must
warn that transparent fee funding can correlate the payer with the action.

Starting fee estimates use the baseline's serialized transaction size, never
its all-bytes verifier score:

`54,739 bytes × 1 sat/byte = 54,739 satoshis = 0.00054739 BCH`

This is 0.54739% of one 0.1 BCH note. It is the default-minimum relay estimate
for the verifier transaction alone. Preparation transactions, protocol state,
encrypted records, boundary outputs, fee inputs, and higher node or mempool fee
floors are additional and must be measured at G6. The current research fixture's
5,000-sat encoded fee is 49,739 satoshis short of this estimate.

### Q-022 — verifier-carrier preparation

**Status:** MEASURED, owner: Gate G6

Who constructs and funds the source outputs required by a distributed
verifier?

Required properties:

- permissionless deterministic creation;
- no exclusive inventory;
- no theft or substitution;
- bounded preparation cost;
- safe reuse only if explicitly proven; and
- deterministic recovery after conflicts or reorgs.

### Q-023 — root history and unilateral progress

**Status:** MEASURED, owner: Gates G5 and G6

Choose the accepted-root and witness-update model. It must define:

- confirmed versus unconfirmed roots;
- root-history depth;
- stale note witnesses;
- reorg rollback;
- state-censorship behavior; and
- whether a user can progress without a coordinator.

### Q-024 — proving implementation

**Status:** MEASURED, owner: Gate G4

Default architecture: one typed native core compiled to WASM, with TypeScript
bindings and an independent reference checker.

The implementation must show:

- canonical byte behavior;
- secure randomness;
- verifier-bundle loading, profile selection, and hash verification without
  hardcoded keys;
- browser/mobile packaging;
- memory cleanup limitations;
- reproducible native and WASM builds; and
- cross-language vectors.

## 6. Governance and operational decisions

### Q-025 — profile authentication

**Status:** DEFERRED, owner: Gate G8

Define how clients authenticate:

- the standard release;
- the profile manifest;
- security advisories;
- genesis instance metadata; and
- profile deprecation.

Signatures may authenticate maintainer statements but cannot create runtime
spend or upgrade authority. BCH-authenticated metadata and content hashes should
be evaluated.

### Q-026 — artifact durability

**Status:** OPEN, owner: Gates G5 and G8

Define how a user obtains proving artifacts years later if all current project
infrastructure disappears.

The answer must include reproducibility, verified setup material,
content-addressing, multiple independent distribution paths, offline bundles,
and failure behavior.

### Q-027 — incident response and reserve cap

**Status:** LOCKED for authority; MEASURED at Gate G9

No pause, rescue, administrator, or upgrade path exists after genesis. A defect
cannot give maintainers new authority over an existing instance.

The build must support an immutable maximum reserve selected at genesis. The
exact Chipnet or mainnet value is a G9 qualification decision, not a reason to
delay the protocol candidate.

Define:

- candidate and mainnet exposure caps;
- circuit, setup, wallet, and covenant incident classes;
- public advisory authentication;
- profile deprecation;
- migration without hidden authority; and
- behavior when migration is impossible.

### Q-028 — organizational and legal boundary

**Status:** LOCKED for operations

shield.cash is publisher-only: specifications, SDKs, artifacts, conformance
tooling, documentation, and reference source. It does not operate public
indexers or RPC services, relayers, broadcasters, coordinators, hosted provers,
artifact servers, Chipnet endpoints, or a consumer transaction application.
It receives no protocol fee and has no required runtime role.

Jurisdiction-specific legal analysis is deliberately deferred to G9, before
release. “Protocol” remains a technical description, not a legal conclusion.

## 7. G0 completion checklist

G0 may be proposed for PASS only when:

- Q-011, Q-013, Q-014, Q-027, and Q-028 are resolved;
- Q-016 through Q-024 and Q-026 have explicit evidence owners and test plans;
- resource budgets are ratified;
- the leakage matrix in [PRIVACY.md](PRIVACY.md) is accepted;
- the provider trust map is accepted; and
- the publisher-only maintainer boundary is accepted.
