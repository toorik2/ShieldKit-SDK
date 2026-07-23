# Gate-driven roadmap

Document version: 0.2

Status: active planning map

Scheduling rule: dependencies and evidence determine progression, not dates

## 1. Critical path

```text
Charter and product freeze
          |
          v
Current BCH + verifier feasibility
          |
          v
Exact complete settlement envelope
          |
          +----------------+----------------+----------------+
          |                |                |                |
          v                v                v                v
 Relation/VM         Local wallet     Recovery/DA     Liveness/fees
 soundness           and prover
          |                |                |                |
          +----------------+----------------+----------------+
                           |
                           v
              Privacy + interoperability
                           |
                           v
            Operational independence/supply chain
                           |
                           v
                  Profile qualification
```

The project must not build upward around a failed lower dependency.

## 2. Phase A — direction freeze

Entry: current repository state

Exit: G0 PASS

### Deliverables

- ratified [charter](CHARTER.md);
- resolved G0 entries in [open decisions](OPEN_QUESTIONS.md);
- privacy adversary and leakage matrix;
- provider and organizational role map;
- incident and failure-containment defaults;
- evidence-record schema; and
- RFC/decision-change procedure.

### Forbidden work

Before G0 passes, do not add:

- circuits;
- covenants;
- SDK packages;
- proving artifacts;
- hosted services;
- deployment tooling; or
- compatibility promises.

Small read-only probes used to resolve G0 are allowed and recorded outside the
future protocol source tree.

### G0 decision meeting

The direction freeze should produce explicit answers to:

1. Who is the first reference integrator?
2. What is the V1 privacy claim?
3. Which client platforms are required?
4. What denomination and action set are being tested?
5. What infrastructure, if any, will maintainers actually operate?
6. Which facts would cause the project to stop?

## 3. Phase B — feasibility laboratory

Entry: G0 PASS

Exit: G1 PASS and one frozen G2 candidate

This phase creates evidence experiments, not a protocol implementation.

### Workstream B1 — BCH execution surface

- pin current BCH specifications and BCHN releases;
- probe standardness and consensus limits on live current nodes;
- reproduce P2S, token commitment, input size, and transaction-size behavior;
- define the complete all-bytes scoring model;
- cross-check libauth and LeanBCH behavior; and
- publish raw node/VM evidence.

### Workstream B2 — proof-system envelope

- reproduce verifier.cash candidate `bn254-onetx-pf6-a3-r1` from pinned commit
  `26468ae29004d2401619032de2a6ec8de269a4d6` as the initial 54,949-byte
  score baseline;
- define the versioned verifier-bundle interface and authenticated manifest;
- generate two independently initialized `development-only` bundles and prove
  that they create distinct profile identifiers and genesis data without
  changing wallet or conformance semantics;
- distinguish public-bench, fixed-context, and research-only evidence;
- measure complete proof and public-input variation;
- compare any alternative only through real standard transactions;
- allocate byte and VM budgets to proof, state, action data, encryption, and
  fees; and
- select or reject the proof system at G1.

### Workstream B3 — protocol-kernel experiments

Build independent, disposable experiments for:

- canonical action envelope and digest binding;
- 128-byte-or-less state commitment;
- note commitment and spend-authority relation;
- note tree and nullifier update;
- encrypted recipient recovery record;
- exact transaction role binding;
- preparation transaction and verifier carriers; and
- deposit, transfer, and withdrawal accounting.

No experiment is copied into the protocol candidate by default. Requirements
and evidence are carried forward; code is reviewed as new work.

### Workstream B4 — local proving budget

Before freezing G2:

- generate representative full-relation proving artifacts;
- benchmark cold and warm proving on every G0 target;
- record compressed artifact size, verification time, witness time, proof time,
  peak memory, and failure behavior; and
- stop if the required local flow cannot meet the G0 budgets.

### Phase B exit package

The G2 candidate package must identify one exact:

- relation;
- compiler and toolchain;
- action ABI;
- proof/VK/setup;
- state encoding;
- BCH topology;
- encrypted record;
- fee behavior; and
- artifact manifest.

Only this frozen package may enter downstream gates.

## 4. Phase C — protocol candidate

Entry: G2 PASS

Exit: G3, G4, G5, and G6 PASS

### Workstream C1 — normative protocol

- specify byte encodings from first principles;
- specify keys, notes, commitments, nullifiers, trees, and encryption;
- specify actions, state transitions, public boundaries, and fees;
- specify profile and instance manifests;
- specify BCH preparation and settlement transactions;
- specify recovery, reorg, and pending-state behavior; and
- specify every rejection rule.

### Workstream C2 — relation and BCH settlement

- implement the full frozen relation;
- compile exact scripts and verifier artifacts reproducibly;
- generate valid, invalid, and transaction-mutation corpora;
- build independent reference transition logic;
- prove exact role and script binding;
- cross-check complete transactions in current nodes, libauth, and LeanBCH; and
- fuzz parsers, circuits, scripts, and builders.

### Workstream C3 — local wallet engine

- typed core implementation;
- deterministic seed/key/address derivation;
- encrypted note store;
- chain scanner and witness maintenance;
- local prover and artifact verifier;
- transaction planner;
- pending-action and conflict manager;
- reorg-safe persistence;
- native, WASM, browser, and Android packaging; and
- a capability-limited application API.

### Workstream C4 — recovery and liveness

- raw-node recovery from genesis;
- optional verified indexer adapter;
- 10,000-transition recovery corpus;
- root history and reorg tests;
- 100-client contention test;
- preparation inventory and griefing tests;
- fee-source privacy and conservation tests; and
- coordinator disappearance and malicious behavior tests.

### Phase C promotion rule

No SDK package may be described as a shield.cash implementation until all four
gates pass for the same frozen G2 candidate.

## 5. Phase D — interoperability and operational independence

Entry: G3, G4, G5, and G6 PASS

Exit: G7 and G8 PASS

### Deliverables

- second independent decoder/reference implementation;
- canonical cross-language vectors;
- public conformance runner;
- two independent application integrations;
- privacy leakage and anonymity analysis;
- self-hosted raw-BCHN integration path;
- at least two chain-provider implementations;
- fault-injection provider suite;
- reproducible offline artifact bundle;
- three independent artifact distribution paths;
- authenticated profile/instance registry design; and
- supply-chain, release-signing, and advisory procedures.

### Provider kit boundary

Only after the required self-hosted path passes may the repository publish
optional provider implementations:

- indexer;
- broadcaster;
- relayer;
- coordinator;
- artifact mirror; and
- health/observability service.

Each implementation must ship with a statement of:

- what it observes;
- what it can censor or delay;
- what it cannot forge;
- how clients verify it;
- how to replace it; and
- how the protocol behaves when it disappears.

No provider is bundled as a silent default.

## 6. Phase E — profile qualification

Entry: G7 and G8 PASS

Exit: G9 PASS

### E1 — profile freeze

- freeze normative specification and profile manifest;
- freeze circuit, scripts, VK, action ABI, and source topology;
- publish deterministic build environments;
- generate final test vectors;
- independently reproduce every artifact hash; and
- invalidate every prior candidate identifier.

### E2 — setup and audits

- run and verify the circuit-specific setup ceremony;
- publish transcript, contribution validation, and final artifact derivation;
- complete independent cryptographic/circuit audit;
- complete separate BCH/wallet/provider audit;
- resolve findings; and
- rerun every affected gate.

### E3 — Chipnet qualification

- meet the exact G9 volume and integration thresholds;
- include all valid and adversarial transactions through independent nodes;
- perform complete seed-only recovery using two implementations;
- exercise coordinator, indexer, relayer, mirror, and broadcaster failures;
- rehearse circuit, artifact, provider, and wallet incident procedures; and
- publish a qualification dossier with raw evidence.

### E4 — mainnet candidate

- define immutable profile and instance identifiers;
- publish reserve/exposure cap;
- publish exact risk and privacy statements;
- publish migration and deprecation behavior;
- complete jurisdiction-specific operational review;
- publish offline recovery and artifact packages; and
- obtain G9 PASS for the exact release.

Mainnet creation is a separate explicit decision after qualification. G9 PASS
does not itself authorize a deployment.

## 7. Planned repository evolution

### Current, before G0

```text
README.md
docs/
  CHARTER.md
  KILL_GATES.md
  OPEN_QUESTIONS.md
  ROADMAP.md
```

### After G0

```text
docs/
evidence/
  schema/
  G1/
experiments/
```

Experiments are non-normative and disposable.

### After G2

```text
spec/
profiles/
conformance/
reference/
wallet-core/
sdk/
```

Exact language/package layout is selected only after the G4 portability
experiment. The archived implementation’s package layout is not a default.

### After G8

```text
providers/
  indexer/
  broadcaster/
  relayer/
  coordinator/
  artifact-mirror/
```

Provider packages remain optional and independently removable.

## 8. Evidence import policy

The archived evidence lab is:

`/home/toorik/Projects/ZK-Proofs/shield.cash-evidence-20260723T121421Z`

Historical material may be imported only as a new evidence record containing:

- original path and hash;
- original source/toolchain provenance;
- the claim it actually supports;
- explicit non-claims;
- current reproduction command and result;
- current node/VM cross-check;
- applicable gate; and
- reviewer disposition.

No source code is copied merely because it already exists. Any reused algorithm
or encoding must first appear as a ratified requirement, then be independently
implemented or reviewed against the specification.

## 9. Immediate next actions

G0 is frozen. The current work sequence is:

1. reproduce current BCH policy and node behavior;
2. independently reproduce and qualify the pinned 54,949-byte verifier score
   baseline;
3. specify and measure the complete preparation-plus-action fee envelope;
4. allocate the 95,000-byte complete-action budget;
5. benchmark a representative full-relation local prover; and
6. pass or fail G1 before freezing a G2 candidate.

## 10. Stop conditions

The project should stop or rewrite the charter if evidence establishes that:

- a complete action cannot fit the standard BCH envelope with margin;
- required local proving is not viable on target wallets;
- chain-only note recovery is not achievable;
- safe liveness requires an exclusive coordinator;
- the only usable product is isolated per-application pools;
- optional services become de facto protocol authorities;
- the privacy claim requires an unrealistic population or behavior; or
- maintainers cannot sustainably support the audit, setup, supply-chain, and
  incident-response obligations.

Stopping at a failed gate is a successful use of the roadmap.
