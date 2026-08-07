# Model

ShieldKit is easiest to understand as four objects:

| Object | Meaning |
| --- | --- |
| **Toolkit** | Mutable source, CLI, tests, and local runtime |
| **Profile** | Immutable relation, verifier, encodings, artifacts, and policy identity |
| **Instance** | One on-chain pool genesis using one profile |
| **Data home** | Private local wallet, notes, journal, runtime, and recovery state |

Toolkit versions may change without changing an instance. A profile or setup
change requires a new profile identity and a new genesis. Instances never merge
their anonymity sets.

## Flow

```text
owner
  │
  ├── private wallet + data home
  │
  ▼
ShieldKit CLI ── selects one profile ──► prover + transaction builder
  │                                           │
  ├── verifies provider responses locally     └── exact proof-bound action
  ▼
Chipnet provider(s) ─────────────────────────► BCH transaction graph
```

Secrets and proofs are produced locally. Providers may supply chain data and
broadcast bytes, but they do not authorize a spend. BCH history, the immutable
profile, and locally verified state transitions are the public authority.

## Pool lifecycle

Each deposit, transfer, or withdrawal spends the current state and creates its
successor in one BCH transaction. The current state is a serial writer: if
another action wins the race, the losing client must refresh and re-prove
against the new state.

- **Create** establishes a profile-specific instance and initial state.
- **Deposit** creates a shielded note from a transparent boundary input.
- **Transfer** replaces an owned note without leaving the shielded set.
- **Withdraw** spends a note to a transparent external address.
- **Delivery recovery** inspects a recorded send and permits only explicit
  exact-byte rebroadcast. Native recovery components can reconstruct eligible
  material from authenticated history, but they are not the root command.

## Repository shelves

- **Product** contains current PF10 user guidance.
- **Lab** describes executable research without a support or portability promise.
- **Record** preserves specs, evidence, decisions, and dated results.
- **Vendor** documentation belongs to its upstream source and is not part of the
  ShieldKit navigation.
- **Archive** is historical and never a current setup path.

This separation keeps volatile status out of immutable profile and evidence
records. See [the Record index](../record/README.md) for the deeper material.
