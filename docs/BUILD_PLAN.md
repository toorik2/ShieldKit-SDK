# Executable build plan

Document version: 1.1

Status: active under the `g0-v2` freeze

## Outcome

Build a narrow BCH shielded-transfer standard for fixed 0.1 BCH notes, together
with a local wallet/prover SDK and a rigorous conformance lab. The required path
must work without shield.cash-operated infrastructure and without any
post-genesis administrator, pause, rescue, sequencing, fee, or upgrade
authority.

The concrete engineering target is a live BCH Chipnet instance that completes
real deposit, private-transfer, withdrawal, recovery, and reorg-safe wallet
flows. Mainnet deployment is not part of this plan.

The work is complete only when the specification, real cryptography, BCH
settlement, SDK, recovery path, adversarial corpus, and reproducible evidence
agree for the same frozen profile. Scaffolding, projections, synthetic
acceptance, or isolated script success do not count.

## Fixed inputs

- Primary integrator: a user-facing BCH wallet or application.
- Asset and denomination: BCH, fixed 0.1 BCH notes.
- Actions: deposit, one-note private transfer, and withdrawal. Other
  cardinalities remain measured candidates.
- Privacy claim: blockchain unlinkability as defined in
  [PRIVACY.md](PRIVACY.md).
- Required clients: desktop, browser, and Android under the ratified budgets.
- Fee model: one transparent fee input plus one canonical change output;
  verifier-carrier values may also fund the miner fee.
- Initial verifier sizing baseline: 54,949 all-bytes score and 54,739 serialized
  settlement bytes from verifier.cash candidate `bn254-onetx-pf6-a3-r1`.
- Verifier material: one typed, versioned profile bundle. The initial Chipnet
  build may use freshly generated local setup only as `development-only`; a
  later multi-party-ceremony bundle uses the same interface but creates a new
  profile and genesis.
- Operational model: publisher-only and completely hands-off after genesis.
- Evidence boundary: the archived prior repository is read-only research input,
  never protocol authority.

## Execution sequence

### B1 — pass or fail G1

Run these workstreams in parallel where they do not share write ownership:

1. **BCH policy and node reality**
   - Pin current consensus and standardness rules from primary sources.
   - Reproduce relevant behavior on two unmodified BCHN peers.
   - Record transaction, input-bytecode, P2S, token, stack, and VM-density
     limits with exact versions and commands.

2. **Verifier and fee envelope**
   - Rebuild the pinned verifier candidate byte-for-byte.
   - Specify the versioned verifier-bundle manifest and loader interface.
   - Generate a fresh `development-only` setup, verification key, proving
     artifacts, and BCH verifier scripts from pinned tools.
   - Prove that a second independently initialized bundle changes the profile
     identifier and genesis without changing wallet or conformance semantics.
   - Decode and score the complete settlement wire and every source output.
   - Build the permissionless carrier-preparation transaction.
   - Add the transparent fee input and canonical change output.
   - Test whole-transaction standardness and calculate preparation plus
     settlement fees at explicit feerates.

3. **Proof-system and prover feasibility**
   - Define the minimum real relation needed to represent the three actions.
   - Generate real BN254 Groth16 artifacts from pinned tools.
   - Benchmark witness generation and proving on representative desktop,
     browser, and Android-class hardware.
   - Compare alternatives only when real artifacts and complete BCH
     transactions exist.

4. **Envelope budget**
   - Allocate every byte and operation to verifier, state, action data,
     encryption, fees, change, and safety margin.
   - Reject any candidate that cannot retain the G2 headroom.

G1 ends with a reproducible PASS package or an explicit proof that the selected
profile is infeasible. A failed candidate triggers a bounded alternative, not a
weakened evidence bar.

### B2 — freeze one exact G2 candidate

Create one internally consistent candidate containing:

- normative canonical encodings and domain separation;
- note, key, commitment, nullifier, tree, and encryption definitions;
- independent reference transition logic;
- real deposit, transfer, and withdrawal relations;
- proving and verifying keys with setup provenance;
- a typed verifier-bundle manifest with an explicit setup mode;
- immutable genesis/profile/instance manifests and maximum reserve;
- exact BCH preparation and settlement transaction templates;
- proof-to-transaction, source-script, value, token, fee, and successor binding;
- deterministic transaction construction;
- chain-only encrypted-note discovery and recovery; and
- a versioned artifact manifest with content hashes.

Then execute the complete candidate in standard BCH transactions. G2 requires
the full valid corpus, negative mutation matrix, zero unscored bytes, and the
quantitative limits in [KILL_GATES.md](KILL_GATES.md).

The first Chipnet candidate may be built from a `development-only` bundle. A
later `ceremony-production` bundle must pass through the same interface, receive
a new profile identifier and genesis, and rerun every artifact-dependent gate;
it is not an upgrade to the development instance.

### B3 — close G3 through G6 in parallel

After the G2 freeze, use four isolated workstreams:

- **G3 soundness:** relation review, whole-transaction substitution attacks,
  malformed encodings, adversarial witnesses, fuzzing, differential checks,
  libauth/BCHN/LeanBCH agreement, and zero false accepts.
- **G4 local SDK:** typed core, native/WASM bindings, local proving, secure
  randomness, wallet state, transaction planning, persistence, packaging, and
  target-device benchmarks.
- **G5 recovery:** raw BCH history scan, note decryption, witness rebuild,
  reorg rollback, provider-equivocation tests, and recovery with every optional
  service absent.
- **G6 liveness and fees:** state races, stale proofs, retries, carrier
  preparation, fee variation, griefing, mempool behavior, and coordinator
  disappearance.

No workstream may silently change the G2 candidate. Any candidate change
invalidates all affected evidence and reopens the appropriate gates.

### B4 — interoperability and operational independence

Close G7 and G8 with:

- an independent decoder/reference checker;
- canonical cross-language vectors;
- public conformance and adversarial runners;
- mutually compatible wallet/application integrations;
- measured privacy leakage for exact transaction behavior;
- replaceable chain-provider interfaces and fault injection;
- offline, reproducible verifier bundles with setup-transcript verification;
  and
- authenticated, content-addressed release inputs with no runtime authority.

### B5 — live Chipnet target and qualification boundary

After all prerequisite local and node gates pass:

1. generate a fresh Chipnet funding address using the repository's locally
   controlled test wallet;
2. calculate the exact requested amount and explain what each output and fee
   funds;
3. ask the user to fund that address and wait for confirmation;
4. deploy the authenticated Chipnet profile and instance;
5. execute real deposit, private transfer, withdrawal, contention, recovery,
   and reorg tests; and
6. persist transaction IDs, raw transactions, node verdicts, artifact hashes,
   and the final Chipnet conformance report.

Do not request coins before the candidate, scripts, wallet, expected
transactions, and amount calculation are ready. Never expose or transmit the
wallet seed or private keys.

Prepare the remaining G9 technical dossier, but do not deploy mainnet instances,
publish mainnet or legal qualification claims, operate services, request
external legal conclusions, or perform other externally consequential release
actions without explicit authorization.

## Required repository shape

The exact package layout may evolve through measured evidence, but the result
must cleanly separate:

- `spec/` — normative protocol and encoding definitions;
- `packages/core/` — deterministic typed reference logic;
- `packages/sdk/` — wallet-facing native/WASM/TypeScript API;
- `circuits/` — real relations and reproducible artifacts;
- `bch/` — preparation, settlement, and covenant construction;
- `conformance/` — vectors, independent decoding, mutation, and differential
  runners;
- `evidence/` — immutable gate records and raw measurements; and
- `policy/` — gate state and the G0 drift lock.

## Local completion standard

Do not stop at a plan, scaffold, compile success, or one happy-path proof.
Continue until every in-scope engineering deliverable above exists, all locally
executable gates pass for the same artifacts, and the live Chipnet flow passes
end to end. The expected user-funded Chipnet step is a temporary coordination
point, not a reason to weaken or prematurely terminate the goal.
