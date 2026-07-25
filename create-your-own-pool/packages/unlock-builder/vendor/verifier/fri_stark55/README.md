# FRI-STARK55

## Release status: blocked

This directory is a research demonstrator, not a funded production verifier.
`node fri_stark55/verifier-bench.mjs` is the release-facing gate and is
expected to exit non-zero for the checked-in artifact. `node
fri_stark55/release_gate.mjs` is the shorter fail-closed policy check; it
requires a real `production_manifest.json` and rejects the fixture's Fibonacci
relation, deterministic category, synthetic UTXOs, dummy output, and test
satoshi values.

This directory is a standard-transaction integration of the repaired Circle-STARK
implementation in `../fri_stark/`.

The research script under test is the QM31/L2 split verifier, wrapped in P2SH32:

- Circle-FRI uses the repaired QM31 challenge path and the L2 twin-adjacent pair
  commitment.
- The OOD point is derived from the squeezed QM31 challenge by a rational circle
  parametrization and is checked on-VM; a prover-chosen zeta is rejected.
- The trace columns are merged into one Merkle leaf.
- A leader input performs the H-pinned algebra and full final-codeword binding.
- Five query slots are covered by five position-bound follower inputs.
- A seventh, tokenless library input commits the exact function-table bodies and balanced verifier
  chunks with an ID-and-body hash chain. Followers load those committed bytes with consensus
  `OP_INPUTBYTECODE`/`OP_DEFINE` and invoke them only after pinning the library P2SH32 hash.
- The fixture models P2SH32 spends and carries redeem scripts in unlockings;
  its category, outpoints, values, and recipient are synthetic research data.

The concrete build parameters are `logn=3`, `logBlowup=3`, and `NQ=5`:

```
n = 8, evaluation domain N = 64, final FRI codeword = 8 QM31 cells
inputs = 1 leader + 5 query followers + 1 committed verifier library
```

The security parameter is intentionally not advertised as 128-bit. Five FRI
queries are enough to exercise the complete sound verifier, but they are a
small demonstrator parameter. A provable-128 deployment
requires a query-amortizing PCS change (for example arity-4/vector folding plus
canonical multiproofs); it is not silently inferred from this build.

The current honest vector measures 27,069 bytes across locking/unlocking scripts
and 27,236 bytes serialized, with a 6,992-byte maximum unlocking, 3,178-byte
maximum redeem, and 2,533,067 maximum per-input operation cost. All seven inputs
accept under the standard BCH-2026 VM and the package is below the strict
45,000-byte crown target. This is a compression result, not a production release:
the relation, query count, field security, provenance, and independent evidence
remain research-only and the verifier bench therefore still fails closed. The
heaviest follower uses about 99.95% of its current witness-bound operation budget; that
is a measured consensus pass, not a claim of production headroom.

Those numbers are research measurements only. VM acceptance and a small proof
of a Fibonacci relation do not establish an application statement, real-money
security, or deployment provenance.

## Reproduce

From the repository root:

```bash
node fri_stark55/build.mjs
node fri_stark55/redteam.mjs
node fri_stark55/adaptive_zeta_redteam.mjs
node fri_stark55/verifier-bench.mjs   # comprehensive bench; must fail closed today
node fri_stark55/release_gate.mjs     # production manifest/source policy
```

The build and red-team commands use `createVirtualMachineBch2026(true)` and a fully encoded BCH
transaction. `build.mjs` fails unless every input accepts, every P2SH32 script is
within the standard limits, both the script package and serialized transaction
are below 45,000 bytes, and the operation budget is satisfied. It writes the
honest five-query research vector before that strict size assertion, so an
over-cap run cannot leave behind a lower-query artifact.

`redteam.mjs` checks the JS reference, a false Fibonacci trace, state/target/
challenge/position tampering, P2SH redeem tampering, leader bypass, category and
output-commitment substitution, and a deterministic witness mutation sweep. It
also exits non-zero when the strict crown size gate is blocked, even if every
soundness mutation is rejected.
`adaptive_zeta_redteam.mjs` is a regression for the pre-fix free-zeta forge: it
constructs a false trace with a constant low-degree q and confirms both the JS
reference and every standard BCH input reject it.

`verifier-bench.mjs` additionally runs both standard and strict BCH-2026 VM
evaluation, exact transaction/locking/serialization checks, deterministic
rebuild checks, false-statement and FRI/DEEP/Fiat-Shamir/Merkle mutation
matrices, split-input coverage and P2SH binding mutations, token-category and
NFT-capability substitutions, push-only witness parsing, dynamic-library
commitment/loading mutations, resource ceilings,
and the two independent red-team regressions. It never turns a failing
production gate into a passing score because the local VM accepted a toy proof.
Every research invalid vector is evaluated under both standard and strict
BCH-2026 VM rules.
The L2 transcript regression independently recomputes the merged-trace
challenge prefix and checks that the verifier squeezes the same alpha.
The token mutation matrix includes the previously found input-NFT capability
escalation regression; the repaired covenant rejects it. The missing production
manifest, real application AIR, provenance, and strict size gate remain hard
release blockers.

The experimental shared-witness loader is fail-closed in `buildBundle`; it is not
part of the measured artifact and cannot be selected by an adapter or environment
setting without a separate consensus/resource bench.

### Production manifest contract

When an actual application verifier exists, `production_manifest.json` must be
created by the application owner (it is intentionally absent here). The bench
requires, at minimum:

- a non-fixture application statement and non-empty description, plus SHA-256
  of its normative spec;
- `network: "mainnet"`, the real CashToken genesis tx/category, and real funded
  application UTXOs with mutable NFT capability. Each `fundingUtxos` record must
  also pin `valueSatoshis`, `lockingBytecodeSha256`, `tokenAmount`, and
  `nftCommitmentSha256`; the bench binds the runtime source outputs to those
  exact values. Any tokenless verifier-library UTXO must be explicitly marked
  `role: "library"` and contain no token fields; it is still checked by the
  dynamic-library commitment gate;
- `securityTargetBits >= 128`, `soundnessModel: "provable"`, a soundness bound
  and challenge-field size covering that target, and the actual query count;
- `maxTotalBytes: 45000` plus a separately hashed security certificate that
  derives the bound from the pinned FRI/PCS parameters;
- `proofBinding: "runtime"` plus at least two distinct valid proof artifacts
  accepted by the same locking program;
- an `independentReferenceModule` that is a separate repository-local module
  exporting `verify(bundle)`, is included in the audited source closure, and
  does not import the production adapter;
- a `verifierSourceSha256` map covering every reachable verifier source file
  exactly (no omitted, mismatched, or extra entries);
- reproducible build/vector hashes;
- a hash-pinned dependency/toolchain lockfile (`dependencyLockPath` and
  `dependencyLockSha256`) naming the actual npm/pnpm/yarn lockfile, so
  VM/library versions are part of the release identity;
- at least two independently hashed verifier artifacts, two full-node evidence
  artifacts, an audit reference, and an application test artifact; and
- an adapter module exporting `loadVerifierBench()` when the production vectors
  differ from this research fixture. The adapter returns the bundle shape used
  by the runner, must declare `kind: "production-adapter"`,
  `deploymentStatus: "production"`, the exact manifest `statementId`,
  `statementDescription`, and `statementSpecSha256`, plus matching `queryCount`, `securityTargetBits`,
  `soundnessModel`, and `proofBinding`, and
  must provide an independent valid/invalid differential,
  at least eight labelled, distinct soundness cases covering statement,
  transcript, OOD, FRI, Merkle, coverage, binding, and parser families, plus at
  least twelve labelled, distinct mutation cases spanning at least eight fault
  families. Every invalid case is checked under both standard and strict
  BCH-2026 VM rules, and proof-family invalids must remain consensus-valid so a
  stateless transaction failure cannot masquerade as a soundness result. It
  must also return at least two distinct `extraValid` runtime proofs under the
  same locking set, accepted by both VM modes, plus a byte-identical `rebuildValid`
  vector that matches a second independent `loadVerifierBench()` invocation,
  `reproducible: true`, and
  `provenance: { real: true, mainnet: true, fundingVerified: true }`.

The standalone release gate loads that adapter and enforces the same identity
contract, so a status/label-only promotion cannot pass by skipping the bench.
The production source path also has no environment-selected verifier behavior;
the fold-layer loop is an explicit experimental builder option and is not
silently selected by process environment.
The release source audit likewise rejects the experimental shared-witness path
and fold-loop path until each has a separate consensus/resource audit.

The category is a deterministic test deployment identifier derived from this
project name. A production deployment must replace it with the real genesis
CashToken category before funding the UTXOs; no verifier logic depends on a
secret or a proving key.
