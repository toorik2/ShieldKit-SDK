# G1 verifier baseline observation — FAIL (reproduction qualification only)

Candidate: `bn254-onetx-pf6-a3-r1`; source commit: `26468ae29004d2401619032de2a6ec8de269a4d6`.

The source commit was present and clean. Its current read-only run
`20260723t123647234z-bn254-onetx-pf6-a3-r1-ab74b984c9-12d9febd` is internally
hash-consistent with the frozen baseline: result SHA-256
`98436d26947015206f28f9dca870422f8a60391382fa8c501b9856f947baffca`; complete
transaction-hex SHA-256 `6b19b26edf22477f50fb27fdd9182f6cc1505d3062451abfc00f5a789270570a`.
It reports 54,949 all-bytes score = 54,671 script bytes + 278 transaction
overhead, and 54,739 serialized transaction bytes.

The read-only transaction decoder reports version 2, six inputs, sequence zero,
unlocking sizes `[9853, 9848, 9877, 8893, 7452, 8538]`, one 1,000-satoshi
`OP_RETURN` (`6a`) output, and locktime zero. The six source records each carry
1,000 satoshis and a 35-byte P2SH32 locking bytecode. Four share
`aa20d14ec211559437a077c76e4aad6fb9ba9f48b0827f895a5b9d6f07b47994fa8b87`;
the genesis and terminal locks are recorded in `source-locking-bytecodes.hex`.
Thus the fixture encodes `(6 * 1000) - 1000 = 5000` satoshis miner fee.

The existing-run VM corpus says: honest 6/6 accept; three extra-valid proof
sets 18/18 inputs accept; worst-case 6/6 accepts; off-curve A and B 6/6 each
reject. Its noncanonical-B mutation rejects at genesis, and off-subgroup-B
rejects at terminal. This is observed existing-run evidence, not a newly
regenerated corpus in this worktree.

## Reproduction falsifier

An archived clean copy of the exact commit was used so the source checkout was
not changed. Root `npm ci` and harness `corepack pnpm install --frozen-lockfile`
were successful. The documented command was then run exactly against the
candidate. It first failed because the committed tree omits harness `tsx`; after
harness install it failed because the committed tree omits
`vendor/cashc-resched/packages/cashc/dist/index.js`. Rebuilding the vendor at
the manifest-pinned `1c707c1dbf87396b30ba5e0704b1db44475ce893` unblocked that
missing artifact, but the build then terminated before gate evaluation with
`Error: ProjectivePoint expected` during ECIP generation. No `gateOk=true`
artifact was regenerated.

This independently falsifies the requested clean pinned-source reproduction;
therefore the evidence record verdict is `FAIL`. It does not invalidate the
read-only observed fixture measurements, but they remain unqualified for a
reproducible G1 baseline.

## G1 support boundary

Supported only as read-only research observation: a fixed six-input BN254
Groth16/P2SH32 transaction with the stated byte figures and local BCH-2026 VM
corpus. Not supported: G1 PASS, current peer behavior, standard relay at the
baseline fee, complete transaction envelope headroom, profile-bundle binding,
fresh development setup, second-bundle replacement, ceremony provenance, or
production/release readiness.

The candidate manifest is explicitly `research` and declares
`vkBinding: fixed` and `deploymentBinding: fixed`. That is hardcoded verifier
material, not the required typed, provenance-bound shield.cash verifier bundle.

## Small extracts

The four files beside this report are small transcriptions for local review;
their local hashes are in `local-extracts.sha256`, while authoritative source
paths and SHA-256 values are in `observation.json`.
The 54,739-byte transaction hex and 1.6 MB red-team vectors were deliberately
not copied.
