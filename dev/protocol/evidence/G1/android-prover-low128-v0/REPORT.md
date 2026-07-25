# G1/G4 Android local prover: low128 v0

Status: **NOT MEASURED**.

The workspace has no Android SDK/NDK, `adb`, emulator, AVD manager, Gradle, or
attached physical device. Consequently no Android runtime was used, no proof,
witness, timing, RSS, public-signal hash, or independent verification was
generated, and this report is not a schema evidence observation or a PASS/FAIL
gate record. The command output inventory is retained in `raw/tool-inventory.txt`.

`packages/android-prover-harness` is reusable execution infrastructure only. It
requires USB `adb`, direct SHA-256-pinned regular files, no remote artifact
retrieval, an Android-local native prover and local snarkjs verifier, bounded
command output, input identity rechecks, and cleanup of its unique staging
directory. It does not create witnesses, setup material, network calls, BCH
transactions, broadcasts, or production claims.

To obtain an initial measurement on a real device, attach it by USB and run
`adb devices -l`; prepare a manifest pinning the exact development-only v0
zkey (`37a7ee2fe9e7ee1e2583d60e0e52d86360d7c7a7be5b23dbb0cc166bb5905453`),
verification key, native Android prover, pinned snarkjs, and three exact corpus
witnesses. Execute the harness, then separately record build fingerprint,
elapsed time, peak app/process RSS measurement scope, proof and public-signal
hashes, and local independent verifier result. Compare each initial run with
the Android targets of 120 seconds and 1.5 GiB; p95 requires a fixed fixture
and a qualifying distribution. The harness's adb-shell prover `VmRSS` sampler
is feasibility telemetry only: it cannot satisfy the frozen Android app RSS
requirement without an instrumented app/process-tree measurement.
