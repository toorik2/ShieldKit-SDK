# Android local-prover harness

This is a fail-closed, physical-Android/Termux execution harness for the exact
caller-pinned Groth16 artifacts. It only accepts USB `adb`, direct regular files
with SHA-256 pins, the fixed `/data/local/tmp/shield-cash` staging root, and the
three canonical low128 action public signals. It rejects duplicate-key JSON,
uses role-and-hash remote names (never basenames), verifies every staged file
and the generated runner before each action, and rechecks the pinned `adb`
binary around every call. It never fetches artifacts or contacts a prover
service. The on-device runner invokes only the caller-supplied native prover
and pinned local `snarkjs`, then verifies each proof locally.

It is intentionally unmeasured until a real Android runtime is attached. Run
the package tests locally with `npm --prefix packages/android-prover-harness test`.
For a measurement, create an absolute-path manifest from the known v0 hashes,
ensure an Android-native prover and Node/snarkjs are already installed locally
on the USB-attached device, then call `runAndroidProverHarness`. Its RSS result
is only direct native-prover `VmRSS` sampled by an `adb` shell: it is feasibility
telemetry, not frozen Android app/process-tree RSS. An instrumented Android app
on a fixed fixture is still required for G4's 120-second, 1.5-GiB, and p95 gates.
Do not label a one-run result p95 or G4 qualification.
