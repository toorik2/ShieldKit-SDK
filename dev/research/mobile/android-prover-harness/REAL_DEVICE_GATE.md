# Android G4 real-device gate

This repository contains Android-library source under
`dev/research/android/shieldcash-prover-sdk`, but no APK has been built and this host has
neither an Android SDK/NDK, Gradle, `adb`, emulator, nor attached Android
device. The library deliberately requires a separately pinned
`libshield_pf7.so`; no Android ABI-native PF7 binary is included. Therefore no
Android proof, APK, memory number, timing number, or G4 Android result is
claimed.

The source now specifies a descriptor-only native session: proving and
verification artifacts must be app-private direct regular files, opened once,
SHA-256-pinned, and passed to JNI only as live descriptors. The future JNI
backend must hash/fstat/mmap those descriptors and reject concurrent sessions.
This is source-level hardening, not NDK or device evidence.

The existing USB-only harness is deliberately not an Android-package substitute:
it is only a fail-closed way to stage profile-derived artifacts to a physical
device and validate a native-prover feasibility run. It must never be used to
claim the G4 production-packaging requirement.

Run the reproducible read-only inventory before attempting the package build:

```sh
npm --prefix packages/android-prover-harness run probe:environment -- /absolute/output.json
```

Once a USB-connected physical device, an authenticated profile-bound
Android-native PF7 prover, and the pinned manifest exist, the feasibility
harness entry point is:

```sh
npm --prefix packages/android-prover-harness run run:device -- /absolute/manifest.json
```

It remains feasibility-only telemetry, not the package qualification below.

## Required package measurement

Before an Android result is accepted, build a release-signed, offline-capable
APK from the wallet/prover package. Record its signing-certificate digest, APK
SHA-256, package name/version, Android API level, build fingerprint, device
model, RAM/storage capacity, CPU ABI/governor, thermal state, and the exact
typed Chipnet profile triple. The package must include its local prover and
profile verifier; it must not call a relayer, hosted prover, artifact server,
or witness upload endpoint.

The release package needs a benchmark-only local entry point which, for every
canonical action, records these boundaries separately:

1. cold package start and authenticated profile verification;
2. witness generation;
3. proving;
4. local proof verification; and
5. serialized transaction planning.

Collect 20 cold and 20 warm repetitions for each action on the frozen fixture.
Measure the package's own process-tree `VmRSS` at 50 ms or faster from within
the package (or a package-owned helper), retain the maximum, and preserve raw
per-run records. The proof stage fails if p95 exceeds 120 s or if peak app RSS
exceeds 1.5 GiB. Artifact downloads are out of scope for a measured local
profile: an interrupted local import/prove must fail closed without changing
wallet state, and resume behavior must be separately tested.

The evidence package must include the raw device capture, manifest hashes,
proof/public-signal hashes, independent local verification result, and a
statement of every network socket attempted. Only then may the native harness
be used as cross-check evidence for the exact same pinned profile and prover.
