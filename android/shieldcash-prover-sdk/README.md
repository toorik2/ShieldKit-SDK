# shield.cash Android prover SDK

This is an Android-library source package, not an APK or a completed device
qualification. It has no `INTERNET` permission and exposes only an in-process,
typed `Pf7NativeBackend` boundary. `ProfileBoundPf7Prover` requires exact
Chipnet/profile/instance equality plus independently SHA-256-pinned proving and
verification material; it proves locally and immediately verifies the same
proof and two public signals locally.

`NativePf7Backend` deliberately loads `libshield_pf7.so`. No Android ABI-native
PF7 backend is included in this repository, so construction fails closed rather
than falling back to JavaScript, a remote prover, a service, or a synthetic
acceptance path. A future native backend must be pinned into a new immutable
profile/package measurement; it cannot hot-swap a deployed instance.

Build requirements are Android Gradle Plugin 8.7.3, compile SDK 35, and a
locally installed Android SDK/NDK. This host has none of those tools, so this
source package has only host-Java compilation coverage. See
`packages/android-prover-harness/REAL_DEVICE_GATE.md` for the required APK and
physical-device measurement evidence.
