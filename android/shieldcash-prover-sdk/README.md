# shield.cash Android prover SDK

This is an Android-library source package, not an APK or a completed device
qualification. It has no `INTERNET` permission and exposes only an in-process,
typed `Pf7NativeBackend` boundary. `ProfileBoundPf7Prover` requires exact
Chipnet/profile/instance equality plus independently SHA-256-pinned proving and
verification material, a source-pinned Rapidsnark revision, and a native-backend
build hash; it proves locally and immediately verifies the same proof and two
canonical public signals locally.

`NativePf7Backend` deliberately loads `libshield_pf7.so`. No Android ABI-native
PF7 backend is included in this repository, so construction fails closed rather
than falling back to JavaScript, a remote prover, a service, or a synthetic
acceptance path. A future native backend must be pinned into a new immutable
profile/package measurement; it cannot hot-swap a deployed instance.

## Descriptor-only native session

The application installs authenticated artifacts directly under
`Context.getFilesDir()` and constructs `AppPrivateArtifact` using a single safe
file name and its manifest hash. During `proveAndVerify`, the Java facade:

- rejects directory/file symlinks, traversal names, non-regular files, and
  hash or identity changes while opening;
- opens both artifacts once, hashes the opened stream, then gives JNI only the
  live `FileDescriptor` and byte length — never a path or artifact byte array;
- serializes all process-local proof sessions; and
- closes the native session before closing those descriptors.

The future JNI implementation must duplicate each descriptor, `fstat` it as a
regular file, hash the descriptor contents against the supplied profile binding,
and mmap only the duplicated proving-key descriptor. It must never reopen a
path. A path replacement after open therefore cannot change the material seen
by a session, and descriptor/content replacement fails its native hash check.
The detailed ABI and mandatory native checks are in
[`NATIVE_SESSION_ABI.md`](NATIVE_SESSION_ABI.md).

The Java API is intentionally Kotlin-friendly: immutable value classes,
non-null constructor inputs, `AutoCloseable` native sessions, and no checked
network or provider types. Kotlin consumers use `ProfileTriple`,
`ArtifactBinding`, `AppPrivateArtifact`, `ProofRequest`, and
`ProfileBoundPf7Prover` through normal Java interop.

Build requirements are Android Gradle Plugin 8.7.3, compile SDK 35, and a
locally installed Android SDK/NDK. This host has none of those tools, so this
source package has only host-Java compilation coverage. See
`packages/android-prover-harness/REAL_DEVICE_GATE.md` for the required APK and
physical-device measurement evidence.
