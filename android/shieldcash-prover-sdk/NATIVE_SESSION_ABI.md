# PF7 Android native-session ABI

Status: source contract only. No `libshield_pf7.so`, NDK build, APK, emulator,
or physical-device measurement is supplied by this repository.

`NativePf7Backend` has exactly one artifact-opening JNI call:

```text
nativeOpenSession(
  provingKeyFd, provingKeyBytes, verificationKeyFd, verificationKeyBytes,
  network, profileId, instanceId,
  provingKeySha256, verificationKeySha256,
  rapidsnarkSourceCommit, nativeBackendBuildSha256
) -> NativeSession
```

The JNI implementation is required to do all of the following before creating
the session:

1. duplicate both supplied descriptors with close-on-exec semantics;
2. `fstat` each duplicate and reject anything other than a regular file;
3. reject negative or mismatched lengths and hash the duplicate descriptors
   from offset zero using SHA-256;
4. compare those hashes and every profile/artifact/source-build string exactly
   with the JNI arguments and compile-time `nativeBuildIdentity()` values;
5. mmap the duplicated proving-key descriptor read-only, private, and only for
   the checked length; and
6. keep all duplicates/mappings private to `NativeSession`, zeroize temporary
   witness/proof buffers where feasible, and release them in `nativeClose`.

The implementation must not accept an artifact path, reopen a path, fetch an
artifact, invoke a shell, create a network connection, or use a global mutable
setup. It must reject a second open while a session exists. `nativeProve` and
`nativeVerify` execute only on that session and must reject calls after close.

The application facade separately holds a process-wide proof lock. The JNI lock
is defense in depth against another direct JNI caller. Neither lock is a
protocol authority; failure merely makes the local wallet retry later.

The first actual Android backend must be built from a source-pinned Rapidsnark
revision, record compiler/NDK/ABI/build inputs, be packaged with the exact
profile bundle, and then receive a new profile/genesis if any profile-bound
artifact changes. It must still pass real APK and device proof measurements
before any G4 or production claim.
