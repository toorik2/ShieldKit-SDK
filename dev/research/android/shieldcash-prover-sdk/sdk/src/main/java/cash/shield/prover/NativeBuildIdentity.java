package cash.shield.prover;

/** Identity compiled into the JNI library by its source-pinned Android build. */
public final class NativeBuildIdentity {
  public final String rapidsnarkSourceCommit;
  public final String nativeBackendBuildSha256;
  public NativeBuildIdentity(String rapidsnarkSourceCommit, String nativeBackendBuildSha256) {
    // Reuse binding validation so JNI cannot introduce weakly formatted identities.
    new ArtifactBinding("0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000", rapidsnarkSourceCommit, nativeBackendBuildSha256);
    this.rapidsnarkSourceCommit = rapidsnarkSourceCommit;
    this.nativeBackendBuildSha256 = nativeBackendBuildSha256;
  }
}
