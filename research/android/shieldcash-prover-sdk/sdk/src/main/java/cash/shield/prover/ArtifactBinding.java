package cash.shield.prover;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Immutable, profile-manifest supplied identity of the artifacts a native PF7
 * session may consume. It is deliberately not a set of paths or byte arrays.
 */
public final class ArtifactBinding {
  private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
  private static final Pattern GIT_COMMIT = Pattern.compile("[0-9a-f]{40}");

  public final String provingKeySha256;
  public final String verificationKeySha256;
  public final String rapidsnarkSourceCommit;
  public final String nativeBackendBuildSha256;

  public ArtifactBinding(String provingKeySha256, String verificationKeySha256,
      String rapidsnarkSourceCommit, String nativeBackendBuildSha256) {
    if (provingKeySha256 == null || verificationKeySha256 == null || rapidsnarkSourceCommit == null || nativeBackendBuildSha256 == null
        || !SHA256.matcher(provingKeySha256).matches() || !SHA256.matcher(verificationKeySha256).matches()
        || !GIT_COMMIT.matcher(rapidsnarkSourceCommit).matches() || !SHA256.matcher(nativeBackendBuildSha256).matches()) {
      throw new IllegalArgumentException("invalid immutable PF7 artifact binding");
    }
    this.provingKeySha256 = provingKeySha256;
    this.verificationKeySha256 = verificationKeySha256;
    this.rapidsnarkSourceCommit = rapidsnarkSourceCommit;
    this.nativeBackendBuildSha256 = nativeBackendBuildSha256;
  }

  @Override public boolean equals(Object other) {
    if (!(other instanceof ArtifactBinding)) return false;
    ArtifactBinding value = (ArtifactBinding) other;
    return provingKeySha256.equals(value.provingKeySha256) && verificationKeySha256.equals(value.verificationKeySha256)
        && rapidsnarkSourceCommit.equals(value.rapidsnarkSourceCommit) && nativeBackendBuildSha256.equals(value.nativeBackendBuildSha256);
  }
  @Override public int hashCode() { return Objects.hash(provingKeySha256, verificationKeySha256, rapidsnarkSourceCommit, nativeBackendBuildSha256); }
}
