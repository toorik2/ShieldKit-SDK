package cash.shield.prover;

import java.util.Objects;
import java.util.regex.Pattern;

/** Immutable Chipnet/profile/instance coordinate; no profile hot swap is valid. */
public final class ProfileTriple {
  private static final Pattern ID = Pattern.compile("sha256:[0-9a-f]{64}");
  public final String network;
  public final String profileId;
  public final String instanceId;

  public ProfileTriple(String network, String profileId, String instanceId) {
    if (!"chipnet".equals(network) || !ID.matcher(profileId).matches() || !ID.matcher(instanceId).matches()) {
      throw new IllegalArgumentException("invalid immutable Chipnet profile triple");
    }
    this.network = network;
    this.profileId = profileId;
    this.instanceId = instanceId;
  }

  @Override public boolean equals(Object other) {
    if (!(other instanceof ProfileTriple)) return false;
    ProfileTriple value = (ProfileTriple) other;
    return network.equals(value.network) && profileId.equals(value.profileId) && instanceId.equals(value.instanceId);
  }
  @Override public int hashCode() { return Objects.hash(network, profileId, instanceId); }
}
