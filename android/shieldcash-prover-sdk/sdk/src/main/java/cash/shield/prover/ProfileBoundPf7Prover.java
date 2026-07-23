package cash.shield.prover;

import java.util.Arrays;

/**
 * Local, immutable-profile PF7 prover facade. A proof is returned only after
 * the same supplied backend verifies it against the exact pinned VK and two
 * canonical public signals. The caller owns witness bytes throughout.
 */
public final class ProfileBoundPf7Prover {
  private final ProfileTriple expected;
  private final PinnedAsset provingKey;
  private final PinnedAsset verificationKey;
  private final Pf7NativeBackend backend;

  public ProfileBoundPf7Prover(ProfileTriple expected, ProfileTriple observed, PinnedAsset provingKey, PinnedAsset verificationKey, Pf7NativeBackend backend) {
    if (expected == null || observed == null || !expected.equals(observed)) throw new SecurityException("profile triple mismatch");
    if (provingKey == null || verificationKey == null || backend == null) throw new IllegalArgumentException("missing local PF7 material");
    this.expected = expected; this.provingKey = provingKey; this.verificationKey = verificationKey; this.backend = backend;
  }

  public ProfileTriple profile() { return expected; }
  public Pf7NativeBackend.Proof proveAndVerify(byte[] witness, String[] expectedSignals) {
    if (witness == null || expectedSignals == null || expectedSignals.length != 2) throw new IllegalArgumentException("invalid local witness or public signals");
    Pf7NativeBackend.Proof proof = backend.prove(provingKey, witness.clone());
    if (!Arrays.equals(expectedSignals, proof.publicSignals())) throw new SecurityException("native PF7 public signals mismatch");
    if (!backend.verify(verificationKey, proof, expectedSignals.clone())) throw new SecurityException("native PF7 verification rejected proof");
    return proof;
  }
}
