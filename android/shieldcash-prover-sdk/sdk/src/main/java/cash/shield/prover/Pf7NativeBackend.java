package cash.shield.prover;

/**
 * In-process, descriptor-only PF7 boundary. Implementations may not receive
 * artifact paths or artifact bytes, contact a service, or retain an FD after
 * the session closes.
 */
public interface Pf7NativeBackend {
  Session open(ProfileTriple profile, ArtifactBinding binding, AppPrivateArtifact.Opened provingKey,
      AppPrivateArtifact.Opened verificationKey);

  interface Session extends AutoCloseable {
    Proof prove(byte[] witness);
    boolean verify(Proof proof, PublicSignals publicSignals);
    @Override void close();
  }

  final class Proof {
    private final byte[] bytes;
    private final PublicSignals publicSignals;
    public Proof(byte[] bytes, PublicSignals publicSignals) {
      if (bytes == null || bytes.length == 0 || publicSignals == null) throw new IllegalArgumentException("invalid PF7 proof result");
      this.bytes = bytes.clone(); this.publicSignals = publicSignals;
    }
    public byte[] bytes() { return bytes.clone(); }
    public PublicSignals publicSignals() { return publicSignals; }
  }
}
