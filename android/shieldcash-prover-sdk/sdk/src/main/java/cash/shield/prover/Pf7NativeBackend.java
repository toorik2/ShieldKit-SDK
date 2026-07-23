package cash.shield.prover;

/**
 * The only production proving boundary. Implementations must be an in-process
 * Android-native PF7/BN254 backend; no HTTP, remote prover, relayer, indexer,
 * artifact fetch, or witness export is part of this interface.
 */
public interface Pf7NativeBackend {
  Proof prove(PinnedAsset provingKey, byte[] witness);
  boolean verify(PinnedAsset verificationKey, Proof proof, String[] publicSignals);

  final class Proof {
    private final byte[] bytes;
    private final String[] publicSignals;
    public Proof(byte[] bytes, String[] publicSignals) {
      if (bytes == null || publicSignals == null || publicSignals.length != 2) throw new IllegalArgumentException("invalid PF7 proof result");
      this.bytes = bytes.clone(); this.publicSignals = publicSignals.clone();
    }
    public byte[] bytes() { return bytes.clone(); }
    public String[] publicSignals() { return publicSignals.clone(); }
  }
}
