package cash.shield.prover;

/** JNI binding for a separately pinned Android ABI-specific PF7 backend. */
public final class NativePf7Backend implements Pf7NativeBackend {
  static { System.loadLibrary("shield_pf7"); }
  @Override public Proof prove(PinnedAsset provingKey, byte[] witness) {
    NativeResult result = nativeProve(provingKey.copy(), witness);
    return new Proof(result.proof, result.publicSignals);
  }
  @Override public boolean verify(PinnedAsset verificationKey, Proof proof, String[] publicSignals) {
    return nativeVerify(verificationKey.copy(), proof.bytes(), publicSignals);
  }
  private static final class NativeResult { final byte[] proof; final String[] publicSignals; NativeResult(byte[] proof, String[] publicSignals) { this.proof = proof; this.publicSignals = publicSignals; } }
  private static native NativeResult nativeProve(byte[] provingKey, byte[] witness);
  private static native boolean nativeVerify(byte[] verificationKey, byte[] proof, String[] publicSignals);
}
