package cash.shield.prover;

/** Caller-owned witness bytes and the independently constructed expected public ABI. */
public final class ProofRequest {
  private final byte[] witness;
  public final PublicSignals expectedPublicSignals;
  public ProofRequest(byte[] witness, PublicSignals expectedPublicSignals) {
    if (witness == null || witness.length == 0 || expectedPublicSignals == null) throw new IllegalArgumentException("invalid local proof request");
    this.witness = witness.clone(); this.expectedPublicSignals = expectedPublicSignals;
  }
  byte[] witnessCopy() { return witness.clone(); }
}
