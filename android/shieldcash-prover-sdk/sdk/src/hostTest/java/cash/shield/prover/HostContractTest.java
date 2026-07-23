package cash.shield.prover;

/** Host-only fail-closed contract test; it deliberately never accepts a proof. */
public final class HostContractTest {
  private static final String A = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  private static final String B = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  private static final class RejectingBackend implements Pf7NativeBackend {
    @Override public Proof prove(PinnedAsset provingKey, byte[] witness) { return new Proof(new byte[] {1}, new String[] {"1", "2"}); }
    @Override public boolean verify(PinnedAsset verificationKey, Proof proof, String[] publicSignals) { return false; }
  }
  private static void require(boolean value) { if (!value) throw new AssertionError(); }
  public static void main(String[] args) {
    ProfileTriple expected = new ProfileTriple("chipnet", A, B);
    boolean mismatch = false;
    try { new ProfileBoundPf7Prover(expected, new ProfileTriple("chipnet", B, A), new PinnedAsset(new byte[] {1}, PinnedAsset.sha256(new byte[] {1})), new PinnedAsset(new byte[] {2}, PinnedAsset.sha256(new byte[] {2})), new RejectingBackend()); } catch (SecurityException error) { mismatch = true; }
    require(mismatch);
    ProfileBoundPf7Prover prover = new ProfileBoundPf7Prover(expected, expected, new PinnedAsset(new byte[] {1}, PinnedAsset.sha256(new byte[] {1})), new PinnedAsset(new byte[] {2}, PinnedAsset.sha256(new byte[] {2})), new RejectingBackend());
    boolean rejected = false;
    try { prover.proveAndVerify(new byte[] {3}, new String[] {"1", "2"}); } catch (SecurityException error) { rejected = true; }
    require(rejected);
  }
}
