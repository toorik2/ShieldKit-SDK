package cash.shield.prover;

import java.io.File;
import java.nio.file.Files;

/** Host-only fail-closed contract test; it deliberately never accepts a proof. */
public final class HostContractTest {
  private static final String A = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  private static final String B = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  private static final String RAPIDSNARK = "0123456789abcdef0123456789abcdef01234567";
  private static class FakeBackend implements Pf7NativeBackend {
    private final boolean verify;
    FakeBackend(boolean verify) { this.verify = verify; }
    @Override public Session open(ProfileTriple profile, ArtifactBinding binding, AppPrivateArtifact.Opened provingKey, AppPrivateArtifact.Opened verificationKey) {
      require(provingKey.bytes > 0 && verificationKey.bytes > 0);
      return new Session() {
        @Override public Proof prove(byte[] witness) { return new Proof(new byte[] {1}, new PublicSignals("1", "2")); }
        @Override public boolean verify(Proof proof, PublicSignals publicSignals) { return verify; }
        @Override public void close() {}
      };
    }
  }
  private static final class ReentrantBackend extends FakeBackend {
    ProfileBoundPf7Prover target; boolean rejected;
    ReentrantBackend() { super(true); }
    @Override public Session open(ProfileTriple profile, ArtifactBinding binding, AppPrivateArtifact.Opened provingKey, AppPrivateArtifact.Opened verificationKey) {
      try { target.proveAndVerify(new ProofRequest(new byte[] {9}, new PublicSignals("1", "2"))); }
      catch (IllegalStateException error) { rejected = true; }
      return super.open(profile, binding, provingKey, verificationKey);
    }
  }
  private static void require(boolean value) { if (!value) throw new AssertionError(); }
  public static void main(String[] args) throws Exception {
    ProfileTriple expected = new ProfileTriple("chipnet", A, B);
    String configured = System.getProperty("shield.cash.hostTestDirectory");
    if (configured == null) throw new AssertionError("host test directory is required");
    File directory = new File(configured).getCanonicalFile();
    if (!directory.mkdir()) throw new AssertionError("host test directory must be newly created");
    Files.write(new File(directory, "proving.zkey").toPath(), new byte[] {1});
    Files.write(new File(directory, "verification.vk").toPath(), new byte[] {2});
    AppPrivateArtifact proving = new AppPrivateArtifact(directory, "proving.zkey", AppPrivateArtifactTestHash.hash(new byte[] {1}));
    AppPrivateArtifact verification = new AppPrivateArtifact(directory, "verification.vk", AppPrivateArtifactTestHash.hash(new byte[] {2}));
    ArtifactBinding binding = new ArtifactBinding(proving.sha256, verification.sha256, RAPIDSNARK, A.substring("sha256:".length()));
    boolean mismatch = false;
    try { new ProfileBoundPf7Prover(expected, new ProfileTriple("chipnet", B, A), binding, proving, verification, new FakeBackend(false)); } catch (SecurityException error) { mismatch = true; }
    require(mismatch);
    ProfileBoundPf7Prover prover = new ProfileBoundPf7Prover(expected, expected, binding, proving, verification, new FakeBackend(false));
    boolean rejected = false;
    try { prover.proveAndVerify(new ProofRequest(new byte[] {3}, new PublicSignals("1", "2"))); } catch (SecurityException error) { rejected = true; }
    require(rejected);
    Pf7NativeBackend.Proof accepted = new ProfileBoundPf7Prover(expected, expected, binding, proving, verification, new FakeBackend(true)).proveAndVerify(new ProofRequest(new byte[] {3}, new PublicSignals("1", "2")));
    require(accepted.bytes().length == 1);
    ReentrantBackend reentrantBackend = new ReentrantBackend();
    ProfileBoundPf7Prover reentrant = new ProfileBoundPf7Prover(expected, expected, binding, proving, verification, reentrantBackend);
    reentrantBackend.target = reentrant;
    reentrant.proveAndVerify(new ProofRequest(new byte[] {3}, new PublicSignals("1", "2")));
    require(reentrantBackend.rejected);
    boolean unsafe = false;
    try { new AppPrivateArtifact(directory, "../outside", proving.sha256); } catch (IllegalArgumentException error) { unsafe = true; }
    require(unsafe);
    Files.createSymbolicLink(new File(directory, "linked.zkey").toPath(), new File(directory, "proving.zkey").toPath());
    boolean symlinkRejected = false;
    try { new AppPrivateArtifact(directory, "linked.zkey", proving.sha256).open(); } catch (SecurityException error) { symlinkRejected = true; }
    require(symlinkRejected);
  }

  private static final class AppPrivateArtifactTestHash {
    static String hash(byte[] bytes) { try { StringBuilder out = new StringBuilder(); for (byte value : java.security.MessageDigest.getInstance("SHA-256").digest(bytes)) out.append(String.format("%02x", value & 0xff)); return out.toString(); } catch (java.security.NoSuchAlgorithmException error) { throw new AssertionError(error); } }
  }
}
