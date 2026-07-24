package cash.shield.prover;

import java.io.FileDescriptor;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * JNI implementation backed by source-pinned Rapidsnark. JNI must duplicate,
 * fstat, hash, and mmap only the supplied regular descriptors; it must not
 * reopen artifact paths. Missing or mismatched native material fails closed.
 */
public final class NativePf7Backend implements Pf7NativeBackend {
  private static final AtomicBoolean PROCESS_SESSION = new AtomicBoolean(false);
  static { System.loadLibrary("shield_pf7"); }
  private final ProfileTriple profile;
  private final ArtifactBinding binding;

  public NativePf7Backend(ProfileTriple profile, ArtifactBinding binding) {
    if (profile == null || binding == null) throw new IllegalArgumentException("missing PF7 native profile binding");
    NativeBuildIdentity actual = nativeBuildIdentity();
    if (actual == null || !binding.rapidsnarkSourceCommit.equals(actual.rapidsnarkSourceCommit)
        || !binding.nativeBackendBuildSha256.equals(actual.nativeBackendBuildSha256)) throw new SecurityException("native PF7 build identity mismatch");
    this.profile = profile; this.binding = binding;
  }

  @Override public Session open(ProfileTriple profile, ArtifactBinding binding, AppPrivateArtifact.Opened provingKey,
      AppPrivateArtifact.Opened verificationKey) {
    if (!this.profile.equals(profile) || !this.binding.equals(binding) || provingKey == null || verificationKey == null
        || !binding.provingKeySha256.equals(provingKey.sha256) || !binding.verificationKeySha256.equals(verificationKey.sha256)) {
      throw new SecurityException("native PF7 session binding mismatch");
    }
    if (!PROCESS_SESSION.compareAndSet(false, true)) throw new IllegalStateException("a PF7 native proof session is already active");
    try {
      NativeSession session = nativeOpenSession(provingKey.descriptor(), provingKey.bytes, verificationKey.descriptor(), verificationKey.bytes,
          profile.network, profile.profileId, profile.instanceId, binding.provingKeySha256, binding.verificationKeySha256,
          binding.rapidsnarkSourceCommit, binding.nativeBackendBuildSha256);
      if (session == null) throw new SecurityException("native PF7 session was not created");
      return new LockedSession(session);
    } catch (Throwable error) { PROCESS_SESSION.set(false); throw error; }
  }

  private static final class LockedSession implements Session {
    private final NativeSession session; private boolean closed;
    LockedSession(NativeSession session) { this.session = session; }
    @Override public Proof prove(byte[] witness) { if (closed || witness == null || witness.length == 0) throw new IllegalStateException("native PF7 session is unavailable"); NativeResult result = session.nativeProve(witness.clone()); if (result == null) throw new SecurityException("native PF7 prover returned no result"); return new Proof(result.proof, new PublicSignals(result.publicSignals)); }
    @Override public boolean verify(Proof proof, PublicSignals publicSignals) { if (closed || proof == null || publicSignals == null) throw new IllegalStateException("native PF7 session is unavailable"); return session.nativeVerify(proof.bytes(), publicSignals.nativeValues()); }
    @Override public void close() { if (!closed) { closed = true; try { session.nativeClose(); } finally { PROCESS_SESSION.set(false); } } }
  }
  private static final class NativeResult { final byte[] proof; final String[] publicSignals; NativeResult(byte[] proof, String[] publicSignals) { this.proof = proof; this.publicSignals = publicSignals; } }
  private static final class NativeSession { private native NativeResult nativeProve(byte[] witness); private native boolean nativeVerify(byte[] proof, String[] publicSignals); private native void nativeClose(); }
  private static native NativeBuildIdentity nativeBuildIdentity();
  private static native NativeSession nativeOpenSession(FileDescriptor provingKey, long provingKeyBytes,
      FileDescriptor verificationKey, long verificationKeyBytes, String network, String profileId, String instanceId,
      String provingKeySha256, String verificationKeySha256, String rapidsnarkSourceCommit, String nativeBackendBuildSha256);
}
