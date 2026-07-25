package cash.shield.prover;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Kotlin-friendly Java facade for one immutable Chipnet/profile/instance.
 * It serializes all proving in-process and returns only locally re-verified
 * proofs. It has no transport, fallback, remote proving, or artifact fetch.
 */
public final class ProfileBoundPf7Prover {
  private static final AtomicBoolean PROCESS_PROOF = new AtomicBoolean(false);
  private final ProfileTriple expected;
  private final ArtifactBinding binding;
  private final AppPrivateArtifact provingKey;
  private final AppPrivateArtifact verificationKey;
  private final Pf7NativeBackend backend;

  public ProfileBoundPf7Prover(ProfileTriple expected, ProfileTriple observed, ArtifactBinding binding,
      AppPrivateArtifact provingKey, AppPrivateArtifact verificationKey, Pf7NativeBackend backend) {
    if (expected == null || observed == null || !expected.equals(observed)) throw new SecurityException("profile triple mismatch");
    if (binding == null || provingKey == null || verificationKey == null || backend == null) throw new IllegalArgumentException("missing local PF7 material");
    if (!binding.provingKeySha256.equals(provingKey.sha256) || !binding.verificationKeySha256.equals(verificationKey.sha256)) throw new SecurityException("profile artifact binding mismatch");
    this.expected = expected; this.binding = binding; this.provingKey = provingKey; this.verificationKey = verificationKey; this.backend = backend;
  }

  public ProfileTriple profile() { return expected; }
  public Pf7NativeBackend.Proof proveAndVerify(ProofRequest request) {
    if (request == null) throw new IllegalArgumentException("missing local proof request");
    if (!PROCESS_PROOF.compareAndSet(false, true)) throw new IllegalStateException("a PF7 proof is already active in this process");
    try (AppPrivateArtifact.Opened proving = provingKey.open(); AppPrivateArtifact.Opened verification = verificationKey.open();
        Pf7NativeBackend.Session session = backend.open(expected, binding, proving, verification)) {
      Pf7NativeBackend.Proof proof = session.prove(request.witnessCopy());
      if (!request.expectedPublicSignals.equals(proof.publicSignals())) throw new SecurityException("native PF7 public signals mismatch");
      if (!session.verify(proof, request.expectedPublicSignals)) throw new SecurityException("native PF7 verification rejected proof");
      return proof;
    } finally { PROCESS_PROOF.set(false); }
  }
}
