package cash.shield.prover;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.regex.Pattern;

/** Caller-owned asset bytes are accepted only after exact SHA-256 authentication. */
public final class PinnedAsset {
  private static final Pattern SHA = Pattern.compile("[0-9a-f]{64}");
  private final byte[] bytes;
  public final String sha256;

  public PinnedAsset(byte[] bytes, String sha256) {
    if (bytes == null || !SHA.matcher(sha256).matches()) throw new IllegalArgumentException("invalid pinned asset");
    this.bytes = Arrays.copyOf(bytes, bytes.length);
    this.sha256 = sha256;
    if (!sha256(this.bytes).equals(sha256)) throw new SecurityException("pinned asset hash mismatch");
  }

  public byte[] copy() { return Arrays.copyOf(bytes, bytes.length); }
  public static String sha256(byte[] bytes) {
    try {
      byte[] hash = MessageDigest.getInstance("SHA-256").digest(bytes);
      StringBuilder out = new StringBuilder(64);
      for (byte value : hash) out.append(String.format("%02x", value & 0xff));
      return out.toString();
    } catch (NoSuchAlgorithmException error) { throw new IllegalStateException("SHA-256 unavailable", error); }
  }
}
