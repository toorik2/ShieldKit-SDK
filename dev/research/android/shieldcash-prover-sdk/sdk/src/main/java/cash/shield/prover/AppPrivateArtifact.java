package cash.shield.prover;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A SHA-256-pinned regular artifact stored directly in an application's private
 * files directory. The native boundary receives only the opened descriptor,
 * never this path. Android callers must pass {@code Context.getFilesDir()}.
 */
public final class AppPrivateArtifact {
  private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
  private static final Pattern NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
  private final File privateDirectory;
  private final String fileName;
  public final String sha256;

  public AppPrivateArtifact(File privateDirectory, String fileName, String sha256) {
    if (privateDirectory == null || fileName == null || sha256 == null || !NAME.matcher(fileName).matches() || !SHA256.matcher(sha256).matches()) {
      throw new IllegalArgumentException("invalid app-private pinned artifact");
    }
    this.privateDirectory = privateDirectory;
    this.fileName = fileName;
    this.sha256 = sha256;
  }

  /** Opens and authenticates a direct regular child. The returned FD stays pinned until close. */
  Opened open() {
    try {
      File root = privateDirectory.getCanonicalFile();
      if (Files.isSymbolicLink(privateDirectory.toPath()) || !root.isDirectory()) throw new SecurityException("artifact directory is unsafe");
      File candidate = new File(privateDirectory, fileName);
      File canonical = candidate.getCanonicalFile();
      if (!Objects.equals(canonical.getParentFile(), root) || Files.isSymbolicLink(candidate.toPath())) throw new SecurityException("artifact path is unsafe");
      BasicFileAttributes before = Files.readAttributes(candidate.toPath(), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!before.isRegularFile() || before.isSymbolicLink()) throw new SecurityException("artifact is not a direct regular file");
      FileInputStream stream = new FileInputStream(candidate);
      try {
        FileDescriptor descriptor = stream.getFD();
        String observed = sha256(stream.getChannel());
        if (!sha256.equals(observed)) throw new SecurityException("artifact hash mismatch");
        BasicFileAttributes after = Files.readAttributes(candidate.toPath(), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!after.isRegularFile() || after.isSymbolicLink() || before.size() != after.size()
            || !Objects.equals(before.fileKey(), after.fileKey())) throw new SecurityException("artifact path changed while opening");
        stream.getChannel().position(0);
        return new Opened(stream, descriptor, before.size(), sha256);
      } catch (IOException error) {
        try { stream.close(); } catch (IOException ignored) {}
        throw new SecurityException("artifact descriptor cannot be opened safely", error);
      } catch (RuntimeException | Error error) {
        try { stream.close(); } catch (IOException ignored) {}
        throw error;
      }
    } catch (IOException error) { throw new SecurityException("artifact cannot be opened safely", error); }
  }

  private static String sha256(FileChannel channel) throws IOException {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      ByteBuffer buffer = ByteBuffer.allocateDirect(64 * 1024);
      while (channel.read(buffer) != -1) { buffer.flip(); digest.update(buffer); buffer.clear(); }
      StringBuilder out = new StringBuilder(64);
      for (byte value : digest.digest()) out.append(String.format("%02x", value & 0xff));
      return out.toString();
    } catch (NoSuchAlgorithmException error) { throw new IllegalStateException("SHA-256 unavailable", error); }
  }

  /** Package-private capability: only the backend can use the FD. */
  static final class Opened implements AutoCloseable {
    private final FileInputStream stream;
    private final FileDescriptor descriptor;
    final long bytes;
    final String sha256;
    private boolean closed;
    private Opened(FileInputStream stream, FileDescriptor descriptor, long bytes, String sha256) {
      this.stream = stream; this.descriptor = descriptor; this.bytes = bytes; this.sha256 = sha256;
    }
    FileDescriptor descriptor() { if (closed) throw new IllegalStateException("artifact descriptor is closed"); return descriptor; }
    @Override public void close() {
      if (!closed) { closed = true; try { stream.close(); } catch (IOException error) { throw new IllegalStateException("artifact descriptor close failed", error); } }
    }
  }
}
