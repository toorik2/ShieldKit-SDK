package cash.shield.prover;

import java.util.Arrays;

/** Exactly two canonical BN254 public-field elements for the frozen relation ABI. */
public final class PublicSignals {
  private static final java.math.BigInteger MODULUS = new java.math.BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
  private final String[] values;
  public PublicSignals(String first, String second) { this(new String[] { first, second }); }
  public PublicSignals(String[] values) {
    if (values == null || values.length != 2) throw new IllegalArgumentException("PF7 requires exactly two public signals");
    this.values = values.clone();
    for (String value : this.values) {
      if (value == null || !value.matches("0|[1-9][0-9]*") || new java.math.BigInteger(value).compareTo(MODULUS) >= 0) throw new IllegalArgumentException("public signal is not a canonical BN254 scalar");
    }
  }
  String[] nativeValues() { return values.clone(); }
  @Override public boolean equals(Object other) { return other instanceof PublicSignals && Arrays.equals(values, ((PublicSignals) other).values); }
  @Override public int hashCode() { return Arrays.hashCode(values); }
}
