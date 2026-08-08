"""
native_gf_p2.py -- quadratic extension field GF(p^2) over Goldilocks for the native
CT-AIR prover/verifier (HP1.6, AUFGABE 2 / Runde-1-Befund L#3). p = 2^64-2^32+1.

WHY (plan 1.6 + L#3, hp6_air_ext_split.py / cost_report_native_ext.py): a 64-bit
base field caps a single Fiat-Shamir / FRI-fold / DEEP-combination challenge at
~64-bit soundness (error ~ deg/|F|). For the >=100-bit config (native_ct_air_config)
the RANDOM challenges -- alpha (constraint combination), beta (FRI folding), the FS
squeezes -- MUST be drawn from GF(p^2); the hash, the trace columns, the Poseidon2
S-box/MDS and the vanishing Z_H(x) stay BASE field. This module is ONLY the
extension arithmetic those challenges need.

CONSTRUCTION (NOT invented -- mirrors cost_report_native_ext.py:63 + Plonky2/Plonky3
Goldilocks binomial extension): GF(p^2) = F_p[u]/(u^2 - EXT_NONRES), EXT_NONRES=7
pinned in native_ct_air_config (single source, drift-protected). An element
a = (a0, a1) == a0 + a1*u, with u^2 = 7. Karatsuba multiply; conj = the Frobenius
map a -> a^p; norm = a*conj(a) lands in the base field. self_test() empirically
proves the field axioms AND that 7 is a quadratic non-residue (so u^2-7 is
irreducible and GF(p^2) is a field) -- a real check on real field elements, no mock.
"""
import os
import sys

_APPS = os.path.dirname(os.path.abspath(__file__))
if _APPS not in sys.path:
    sys.path.insert(0, _APPS)

from native_ct_air_config import P, EXT_NONRES as W

ZERO = (0, 0)
ONE = (1, 0)
U = (0, 1)   # the extension generator u, with u^2 = W


def from_base(a):
    """Embed a base-field element a into GF(p^2): a -> a + 0*u."""
    return (a % P, 0)


def is_base(a):
    """True iff a lies in the base field (its u-coefficient is 0)."""
    return a[1] % P == 0


def eq(a, b):
    return a[0] % P == b[0] % P and a[1] % P == b[1] % P


def add(a, b):
    return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)


def sub(a, b):
    return ((a[0] - b[0]) % P, (a[1] - b[1]) % P)


def neg(a):
    return ((-a[0]) % P, (-a[1]) % P)


def mul(a, b):
    """Karatsuba multiply in F_p[u]/(u^2 - W) (cost_report_native_ext convention):
    t0=a0*b0, t1=a1*b1, t2=(a0+a1)(b0+b1); c0=t0+W*t1, c1=t2-t0-t1."""
    a0, a1 = a[0] % P, a[1] % P
    b0, b1 = b[0] % P, b[1] % P
    t0 = (a0 * b0) % P
    t1 = (a1 * b1) % P
    t2 = ((a0 + a1) * (b0 + b1)) % P
    c0 = (t0 + W * t1) % P
    c1 = (t2 - t0 - t1) % P
    return (c0, c1)


def scalar(s, a):
    """Base-field scalar s times extension element a (cheaper than a full mul)."""
    s %= P
    return ((s * a[0]) % P, (s * a[1]) % P)


def conj(a):
    """Frobenius automorphism a -> a^p = a0 - a1*u (fixes the base field)."""
    return (a[0] % P, (-a[1]) % P)


def norm(a):
    """Field norm N(a) = a*conj(a) = a0^2 - W*a1^2 (a BASE-field element)."""
    return (a[0] * a[0] - W * a[1] * a[1]) % P


def inv(a):
    """Multiplicative inverse 1/a = conj(a)/N(a). Raises on the zero element."""
    n = norm(a)
    if n == 0:
        raise ZeroDivisionError("GF(p^2) inverse of zero / zero-norm element")
    ninv = pow(n, P - 2, P)
    return ((a[0] * ninv) % P, ((-a[1]) * ninv) % P)


def power(a, e):
    """a^e for a non-negative integer exponent e (square-and-multiply)."""
    if e < 0:
        raise ValueError("negative exponent")
    result = ONE
    base = (a[0] % P, a[1] % P)
    while e:
        if e & 1:
            result = mul(result, base)
        base = mul(base, base)
        e >>= 1
    return result


def self_test():
    import random
    # 7 MUST be a quadratic non-residue mod p (Euler) -> u^2-7 irreducible -> field.
    # If this fails, GF(p^2) has zero divisors and every challenge below is unsound.
    assert pow(W, (P - 1) // 2, P) == P - 1, "W=%d is a quadratic residue -> GF(p^2) invalid" % W
    assert eq(mul(U, U), from_base(W)), "u^2 != W"
    rng = random.Random(0xC7A12026)
    fb = lambda: rng.randrange(0, P)
    el = lambda: (fb(), fb())
    for _ in range(200):
        x, y = fb(), fb()
        # embedding is a ring homomorphism
        assert eq(mul(from_base(x), from_base(y)), from_base((x * y) % P)), "embed not multiplicative"
        assert eq(add(from_base(x), from_base(y)), from_base((x + y) % P)), "embed not additive"
        a, b, c = el(), el(), el()
        assert eq(mul(a, b), mul(b, a)), "mul not commutative"
        assert eq(mul(mul(a, b), c), mul(a, mul(b, c))), "mul not associative"
        assert eq(mul(a, add(b, c)), add(mul(a, b), mul(a, c))), "distributivity fails"
        assert eq(mul(a, ONE), a) and eq(add(a, ZERO), a), "identity element fails"
        assert eq(sub(a, a), ZERO) and eq(add(a, neg(a)), ZERO), "additive inverse fails"
        # scalar(s,a) == mul(from_base(s), a)
        assert eq(scalar(x, a), mul(from_base(x), a)), "scalar != base-mul"
        # multiplicative inverse (norm 0 only for a==0 since the form is anisotropic)
        if norm(a) != 0:
            assert eq(mul(a, inv(a)), ONE), "a * inv(a) != 1"
        # Frobenius a^p == conj(a); norm(a) == a*conj(a) and is base-field
        assert eq(power(a, P), conj(a)), "a^p != conj(a) (Frobenius)"
        nc = mul(a, conj(a))
        assert nc[1] == 0 and nc[0] == norm(a), "norm != a*conj(a)"
        # power base cases
        assert eq(power(a, 0), ONE) and eq(power(a, 1), a), "power base cases"
        assert eq(power(a, 2), mul(a, a)), "power square mismatch"
    # a genuinely non-base element is not flagged as base
    assert not is_base((1, 1)) and is_base(from_base(5)), "is_base misclassifies"
    # zero has no inverse (fail-closed)
    try:
        inv(ZERO); zero_inv = True
    except ZeroDivisionError:
        zero_inv = False
    assert zero_inv is False, "inverse of zero not rejected"
    return True


if __name__ == "__main__":
    ok = self_test()
    print("native GF(p^2) over Goldilocks (u^2-%d, Plonky3 binomial extension): %s"
          % (W, "OK" if ok else "FAIL"))
    print("  field axioms + inverse + Frobenius(a^p==conj) + norm verified on 200 random elements")
    print("  %d confirmed quadratic non-residue mod p (u^2-%d irreducible -> GF(p^2) is a field)"
          % (W, W))
