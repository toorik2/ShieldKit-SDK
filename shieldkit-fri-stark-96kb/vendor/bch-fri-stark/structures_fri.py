import os
from cashvm import VM, P, N, OP, DEFINE, encode_num, decode_num, VMError

# Goldilocks prime, the standard STARK field
P_GOLD = 2**64 - 2**32 + 1

def inv(a, p): return pow(a % p, p - 2, p)

# ---- modular helper functions (p kept resident on the ALT stack) ------------
# Each takes [.., a, b] on main and returns [.., (a OP b) mod p] in [0,p).
NORM_TAIL = [OP("FROMALT"), OP("TUCK"), OP("MOD"),
             OP("OVER"), OP("ADD"), OP("OVER"), OP("MOD"),
             OP("SWAP"), OP("TOALT")]
MULMOD = b"\x01"; MULMOD_BODY = [OP("MUL")] + NORM_TAIL
ADDMOD = b"\x02"; ADDMOD_BODY = [OP("ADD")] + NORM_TAIL
SUBMOD = b"\x03"; SUBMOD_BODY = [OP("SUB")] + NORM_TAIL

def MM(): return [P(MULMOD), OP("INVOKE")]
def AM(): return [P(ADDMOD), OP("INVOKE")]
def SM(): return [P(SUBMOD), OP("INVOKE")]

# ---- FRI fold structure (function id = 0x20) --------------------------------
# Computes  folded = (f_pos+f_neg)/2  +  beta*(f_pos-f_neg)/(2x)   (mod p)
# Verifies the supplied modular inverses inv2 = (2)^-1 and inv2x = (2x)^-1.
# Main entry (bottom->top): [ f_pos, f_neg, beta, x, inv2, inv2x ] ; alt: [ p ]
# Returns: [ folded ]
FOLD = b"\x20"
fold_body = (
    # --- hint check: inv2 * 2 == 1 ---
    [N(1), OP("PICK")] + [N(2)] + MM() + [N(1), OP("NUMEQUALVERIFY")] +
    # --- hint check: inv2x * (x*2) == 1 ---
    [N(0), OP("PICK")] +                     # copy inv2x
    [N(3), OP("PICK"), N(2)] + MM() +        # (x*2) mod p
    MM() + [N(1), OP("NUMEQUALVERIFY")] +    # inv2x*(2x) == 1
    # --- summ = f_pos + f_neg ; e = summ * inv2 ---
    [N(5), OP("PICK"), N(5), OP("PICK")] + AM() +   # summ
    [N(2), OP("PICK")] + MM() +                      # e = summ*inv2
    # --- diff = f_pos - f_neg ; o1 = diff*inv2x ; o = o1*beta ---
    [N(6), OP("PICK"), N(6), OP("PICK")] + SM() +    # diff
    [N(2), OP("PICK")] + MM() +                      # o1 = diff*inv2x
    [N(5), OP("PICK")] + MM() +                      # o  = o1*beta
    # --- folded = e + o ---
    AM() +
    # --- drop the 6 original operands beneath folded ---
    [OP("SWAP"), OP("DROP")] * 6
)

def witness_fold(fp, fn, beta, x, p):
    i2  = inv(2, p)
    i2x = inv((2 * x) % p, p)
    prog  = [P(encode_num(p)), OP("TOALT")]    # p -> alt
    prog += [N(fp % p), N(fn % p), N(beta % p), N(x % p), N(i2), N(i2x)]
    # define helpers + fold
    for fid, body in [(MULMOD, MULMOD_BODY), (ADDMOD, ADDMOD_BODY),
                      (SUBMOD, SUBMOD_BODY), (FOLD, fold_body)]:
        prog += [P(fid), DEFINE(body)]
    prog += [P(FOLD), OP("INVOKE")]
    return prog

def fold_ref(fp, fn, beta, x, p):
    return ((fp + fn) * inv(2, p) + beta * (fp - fn) * inv((2*x) % p, p)) % p

# ---- tests ------------------------------------------------------------------
print("field = Goldilocks  p = 2^64 - 2^32 + 1 =", P_GOLD)
import random
random.seed(1)
allok = True
for t in range(8):
    fp   = random.randrange(P_GOLD)
    fn   = random.randrange(P_GOLD)
    beta = random.randrange(P_GOLD)
    x    = random.randrange(1, P_GOLD)
    prog = witness_fold(fp, fn, beta, x, P_GOLD)
    vm = VM(); vm.run(prog)
    got = decode_num(vm.s[-1])
    exp = fold_ref(fp, fn, beta, x, P_GOLD)
    status = "OK" if (got == exp and len(vm.s) == 1) else "FAIL"
    if status == "FAIL": allok = False
    print(f"  fold test {t}: got==ref {got==exp}  stackdepth={len(vm.s)}  steps={vm.steps}  [{status}]")

# negative test: bad inverse hint must fail
def test_bad_hint():
    fp, fn, beta, x = 11, 7, 5, 3
    p = P_GOLD
    i2  = inv(2, p)
    i2x_bad = (inv((2*x) % p, p) + 1) % p          # corrupted inverse
    prog  = [P(encode_num(p)), OP("TOALT")]
    prog += [N(fp), N(fn), N(beta), N(x), N(i2), N(i2x_bad)]
    for fid, body in [(MULMOD, MULMOD_BODY),(ADDMOD,ADDMOD_BODY),(SUBMOD,SUBMOD_BODY),(FOLD,fold_body)]:
        prog += [P(fid), DEFINE(body)]
    prog += [P(FOLD), OP("INVOKE")]
    try:
        VM().run(prog); return False
    except VMError:
        return True

assert test_bad_hint(), "bad inverse hint should fail"
print("  fold bad-inverse-hint rejection: CORRECTLY REJECTED")

# also verify a tiny prime end-to-end by brute force to confirm the math/codec
def test_small_prime():
    p = 97
    for _ in range(200):
        fp = random.randrange(p); fn = random.randrange(p)
        beta = random.randrange(p); x = random.randrange(1, p)
        prog = witness_fold(fp, fn, beta, x, p)
        got = decode_num(VM().run(prog)[-1])
        if got != fold_ref(fp, fn, beta, x, p): return False
    return True

assert test_small_prime(), "small-prime fold mismatch"
print("  fold over p=97 (200 random cases):  ALL MATCH REFERENCE")
print("\nFRI FOLD STRUCTURE:", "ALL VECTORS PASS" if allok else "FAILURES PRESENT")
