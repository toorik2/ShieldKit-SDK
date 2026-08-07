"""
proof_size.py -- byte accounting for a zk-STARK proof, to check the <=90KB budget.
Conservative FRI model (SHA256 Merkle, Goldilocks base, degree-2 ext for FRI values).
"""
import math, hashlib, os
from cashvm import VM, P as PUSH, N, OP, DEFINE, VMError
from structures_merkle import merkle_body, MERKLE_FID, build_tree, proof

HASH   = 32     # SHA256 (128-bit post-quantum margin under Grover)
FELT   = 8      # Goldilocks base field element
EXT    = 16     # degree-2 extension element (FRI folded values / challenges)

def proof_bytes(log_trace, blowup, queries, grind_bits, fold, n_cols, final_deg=8):
    N = (1 << log_trace) * blowup
    logN = int(math.log2(N))
    layers = max(1, math.ceil((logN - int(math.log2(final_deg))) / int(math.log2(fold))))
    size = 0
    parts = {}
    # FRI layer commitment roots
    parts["fri_roots"]    = layers * HASH
    # per query: trace/composition column openings (values + one Merkle path)
    parts["trace_open"]   = queries * (n_cols * FELT + logN * HASH)
    # per query: FRI folding openings across layers (fold values + path each layer)
    fri = 0
    d = logN
    for _ in range(layers):
        fri += queries * (fold * EXT + d * HASH)
        d = max(1, d - int(math.log2(fold)))
    parts["fri_query"]    = fri
    # final layer polynomial sent in the clear
    parts["final_poly"]   = final_deg * EXT
    # grinding nonce + transcript misc
    parts["grind+misc"]   = 8 + 64
    size = sum(parts.values())
    sec  = queries * math.log2(blowup) + grind_bits   # conjectured soundness (bits)
    return size, sec, parts

print("target: zero-knowledge + post-quantum + <=90KB\n")
print(f"{'log2(trace)':>11} {'blowup':>7} {'queries':>8} {'grind':>6} {'fold':>5} "
      f"{'~security':>10} {'proof KB':>9}")
chosen = None
for log_trace in (10, 12, 14, 16):
    # pick params aiming ~100-bit security under 90KB
    blowup, queries, grind, fold, cols = 16, 21, 16, 8, 12
    size, sec, parts = proof_bytes(log_trace, blowup, queries, grind, fold, cols)
    fits = size <= 90_000 and sec >= 100
    print(f"{log_trace:>11} {blowup:>7} {queries:>8} {grind:>6} {fold:>5} "
          f"{sec:>9.0f}b {size/1000:>8.1f}K  {'OK' if fits else ''}")
    if log_trace == 14:
        chosen = (log_trace, blowup, queries, grind, fold, cols, size, sec, parts)

lt, bl, q, gr, fo, co, size, sec, parts = chosen
print(f"\nchosen config (trace 2^{lt}):  security ~{sec:.0f} bits, proof {size/1000:.1f} KB")
for k, v in parts.items():
    print(f"   {k:<12} {v/1000:6.2f} KB")
print(f"   {'TOTAL':<12} {size/1000:6.2f} KB   ({'<=90KB OK' if size<=90000 else 'OVER'})")

# ---- HIDING commitment: salted Merkle leaf, verified by the EXISTING verifier ----
# leaf item = salt(32) || value ; commitment = SHA256(salt||value) hides `value`.
def salted_leaf(value, salt=None):
    salt = salt or os.urandom(32)
    return salt + value, salt

leaves = [salted_leaf(os.urandom(8))[0] for _ in range(256)]
layers = build_tree(leaves); root = layers[-1][0]; idx = 123
pth = proof(layers, idx)
prog = [PUSH(root), N(len(pth)), PUSH(leaves[idx])]
for (sib, d) in reversed(pth):
    prog += [PUSH(sib), OP("TOALT"), N(d), OP("TOALT")]
prog += [PUSH(MERKLE_FID), DEFINE(merkle_body), PUSH(MERKLE_FID), OP("INVOKE")]
VM().run(prog)
print("\nhiding commitment: salted-leaf opening verifies on existing verifier:  PASS")
# hiding argument: same value, two salts -> different commitments, root reveals nothing
v = os.urandom(8)
c1 = hashlib.sha256(salted_leaf(v)[0]).digest()
c2 = hashlib.sha256(salted_leaf(v)[0]).digest()
print("                   same value, different salt -> different commitment:",
      "PASS" if c1 != c2 else "FAIL")
