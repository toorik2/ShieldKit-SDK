import os, hashlib
from cashvm import VM, P, N, OP, DEFINE, encode_num, decode_num, VMError
from structures_merkle import build_tree, proof, merkle_body, MERKLE_FID

# QUERY wrapper (fid 0x11): pull (root, depth, leaf) from alt, then invoke merkle.
QUERY_FID = b"\x11"
query_body = [
    OP("FROMALT"),  # root  -> main bottom
    OP("FROMALT"),  # depth
    OP("FROMALT"),  # leaf  (top)
    P(MERKLE_FID), OP("INVOKE"),
]

# Outer loop over N queries, counter on main.
def build_multi_query(queries):
    """queries: list of (root, leaf, path).  Verifies ALL in one VM evaluation."""
    prog = []
    # lay each query's data on alt; query 0 must end on TOP -> push last query first.
    for (root, leaf, path) in reversed(queries):
        # push so that after all pushes, this query's order top->down is:
        #   root, depth, leaf, dir0, sib0, dir1, sib1, ...
        # LIFO: push deepest path level first ... then leaf, depth, root last.
        for (sib, d) in reversed(path):
            prog += [P(sib), OP("TOALT")]      # sib (merkle pops 2nd)
            prog += [N(d), OP("TOALT")]        # dir (merkle pops 1st)
        prog += [P(leaf), OP("TOALT")]
        prog += [N(len(path)), OP("TOALT")]
        prog += [P(root), OP("TOALT")]
    # define functions
    prog += [P(MERKLE_FID), DEFINE(merkle_body)]
    prog += [P(QUERY_FID), DEFINE(query_body)]
    # outer loop: counter = N
    prog += [N(len(queries))]
    prog += [
        OP("BEGIN"),
            P(QUERY_FID), OP("INVOKE"),
            N(1), OP("SUB"),
            OP("DUP"), N(0), OP("NUMEQUAL"),
        OP("UNTIL"),
        OP("DROP"),
    ]
    return prog

def make_query(n_leaves, index):
    leaves = [os.urandom(16) for _ in range(n_leaves)]
    layers = build_tree(leaves)
    return (layers[-1][0], leaves[index], proof(layers, index))

# ---- test: 16 queries across independent trees, one VM evaluation -----------
queries = [make_query(1024, i * 61 % 1024) for i in range(16)]
prog = build_multi_query(queries)
vm = VM(); vm.run(prog)
assert vm.s == [], "stack not clean: %r" % vm.s
print(f"multi-query loop: {len(queries)} queries (depth-10 each) verified in ONE evaluation")
print(f"  total VM steps = {vm.steps},  peak stack+alt depth = {vm.maxdepth}")

# ---- negative: corrupt query #9's leaf -> whole evaluation must fail --------
bad = list(queries)
r, l, p = bad[9]; bad[9] = (r, os.urandom(16), p)
try:
    VM().run(build_multi_query(bad)); raise SystemExit("ERROR: should have failed")
except VMError:
    print("  corrupting one query out of 16: CORRECTLY REJECTED whole proof")

print("\nMULTI-QUERY LOOP STRUCTURE: ALL VECTORS PASS")
