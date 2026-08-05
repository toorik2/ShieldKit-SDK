import hashlib, os
from cashvm import VM, P, N, OP, DEFINE, encode_num, decode_num, VMError

H = lambda b: hashlib.sha256(b).digest()

# ---- reference Merkle tree (independent of the VM) --------------------------
def leaf_hash(v): return H(v)
def node_hash(l, r): return H(l + r)

def build_tree(leaves):
    level = [leaf_hash(v) for v in leaves]
    layers = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            l = level[i]
            r = level[i+1] if i+1 < len(level) else level[i]  # duplicate last if odd
            nxt.append(node_hash(l, r))
        level = nxt
        layers.append(level)
    return layers

def proof(layers, index):
    """Return list of (sibling, dir) from leaf up. dir=0 => current is LEFT child."""
    path = []
    idx = index
    for d in range(len(layers) - 1):
        level = layers[d]
        if idx % 2 == 0:
            sib = level[idx+1] if idx+1 < len(level) else level[idx]
            path.append((sib, 0))   # current is left
        else:
            path.append((level[idx-1], 1))  # current is right
        idx //= 2
    return path

# ---- the VM structure: verify_merkle_path (function id = 0x10) ---------------
# Precondition on entry (main, bottom->top): [ root, depth, leaf ]
# alt stack (top first): dir_0, sib_0, dir_1, sib_1, ... (level 0 consumed first)
# Effect: hashes leaf up the path; EQUALVERIFY against root. Leaves clean stack.
MERKLE_FID = b"\x10"

merkle_body = [
    OP("SHA256"),                      # cur = H(leaf)            main:[root,depth,cur]
    OP("BEGIN"),
        OP("FROMALT"),                 # dir                      [root,depth,cur,dir]
        OP("FROMALT"),                 # sib                      [root,depth,cur,dir,sib]
        OP("SWAP"),                    #                          [...,cur,sib,dir]
        OP("IF"),                      # dir==1 -> cur is RIGHT    consumes dir
            OP("SWAP"),                #                          [...,depth, sib, cur]
            OP("CAT"),                 # sib||cur
        OP("ELSE"),                    # dir==0 -> cur is LEFT
            OP("CAT"),                 # cur||sib
        OP("ENDIF"),
        OP("SHA256"),                  # newcur                   [root,depth,newcur]
        OP("SWAP"),                    #                          [root,newcur,depth]
        OP("1SUB"),                    # depth-1                  [root,newcur,depth-1]
        OP("DUP"), N(0), OP("NUMEQUAL"),  # flag=(depth-1==0)     [root,newcur,depth-1,flag]
        OP("TOALT"),                   # park flag                [root,newcur,depth-1]
        OP("SWAP"),                    #                          [root,depth-1,newcur]
        OP("FROMALT"),                 # bring flag back          [root,depth-1,newcur,flag]
    OP("UNTIL"),                       # exit when flag!=0
    # main now: [root, 0, cur]
    OP("SWAP"), OP("DROP"),            # drop the 0 -> [root, cur]
    OP("EQUALVERIFY"),                 # root == cur ?  (fails otherwise)
]

def witness_merkle(root, leaf, path):
    """Build the setup program that lays out stacks, then defines+invokes the fn."""
    prog = []
    # push main: root, depth, leaf
    prog += [P(root), N(len(path)), P(leaf)]
    # push path onto alt so level 0 ends up on TOP.
    # For each level we need (FROMALT->dir, FROMALT->sib): so push sib first, then dir.
    # And level 0 must be popped first => push level (d-1) first ... level 0 last.
    for (sib, d) in reversed(path):
        prog += [P(sib), OP("TOALT")]          # sib (popped 2nd)
        prog += [N(d), OP("TOALT")]            # dir (popped 1st)
    # define + invoke
    prog += [P(MERKLE_FID), DEFINE(merkle_body)]
    prog += [P(MERKLE_FID), OP("INVOKE")]
    return prog

# ---- tests ------------------------------------------------------------------
def test_merkle(n_leaves, index):
    leaves = [os.urandom(16) for _ in range(n_leaves)]
    layers = build_tree(leaves)
    root = layers[-1][0]
    path = proof(layers, index)
    prog = witness_merkle(root, leaves[index], path)
    vm = VM(); vm.run(prog)
    assert vm.s == [], "stack not clean: %r" % vm.s
    return len(path), vm.steps

ok = True
for (n, idx) in [(8, 0), (8, 7), (8, 3), (16, 5), (16, 10), (1024, 511), (1024, 1023)]:
    depth, steps = test_merkle(n, idx)
    print(f"merkle  leaves={n:<5} index={idx:<5} depth={depth:<3} steps={steps:<4} -> VALID")

# negative test: tamper one sibling -> must fail
def test_merkle_tamper():
    leaves = [os.urandom(16) for _ in range(8)]
    layers = build_tree(leaves); root = layers[-1][0]
    path = proof(layers, 3)
    bad = list(path); bad[0] = (os.urandom(32), bad[0][1])  # corrupt a sibling
    prog = witness_merkle(root, leaves[3], bad)
    vm = VM()
    try:
        vm.run(prog); return False
    except VMError:
        return True

assert test_merkle_tamper(), "tampered proof should have failed"
print("merkle  tampered-proof rejection           -> CORRECTLY REJECTED")

# negative test: wrong leaf -> must fail
def test_merkle_wrongleaf():
    leaves = [os.urandom(16) for _ in range(8)]
    layers = build_tree(leaves); root = layers[-1][0]
    path = proof(layers, 3)
    prog = witness_merkle(root, os.urandom(16), path)  # wrong leaf
    vm = VM()
    try:
        vm.run(prog); return False
    except VMError:
        return True

assert test_merkle_wrongleaf(), "wrong leaf should have failed"
print("merkle  wrong-leaf rejection               -> CORRECTLY REJECTED")
print("\nMERKLE STRUCTURE: ALL VECTORS PASS")
