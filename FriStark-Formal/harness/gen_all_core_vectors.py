#!/usr/bin/env python3
"""Generate core KAT vectors with ProcessPool; production-param discipline for product labels."""
import json, os, sys, hashlib, random
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"vendor/bch-fri-stark/apps"))
sys.path.insert(0, str(ROOT/"vendor/bch-fri-stark"))

P = (1 << 64) - (1 << 32) + 1
NWORK = min(8, max(1, (os.cpu_count() or 4) - 2))

def field_batch(seed):
    import native_gf_p2 as F
    rng = random.Random(seed)
    rows = []
    for _ in range(200):
        a = (rng.randrange(P), rng.randrange(P))
        b = (rng.randrange(P), rng.randrange(P))
        rows.append({
            "a": list(a), "b": list(b),
            "add": list(F.add(a,b)),
            "mul": list(F.mul(a,b)),
            "sub": list(F.sub(a,b)),
            "norm": F.norm(a),
            "inv": list(F.inv(a)) if F.norm(a) != 0 else None,
        })
    return rows

def gen_field():
    seeds = [0xC7A12026 + i for i in range(NWORK)]
    all_rows = []
    with ProcessPoolExecutor(max_workers=NWORK) as ex:
        for rows in ex.map(field_batch, seeds):
            all_rows.extend(rows)
    out = ROOT/"vectors/field/C-field.jsonl"
    with out.open("w") as f:
        for r in all_rows:
            f.write(json.dumps(r)+"\n")
    return len(all_rows)

def gen_poseidon():
    from native_poseidon2 import permutation, hash_to_1
    rows = []
    # official KAT
    rows.append({"in": list(range(12)), "out": permutation(list(range(12))), "kind": "perm"})
    rng = random.Random(42)
    for i in range(256):
        st = [rng.randrange(P) for _ in range(12)]
        rows.append({"in": st, "out": permutation(st), "kind": "perm"})
    for i in range(32):
        inp = [rng.randrange(P) for _ in range(rng.randint(1, 24))]
        rows.append({"in": inp, "out": hash_to_1(inp), "kind": "hash_to_1"})
    out = ROOT/"vectors/poseidon/C-poseidon.jsonl"
    with out.open("w") as f:
        for r in rows:
            f.write(json.dumps(r)+"\n")
    return len(rows)

def gen_merkle():
    import hashlib
    H = lambda b: hashlib.sha256(b).digest()
    def leaf_hash(v): return H(v)
    def node_hash(l,r): return H(l+r)
    def build_tree(leaves):
        level = [leaf_hash(v) for v in leaves]
        layers = [level]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                l = level[i]
                r = level[i+1] if i+1 < len(level) else level[i]
                nxt.append(node_hash(l,r))
            level = nxt
            layers.append(level)
        return layers
    def proof(layers, index):
        path = []; idx = index
        for d in range(len(layers)-1):
            level = layers[d]
            if idx % 2 == 0:
                sib = level[idx+1] if idx+1 < len(level) else level[idx]
                path.append((sib.hex(), 0))
            else:
                path.append((level[idx-1].hex(), 1))
            idx //= 2
        return path
    rows = []
    rng = random.Random(7)
    for n, idx in [(8,0),(8,7),(8,3),(16,5),(32,10),(64,31)] + [(8, rng.randrange(8)) for _ in range(100)]:
        leaves = [rng.randbytes(16) for _ in range(n)]
        layers = build_tree(leaves)
        root = layers[-1][0].hex()
        path = proof(layers, idx)
        rows.append({
            "leaves": [x.hex() for x in leaves],
            "index": idx,
            "root": root,
            "path": path,
            "ok": True,
        })
        # adversarial
        bad = list(path)
        if bad:
            b0 = bytes.fromhex(bad[0][0])
            bad[0] = (bytes((b ^ 0xFF) for b in b0).hex(), bad[0][1])
            rows.append({
                "leaves": [x.hex() for x in leaves],
                "index": idx,
                "root": root,
                "path": bad,
                "ok": False,
            })
    out = ROOT/"vectors/merkle/C-merkle.jsonl"
    with out.open("w") as f:
        for r in rows:
            f.write(json.dumps(r)+"\n")
    return len(rows)

def gen_fri_folds():
    import native_gf_p2 as F
    rng = random.Random(99)
    rows = []
    inv2 = pow(2, P-2, P)
    for _ in range(200):
        v = (rng.randrange(P), rng.randrange(P))
        w = (rng.randrange(P), rng.randrange(P))
        beta = (rng.randrange(P), rng.randrange(P))
        xpos = rng.randrange(1, P)
        # fold: (v+w)/2 + beta*(v-w)/(2x)
        i2x = pow((2 * xpos) % P, P-2, P)
        half = F.scalar(inv2, F.add(v,w))
        diff = F.sub(v,w)
        term = F.mul(beta, F.scalar(i2x, diff))
        folded = F.add(half, term)
        rows.append({"v": list(v), "w": list(w), "beta": list(beta), "xpos": xpos, "folded": list(folded)})
        # forge
        bad = F.add(folded, F.from_base(1))
        rows.append({"v": list(v), "w": list(w), "beta": list(beta), "xpos": xpos, "folded": list(bad), "forge": True})
    out = ROOT/"vectors/fri/C-fri-fold.jsonl"
    with out.open("w") as f:
        for r in rows:
            f.write(json.dumps(r)+"\n")
    return len(rows)

def gen_verify_bundles():
    """Atomic check bundles: honest + forges, product eligibility with production params."""
    import hashlib
    # honest merkle-based mini proof checklist
    leaf = b"hello-fri"
    root = hashlib.sha256(leaf).digest()
    # single-leaf tree: path empty, root = leafHash
    honest_checks = [
        {"tag": "merkleOpen", "root": root.hex(), "leaf": leaf.hex(), "index": 0, "path": []},
        {"tag": "grindOk", "ok": True},
        {"tag": "fieldEq", "a": 1, "b": 1},
    ]
    # fri fold honest from gen
    import native_gf_p2 as F
    v, w, beta, xpos = (2,3), (4,5), (6,7), 9
    inv2 = pow(2, P-2, P)
    i2x = pow((2 * xpos) % P, P-2, P)
    folded = F.add(F.scalar(inv2, F.add(v,w)), F.mul(beta, F.scalar(i2x, F.sub(v,w))))
    honest_checks.append({
        "tag": "friFold",
        "v": list(v), "w": list(w), "beta": list(beta),
        "folded": list(folded), "xpos": xpos
    })
    prod = {
        "checks": honest_checks,
        "accept": True,
        "label": "honest-atomic-secure",
        "eligibility": "product",
        "blowup": 2048, "queries": 8, "grindBits": 24, "fold": 8,
    }
    forge_bad_merkle = dict(prod)
    forge_bad_merkle = {
        **prod,
        "label": "forge-bad-merkle",
        "accept": False,
        "checks": [
            {"tag": "merkleOpen", "root": root.hex(), "leaf": b"wrong".hex(), "index": 0, "path": []},
        ],
    }
    forge_bad_fold = {
        **prod,
        "label": "forge-bad-fold",
        "accept": False,
        "checks": [{
            "tag": "friFold",
            "v": list(v), "w": list(w), "beta": list(beta),
            "folded": list(F.add(folded, F.from_base(1))), "xpos": xpos
        }],
    }
    forge_grind = {
        **prod,
        "label": "forge-grind",
        "accept": False,
        "checks": [{"tag": "grindOk", "ok": False}],
    }
    forge_params = {
        **prod,
        "label": "forge-wrong-params-as-product",
        "accept": False,
        "blowup": 8, "queries": 1, "grindBits": 2, "fold": 1,
        "checks": honest_checks,
    }
    # more forges
    forges = [forge_bad_merkle, forge_bad_fold, forge_grind, forge_params]
    for i in range(8):
        forges.append({
            **prod,
            "label": f"forge-reject-{i}",
            "accept": False,
            "checks": [{"tag": "reject", "why": f"forge{i}"}],
        })
    out = ROOT/"vectors/verify/C-verify-secure.jsonl"
    with out.open("w") as f:
        f.write(json.dumps(prod)+"\n")
        for g in forges:
            f.write(json.dumps(g)+"\n")
    # also run real python STARK verify smoke as oracle label
    try:
        import native_ct_air_stark as STK, native_ct_air_prover as CT
        pf = STK.prove(CT._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=4, fold_step=2, deep=True)
        ok, why = STK.verify(pf)
        meta = {"python_demo_verify": ok, "why": why, "eligibility": "development-only",
                "blowup": 8, "queries": 4, "grindBits": 2, "fold": 2}
        (ROOT/"vectors/verify/python_demo_oracle.json").write_text(json.dumps(meta, indent=2))
    except Exception as e:
        (ROOT/"vectors/verify/python_demo_oracle.json").write_text(json.dumps({"error": str(e)}))
    return 1 + len(forges)

def gen_statement():
    # FE packing KAT: 32 zero bytes -> 4 zero FE for GDig32
    rows = []
    bs = bytes([1]*32)
    # LE limbs
    limbs = []
    for i in range(4):
        n = int.from_bytes(bs[i*8:(i+1)*8], "little")
        limbs.append(n % P)
    rows.append({"kind": "gdig32", "bytes": bs.hex(), "fe": limbs})
    H = bytes(range(32))
    hfe = []
    for i in range(4):
        chunk = H[7*i:7*i+7]
        n = int.from_bytes(chunk, "big")  # BE of 7 bytes with leading 0
        hfe.append(n % P)
    n4 = int.from_bytes(H[28:32], "big")
    hfe.append(n4 % P)
    rows.append({"kind": "hash56", "bytes": H.hex(), "fe": hfe})
    out = ROOT/"vectors/statement/C-statement-v1.jsonl"
    with out.open("w") as f:
        for r in rows:
            f.write(json.dumps(r)+"\n")
    return len(rows)

def main():
    counts = {}
    counts["field"] = gen_field()
    counts["poseidon"] = gen_poseidon()
    counts["merkle"] = gen_merkle()
    counts["fri"] = gen_fri_folds()
    counts["verify"] = gen_verify_bundles()
    counts["statement"] = gen_statement()
    man = {"workers": NWORK, "counts": counts, "production": {"blowup":2048,"queries":8,"grindBits":24,"fold":8}}
    (ROOT/"vectors/MANIFEST.json").write_text(json.dumps(man, indent=2))
    print(json.dumps(man, indent=2))

if __name__ == "__main__":
    main()
