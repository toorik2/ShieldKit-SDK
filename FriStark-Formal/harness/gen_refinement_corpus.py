#!/usr/bin/env python3
"""Multi-sample differential corpora for role-linked abstract checks."""
import json, os, random, hashlib
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors/refinement"
OUT.mkdir(parents=True, exist_ok=True)
P = (1<<64)-(1<<32)+1
NWORK = min(8, max(1, (os.cpu_count() or 4)-2))

def merkle_batch(seed):
    rng = random.Random(seed)
    rows = []
    H = lambda b: hashlib.sha256(b).digest()
    def build(leaves):
        level = [H(v) for v in leaves]
        layers = [level]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                l = level[i]; r = level[i+1] if i+1 < len(level) else level[i]
                nxt.append(H(l+r))
            level = nxt; layers.append(level)
        return layers
    def path(layers, idx):
        p=[]; i=idx
        for d in range(len(layers)-1):
            level=layers[d]
            if i%2==0:
                sib=level[i+1] if i+1<len(level) else level[i]
                p.append((sib.hex(),0))
            else:
                p.append((level[i-1].hex(),1))
            i//=2
        return p
    for _ in range(50):
        n = rng.choice([4,8,16,32])
        leaves = [rng.randbytes(16) for _ in range(n)]
        layers = build(leaves)
        root = layers[-1][0].hex()
        idx = rng.randrange(n)
        rows.append({"ok": True, "leaf": leaves[idx].hex(), "root": root, "path": path(layers, idx), "index": idx})
        # adversarial
        bad = list(path(layers, idx))
        if bad:
            s,d = bad[0]
            bad[0] = (bytes(x^0xFF for x in bytes.fromhex(s)).hex(), d)
            rows.append({"ok": False, "leaf": leaves[idx].hex(), "root": root, "path": bad, "index": idx})
    return rows

def fri_batch(seed):
    import sys
    sys.path.insert(0, str(ROOT/"vendor/bch-fri-stark/apps"))
    import native_gf_p2 as F2
    rng = random.Random(seed)
    rows = []
    inv2 = pow(2, P-2, P)
    for _ in range(50):
        v = (rng.randrange(P), rng.randrange(P))
        w = (rng.randrange(P), rng.randrange(P))
        beta = (rng.randrange(P), rng.randrange(P))
        xpos = rng.randrange(1, P)
        i2x = pow((2*xpos)%P, P-2, P)
        folded = F2.add(F2.scalar(inv2, F2.add(v,w)), F2.mul(beta, F2.scalar(i2x, F2.sub(v,w))))
        rows.append({"ok": True, "v": list(v), "w": list(w), "beta": list(beta), "xpos": xpos, "folded": list(folded)})
        bad = F2.add(folded, F2.from_base(1))
        rows.append({"ok": False, "v": list(v), "w": list(w), "beta": list(beta), "xpos": xpos, "folded": list(bad)})
    return rows

def main():
    with ProcessPoolExecutor(max_workers=NWORK) as ex:
        mrows = []
        for part in ex.map(merkle_batch, [100+i for i in range(NWORK)]):
            mrows.extend(part)
        frows = []
        for part in ex.map(fri_batch, [200+i for i in range(NWORK)]):
            frows.extend(part)
    (OUT/"merkle.jsonl").write_text("\n".join(json.dumps(r) for r in mrows)+"\n")
    (OUT/"fri.jsonl").write_text("\n".join(json.dumps(r) for r in frows)+"\n")
    # Role → corpus mapping (which abstract checks each FRI role exercises)
    roles = {
        "blob": {"corpus": ["merkle"], "samples": len(mrows), "note": "FS blob commitment + merkle material"},
        "deepquery": {"corpus": ["merkle"], "samples": len(mrows), "note": "trace/comp openings"},
        "aggFRI": {"corpus": ["fri", "merkle"], "samples": len(frows)+len(mrows), "note": "FRI fold + layer merkle"},
        "comp_trans": {"corpus": ["fri"], "samples": len(frows), "note": "composition / fold chain"},
        "comp_final": {"corpus": ["merkle", "fri"], "samples": len(mrows)+len(frows), "note": "final root + last fold"},
    }
    (OUT/"role_map.json").write_text(json.dumps(roles, indent=2))
    print(json.dumps({"workers": NWORK, "merkle": len(mrows), "fri": len(frows), "roles": list(roles)}, indent=2))

if __name__ == "__main__":
    main()
