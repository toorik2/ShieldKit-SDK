#!/usr/bin/env python3
"""Independent dense-valid BN254 Groth16 corpus for the c7 strict promotion gate.

The corpus is generated from scalar VK data and checked with py_ecc.bn128. It does not
call the repository's JS proof minter. Each candidate is flat so c7_merge.ts can consume
one object directly with ELIG_INSTANCE=file ELIG_FILE=... .
"""
import argparse
import json
import random
from pathlib import Path

from py_ecc.bn128 import FQ12, G1, G2, add, curve_order, multiply, neg, pairing


def point_g1(p):
    return {"x": str(int(p[0])), "y": str(int(p[1]))}


def point_g2(p):
    return {
        "x": {"c0": str(int(p[0].coeffs[0])), "c1": str(int(p[0].coeffs[1]))},
        "y": {"c0": str(int(p[1].coeffs[0])), "c1": str(int(p[1].coeffs[1]))},
    }


def vm_positive_len(n):
    if n == 0:
        return 0
    raw = n.to_bytes((n.bit_length() + 7) // 8, "little")
    return len(raw) + (1 if raw[-1] & 0x80 else 0)


def check(vk, proof, inputs):
    vkx = vk["ic"][0]
    for i, value in enumerate(inputs):
        vkx = add(vkx, multiply(vk["ic"][i + 1], value % curve_order))
    a, b, c = proof
    product = (
        pairing(b, neg(a))
        * pairing(vk["beta"], vk["alpha"])
        * pairing(vk["gamma"], vkx)
        * pairing(vk["delta"], c)
    )
    return product == FQ12.one()


def candidate_record(index, proof, inputs):
    a, b, c = proof
    pa, pb, pc = point_g1(a), point_g2(b), point_g1(c)
    values = [
        int(pa["x"]), int(pa["y"]),
        int(pb["x"]["c0"]), int(pb["x"]["c1"]),
        int(pb["y"]["c0"]), int(pb["y"]["c1"]),
        int(pc["x"]), int(pc["y"]),
        *inputs,
    ]
    return {
        "id": f"dense-{index:04d}",
        "Ax": pa["x"], "Ay": pa["y"],
        "Bxa": pb["x"]["c0"], "Bxb": pb["x"]["c1"],
        "Bya": pb["y"]["c0"], "Byb": pb["y"]["c1"],
        "Cx": pc["x"], "Cy": pc["y"],
        "in0": str(inputs[0]), "in1": str(inputs[1]),
        "denseArgCount": sum(vm_positive_len(v) == 32 for v in values),
        "argBytes": sum(vm_positive_len(v) for v in values),
        "verified": True,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors", default="harness/src/checkpoints/pairing-vectors.json")
    ap.add_argument("--out", default="/tmp/verifier-cash-dense-proof-corpus-20260717.json")
    ap.add_argument("--candidate-dir", default="/tmp/verifier-cash-dense-proof-candidates-20260717")
    ap.add_argument("--count", type=int, default=256)
    ap.add_argument("--seed", type=int, default=0x5A17D00E)
    args = ap.parse_args()
    if args.count < 16:
        raise SystemExit("--count must be >= 16")

    vectors = json.loads(Path(args.vectors).read_text())
    scalars = vectors["scalars"]
    r = curve_order
    alpha_s, beta_s = int(scalars["alpha"]), int(scalars["beta"])
    gamma_s, delta_s = int(scalars["gamma"]), int(scalars["delta"])
    ic_s = [int(x) for x in scalars["ic"]]
    vk = {
        "alpha": multiply(G1, alpha_s % r),
        "beta": multiply(G2, beta_s % r),
        "gamma": multiply(G2, gamma_s % r),
        "delta": multiply(G2, delta_s % r),
        "ic": [multiply(G1, x % r) for x in ic_s],
    }
    rng = random.Random(args.seed)
    min_dense = 1 << 249
    inv_delta = pow(delta_s, r - 2, r)
    rows = []
    candidate_dir = Path(args.candidate_dir)
    candidate_dir.mkdir(parents=True, exist_ok=True)
    for index in range(args.count):
        in0, in1 = rng.randrange(min_dense, r), rng.randrange(min_dense, r)
        a_s, b_s = rng.randrange(1, r), rng.randrange(1, r)
        vkx_s = (ic_s[0] + in0 * ic_s[1] + in1 * ic_s[2]) % r
        c_s = ((a_s * b_s - alpha_s * beta_s - vkx_s * gamma_s) * inv_delta) % r
        proof = (multiply(G1, a_s), multiply(G2, b_s), multiply(G1, c_s))
        if not check(vk, proof, [in0, in1]):
            raise SystemExit(f"py_ecc rejected generated candidate {index}")
        row = candidate_record(index, proof, [in0, in1])
        rows.append(row)

    rows.sort(key=lambda x: (-x["denseArgCount"], -x["argBytes"], x["id"]))
    for rank, row in enumerate(rows):
        row["densityRank"] = rank
        (candidate_dir / f"{rank:03d}-{row['id']}.json").write_text(json.dumps(row, indent=2) + "\n")
    corpus = {
        "schema": "verifier.cash/dense-proof-corpus/v1",
        "curve": "BN254/alt_bn128",
        "sourceVectors": args.vectors,
        "generator": "tools/dense-proof-corpus.py",
        "oracle": "py_ecc.bn128",
        "seed": args.seed,
        "count": len(rows),
        "verifiedCount": len(rows),
        "candidates": rows,
    }
    Path(args.out).write_text(json.dumps(corpus, indent=2) + "\n")
    print(json.dumps({
        "out": args.out,
        "candidateDir": str(candidate_dir),
        "count": len(rows),
        "verifiedCount": len(rows),
        "top": rows[:5],
    }, indent=2))


if __name__ == "__main__":
    main()
