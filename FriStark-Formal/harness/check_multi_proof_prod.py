#!/usr/bin/env python3
"""
Phase-1 multi-proof gate: ≥3 honest production-param STARK proofs under V1 pin.
Requires blowup=2048, nq=8, grind_b=24, fold_step=8, deep=True, Python verify ok.
Does not invent paths — fails if MANIFEST or files lie.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors" / "verify"
sys.path.insert(0, str(ROOT / "vendor" / "bch-fri-stark"))
sys.path.insert(0, str(ROOT / "vendor" / "bch-fri-stark" / "apps"))

import native_ct_air_stark as STK  # noqa: E402

REQ = {
    "blowup": 2048,
    "nq": 8,
    "grind_b": 24,
    "fold_step": 8,
}


def check_one(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"MISSING {path}")
    proof = json.loads(path.read_text())
    for k, v in REQ.items():
        got = proof.get(k)
        if got != v:
            raise SystemExit(f"FAIL {path.name}: {k}={got} want {v}")
    if proof.get("deep") is not True:
        raise SystemExit(f"FAIL {path.name}: deep={proof.get('deep')} want True")
    depth = proof.get("stmt", {}).get("depth")
    ok, msg = STK.verify(proof)
    if not ok:
        raise SystemExit(f"FAIL verify {path.name}: {msg}")
    return {"path": str(path.relative_to(ROOT)), "depth": depth, "ok": True, **{k: proof.get(k) for k in REQ}}


def main() -> int:
    # Canonical multi-proof set (must match MANIFEST multi_proof.stark_ct basenames)
    names = ["prod_proof_d1.json", "prod_proof_d2.json", "prod_proof_d3.json"]
    rows = []
    for name in names:
        rows.append(check_one(OUT / name))

    # MANIFEST honesty
    man = json.loads((ROOT / "vectors" / "MANIFEST.json").read_text())
    listed = man.get("multi_proof", {}).get("stark_ct", [])
    listed_base = [Path(p).name for p in listed]
    if listed_base != names:
        raise SystemExit(f"MANIFEST stark_ct mismatch: {listed_base} != {names}")

    depths = sorted({r["depth"] for r in rows})
    if len(rows) < 3:
        raise SystemExit(f"need ≥3 proofs, got {len(rows)}")

    print(f"multi_stark_proofs={len(rows)}")
    for r in rows:
        print(
            f"  {Path(r['path']).name}: depth={r['depth']} "
            f"blowup={r['blowup']} nq={r['nq']} grind={r['grind_b']} fold_step={r['fold_step']} verify=ok"
        )
    print(f"depths={depths}")
    print("prod_params=blowup=2048 queries=8 grind=24 fold=8")
    print("DIFF_MULTI_STARK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
