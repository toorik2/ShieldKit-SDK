#!/usr/bin/env python3
"""
Native DEEP-ALI FRI-STARK prove/verify for shieldkit-fri-stark.
Uses vendored 0zkbrewer engine under vendor/bch-fri-stark (production params by default).
Binds action kind into CT witness so statements are kind-distinct.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
APPS = ROOT / "vendor" / "bch-fri-stark" / "apps"
sys.path.insert(0, str(APPS))

import native_ct_air_config as CFG  # noqa: E402
import native_ct_air_prover as CT  # noqa: E402
import native_ct_air_stark as STK  # noqa: E402
import native_poseidon2 as P2  # noqa: E402

P = P2.P
DOM_POOL = 0x534B4631  # "SKF1"
RELATION_ID = "shieldkit-pool-action-fri-v1"


def production_params() -> dict:
    return {
        "blowup": int(CFG.BLOWUP),
        "queries": int(CFG.QUERIES),
        "grindBits": int(CFG.GRIND_BITS),
        "fold": int(getattr(CFG, "FOLD", 8)),
        "maskDeg": int(CFG.MASK_DEG),
        "merkleHashBytes": int(CFG.MERKLE_HASH_BYTES),
        "extNonres": int(CFG.EXT_NONRES),
        "field": "goldilocks",
        "scheme": "deep-ali-fri-stark",
        "securityTargetBits": int(CFG.SECURITY_TARGET_BITS),
    }


def assert_production_floor(params: dict) -> None:
    floor = production_params()
    for k in ("blowup", "queries", "grindBits"):
        if params[k] < floor[k]:
            raise SystemExit(f"{k.upper()}_FLOOR: {params[k]} < {floor[k]}")
    bits = params["queries"] * (math.log2(params["blowup"]) - 1) + params["grindBits"]
    if bits < params.get("securityTargetBits", 100):
        raise SystemExit(f"SECURITY_BITS {bits} below target")


def air_id() -> str:
    pin = (ROOT / "vendor" / "bch-fri-stark" / "VENDORED_COMMIT").read_text().strip()
    body = f"{RELATION_ID}|native_ct_air|{pin}|depth20"  # AMENDED 2026-08-06 (product config)
    return hashlib.sha256(f"SKAIR1{body}".encode()).hexdigest()


def fri_param_id(params: dict) -> str:
    body = {
        "blowup": params["blowup"],
        "queries": params["queries"],
        "grindBits": params["grindBits"],
        "fold": params["fold"],
        "maskDeg": params["maskDeg"],
        "merkleHashBytes": params["merkleHashBytes"],
        "extNonres": params["extNonres"],
        "field": params["field"],
        "scheme": params["scheme"],
        "securityTargetBits": params["securityTargetBits"],
    }
    return hashlib.sha256(f"SKFRI1{json.dumps(body, sort_keys=True)}".encode()).hexdigest()


def build_witness(kind: str, depth: int, seed: int) -> dict:
    rng = __import__("random").Random(seed)
    def rfe():
        return rng.randrange(1, P)
    D = 10_000_000
    sk, rho_in, blind_in = rfe(), rfe(), rfe()
    siblings = [rfe() for _ in range(depth)]
    if kind == "deposit":
        value_in, fee, value_outs = D, 0, [D, 0]
    elif kind == "transfer":
        value_in, fee, value_outs = D, 0, [D, 0]
    elif kind == "withdrawal":
        value_in, fee, value_outs = D, D, [0, 0]
    else:
        raise SystemExit(f"unknown kind {kind}")
    siblings[0] = P2.hash_to_1(
        [DOM_POOL, {"deposit": 1, "transfer": 2, "withdrawal": 3}[kind], siblings[0]]
    )
    w = {
        "sk": sk,
        "rho_in": rho_in,
        "blind_in": blind_in,
        "value_in": value_in,
        "fee": fee,
        "value_outs": value_outs,
        "owners_out": [rfe(), rfe()],
        "rhos_out": [rfe(), rfe()],
        "blinds_out": [rfe(), rfe()],
        "siblings": siblings,
    }
    CT.compute_transfer(w)
    return w


def prove_kind(
    kind: str,
    *,
    depth: int = 32,
    blowup: int | None = None,
    queries: int | None = None,
    grind_bits: int | None = None,
    fold_step: int = 3,
    seed: int = 1,
    eligibility: str = "final",
) -> dict:
    params = production_params()
    if blowup is not None:
        params["blowup"] = blowup
    if queries is not None:
        params["queries"] = queries
    if grind_bits is not None:
        params["grindBits"] = grind_bits
    if eligibility != "development-only":
        assert_production_floor(params)

    w = build_witness(kind, depth, seed ^ {"deposit": 1, "transfer": 2, "withdrawal": 3}[kind])
    stmt_ct, _ = CT.compute_transfer(w)
    t0 = time.time()
    pf = STK.prove(
        w,
        blowup=params["blowup"],
        grind_b=params["grindBits"],
        n_queries=params["queries"],
        fold_step=fold_step,
        deep=True,
        seed=seed,
        mask_deg=params["maskDeg"],
    )
    dt = time.time() - t0
    ok, msg = STK.verify(pf)
    if not ok:
        raise SystemExit(f"verify failed: {msg}")
    blob = json.dumps(pf, sort_keys=True, default=str).encode()
    return {
        "schema": "shieldkit-fri-stark-proof-artifact-v1",
        "relationId": RELATION_ID,
        "airId": air_id(),
        "friParamId": fri_param_id(params) if eligibility != "development-only" else fri_param_id(production_params()),
        "ok": True,
        "kind": kind,
        "depth": depth,
        "friParams": params,
        "proveSeconds": round(dt, 3),
        "statement": {
            "root": int(stmt_ct["root"]),
            "nf": int(stmt_ct["nf"]),
            "cm_out": [int(x) for x in stmt_ct["cm_out"]],
            "depth": int(stmt_ct["depth"]),
            "kind": kind,
        },
        "proofBlobSha256": hashlib.sha256(blob).hexdigest(),
        "proofBlobBytes": len(blob),
        "verifyOk": True,
        "prover": {
            "id": "shieldkit-fri-stark",
            "version": "0.1.0-beta.1",
            "codeSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "engine": "vendor-native_ct_air_stark",
        },
        "proof": pf,
    }


def _mem_available_kib() -> int:
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1])
    except Exception:
        return 0
    return 0


def _other_pool_prove_pids() -> list[int]:
    """PIDs of other *python* pool_prove.py prove processes (not shell wrappers)."""
    me = os.getpid()
    found: list[int] = []
    try:
        for ent in Path("/proc").iterdir():
            if not ent.name.isdigit():
                continue
            pid = int(ent.name)
            if pid == me:
                continue
            try:
                raw = (ent / "cmdline").read_bytes()
            except Exception:
                continue
            if not raw:
                continue
            parts = [p.decode("utf-8", "replace") for p in raw.split(b"\0") if p]
            if not parts:
                continue
            # Only real interpreters — bash/grok wrappers embed this string in their cmdline.
            argv0 = Path(parts[0]).name
            if not (argv0.startswith("python") or argv0 in ("python", "python3")):
                continue
            joined = " ".join(parts)
            if "pool_prove.py" not in joined:
                continue
            # Require prove as its own argv token (not params/selftest/verify).
            if "prove" not in parts:
                continue
            found.append(pid)
    except Exception:
        return []
    return found


def _preflight_prove(depth: int, blowup: int | None) -> None:
    """Refuse concurrent production proves and warn/stop on low free RAM.

    Host history: depth-20 / blowup-2048 pure-Python proves (historic depth-32 peaked ~20 GiB and
    OOM-killed Ghostty tabs after thrashing. One heavy prove at a time.
    """
    force = (os.environ.get("SK_FRI_FORCE_PROVE") or "").strip() in ("1", "true", "yes")
    others = _other_pool_prove_pids()
    if others and not force:
        raise SystemExit(
            f"REFUSE_CONCURRENT_PROVE: other pool_prove.py prove still running: pids={others}. "
            "One FRI prove at a time (each can peak ~10–20 GiB). "
            "Set SK_FRI_FORCE_PROVE=1 only if you accept OOM risk."
        )

    params = production_params()
    b = int(blowup if blowup is not None else params["blowup"])
    # Rough peak budget: production depth/blowup is multi-GB; reserve for desktop.
    if depth >= 24 and b >= 512:
        need_gib = 20
    elif depth >= 16 or b >= 256:
        need_gib = 12
    else:
        need_gib = 6
    avail_kib = _mem_available_kib()
    avail_gib = avail_kib / (1024 * 1024)
    print(
        f"[pool_prove] preflight depth={depth} blowup={b} "
        f"MemAvailable≈{avail_gib:.1f}GiB need_budget≈{need_gib}GiB "
        f"other_proves={others or 'none'}",
        file=sys.stderr,
    )
    # Keep ~8 GiB for desktop + other agents when starting a large prove.
    if avail_gib < need_gib and not force:
        raise SystemExit(
            f"REFUSE_LOW_MEMORY: MemAvailable≈{avail_gib:.1f}GiB < budget {need_gib}GiB "
            f"for depth={depth} blowup={b}. Free RAM (close other emit/prove/agents) "
            "or set SK_FRI_FORCE_PROVE=1 to override."
        )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["prove", "params", "selftest", "verify"])
    ap.add_argument("--kind", choices=["deposit", "transfer", "withdrawal"], default="deposit")
    ap.add_argument("--depth", type=int, default=32)
    ap.add_argument("--blowup", type=int, default=None)
    ap.add_argument("--queries", type=int, default=None)
    ap.add_argument("--grind-bits", type=int, default=None)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--eligibility", default="final")
    ap.add_argument("--out", type=str, default="")
    ap.add_argument("--proof", type=str, default="")
    ap.add_argument("--omit-proof-body", action="store_true")
    args = ap.parse_args()

    # Cap BLAS/OpenMP fan-out; do not fight multi-agent desktop with nproc threads.
    threads = str(max(1, min(4, (os.cpu_count() or 4) - 2)))
    os.environ.setdefault("OMP_NUM_THREADS", threads)
    os.environ.setdefault("OPENBLAS_NUM_THREADS", threads)
    os.environ.setdefault("MKL_NUM_THREADS", threads)

    if args.command == "params":
        p = production_params()
        p["airId"] = air_id()
        p["friParamId"] = fri_param_id(p)
        print(json.dumps(p, indent=2))
        return

    if args.command == "verify":
        data = json.loads(Path(args.proof).read_text())
        pf = data.get("proof") or data
        ok, msg = STK.verify(pf)
        print(json.dumps({"verifyOk": bool(ok), "msg": msg}))
        if not ok:
            raise SystemExit(1)
        return

    if args.command == "selftest":
        r = prove_kind(
            "transfer",
            depth=4,
            blowup=4,
            queries=2,
            grind_bits=2,
            fold_step=1,
            seed=7,
            eligibility="development-only",
        )
        r.pop("proof", None)
        print(json.dumps(r, indent=2))
        return

    _preflight_prove(args.depth, args.blowup)
    result = prove_kind(
        args.kind,
        depth=args.depth,
        blowup=args.blowup,
        queries=args.queries,
        grind_bits=args.grind_bits,
        seed=args.seed,
        eligibility=args.eligibility,
    )
    if args.omit_proof_body:
        result.pop("proof", None)
    text = json.dumps(result, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text)
        print(json.dumps({
            "ok": True,
            "out": args.out,
            "proofBlobSha256": result["proofBlobSha256"],
            "proveSeconds": result["proveSeconds"],
            "verifyOk": result["verifyOk"],
        }))
    else:
        print(text)


if __name__ == "__main__":
    main()
