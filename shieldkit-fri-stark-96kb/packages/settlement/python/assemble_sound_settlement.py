#!/usr/bin/env python3
"""
Product settlement assembler: real Goldilocks DEEP-ALI FRI multi-input P2SH32 locks
via vendor native_ct_verifier_tx.build_sound_verifier_inputs + Libauth p2sh_multi.

Not PLACEHOLDER tag-hash toys. Emits JSON for packages/settlement product path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
APPS = ROOT / "vendor" / "bch-fri-stark" / "apps"
VENDOR = ROOT / "vendor" / "bch-fri-stark"
sys.path.insert(0, str(APPS))
sys.path.insert(0, str(VENDOR))
sys.path.insert(0, str(ROOT / "packages" / "prove" / "python"))

import native_ct_verifier_tx as V  # noqa: E402
import native_shard_deploy_check as D  # noqa: E402
import native_ct_air_stark as STK  # noqa: E402
import native_ct_air_prover as CT  # noqa: E402
import pool_prove as PP  # noqa: E402

VENDORED_COMMIT = (VENDOR / "VENDORED_COMMIT").read_text().strip() if (VENDOR / "VENDORED_COMMIT").exists() else "unknown"


def _security_bits(nq: int, blowup: int, grind: int) -> float:
    import math
    return nq * (math.log2(blowup) - 1) + grind


def is_power_of_8(n: int) -> bool:
    """True iff n == 8^m for some m>=0 (required for fold-8 loop all-s=3 redeems)."""
    if n <= 0:
        return False
    while n % 8 == 0:
        n //= 8
    return n == 1


def natural_trace_T(depth: int) -> int:
    """Natural FRI T for membership depth (STK.ct_build_layout pad-to-2^m)."""
    d = int(depth)
    if d >= 32:
        return 2048
    if d >= 4:
        return 1024
    return max(8, 1 << max(3, d))


def fri_security_bits(blowup: int, queries: int, grind: int) -> float:
    import math

    return float(queries) * (math.log2(float(blowup)) - 1.0) + float(grind)


def resolve_production_floor_domain(
    depth: int = 32,
    blowup: int = 2048,
    queries: int = 8,
    grind: int = 24,
    fold_step: int = 3,
    deep: bool = True,
) -> dict:
    """
    Resolve fold-8–legal domain without weakening security floor.

    AMENDED 2026-08-06: product config depth-20/blowup2048 has T=1024 → N=2^21 = 8^7 (legal). (Historic depth32/blowup2048 had T=2048 → N=2^22 ∉ 8ᵐ.)
    2048→8192 (N=2^24=8^8, security 120 bit) over T-pad.
    """
    T = natural_trace_T(depth)
    bits_floor = fri_security_bits(blowup, queries, grind)
    if bits_floor < 100:
        return {
            "ok": False,
            "depth": depth,
            "blowup": blowup,
            "queries": queries,
            "grind": grind,
            "fold_step": fold_step,
            "deep": deep,
            "T": T,
            "N": T * blowup,
            "pad": None,
            "securityBits": bits_floor,
            "reason": f"security floor {bits_floor} < 100 bit",
        }
    if int(fold_step) != 3:
        return {
            "ok": False,
            "depth": depth,
            "blowup": blowup,
            "queries": queries,
            "grind": grind,
            "fold_step": fold_step,
            "deep": deep,
            "T": T,
            "N": T * blowup,
            "pad": None,
            "securityBits": bits_floor,
            "reason": "fold_step must be 3 for fold-8 loop redeems",
        }
    b = int(blowup)
    pad = None
    N = T * b
    if not is_power_of_8(N):
        b0 = b
        guard = 0
        while not is_power_of_8(T * b) and guard < 16:
            b *= 2
            guard += 1
        if not is_power_of_8(T * b):
            return {
                "ok": False,
                "depth": depth,
                "blowup": blowup,
                "queries": queries,
                "grind": grind,
                "fold_step": fold_step,
                "deep": deep,
                "T": T,
                "N": T * blowup,
                "pad": None,
                "securityBits": bits_floor,
                "reason": f"cannot make N=8^m from T={T} blowupFloor={blowup}",
            }
        pad = {
            "kind": "blowup",
            "from": b0,
            "to": b,
            "T": T,
            "N": T * b,
            "note": "Domain pad raises blowup only so N=8^m; security does not weaken.",
        }
        N = T * b
    return {
        "ok": True,
        "depth": int(depth),
        "blowup": int(b),
        "queries": int(queries),
        "grind": int(grind),
        "fold_step": int(fold_step),
        "deep": bool(deep),
        "T": int(T),
        "N": int(N),
        "pad": pad,
        "securityBits": fri_security_bits(b, queries, grind),
        "reason": None,
    }


def fri_domain_preflight(
    depth: int,
    blowup: int,
    fold_step: int = 3,
    *,
    resolve_pad: bool = False,
    queries: int = 8,
    grind: int = 24,
) -> dict:
    """
    Fail-closed check before multi-minute prove.

    Vendor fold-8 loop redeem asserts all rounds s=3 ⇒ N=T*blowup must be 8^m.
    Exact floor depth32/blowup2048 ⇒ N=2^22 (not 8^m). Pass resolve_pad=True for
    plan-legal blowup pad (2048→8192).
    """
    if resolve_pad:
        r = resolve_production_floor_domain(depth, blowup, queries, grind, fold_step, True)
        return {
            "ok": r["ok"],
            "depth": r["depth"],
            "blowup": r["blowup"],
            "fold_step": r["fold_step"],
            "T": r["T"],
            "N": r["N"],
            "N_is_8m": is_power_of_8(r["N"]),
            "pad": r["pad"],
            "securityBits": r["securityBits"],
            "reason": r["reason"],
        }
    T = natural_trace_T(depth)
    try:
        meta = STK.ct_build_layout(int(depth))
        raw = int(meta["raw"]) if isinstance(meta, dict) else int(meta[0]["raw"])
        t2 = 1
        while t2 < raw:
            t2 <<= 1
        T = t2
    except Exception:
        pass
    N = int(T) * int(blowup)
    ok = is_power_of_8(N) and int(fold_step) == 3
    return {
        "ok": ok,
        "depth": depth,
        "blowup": blowup,
        "fold_step": fold_step,
        "T": int(T),
        "N": N,
        "N_is_8m": is_power_of_8(N),
        "pad": None,
        "reason": None
        if ok
        else (
            f"FRI domain N=T*blowup={T}*{blowup}={N} is not 8^m; "
            "fold-8 loop redeem requires all rounds s=3. "
            "Use resolve_pad / blowup→8192 (N=2^24) before proving."
        ),
    }


def assemble(
    kind: str,
    *,
    depth: int = 32,
    nq: int = 8,
    blowup: int = 2048,
    grind_b: int = 24,
    fold_step: int = 3,
    seed: int = 1,
    evaluate_vm: bool = True,
    forge_omit_final: bool = True,
) -> dict:
    t0 = time.time()
    # Hot-path patches: Rust FRI-terms + memoized _setup (floor N=2^24 was multi-10min hang).
    try:
        from rust_fri_bridge import patch_assemble_hotpaths

        _hp = patch_assemble_hotpaths(STK, V)
        print(
            f"assemble: hotpaths rustFriTerms={_hp.get('rustFriTerms')} "
            f"setupMemoize={_hp.get('setupMemoize')} selectorsAtK={_hp.get('selectorsAtK')} "
            f"worker={_hp.get('workerExists')}",
            flush=True,
        )
    except Exception as e:
        print(f"assemble: rust fri bridge unavailable ({e}); pure-Python path", flush=True)
    # Domain: exact floor may need 8ᵐ pad. VC_FLOOR_DOMAIN_PAD=1 (default for depth≥32)
    # applies plan-legal blowup pad without weakening security.
    resolve_pad = os.environ.get("VC_FLOOR_DOMAIN_PAD", "").strip() in ("1", "true", "yes")
    if not resolve_pad and int(depth) >= 32:
        resolve_pad = True  # product floor always domain-pads when needed
    pre = fri_domain_preflight(
        depth, blowup, fold_step, resolve_pad=resolve_pad, queries=nq, grind=grind_b
    )
    if not pre["ok"]:
        raise SystemExit(
            json.dumps(
                {
                    "ok": False,
                    "infeasible": True,
                    "productionFloorGreen": False,
                    "preflight": pre,
                }
            )
        )
    # Apply resolved blowup (may be padded)
    blowup = int(pre["blowup"])
    domain_pad = pre.get("pad")

    # Statement-compatible witness with Rust pool_witness / pool_prove.build_witness
    xor = {"deposit": 1, "transfer": 2, "withdrawal": 3}[kind]
    w = PP.build_witness(kind, depth, seed ^ xor)
    stmt_ct, _ = CT.compute_transfer(w)

    # Sound assembler currently uses STK.prove(demo_witness) inside build_sound_verifier_inputs.
    # Override: monkey-patch prove path by providing VC_PROOF_CACHE after we prove with our witness.
    cache = Path(os.environ.get("VC_PROOF_CACHE") or "")
    if not cache.name:
        cache = Path(
            f"/tmp/grok-goal-a75a99dfd55d/implementer/pf-cache/"
            f"pf-{kind}-d{depth}-b{blowup}-n{nq}-g{grind_b}-s{seed}.pkl"
        )
        os.environ["VC_PROOF_CACHE"] = str(cache)
        cache.parent.mkdir(parents=True, exist_ok=True)

    if not cache.is_file():
        print(f"assemble: STK.prove kind={kind} depth={depth} nq={nq} blowup={blowup} grind={grind_b} …", flush=True)
        pf = STK.prove(
            w,
            blowup=blowup,
            grind_b=grind_b,
            n_queries=nq,
            fold_step=fold_step,
            deep=True,
            seed=seed,
        )
        ok, why = STK.verify(pf)
        if not ok:
            raise SystemExit(f"STK.verify failed: {why}")
        # Align stmt kind for product
        pf.setdefault("stmt", {})
        if isinstance(pf["stmt"], dict):
            pf["stmt"]["kind"] = kind
        cache.parent.mkdir(parents=True, exist_ok=True)
        import pickle
        with open(cache, "wb") as f:
            pickle.dump(pf, f, protocol=4)
        print(f"assemble: wrote proof cache {cache}", flush=True)
    else:
        print(f"assemble: using proof cache {cache}", flush=True)
        import pickle as _pickle
        with open(cache, "rb") as _f:
            pf = _pickle.load(_f)  # artifact statement + cache-consistency use the loaded pf

    # Product tip: VC_ROLE_INDEX_BASE=1 → state@0 + FRI roles@1..n (absolute idx in redeems).
    try:
        input_base = int(str(os.environ.get("VC_ROLE_INDEX_BASE") or os.environ.get("VC_INPUT_BASE") or "0").strip() or "0")
    except ValueError:
        input_base = 0

    # build_sound_verifier_inputs proves with CT._demo_witness unless cache matches nq/blowup/grind/depth.
    # Cache key check uses stmt.depth — our cache must match.
    inputs, roles, meta = V.build_sound_verifier_inputs(
        nq=nq,
        blowup=blowup,
        grind_b=grind_b,
        fold_step=fold_step,
        seed=seed,
        depth=depth,
        input_base=input_base,
    )
    # For VM eval with input_base>0, prepend inert fillers so absolute indices match the tip layout.
    # Product substitutes real state@0 covenant for fillers; fillers only pad the multi-input harness.
    fillers = [{"redeem": "OP_1", "unlock": ""} for _ in range(input_base)]
    eval_inputs = fillers + inputs
    fri_abs = list(range(input_base, input_base + len(inputs)))

    vm = None
    forge = None
    if evaluate_vm:
        res = D._p2sh_multi(eval_inputs, evaluate=fri_abs)
        rs = {x["idx"]: x for x in res.get("results", [])}
        n_ok = sum(1 for i in fri_abs if rs.get(i, {}).get("ok"))
        max_unlock = max((rs[i].get("scriptSigBytes") or 0) for i in fri_abs) if fri_abs else 0
        max_redeem = max((rs[i].get("redeemBytes") or 0) for i in fri_abs) if fri_abs else 0
        fails = [
            {
                "idx": i,
                "role": roles[i - input_base],
                "error": str(rs.get(i, {}).get("error") or "")[:200],
            }
            for i in fri_abs
            if not rs.get(i, {}).get("ok")
        ]
        vm = {
            "nInputs": len(eval_inputs),
            "nFriRoles": len(inputs),
            "inputBase": input_base,
            "nOk": n_ok,
            "allAccept": n_ok == len(inputs),
            "txBytes": res.get("txBytes"),
            "underStandardLimit": bool(res.get("underStandardLimit") or (0 < (res.get("txBytes") or 0) < 100_000)),
            "maxUnlockBytes": max_unlock,
            "maxRedeemBytes": max_redeem,
            "unlockBarOk": max_unlock <= 10_000,
            "txBarOk": 0 < (res.get("txBytes") or 0) <= 100_000,
            "fails": fails,
            "perInput": [
                {
                    "idx": i,
                    "role": roles[i - input_base],
                    "ok": bool(rs.get(i, {}).get("ok")),
                    "scriptSigBytes": rs.get(i, {}).get("scriptSigBytes"),
                    "redeemBytes": rs.get(i, {}).get("redeemBytes"),
                }
                for i in fri_abs
            ],
        }
        if forge_omit_final and vm["allAccept"]:
            # omit last FRI role (comp_final); blob is at absolute index input_base
            omit = eval_inputs[:-1]
            r0 = D._p2sh_multi(omit, evaluate=[input_base])
            blob_ok = bool(r0.get("results", [{}])[0].get("ok"))
            forge = {
                "omit_final": {"blobAccepts": blob_ok, "rejectOk": not blob_ok},
            }

    # Export asm for product (locking via libauth P2SH32 elsewhere)
    # `index` is absolute tip index (state@0 → blob@1, ...).
    role_inputs = [
        {
            "role": roles[i],
            "redeemAsm": inputs[i]["redeem"],
            "unlockAsm": inputs[i].get("unlock") or "",
            "index": input_base + i,
            "friIndex": i,
        }
        for i in range(len(inputs))
    ]

    sec = _security_bits(nq, blowup, grind_b)
    topology_id = (
        "fri-sound-lean-fused-state0-v1" if input_base == 1 else "fri-sound-lean-fused-v1"
    )
    out = {
        "schema": "shieldkit-fri-stark-sound-settlement-v1",
        "productionVerifiers": True,
        "placeholder": False,
        "placeholderKind": None,
        "topologyId": topology_id,
        "kind": kind,
        "depth": depth,
        "friParams": {
            "blowup": blowup,
            "queries": nq,
            "grindBits": grind_b,
            "fold_step": fold_step,
            "deep": True,
        },
        "domainPreflight": pre,
        "domainPad": domain_pad,
        "securityBits": sec,
        # u64 fields as decimal strings (JS JSON.parse is not safe for integers > 2^53).
        "statement": {
            # The artifact statement must be the PROOF's statement (the pf cache may be
            # a caller-supplied wallet witness — production-randomness item 2), not the
            # assemble's own seed witness. Same value for the legacy seed-1 path.
            "root": str(int(pf["stmt"]["root"])),
            "nf": str(int(pf["stmt"]["nf"])),
            "cm_out": [str(int(x)) for x in pf["stmt"]["cm_out"]],
            "depth": int(pf["stmt"]["depth"]),
            "kind": kind,
        },
        "roles": roles,
        "nInputs": len(inputs),
        "inputBase": input_base,
        "roleIndexBase": input_base,
        "tipInputCount": len(eval_inputs),
        "meta": meta,
        "vendorPin": VENDORED_COMMIT,
        "engine": "vendor-native_ct_verifier_tx.build_sound_verifier_inputs",
        "vm": vm,
        "forge": forge,
        "roleInputs": role_inputs,
        "assembleSeconds": round(time.time() - t0, 3),
        "proofCache": str(cache),
    }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["deposit", "transfer", "withdrawal", "preflight"])
    ap.add_argument("--depth", type=int, default=20)  # AMENDED 2026-08-06 (product config)
    ap.add_argument("--nq", type=int, default=8)
    ap.add_argument("--blowup", type=int, default=2048)
    ap.add_argument("--grind", type=int, default=24)
    ap.add_argument("--fold-step", type=int, default=3)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", type=str, default="")
    ap.add_argument("--no-vm", action="store_true")
    args = ap.parse_args()
    if args.kind == "preflight":
        pre_exact = fri_domain_preflight(args.depth, args.blowup, args.fold_step, resolve_pad=False)
        pre_pad = fri_domain_preflight(
            args.depth, args.blowup, args.fold_step, resolve_pad=True, queries=args.nq, grind=args.grind
        )
        resolved = resolve_production_floor_domain(
            args.depth, args.blowup, args.nq, args.grind, args.fold_step, True
        )
        # doc.ok tracks *exact* floor (no pad): still fail-closed for the bare tuple.
        # withPad/resolved is the product path that clears DOMAIN_8M without security weaken.
        doc = {
            "exact": pre_exact,
            "withPad": pre_pad,
            "resolved": resolved,
            "ok": pre_exact["ok"],
            "infeasible": not pre_exact["ok"],
            "domainPadOk": bool(pre_pad.get("ok")),
            "productionFloorGreen": False,  # size/prove not claimed by preflight alone
            "preflight": pre_exact,
        }
        text = json.dumps(doc, indent=2)
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(text + "\n")
        print(text)
        # Exit 4 when exact domain illegal (historic contract); pad path still documented.
        sys.exit(0 if pre_exact["ok"] else 4)
    result = assemble(
        args.kind,
        depth=args.depth,
        nq=args.nq,
        blowup=args.blowup,
        grind_b=args.grind,
        fold_step=args.fold_step,
        seed=args.seed,
        evaluate_vm=not args.no_vm,
    )
    text = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        # Strip huge asm from file optionally? Keep full for product.
        Path(args.out).write_text(text + "\n")
        # Also write slim without roleInputs asm for reports
        slim = {k: v for k, v in result.items() if k != "roleInputs"}
        slim["roleInputCount"] = len(result["roleInputs"])
        Path(args.out.replace(".json", ".slim.json")).write_text(json.dumps(slim, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in result if k != "roleInputs"}, indent=2))
    if result.get("vm") and not result["vm"].get("allAccept"):
        sys.exit(2)
    if result.get("vm") and not (result["vm"].get("txBarOk") and result["vm"].get("unlockBarOk")):
        sys.exit(3)


if __name__ == "__main__":
    main()
