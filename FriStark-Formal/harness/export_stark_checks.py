#!/usr/bin/env python3
"""Export production STARK checklists: structural Lean atoms only (no reject-tag theater).

Honest + forges always export merkle/fri/grind/idx/final checks that Lean re-executes.
Accept label from Python STK.verify (honest once; forges labeled accept=False and must
independently fail at least one Lean structural check).
"""
from __future__ import annotations
import copy, json, sys, time, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor/bch-fri-stark/apps"))
sys.path.insert(0, str(ROOT / "vendor/bch-fri-stark"))

import native_ct_air_config as C
import native_ct_air_stark as STK
import native_gf_p2 as F2
from stark import FS, Hf, m_verify, merkle, m_root

P = C.P
OUT = ROOT / "vectors/verify"
OUT.mkdir(parents=True, exist_ok=True)

def _ext_challenge(fs):
    return (fs.challenge(), fs.challenge())

def fs_before_grind(proof):
    """Replay verify FS up to grind. Returns (ok, state_bytes|None, why, expected_betas, expected_ri, N, T)."""
    from native_ct_air_stark import (
        ct_build_layout, ct_public_layout, ct_num_transition_residuals,
        ct_boundary_constraints, _setup, _selector_vectors, _deep_replay, _fri_folds_to_final,
    )
    stmt = proof["stmt"]; D = stmt["depth"]
    meta, T = ct_build_layout(D)
    N, oT, oN, off, Hd, Dd, last = _setup(T, proof["blowup"])
    lay = ct_public_layout(meta, T)
    sv = _selector_vectors(lay, T, N, oT, oN, off)
    tp_root = bytes.fromhex(proof["tp_root"])
    fri_roots = [bytes.fromhex(r) for r in proof["fri_roots"]]
    step = proof.get("fold_step", 1)
    fs = FS(); fs.absorb(tp_root)
    fs.absorb_int(stmt["root"]); fs.absorb_int(stmt["nf"])
    for cm in stmt["cm_out"]:
        fs.absorb_int(cm)
    n_T = ct_num_transition_residuals()
    bcons = ct_boundary_constraints(meta, stmt)
    alphas_T = [_ext_challenge(fs) for _ in range(n_T)]
    alphas_B = [_ext_challenge(fs) for _ in range(len(bcons))]
    deep = proof.get("deep", False)
    if deep:
        ok, why, _z, _zg, _da, _q = _deep_replay(fs, proof, alphas_T, alphas_B, meta, T, oT,
                                                  Hd, Dd, N, last, lay, sv)
        if not ok:
            return False, None, why, [], 0, N, T
    fs.absorb(b"fri"); betas = []; size = N; ri = 0
    if step == 1:
        while True:
            if ri >= len(fri_roots):
                return False, fs.s, "fri_roots length", betas, ri, N, T
            fs.absorb(fri_roots[ri]); ri += 1
            if size <= 8:
                break
            betas.append(_ext_challenge(fs)); size //= 2
    else:
        while True:
            if ri >= len(fri_roots):
                return False, fs.s, "fri_roots length", betas, ri, N, T
            fs.absorb(fri_roots[ri]); s = min(step, _fri_folds_to_final(size)); ri += 1
            if s == 0:
                break
            for _ in range(s):
                betas.append(_ext_challenge(fs)); size >>= 1
    if len(fri_roots) != ri:
        return False, fs.s, "fri_roots length", betas, ri, N, T
    return True, fs.s, "ok", betas, ri, N, T

def digest_open(root_hex, leaf_bytes, path_pairs):
    path = []
    for s, d in path_pairs:
        sb = bytes.fromhex(s) if isinstance(s, str) else s
        path.append([sb.hex(), int(d)])
    leaf = leaf_bytes if isinstance(leaf_bytes, (bytes, bytearray)) else bytes(leaf_bytes)
    root = bytes.fromhex(root_hex) if isinstance(root_hex, str) else root_hex
    ok = m_verify(root, leaf, 0, [(bytes.fromhex(s), b) for s, b in path])
    return {
        "tag": "merkleOpenDigest",
        "root": root.hex(),
        "leafDigest": leaf.hex(),
        "path": path,
        "py_ok": bool(ok),
    }

def fri_fold_check(v, w, beta, xpos):
    inv2 = pow(2, P-2, P)
    i2x = pow((2 * int(xpos)) % P, P-2, P)
    fv, fw, be = tuple(map(int, v)), tuple(map(int, w)), tuple(map(int, beta))
    half = F2.scalar(inv2, F2.add(fv, fw))
    term = F2.mul(be, F2.scalar(i2x, F2.sub(fv, fw)))
    folded = F2.add(half, term)
    return {"tag": "friFold", "v": list(fv), "w": list(fw), "beta": list(be),
            "folded": list(folded), "xpos": int(xpos)}

def structural_checks(proof):
    """Always export structural atoms; keep failing merkle opens (do not filter)."""
    from native_ct_air_stark import (
        FLAT_COLS, _leaf, _leaf_ext, _leaf_ext_pair, _leaf_ext_coset, _setup, ct_build_layout,
        _fri_folds_to_final,
    )
    checks = []
    stmt = proof["stmt"]; D = stmt["depth"]
    meta, T = ct_build_layout(D)
    N, oT, oN, off, Hd, Dd, last = _setup(T, proof["blowup"])
    deep = proof.get("deep", False)
    step = proof.get("fold_step", 1)
    pairleaf = proof.get("pairleaf", False)

    # FS grind + idx + fri_roots length + beta match
    fs_ok, fs_state, fs_why, exp_betas, exp_ri, N2, T2 = fs_before_grind(proof)
    checks.append({"tag": "natEq", "a": len(proof.get("fri_roots", [])), "b": exp_ri, "note": "fri_roots_len"})
    if fs_state is not None:
        nonce = bytes.fromhex(proof["nonce"])
        checks.append({
            "tag": "grindCheck",
            "state": fs_state.hex(),
            "nonce": nonce.hex(),
            "grindBits": int(proof["grind_b"]),
        })
        # idx list after absorb nonce
        fs2 = FS(); fs2.s = fs_state
        fs2.absorb(nonce)
        nq = int(proof["nq"])
        exp_idxs = [fs2.challenge_idx(N) for _ in range(nq)]
        act_idxs = [int(q["k"]) for q in proof.get("queries", [])]
        checks.append({"tag": "natListEq", "a": exp_idxs, "b": act_idxs, "note": "query_idxs"})
    # beta list equality when both available
    if exp_betas:
        act = [tuple(map(int, b)) for b in proof.get("betas", [])]
        exp = [tuple(map(int, b)) for b in exp_betas]
        # encode as paired natEq on flattened length + first mismatch via extEq batch
        checks.append({"tag": "natEq", "a": len(act), "b": len(exp), "note": "betas_len"})
        for i, (e, a) in enumerate(zip(exp, act)):
            checks.append({"tag": "extEq", "a": list(e), "b": list(a), "note": f"beta[{i}]"})

    # final root bind
    try:
        final = [tuple(map(int, v)) for v in proof["final"]]
        fri_roots = proof["fri_roots"]
        if step == 1 and pairleaf:
            _hf = len(final) // 2
            leaves = [STK._leaf_ext_pair(final[i], final[i + _hf], b"\x00"*16) for i in range(_hf)]
        else:
            leaves = [STK._leaf_ext(v, b"\x00"*16) for v in final]
        tree = merkle(leaves)
        recomputed = m_root(tree)
        checks.append({
            "tag": "bytesEq",
            "a": recomputed.hex(),
            "b": fri_roots[-1] if fri_roots else "",
            "note": "final_root",
        })
    except Exception as e:
        checks.append({"tag": "natEq", "a": 0, "b": 1, "note": f"final_root_err:{e}"})

    sizes = []; size = N
    if step == 1:
        while True:
            sizes.append(size)
            if size <= 8: break
            size //= 2

    for q in proof.get("queries", []):
        k = int(q["k"])
        if "pk" in q and "ck" in q and "sk" in q:
            leaf = _leaf([q["ck"][c] for c in FLAT_COLS], bytes.fromhex(q["sk"]))
            checks.append(digest_open(proof["tp_root"], leaf, q["pk"]))
        if not deep and "pn" in q and "cn" in q and "sn" in q:
            leaf = _leaf([q["cn"][c] for c in FLAT_COLS], bytes.fromhex(q["sn"]))
            checks.append(digest_open(proof["tp_root"], leaf, q["pn"]))
        if deep and "cp" in q and "cc" in q and "comp_root" in proof:
            leaf = _leaf_ext(tuple(q["cc"]), b"\x00"*16)
            checks.append(digest_open(proof["comp_root"], leaf, q["cp"]))
        if step == 1 and sizes:
            ci = k
            for li, fl in enumerate(q.get("fri", [])):
                if li >= len(sizes): break
                half = sizes[li] // 2; ii = ci % half
                fv = tuple(fl["v"]); fw = tuple(fl["w"])
                if pairleaf and "p" in fl:
                    leaf = _leaf_ext_pair(fv, fw, b"\x00"*16)
                    checks.append(digest_open(proof["fri_roots"][li], leaf, fl["p"]))
                else:
                    if "vp" in fl:
                        leaf = _leaf_ext(fv, b"\x00"*16)
                        checks.append(digest_open(proof["fri_roots"][li], leaf, fl["vp"]))
                    if "wp" in fl:
                        leaf = _leaf_ext(fw, b"\x00"*16)
                        checks.append(digest_open(proof["fri_roots"][li], leaf, fl["wp"]))
                if li < len(proof.get("betas", [])):
                    xpos = pow((off * pow(oN, ii, P)) % P, 2 ** li, P)
                    beta = tuple(proof["betas"][li])
                    checks.append(fri_fold_check(fv, fw, beta, xpos))
                    if li + 1 < len(q["fri"]):
                        nh = sizes[li+1] // 2
                        tgt = tuple(q["fri"][li+1]["w"]) if (ii >= nh) else tuple(q["fri"][li+1]["v"])
                        inv2 = pow(2, P-2, P); i2x = pow((2 * xpos) % P, P-2, P)
                        folded = F2.add(F2.scalar(inv2, F2.add(fv, fw)),
                                        F2.mul(beta, F2.scalar(i2x, F2.sub(fv, fw))))
                        checks.append({"tag": "extEq", "a": list(folded), "b": list(tgt)})
                ci = ii
        else:
            for ridx, fl in enumerate(q.get("fri", [])):
                if ridx >= len(proof.get("fri_roots", [])): break
                if "coset" in fl and "p" in fl:
                    coset = [tuple(v) for v in fl["coset"]]
                    leaf = _leaf_ext_coset(coset, b"\x00"*16)
                    checks.append(digest_open(proof["fri_roots"][ridx], leaf, fl["p"]))
                if "coset" in fl and len(fl["coset"]) >= 2 and proof.get("betas"):
                    beta = tuple(proof["betas"][min(ridx, len(proof["betas"])-1)])
                    checks.append(fri_fold_check(fl["coset"][0], fl["coset"][1], beta, 1))
    return checks

def lean_would_pass_structure(checks, blowup, queries, grind, fold):
    """Quick python simulation of Lean structural gates for export sanity."""
    if blowup != C.BLOWUP or queries != C.QUERIES or grind != C.GRIND_BITS or fold != C.FOLD:
        return False
    if not checks:
        return False
    for c in checks:
        t = c["tag"]
        if t == "merkleOpenDigest":
            if not c.get("py_ok", False):
                return False
        elif t == "friFold":
            # recompute
            inv2 = pow(2, P-2, P)
            xpos = c["xpos"]
            i2x = pow((2 * xpos) % P, P-2, P)
            fv, fw, be = tuple(c["v"]), tuple(c["w"]), tuple(c["beta"])
            folded = F2.add(F2.scalar(inv2, F2.add(fv, fw)),
                            F2.mul(be, F2.scalar(i2x, F2.sub(fv, fw))))
            if list(folded) != list(c["folded"]):
                return False
        elif t == "extEq":
            if list(c["a"]) != list(c["b"]):
                return False
        elif t == "grindCheck":
            st = bytes.fromhex(c["state"]); nonce = bytes.fromhex(c["nonce"])
            d = hashlib.sha256(st + nonce).digest()
            n = int.from_bytes(d[:8], "little")
            if n >= (1 << (64 - c["grindBits"])):
                return False
        elif t == "natListEq":
            if list(c["a"]) != list(c["b"]):
                return False
        elif t == "natEq":
            if int(c["a"]) != int(c["b"]):
                return False
        elif t == "bytesEq":
            if c["a"] != c["b"]:
                return False
    return True

def forge_proofs(pf):
    forges = []
    def add(name, p): forges.append((name, p))
    p = copy.deepcopy(pf); p["tp_root"] = "00"*32; add("forge-tp-root", p)
    p = copy.deepcopy(pf); p["fri_roots"] = list(p["fri_roots"]); p["fri_roots"][0] = "11"*32; add("forge-fri-root", p)
    p = copy.deepcopy(pf); p["queries"] = copy.deepcopy(p["queries"])
    if p["queries"]: p["queries"][0]["k"] = (int(p["queries"][0]["k"]) + 3) % max(2, int(p["blowup"]))
    add("forge-query-k", p)
    p = copy.deepcopy(pf); p["betas"] = copy.deepcopy(p["betas"])
    if p["betas"]:
        b = list(p["betas"][0]); b[0] = (int(b[0])+1) % P; p["betas"][0] = b
    add("forge-beta", p)
    p = copy.deepcopy(pf); p["nonce"] = "ff"*8; add("forge-nonce", p)
    p = copy.deepcopy(pf); p["queries"] = []; add("forge-empty-q", p)
    p = copy.deepcopy(pf); p["nq"] = int(p["nq"]) + 1; add("forge-nq", p)
    p = copy.deepcopy(pf)
    if p["queries"] and p["queries"][0].get("pk"):
        p["queries"] = copy.deepcopy(p["queries"])
        sib, d = p["queries"][0]["pk"][0]
        p["queries"][0]["pk"][0] = ["00"*32, d]
    add("forge-path", p)
    p = copy.deepcopy(pf); p["blowup"] = 8; add("forge-blowup-label", p)
    p = copy.deepcopy(pf); p["final"] = copy.deepcopy(p["final"])
    if p["final"]:
        slot = list(p["final"][0]); slot[0] = (int(slot[0])+1) % P; p["final"][0] = slot
    add("forge-final", p)
    p = copy.deepcopy(pf); p["fri_roots"] = list(p["fri_roots"]) + ["22"*32]; add("forge-extra-root", p)
    p = copy.deepcopy(pf)
    if "comp_root" in p: p["comp_root"] = "33"*32
    add("forge-comp-root", p)
    return forges

def bundle(label, proof, accept_override=None):
    print("bundle", label, flush=True)
    checks = structural_checks(proof)
    if accept_override is None:
        t0 = time.time()
        ok, why = STK.verify(proof)
        print(f"  oracle {ok} {why} in {time.time()-t0:.2f}s", flush=True)
    else:
        ok, why = accept_override, "forced"
        print(f"  accept_override {ok}", flush=True)
    lean_ok = lean_would_pass_structure(
        checks, int(proof.get("blowup",0)), int(proof.get("nq",0)),
        int(proof.get("grind_b",0)), int(proof.get("fold_step",0)))
    print(f"  lean_struct_sim {lean_ok} n_checks={len(checks)}", flush=True)
    if ok and not lean_ok:
        print("  WARNING: python accept but lean struct would reject", flush=True)
    if (not ok) and lean_ok:
        print("  WARNING: python reject but lean struct would accept — forge gap!", flush=True)
    return {
        "label": label,
        "accept": bool(ok),
        "eligibility": "product",
        "blowup": int(proof.get("blowup", 0)),
        "queries": int(proof.get("nq", 0)),
        "grindBits": int(proof.get("grind_b", 0)),
        "fold": int(proof.get("fold_step", 0)),
        "checks": checks,
        "python_why": why,
        "n_checks": len(checks),
        "lean_struct_sim": lean_ok,
    }

def main():
    cache = OUT / "prod_proof_d2.json"
    pf = json.loads(cache.read_text())
    print("loaded", flush=True)
    # Honest: real oracle
    bundles = [bundle("honest-prod", pf)]
    assert bundles[0]["accept"], "honest must accept"
    assert bundles[0]["lean_struct_sim"], "honest must pass lean structure"
    # Forges: still run oracle for accept label (required for agreeWithOracle), structural must fail
    for name, fp in forge_proofs(pf):
        b = bundle(name, fp)
        bundles.append(b)
        if b["lean_struct_sim"]:
            raise SystemExit(f"FORGE GAP: {name} still passes lean structural sim")
        if b["accept"]:
            raise SystemExit(f"FORGE GAP: {name} still accepted by python")
    outp = OUT / "C-verify-prod.jsonl"
    with outp.open("w") as f:
        for b in bundles:
            f.write(json.dumps(b)+"\n")
    summary = {
        "bundles": len(bundles),
        "honest_accept": bundles[0]["accept"],
        "forge_count": len(bundles)-1,
        "forge_accepts": sum(1 for b in bundles[1:] if b["accept"]),
        "forge_lean_struct_accepts": sum(1 for b in bundles[1:] if b["lean_struct_sim"]),
        "honest_n_checks": bundles[0]["n_checks"],
        "no_reject_tags": all(
            all(c.get("tag") != "reject" for c in b["checks"]) for b in bundles
        ),
        "prod": {"blowup": C.BLOWUP, "queries": C.QUERIES, "grind": C.GRIND_BITS, "fold": C.FOLD},
    }
    (OUT / "C-verify-prod.summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2), flush=True)

if __name__ == "__main__":
    main()
