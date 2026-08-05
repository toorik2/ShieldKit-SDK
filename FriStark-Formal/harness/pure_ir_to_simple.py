#!/usr/bin/env python3
"""Convert pure-verify IR → Lean DiffPureVerify simple format.

PURE KERNEL RULES:
  - Emit DEEPQAT (raw openings) for Lean QAt.eval — never DEEPQ_TERM lists.
  - Never emit synthetic NATEQ|0|1 from IR fail.
  - FS absorb/challenge with pre|post for Lean recompute.
"""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
src = ROOT / "vectors/verify/C-pure-verify-ir.jsonl"
dst = ROOT / "vectors/verify/C-pure-verify.simple"
if not src.exists():
    raise SystemExit(f"missing {src}")

out: list[str] = []
stats = {
    "fail_dropped": 0,
    "fs": 0,
    "deep_q_at": 0,
    "coset_fold": 0,
    "deep_q_terms_banned": 0,
    "real": 0,
}


def need_pre(s: dict) -> str:
    pre = s.get("pre")
    if pre is None:
        raise SystemExit(f"missing pre on FS op {s.get('op')}")
    return pre


def e2(p) -> str:
    return f"{p[0]}|{p[1]}"


def elist(pairs) -> str:
    return ";".join(f"{a[0]},{a[1]}" for a in pairs)


def flist(xs) -> str:
    return ",".join(str(int(x)) for x in xs)


for line in src.read_text().splitlines():
    if not line.strip():
        continue
    b = json.loads(line)
    out.append(
        f"BUNDLE|{b['label']}|{1 if b['accept'] else 0}|{b['eligibility']}|"
        f"{b['blowup']}|{b['queries']}|{b['grindBits']}|{b['fold']}"
    )
    for s in b["steps"]:
        op = s.get("op")
        if op == "deep_q_terms":
            stats["deep_q_terms_banned"] += 1
            raise SystemExit("deep_q_terms forbidden on pure path")
        if op == "params":
            out.append(f"PARAMS|{s['blowup']}|{s['queries']}|{s['grindBits']}|{s['fold']}")
            stats["real"] += 1
        elif op == "fs_absorb":
            out.append(f"FSABSORB|{need_pre(s)}|{s['data']}|{s['state']}")
            stats["fs"] += 1
            stats["real"] += 1
        elif op == "fs_absorb_int":
            out.append(f"FSABSORBINT|{need_pre(s)}|{s['v']}|{s['state']}")
            stats["fs"] += 1
            stats["real"] += 1
        elif op == "fs_absorb_int4":
            pre = need_pre(s)
            posts = s.get("posts")
            vals = s["vals"]
            if not posts or len(posts) != 4:
                raise SystemExit("fs_absorb_int4 needs posts")
            cur = pre
            for v, post in zip(vals, posts):
                out.append(f"FSABSORBINT|{cur}|{v}|{post}")
                cur = post
                stats["fs"] += 1
                stats["real"] += 1
        elif op == "fs_ext_challenge":
            a = s["a"]
            out.append(f"FSEXTCHAL|{need_pre(s)}|{a[0]}|{a[1]}|{s['state']}")
            stats["fs"] += 1
            stats["real"] += 1
        elif op == "fs_challenge_idx":
            out.append(f"FSIDX|{need_pre(s)}|{s['N']}|{s['idx']}|{s['state']}")
            stats["fs"] += 1
            stats["real"] += 1
        elif op == "grindCheck":
            out.append(f"GRINDCHECK|{s['state']}|{s['nonce']}|{s['grindBits']}")
            stats["real"] += 1
        elif op == "query_idxs":
            out.append(
                f"NATLISTEQ|{','.join(map(str, s['expect']))}|{','.join(map(str, s['actual']))}"
            )
            stats["real"] += 1
        elif op == "fri_roots_len":
            out.append(f"NATEQ|{s['got']}|{s['expect']}")
            stats["real"] += 1
        elif op == "final_root":
            out.append(f"BYTESEQ|{s['recomputed']}|{s['expect']}")
            stats["real"] += 1
        elif op == "merkleOpenDigest":
            path = ",".join(f"{a}:{d}" for a, d in s["path"])
            out.append(f"MERKLE|{s['root']}|{s['leafDigest']}|{path}")
            stats["real"] += 1
        elif op == "friFold":
            v, w, be, fo = s["v"], s["w"], s["beta"], s["folded"]
            out.append(
                f"FRIFOLD|{v[0]}|{v[1]}|{w[0]}|{w[1]}|{be[0]}|{be[1]}|{fo[0]}|{fo[1]}|{s['xpos']}"
            )
            stats["real"] += 1
        elif op == "extEq":
            a, b2 = s["a"], s["b"]
            out.append(f"EXTEQ|{a[0]}|{a[1]}|{b2[0]}|{b2[1]}")
            stats["real"] += 1
        elif op == "deep_z":
            z, zg, ez, ezg = s["z"], s["zg"], s["expect_z"], s["expect_zg"]
            out.append(
                f"DEEPZ|{ez[0]}|{ez[1]}|{ezg[0]}|{ezg[1]}|{z[0]}|{z[1]}|{s.get('oT', 0)}"
            )
            stats["real"] += 1
        elif op == "deep_alphas":
            got, exp = s["got"], s["expect"]
            out.append(f"NATEQ|{len(got)}|{len(exp)}")
            for g, e in zip(got, exp):
                out.append(f"EXTEQ|{g[0]}|{g[1]}|{e[0]}|{e[1]}")
            stats["real"] += 1
        elif op == "betas_match":
            got, exp = s["got"], s["expect"]
            out.append(f"NATEQ|{len(got)}|{len(exp)}")
            for g, e in zip(got, exp):
                out.append(f"EXTEQ|{g[0]}|{g[1]}|{e[0]}|{e[1]}")
            stats["real"] += 1
        elif op == "deep_q_at":
            sel = s["sel"]
            sm = s["sel_mask"]
            keys = [
                "is_full", "is_partial", "is_block_start", "is_reabsorb",
                "is_range", "is_range_first", "is_range_step", "is_range_last",
            ]
            bind = s.get("bind", "fri0")
            out.append(
                f"DEEPQAT_BEGIN|{s['x']}|{s['z'][0]}|{s['z'][1]}|{s['zg'][0]}|{s['zg'][1]}|"
                f"{s['comp_z'][0]}|{s['comp_z'][1]}|{s['rw_zg'][0]}|{s['rw_zg'][1]}|"
                f"{s['cc'][0]}|{s['cc'][1]}|{s['expect'][0]}|{s['expect'][1]}|{bind}"
            )
            out.append(f"DEEPQAT_CK|{flist(s['ck'])}")
            out.append(f"DEEPQAT_PCZ|{elist(s['Pcz'])}")
            out.append(f"DEEPQAT_PCZG|{elist(s['Pczg'])}")
            out.append(f"DEEPQAT_ALPHA|{elist(s['deep_alphas'])}")
            out.append(
                "DEEPQAT_SEL|"
                + "|".join(str(sel[k]) for k in keys)
                + f"|{flist(sel['rc'])}|{flist(sel['chain_minv'])}|{sel['range_weight']}"
            )
            out.append(
                "DEEPQAT_SELMASK|"
                + "|".join(f"{sm[k][0]},{sm[k][1]}" for k in keys)
                + f"|{elist(sm['rc'])}|{elist(sm['chain_minv'])}"
            )
            out.append("DEEPQAT_END")
            stats["deep_q_at"] += 1
            stats["real"] += 1
        elif op == "cosetFold":
            # Production coset multi-fold — Lean Coset.cosetFold recompute
            ex = s["expect"]
            out.append(
                f"COSETFOLD_BEGIN|{s['base']}|{s['li0']}|{s['s']}|{s['off']}|{s['oN']}|{s['N']}|"
                f"{ex[0]}|{ex[1]}|{len(s['coset'])}|{len(s['betas'])}"
            )
            out.append(f"COSETFOLD_C|{elist(s['coset'])}")
            out.append(f"COSETFOLD_B|{elist(s['betas'])}")
            out.append("COSETFOLD_END")
            stats["coset_fold"] += 1
            stats["real"] += 1
        elif op == "fail":
            stats["fail_dropped"] += 1
            continue
    out.append("END")

# Product AIR binding steps (KATs) as pure-path product eligibility checks
# Encoded as PRODUCT_AIR_KIND|deposit|transfer|withdrawal accept flags via Lean side suite.
# DiffPureVerify also runs ProductV1 in-process; marker records corpus intent:
out.append("PRODUCT_AIR_BIND|1")

dst.write_text("\n".join(out) + "\n")
print("wrote", dst, "lines", len(out), "stats", stats)

if any(ln == "NATEQ|0|1" for ln in out):
    raise SystemExit("SYNTHETIC_REJECT theater")
if stats["deep_q_at"] < 1:
    raise SystemExit("pure path missing deep_q_at on corpus")
if stats["coset_fold"] < 1:
    raise SystemExit("pure path missing cosetFold (production FRI)")
if stats["deep_q_terms_banned"]:
    raise SystemExit("deep_q_terms leaked")
print("PURE_SIMPLE_OK")
