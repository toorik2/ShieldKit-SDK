#!/usr/bin/env python3
"""Convert full-verify IR → Lean DiffFullVerify simple format.

HARD RULES (skeptic):
  - Never emit synthetic NATEQ|0|1 / REJECT tags from IR `fail` ops.
  - Only emit Lean-reexecutable steps (FS absorb/challenge, grind, merkle,
    friFold, deepZ, deepQ, idx, params, …) on real proof material.
  - IR `fail` is diagnostic-only and is dropped.
"""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
src = ROOT / "vectors/verify/C-full-verify-ir.jsonl"
dst = ROOT / "vectors/verify/C-full-verify.simple"
if not src.exists():
    raise SystemExit(f"missing {src}")

out: list[str] = []
stats = {"fail_dropped": 0, "fs": 0, "real": 0, "bundles": 0}


def need_pre(s: dict) -> str:
    pre = s.get("pre")
    if pre is None:
        raise SystemExit(f"missing pre on FS op {s.get('op')} — re-export IR")
    return pre


for line in src.read_text().splitlines():
    if not line.strip():
        continue
    b = json.loads(line)
    stats["bundles"] += 1
    out.append(
        f"BUNDLE|{b['label']}|{1 if b['accept'] else 0}|{b['eligibility']}|"
        f"{b['blowup']}|{b['queries']}|{b['grindBits']}|{b['fold']}"
    )
    for s in b["steps"]:
        op = s.get("op")
        if op == "params":
            out.append(f"PARAMS|{s['blowup']}|{s['queries']}|{s['grindBits']}|{s['fold']}")
            stats["real"] += 1
        elif op == "fs_absorb":
            pre = need_pre(s)
            out.append(f"FSABSORB|{pre}|{s['data']}|{s['state']}")
            stats["fs"] += 1
            stats["real"] += 1
        elif op == "fs_absorb_int":
            pre = need_pre(s)
            out.append(f"FSABSORBINT|{pre}|{s['v']}|{s['state']}")
            stats["fs"] += 1
            stats["real"] += 1
        elif op == "fs_absorb_int4":
            # four sequential absorb_int with pre_i / post_i if present; else expand from vals+pre
            pre = need_pre(s)
            posts = s.get("posts")  # optional list of 4 post states
            vals = s["vals"]
            if posts and len(posts) == 4:
                cur_pre = pre
                for v, post in zip(vals, posts):
                    out.append(f"FSABSORBINT|{cur_pre}|{v}|{post}")
                    cur_pre = post
                    stats["fs"] += 1
                    stats["real"] += 1
            else:
                # fallback: single marker as four ints against final state only invalid —
                # require posts in export
                raise SystemExit(f"fs_absorb_int4 needs posts (4) for Lean re-exec, label={b['label']}")
        elif op == "fs_challenge":
            pre = need_pre(s)
            out.append(f"FSCHAL|{pre}|{s['f']}|{s['state']}")
            stats["fs"] += 1
            stats["real"] += 1
        elif op == "fs_ext_challenge":
            pre = need_pre(s)
            a = s["a"]
            out.append(f"FSEXTCHAL|{pre}|{a[0]}|{a[1]}|{s['state']}")
            stats["fs"] += 1
            stats["real"] += 1
        elif op == "fs_challenge_idx":
            pre = need_pre(s)
            out.append(f"FSIDX|{pre}|{s['N']}|{s['idx']}|{s['state']}")
            stats["fs"] += 1
            stats["real"] += 1
        elif op == "grindCheck":
            out.append(f"GRINDCHECK|{s['state']}|{s['nonce']}|{s['grindBits']}")
            stats["real"] += 1
        elif op == "query_idxs":
            # Prefer per-idx FS re-exec when present; also bind list equality of FS vs proof
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
        elif op == "deep_q_terms":
            ex = s["expect"]
            terms = s["terms"]
            out.append(f"DEEPQ_BEGIN|{len(terms)}|{ex[0]}|{ex[1]}")
            for tm in terms:
                a, v, m, i = tm["alpha"], tm["val"], tm["mask"], tm["invDenom"]
                out.append(
                    f"DEEPQ_TERM|{a[0]}|{a[1]}|{v[0]}|{v[1]}|{m[0]}|{m[1]}|{i[0]}|{i[1]}"
                )
            out.append("DEEPQ_END")
            stats["real"] += 1
        elif op == "betas_match":
            got, exp = s["got"], s["expect"]
            out.append(f"NATEQ|{len(got)}|{len(exp)}")
            for g, e in zip(got, exp):
                out.append(f"EXTEQ|{g[0]}|{g[1]}|{e[0]}|{e[1]}")
            stats["real"] += 1
        elif op == "fail":
            # DIAGNOSTIC ONLY — never convert to synthetic Lean reject
            stats["fail_dropped"] += 1
            continue
        # skip meta / deep_compose_ok / deep_q_at / coset_fold_result / fs_state / ok
    out.append("END")

dst.write_text("\n".join(out) + "\n")
print("wrote", dst, "lines", len(out), "stats", stats)

# Skeptic gate: no NATEQ|0|1 theater
theater = [ln for ln in out if ln == "NATEQ|0|1"]
if theater:
    raise SystemExit(f"SYNTHETIC_REJECT theater present: {len(theater)} NATEQ|0|1")

# Every forge must have real steps beyond PARAMS alone (or product params reject via BUNDLE fields)
from collections import Counter

cur = None
forge_tags: dict[str, Counter] = {}
for ln in out:
    if ln.startswith("BUNDLE|"):
        parts = ln.split("|")
        cur = parts[1]
        if parts[2] == "0":
            forge_tags[cur] = Counter()
        else:
            cur = None
    elif cur is not None and ln != "END":
        forge_tags[cur][ln.split("|")[0]] += 1

weak = []
for name, c in forge_tags.items():
    real = sum(v for k, v in c.items() if k != "PARAMS")
    # product params forges (blowup/nq) may reject on BUNDLE fields alone with few steps —
    # still require ≥1 real check tag in body when steps exist
    if real == 0 and c.get("PARAMS", 0) <= 1:
        # only PARAMS: ok only if params fields themselves are non-prod (checked in Lean product gate)
        weak.append((name, dict(c)))
print("forge_tag_summary:")
for name, c in forge_tags.items():
    print(f"  {name}: {dict(c)}")
print("weak_forges (PARAMS-only body):", weak)
