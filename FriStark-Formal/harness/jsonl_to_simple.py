#!/usr/bin/env python3
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
src = ROOT/"vectors/verify/C-verify-prod.jsonl"
dst = ROOT/"vectors/verify/C-verify-prod.simple"
if not src.exists():
    print("missing", src); sys.exit(2)
lines_out = []
reject_count = 0
for line in src.read_text().splitlines():
    if not line.strip(): continue
    b = json.loads(line)
    acc = 1 if b["accept"] else 0
    lines_out.append(f"BUNDLE|{b['label']}|{acc}|{b['eligibility']}|{b['blowup']}|{b['queries']}|{b['grindBits']}|{b['fold']}")
    for c in b["checks"]:
        tag = c.get("tag")
        if tag == "merkleOpenDigest":
            path = ",".join(f"{s}:{d}" for s,d in c["path"])
            lines_out.append(f"MERKLE_DIGEST|{c['root']}|{c['leafDigest']}|{path}")
        elif tag == "merkleOpen":
            path = ",".join(f"{s}:{d}" for s,d in c.get("path",[]))
            lines_out.append(f"MERKLE|{c['root']}|{c['leaf']}|{c.get('index',0)}|{path}")
        elif tag == "friFold":
            v,w,be,fo = c["v"], c["w"], c["beta"], c["folded"]
            lines_out.append(f"FRIFOLD|{v[0]}|{v[1]}|{w[0]}|{w[1]}|{be[0]}|{be[1]}|{fo[0]}|{fo[1]}|{c['xpos']}")
        elif tag == "extEq":
            a,b2 = c["a"], c["b"]
            lines_out.append(f"EXTEQ|{a[0]}|{a[1]}|{b2[0]}|{b2[1]}")
        elif tag == "fieldEq":
            lines_out.append(f"FIELDEQ|{c['a']}|{c['b']}")
        elif tag == "grindCheck":
            lines_out.append(f"GRINDCHECK|{c['state']}|{c['nonce']}|{c['grindBits']}")
        elif tag == "natListEq":
            a = ",".join(str(x) for x in c["a"])
            b2 = ",".join(str(x) for x in c["b"])
            lines_out.append(f"NATLISTEQ|{a}|{b2}")
        elif tag == "natEq":
            lines_out.append(f"NATEQ|{c['a']}|{c['b']}")
        elif tag == "bytesEq":
            lines_out.append(f"BYTESEQ|{c['a']}|{c['b']}")
        elif tag == "reject":
            reject_count += 1
            # BAN reject tags in product corpus
            raise SystemExit(f"reject tag forbidden in product corpus: {c}")
        elif tag == "grindOk":
            raise SystemExit("grindOk bool forbidden; use grindCheck")
    lines_out.append("END")
dst.write_text("\n".join(lines_out)+"\n")
print("wrote", dst, "lines", len(lines_out), "reject_tags", reject_count)
