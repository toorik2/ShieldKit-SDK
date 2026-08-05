#!/usr/bin/env python3
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/"vectors/refinement"
# merkle: leaf is raw; root and path are over H(leaf) layers — Lean verifyDigest(root, hash(leaf), path)
mlines=[]
for line in (OUT/"merkle.jsonl").read_text().splitlines():
    if not line: continue
    r=json.loads(line)
    path=",".join(f"{s}:{d}" for s,d in r["path"])
    mlines.append(f"{1 if r['ok'] else 0}|{r['leaf']}|{r['root']}|{path}")
(OUT/"merkle.simple").write_text("\n".join(mlines)+"\n")
flines=[]
for line in (OUT/"fri.jsonl").read_text().splitlines():
    if not line: continue
    r=json.loads(line)
    v,w,b,f=r["v"],r["w"],r["beta"],r["folded"]
    flines.append(f"{1 if r['ok'] else 0}|{v[0]}|{v[1]}|{w[0]}|{w[1]}|{b[0]}|{b[1]}|{f[0]}|{f[1]}|{r['xpos']}")
(OUT/"fri.simple").write_text("\n".join(flines)+"\n")
print("merkle", len(mlines), "fri", len(flines))
