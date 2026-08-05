#!/usr/bin/env python3
import re, sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
cfg = (ROOT/"vendor/bch-fri-stark/apps/native_ct_air_config.py").read_text()
lean = (ROOT/"FriStark/Params/V1.lean").read_text()
def grab_py(name):
    m = re.search(rf'^{name}\s*=\s*(\d+)', cfg, re.M)
    return int(m.group(1)) if m else None
def grab_lean(name):
    m = re.search(rf'def {name}\s*:\s*Nat\s*:=\s*(\d+)', lean)
    return int(m.group(1)) if m else None
pairs = [("BLOWUP","BLOWUP"),("QUERIES","QUERIES"),("GRIND_BITS","GRIND_BITS"),("FOLD","FOLD")]
ok = True
for py, ln in pairs:
    a, b = grab_py(py), grab_lean(ln)
    print(f"{py}: python={a} lean={b}")
    if a != b:
        ok = False
# product corpus guard
for p in (ROOT/"vectors").rglob("*.json"):
    t = p.read_text()
    if '"eligibility": "product"' in t or '"eligibility":"product"' in t:
        if '"blowup": 2048' not in t and '"blowup":2048' not in t:
            print("FAIL product corpus missing blowup 2048", p)
            ok = False
        if ('"queries": 8' not in t and '"queries":8' not in t) and ('"nq": 8' not in t and '"nq":8' not in t):
            # allow nq
            if '"queries"' in t or '"nq"' in t:
                print("WARN check queries in", p)
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
