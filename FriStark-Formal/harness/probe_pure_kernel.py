#!/usr/bin/env python3
"""Probe: pure accept kernel is QAt+cosetFold, not deep_q_terms / pairwise_diag."""
from pathlib import Path
import json, sys
ROOT = Path(__file__).resolve().parents[1]
full = (ROOT / "FriStark/Full/Verify.lean").read_text()
qat = (ROOT / "FriStark/Deep/QAt.lean").read_text()
coset = (ROOT / "FriStark/FRI/Coset.lean").read_text()
assert "deepQAt" in full and "matchesExpect" in full
assert "cosetFold" in full and "verifyCosetFold" in coset
assert "def eval" in qat
assert "| deepQTerms" not in full
simple = (ROOT / "vectors/verify/C-pure-verify.simple").read_text()
assert "DEEPQ_TERM" not in simple and "NATEQ|0|1" not in simple
assert "DEEPQAT_BEGIN" in simple and "COSETFOLD_BEGIN" in simple
terms = qats = cfolds = 0
for line in (ROOT / "vectors/verify/C-pure-verify-ir.jsonl").read_text().splitlines():
    b = json.loads(line)
    for s in b["steps"]:
        op = s.get("op")
        if op == "deep_q_terms":
            terms += 1
        if op == "deep_q_at":
            qats += 1
            assert s.get("bind") == "fri0" or b["label"] != "honest-prod" or True
        if op == "cosetFold":
            cfolds += 1
        assert s.get("note") != "pairwise_diag"
        assert op != "coset_fold_result"
# honest binds fri0
for line in (ROOT / "vectors/verify/C-pure-verify-ir.jsonl").read_text().splitlines():
    b = json.loads(line)
    if b["label"] == "honest-prod":
        for s in b["steps"]:
            if s.get("op") == "deep_q_at":
                assert s.get("bind") == "fri0", s.get("bind")
assert terms == 0 and qats >= 1 and cfolds >= 1, (terms, qats, cfolds)
print("PROBE_PURE_KERNEL_OK", f"deep_q_at={qats} cosetFold={cfolds}")
sys.exit(0)
