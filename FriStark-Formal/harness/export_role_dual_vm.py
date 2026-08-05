#!/usr/bin/env python3
"""Export sound-secure dual-vm comparisons into a Lean-friendly simple corpus.

Source of truth: vectors/xcheck/sound-secure-xcheck-report.json comparisons[].
Writes vectors/refinement/dual_vm_roles.simple (one line per input):
  index|role|libauthAccepted|leanVerifyInput|agreeAccept
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
XREP = ROOT / "vectors/xcheck/sound-secure-xcheck-report.json"
OUT = ROOT / "vectors/refinement/dual_vm_roles.simple"
ROLES = ("blob", "deepquery", "aggFRI", "comp_trans", "comp_final")


def role_from_label(label: str) -> str:
    # labels look like "0:blob", "8:aggFRI"
    if ":" in label:
        return label.split(":", 1)[1]
    return label


def main() -> int:
    if not XREP.exists():
        print(f"missing {XREP}", file=sys.stderr)
        return 2
    data = json.loads(XREP.read_text())
    comps = data.get("comparisons") or []
    lines: list[str] = []
    by_role: Counter[str] = Counter()
    for c in comps:
        idx = int(c["index"])
        role = role_from_label(str(c.get("label", "")))
        if role not in ROLES:
            print(f"unknown role label {c.get('label')!r}", file=sys.stderr)
            return 2
        la = 1 if c.get("libauthAccepted") is True else 0
        lv = 1 if c.get("leanVerifyInput") is True else 0
        ag = 1 if c.get("agreeAccept") is True else 0
        lines.append(f"{idx}|{role}|{la}|{lv}|{ag}")
        by_role[role] += 1
    missing = [r for r in ROLES if by_role[r] < 1]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + ("\n" if lines else ""))
    summary = {
        "source": str(XREP.relative_to(ROOT)),
        "out": str(OUT.relative_to(ROOT)),
        "n": len(lines),
        "byRole": dict(by_role),
        "missingRoles": missing,
        "gates": data.get("gates"),
    }
    print(json.dumps(summary, indent=2))
    return 0 if not missing and lines else 1


if __name__ == "__main__":
    raise SystemExit(main())
