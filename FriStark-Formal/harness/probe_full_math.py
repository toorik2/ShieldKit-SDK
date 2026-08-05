#!/usr/bin/env python3
"""Fail-closed: every harness that builds ComposePack / composeCheck must use
packFromLayoutWithZg (or import ComposeFromLayout). No export-only OOD pockets.
"""
from __future__ import annotations
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "harness"

def lean_files():
    return sorted(HARNESS.glob("*.lean"))

def main() -> int:
    # Core modules
    v = (ROOT / "FriStark/Full/Verify.lean").read_text()
    assert "deepQAtLayout" in v and "composeCheck" in v
    assert (ROOT / "FriStark/Domain/ComposeFromLayout.lean").exists()
    assert "packFromLayoutWithZg" in (ROOT / "FriStark/Domain/ComposeFromLayout.lean").read_text()
    assert "deep_compose_ok" not in (ROOT / "harness/export_full_verify_ir.py").read_text()

    # Every harness that mentions composeCheck or ComposePack must use the factory
    offenders = []
    covered = []
    for path in lean_files():
        t = path.read_text()
        # Only flag harnesses that *construct* accept-path ComposePack / emit Step.composeCheck
        uses_compose = (
            "Step.composeCheck" in t
            or re.search(r"ComposePack\s*:=", t) is not None
            or "let pack : ComposePack" in t
            or "composePack :" in t
            or "packFromLayoutWithZg" in t
        )
        # Orchestrators that only re-run pure binary are not pack builders
        if path.name == "DiffOpeningConsistency.lean":
            continue
        if not uses_compose:
            continue
        has_factory = (
            "packFromLayoutWithZg" in t
            or "packFromLayout " in t
            or "ComposeFromLayout" in t
        )
        # Free-form export OOD assignment into pack (anti-pattern)
        bad_export_ood = bool(
            re.search(
                r"wNext\s*:=\s*cW|zhInv\s*:=\s*cZh|pub\s*:=\s*cPub|"
                r"wNext\s*:=\s*expRw|zhInv\s*:=\s*expZh",
                t,
            )
        )
        if not has_factory:
            offenders.append(f"{path.name}: compose without packFromLayoutWithZg/ComposeFromLayout")
        if bad_export_ood and "cross-check" not in t.lower() and "Cross-check" not in t:
            # Allow variables named expRw for cross-check equality only if factory present
            if has_factory and ("expRw" in t or "expZh" in t):
                pass  # cross-check pattern OK if factory builds pack
            elif not has_factory:
                offenders.append(f"{path.name}: export OOD fields assigned into ComposePack")
        # Stronger: if pack : ComposePack := { ... wNext := cW
        if re.search(r"ComposePack\s*:=\s*\{[^}]*wNext\s*:=\s*cW", t, re.S):
            offenders.append(f"{path.name}: free ComposePack with wNext:=cW (export OOD)")
        if re.search(r"ComposePack\s*:=\s*\{[^}]*pub\s*:=\s*cPub", t, re.S):
            offenders.append(f"{path.name}: free ComposePack with pub:=cPub (export OOD)")
        covered.append(path.name)

    # Must cover the three known accept harnesses
    for must in ("DiffFullMath.lean", "DiffAirCompose.lean", "DiffPureVerify.lean"):
        if must not in covered:
            offenders.append(f"missing compose coverage for {must}")
        text = (HARNESS / must).read_text()
        if "packFromLayoutWithZg" not in text and "ComposeFromLayout" not in text:
            offenders.append(f"{must} missing packFromLayoutWithZg")

    if offenders:
        print("PROBE_FULL_MATH_FAIL")
        for o in offenders:
            print(" ", o)
        return 1

    status = (ROOT / "evidence/STATUS.md").read_text()
    assert "packFromLayoutWithZg" in status or "H-layout" in status
    print(
        "PROBE_FULL_MATH_OK",
        "compose_sites=" + ",".join(covered),
        "factory=packFromLayoutWithZg",
    )
    return 0

if __name__ == "__main__":
    sys.exit(main())
