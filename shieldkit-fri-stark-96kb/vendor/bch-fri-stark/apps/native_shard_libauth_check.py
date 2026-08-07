"""native_shard_libauth_check.py -- HP4 faithful-translation proof on the REAL libauth BCH-2026
VM. native_ct_shard.self_test proves the cashvm token programs reproduce the prover; this adds
the missing half: that tokens_to_asm emits CashAssembly whose libauth final stack equals the
cashvm stack byte-for-byte, including the OP_DEFINE/OP_INVOKE field-function table (MULMOD/
ADDMOD/SUBMOD). It also wraps a fragment into a self-checking program and shows it ACCEPTs
cleanly on createVirtualMachineBch2026 (the field-op analogue of the merkle-opening accept).

Covers the self-contained field-op fragments with deterministic numeric inputs (sbox, GF(p^2)
ext-mul, conservation) -- between them they exercise MM/AM/SM, squaring, Karatsuba and the
subtraction chain, i.e. the whole DEFINE/INVOKE emission. state/range/composition/ext-fold use
the same emission and are exercised end-to-end on real trace+proof values in the full per-query
shard run (HP4.5). No mock, no fake data: real VM, real bytes, exact assertions (TEST_RULES).
"""
import json
import os
import subprocess
import sys
import tempfile

_APPS = os.path.dirname(os.path.abspath(__file__))
if _APPS not in sys.path:
    sys.path.insert(0, _APPS)
_CASH = os.path.join(os.path.dirname(_APPS), "cashscript")
_HARNESS = os.path.join("native_shard", "stack_validate.mjs")

import native_ct_shard as S
from cashvm import VM, decode_num, N as NUM, OP


def _cashvm(prog):
    vm = VM()
    vm.run(prog)
    return [el.hex() for el in vm.s], [decode_num(el) for el in vm.s]


def _libauth(asm):
    fd, path = tempfile.mkstemp(suffix=".asm")
    os.close(fd)
    try:
        with open(path, "w") as f:
            f.write(asm)
        out = subprocess.run(["node", _HARNESS, path], cwd=_CASH,
                             capture_output=True, text=True)
    finally:
        os.remove(path)
    lines = [ln for ln in out.stdout.splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError("no JSON from libauth harness; stderr=" + out.stderr[:400])
    return json.loads(lines[-1])


# deterministic field-op fragments (each self-contained: includes the field prelude/DEFINEs)
_FRAGS = [
    ("sbox", S.sbox_lane_residuals_prog(5, 7, 999, 12345, 67890, 1), 3),
    ("ext_mul", S.ext_mul_prog(111, 222, 333, 444), 2),
    ("conserv", S.conservation_prog(1234, 600, 300, 100), 1),
]


def run():
    ok_all = True
    print("field-op fragment faithfulness (libauth final stack == cashvm) on real BCH-2026 VM:")
    for name, prog, nitems in _FRAGS:
        ref_hex, _ = _cashvm(prog)
        res = _libauth(S.tokens_to_asm(prog))
        if res.get("asmError"):
            print("  %-8s ASM ERROR: %s" % (name, res["asmError"]))
            ok_all = False
            continue
        match = res["stack"] == ref_hex
        ok = match and len(ref_hex) == nitems
        ok_all = ok_all and ok
        print("  %-8s bytes=%-4d items=%d  libauth==cashvm:%s  [%s]"
              % (name, res["bytes"], len(ref_hex), match, "OK" if ok else "FAIL"))
        if not match:
            print("     cashvm :", ref_hex)
            print("     libauth:", res["stack"])
    # consensus-clean self-checking ACCEPT: assert each computed value == cashvm reference,
    # clean the alt stack (p), end with one truthy item -> the real VM must accept.
    name, prog, _ = _FRAGS[0]
    _, vals = _cashvm(prog)
    term = []
    for v in reversed(vals):
        term += [NUM(v), OP("NUMEQUALVERIFY")]
    term += [OP("FROMALT"), OP("DROP"), NUM(1)]
    res = _libauth(S.tokens_to_asm(prog + term))
    accept = (not res.get("asmError") and res["error"] is None and res["stack"] == ["01"])
    ok_all = ok_all and accept
    print("consensus-clean self-checking ACCEPT (%s): bytes=%d error=%s stack=%s [%s]"
          % (name, res["bytes"], res["error"], res.get("stack"),
             "ACCEPTED" if accept else "REJECTED"))
    return ok_all


if __name__ == "__main__":
    success = run()
    print("LIBAUTH FIELD-OP FAITHFULNESS:", "ALL OK" if success else "FAIL")
    sys.exit(0 if success else 1)
