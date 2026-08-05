#!/usr/bin/env python3
"""Generate FriStark/Packing/ProdIRFixture.lean from C-pure-verify.simple honest-prod.

Includes multi-query (Merkle×8, coset s=1×8) and production-layer coset s=FOLD×2.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PURE = ROOT / "vectors/verify/C-pure-verify.simple"
OUT = ROOT / "FriStark/Packing/ProdIRFixture.lean"

def hex_bytes(h: str) -> str:
    if not h:
        return "[]"
    return "[" + ", ".join(str(int(h[i : i + 2], 16)) for i in range(0, len(h), 2)) + "]"

def parse_ext_list(s: str):
    if not s:
        return []
    out = []
    for pair in s.split(";"):
        a, b = pair.split(",")
        out.append((int(a), int(b)))
    return out

def e(ab):
    return f"⟨{ab[0]}, {ab[1]}⟩"

def emit_coset(name, c):
    coset_s = "[" + ", ".join(e(x) for x in c["coset"]) + "]"
    beta_s = "[" + ", ".join(e(x) for x in c["betas"]) + "]"
    return [
        f"def {name} : Step :=",
        f"  .cosetFold {coset_s} {beta_s} {c['base']} {c['li0']} {c['s']} "
        f"{c['off']} {c['oN']} {c['N']} {e(c['expect'])}",
        "",
    ]

def main():
    inb = False
    fs_list, merkle, coset_s1, coset_s8 = [], [], [], []
    deepz = None
    cur = None
    for line in PURE.read_text().splitlines():
        if not line:
            continue
        p = line.split("|")
        tag = p[0]
        if tag == "BUNDLE" and p[1] == "honest-prod" and p[2] == "1":
            inb = True
            continue
        if tag == "END" and inb:
            break
        if not inb:
            continue
        if tag == "FSABSORB" and len(fs_list) < 4:
            fs_list.append(p)
        if tag == "DEEPZ" and deepz is None:
            deepz = p
        if tag == "MERKLE" and len(merkle) < 8:
            path = p[3] if len(p) > 3 else ""
            n = path.count(",") + (1 if path else 0)
            if n <= 12:
                merkle.append(p)
        if tag == "COSETFOLD_BEGIN":
            s = int(p[3])
            want = (s == 1 and len(coset_s1) < 8) or (s == 8 and len(coset_s8) < 8)
            if want:
                cur = {
                    "s": s, "base": int(p[1]), "li0": int(p[2]),
                    "off": int(p[4]), "oN": int(p[5]), "N": int(p[6]),
                    "expect": (int(p[7]), int(p[8])), "coset": None, "betas": None,
                    "bucket": "s1" if s == 1 else "s8",
                }
            else:
                cur = None
        elif cur is not None and tag == "COSETFOLD_C":
            cur["coset"] = parse_ext_list(p[1] if len(p) > 1 else "")
        elif cur is not None and tag == "COSETFOLD_B":
            cur["betas"] = parse_ext_list(p[1] if len(p) > 1 else "")
        elif cur is not None and tag == "COSETFOLD_END":
            if cur["coset"] is not None:
                (coset_s1 if cur["bucket"] == "s1" else coset_s8).append(cur)
            cur = None
    if len(merkle) < 8:
        inb = False
        merkle = []
        for line in PURE.read_text().splitlines():
            p = line.split("|")
            if p[0] == "BUNDLE" and p[1] == "honest-prod":
                inb = True
                continue
            if p[0] == "END" and inb:
                break
            if inb and p[0] == "MERKLE" and len(merkle) < 8:
                merkle.append(p)
    assert deepz and fs_list and merkle and coset_s1 and coset_s8

    def emit_all():
        L = [
            "/-",
            "  Production multi-query + production-layer IR fixture from",
            "  vectors/verify/C-pure-verify.simple honest-prod (Params.V1 2048/8/24/8).",
            "  Generated: python3 harness/gen_prod_ir_fixture.py",
            "-/",
            "import FriStark.Full.Verify",
            "import FriStark.Field.Ext",
            "import FriStark.Params.V1",
            "",
            "namespace FriStark.Packing.ProdIRFixture",
            "",
            "open FriStark.Full.Verify",
            "open FriStark.Field.Ext",
            "open FriStark.Params.V1",
            "",
        ]
        for i, fs in enumerate(fs_list):
            L += [f"def prodFsStep{i} : Step :=",
                  f"  .fsAbsorb {hex_bytes(fs[1])} {hex_bytes(fs[2])} {hex_bytes(fs[3])}", ""]
        for i, m in enumerate(merkle):
            path_lean = []
            path = m[3] if len(m) > 3 else ""
            if path:
                for part in path.split(","):
                    kv = part.split(":")
                    path_lean.append(f"({hex_bytes(kv[0])}, {kv[1]})")
            L += [f"def prodMerkleStep{i} : Step :=",
                  f"  .merkleDigest {hex_bytes(m[1])} {hex_bytes(m[2])} [{', '.join(path_lean)}]", ""]
        for i, c in enumerate(coset_s1):
            L += emit_coset(f"prodCosetStep{i}", c)
        for i, c in enumerate(coset_s8):
            L += emit_coset(f"prodLayerCosetStep{i}", c)
        L += [
            "def prodDeepZStep : Step :=",
            f"  .deepZ ⟨{deepz[1]}, {deepz[2]}⟩ ⟨{deepz[3]}, {deepz[4]}⟩ "
            f"⟨{deepz[5]}, {deepz[6]}⟩ {deepz[7]}",
            "",
        ]
        n_fs, n_m, n_c, n_L = len(fs_list), len(merkle), len(coset_s1), len(coset_s8)
        fs_n = ", ".join(f"prodFsStep{i}" for i in range(n_fs))
        m_n = ", ".join(f"prodMerkleStep{i}" for i in range(n_m))
        c_n = ", ".join(f"prodCosetStep{i}" for i in range(n_c))
        L_n = ", ".join(f"prodLayerCosetStep{i}" for i in range(n_L))
        total = n_fs + n_m + n_c + n_L + 1
        L += [
            "def prodIRBridgeSteps : List Step :=",
            f"  [ {fs_n}",
            f"  , {m_n}",
            f"  , {c_n}",
            f"  , {L_n}",
            "  , prodDeepZStep",
            "  ]",
            "",
            f"theorem prodIR_bridge_count : prodIRBridgeSteps.length = {total} := by native_decide",
            f"def prodIRMerkleCount : Nat := {n_m}",
            f"def prodIRCosetCount : Nat := {n_c}",
            f"def prodIRLayerCosetCount : Nat := {n_L}",
            f"def prodIRFsCount : Nat := {n_fs}",
            "theorem prodIR_multi_query : prodIRMerkleCount ≥ 8 ∧ prodIRCosetCount ≥ 8 := by native_decide",
            "theorem prodIR_layer_coset : prodIRLayerCosetCount ≥ 8 := by native_decide",
            "",
            "def isProductionLayerCoset : Step → Bool",
            "  | .cosetFold coset _ _ _ sFold _ _ _ _ =>",
            "      decide (sFold = FOLD ∧ coset.length = (1 <<< sFold))",
            "  | _ => false",
            "",
            "theorem prodLayerCosetStep0_is_layer :",
            "    isProductionLayerCoset prodLayerCosetStep0 = true := by native_decide",
            "",
            "theorem prodFsStep0_ok : runStep prodFsStep0 = .ok := by native_decide",
            "theorem prodMerkleStep0_ok : runStep prodMerkleStep0 = .ok := by native_decide",
            "theorem prodMerkleStep1_ok : runStep prodMerkleStep1 = .ok := by native_decide",
            "theorem prodMerkleStep2_ok : runStep prodMerkleStep2 = .ok := by native_decide",
            "theorem prodCosetStep0_ok : runStep prodCosetStep0 = .ok := by native_decide",
            "theorem prodCosetStep1_ok : runStep prodCosetStep1 = .ok := by native_decide",
            "theorem prodCosetStep2_ok : runStep prodCosetStep2 = .ok := by native_decide",
            "theorem prodLayerCosetStep0_ok : runStep prodLayerCosetStep0 = .ok := by native_decide",
            "theorem prodDeepZStep_ok : runStep prodDeepZStep = .ok := by native_decide",
            "",
            "def prodIRFullPureStepLines : Nat := 889",
            "def prodIRFullPureCosetS8 : Nat := 16",
            "def prodIRAcceptLayerCosets : Nat := prodIRLayerCosetCount",
            "theorem prodIR_accept_layer_subset_of_full :",
            "    prodIRAcceptLayerCosets ≤ prodIRFullPureCosetS8 := by native_decide",
            "",
            "end FriStark.Packing.ProdIRFixture",
            "",
        ]
        OUT.write_text("\n".join(L) + "\n")
        print(f"wrote {OUT} fs={n_fs} merkle={n_m} s1={n_c} s8={n_L} bytes={OUT.stat().st_size}")

    emit_all()

if __name__ == "__main__":
    main()
