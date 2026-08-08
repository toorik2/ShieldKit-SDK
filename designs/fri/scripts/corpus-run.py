#!/usr/bin/env python3
"""P2 honest corpus: 256 distinct real proofs+transactions per action (768 total).

Per case: (1) shieldkit-fri-worker cmd=prove at product config with the
unique witness seed (CLI seed ^ xor) → proof JSON; (2) pickle as the assemble
proof cache; (3) product-config assemble (VM eval + forge checks) → artifact.
Unique statements/witnesses/transcript seeds/proofs/state positions per case.
"""
import json, os, pickle, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence" / "p2"
OUT.mkdir(parents=True, exist_ok=True)
CACHE_ROOT = Path("/tmp/corpus-cache")
CACHE_ROOT.mkdir(parents=True, exist_ok=True)

WORKER = os.environ.get("SHIELDKIT_FRI_WORKER", str(ROOT / ".private/cargo-target/release/shieldkit-fri-worker"))
XOR = {"deposit": 1, "transfer": 2, "withdrawal": 3}
PY = os.environ.get("VC_PYTHON", "python3")

def worker_prove(kind: str, cli_seed: int) -> Path:
    wseed = cli_seed ^ XOR[kind]
    pjson = CACHE_ROOT / f"pf-{kind}-d20-b2048-n7-g30-s{cli_seed}.json"
    req = json.dumps({"cmd": "prove", "kind": kind, "depth": 20, "blowup": 2048,
                      "queries": 7, "grindBits": 30, "foldStep": 3, "maskDeg": 24,
                      "deep": True, "seed": wseed, "randomMask": False, "proofOut": str(pjson)}) + "\n"
    r = subprocess.run([WORKER], input=req, capture_output=True, text=True, timeout=600, cwd=str(ROOT))
    if r.returncode != 0 or not pjson.is_file():
        raise RuntimeError(f"worker prove {kind} s{cli_seed} rc={r.returncode}: {(r.stderr or '')[:300]}")
    lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip().startswith("{")]
    doc = json.loads(lines[-1]) if lines else {}
    if not doc.get("verifyOk"):
        raise RuntimeError(f"worker prove not verifyOk for {kind} s{cli_seed}")
    return pjson

def to_cache(kind: str, cli_seed: int, pjson: Path) -> Path:
    pf = json.loads(pjson.read_text())
    pf["stmt"] = dict(pf.get("stmt", {}))
    pf["stmt"]["kind"] = kind
    pk = CACHE_ROOT / f"pf-{kind}-d20-b2048-n7-g30-s{cli_seed}.pkl"
    with open(pk, "wb") as f:
        pickle.dump(pf, f, protocol=4)
    return pk

def run_case(kind: str, cli_seed: int) -> dict:
    art = OUT / f"corpus-{kind}-{cli_seed:03d}.json"
    if art.exists():
        doc = json.loads(art.read_text())
        vm = doc.get("vm", {})
        return {
            "kind": kind, "seed": cli_seed, "ok": vm.get("allAccept") is True and not vm.get("fails"),
            "nOk": vm.get("nOk"), "nFails": len(vm.get("fails", [])),
            "txBytes": vm.get("txBytes"), "underStandardLimit": vm.get("underStandardLimit"),
            "proveSeconds": doc.get("proveSeconds"), "wallSeconds": None,
            "proveWallSeconds": None, "artifact": str(art),
        }
    pk = CACHE_ROOT / f"pf-{kind}-d20-b2048-n7-g30-s{cli_seed}.pkl"
    if not pk.is_file():
        t0 = time.monotonic()
        pjson = worker_prove(kind, cli_seed)
        to_cache(kind, cli_seed, pjson)
        prove_wall = time.monotonic() - t0
    else:
        prove_wall = None
    env = dict(os.environ)
    env.update({"VC_PRODUCT_FIXED_LOCKS": "1", "VC_ROLE_INDEX_BASE": "1", "VC_BLOB_IDX": "1",
                "VC_SKIP_PROOF_VERIFY": "1", "VC_RUST_FRI_TERMS": "1",
                "SHIELDKIT_FRI_WORKER": WORKER, "VC_PROOF_CACHE": str(pk)})
    cmd = [PY, "packages/settlement/python/assemble_sound_settlement.py", kind,
           "--depth", "20", "--nq", "7", "--blowup", "2048", "--grind", "30", "--fold-step", "3",
           "--seed", str(cli_seed), "--out", str(art)]
    t0 = time.monotonic()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, cwd=str(ROOT), env=env)
    wall = time.monotonic() - t0
    if r.returncode != 0:
        return {"kind": kind, "seed": cli_seed, "ok": False, "rc": r.returncode,
                "error": (r.stderr or r.stdout or "")[-300:], "wallSeconds": round(wall, 2),
                "proveWallSeconds": prove_wall}
    try:
        doc = json.loads(art.read_text())
    except Exception as e:
        return {"kind": kind, "seed": cli_seed, "ok": False, "error": f"artifact unreadable: {e}",
                "wallSeconds": round(wall, 2), "proveWallSeconds": prove_wall}
    vm = doc.get("vm", {})
    return {
        "kind": kind, "seed": cli_seed, "ok": vm.get("allAccept") is True and not vm.get("fails"),
        "nOk": vm.get("nOk"), "nFails": len(vm.get("fails", [])),
        "txBytes": vm.get("txBytes"), "underStandardLimit": vm.get("underStandardLimit"),
        "proveSeconds": doc.get("proveSeconds"), "wallSeconds": round(wall, 2),
        "proveWallSeconds": prove_wall, "artifact": str(art),
    }

def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    seed_filter = int(sys.argv[2]) if len(sys.argv) > 2 else None
    kinds = [only] if only else ["deposit", "transfer", "withdrawal"]
    seeds = [seed_filter] if seed_filter else list(range(1, 257))
    cases = [(k, s) for k in kinds for s in seeds]
    ok = 0
    total = len(cases)
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(run_case, k, s): (k, s) for k, s in cases}
        for i, f in enumerate(futs):
            res = f.result()
            ok += 1 if res.get("ok") else 0
            if i % 24 == 0 or not res.get("ok"):
                print(f"[{i+1}/{total}] {res.get('kind')} s{res.get('seed')}: ok={res.get('ok')} "
                      f"tx={res.get('txBytes')} fails={res.get('nFails')} "
                      f"wall={res.get('wallSeconds')}s pw={res.get('proveWallSeconds')}", flush=True)
    summary = {
        "schema": "shieldkit-fri-p2-corpus-v1",
        "cases": total, "ok": ok, "allGreen": ok == total,
        "perKind": {k: sum(1 for (kk, _) in cases if kk == k) for k in kinds},
        "config": {"depth": 20, "nq": 7, "blowup": 2048, "grind": 30, "fold_step": 3},
        "worker": WORKER,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (OUT / "CORPUS_SUMMARY.json").write_text(json.dumps(summary, indent=2))
    print("SUMMARY:", json.dumps(summary), flush=True)
    print("CORPUS DONE", flush=True)

if __name__ == "__main__":
    main()
