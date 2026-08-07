#!/usr/bin/env python3
"""P5 honest prover campaign: 3 warmups + 32 measured worker proofs per action.

Each run: shieldkit-fri-worker cmd=prove at the REAL product config
(depth=20 nq=7 blowup=2048 grind=30 fold_step=3 deep, seed matched to the
assemble's witness: seed ^ xor). proveSeconds + peakRssBytes are measured
inside the Rust worker. Artifacts → evidence/sla/proof-{kind}-{i:02d}.json.
"""
import json, os, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = Path(os.environ.get("SHIELDKIT_FRI_WORKER", ROOT / ".private/cargo-target/release/shieldkit-fri-worker"))
OUT = ROOT / "evidence" / "sla"
OUT.mkdir(parents=True, exist_ok=True)

# assemble: PP.build_witness(kind, depth, seed ^ xor) with xor {deposit:1, transfer:2, withdrawal:3}
XOR = {"deposit": 1, "transfer": 2, "withdrawal": 3}
SEED = 1

RANDOM = "--random" in sys.argv

def run_prove(kind: str) -> dict:
    req = json.dumps({
        "cmd": "prove", "kind": kind, "depth": 20,
        "blowup": 2048, "queries": 7, "grindBits": 30, "foldStep": 3,
        "maskDeg": 24, "deep": True,
        **({} if RANDOM else {"seed": SEED ^ XOR[kind], "randomMask": False}),
    }) + "\n"
    t0 = time.monotonic()
    r = subprocess.run([str(WORKER)], input=req, capture_output=True,
                       text=True, timeout=600, cwd=str(ROOT))
    wall = time.monotonic() - t0
    if r.returncode != 0:
        raise RuntimeError(f"worker rc={r.returncode}: {(r.stderr or '')[:400]}")
    lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError(f"no JSON: {(r.stderr or '')[:400]}")
    doc = json.loads(lines[-1])
    if not doc.get("verifyOk"):
        raise RuntimeError(f"prove not ok: {doc}")
    return {"proveSeconds": doc["proveSeconds"], "peakRssBytes": doc["peakRssBytes"],
            "wallSeconds": round(wall, 3), "verifyOk": True, "proofBlobSha256": doc.get("proofBlobSha256")}

def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for kind in ("deposit", "transfer", "withdrawal"):
        if only and kind != only:
            continue
        for w in range(3):
            m = run_prove(kind)
            print(f"{kind} warmup {w}: {m['proveSeconds']}s rss={m['peakRssBytes']}", flush=True)
        for i in range(1, 33):
            m = run_prove(kind)
            art = {
                "schema": "shieldkit-fri-p5-prove-sample-v1",
                "kind": kind, "sample": i,
                "proveSeconds": m["proveSeconds"], "peakRssBytes": m["peakRssBytes"],
                "wallSeconds": m["wallSeconds"], "verifyOk": m["verifyOk"],
                "proofBlobSha256": m["proofBlobSha256"],
                "config": {"depth": 20, "nq": 7, "blowup": 2048, "grind": 30, "fold_step": 3,
                           "mask_deg": 24, "deep": True, "seed": None if RANDOM else SEED ^ XOR[kind],
                           "maskSource": "csprng(thread_rng, 128-bit)" if RANDOM else "splitmix64(seed)",
                           "T": 1024, "N": "2^21"},
                "worker": str(WORKER),
                "command": "shieldkit-fri-worker prove (product config)",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            (OUT / f"proof-{kind}-{i:02d}.json").write_text(json.dumps(art, indent=2))
            print(f"{kind} #{i}: {m['proveSeconds']}s rss={m['peakRssBytes']}", flush=True)
    print("CAMPAIGN DONE", flush=True)

if __name__ == "__main__":
    main()
