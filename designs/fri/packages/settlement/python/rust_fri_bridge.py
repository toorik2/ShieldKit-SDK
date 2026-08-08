"""
Bridge to shieldkit-fri-worker for fast FRI terms + unlock packs.

Replaces pure-Python query_fri_terms_fold8 at floor scale (N=2^24 hung >10min).
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_WORKER = ROOT / ".private" / "cargo-target" / "release" / "shieldkit-fri-worker"


def worker_path() -> Path:
    env = os.environ.get("SHIELDKIT_FRI_WORKER") or os.environ.get("VC_FRI_WORKER")
    if env:
        return Path(env)
    return DEFAULT_WORKER


def _json_safe(obj: Any) -> Any:
    """Convert proof-like structures (tuples, bytes) into JSON-serializable form."""
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(x) for x in obj]
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).hex()
    if isinstance(obj, int):
        # keep as int (JSON number); u64 ok in Python json
        return obj
    if isinstance(obj, float):
        return obj
    if isinstance(obj, str):
        return obj
    if obj is None or isinstance(obj, bool):
        return obj
    return str(obj)


def call_worker(req: dict, timeout: float = 120.0) -> dict:
    w = worker_path()
    if not w.is_file():
        raise FileNotFoundError(f"shieldkit-fri-worker not found at {w}; cargo build -p shieldkit-fri-worker --release")
    r = subprocess.run(
        [str(w)],
        input=json.dumps(req) + "\n",
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(ROOT),
    )
    lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError(
            f"fri-worker no JSON (status={r.status}): stderr={(r.stderr or '')[:800]}"
        )
    doc = json.loads(lines[-1])
    if not doc.get("ok", True) and doc.get("error"):
        raise RuntimeError(f"fri-worker error: {doc['error']}")
    return doc


def proof_to_json_file(pf: dict, path: Path | None = None) -> Path:
    """Write proof dict as JSON for the Rust worker."""
    if path is None:
        fd, name = tempfile.mkstemp(prefix="pf-rust-", suffix=".json")
        os.close(fd)
        path = Path(name)
    path.write_text(json.dumps(_json_safe(pf)))
    return path


def query_fri_terms_fold8_rust(pf: dict) -> list[dict]:
    """
    Fast fold-8 FRI terms. Returns list of {k, rounds: [...]} matching vendor shape
    closely enough for unlock builders (base, coset, path, root, s, li0, stride, betas, i2x, ...).
    """
    path = proof_to_json_file(pf)
    try:
        doc = call_worker({"cmd": "fri-terms", "proofPath": str(path)})
    finally:
        try:
            path.unlink()
        except OSError:
            pass
    queries = doc.get("queries") or []
    # Normalize path entries to [(hex, bit), ...] tuples for vendor consumers.
    out = []
    for q in queries:
        rounds = []
        for r in q.get("rounds") or []:
            path = []
            for p in r.get("path") or []:
                if isinstance(p, (list, tuple)) and len(p) >= 2:
                    path.append((p[0], int(p[1])))
                elif isinstance(p, dict):
                    path.append((p.get("0") or p.get("hex") or "", int(p.get("1") or p.get("bit") or 0)))
            coset = [tuple(c) if not isinstance(c, tuple) else c for c in (r.get("coset") or [])]
            betas = [tuple(b) if not isinstance(b, tuple) else b for b in (r.get("betas") or [])]
            rounds.append(
                {
                    "base": int(r["base"]),
                    "coset": coset,
                    "path": path,
                    "root": r.get("root") or "",
                    "s": int(r["s"]),
                    "li0": int(r["li0"]),
                    "stride": int(r["stride"]),
                    "betas": betas,
                    "i2x": [int(x) for x in (r.get("i2x") or [])],
                    "ci": int(r.get("ci") or 0),
                    "comp_pos": int(r.get("comp_pos") or 0),
                    "fold_tgt": tuple(r.get("fold_tgt") or (0, 0)),
                }
            )
        out.append({"k": int(q.get("k") or 0), "rounds": rounds})
    return out


def assemble_unlocks_rust(pf: dict, *, aggfri_pad: int = 120, out_path: str | None = None) -> dict:
    path = proof_to_json_file(pf)
    try:
        req = {
            "cmd": "assemble-unlocks",
            "proofPath": str(path),
            "aggfriPad": aggfri_pad,
        }
        if out_path:
            req["out"] = out_path
        return call_worker(req, timeout=300.0)
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def patch_stark_query_fri_terms(stk_module) -> bool:
    """
    Monkey-patch STK.query_fri_terms_fold8 to use Rust when VC_RUST_FRI_TERMS is set (default on).
    Returns True if patched.
    """
    flag = os.environ.get("VC_RUST_FRI_TERMS", "1").strip().lower()
    if flag in ("0", "false", "no", "off"):
        return False
    if not worker_path().is_file():
        return False

    def _fast(proof):
        return query_fri_terms_fold8_rust(proof)

    stk_module.query_fri_terms_fold8 = _fast
    return True


class _LazyDomain:
    """Domain D[i] = off * oN^i mod P without materializing N=2^24 arrays."""

    __slots__ = ("off", "oN", "N", "P", "mul")

    def __init__(self, off: int, oN: int, N: int, P: int, mul):
        self.off = off
        self.oN = oN
        self.N = N
        self.P = P
        self.mul = mul

    def __getitem__(self, k):
        if isinstance(k, slice):
            # prove() does `Dd[:]` — materialize only on explicit slice (small domains);
            # the assemble path never slices, so floor stays lazy.
            return [self.mul(self.off, pow(self.oN, i, self.P))
                    for i in range(*k.indices(self.N))]
        i = int(k) % self.N
        return self.mul(self.off, pow(self.oN, i, self.P))

    def __len__(self) -> int:
        return self.N


def patch_setup_memoize(stk_module) -> bool:
    """
    Memoize STK._setup and avoid materializing Dd of size N=T*blowup.
    Floor N=2^24 made pure-Python domain lists multi-minute and multi-GB.
    """
    if getattr(stk_module, "_setup_memoized", False):
        return True
    # Field helpers live on the stark module / goldilocks imports
    P = getattr(stk_module, "P", None)
    mul = getattr(stk_module, "mul", None)
    root = getattr(stk_module, "root", None)
    G = getattr(stk_module, "G", None)
    if P is None or mul is None or root is None or G is None:
        # fall back to import from same package
        try:
            from native_poseidon2 import P as _P  # type: ignore
            P = _P
        except Exception:
            pass
        try:
            # goldilocks helpers often re-exported on STK
            mul = stk_module.mul
            root = stk_module.root
            G = stk_module.G
            P = stk_module.P
        except Exception:
            # still memoize original if we can't lazy-domain
            orig = stk_module._setup
            cache: dict[tuple[int, int], tuple] = {}

            def _memo_only(T, blowup):
                key = (int(T), int(blowup))
                if key not in cache:
                    cache[key] = orig(T, blowup)
                return cache[key]

            stk_module._setup = _memo_only
            stk_module._setup_memoized = True
            return True

    cache: dict[tuple[int, int], tuple] = {}

    def _lazy_setup(T, blowup):
        key = (int(T), int(blowup))
        hit = cache.get(key)
        if hit is not None:
            return hit
        T = int(T)
        blowup = int(blowup)
        N = blowup * T
        oT = root(T)
        oN = root(N)
        off = G
        Hd = [pow(oT, i, P) for i in range(T)]
        Dd = _LazyDomain(off, oN, N, P, mul)
        hit = (N, oT, oN, off, Hd, Dd, Hd[T - 1])
        cache[key] = hit
        return hit

    stk_module._setup = _lazy_setup
    stk_module._setup_memoized = True
    stk_module._setup_cache = cache
    return True


# ---------------------------------------------------------------------------
# Selectors-at-k: kill the full-domain selector LDE (N=2^24) in _sound_tail_terms.
#
# _sound_tail_terms only needs every public selector evaluated at ONE index k
# (the query's FRI-domain index), but the vendor calls STK._selector_vectors,
# which NTT-LDEs all 9 selspec + WIDTH rc + WIDTH chain_minv columns onto the
# FULL domain N=T*blowup (2^24 at floor) — minutes of pure-Python and ~30 GiB.
# We replace it with intt(T) + Horner at x = off*oN^k per column (memoized).
# ---------------------------------------------------------------------------

def patch_sound_tail_selectors_at_k(vt_module, stk_module) -> bool:
    """Monkey-patch native_ct_verifier_tx._sound_tail_terms to evaluate public
    selectors only at the query index k instead of materializing the full-domain
    LDE. Returns True when patched."""
    if getattr(vt_module, "_sound_tail_terms_patched", False):
        return True
    import inspect

    P = getattr(stk_module, "P", None)
    mul = getattr(stk_module, "mul", None)
    sel_keys = getattr(stk_module, "_SEL_KEYS", None)
    if P is None or mul is None or sel_keys is None:
        return False
    try:
        import native_ntt
        from native_poseidon2_constants import WIDTH
    except Exception:
        return False

    _coeff_cache: dict = {}

    def _poly_at(colname, vals, T, oT, x):
        """intt(vals on H) -> coeffs (memoized), then Horner at x."""
        key = (int(T), colname, tuple(vals))
        coeffs = _coeff_cache.get(key)
        if coeffs is None:
            coeffs = native_ntt.intt(list(vals), int(T), oT)
            _coeff_cache[key] = coeffs
        acc = 0
        for c in reversed(coeffs):
            acc = (acc * x + c) % P
        return acc

    def _selector_vals_at_k(lay, T, oT, oN, off, k):
        """Same dict shape as _selector_vectors but SCALARS at index k."""
        k = int(k)
        x = mul(off, pow(oN, k, P))
        T = int(T)
        sv = {key: _poly_at(key, lay[key], T, oT, x) for key in sel_keys}
        sv["rc"] = [_poly_at(("rc", i), lay["rc"][i], T, oT, x) for i in range(WIDTH)]
        sv["chain_minv"] = [
            _poly_at(("cm", j), [lay["chain_minv"][r][j] for r in range(T)], T, oT, x)
            for j in range(WIDTH)
        ]
        return sv

    # Rebuild _sound_tail_terms with the LDE line replaced by selectors-at-k.
    try:
        orig = inspect.getsource(vt_module._sound_tail_terms)
    except (OSError, TypeError):
        return False
    new = orig.replace(
        "sv = STK._selector_vectors(ly, T, N0, oT, oN, of)",
        "sv = _selector_vals_at_k(ly, T, oT, oN, of, k)",
    )
    if new == orig:
        return False
    for a, b in (
        ("sv[kk][k]", "sv[kk]"),
        ('sv["rc"][i][k]', 'sv["rc"][i]'),
        ('sv["chain_minv"][j][k]', 'sv["chain_minv"][j]'),
        ('sv["range_weight"][k]', 'sv["range_weight"]'),
    ):
        new = new.replace(a, b)
    ns = dict(vt_module.__dict__)
    ns["_selector_vals_at_k"] = _selector_vals_at_k
    exec(compile(new, "<patched _sound_tail_terms>", "exec"), ns)
    vt_module._sound_tail_terms = ns["_sound_tail_terms"]
    vt_module._sound_tail_terms_patched = True
    vt_module._sel_at_k_cache = _coeff_cache
    return True


def patch_assemble_hotpaths(stk_module, vt_module=None) -> dict:
    """Apply all assemble-time hot-path patches. Returns status flags."""
    return {
        "rustFriTerms": patch_stark_query_fri_terms(stk_module),
        "setupMemoize": patch_setup_memoize(stk_module),
        "selectorsAtK": patch_sound_tail_selectors_at_k(vt_module, stk_module) if vt_module is not None else False,
        "worker": str(worker_path()),
        "workerExists": worker_path().is_file(),
    }
