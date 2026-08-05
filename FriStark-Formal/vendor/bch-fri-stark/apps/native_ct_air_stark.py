"""
native_ct_air_stark.py -- HP1.6 real FRI-STARK prove/verify over the CT-AIR transfer.

Produces a succinct, zero-knowledge proof that a witness satisfies the full CT-AIR
(Poseidon2 rounds + A2 sponge chaining/capacity + A3 held-value bindings + Num2Bits
range + conservation + public statement), then verifies it from query openings ONLY.
Reference-grade, mirroring the proven membership_stark.prove/verify machinery
(commit -> Fiat-Shamir -> alpha-composition -> FRI folding -> grind -> queries), with
the Runde-1 L#3 field split applied (hp6_air_ext_split / cost_report_native_ext):

  * BASE Goldilocks: the trace columns + their Merkle commitment (SHA256 leaves), the
    Poseidon2 S-box/MDS residuals fn(cur,nxt,x), the vanishing Z_H(x)=x^T-1 and the
    boundary 1/(x-H[row]) -- all base-field polynomial identities at the base point x.
  * GF(p^2) (native_gf_p2): the random constraint-combination challenges alpha, the
    accumulator/composition value, the FRI folding challenges beta and the folded FRI
    values -- so a single challenge's soundness error ~ deg/|F| clears 100 bit.

NO mocks, NO invented constants: the constraint set is the verified unified interface
in native_ct_air_prover (ct_transition_residuals / ct_boundary_constraints), the
extension field is native_gf_p2 (Plonky3 u^2-7), the engine is stark.py. self_test()
proves a real proof verifies and that tampering (statement, trace opening, FRI value,
grind) is rejected -- real witness from _demo_witness.
"""
import os
import sys

_APPS = os.path.dirname(os.path.abspath(__file__))
if _APPS not in sys.path:
    sys.path.insert(0, _APPS)
_PKG = os.path.dirname(_APPS)                       # package root (holds stark.py)
if _PKG not in sys.path:
    sys.path.insert(0, _PKG)

from stark import (P, sub, mul, inv, G, root, Hf, enc, merkle, m_root, m_path,
                   m_verify, FS, grind)
import native_gf_p2 as F2
from native_ntt import lde_coset, intt
from native_ct_air_prover import (WIDTH, FLAT_COLS, build_ct_trace, build_full_flat_trace,
                                   ct_public_layout, ct_transition_residuals,
                                   ct_num_transition_residuals, ct_boundary_constraints,
                                   ct_transition_residuals_ext, ct_boundary_constraints_ext,
                                   ct_build_layout, _demo_witness)
from native_ct_air_config import (BLOWUP as CFG_BLOWUP, QUERIES as CFG_QUERIES,
                                   GRIND_BITS as CFG_GRIND, MASK_DEG, FOLD as CFG_FOLD)

# Self-test / functional params: correctness is independent of the soundness rate, so
# the self-test uses a small (fast) blowup. comp has symbolic degree ~2T (degree-(T-1)
# selector * degree-2 column residual), so the FRI domain N=blowup*T needs blowup>=4 to stay
# low-degree -- this is exactly why the tested rate is 2/blowup, not 1/blowup (HP1.0a). The
# pinned >=100-bit deploy config is CFG_BLOWUP/QUERIES/GRIND; MASK_DEG (ZK mask degree, hides
# trace values via R(x)*Z_H(x), vanishes on H) is the pinned config value (HP1.2/1.3, >=4*QUERIES).
TEST_BLOWUP = 4
TEST_QUERIES = 4
TEST_GRIND = 4


def _setup(T, blowup):
    """FRI domain: H = T-th roots (trace), D = coset off*<N-th roots>, N = blowup*T."""
    N = blowup * T
    oT = root(T); oN = root(N); off = G
    Hd = [pow(oT, i, P) for i in range(T)]
    Dd = [mul(off, pow(oN, i, P)) for i in range(N)]
    return N, oT, oN, off, Hd, Dd, Hd[T - 1]


def _leaf(vals, salt):
    """Base-field trace leaf (salted hash of the row's columns)."""
    return Hf(salt + b"".join(enc(v) for v in vals))


def _leaf_ext(v, salt):
    """FRI leaf for a GF(p^2) value = its two base limbs."""
    return Hf(salt + enc(v[0]) + enc(v[1]))


def _leaf_ext_pair(v, w, salt):
    """HP6.1 pair-leaf: the fold-2 coset (v@i, w@i+half) committed as ONE leaf = its four base limbs.
    Halves the per-layer Merkle paths (1 opening instead of 2) -> ~2x fewer FRI witness bytes, no soundness
    change (both values are bound to the same leaf hash -> the FS-pinned layer root)."""
    return Hf(salt + enc(v[0]) + enc(v[1]) + enc(w[0]) + enc(w[1]))


def _leaf_ext_coset(coset, salt):
    """HP1.9-FOLD8 layer-skip leaf (ethSTARK v1.2 3.11.1): the 2^s-coset
    {vals[base + m*(n/2^s)] : m=0..2^s-1} packed as ONE Merkle leaf (its 2*2^s base limbs) ->
    1 authentication path per committed layer instead of 2^s. "The cost of skipping layers is
    sending more field elements, but not more authentication paths" -- the <100KB byte win.
    Generalises _leaf_ext_pair (which is the s=1 case)."""
    return Hf(salt + b"".join(enc(v[0]) + enc(v[1]) for v in coset))


def _fold_once(vals, dom, beta, inv2):
    """One FRI fold-by-2 in GF(p^2): (vals[j], vals[j+half]) over base domain point dom[j] ->
    half folded values, and the squared domain for the next layer. Identical butterfly to the
    fold-2 commit loop; used by the fold-8 commit (which folds s times between commitments)."""
    half = len(vals) // 2
    nv = [F2.add(F2.scalar(inv2, F2.add(vals[j], vals[j + half])),
                 F2.mul(beta, F2.scalar(inv(mul(2, dom[j])), F2.sub(vals[j], vals[j + half]))))
          for j in range(half)]
    return nv, [mul(d, d) for d in dom[:half]]


def _fri_folds_to_final(n):
    """Number of fold-by-2 steps that bring FRI layer size n down to <= 8 (the commit-phase
    stop rule, shared by fold-2 and fold-8)."""
    f = 0
    while (n >> f) > 8:
        f += 1
    return f


def _coset_fold(coset, base, li0, s, betas_round, off, oN, N, inv2):
    """Fold a 2^s-coset of committed layer li0 (size n=N>>li0) down to ONE value, recomputing
    each internal fold's domain point (off*oN^gidx)^(2^(li0+f)) from the base index alone
    (verifier-style -- no domain array). betas_round = betas[li0:li0+s]. Validated to equal s
    sequential _fold_once against the real fold-2 layers (hp19_fold8_validate: 3016 cross-checks)."""
    n = N >> li0
    stride = n >> s
    cur = list(coset)
    for f in range(s):
        h = len(cur) // 2                                        # 2^(s-1-f) output elements
        beta = betas_round[f]
        nxt = [None] * h
        for m in range(h):
            x = pow(mul(off, pow(oN, base + m * stride, P)), 1 << (li0 + f), P)
            i2x = inv(mul(2, x)); fp = cur[m]; fm = cur[m + h]
            nxt[m] = F2.add(F2.scalar(inv2, F2.add(fp, fm)),
                            F2.mul(beta, F2.scalar(i2x, F2.sub(fp, fm))))
        cur = nxt
    return cur[0]


def _fri_commit_fold8(vals, dom, N, off, oN, fs, step, inv2):
    """FRI commit phase with layer-skipping (ethSTARK 3.11.1): commit a Merkle root only every
    `step` layers, packing the 2^s-coset per leaf (s = folds until the next commit), and draw s
    fold challenges per committed round. Returns (fri_trees, betas, rounds, final) where
    rounds[r] = (li0, s, layer_values, tree) is the committed layer's global fold-start, its
    fold count, its full values (for coset openings), and its Merkle tree."""
    fri_trees = []; betas = []; rounds = []; li0 = 0
    while True:
        s = min(step, _fri_folds_to_final(len(vals)))
        if s == 0:                                               # final committed layer (<=8), sent in clear
            tr = merkle([_leaf_ext(v, b"\x00" * 16) for v in vals])
            fri_trees.append(tr); fs.absorb(m_root(tr)); rounds.append((li0, 0, vals, tr))
            return fri_trees, betas, rounds, vals
        stride = len(vals) >> s
        tr = merkle([_leaf_ext_coset([vals[base + m * stride] for m in range(1 << s)],
                                     b"\x00" * 16) for base in range(stride)])
        fri_trees.append(tr); fs.absorb(m_root(tr)); rounds.append((li0, s, vals, tr))
        for _ in range(s):
            beta = _ext_challenge(fs); betas.append(beta)
            vals, dom = _fold_once(vals, dom, beta, inv2)
        li0 += s


def _ext_challenge(fs):
    """Draw a GF(p^2) challenge = two base squeezes of the SAME transcript (Plonky3:
    one ext challenge is two base limbs; no extra hashing -- cost_report_native_ext)."""
    return (fs.challenge(), fs.challenge())


_SEL_KEYS = ("is_full", "is_partial", "is_block_start", "is_reabsorb", "is_range",
             "is_range_first", "is_range_step", "is_range_last", "range_weight")


def _selector_vectors(lay, T, N, oT, oN, off):
    """Low-degree-extend every public selector / round-constant / chain-row / weight
    from H onto the coset D (one NTT each) so the composition reads them by index
    instead of an O(deg) Horner evaluation per point."""
    sv = {key: lde_coset(lay[key], T, N, oT, oN, off) for key in _SEL_KEYS}
    sv["rc"] = [lde_coset(lay["rc"][k], T, N, oT, oN, off) for k in range(WIDTH)]
    sv["chain_minv"] = [lde_coset([lay["chain_minv"][r][j] for r in range(T)],
                                  T, N, oT, oN, off) for j in range(WIDTH)]
    return sv


def _pub_at_idx(sv, i):
    """Public selector values at FRI-domain index i (from the precomputed LDE vectors)."""
    return {"is_full": sv["is_full"][i], "is_partial": sv["is_partial"][i],
            "rc": [sv["rc"][k][i] for k in range(WIDTH)],
            "is_block_start": sv["is_block_start"][i], "is_reabsorb": sv["is_reabsorb"][i],
            "chain_minv": [sv["chain_minv"][j][i] for j in range(WIDTH)],
            "is_range": sv["is_range"][i], "is_range_first": sv["is_range_first"][i],
            "is_range_step": sv["is_range_step"][i], "is_range_last": sv["is_range_last"][i]}


def _ood_pub_at(lay, T, oT, z):
    """HP5.2/HP3.3: the public selectors evaluated at the OOD point z in GF(p^2) -- SAME dict shape as
    _pub_at_idx (index-based on D), but here every column is evaluated out-of-domain via _ood_public_at
    (intt -> GF(p^2)-Horner). The verifier builds the identical dict itself at z (anti-forgery, HP7.4)."""
    return {"is_full": _ood_public_at(lay["is_full"], T, oT, z),
            "is_partial": _ood_public_at(lay["is_partial"], T, oT, z),
            "rc": [_ood_public_at(lay["rc"][k], T, oT, z) for k in range(WIDTH)],
            "is_block_start": _ood_public_at(lay["is_block_start"], T, oT, z),
            "is_reabsorb": _ood_public_at(lay["is_reabsorb"], T, oT, z),
            "chain_minv": [_ood_public_at([lay["chain_minv"][r][j] for r in range(T)], T, oT, z)
                           for j in range(WIDTH)],
            "is_range": _ood_public_at(lay["is_range"], T, oT, z),
            "is_range_first": _ood_public_at(lay["is_range_first"], T, oT, z),
            "is_range_step": _ood_public_at(lay["is_range_step"], T, oT, z),
            "is_range_last": _ood_public_at(lay["is_range_last"], T, oT, z)}


def _compose_at(cur, nxt, x, w_next, last, ZHx_inv, Hd, pub_x, alphas_T, bcons, alphas_B):
    """The composition value at one point: sum_j alpha_j * quotient_j  in GF(p^2).
    transition q = v*(x-last)/Z_H(x) ; boundary q = v/(x-H[row]). v base, alpha ext."""
    xl = sub(x, last)
    acc = F2.ZERO
    for a, v in zip(alphas_T, ct_transition_residuals(cur, nxt, pub_x, w_next)):
        acc = F2.add(acc, F2.scalar(mul(mul(v, xl), ZHx_inv), a))
    for (row, fn), a in zip(bcons, alphas_B):
        acc = F2.add(acc, F2.scalar(mul(fn(cur), inv(sub(x, Hd[row]))), a))
    return acc


def _compose_at_ext(cur, nxt, z, w_next, last, ZHz_inv, Hd, pub_x, alphas_T, bcons_ext, alphas_B):
    """HP4.3: the composition value comp(z) at the out-of-domain point z over GF(p^2) -- the DEEP AIR-eval-
    ONCE (DEEP_ALI_resolution.md sec 5-7). Mirrors _compose_at:186-195 with FULL GF(p^2) arithmetic: cur/nxt/
    pub_x/w_next are the OOD mask values (GF(p^2)); z, ZHz_inv=1/(z^T-1), the (z-H[row])^-1 boundary quotients
    are GF(p^2). transition q = v*(z-last)/Z_H(z); boundary q = v/(z-H[row]); alphas a in GF(p^2)."""
    zl = F2.sub(z, F2.from_base(last))
    acc = F2.ZERO
    for a, v in zip(alphas_T, ct_transition_residuals_ext(cur, nxt, pub_x, w_next)):
        acc = F2.add(acc, F2.mul(F2.mul(F2.mul(v, zl), ZHz_inv), a))
    for (row, fn), a in zip(bcons_ext, alphas_B):
        acc = F2.add(acc, F2.mul(F2.mul(fn(cur), F2.inv(F2.sub(z, F2.from_base(Hd[row])))), a))
    return acc


def _ood_horner(coeffs, z):
    """HP3.1: evaluate a base-field coefficient polynomial (low->high order) at the DEEP out-of-domain
    point z in GF(p^2). native p_eval (stark.py) is base-only; z is a GF(p^2) element, so this is the
    GF(p^2)-Horner accumulation acc = z*acc + c_i with the base coeff embedded via F2.from_base."""
    acc = F2.ZERO
    for c in reversed(coeffs):
        acc = F2.add(F2.mul(z, acc), F2.from_base(c))
    return acc


def _ood_public_at(h_vals, T, oT, z):
    """HP3.3: an UNMASKED public column (given by its T values on H = <oT>) evaluated at z in GF(p^2)
    (intt -> base coeffs, then GF(p^2)-Horner). For the public selectors / rc / chain_minv / range_weight
    -- the verifier evaluates these itself at z (anti-forgery, DEEP_ALI_resolution.md sec 6). Deterministic
    from the public layout; no secret input."""
    return _ood_horner(intt(h_vals, T, oT), z)


def _ood_trace_at(h_vals, mask_R, T, oT, z):
    """HP3.2: a MASKED trace column at the OOD point z in GF(p^2). The committed trace poly is
    P_c = intt(h_vals) + R(x)*(x^T - 1) (native_ntt.lde_coset:76-82); the DEEP quotient binds the
    COMMITTED values, so the mask value MUST be P_c(z), NOT the unmasked interpolant (z not in H =>
    R(z)*(z^T - 1) != 0). PROVER-only (needs the secret mask R). DEEP_ALI_resolution.md sec 6."""
    coeffs = intt(h_vals, T, oT) + [0] * len(mask_R)
    for k in range(len(mask_R)):
        coeffs[k] = (coeffs[k] - mask_R[k]) % P
        coeffs[T + k] = (coeffs[T + k] + mask_R[k]) % P
    return _ood_horner(coeffs, z)


def prove(w, blowup=TEST_BLOWUP, grind_b=TEST_GRIND, n_queries=TEST_QUERIES, mask_deg=MASK_DEG,
          seed=None, return_fri=False, pairleaf=False, fold_step=1, deep=False):
    """Build the CT-AIR trace for witness w and produce a real FRI-STARK proof. seed=None
    draws the ZK mask + Merkle salts from os.urandom (production: an unpredictable mask is
    REQUIRED for zero-knowledge). An integer seed makes the proof DETERMINISTIC (HP1.9,
    reproducible test vectors) -- NEVER use a fixed seed in production (it breaks ZK)."""
    trace, stmt = build_ct_trace(w)
    cols, T, meta = build_full_flat_trace(trace)
    if seed is None:
        _rand = os.urandom
    else:
        import random as _random
        _rng = _random.Random(seed)
        _rand = lambda nb: _rng.getrandbits(nb * 8).to_bytes(nb, "little")
    N, oT, oN, off, Hd, Dd, last = _setup(T, blowup)
    lay = ct_public_layout(meta, T)
    sv = _selector_vectors(lay, T, N, oT, oN, off)

    # low-degree-extend + ZK-mask each committed column onto the FRI domain D (NTT)
    colvals = {}; mask_Rs = {}
    for c in FLAT_COLS:
        R = [int.from_bytes(_rand(8), "little") % P for _ in range(mask_deg)]
        mask_Rs[c] = R                                    # HP5.2: keep the per-column mask R (P_c(z) needs it)
        colvals[c] = lde_coset(cols[c], T, N, oT, oN, off, mask_R=R)
    salts = [_rand(16) for _ in range(N)]
    leaves = [_leaf([colvals[c][i] for c in FLAT_COLS], salts[i]) for i in range(N)]
    tree = merkle(leaves)

    fs = FS(); fs.absorb(m_root(tree))
    fs.absorb_int(stmt["root"]); fs.absorb_int(stmt["nf"])
    for cm in stmt["cm_out"]:
        fs.absorb_int(cm)
    n_T = ct_num_transition_residuals()
    bcons = ct_boundary_constraints(meta, stmt)
    alphas_T = [_ext_challenge(fs) for _ in range(n_T)]
    alphas_B = [_ext_challenge(fs) for _ in range(len(bcons))]

    shift = N // T
    comp = [F2.ZERO] * N
    for i in range(N):
        x = Dd[i]; inx = (i + shift) % N
        cur = {c: colvals[c][i] for c in FLAT_COLS}
        nxt = {c: colvals[c][inx] for c in FLAT_COLS}
        pub_x = _pub_at_idx(sv, i); w_next = sv["range_weight"][inx]
        ZHx_inv = inv(sub(pow(x, T, P), 1))
        comp[i] = _compose_at(cur, nxt, x, w_next, last, ZHx_inv, Hd, pub_x,
                              alphas_T, bcons, alphas_B)

    # HP2/HP5 (DEEP): commit comp separately, derive the OOD point z, evaluate the mask values, draw the DEEP
    # combination alphas, and build the DEEP-quotient q. deep=False: byte-identical (this whole block skipped).
    comp_tree = None; q = None; _deep = None
    if deep:
        # HP2: commit the composition LDE as its OWN Merkle tree (unsalted, like FRI-layer-0 :257) and absorb
        # comp_root into FS AFTER the AIR-alphas (:231-232) and BEFORE z (Frozen-Heart; DEEP_ALI_resolution.md 4).
        comp_tree = merkle([_leaf_ext(comp[i], b"\x00" * 16) for i in range(N)])
        fs.absorb(m_root(comp_tree))
        # HP5.1: draw z from FS after comp_root; force z into GF(p^2)\GF(p) so z (and z*g) lie outside H and D
        # (both base-field domains) w.h.p. -- DEEP_ALI_resolution.md 8 (ethSTARK v1.2 5.3, Spec-Z.776). fail-closed.
        z = _ext_challenge(fs)
        if z[1] % P == 0:
            z = (z[0], 1)
        zg = F2.scalar(oT, z)                             # z*g, g = oT (trace-domain generator; prove:237-240)
        # HP5.2: the OOD mask values -- masked trace at z/z*g (HP3.2), public selectors at z + range_weight at
        # z*g (HP3.3), comp(z) via the GF(p^2) AIR-eval-ONCE (HP4.3).
        Pcz = {c: _ood_trace_at(cols[c], mask_Rs[c], T, oT, z) for c in FLAT_COLS}
        Pczg = {c: _ood_trace_at(cols[c], mask_Rs[c], T, oT, zg) for c in FLAT_COLS}
        pub_z = _ood_pub_at(lay, T, oT, z)
        rw_zg = _ood_public_at(lay["range_weight"], T, oT, zg)
        ZHz_inv = F2.inv(F2.sub(F2.power(z, T), F2.ONE))
        comp_z = _compose_at_ext(Pcz, Pczg, z, rw_zg, last, ZHz_inv, Hd,
                                 pub_z, alphas_T, ct_boundary_constraints_ext(meta, stmt), alphas_B)
        # the committed public selector columns with a DEEP z-term (8 indicators + rc[12] + chain_minv[12] = 32;
        # range_weight is the single z*g selector). FIXED order (D-values, mask value at z).
        _sel_keys8 = ("is_full", "is_partial", "is_block_start", "is_reabsorb",
                      "is_range", "is_range_first", "is_range_step", "is_range_last")
        sel_terms = [(sv[k], pub_z[k]) for k in _sel_keys8]
        sel_terms += [(sv["rc"][k], pub_z["rc"][k]) for k in range(WIDTH)]
        sel_terms += [(sv["chain_minv"][j], pub_z["chain_minv"][j]) for j in range(WIDTH)]
        # HP5.3: absorb ALL mask values into FS BEFORE drawing deep_alphas (Frozen-Heart; DEEP_ALI_resolution 11)

        def _absorb_ext(v):
            fs.absorb_int(v[0]); fs.absorb_int(v[1])
        for c in FLAT_COLS:
            _absorb_ext(Pcz[c]); _absorb_ext(Pczg[c])
        for _dv, _m in sel_terms:
            _absorb_ext(_m)
        _absorb_ext(rw_zg); _absorb_ext(comp_z)
        # HP5.4: draw the M deep_alphas (one per DEEP term) in the SAME fixed order q is built below.
        n_terms = 2 * len(FLAT_COLS) + len(sel_terms) + 1 + 1
        deep_alphas = [_ext_challenge(fs) for _ in range(n_terms)]
        # HP5.5: build the DEEP-quotient q over D. Two shared denominators (Dd[j]-z)^-1, (Dd[j]-z*g)^-1.
        inv_z = [F2.inv(F2.sub(F2.from_base(Dd[j]), z)) for j in range(N)]
        inv_zg = [F2.inv(F2.sub(F2.from_base(Dd[j]), zg)) for j in range(N)]
        q = [F2.ZERO] * N
        _ai = [0]

        def _acc(dvals, is_ext, mask_ood, inv_arr):
            a = deep_alphas[_ai[0]]; _ai[0] += 1
            for j in range(N):
                dv = dvals[j] if is_ext else F2.from_base(dvals[j])
                q[j] = F2.add(q[j], F2.mul(a, F2.mul(F2.sub(dv, mask_ood), inv_arr[j])))
        for c in FLAT_COLS:                               # trace columns: z-term then z*g-term
            _acc(colvals[c], False, Pcz[c], inv_z)
            _acc(colvals[c], False, Pczg[c], inv_zg)
        for _dv, _m in sel_terms:                         # public selectors: z-term
            _acc(_dv, False, _m, inv_z)
        _acc(sv["range_weight"], False, rw_zg, inv_zg)    # range_weight: z*g-term
        _acc(comp, True, comp_z, inv_z)                   # composition: z-term
        _deep = {"comp_root": m_root(comp_tree).hex(), "z": z, "zg": zg, "comp_z": comp_z, "rw_zg": rw_zg,
                 "Pcz": Pcz, "Pczg": Pczg, "sel_z": [_m for _dv, _m in sel_terms], "deep_alphas": deep_alphas}

    # FRI: commit + fold the composition in GF(p^2) until the layer is small. fold_step=1 =
    # classic fold-by-2 (one Merkle root per layer, the tp_root/query structure the shard reads);
    # fold_step=s = ethSTARK 3.11.1 layer-skipping (commit every s-th layer, 2^s-coset leaf) for
    # the <100KB whole-tx: fewer authentication paths (HP1.9-FOLD8).
    fri_layers = []; fri_trees = []; vals = (list(q) if deep else comp[:]); dom = Dd[:]; betas = []
    fs.absorb(b"fri")                                     # HP5.6: DEEP FRIs the DEEP-quotient q (not comp directly)
    inv2 = inv(2)
    _rounds = None
    if fold_step == 1:
        while True:
            _h = len(vals) // 2                       # HP6.1: pair-leaf commit = the fold-2 coset (v@i, w@i+half)
            tr = (merkle([_leaf_ext_pair(vals[i], vals[i + _h], b"\x00" * 16) for i in range(_h)]) if pairleaf
                  else merkle([_leaf_ext(vals[i], b"\x00" * 16) for i in range(len(vals))]))
            fri_layers.append(vals); fri_trees.append(tr); fs.absorb(m_root(tr))
            if len(vals) <= 8:
                break
            beta = _ext_challenge(fs); betas.append(beta)
            half = len(vals) // 2; nv = [None] * half
            for j in range(half):
                x = dom[j]; fp = vals[j]; fm = vals[j + half]
                i2x = inv(mul(2, x))
                nv[j] = F2.add(F2.scalar(inv2, F2.add(fp, fm)),
                               F2.mul(beta, F2.scalar(i2x, F2.sub(fp, fm))))
            vals = nv; dom = [mul(d, d) for d in dom[:half]]
        final = fri_layers[-1]
    else:
        fri_trees, betas, _rounds, final = _fri_commit_fold8(vals, dom, N, off, oN, fs, fold_step, inv2)

    nonce = grind(fs.s, grind_b); fs.absorb(nonce)
    idxs = [fs.challenge_idx(N) for _ in range(n_queries)]
    Q = []
    for k in idxs:
        kn = (k + shift) % N
        if deep:                                          # HP5.7: DEEP opens ONLY trace(x_k) + comp(x_k); the next-row
            op = {"k": k,                                  # coupling is bound once by trace(z*g) -> kn/cn/sn/pn dropped.
                  "ck": {c: colvals[c][k] for c in FLAT_COLS}, "sk": salts[k].hex(),
                  "pk": [(s.hex(), b) for s, b in m_path(tree, k)],
                  "cc": comp[k], "cp": [(s.hex(), b) for s, b in m_path(comp_tree, k)], "fri": []}
        else:                                             # deep=False: unchanged (byte-identical regression oracle)
            op = {"k": k,
                  "ck": {c: colvals[c][k] for c in FLAT_COLS}, "sk": salts[k].hex(),
                  "pk": [(s.hex(), b) for s, b in m_path(tree, k)],
                  "cn": {c: colvals[c][kn] for c in FLAT_COLS}, "sn": salts[kn].hex(),
                  "pn": [(s.hex(), b) for s, b in m_path(tree, kn)], "fri": []}
        ci = k
        if fold_step == 1:
            for li in range(len(fri_layers) - 1):
                half = len(fri_layers[li]) // 2; ii = ci % half
                if pairleaf:                          # HP6.1: open the ONE pair-leaf at index ii -> (v, w) + 1 path
                    op["fri"].append({"v": fri_layers[li][ii], "w": fri_layers[li][ii + half],
                                      "p": [(s.hex(), b) for s, b in m_path(fri_trees[li], ii)]})
                else:
                    op["fri"].append({"v": fri_layers[li][ii],
                                      "vp": [(s.hex(), b) for s, b in m_path(fri_trees[li], ii)],
                                      "w": fri_layers[li][ii + half],
                                      "wp": [(s.hex(), b) for s, b in m_path(fri_trees[li], ii + half)]})
                ci = ii
        else:                                         # HP1.9-FOLD8: open ONE 2^s-coset leaf per committed round
            for (_li0, _s, _rv, _tr) in _rounds:
                if _s == 0:
                    break
                _stride = len(_rv) >> _s; base = ci % _stride
                op["fri"].append({"base": base,
                                  "coset": [_rv[base + m * _stride] for m in range(1 << _s)],
                                  "p": [(s.hex(), b) for s, b in m_path(_tr, base)]})
                ci = base
        Q.append(op)
    _out = {"stmt": stmt, "tp_root": m_root(tree).hex(),
            "fri_roots": [m_root(t).hex() for t in fri_trees], "final": final, "betas": betas,
            "nonce": nonce.hex(), "queries": Q, "grind_b": grind_b, "blowup": blowup,
            "nq": len(Q), "mask_deg": mask_deg, "pairleaf": pairleaf, "fold_step": fold_step}
    if deep:                             # HP5.8: the DEEP proof fields (z/z*g/masks/comp(z)/deep_alphas/comp_root).
        _out["deep"] = True              # deep=False: dict byte-identical (no keys added).
        _out["comp_root"] = _deep["comp_root"]
        _out["z"] = _deep["z"]; _out["zg"] = _deep["zg"]
        _out["comp_z"] = _deep["comp_z"]; _out["rw_zg"] = _deep["rw_zg"]
        _out["Pcz"] = _deep["Pcz"]; _out["Pczg"] = _deep["Pczg"]
        _out["sel_z"] = _deep["sel_z"]; _out["deep_alphas"] = _deep["deep_alphas"]
    if return_fri:                       # test-only hook (default off; production dict byte-identical):
        _out["_fri_layers"] = fri_layers  # expose real FRI layer values + domain for fold-change validation
        _out["_Dd"] = Dd                  # (HP6.1 pair-leaf prototype needs the full layer to build the pair-tree)
    return _out


def _deep_replay(fs, proof, alphas_T, alphas_B, meta, T, oT, Hd, Dd, N, last, lay, sv):
    """HP7/HP8: reconstruct the DEEP-ALI Fiat-Shamir state on `fs` (absorb comp_root, draw z, evaluate the
    verifier's own selectors at z, check the ONE AIR binding comp(z)==AIR(z), absorb the mask values, draw
    deep_alphas -- in the prover's EXACT order, HP5.1-5.4) and return a q(x_k) evaluator. SINGLE source of the
    DEEP formula, shared by verify (HP7) + query_terms/query_fri_terms_fold8 (HP8). Returns
    (ok, why, z, zg, deep_alphas, q_at); q_at(x, k, ck, cc) -> the DEEP-quotient at the query point x=Dd[k]."""
    fs.absorb(bytes.fromhex(proof["comp_root"]))          # HP7.2
    z = _ext_challenge(fs)                                # HP7.1
    if z[1] % P == 0:
        z = (z[0], 1)
    zg = F2.scalar(oT, z)
    if z != tuple(proof["z"]) or zg != tuple(proof["zg"]):
        return False, "deep z mismatch", None, None, None, None
    Pcz = {c: tuple(proof["Pcz"][c]) for c in FLAT_COLS}
    Pczg = {c: tuple(proof["Pczg"][c]) for c in FLAT_COLS}
    comp_z_pf = tuple(proof["comp_z"]); rw_zg = tuple(proof["rw_zg"])
    pub_z_v = _ood_pub_at(lay, T, oT, z)                  # HP7.4: verifier's OWN selectors at z (anti-forgery)
    if _ood_public_at(lay["range_weight"], T, oT, zg) != rw_zg:
        return False, "deep range_weight(z*g) mismatch", None, None, None, None
    ZHz_inv = F2.inv(F2.sub(F2.power(z, T), F2.ONE))      # HP7.5: comp(z) == AIR-eval-once at z (GF(p^2))
    if _compose_at_ext(Pcz, Pczg, z, rw_zg, last, ZHz_inv, Hd, pub_z_v, alphas_T,
                       ct_boundary_constraints_ext(meta, proof["stmt"]), alphas_B) != comp_z_pf:
        return False, "comp(z) != AIR(z)", None, None, None, None
    _sel_keys8 = ("is_full", "is_partial", "is_block_start", "is_reabsorb",
                  "is_range", "is_range_first", "is_range_step", "is_range_last")
    sel_terms_v = [(sv[key], pub_z_v[key]) for key in _sel_keys8]
    sel_terms_v += [(sv["rc"][kk], pub_z_v["rc"][kk]) for kk in range(WIDTH)]
    sel_terms_v += [(sv["chain_minv"][j], pub_z_v["chain_minv"][j]) for j in range(WIDTH)]
    for c in FLAT_COLS:                                   # HP7.3: absorb ALL mask values BEFORE deep_alphas
        fs.absorb_int(Pcz[c][0]); fs.absorb_int(Pcz[c][1])
        fs.absorb_int(Pczg[c][0]); fs.absorb_int(Pczg[c][1])
    for _dv, _m in sel_terms_v:
        fs.absorb_int(_m[0]); fs.absorb_int(_m[1])
    fs.absorb_int(rw_zg[0]); fs.absorb_int(rw_zg[1])
    fs.absorb_int(comp_z_pf[0]); fs.absorb_int(comp_z_pf[1])
    deep_alphas = [_ext_challenge(fs) for _ in range(2 * len(FLAT_COLS) + len(sel_terms_v) + 2)]
    if deep_alphas != [tuple(a) for a in proof["deep_alphas"]]:
        return False, "deep_alphas mismatch", None, None, None, None

    def q_at(x, k, ck, cc):                               # HP7.7: q(x_k), SAME term order as prover HP5.5
        invz = F2.inv(F2.sub(F2.from_base(x), z))
        invzg = F2.inv(F2.sub(F2.from_base(x), zg))
        acc = F2.ZERO; ai = 0
        for c in FLAT_COLS:
            cke = F2.from_base(ck[c])
            acc = F2.add(acc, F2.mul(deep_alphas[ai], F2.mul(F2.sub(cke, Pcz[c]), invz))); ai += 1
            acc = F2.add(acc, F2.mul(deep_alphas[ai], F2.mul(F2.sub(cke, Pczg[c]), invzg))); ai += 1
        for _dv, _m in sel_terms_v:
            acc = F2.add(acc, F2.mul(deep_alphas[ai], F2.mul(F2.sub(F2.from_base(_dv[k]), _m), invz))); ai += 1
        acc = F2.add(acc, F2.mul(deep_alphas[ai],
                     F2.mul(F2.sub(F2.from_base(sv["range_weight"][k]), rw_zg), invzg))); ai += 1
        acc = F2.add(acc, F2.mul(deep_alphas[ai], F2.mul(F2.sub(cc, comp_z_pf), invz))); ai += 1
        return acc
    return True, "ok", z, zg, deep_alphas, q_at


def verify(proof):
    """Verify a CT-AIR FRI-STARK proof from its query openings only. Returns (ok, why)."""
    stmt = proof["stmt"]; D = stmt["depth"]
    meta, T = ct_build_layout(D)
    N, oT, oN, off, Hd, Dd, last = _setup(T, proof["blowup"])
    lay = ct_public_layout(meta, T)
    sv = _selector_vectors(lay, T, N, oT, oN, off)
    tp_root = bytes.fromhex(proof["tp_root"])
    fri_roots = [bytes.fromhex(r) for r in proof["fri_roots"]]
    pairleaf = proof.get("pairleaf", False)               # HP6.1: pair-leaf FRI commit (1 Merkle path/layer)
    step = proof.get("fold_step", 1)                      # HP1.9-FOLD8: 1 = fold-2; s = layer-skip fold-2^s

    fs = FS(); fs.absorb(tp_root)
    fs.absorb_int(stmt["root"]); fs.absorb_int(stmt["nf"])
    for cm in stmt["cm_out"]:
        fs.absorb_int(cm)
    n_T = ct_num_transition_residuals()
    bcons = ct_boundary_constraints(meta, stmt)
    alphas_T = [_ext_challenge(fs) for _ in range(n_T)]
    alphas_B = [_ext_challenge(fs) for _ in range(len(bcons))]

    deep = proof.get("deep", False)                       # HP7: DEEP-ALI verify path (via shared _deep_replay)
    _deep_q_at = None
    if deep:
        ok, why, _z, _zg, _da, _deep_q_at = _deep_replay(fs, proof, alphas_T, alphas_B, meta, T, oT,
                                                         Hd, Dd, N, last, lay, sv)
        if not ok:
            return False, why

    fs.absorb(b"fri"); betas = []; sizes = []; rmeta = []; size = N; ri = 0
    if step == 1:
        while True:
            fs.absorb(fri_roots[ri]); sizes.append(size); ri += 1
            if size <= 8:
                break
            betas.append(_ext_challenge(fs)); size //= 2
    else:                                                # HP1.9-FOLD8: 1 root/round, s betas/round
        g = 0
        while True:
            fs.absorb(fri_roots[ri]); s = min(step, _fri_folds_to_final(size))
            rmeta.append((s, size, g)); ri += 1                       # (fold count, layer size, global fold-start)
            if s == 0:
                break
            for _ in range(s):
                betas.append(_ext_challenge(fs)); size >>= 1
            g += s
    if len(fri_roots) != ri:                              # HP7.4c: the FS loop absorbs exactly `ri` roots (it stops
        return False, "fri_roots length"                  # on `size`, not on len). Reject extra/short fri_roots so
    if betas != [tuple(b) for b in proof["betas"]]:       # an appended, never-FS-absorbed root cannot become [-1].
        return False, "beta mismatch"
    nonce = bytes.fromhex(proof["nonce"])
    if int.from_bytes(Hf(fs.s + nonce)[:8], "little") >= (1 << (64 - proof["grind_b"])):
        return False, "grind"
    fs.absorb(nonce)
    nq = proof["nq"]
    idxs = [fs.challenge_idx(N) for _ in range(nq)]
    if [q["k"] for q in proof["queries"]] != idxs:
        return False, "idx mismatch"

    final = proof["final"]; shift = N // T; inv2 = inv(2)
    if step == 1 and pairleaf:                            # HP7.4c: bind the clear final layer to its commitment
        _hf = len(final) // 2                             # fri_roots[-1] (== the FS-absorbed final root, guaranteed
        final_tree = merkle([_leaf_ext_pair(final[i], final[i + _hf], b"\x00" * 16) for i in range(_hf)])
    else:                                                 # by the length guard above). The clear proof["final"] was
        final_tree = merkle([_leaf_ext(v, b"\x00" * 16) for v in final])   # never checked to EQUAL it -> unqueried
    if m_root(final_tree) != fri_roots[-1]:               # slots free / per-input divergence. Mirror on-chain in
        return False, "final root"                        # native_ct_shard fri_final_root_bind_prog (HP7.4c).
    for q in proof["queries"]:
        k = q["k"]; x = Dd[k]; kn = (k + shift) % N
        if not m_verify(tp_root, _leaf([q["ck"][c] for c in FLAT_COLS], bytes.fromhex(q["sk"])),
                        k, [(bytes.fromhex(s), b) for s, b in q["pk"]]):
            return False, "col path k"
        if not deep:                                      # deep=False: verify the kn opening + per-query AIR-eval
            if not m_verify(tp_root, _leaf([q["cn"][c] for c in FLAT_COLS], bytes.fromhex(q["sn"])),
                            kn, [(bytes.fromhex(s), b) for s, b in q["pn"]]):
                return False, "col path kn"
            pub_x = _pub_at_idx(sv, k); w_next = sv["range_weight"][kn]
            ZHx_inv = inv(sub(pow(x, T, P), 1))
            comp_x = _compose_at(q["ck"], q["cn"], x, w_next, last, ZHx_inv, Hd, pub_x,
                                 alphas_T, bcons, alphas_B)
        else:                                             # HP7.7/7.8: DEEP -- open comp(x_k) vs comp_root, then the
            cc = tuple(q["cc"])                           # DEEP-quotient q(x_k) replaces the per-query AIR-eval.
            if not m_verify(bytes.fromhex(proof["comp_root"]), _leaf_ext(cc, b"\x00" * 16), k,
                            [(bytes.fromhex(s), b) for s, b in q["cp"]]):
                return False, "comp path k"
            comp_x = _deep_q_at(x, k, q["ck"], cc)
        ci = k
        if step == 1:
            for li, fl in enumerate(q["fri"]):
                half = sizes[li] // 2; ii = ci % half
                fv = tuple(fl["v"]); fw = tuple(fl["w"])
                if pairleaf:                          # HP6.1: ONE Merkle verify of the pair-leaf at index ii
                    if not m_verify(fri_roots[li], _leaf_ext_pair(fv, fw, b"\x00" * 16), ii,
                                    [(bytes.fromhex(s), b) for s, b in fl["p"]]):
                        return False, "fri%d pair" % li
                else:
                    if not m_verify(fri_roots[li], _leaf_ext(fv, b"\x00" * 16), ii,
                                    [(bytes.fromhex(s), b) for s, b in fl["vp"]]):
                        return False, "fri%d v" % li
                    if not m_verify(fri_roots[li], _leaf_ext(fw, b"\x00" * 16), ii + half,
                                    [(bytes.fromhex(s), b) for s, b in fl["wp"]]):
                        return False, "fri%d w" % li
                if li == 0:
                    tgt = fw if k >= half else fv
                    if tgt != comp_x:
                        return False, "comp != fri0"
                xpos = pow(mul(off, pow(oN, ii, P)), 2 ** li, P); beta = betas[li]
                i2x = inv(mul(2, xpos))
                folded = F2.add(F2.scalar(inv2, F2.add(fv, fw)),
                                F2.mul(beta, F2.scalar(i2x, F2.sub(fv, fw))))
                if li + 1 < len(q["fri"]):
                    nh = sizes[li + 1] // 2
                    tgt = tuple(q["fri"][li + 1]["w"]) if (ii >= nh) else tuple(q["fri"][li + 1]["v"])
                    if folded != tgt:
                        return False, "fold L%d" % li
                else:
                    if folded != tuple(final[ii % len(final)]):
                        return False, "fri final"
                ci = ii
        else:                                         # HP1.9-FOLD8: 2^s-coset open + s internal folds/round
            for ridx, fl in enumerate(q["fri"]):
                s, sz, li0 = rmeta[ridx]; stride = sz >> s
                base = fl["base"]; coset = [tuple(v) for v in fl["coset"]]
                if base != ci % stride:
                    return False, "fri%d base" % ridx
                if not m_verify(fri_roots[ridx], _leaf_ext_coset(coset, b"\x00" * 16), base,
                                [(bytes.fromhex(s2), b) for s2, b in fl["p"]]):
                    return False, "fri%d coset" % ridx
                if ridx == 0 and coset[ci // stride] != comp_x:      # comp(x_k) == the packed element at k
                    return False, "comp != fri0"
                folded = _coset_fold(coset, base, li0, s, betas[li0:li0 + s], off, oN, N, inv2)
                ci = base
                if ridx + 1 < len(q["fri"]):
                    ns, nsz, nli0 = rmeta[ridx + 1]; nstride = nsz >> ns
                    ncoset = [tuple(v) for v in q["fri"][ridx + 1]["coset"]]
                    if folded != ncoset[ci // nstride]:
                        return False, "fold round %d" % ridx
                else:
                    if folded != tuple(final[ci % len(final)]):
                        return False, "fri final"
    return True, "ok"


def query_terms(proof):
    """Decompose each query's composition into the exact terms the on-chain shard (HP2.5)
    accumulates, so the BCH-VM composition can be tested against verify()'s comp_x:
      comp = qf_trans * sum_j(trans_v_j * alpha_j) + sum_b(bound_v_b * invX_b * alpha_b)
    where qf_trans = (x-last)*Z_H(x)^-1 is shared by all transition residuals. Replays the
    verify Fiat-Shamir to recover the alphas; returns one dict per query."""
    stmt = proof["stmt"]; D = stmt["depth"]
    meta, T = ct_build_layout(D)
    N, oT, oN, off, Hd, Dd, last = _setup(T, proof["blowup"])
    lay = ct_public_layout(meta, T)
    sv = _selector_vectors(lay, T, N, oT, oN, off)
    fs = FS(); fs.absorb(bytes.fromhex(proof["tp_root"]))
    fs.absorb_int(stmt["root"]); fs.absorb_int(stmt["nf"])
    for cm in stmt["cm_out"]:
        fs.absorb_int(cm)
    bcons = ct_boundary_constraints(meta, stmt)
    alphas_T = [_ext_challenge(fs) for _ in range(ct_num_transition_residuals())]
    alphas_B = [_ext_challenge(fs) for _ in range(len(bcons))]
    shift = N // T
    deep = proof.get("deep", False)                       # HP8.1: DEEP -- the per-query AIR decomposition is obsolete
    if deep:                                              # (no per-query mapped-core); the shard binds q(x_k) to the
        ok, why, _z, _zg, _da, _q_at = _deep_replay(     # FRI-layer-0 + comp(x_k) to comp_root instead. SAME q(x_k)
            fs, proof, alphas_T, alphas_B, meta, T, oT, Hd, Dd, N, last, lay, sv)   # as verify (single source).
        if not ok:
            raise ValueError("query_terms: DEEP replay failed: %s" % why)
    out = []
    for q in proof["queries"]:
        k = q["k"]; x = Dd[k]
        if deep:
            cc = tuple(q["cc"])
            out.append({"k": k, "comp_x": _q_at(x, k, q["ck"], cc),
                        "ck": q["ck"], "cc": cc, "cp": q["cp"]})
            continue
        kn = (k + shift) % N
        cur = q["ck"]; nxt = q["cn"]
        pub_x = _pub_at_idx(sv, k); w_next = sv["range_weight"][kn]
        ZHx_inv = inv(sub(pow(x, T, P), 1))
        terms = {"trans_v": ct_transition_residuals(cur, nxt, pub_x, w_next),
                 "trans_a": alphas_T,
                 "qf_trans": mul(sub(x, last), ZHx_inv),
                 "bound_v": [fn(cur) for _r, fn in bcons],
                 "bound_invX": [inv(sub(x, Hd[row])) for row, _f in bcons],
                 "bound_a": alphas_B,
                 "comp_x": _compose_at(cur, nxt, x, w_next, last, ZHx_inv, Hd, pub_x,
                                       alphas_T, bcons, alphas_B)}
        out.append(terms)
    return out


def query_fri_terms(proof):
    """Per-query FRI fold-chain data for the on-chain test (HP3.5b/3.5c): for each layer
    the openings (v/w + Merkle paths), the verifier-derived fold index ii, the fold point
    xpos=(off*oN^ii)^(2^li), beta, the fold target (next layer's v/w, or the final layer),
    and the layer-0 composition target. Replays the verify Fiat-Shamir for the betas;
    comp_x comes from query_terms."""
    stmt = proof["stmt"]; D = stmt["depth"]
    meta, T = ct_build_layout(D)
    N, oT, oN, off, Hd, Dd, last = _setup(T, proof["blowup"])
    fs = FS(); fs.absorb(bytes.fromhex(proof["tp_root"]))
    fs.absorb_int(stmt["root"]); fs.absorb_int(stmt["nf"])
    for cm in stmt["cm_out"]:
        fs.absorb_int(cm)
    bcons = ct_boundary_constraints(meta, stmt)
    [_ext_challenge(fs) for _ in range(ct_num_transition_residuals())]
    [_ext_challenge(fs) for _ in range(len(bcons))]
    fs.absorb(b"fri"); betas = []; sizes = []; size = N; ri = 0
    froots = proof["fri_roots"]
    while True:
        fs.absorb(bytes.fromhex(froots[ri])); sizes.append(size); ri += 1
        if size <= 8:
            break
        betas.append(_ext_challenge(fs)); size //= 2
    final = proof["final"]
    qt = query_terms(proof)
    out = []
    for qi, q in enumerate(proof["queries"]):
        k = q["k"]; layers = []; ci = k
        for li, fl in enumerate(q["fri"]):
            half = sizes[li] // 2; ii = ci % half
            xpos = pow(mul(off, pow(oN, ii, P)), 2 ** li, P)
            if li + 1 < len(q["fri"]):
                nh = sizes[li + 1] // 2
                ft = tuple(q["fri"][li + 1]["w"]) if ii >= nh else tuple(q["fri"][li + 1]["v"])
            else:
                ft = tuple(final[ii % len(final)])
            ct = (tuple(fl["w"]) if k >= half else tuple(fl["v"])) if li == 0 else None
            _lay = {"v": tuple(fl["v"]), "w": tuple(fl["w"]), "ii": ii, "half": half, "xpos": xpos,
                    "beta": betas[li], "fold_tgt": ft, "comp_tgt": ct, "root": froots[li]}
            if proof.get("pairleaf"):
                _lay["p"] = fl["p"]                # HP6.1: the ONE pair-leaf path (v@ii + w@ii+half together)
            else:
                _lay["vp"] = fl["vp"]; _lay["wp"] = fl["wp"]
            layers.append(_lay)
            ci = ii
        out.append({"k": k, "comp_x": qt[qi]["comp_x"], "layers": layers})
    return out


def query_fri_terms_fold8(proof):
    """HP1.9-FOLD8: per-query per-round FRI data for the on-chain shard (ethSTARK 3.11.1 layer-skipping)
    -- the coset (2^s opened values), the base leaf index + Merkle path + round root, the s FS betas,
    the 2^s-1 inverse HINTS i2x=inv(2*xpos) per butterfly (checked i2x*twox==1 on-chain, fail-closed),
    the carried index ci and its coset position ci//stride, and the fold target (the next round's coset
    element, or the final layer). Mirrors exactly what fri_coset_bind_prog + fri_coset_open_fold_prog +
    fri_final_bind_prog consume. fold-8 proofs only (the fold-2 query_fri_terms handles fold_step=1)."""
    if proof.get("fold_step", 1) == 1:
        raise ValueError("query_fri_terms_fold8 requires a fold-8 proof (use query_fri_terms for fold-2)")
    stmt = proof["stmt"]; D = stmt["depth"]; step = proof["fold_step"]
    meta, T = ct_build_layout(D)
    N, oT, oN, off, Hd, Dd, last = _setup(T, proof["blowup"])
    betas = [tuple(b) for b in proof["betas"]]
    rounds = []; size = N; g = 0                                # committed rounds (global fold-start, s, size)
    while True:
        s = min(step, _fri_folds_to_final(size))
        rounds.append((g, s, size))
        if s == 0:
            break
        g += s; size >>= s
    qt = query_terms(proof); final = proof["final"]; out = []
    for qi, q in enumerate(proof["queries"]):
        k = q["k"]; ci = k; rnds = []
        for ridx, fl in enumerate(q["fri"]):
            li0, s, _size = rounds[ridx]
            base = fl["base"]; coset = [tuple(v) for v in fl["coset"]]
            stride = (N >> li0) >> s
            i2x = []; cnt = 1 << s                              # per-butterfly inverse hints (processing order)
            for f in range(s):
                h = cnt // 2
                for m in range(h):
                    twox = (2 * pow(mul(off, pow(oN, base + m * stride, P)), 1 << (li0 + f), P)) % P
                    i2x.append(inv(twox))
                cnt = h
            ci_next = base
            if ridx + 1 < len(q["fri"]):
                nli0, ns, _ns = rounds[ridx + 1]; nstride = (N >> nli0) >> ns
                fold_tgt = tuple(q["fri"][ridx + 1]["coset"][ci_next // nstride])
            else:
                fold_tgt = tuple(final[ci_next % len(final)])
            rnds.append({"base": base, "coset": coset, "path": fl["p"], "root": proof["fri_roots"][ridx],
                         "s": s, "li0": li0, "stride": stride, "betas": betas[li0:li0 + s], "i2x": i2x,
                         "ci": ci, "comp_pos": ci // stride, "fold_tgt": fold_tgt})
            ci = ci_next
        out.append({"k": k, "comp_x": qt[qi]["comp_x"], "rounds": rnds})
    return out


def export_witness(proof, path=None):
    """HP1.7: serialize a proof to a JSON-ready dict for the on-chain shard + harness.
    Public inputs (statement, roots) + per-query openings (k/kn columns, salts, Merkle
    paths) + FRI layer openings are already in `proof`; GF(p^2) values serialize as
    [a0,a1]. Adds the per-query INVERSE HINTS (Z_H(x)^-1, (x-H[row])^-1 per boundary,
    (2*xpos)^-1 per FRI layer) + 2^-1: a hint-based BCH-VM verifier replaces each modular
    inverse with one multiplication check (hint * value == 1). Deterministic from proof.
    Returns (dict, json_blob); writes the blob to `path` when given."""
    import json
    stmt = proof["stmt"]; D = stmt["depth"]
    meta, T = ct_build_layout(D)
    N, oT, oN, off, Hd, Dd, last = _setup(T, proof["blowup"])
    brows = [row for row, _ in ct_boundary_constraints(meta, stmt)]
    sizes = []; size = N
    while True:
        sizes.append(size)
        if size <= 8:
            break
        size //= 2
    deep = proof.get("deep", False)                              # HP6: DEEP -> GF(p^2) inverse hints
    if deep:
        z = tuple(proof["z"]); zg = tuple(proof["zg"])

    def _base_comp_hints(x):                                     # deep=False: per-query base composition inverses
        return {"zh_inv": inv(sub(pow(x, T, P), 1)),
                "bnd_inv": [inv(sub(x, Hd[row])) for row in brows]}

    def _deep_div_hints(x):                                      # HP6.1: DEEP GF(p^2) division inverses per query
        return {"deep_inv_z": F2.inv(F2.sub(F2.from_base(x), z)),
                "deep_inv_zg": F2.inv(F2.sub(F2.from_base(x), zg))}
    hints = []
    if proof.get("fold_step", 1) == 1:
        for q in proof["queries"]:
            k = q["k"]; x = Dd[k]
            h = (_deep_div_hints(x) if deep else _base_comp_hints(x))
            h["fri_xpos2_inv"] = []
            ci = k
            for li in range(len(q["fri"])):
                half = sizes[li] // 2; ii = ci % half
                xpos = pow(mul(off, pow(oN, ii, P)), 2 ** li, P)
                h["fri_xpos2_inv"].append(inv(mul(2, xpos)))
                ci = ii
            hints.append(h)
    else:                                                        # HP1.9-FOLD8: per-ROUND coset i2x hints
        qft = query_fri_terms_fold8(proof)                       # 2^s-1 hints per committed round
        for q, e in zip(proof["queries"], qft):
            x = Dd[q["k"]]
            h = (_deep_div_hints(x) if deep else _base_comp_hints(x))
            h["fri_coset_i2x"] = [r["i2x"] for r in e["rounds"]]
            hints.append(h)
    out = dict(proof)
    out["inverse_hints"] = hints
    out["inv2"] = inv(2)
    out["boundary_rows"] = brows
    out["T"] = T
    out["N"] = N
    if deep:                                                     # HP6.2: the once-at-z GF(p^2) inverse hints
        out["deep_zh_inv"] = F2.inv(F2.sub(F2.power(z, T), F2.ONE))
        out["deep_bnd_inv"] = [F2.inv(F2.sub(z, F2.from_base(Hd[row]))) for row in brows]
    blob = json.dumps(out)
    if path is not None:
        with open(path, "w") as f:
            f.write(blob)
    return out, blob


def self_test():
    w = _demo_witness(depth=2)
    proof = prove(w)
    ok, why = verify(proof)
    assert ok, "valid proof rejected: %s" % why

    # tamper: wrong public nullifier in the statement -> rejected
    import copy
    bad = copy.deepcopy(proof); bad["stmt"]["nf"] = (bad["stmt"]["nf"] + 1) % P
    ok, why = verify(bad)
    assert not ok, "tampered statement (nf) accepted"
    # tamper: flip one opened trace column value -> Merkle path / composition rejects
    bad = copy.deepcopy(proof)
    bad["queries"][0]["ck"]["s0"] = (bad["queries"][0]["ck"]["s0"] + 1) % P
    ok, why = verify(bad)
    assert not ok, "tampered trace opening accepted"
    # tamper: corrupt a committed FRI value -> rejected
    bad = copy.deepcopy(proof)
    v0 = bad["queries"][0]["fri"][0]["v"]
    bad["queries"][0]["fri"][0]["v"] = ((v0[0] + 1) % P, v0[1])
    ok, why = verify(bad)
    assert not ok, "tampered FRI value accepted"
    # tamper: wrong grind nonce -> rejected. Flip a bit of the REAL nonce (guaranteed != the
    # honest one) so the tamper is never a no-op -- a fixed constant like 00*8 can coincide with
    # the honest nonce (grind counts from 0) ~1/2^grind_b of the time, making the assert flaky.
    bad = copy.deepcopy(proof)
    _bn = bytearray(bytes.fromhex(proof["nonce"])); _bn[0] ^= 1
    bad["nonce"] = bytes(_bn).hex()
    ok, why = verify(bad)
    assert not ok, "tampered grind nonce accepted"

    # HP1.9-FOLD8: layer-skipping FRI (ethSTARK 3.11.1) verifies, commits FEWER Merkle roots than
    # fold-2 at the same soundness (the <100KB byte win), and rejects coset/beta/final tampering.
    p8 = prove(w, fold_step=3)
    ok8, why8 = verify(p8)
    assert ok8, "fold-8 proof rejected: %s" % why8
    assert len(p8["fri_roots"]) < len(proof["fri_roots"]), \
        "fold-8 did not reduce FRI roots (%d vs %d)" % (len(p8["fri_roots"]), len(proof["fri_roots"]))
    bad = copy.deepcopy(p8)                            # tamper one packed coset value -> reject
    c0 = bad["queries"][0]["fri"][0]["coset"][0]
    bad["queries"][0]["fri"][0]["coset"][0] = ((c0[0] + 1) % P, c0[1])
    assert not verify(bad)[0], "tampered fold-8 coset value accepted"
    bad = copy.deepcopy(p8)                            # tamper a fold challenge -> reject
    bad["betas"][0] = ((bad["betas"][0][0] + 1) % P, bad["betas"][0][1])
    assert not verify(bad)[0], "tampered fold-8 beta accepted"
    bad = copy.deepcopy(p8)                            # tamper the final layer -> reject
    bad["final"] = [((v[0] + 1) % P, v[1]) for v in bad["final"]]
    assert not verify(bad)[0], "tampered fold-8 final accepted"

    # an independent valid witness also verifies (not a fluke)
    proof2 = prove(_demo_witness(depth=3, seed=999))
    ok2, why2 = verify(proof2)
    assert ok2, "second valid proof rejected: %s" % why2

    # HP1.9 determinism: a fixed seed yields a byte-identical proof; it still verifies
    import json
    pa = prove(w, seed=2026)
    pb = prove(w, seed=2026)
    assert json.dumps(pa, sort_keys=True) == json.dumps(pb, sort_keys=True), \
        "prove(seed) is not deterministic"
    assert verify(pa)[0], "seeded proof rejected"
    pc = prove(w, seed=777)
    assert json.dumps(pc, sort_keys=True) != json.dumps(pa, sort_keys=True), \
        "different seed produced an identical proof (mask not seeded)"
    assert verify(pc)[0], "second seeded proof rejected"

    # HP1.7 export: the JSON blob round-trips and the reloaded proof verifies
    out, blob = export_witness(pa)
    reloaded = json.loads(blob)
    okr, whyr = verify(reloaded)
    assert okr, "exported/reloaded proof rejected: %s" % whyr

    # HP14: DEEP-ALI path -- a real deep proof verifies, and every DEEP tamper variant is rejected
    # fail-closed (_deep_replay's z / mask / comp(z) / deep_alphas checks + the comp(x_k) opening + the
    # DEEP FRI fold). deep=False stays byte-identical to the non-DEEP path (no regression).
    pd = prove(w, fold_step=3, deep=True, seed=0xD00D)
    okd, whyd = verify(pd)
    assert okd, "deep proof rejected: %s" % whyd                                              # 14.1
    assert pd.get("deep") and "comp_root" in pd, "deep proof missing DEEP fields"
    _fc0 = FLAT_COLS[0]

    def _drej(mut, msg):
        b = copy.deepcopy(pd); mut(b)
        assert not verify(b)[0], msg

    _drej(lambda b: b.__setitem__("z", [(b["z"][0] + 1) % P, b["z"][1]]), "tampered deep z accepted")   # 14.2
    _drej(lambda b: b["Pcz"].__setitem__(_fc0, [(b["Pcz"][_fc0][0] + 1) % P, b["Pcz"][_fc0][1]]),
          "tampered Pc(z) accepted")                                                           # 14.3
    _drej(lambda b: b["Pczg"].__setitem__(_fc0, [(b["Pczg"][_fc0][0] + 1) % P, b["Pczg"][_fc0][1]]),
          "tampered Pc(z*g) accepted")                                                         # 14.4
    _drej(lambda b: b.__setitem__("rw_zg", [(b["rw_zg"][0] + 1) % P, b["rw_zg"][1]]),
          "tampered range_weight(z*g) accepted")                                               # 14.5
    _drej(lambda b: b.__setitem__("comp_z", [(b["comp_z"][0] + 1) % P, b["comp_z"][1]]),
          "tampered comp(z) accepted")                                                          # 14.6
    _drej(lambda b: b["queries"][0].__setitem__(
        "cc", [(b["queries"][0]["cc"][0] + 1) % P, b["queries"][0]["cc"][1]]),
        "tampered comp(x_k) opening accepted")                                                 # 14.7
    _drej(lambda b: b["deep_alphas"].__setitem__(
        0, [(b["deep_alphas"][0][0] + 1) % P, b["deep_alphas"][0][1]]),
        "tampered deep_alpha accepted")                                                        # 14.8a

    def _dfri(b):
        c = b["queries"][0]["fri"][0]["coset"]; c[0] = ((c[0][0] + 1) % P, c[0][1])
    _drej(_dfri, "tampered DEEP FRI coset accepted")                                            # 14.8b
    assert json.dumps(prove(w, seed=4242), sort_keys=True) == \
        json.dumps(prove(w, deep=False, seed=4242), sort_keys=True), \
        "deep=False not byte-identical to default (deep flag perturbed the non-DEEP path)"      # 14.9
    print("  HP14 DEEP-ALI: real deep proof verifies; z / Pc(z) / Pc(z*g) / range_weight(z*g) / comp(z) / "
          "comp(x_k)-opening / deep_alpha / DEEP-FRI tamper all rejected; deep=False byte-identical")

    # inverse hints are valid (hint * value == 1) -> a hint-based shard can skip inverses
    meta, T = ct_build_layout(pa["stmt"]["depth"])
    N, oT, oN, off, Hd, Dd, last = _setup(T, pa["blowup"])
    assert mul(out["inv2"], 2) == 1, "inv2 hint invalid"
    for q, h in zip(pa["queries"], out["inverse_hints"]):
        x = Dd[q["k"]]
        assert mul(h["zh_inv"], sub(pow(x, T, P), 1)) == 1, "zh_inv hint invalid"
        for row, hv in zip(out["boundary_rows"], h["bnd_inv"]):
            assert mul(hv, sub(x, Hd[row])) == 1, "boundary inv hint invalid"
    return True, pa


if __name__ == "__main__":
    ok, proof = self_test()
    print("HP1.6 CT-AIR FRI-STARK prove/verify (GF(p^2) alpha/beta, base S-box/MDS): %s"
          % ("OK" if ok else "FAIL"))
    print("  real proof verifies; statement / trace-opening / FRI-value / grind tamper rejected")
    print("  self-test config: blowup=%d queries=%d grind=%d (deploy pinned: %d/%d/%d)"
          % (TEST_BLOWUP, TEST_QUERIES, TEST_GRIND, CFG_BLOWUP, CFG_QUERIES, CFG_GRIND))
    print("  proof: %d FRI layers, %d queries, depth=%d"
          % (len(proof["fri_roots"]), proof["nq"], proof["stmt"]["depth"]))
    # HP1.7: write the witness/proof data file the harness (HP4) + shard (HP3) consume,
    # at the PINNED >=100-bit config (the native N from HP1.2 the shard derives its depth
    # from), seeded for reproducibility. self_test already round-trip-verified the export.
    shard_dir = os.path.join(_PKG, "cashscript", "native_shard")
    os.makedirs(shard_dir, exist_ok=True)
    wpath = os.path.join(shard_dir, "witness_inputs.json")
    # HP11 deploy-fold-8: the pinned config is FOLD=8 (2^3-coset layer-skip = the <100KB whole-tx path,
    # the fri_looped/L1 shard verifier); deploy_proof MUST be fold-8, not the fold-2 default. fold_step is
    # config-driven (Data/Logic separation, RULES Prinzip 6): FOLD=8 -> fold_step = log2(8) = 3.
    _fold_step = CFG_FOLD.bit_length() - 1
    assert (1 << _fold_step) == CFG_FOLD, "config FOLD=%d must be a power of two for the 2^s-coset fold" % CFG_FOLD
    deploy_proof = prove(_demo_witness(depth=2), blowup=CFG_BLOWUP, grind_b=CFG_GRIND,
                         n_queries=CFG_QUERIES, seed=2026, fold_step=_fold_step)
    okd, whyd = verify(deploy_proof)
    out, blob = export_witness(deploy_proof, wpath)
    print("HP1.9 determinism (seeded prove reproducible) + HP1.7 witness export: OK")
    print("  pinned config blowup=%d q=%d grind=%d -> verify=%s" % (CFG_BLOWUP, CFG_QUERIES, CFG_GRIND, okd))
    print("  %s" % wpath)
    print("  %d bytes JSON, %d queries, %d inverse-hint sets (hint*value==1 -> shard skips inverses)"
          % (len(blob), out["nq"], len(out["inverse_hints"])))
