"""
cost_report_native.py -- FULL on-chain hash-STARK verifier op-cost for the
NATIVE CT-AIR (Poseidon2/Goldilocks, EC-FREE, hash-note model).

WHY THIS FILE EXISTS (HP3 + HP4-core of PATHC_PHASE0_HASHSTARK_FEASIBILITY):
  cost_report_full.py measures the full verifier but with the membership_stark AIR
  as a PROXY (8 generic constraints, NAIVE O(T) Horner selectors, fixed Merkle
  depth 18). The CT-AIR (HP2-ERGEBNIS) is now DEFINED: Goldilocks-native, no EC,
  trace driven by Poseidon2 permutations (t=12, x^7, R_F=8 + R_P=22 = 30 rounds).
  This file MEASURES the NATIVE verifier cost on the cashvm VM with:
    * the CORRECT Merkle depth of the native trace (NOT 18), per config,
    * FRI folds + xpos-modexp exactly as HP1 (reused from cost_report_full),
    * AIR-EVAL = Poseidon2 round constraints (x^7 S-box checks + linear layer),
      NOT the membership 8-constraints,
    * SELECTOR-EVAL CLOSED-FORM (Z_H(x)=x^n-1 via fast-exp + periodic round
      selectors x^(n/period)), NOT naive-Horner (HP1.3 / HP1 PFLICHT),
    * FS + selector-hash reused from cost_report_full.
  Every component is RUN through the real VM (vm.op_cost / vm.hash_iters). Numbers
  hand-derived appear only as comments / cross-checks. NO mock / placeholder.

DESIGN (RULES.md / senior-software-engineer / Karpathy / simplify):
  Minimally invasive: imports & REUSES from cost_report_full and the structures_*:
    measure_one_query (Merkle openings, any depth)        [cost_report]
    witness_fold / MULMOD / MM / ADDMOD / AM / SUBMOD / SM [structures_fri]
    _modexp_prog (square-and-multiply via MULMOD)          [cost_report_full]
    measure_fs_recompute / measure_selector_hash          [cost_report_full]
    max_op_cost / max_std_iters / max_cons_iters           [cost_report]
  NO duplicated VM op-cost logic. The only NEW VM program here is the Poseidon2
  round-constraint evaluation (the native AIR) and the closed-form selector eval.

NATIVE AIR (HP2-ERGEBNIS, GOLDILOCKS_NATIVE_HASH.md, PRIMARY: ePrint 2023/323 /
Plonky3 goldilocks/poseidon2.rs):
  Poseidon2 over Goldilocks p=2^64-2^32+1, state t=12, S-box x^7 (smallest valid;
  gcd(7,p-1)=1), R_F=8 (4+4 full), R_P=22 partial -> 30 rounds/perm.
  S-box count/perm = 8*12 + 22*1 = 118 x^7 evals (cross-check).
  LAYOUT = round-per-row (1 round = 1 trace row, t=12 state cells + aux per row).
    This is the AIR-trace-row convention (1 round per row = 30 rows per
    permutation); cross-checked against the working membership STARK which uses
    the identical 1-round-per-row idea (R_ROUNDS rounds -> R_ROUNDS rows + struct
    rows). [Plonky3's *single-row* Poseidon2 AIR (all 30 rounds in one ~600-col
    row) is the alternative; round-per-row keeps width small and matches the PoC's
    Merkle-leaf-per-row commitment, so we use+measure it and flag the alternative.]

PERMS PER TRANSFER (1-in / 2-out, hash-note model, HP2-ERGEBNIS 2a-2f):
  cm    = Poseidon2(value,owner_pk,rho,blind)   -> 1 perm / output note  (N_OUT)
  nf    = Poseidon2(sk,rho,DOMAIN_TAG)          -> 1 perm / input  note  (N_IN)
  owner = Poseidon2(sk) == note.owner_pk        -> 1 perm / input  note  (N_IN)
  memb  = Merkle path depth D (H2=perm/level)   -> D perms / input note  (N_IN*D)
"""
import os, math
from cashvm import P as PUSH, N as NUM, OP, DEFINE, encode_num
from cost_report import measure_one_query, max_std_iters, max_cons_iters, max_op_cost
from structures_fri import (P_GOLD, inv,
                            MULMOD, MULMOD_BODY, ADDMOD, ADDMOD_BODY,
                            SUBMOD, SUBMOD_BODY, MM, AM, SM)
# REUSE the full verifier's already-validated, VM-measured components verbatim:
#   _run, _modexp_prog, measure_one_fold, measure_xpos_modexp_one_layer,
#   measure_fs_recompute, measure_selector_hash  (no duplication of VM logic)
import cost_report_full as FULL
# iii-0b: measure the REAL DEPLOYED structured external MDS (matmul_external_prog) instead of a generic
# 144-mul-add proxy. native_ct_shard lives in apps/ -> add it to the path (code = single source of truth).
import sys as _sys
_sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "apps"))
import native_ct_shard as NCT

P = P_GOLD

# ============================================================================
# NATIVE AIR SHAPE (Poseidon2 / Goldilocks)  -- PRIMARY params
# ============================================================================
T_STATE   = 12                  # state width
R_F       = 8                   # full rounds (4 initial + 4 final)
R_P       = 22                  # partial rounds
ROUNDS    = R_F + R_P           # 30 rounds/perm
ROWS_PER_PERM = ROUNDS          # round-per-row layout -> 30 rows/perm
SBOX_PER_PERM = R_F * T_STATE + R_P * 1   # 118 (cross-check vs KB doc)

# transfer shape
N_IN  = 1
N_OUT = 2

# range / conservation rows
RANGE_ROWS_PER_OUT = 64         # Num2Bits(64): 64 boolean rows / output value
CONS_ROWS          = 4          # additive balance Sum(in)==Sum(out)+fee (few rows)

# FRI / soundness config (= cost_report_full headline; HP6.1 consistency OPEN)
BLOWUP    = 16
Q         = FULL.Q              # 21 queries
FOLD      = FULL.FOLD           # 8
HASH_COST = FULL.HASH_COST      # 192 standard

# selector-coeff blob pinned once (same as full)
SELECTOR_COEFF_BYTES = FULL.SELECTOR_COEFF_BYTES


def _run(prog, hash_cost=HASH_COST):
    return FULL._run(prog, hash_cost)


# ============================================================================
# TRACE SIZE (HP3)
# ============================================================================
def perms_for(D):
    """Poseidon2 perms for 1 transfer with membership depth D (1-in / 2-out)."""
    cm    = N_OUT * 1
    nf    = N_IN  * 1
    owner = N_IN  * 1
    memb  = N_IN  * D
    return dict(cm=cm, nf=nf, owner=owner, memb=memb, total=cm + nf + owner + memb)


def trace_rows(D):
    p = perms_for(D)
    perm_rows  = p["total"] * ROWS_PER_PERM
    range_rows = RANGE_ROWS_PER_OUT * N_OUT
    cons_rows  = CONS_ROWS
    raw = perm_rows + range_rows + cons_rows
    m = math.ceil(math.log2(raw))
    return dict(perms=p, perm_rows=perm_rows, range_rows=range_rows,
                cons_rows=cons_rows, raw=raw, m=m, T=1 << m)


# ============================================================================
# NATIVE AIR-EVAL: Poseidon2 round constraints at the query point
# ----------------------------------------------------------------------------
# The verifier, per committed constraint, evaluates v=fn(cur,nxt,x), forms the
# quotient (transition: v*(x-last)*inv(Z_H); boundary: v*inv(x-H[row])), and
# accumulates acc += alpha*q. (Same composition shape as membership_stark.verify,
# but the CONSTRAINTS are Poseidon2's.)
#
# Poseidon2 constraints expressed as low-degree (<=2) rows. Per STATE LANE we
# constrain the x^7 S-box by AUX cells (deg<=2 each), matching the membership
# pattern (u2=u*u, u4=u2*u2, u6=u4*u2, then x^7=u6*u):
#     c_u2:  u2  - u*u           (u = st + rc)
#     c_u4:  u4  - u2*u2
#     c_u6:  u6  - u4*u2
#     c_st:  st' - (u6*u  applied through the linear layer)
# That is the x^7 S-box in 4 constraints/lane (3 aux + 1 state-update), exactly
# the deg<=2 decomposition the KB doc calls "a few low-degree rows" per x^7.
#
# Per ROW the active lanes differ:
#   * full round:    t=12 lanes get the S-box  -> 12 * 4 = 48 S-box constraints
#   * partial round: 1  lane  gets the S-box   -> 1  * 4 =  4 S-box constraints
# PLUS the LINEAR LAYER (external MDS for full rounds / internal diagonal for
# partial) folded into the state-update constraint: t state-update relations/row,
# each a linear combination of t terms. We charge the linear layer as t
# multiply-adds/lane on full rounds (MDS) and t adds + 1 mul/lane on partial
# (diagonal+sum). Boundary: input/output state binding (t cells in, t out).
#
# IMPORTANT (succinctness): the verifier evaluates ONE composed constraint per
# committed constraint AT THE QUERY POINT x -- it does NOT replay all T rows. The
# number of constraints the verifier evaluates per query is the AIR's constraint
# COUNT (a fixed, trace-INDEPENDENT number), NOT T. We therefore measure the
# per-query AIR-eval as: (worst-case active-row constraint set) once per query.
# We use the FULL-round constraint set (heaviest: 12 lanes) as the per-query
# representative -- a conservative upper bound -- plus the boundary bindings.
# ============================================================================
# constraint counts the verifier composes per query (deg<=2 building blocks)
SBOX_CONSTR_PER_LANE = 4                       # u2,u4,u6,st'  (x^7 decomposition)
FULL_ROUND_LANES     = T_STATE                 # 12
N_SBOX_CONSTR_FULL   = FULL_ROUND_LANES * SBOX_CONSTR_PER_LANE   # 48
# linear layer (external MDS): measured as the DEPLOYED structured matmul_external (iii-0b), not a count here
# boundary: bind input state (t) + output state (t)
N_BOUNDARY_CONSTR    = 2 * T_STATE             # 24


def _native_air_eval_prog():
    """Build a REAL VM program that evaluates the Poseidon2 per-query AIR
    composition (heaviest full-round constraint set + linear layer + boundary).
    Reuses MULMOD/ADDMOD/SUBMOD; inverses are HINT-validated (1 MULMOD check),
    consistent with the FRI-fold inverse pattern in structures_fri."""
    p = P
    prog  = [PUSH(encode_num(p)), OP("TOALT")]
    for fid, body in [(MULMOD, MULMOD_BODY), (ADDMOD, ADDMOD_BODY), (SUBMOD, SUBMOD_BODY)]:
        prog += [PUSH(fid), DEFINE(body)]

    x_val    = 0x1357924680abcdef % p
    last_val = 0x2468ace013579bdf % p
    zhx_inv  = inv(0x777 % p, p)
    zhx_den  = 0x777 % p
    alpha    = 0xabcdef % p
    prog += [NUM(0)]                                  # [acc]

    def hint_inv_check(inv_val, denom_val):
        return [NUM(inv_val % p), NUM(denom_val % p)] + MM() + [NUM(1), OP("NUMEQUALVERIFY")]

    # one S-box lane: u=st+rc ; u2=u*u ; u4=u2*u2 ; u6=u4*u2 ; y=u6*u ; 4 deg-2
    # constraint residuals v_i, each accumulated as transition quotient.
    st0 = 0x0a0b0c0d % p; rc0 = 0x1e1f2021 % p
    def eval_sbox_lane():
        seq = []
        # u = st + rc
        seq += [NUM(st0), NUM(rc0)] + AM()                       # [u]
        seq += [OP("DUP")]                                        # [u,u]
        seq += MM()                                               # u2=u*u   [u2]   (consumes the two u)
        # we now need u2 for u4 and u6, and u for final y; re-materialize operands
        # (values do not change op-cost structure: every MULMOD is full-width)
        # --- emit the 4 constraint residuals as transition quotients ---
        for _ in range(SBOX_CONSTR_PER_LANE):
            # v = (a*b) - c   :  one MUL, one SUB  (deg-2 residual)
            seq += [NUM(0x11111111 % p), NUM(0x22222222 % p)] + MM()
            seq += [NUM(0x33333333 % p)] + SM()                   # v
            # quotient = v*(x-last)*inv(ZHx)  + hint check
            seq += hint_inv_check(zhx_inv, zhx_den)
            seq += [NUM(x_val), NUM(last_val)] + SM()             # (x-last)
            seq += MM()                                            # v*(x-last)
            seq += [NUM(zhx_inv)] + MM()                           # *inv(ZHx)
            seq += [NUM(alpha)] + MM() + AM()                      # acc += alpha*q
        # drop the leftover u2 scratch
        seq += [OP("DROP")]
        return seq

    # linear layer (external MDS): iii-0b -- the DEPLOYED structured matmul_external_prog (Poseidon2 M4-block,
    # ADDMOD + x2/x4-as-adds, ZERO general MULMOD) is measured separately in measure_config via the real
    # NCT.run_matmul_external (code = truth), NOT modelled here as a generic 144 mul-add proxy.

    # boundary constraint: v = st - bnd ; q = v*inv(x-H[row]) ; acc += alpha*q
    bnd_inv = inv(0x999 % p, p); bnd_den = 0x999 % p
    def eval_boundary():
        seq  = [NUM(0x0a0b0c0d % p), NUM(0x55555555 % p)] + SM()       # v
        seq += hint_inv_check(bnd_inv, bnd_den)
        seq += [NUM(bnd_inv)] + MM()
        seq += [NUM(alpha)] + MM() + AM()
        return seq

    # per-query worst case = full round (12 lanes) S-box + linear layer + boundary
    for _ in range(FULL_ROUND_LANES):
        prog += eval_sbox_lane()
    # external MDS added separately in measure_config (deployed matmul_external, iii-0b) -- see note above
    for _ in range(N_BOUNDARY_CONSTR):
        prog += eval_boundary()
    return prog


def measure_native_air_eval():
    return _run(_native_air_eval_prog())


# ============================================================================
# CLOSED-FORM SELECTOR EVAL (HP1.3 / HP1 PFLICHT) -- O(log T), NOT naive Horner
# ----------------------------------------------------------------------------
# A succinct verifier evaluates the public selector / vanishing polynomials in
# CLOSED FORM at the query x (Plonky3 / Winterfell / ethSTARK / Ben-Sasson 2018):
#   * vanishing      Z_H(x) = x^n - 1            -> 1 modexp over an n-bit exponent
#   * periodic round selectors: a round-r selector that is 1 every `period` rows
#     is a coset indicator, evaluable as x^(n/period) compared to a constant
#     -> 1 modexp over a (n/period)-bit exponent per distinct period.
# We MEASURE: Z_H via _modexp_prog (reused), plus one periodic-selector modexp per
# distinct round phase. NO O(T) Horner. This REPLACES cost_report_full's (4b).
# ============================================================================
# distinct periodic selectors the Poseidon2 AIR needs: full-round phase, partial-
# round phase, leaf/level/null/pad structural selectors, range selector, cons
# selector. Conservatively 8 distinct periodic indicators.
N_PERIODIC_SELECTORS = 8


def measure_closed_form_selectors(n_domain):
    """Z_H(x)=x^n-1 (1 modexp, n-bit exp) + N_PERIODIC_SELECTORS coset indicators
    (1 modexp each). All via the REAL VM square-and-multiply (_modexp_prog)."""
    p = P
    base = (p - 7777777) % p
    oc = 0; it = 0
    # Z_H(x) = x^n - 1 : modexp x^n (defines MULMOD only) ...
    o, i = _run(FULL._modexp_prog(base, n_domain, p)); oc += o; it += i
    # ... then the trailing "- 1": one SUBMOD on full-width operands (its own
    # tiny program that defines SUBMOD, so it is REALLY executed on the VM).
    progSub = [PUSH(encode_num(p)), OP("TOALT"), PUSH(SUBMOD), DEFINE(SUBMOD_BODY)]
    progSub += [NUM((p - 3) % p), NUM(1)] + SM()
    o, i = _run(progSub); oc += o; it += i
    # periodic selectors: x^(n/period). Worst-case exponent ~ n (period small);
    # use n-bit exponent as a conservative upper bound for each.
    for _ in range(N_PERIODIC_SELECTORS):
        o, i = _run(FULL._modexp_prog(base, n_domain, p))
        oc += o; it += i
    return oc, it


# ============================================================================
# DRIVER
# ============================================================================
def measure_config(D):
    """Measure the FULL native verifier op-cost for membership depth D."""
    tr = trace_rows(D)
    T = tr["T"]
    N_DOMAIN = T * BLOWUP
    LOGN = int(round(math.log2(N_DOMAIN)))   # Merkle depth of the NATIVE trace
    FRI_DEPTHS = list(range(LOGN, 2, -3))     # [LOGN, LOGN-3, ...] down to >2
    FRI_FOLDS  = len(FRI_DEPTHS) - 1

    # ---- (0a) trace open #1 + (1) trace open #2 (next-row kn) ----
    it_t1, oc_t1 = measure_one_query(LOGN)
    it_t2, oc_t2 = measure_one_query(LOGN)     # 2nd opening, same depth

    # ---- (0b) FRI-layer opens ----
    oc_friopen = 0; it_friopen = 0
    for d in FRI_DEPTHS:
        it_d, oc_d = measure_one_query(max(d, 1))
        oc_friopen += oc_d; it_friopen += it_d

    # ---- (2) FRI folds (reused measured single fold * folds) ----
    oc_fold1, it_fold1 = FULL.measure_one_fold()
    oc_folds = oc_fold1 * FRI_FOLDS
    it_folds = it_fold1 * FRI_FOLDS

    # ---- (3) xpos modexp per fold-layer (reused; exponent uses THIS N) ----
    # measure_xpos_modexp_one_layer uses FULL.N_DOMAIN for the exponent width; we
    # rebuild it here against the native N so the modexp bit-width is correct.
    oc_xpos = 0; it_xpos = 0
    for li in range(FRI_FOLDS):
        # Part A: omegaN^i over an (LOGN)-bit exponent (worst-case i ~ N)
        oA, iA = _run(FULL._modexp_prog((P - 7777777) % P, N_DOMAIN - 1, P))
        # Part B: ()^(2^li) = li squarings (reuse helper's squaring program)
        base = 0x1122334455667788 % P
        progB = [PUSH(encode_num(P)), OP("TOALT")]
        progB += [PUSH(MULMOD), DEFINE(MULMOD_BODY)]
        progB += [NUM(base)]
        for _ in range(li):
            progB += [OP("DUP")] + [NUM(1), OP("PICK")] + MM() + [OP("NIP")]
        oB, iB = _run(progB)
        oc_xpos += oA + oB; it_xpos += iA + iB

    # ---- (4) NATIVE AIR eval (Poseidon2 constraints) ----
    oc_air, it_air = measure_native_air_eval()          # x^7 S-box lanes + boundary bindings
    # (4-MDS) external MDS = the DEPLOYED structured matmul_external (all WIDTH ef at once, M4-block
    # ADDMOD-only, ZERO general MULMOD) measured on the real VM (iii-0b) -- replaces the old generic
    # 144 mul-add proxy so oc_q reflects the on-chain code, not a stale UPPER bound.
    oc_mds = NCT.run_matmul_external([7 * _k + 3 for _k in range(NCT.WIDTH)])[1]
    oc_air += oc_mds

    # ---- (4b) CLOSED-FORM selectors (replaces naive Horner) ----
    oc_sel_eval, it_sel_eval = measure_closed_form_selectors(N_DOMAIN)

    # ---- per-query roll-up ----
    oc_q = oc_t1 + oc_t2 + oc_friopen + oc_folds + oc_xpos + oc_air + oc_sel_eval
    it_q = it_t1 + it_t2 + it_friopen + it_folds + it_xpos + it_air + it_sel_eval

    # ---- once-per-proof (reused, measured on VM) ----
    oc_fs, it_fs = FULL.measure_fs_recompute()
    oc_selhash, it_selhash = FULL.measure_selector_hash()

    oc_total = Q * oc_q + oc_fs + oc_selhash
    it_total = Q * it_q + it_fs + it_selhash

    return dict(
        D=D, tr=tr, T=T, N_DOMAIN=N_DOMAIN, LOGN=LOGN,
        FRI_DEPTHS=FRI_DEPTHS, FRI_FOLDS=FRI_FOLDS,
        oc_t1=oc_t1, oc_t2=oc_t2, oc_friopen=oc_friopen, oc_folds=oc_folds,
        oc_fold1=oc_fold1, oc_xpos=oc_xpos, oc_air=oc_air, oc_mds=oc_mds, oc_sel_eval=oc_sel_eval,
        oc_q=oc_q, it_q=it_q, oc_fs=oc_fs, oc_selhash=oc_selhash,
        oc_total=oc_total, it_total=it_total,
    )


def main():
    print("=" * 80)
    print("NATIVE CT-AIR hash-STARK on-chain verifier cost (HP3 trace + HP4-core)")
    print("Poseidon2/Goldilocks t=12, x^7, R_F=8 + R_P=22 = 30 rounds (round-per-row)")
    print("=" * 80)
    print(f"S-box/perm cross-check = {SBOX_PER_PERM} (KB GOLDILOCKS_NATIVE_HASH.md: 118)")
    print(f"rows/perm = {ROWS_PER_PERM} (round-per-row)   transfer = {N_IN}-in / {N_OUT}-out")
    print(f"FRI: blowup={BLOWUP}  queries q={Q}  fold={FOLD}  hash_cost={HASH_COST}")
    print(f"AIR-eval = Poseidon2 round constraints (x^7 4-constr/lane + structured M4-block external MDS "
          f"[deployed matmul_external, iii-0b] + {N_BOUNDARY_CONSTR} boundary); selectors = CLOSED-FORM O(log T) [HP1 PFLICHT]")
    print()

    # ---------- AUFGABE 1: TRACE TABLE ----------
    print("-" * 80)
    print("AUFGABE 1 -- NATIVE TRACE SIZE per config:")
    print(f"{'D':>3} | {'cm':>2} {'nf':>2} {'own':>3} {'memb':>4} {'perms':>5} | "
          f"{'permR':>6} {'rngR':>4} {'consR':>5} {'rawRows':>7} | {'2^m':>5} {'T':>6}")
    configs = {}
    for D in (20, 26, 32):
        c = measure_config(D)
        configs[D] = c
        tr = c["tr"]; p = tr["perms"]
        print(f"{D:>3} | {p['cm']:>2} {p['nf']:>2} {p['owner']:>3} {p['memb']:>4} "
              f"{p['total']:>5} | {tr['perm_rows']:>6} {tr['range_rows']:>4} "
              f"{tr['cons_rows']:>5} {tr['raw']:>7} | 2^{tr['m']:<3} {tr['T']:>6}")
    print()

    # ---------- AUFGABE 2: NATIVE VERIFIER COST per config ----------
    print("-" * 80)
    print("AUFGABE 2 -- NATIVE FULL-VERIFIER COST per config (all VM-measured):")
    print()
    BUDGET_OP_10K   = max_op_cost(10000)        # 8,032,800 op / input (10KB unlock)
    BUDGET_STD_10K  = max_std_iters(10000)
    BUDGET_CONS_10K = max_cons_iters(10000)
    print(f"per-input budget (10KB non-std unlock): op_cost={BUDGET_OP_10K:,}  "
          f"std_iters={BUDGET_STD_10K:,}  cons_iters={BUDGET_CONS_10K:,}")
    print()

    for D in (20, 26, 32):
        c = configs[D]
        print(f"### CONFIG D={D}  (membership tree depth {D})")
        print(f"  trace T = 2^{c['tr']['m']} = {c['T']:,}   "
              f"FRI domain N = T*{BLOWUP} = 2^{c['LOGN']} = {c['N_DOMAIN']:,}   "
              f"Merkle depth = {c['LOGN']}")
        print(f"  FRI layers depths {c['FRI_DEPTHS']} -> {c['FRI_FOLDS']} folds/query")
        print("  PER-COMPONENT (op_cost):")
        print(f"    (0a) trace open #1                = {c['oc_t1']:>12,}  /query")
        print(f"    (1)  trace open #2 (next-row kn)  = {c['oc_t2']:>12,}  /query")
        print(f"    (0b) FRI-layer opens             = {c['oc_friopen']:>12,}  /query")
        print(f"    (2)  FRI folds (x{c['FRI_FOLDS']})            = {c['oc_folds']:>12,}  /query"
              f"  (1 fold={c['oc_fold1']:,})")
        print(f"    (3)  xpos modexp (x{c['FRI_FOLDS']} layers)   = {c['oc_xpos']:>12,}  /query")
        print(f"    (4)  NATIVE Poseidon2 AIR-eval   = {c['oc_air']:>12,}  /query"
              f"  (incl. structured MDS {c['oc_mds']:,})")
        print(f"    (4b) CLOSED-FORM selectors       = {c['oc_sel_eval']:>12,}  /query")
        print("    ----------------------------------------------------------")
        print(f"    PER-QUERY op_cost                = {c['oc_q']:>12,}")
        print(f"    PER-QUERY hash_iters             = {c['it_q']:>12,}")
        print(f"  ONCE/PROOF: FS={c['oc_fs']:,}op  selector-hash={c['oc_selhash']:,}op")
        print(f"  >> FULL VERIFIER TOTAL  op_cost   = {c['oc_total']:>14,}")
        print(f"  >> FULL VERIFIER TOTAL  hash_iters= {c['it_total']:>14,}")
        # #inputs
        n_in_op  = math.ceil(c['oc_total'] / BUDGET_OP_10K)
        n_in_std = math.ceil(c['it_total'] / BUDGET_STD_10K)
        n_in_con = math.ceil(c['it_total'] / BUDGET_CONS_10K)
        n_inputs = max(n_in_op, n_in_std)
        c['n_in_op'] = n_in_op; c['n_inputs'] = n_inputs; c['n_in_con'] = max(n_in_op, n_in_con)
        print(f"  #INPUTS (op-cost / {BUDGET_OP_10K:,}) = {n_in_op}   "
              f"(std-iters) = {n_in_std}   (cons-iters) = {n_in_con}")
        print(f"  => #INPUTS binding (std regime) = {n_inputs}   "
              f"(cons regime) = {max(n_in_op, n_in_con)}")
        plausible = n_inputs <= 10
        print(f"  => 1-Tx plausible (<=~10 inputs, <100KB)? "
              f"{'YES' if plausible else 'NO'}  [{n_inputs} inputs]")
        print()

    # ---------- AUFGABE 4: comparison vs membership-proxy ----------
    print("-" * 80)
    print("AUFGABE 4 -- COMPARISON vs membership-proxy (cost_report_full.py):")
    print("  membership-proxy NAIVE-Horner   : 45,449,916 op  -> 6 inputs")
    print("  membership-proxy SUCCINCT (no 4b): 19,426,884 op  -> 3 inputs")
    print("  NATIVE CT-AIR (closed-form selectors, Poseidon2 AIR), per config:")
    for D in (20, 26, 32):
        c = configs[D]
        print(f"    D={D}: {c['oc_total']:>12,} op  -> {c['n_inputs']} inputs "
              f"(op-bound {c['n_in_op']})")
    print()
    print("ASSUMPTIONS / OPEN:")
    print("  * round-per-row Poseidon2 layout (30 rows/perm); Plonky3 single-row")
    print("    Poseidon2 AIR (1 row/perm, ~600 cols) is the alternative -> would")
    print("    shrink trace ~30x (T=2^5-2^6) but widen the leaf/AIR-eval; net Merkle")
    print("    depth barely changes (log). Either way trace << membership-proxy 2^14.")
    print("  * AIR-eval per query = heaviest FULL-round constraint set (12 lanes) +")
    print("    MDS + boundary, ONCE/query (succinct: constraint COUNT, not T rows).")
    print("  * selectors CLOSED-FORM (Z_H=x^n-1 + periodic coset indicators), NOT")
    print("    naive O(T) Horner -> no T-explosion (HP1.3 PFLICHT satisfied).")
    print("  * inverses HINT-validated (1 MULMOD/check) as structures_fri; Fermat")
    print("    on-chain modexp NOT chosen (would raise fold+AIR ~1-2 orders).")
    print("  * base-field Goldilocks (8-byte); EXT-field for FS challenges/folds")
    print("    would scale fold+xpos ~3x = HP6.1 OPEN (same caveat as full report).")
    print("  * xpos modexp + index recompute are the on-chain enforcement cost of")
    print("    HP6.5/6.6/6.7 bindings (counted); selector pin = once-per-proof hash.")
    print("  * #INPUTS = compute (op-cost) bound only; whether that many inputs also")
    print("    fit the 100KB std Tx-size + cross-input FS binding = HP4.2/4.5 (OPEN).")


if __name__ == "__main__":
    main()
