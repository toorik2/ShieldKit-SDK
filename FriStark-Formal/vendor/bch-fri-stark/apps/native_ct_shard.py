"""
native_ct_shard.py -- HP2 (K2): the CT-AIR per-query verifier constraints expressed as
REAL BCH-VM programs (cashvm tokens), starting with the Poseidon2 x^7 S-box constraint.

Built on the proven BCH-VM building blocks (nothing invented):
  * cashvm.py        -- the post-Layla VM reference semantics (op_cost accounting).
  * structures_fri   -- Goldilocks field ops MULMOD/ADDMOD/SUBMOD (p resident on alt),
                        invoked via MM()/AM()/SM(); the hint-validated inverse pattern.
  * membership_comp.cash -- the per-query composition shape (selectors are INPUTS, each
                        residual gated by its selector, accumulated as alpha*quotient).

This file is the cashvm-TOKEN model (Python-runnable on cashvm.VM, op_cost-measured the
same way cost_report_native does); the deployable hand-CashAssembly (gen_*.py -> .asm ->
libauth) is HP3/HP4. The token program and the prover MUST compute the identical residual
-- self_test() runs each fragment on the VM against native_ct_air_prover's residual on a
REAL trace (valid -> 0, tamper -> non-zero). No mocks (TEST_RULES).

HP2.1 here: one Poseidon2 S-box lane. The x^7 is the deg<=2 aux decomposition
u=s+rc ; u2=u*u ; u4=u2*u2 ; u6=u4*u2 ; (x^7 = u6*u), and the three round-aux residuals
the AIR constrains, each gated by the round selector:
  c_u2 = gate*(u2 - u*u) ; c_u4 = gate*(u4 - u2*u2) ; c_u6 = gate*(u6 - u4*u2).
On a valid trace all three vanish; tampering any committed aux makes its residual != 0.
"""
import os
import sys

_APPS = os.path.dirname(os.path.abspath(__file__))
if _APPS not in sys.path:
    sys.path.insert(0, _APPS)
_PKG = os.path.dirname(_APPS)
if _PKG not in sys.path:
    sys.path.insert(0, _PKG)

from cashvm import VM, P as PUSH, N as NUM, OP, DEFINE, encode_num, decode_num, VMError
from structures_fri import (P_GOLD, MULMOD, MULMOD_BODY, ADDMOD, ADDMOD_BODY,
                            SUBMOD, SUBMOD_BODY, MM, AM, SM, NORM_TAIL)
from native_poseidon2_constants import WIDTH    # Poseidon2 state width t=12 (single source)
from stark import Hf as SHA, enc as enc8, merkle as smerkle, m_root as sm_root, m_path as sm_path

P = P_GOLD


def _field_prelude():
    """p resident on the alt stack + the MULMOD/ADDMOD/SUBMOD function table."""
    prog = [PUSH(encode_num(P)), OP("TOALT")]
    for fid, body in [(MULMOD, MULMOD_BODY), (ADDMOD, ADDMOD_BODY), (SUBMOD, SUBMOD_BODY)]:
        prog += [PUSH(fid), DEFINE(body)]
    return prog


def sbox_lane_residuals_prog(s, rc, u2, u4, u6, gate):
    """cashvm tokens that leave [c_u2, c_u4, c_u6] (bottom->top) on the stack, where
    c_u2 = gate*(u2 - (s+rc)^2), c_u4 = gate*(u4 - u2^2), c_u6 = gate*(u6 - u4*u2),
    all mod P. Selector `gate` and the committed cells are inputs (membership_comp shape).
    Each residual is computed independently (clear + correct; op-cost packing is HP3)."""
    s %= P; rc %= P; u2 %= P; u4 %= P; u6 %= P; gate %= P
    prog = _field_prelude()
    # c_u2 = gate * (u2 - (s+rc)^2)
    prog += [NUM(s), NUM(rc)] + AM()                 # [u]
    prog += [OP("DUP")] + MM()                        # [u*u]
    prog += [NUM(u2), OP("SWAP")] + SM()              # [u2 - u*u]
    prog += [NUM(gate)] + MM()                         # [c_u2]
    # c_u4 = gate * (u4 - u2^2)
    prog += [NUM(u2), OP("DUP")] + MM()               # [c_u2, u2*u2]
    prog += [NUM(u4), OP("SWAP")] + SM()              # [c_u2, u4 - u2*u2]
    prog += [NUM(gate)] + MM()                         # [c_u2, c_u4]
    # c_u6 = gate * (u6 - u4*u2)
    prog += [NUM(u4), NUM(u2)] + MM()                 # [c_u2, c_u4, u4*u2]
    prog += [NUM(u6), OP("SWAP")] + SM()              # [c_u2, c_u4, u6 - u4*u2]
    prog += [NUM(gate)] + MM()                         # [c_u2, c_u4, c_u6]
    return prog


def run_sbox_lane(s, rc, u2, u4, u6, gate):
    """Run the S-box-lane program on the VM; return ([c_u2,c_u4,c_u6], op_cost)."""
    vm = VM()
    vm.run(sbox_lane_residuals_prog(s, rc, u2, u4, u6, gate))
    assert len(vm.s) == 3, "S-box lane left %d stack items, expected 3" % len(vm.s)
    return [decode_num(x) for x in vm.s], vm.op_cost


_SBOX_OPS = ("s", "rc", "u2", "u4", "u6", "gate")  # stack bottom->top


def sbox_lane_stack_prog():
    """HP2.1 DEPLOYABLE Poseidon2 S-box-lane residual: the six inputs (s,rc,u2,u4,u6,gate) are
    READ FROM THE STACK by PICK (depth-tracked) instead of baked like sbox_lane_residuals_prog.
    Identical arithmetic -- c_u2=gate*(u2-(s+rc)^2), c_u4=gate*(u4-u2^2), c_u6=gate*(u6-u4*u2) --
    so it reproduces run_sbox_lane's [c_u2,c_u4,c_u6] exactly. In the full shard s/u2/u4/u6 are
    opened trace cells, rc is a pinned Poseidon2 round constant and gate is the selector-bound
    round indicator. Needs the field prelude once; leaves [c_u2,c_u4,c_u6] and drops the inputs."""
    prog = []
    above = [0]
    top = {nm: i for i, nm in enumerate(reversed(_SBOX_OPS))}

    def pick(nm): prog.extend([NUM(above[0] + top[nm]), OP("PICK")]); above[0] += 1
    def mm(): prog.extend(MM()); above[0] -= 1
    def am(): prog.extend(AM()); above[0] -= 1
    def sm(): prog.extend(SM()); above[0] -= 1
    def dup(): prog.append(OP("DUP")); above[0] += 1
    def swap(): prog.append(OP("SWAP"))

    pick("s"); pick("rc"); am(); dup(); mm()                                  # (s+rc)^2
    pick("u2"); swap(); sm(); pick("gate"); mm()                              # c_u2
    pick("u2"); dup(); mm(); pick("u4"); swap(); sm(); pick("gate"); mm()     # c_u4
    pick("u4"); pick("u2"); mm(); pick("u6"); swap(); sm(); pick("gate"); mm()  # c_u6
    assert above[0] == 3, "sbox_lane_stack left %d intermediates (expected 3)" % above[0]
    return prog + [OP("TOALT")] * 3 + [OP("DROP")] * 6 + [OP("FROMALT")] * 3


def sbox_lane_stack_unlock(s, rc, u2, u4, u6, gate):
    """Push-only inputs for sbox_lane_stack_prog, bottom->top in _SBOX_OPS order."""
    v = dict(s=s, rc=rc, u2=u2, u4=u4, u6=u6, gate=gate)
    return [NUM(v[n] % P) for n in _SBOX_OPS]


def run_sbox_lane_stack(s, rc, u2, u4, u6, gate):
    """Run the deployable S-box lane on cashvm; ([c_u2,c_u4,c_u6], op_cost)."""
    vm = VM()
    vm.run(_field_prelude() + sbox_lane_stack_unlock(s, rc, u2, u4, u6, gate) + sbox_lane_stack_prog())
    assert len(vm.s) == 3, "sbox_lane_stack left %d items, expected 3" % len(vm.s)
    return [decode_num(x) for x in vm.s], vm.op_cost


def state_residual_lane_prog(M_row, y_full, y_part, diag_j, j, sj, isf, isp):
    """HP2.2: the Poseidon2 linear-layer state-update residual for ONE output lane j
    (the AIR's c_st constraint), leaving [v_j] on the stack:
       ef_j = sum_k M_EXT[j][k]*y_full[k]          (external MDS, full round)
       ip_j = y_part[j]*diag[j] + sum_k y_part[k]  (internal diag+sum, partial round)
       v_j  = isf*(nxt.s_j - ef_j) + isp*(nxt.s_j - ip_j)   mod P
    M_EXT row + diag[j] are PUBLIC constants; y_full/y_part are derived from the committed
    cells (u6_k*(s_k+rc_k) / pass-through). isf/isp are the round-phase selectors (inputs).
    On a valid trace nxt.s_j equals the linear layer applied to y, so v_j == 0."""
    M_row = [m % P for m in M_row]; y_full = [v % P for v in y_full]; y_part = [v % P for v in y_part]
    diag_j %= P; sj %= P; isf %= P; isp %= P
    prog = _field_prelude()
    # ef_j = sum_k M_row[k]*y_full[k]
    prog += [NUM(0)]
    for k in range(WIDTH):
        prog += [NUM(M_row[k]), NUM(y_full[k])] + MM() + AM()       # [ef]
    # term1 = isf*(nxt.s_j - ef)
    prog += [NUM(sj), OP("SWAP")] + SM()                            # [sj-ef]
    prog += [NUM(isf)] + MM()                                        # [term1]
    # ip_j = y_part[j]*diag_j + sum_k y_part[k]
    prog += [NUM(y_part[j]), NUM(diag_j)] + MM()                    # [term1, y_part[j]*diag_j]
    prog += [NUM(0)]
    for k in range(WIDTH):
        prog += [NUM(y_part[k])] + AM()                            # [term1, ydj, sum]
    prog += AM()                                                    # [term1, ip]
    # term2 = isp*(nxt.s_j - ip)
    prog += [NUM(sj), OP("SWAP")] + SM()                           # [term1, sj-ip]
    prog += [NUM(isp)] + MM()                                       # [term1, term2]
    prog += AM()                                                    # [v_j]
    return prog


def run_state_lane(M_row, y_full, y_part, diag_j, j, sj, isf, isp):
    vm = VM()
    vm.run(state_residual_lane_prog(M_row, y_full, y_part, diag_j, j, sj, isf, isp))
    assert len(vm.s) == 1, "state lane left %d items, expected 1" % len(vm.s)
    return decode_num(vm.s[-1]), vm.op_cost


def matmul_external_prog(ybase, sp_start):
    """HP3.5b-iii-0a: the Poseidon2 EXTERNAL MDS ef = M_EXT.y applied via the STRUCTURED M4-block form
    (mirrors native_poseidon2._matmul_external / _matmul_m4) -- ADDMOD + x2/x4 (computed as adds) only,
    ZERO general MULMOD. Reads the 12 full-round inputs y at absolute positions [ybase..ybase+WIDTH-1]
    (copied, y preserved) and leaves [ef_0..ef_{WIDTH-1}] on top in order. This is the SAME matrix as the
    generic 12-term dot product used by state_residual_lane_prog (Sum_k M_EXT[j][k]*y[k]) -- M_EXT IS the
    M4-block circulant -- but ~3.9x cheaper on the VM (measured), because it exploits the block structure
    and small-constant coefficients instead of WIDTH*WIDTH general field muls. Correctness-preserving
    (validated ef == generic M_EXT.y on random + real vectors). `sp_start` = current stack depth. Needs
    one field prelude (ADDMOD reads P from the alt-top). Poseidon2 t=12 (WIDTH multiple of 4)."""
    prog = []; sp = [sp_start]; nres = [0]

    def cp(p): prog.extend([NUM(sp[0] - 1 - p), OP("PICK")]); sp[0] += 1

    def addpp(pa, pb):                                          # push (a+b) mod P; nres counts the intermediate
        cp(pa); cp(pb); prog.extend(AM()); sp[0] -= 1; nres[0] += 1
        return sp[0] - 1

    def m4(pa, pb, pc, pd):                                      # M4 block -> [out0,out1,out2,out3]
        t0 = addpp(pa, pb); t1 = addpp(pc, pd)                  # t0=a+b, t1=c+d
        bb = addpp(pb, pb); t2 = addpp(bb, t1)                  # t2 = 2b + t1
        dd = addpp(pd, pd); t3 = addpp(dd, t0)                  # t3 = 2d + t0
        tw1 = addpp(t1, t1); fo1 = addpp(tw1, tw1); t4 = addpp(fo1, t3)   # t4 = 4t1 + t3
        tw0 = addpp(t0, t0); fo0 = addpp(tw0, tw0); t5 = addpp(fo0, t2)   # t5 = 4t0 + t2
        t6 = addpp(t3, t5); t7 = addpp(t2, t4)
        return [t6, t5, t7, t4]                                 # out lanes [4i, 4i+1, 4i+2, 4i+3]

    m = [None] * WIDTH
    for bi in range(WIDTH // 4):
        o = m4(ybase + 4 * bi, ybase + 4 * bi + 1, ybase + 4 * bi + 2, ybase + 4 * bi + 3)
        for l in range(4):
            m[4 * bi + l] = o[l]
    stored = [None] * 4                                          # stored[l] = sum_j m[4j+l]
    for l in range(4):
        acc = m[l]
        for j in range(1, WIDTH // 4):
            acc = addpp(acc, m[4 * j + l])
        stored[l] = acc
    ef = [None] * WIDTH
    for i in range(WIDTH):
        ef[i] = addpp(m[i], stored[i % 4])                      # ef[i] = m[i] + stored[i%4]
    for i in range(WIDTH):
        cp(ef[i])                                               # copy ef_0..ef_{WIDTH-1} to the top in order
    # clean net effect: stash the WIDTH ef copies, DROP the nres intermediates, restore -> [.. inputs (y
    # preserved) .., ef_0..ef_{WIDTH-1}]. Deterministic count (nres) so the caller's sp accounting is exact.
    return prog + [OP("TOALT")] * WIDTH + [OP("DROP")] * nres[0] + [OP("FROMALT")] * WIDTH


def run_matmul_external(y):
    """Run the structured external-MDS prog on cashvm; ([ef_0..ef_{WIDTH-1}], op_cost). ef == M_EXT.y."""
    vm = VM()
    vm.run(_field_prelude() + [NUM(v % P) for v in y] + matmul_external_prog(0, WIDTH))
    return [decode_num(x) for x in vm.s[-WIDTH:]], vm.op_cost


_STATE_EF_OPS = (
    ("ef",)                                         # precomputed ef_j = (M_EXT.y_full)[j] (from matmul_external)
    + tuple("yp%d" % k for k in range(WIDTH))       # partial-round inputs (trace-derived)
    + ("diag", "sj", "isf", "isp")                  # internal diag const, next cell, phase selectors
)


def state_lane_from_ef_stack_prog(j):
    """HP3.5b-iii-0b: the Poseidon2 state residual for lane j reading a PRECOMPUTED ef_j (=
    (M_EXT.y_full)[j], produced once for ALL lanes by matmul_external_prog's structured M4-block form)
    instead of recomputing the generic 12-term M_EXT-row dot. Block (bottom->top, _STATE_EF_OPS):
    [ef, yp_0..yp_{W-1}, diag, sj, isf, isp]. Arithmetic for ip + v is IDENTICAL to state_residual_lane_prog
    -- ip = yp[j]*diag + sum_k yp[k]; v = isf*(sj-ef) + isp*(sj-ip) mod P -- only ef is looked up, not
    recomputed, so v_j is numerically identical. Needs the field prelude once; leaves [v_j], drops the
    block. Used by assemble_transition_residuals (0b) after matmul_external computes all WIDTH ef; this
    eliminates the WIDTH*WIDTH generic MDS muls (compose op reduction; CHIP: OP_MUL costs size^2)."""
    prog = []; above = [0]
    top = {nm: i for i, nm in enumerate(reversed(_STATE_EF_OPS))}

    def pick(nm): prog.extend([NUM(above[0] + top[nm]), OP("PICK")]); above[0] += 1
    def num(v): prog.append(NUM(v % P)); above[0] += 1
    def mm(): prog.extend(MM()); above[0] -= 1
    def am(): prog.extend(AM()); above[0] -= 1
    def sm(): prog.extend(SM()); above[0] -= 1
    def swap(): prog.append(OP("SWAP"))

    pick("sj"); pick("ef"); sm(); pick("isf"); mm()         # term1 = isf*(sj - ef)   (sj second, ef top)
    pick("yp%d" % j); pick("diag"); mm()                    # yp[j]*diag
    num(0)
    for k in range(WIDTH):
        pick("yp%d" % k); am()                              # sum_k yp[k]
    am()                                                    # ip = yp[j]*diag + sum
    pick("sj"); swap(); sm(); pick("isp"); mm()             # term2 = isp*(sj - ip)
    am()                                                    # v_j
    assert above[0] == 1, "state_lane_from_ef left %d intermediates (expected 1)" % above[0]
    return prog + [OP("TOALT")] + [OP("DROP")] * len(_STATE_EF_OPS) + [OP("FROMALT")]


def state_lane_from_ef_stack_unlock(ef_j, y_part, diag_j, sj, isf, isp):
    """Push-only inputs for state_lane_from_ef_stack_prog, bottom->top in _STATE_EF_OPS order."""
    vals = [ef_j] + list(y_part) + [diag_j, sj, isf, isp]
    assert len(vals) == len(_STATE_EF_OPS), "state_from_ef unlock arity %d != %d" % (len(vals), len(_STATE_EF_OPS))
    return [NUM(v % P) for v in vals]


def run_state_lane_from_ef(ef_j, y_part, diag_j, j, sj, isf, isp):
    """Run the deployable ef-reading state lane on cashvm; (v_j, op_cost). v_j == run_state_lane's."""
    vm = VM()
    vm.run(_field_prelude() + state_lane_from_ef_stack_unlock(ef_j, y_part, diag_j, sj, isf, isp)
           + state_lane_from_ef_stack_prog(j))
    assert len(vm.s) == 1, "state_lane_from_ef left %d items, expected 1" % len(vm.s)
    return decode_num(vm.s[-1]), vm.op_cost


def range_residuals_prog(b, acc, value, isr, isf, ist, isl, nxt_bit, nxt_acc, nxt_value, w_next):
    """HP2.4: the poly-form Num2Bits range residuals (A1 wrap-safe), leaving the 5
    residuals [r_bool, r_init, r_step, r_vconst, r_last] on the stack. s0=bit, s1=acc,
    s2=value; selectors is_range/is_range_first/is_range_step/is_range_last are inputs;
    w_next = 2^(local index of the NEXT row):
      r_bool   = is_range      * (b*(b-1))
      r_init   = is_range_first * (acc - b)
      r_step   = is_range_step  * (nxt_acc - acc - nxt_bit*w_next)
      r_vconst = is_range_step  * (nxt_value - value)
      r_last   = is_range_last  * (acc - value)
    All vanish on a valid range block (matches native_ct_air_prover._range_residuals)."""
    b %= P; acc %= P; value %= P; isr %= P; isf %= P; ist %= P; isl %= P
    nxt_bit %= P; nxt_acc %= P; nxt_value %= P; w_next %= P
    prog = _field_prelude()
    # r_bool = isr * (b*(b-1))
    prog += [NUM(b), NUM(1)] + SM() + [NUM(b)] + MM() + [NUM(isr)] + MM()       # [r_bool]
    # r_init = isf * (acc - b)
    prog += [NUM(acc), NUM(b)] + SM() + [NUM(isf)] + MM()                        # [.., r_init]
    # r_step = ist * ((nxt_acc - acc) - nxt_bit*w_next)
    prog += [NUM(nxt_acc), NUM(acc)] + SM()                                      # [.., d]
    prog += [NUM(nxt_bit), NUM(w_next)] + MM() + SM()                            # [.., d - bw]
    prog += [NUM(ist)] + MM()                                                     # [.., r_step]
    # r_vconst = ist * (nxt_value - value)
    prog += [NUM(nxt_value), NUM(value)] + SM() + [NUM(ist)] + MM()              # [.., r_vconst]
    # r_last = isl * (acc - value)
    prog += [NUM(acc), NUM(value)] + SM() + [NUM(isl)] + MM()                    # [.., r_last]
    return prog


def run_range(b, acc, value, isr, isf, ist, isl, nxt_bit, nxt_acc, nxt_value, w_next):
    vm = VM()
    vm.run(range_residuals_prog(b, acc, value, isr, isf, ist, isl,
                                nxt_bit, nxt_acc, nxt_value, w_next))
    assert len(vm.s) == 5, "range left %d items, expected 5" % len(vm.s)
    return [decode_num(x) for x in vm.s], vm.op_cost


_RANGE_OPS = ("b", "acc", "value", "isr", "isf", "ist", "isl",
              "nxt_bit", "nxt_acc", "nxt_value", "w_next")


def range_residual_stack_prog():
    """HP2.4 DEPLOYABLE Num2Bits range residuals: the 11 inputs (b,acc,value, is_range/_first/
    _step/_last, nxt_bit,nxt_acc,nxt_value,w_next) are READ FROM THE STACK by PICK instead of baked
    like range_residuals_prog. Identical arithmetic, so it reproduces run_range's five residuals
    [r_bool,r_init,r_step,r_vconst,r_last] exactly. In the full shard b/acc/value and the nxt.* cells
    are opened trace cells, the is_* are selector-bound row indicators and w_next the pinned bit
    weight. Needs the field prelude once; leaves the 5 residuals (bottom->top), drops the inputs."""
    prog = []
    above = [0]
    top = {nm: i for i, nm in enumerate(reversed(_RANGE_OPS))}

    def pick(nm): prog.extend([NUM(above[0] + top[nm]), OP("PICK")]); above[0] += 1
    def num(v): prog.append(NUM(v % P)); above[0] += 1
    def mm(): prog.extend(MM()); above[0] -= 1
    def am(): prog.extend(AM()); above[0] -= 1
    def sm(): prog.extend(SM()); above[0] -= 1

    pick("b"); num(1); sm(); pick("b"); mm(); pick("isr"); mm()         # r_bool = isr*(b*(b-1))
    pick("acc"); pick("b"); sm(); pick("isf"); mm()                     # r_init = isf*(acc-b)
    pick("nxt_acc"); pick("acc"); sm()                                  # d = nxt_acc-acc
    pick("nxt_bit"); pick("w_next"); mm(); sm()                         # d - nxt_bit*w_next
    pick("ist"); mm()                                                   # r_step = ist*(...)
    pick("nxt_value"); pick("value"); sm(); pick("ist"); mm()          # r_vconst = ist*(nxt_value-value)
    pick("acc"); pick("value"); sm(); pick("isl"); mm()                # r_last = isl*(acc-value)
    assert above[0] == 5, "range_residual_stack left %d intermediates (expected 5)" % above[0]
    return prog + [OP("TOALT")] * 5 + [OP("DROP")] * len(_RANGE_OPS) + [OP("FROMALT")] * 5


def range_residual_stack_unlock(b, acc, value, isr, isf, ist, isl, nxt_bit, nxt_acc, nxt_value, w_next):
    """Push-only inputs for range_residual_stack_prog, bottom->top in _RANGE_OPS order."""
    v = dict(b=b, acc=acc, value=value, isr=isr, isf=isf, ist=ist, isl=isl,
             nxt_bit=nxt_bit, nxt_acc=nxt_acc, nxt_value=nxt_value, w_next=w_next)
    return [NUM(v[n] % P) for n in _RANGE_OPS]


def run_range_stack(b, acc, value, isr, isf, ist, isl, nxt_bit, nxt_acc, nxt_value, w_next):
    """Run the deployable range residuals on cashvm; ([r_bool,r_init,r_step,r_vconst,r_last], op_cost)."""
    vm = VM()
    vm.run(_field_prelude()
           + range_residual_stack_unlock(b, acc, value, isr, isf, ist, isl, nxt_bit, nxt_acc, nxt_value, w_next)
           + range_residual_stack_prog())
    assert len(vm.s) == 5, "range_residual_stack left %d items, expected 5" % len(vm.s)
    return [decode_num(x) for x in vm.s], vm.op_cost


def conservation_prog(vh_in, vh_o0, vh_o1, vh_fee):
    """HP2.4b: the additive conservation residual vh_in - (vh_o0 + vh_o1 + vh_fee) mod P,
    read from the held-value columns at the conservation row (A1 wrap-safe; all four are
    range-checked < 2^62, so both sides are < p and the field identity is integer)."""
    vh_in %= P; vh_o0 %= P; vh_o1 %= P; vh_fee %= P
    prog = _field_prelude()
    prog += [NUM(vh_o0), NUM(vh_o1)] + AM() + [NUM(vh_fee)] + AM()   # [o0+o1+fee]
    prog += [NUM(vh_in), OP("SWAP")] + SM()                          # [vh_in - sum]
    return prog


def run_conservation(vh_in, vh_o0, vh_o1, vh_fee):
    vm = VM()
    vm.run(conservation_prog(vh_in, vh_o0, vh_o1, vh_fee))
    assert len(vm.s) == 1, "conservation left %d items, expected 1" % len(vm.s)
    return decode_num(vm.s[-1]), vm.op_cost


_CONS_OPS = ("vh_in", "vh_o0", "vh_o1", "vh_fee")


def conservation_stack_prog():
    """HP2.4b DEPLOYABLE additive conservation residual vh_in-(vh_o0+vh_o1+vh_fee) mod P: the four
    held-value inputs are READ FROM THE STACK by PICK instead of baked like conservation_prog.
    Identical arithmetic, so it reproduces run_conservation's residual exactly. In the full shard all
    four are opened held-value trace cells (each range-checked < 2^62, so both sides are < p and the
    field identity is integer). Needs the field prelude once; leaves [vh_in - sum], drops the inputs."""
    prog = []
    above = [0]
    top = {nm: i for i, nm in enumerate(reversed(_CONS_OPS))}

    def pick(nm): prog.extend([NUM(above[0] + top[nm]), OP("PICK")]); above[0] += 1
    def am(): prog.extend(AM()); above[0] -= 1
    def sm(): prog.extend(SM()); above[0] -= 1
    def swap(): prog.append(OP("SWAP"))

    pick("vh_o0"); pick("vh_o1"); am(); pick("vh_fee"); am()    # sum = o0+o1+fee
    pick("vh_in"); swap(); sm()                                 # vh_in - sum
    assert above[0] == 1, "conservation_stack left %d intermediates (expected 1)" % above[0]
    return prog + [OP("TOALT")] + [OP("DROP")] * len(_CONS_OPS) + [OP("FROMALT")]


def conservation_stack_unlock(vh_in, vh_o0, vh_o1, vh_fee):
    """Push-only inputs for conservation_stack_prog, bottom->top in _CONS_OPS order."""
    v = dict(vh_in=vh_in, vh_o0=vh_o0, vh_o1=vh_o1, vh_fee=vh_fee)
    return [NUM(v[n] % P) for n in _CONS_OPS]


def run_conservation_stack(vh_in, vh_o0, vh_o1, vh_fee):
    """Run the deployable conservation residual on cashvm; (vh_in - sum, op_cost)."""
    vm = VM()
    vm.run(_field_prelude() + conservation_stack_unlock(vh_in, vh_o0, vh_o1, vh_fee)
           + conservation_stack_prog())
    assert len(vm.s) == 1, "conservation_stack left %d items, expected 1" % len(vm.s)
    return decode_num(vm.s[-1]), vm.op_cost


def hold_residual_stack_prog(n):
    """HP2 (2.20b) DEPLOYABLE A3 held-value HOLD residuals: for each of the n held columns the
    residual nxt[c] - cur[c] (every held column is constant across the transition). The 2*n inputs
    (cur_0..cur_{n-1}, then nxt_0..nxt_{n-1}) are READ FROM THE STACK by PICK (depth-tracked) instead
    of baked -- it reproduces native_ct_air_prover._hold_residuals (over HELD_COLS) exactly. In the
    full shard cur_c/nxt_c are opened trace cells at k/kn. Needs the field prelude once; leaves the
    n residuals [h_0..h_{n-1}] (bottom->top) and drops the inputs."""
    ops = tuple("cur%d" % k for k in range(n)) + tuple("nxt%d" % k for k in range(n))
    prog = []
    above = [0]
    top = {nm: i for i, nm in enumerate(reversed(ops))}

    def pick(nm): prog.extend([NUM(above[0] + top[nm]), OP("PICK")]); above[0] += 1
    def sm(): prog.extend(SM()); above[0] -= 1

    for k in range(n):
        pick("nxt%d" % k); pick("cur%d" % k); sm()          # h_k = nxt_k - cur_k
    assert above[0] == n, "hold_residual_stack left %d intermediates (expected %d)" % (above[0], n)
    return prog + [OP("TOALT")] * n + [OP("DROP")] * len(ops) + [OP("FROMALT")] * n


def hold_residual_stack_unlock(cur_vals, nxt_vals):
    """Push-only inputs for hold_residual_stack_prog, bottom->top: cur_0..cur_{n-1}, nxt_0..nxt_{n-1}."""
    assert len(cur_vals) == len(nxt_vals), "hold unlock arity %d != %d" % (len(cur_vals), len(nxt_vals))
    return [NUM(v % P) for v in list(cur_vals) + list(nxt_vals)]


def run_hold_stack(cur_vals, nxt_vals):
    """Run the deployable hold residuals on cashvm; ([h_0..h_{n-1}], op_cost)."""
    n = len(cur_vals)
    vm = VM()
    vm.run(_field_prelude() + hold_residual_stack_unlock(cur_vals, nxt_vals) + hold_residual_stack_prog(n))
    assert len(vm.s) == n, "hold_residual_stack left %d items, expected %d" % (len(vm.s), n)
    return [decode_num(x) for x in vm.s], vm.op_cost


_CHAIN_OPS = (tuple("cur%d" % k for k in range(WIDTH))       # cur state @k
              + tuple("nxt%d" % k for k in range(WIDTH))     # nxt state @kn
              + tuple("cm%d" % k for k in range(WIDTH))      # chain_minv row (opened D-coset selector)
              + ("isbs", "isra"))                            # is_block_start / is_reabsorb selectors


def chain_residual_stack_prog(minv_cap_rows):
    """HP2 (2.20c) DEPLOYABLE A2 sponge-structure CHAIN residuals, leaving the
    (len(minv_cap_rows)+1) residuals (bottom->top) on the stack:
      capacity[i] = isbs * (minv_cap_rows[i] . cur_state)   for each pinned capacity lane
      chaining    = isra * ((chain_minv . nxt_state) - cur.s0)
    The inverse external-MDS capacity rows are BAKED public constants (2.20-style: a wrong matrix
    cannot be substituted by a prover); cur_state/nxt_state (WIDTH each, opened trace cells @k/@kn),
    the chain_minv row (WIDTH, an opened+committed D-coset selector) and isbs/isra (opened selectors)
    are READ FROM THE STACK by PICK (depth-tracked). Reproduces native_ct_air_prover._chain_residuals
    exactly. Needs the field prelude once; leaves the residuals and drops the inputs."""
    prog = []
    above = [0]
    top = {nm: i for i, nm in enumerate(reversed(_CHAIN_OPS))}

    def pick(nm): prog.extend([NUM(above[0] + top[nm]), OP("PICK")]); above[0] += 1
    def num(v): prog.append(NUM(v % P)); above[0] += 1
    def mm(): prog.extend(MM()); above[0] -= 1
    def am(): prog.extend(AM()); above[0] -= 1
    def sm(): prog.extend(SM()); above[0] -= 1

    for row in minv_cap_rows:                                       # capacity residual per baked M_EXT_INV row
        assert len(row) == WIDTH, "chain capacity row arity %d != WIDTH %d" % (len(row), WIDTH)
        num(0)
        for j in range(WIDTH):
            num(row[j]); pick("cur%d" % j); mm(); am()              # acc += M_EXT_INV[k][j]*cur_j
        pick("isbs"); mm()                                          # capacity[i] = isbs*acc
    num(0)                                                          # chaining residual
    for j in range(WIDTH):
        pick("cm%d" % j); pick("nxt%d" % j); mm(); am()            # chained += chain_minv[j]*nxt_j
    pick("cur0"); sm()                                             # chained - cur.s0
    pick("isra"); mm()                                             # chaining = isra*(chained - cur.s0)
    R = len(minv_cap_rows) + 1
    assert above[0] == R, "chain_residual_stack left %d intermediates (expected %d)" % (above[0], R)
    return prog + [OP("TOALT")] * R + [OP("DROP")] * len(_CHAIN_OPS) + [OP("FROMALT")] * R


def chain_residual_stack_unlock(cur_state, nxt_state, chain_minv, isbs, isra):
    """Push-only inputs for chain_residual_stack_prog, bottom->top in _CHAIN_OPS order."""
    vals = list(cur_state) + list(nxt_state) + list(chain_minv) + [isbs, isra]
    assert len(vals) == len(_CHAIN_OPS), "chain unlock arity %d != %d" % (len(vals), len(_CHAIN_OPS))
    return [NUM(v % P) for v in vals]


def run_chain_stack(minv_cap_rows, cur_state, nxt_state, chain_minv, isbs, isra):
    """Run the deployable chain residuals on cashvm; ([cap_0..cap_{m-1}, chaining], op_cost)."""
    R = len(minv_cap_rows) + 1
    vm = VM()
    vm.run(_field_prelude() + chain_residual_stack_unlock(cur_state, nxt_state, chain_minv, isbs, isra)
           + chain_residual_stack_prog(minv_cap_rows))
    assert len(vm.s) == R, "chain_residual_stack left %d items, expected %d" % (len(vm.s), R)
    return [decode_num(x) for x in vm.s], vm.op_cost


_CMBIND_OPS = ("vh",) + tuple("s%d" % k for k in range(WIDTH))   # held value + cur state @k


def cmbind_residual_stack_prog(minv0_row):
    """HP2 (2.20d) DEPLOYABLE cm-bind BOUNDARY residual vh - (M_EXT_INV[0] . cur_state), leaving [r]
    on the stack: it binds a range block's held value vh to the inverse-external-MDS image of the
    source block's committed output state (A3 held<->cm link). M_EXT_INV[0] is a BAKED public constant
    (no prover substitution); vh and cur_state (WIDTH opened trace cells @k) are READ FROM THE STACK by
    PICK. Reproduces the cm-bind fn in native_ct_air_prover.ct_boundary_constraints exactly (evaluated
    at the query point cur=q.ck; the boundary row lives in the bound_invX denominator). Needs the field
    prelude once; leaves [r] and drops the inputs. The eq boundary residuals (root/nf/cm_out/link =
    cur[a]-b) are a single field subtraction -- the existing SUBMOD primitive -- so they need no prog."""
    assert len(minv0_row) == WIDTH, "cm-bind row arity %d != WIDTH %d" % (len(minv0_row), WIDTH)
    prog = []
    above = [0]
    top = {nm: i for i, nm in enumerate(reversed(_CMBIND_OPS))}

    def pick(nm): prog.extend([NUM(above[0] + top[nm]), OP("PICK")]); above[0] += 1
    def num(v): prog.append(NUM(v % P)); above[0] += 1
    def mm(): prog.extend(MM()); above[0] -= 1
    def am(): prog.extend(AM()); above[0] -= 1
    def sm(): prog.extend(SM()); above[0] -= 1
    def swap(): prog.append(OP("SWAP"))

    num(0)                                                     # dot accumulator
    for j in range(WIDTH):
        num(minv0_row[j]); pick("s%d" % j); mm(); am()        # dot += M_EXT_INV[0][j]*s_j
    pick("vh"); swap(); sm()                                  # r = vh - dot
    assert above[0] == 1, "cmbind_residual_stack left %d intermediates (expected 1)" % above[0]
    return prog + [OP("TOALT")] + [OP("DROP")] * len(_CMBIND_OPS) + [OP("FROMALT")]


def cmbind_residual_stack_unlock(vh, cur_state):
    """Push-only inputs for cmbind_residual_stack_prog, bottom->top: vh, s0..s_{WIDTH-1}."""
    vals = [vh] + list(cur_state)
    assert len(vals) == len(_CMBIND_OPS), "cmbind unlock arity %d != %d" % (len(vals), len(_CMBIND_OPS))
    return [NUM(v % P) for v in vals]


def run_cmbind_stack(minv0_row, vh, cur_state):
    """Run the deployable cm-bind residual on cashvm; ([r], op_cost)."""
    vm = VM()
    vm.run(_field_prelude() + cmbind_residual_stack_unlock(vh, cur_state) + cmbind_residual_stack_prog(minv0_row))
    assert len(vm.s) == 1, "cmbind_residual_stack left %d items, expected 1" % len(vm.s)
    return [decode_num(x) for x in vm.s], vm.op_cost


# Quadratic-extension non-residue: GF(p^2) = F_p[u]/(u^2 - EXT_W). Goldilocks u^2-7
# (single source native_ct_air_config.EXT_NONRES; mirrored here for the VM program).
from native_ct_air_config import EXT_NONRES as EXT_W


def ext_mul_prog(a0, a1, b0, b1):
    """GF(p^2) Karatsuba multiply (a0+a1*u)(b0+b1*u), u^2=EXT_W, leaving [c0, c1] on the
    stack: t0=a0*b0, t1=a1*b1, t2=(a0+a1)(b0+b1), c0=t0+EXT_W*t1, c1=t2-t0-t1 mod P. The
    extension multiply the FRI fold needs (beta in GF(p^2)); base operands are pushed as
    literals so only PICK/ROLL juggle the three intermediates."""
    a0 %= P; a1 %= P; b0 %= P; b1 %= P
    prog = _field_prelude()
    prog += [NUM(a0), NUM(b0)] + MM()                                  # [t0]
    prog += [NUM(a1), NUM(b1)] + MM()                                  # [t0, t1]
    prog += [NUM(a0), NUM(a1)] + AM() + [NUM(b0), NUM(b1)] + AM() + MM()   # [t0, t1, t2]
    # c1 = t2 - t0 - t1
    prog += [NUM(0), OP("PICK")]                                       # copy t2 -> [t0,t1,t2,t2]
    prog += [NUM(3), OP("PICK")] + SM()                                # t2 - t0 -> [t0,t1,t2,d]
    prog += [NUM(2), OP("PICK")] + SM()                                # d - t1 = c1 -> [t0,t1,t2,c1]
    # c0 = t0 + EXT_W*t1
    prog += [NUM(3), OP("PICK")]                                       # copy t0 -> [..,c1,t0]
    prog += [NUM(3), OP("PICK"), NUM(EXT_W % P)] + MM()                # EXT_W*t1 -> [..,c1,t0,Wt1]
    prog += AM()                                                       # t0 + Wt1 = c0 -> [t0,t1,t2,c1,c0]
    # drop the three intermediates t0,t1,t2 beneath [c1,c0]; then order [c0,c1]
    prog += [NUM(4), OP("ROLL"), OP("DROP")]                           # drop t0
    prog += [NUM(3), OP("ROLL"), OP("DROP")]                           # drop t1
    prog += [NUM(2), OP("ROLL"), OP("DROP")]                           # drop t2 -> [c1,c0]
    prog += [OP("SWAP")]                                               # -> [c0,c1]
    return prog


def run_ext_mul(a0, a1, b0, b1):
    vm = VM()
    vm.run(ext_mul_prog(a0, a1, b0, b1))
    assert len(vm.s) == 2, "ext_mul left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


# ---- HP9: GF(p^2) STACK-based arithmetic for the on-chain AIR-eval at z (the DEEP AIR-eval-once runs over
# GF(p^2); DEEP_ALI_resolution.md sec 7). ext_mul_prog above BAKES its operands (the FRI-fold beta is known);
# the AIR-at-z operands are WITNESS values (the OOD masks read from the FS blob), so these read them FROM the
# stack via PICK (like ext_fold_stack_prog:980). Each consumes its GF(p^2) operand block and leaves [c0,c1] on
# top (c0 deeper, c1 on top -- the (a0,a1) convention). No field prelude inside (caller installs it once).
# Cross-checked in _self_test against native_gf_p2 on real cashvm (no mock). ----
def _ext_stack(ops, body):
    """Build a stack GF(p^2) op. `ops` = operand limb names bottom->top; `body(pick,num,mm,am,sm)` builds the two
    result limbs c0 (deeper) then c1 (top) from the operands via a depth-tracked PICK (above = intermediates over
    the operand block). Stashes [c0,c1] on alt, drops the len(ops) operands, restores -> [c0,c1]."""
    prog = []
    above = [0]
    top_index = {n: i for i, n in enumerate(reversed(ops))}

    def pick(name):
        prog.extend([NUM(above[0] + top_index[name]), OP("PICK")]); above[0] += 1

    def num(v):
        prog.append(NUM(v % P)); above[0] += 1

    def mm(): prog.extend(MM()); above[0] -= 1
    def am(): prog.extend(AM()); above[0] -= 1
    def sm(): prog.extend(SM()); above[0] -= 1
    body(pick, num, mm, am, sm)
    assert above[0] == 2, "_ext_stack left %d intermediates (expected 2)" % above[0]
    prog += [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * len(ops) + [OP("FROMALT"), OP("FROMALT")]
    return prog


def ext_add_stack_prog():
    """[a0,a1,b0,b1] -> [a0+b0, a1+b1] (drops the 4 operands)."""
    def body(pick, num, mm, am, sm):
        pick("a0"); pick("b0"); am()                                      # c0 = a0+b0
        pick("a1"); pick("b1"); am()                                      # c1 = a1+b1
    return _ext_stack(["a0", "a1", "b0", "b1"], body)


def ext_sub_stack_prog():
    """[a0,a1,b0,b1] -> [a0-b0, a1-b1]."""
    def body(pick, num, mm, am, sm):
        pick("a0"); pick("b0"); sm()
        pick("a1"); pick("b1"); sm()
    return _ext_stack(["a0", "a1", "b0", "b1"], body)


def ext_scalar_stack_prog():
    """[s, a0, a1] -> [s*a0, s*a1] (base scalar s times GF(p^2) a; native_gf_p2.scalar)."""
    def body(pick, num, mm, am, sm):
        pick("s"); pick("a0"); mm()
        pick("s"); pick("a1"); mm()
    return _ext_stack(["s", "a0", "a1"], body)


def ext_mul_stack_prog():
    """[a0,a1,b0,b1] -> Karatsuba [c0,c1]: c0=a0*b0+EXT_W*a1*b1, c1=(a0+a1)(b0+b1)-a0*b0-a1*b1."""
    def body(pick, num, mm, am, sm):
        pick("a0"); pick("b0"); mm(); pick("a1"); pick("b1"); mm(); num(EXT_W); mm(); am()   # c0
        pick("a0"); pick("a1"); am(); pick("b0"); pick("b1"); am(); mm()                      # t2=(a0+a1)(b0+b1)
        pick("a0"); pick("b0"); mm(); sm(); pick("a1"); pick("b1"); mm(); sm()                # c1 = t2 - a0b0 - a1b1
    return _ext_stack(["a0", "a1", "b0", "b1"], body)


def ext_inv_check_prog():
    """HP13.1: verify a prover-supplied GF(p^2) INVERSE HINT on-chain (fail-closed). Stack [hint0, hint1, d0, d1]
    -> hint*d over GF(p^2) (ext_mul_stack_prog) -> require == GF(p^2) ONE = (1, 0) via two NUMEQUALVERIFY (c1==0
    then c0==1). A wrong hint fails closed, so a DEEP division cannot use a favourable normalizer: every
    1/(x_k - z) resp. 1/(x_k - z*g) hint is FORCED to the unique inverse (hint*(x_k - z) == 1, F6/LB3). GF(p^2)
    counterpart of the base-field i2x*twox==1 hint (ext_fold_logic:1525); reuses ext_mul_stack_prog (DRY).
    Consumes the 4 operands, leaves the stack empty (pure check). The field prelude is installed by the caller."""
    return ext_mul_stack_prog() + [NUM(0), OP("NUMEQUALVERIFY"), NUM(1), OP("NUMEQUALVERIFY")]


def run_ext_inv_check(h0, h1, d0, d1):
    """Run ext_inv_check_prog on real cashvm: (True, op_cost) if hint*(d) == 1 over GF(p^2) (clean empty stack),
    (False, 0) on a fail-closed reject (a wrong hint)."""
    vm = VM()
    try:
        vm.run(_field_prelude() + [NUM(h0 % P), NUM(h1 % P), NUM(d0 % P), NUM(d1 % P)] + ext_inv_check_prog())
        return len(vm.s) == 0, vm.op_cost
    except VMError:
        return False, 0


def deep_term_stack_prog():
    """HP10.1: ONE DEEP-quotient term over GF(p^2). Stack [alpha0,alpha1, inv0,inv1, value0,value1, ood0,ood1]
    (bottom->top) -> [q0,q1] = alpha * (inv * (value - ood)) = deep_alphas[ai]*(value(x_k)-ood)*1/(x_k-z) (resp.
    *1/(x_k-z*g)), the per-term contribution accumulated into q(x_k) (native_ct_air_stark._deep_replay.q_at:500-506).
    value = the opened evaluation at x_k (trace/selector/range_weight base-lifted to (v,0), or comp already ext);
    ood = the FS-blob mask; inv = the hint-validated 1/(x_k-z) (checked separately via ext_inv_check_prog).
    Pure composition of ext_sub_stack_prog + 2x ext_mul_stack_prog (DRY; GF(p^2) mul is commutative). Consumes
    the 8 operand limbs, leaves [q0,q1]. Caller installs the field prelude."""
    return ext_sub_stack_prog() + ext_mul_stack_prog() + ext_mul_stack_prog()


def run_deep_term(alpha, inv, value, ood):
    """Run deep_term_stack_prog on real cashvm; ((q0,q1), op_cost) with q == alpha*(inv*(value-ood)) over GF(p^2).
    alpha/inv/value/ood are GF(p^2) (limb0, limb1) tuples."""
    vm = VM()
    vm.run(_field_prelude() + [NUM(alpha[0] % P), NUM(alpha[1] % P), NUM(inv[0] % P), NUM(inv[1] % P),
                               NUM(value[0] % P), NUM(value[1] % P), NUM(ood[0] % P), NUM(ood[1] % P)]
           + deep_term_stack_prog())
    assert len(vm.s) == 2, "deep_term left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


_DEEP_MAC_FID = b"\x28"


def _deep_mac_body():
    """[acc, alpha, value, ood] -> acc + alpha*(value-ood) over GF(p^2) (DEEP-quotient MAC). The shared inverse
    invz/invzg is factored OUT and applied once to the whole z / z*g accumulator (mirrors compose_ext's acc*qf),
    so the MAC body itself is inverse-free."""
    def body(m):
        m.copy("value"); m.copy("ood"); m.sub()                  # value - ood
        m.copy("alpha"); m.mul()                                 # * alpha
        m.copy("acc"); m.add()                                   # + acc
    return _ext_vstack(["acc", "alpha", "value", "ood"], body)


def deep_quotient_prog(n_flat, n_sel, below=0):
    """HP10.1: the on-chain per-query DEEP quotient q(x_k) == native_ct_air_stark._deep_replay.q_at. Every DEEP
    division shares one of two inverses, so q(x_k) = invz*sum_z alpha*(value-ood) + invzg*sum_zg alpha*(value-ood)
    (invz=1/(x_k-z), invzg=1/(x_k-z*g)); the inverses factor out and are applied ONCE per accumulator (like
    compose_ext_looped's acc_T*qf -- byte cut). Operand block (ext, canonical deep_alphas order, below-relative):
    per term [alpha_i, value_i, ood_i] for i in 0..n_terms-1, then invz, invzg. Term structure
    (n_terms = 2*n_flat+n_sel+2): 2*n_flat trace terms (even i -> z-term ood=Pcz[c], odd i -> z*g-term ood=Pczg[c]),
    n_sel selector terms (z), 1 range_weight term (z*g), 1 comp term (z). value = the opened evaluation at x_k
    (trace/selector/range_weight base-lifted to (v,0), or comp(x_k) already ext); ood = the FS-blob mask. invz/invzg
    MUST be hint-validated by ext_inv_check_prog (HP13.1) before use. MAC body 0x28 accumulates alpha*(value-ood)
    (DRY on _ext_vstack, 2-level nesting). Leaves [q0,q1]; drops the operand block."""
    n_terms = 2 * n_flat + n_sel + 2
    NB = 3 * n_terms + 2
    z_terms = [2 * c for c in range(n_flat)] + [2 * n_flat + s for s in range(n_sel)] + [2 * n_flat + n_sel + 1]
    zg_terms = [2 * c + 1 for c in range(n_flat)] + [2 * n_flat + n_sel]
    invz_i = 3 * n_terms; invzg_i = 3 * n_terms + 1
    prog = [PUSH(_DEEP_MAC_FID), DEFINE(_deep_mac_body())]
    sp = [below + 2 * NB]

    def pk_at(ext_idx):
        prog.extend([NUM(sp[0] - 1 - (below + 2 * ext_idx)), OP("PICK")]); sp[0] += 1
        prog.extend([NUM(sp[0] - 1 - (below + 2 * ext_idx + 1)), OP("PICK")]); sp[0] += 1

    def _acc(term_list, inv_idx):                                # acc = inv * sum_terms alpha*(value-ood)
        prog.extend([NUM(0), NUM(0)]); sp[0] += 2                # acc = 0
        for i in term_list:
            pk_at(3 * i); pk_at(3 * i + 1); pk_at(3 * i + 2)     # alpha, value, ood
            prog.extend([PUSH(_DEEP_MAC_FID), OP("INVOKE")]); sp[0] -= 6
        pk_at(inv_idx)                                           # invz / invzg
        prog.extend(ext_mul_stack_prog()); sp[0] -= 2           # acc * inv

    _acc(z_terms, invz_i)                                        # invz * sum_z
    _acc(zg_terms, invzg_i)                                      # invzg * sum_zg
    prog.extend(ext_add_stack_prog()); sp[0] -= 2              # q = invz*sum_z + invzg*sum_zg
    assert sp[0] == below + 2 * NB + 2, "deep_quotient sp=%d expected %d" % (sp[0], below + 2 * NB + 2)
    return prog + [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * (2 * NB) + [OP("FROMALT"), OP("FROMALT")]


def deep_quotient_unlock(terms, invz, invzg):
    """Push-only operand block for deep_quotient_prog: per term [alpha, value, ood] in canonical deep_alphas order,
    then invz, invzg. Each is a GF(p^2) (limb0, limb1) tuple; value is base-lifted (v, 0) for trace/selector/
    range_weight or the ext comp(x_k)."""
    w = []
    for alpha, value, ood in terms:
        w += [NUM(alpha[0] % P), NUM(alpha[1] % P), NUM(value[0] % P), NUM(value[1] % P),
              NUM(ood[0] % P), NUM(ood[1] % P)]
    return w + [NUM(invz[0] % P), NUM(invz[1] % P), NUM(invzg[0] % P), NUM(invzg[1] % P)]


def run_deep_quotient(n_flat, n_sel, terms, invz, invzg):
    """Run deep_quotient_prog on real cashvm; ((q0,q1), op_cost) with q == q(x_k), or (None, 0) on a VM error."""
    vm = VM()
    try:
        vm.run(_field_prelude() + deep_quotient_unlock(terms, invz, invzg) + deep_quotient_prog(n_flat, n_sel))
        if len(vm.s) != 2:
            return None, 0
        return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost
    except VMError:
        return None, 0


def deep_query_quotient_prog(n_flat, n_sel, below=0):
    """HP10.1: the HINT-VALIDATED per-query DEEP quotient. First FAIL-CLOSED validates the two GF(p^2) inverse
    hints invz=1/(x_k-z), invzg=1/(x_k-z*g) via ext_inv_check (HP13.1) -- against x_k, z, z*g -- then computes
    q(x_k) via deep_quotient with the SAME invz/invzg (PICK'd from the operand block, so a prover cannot check a
    valid inverse while feeding a forged one into the quotient). d_z=(x_k-z) via ext_sub of the base-lifted x_k;
    a forged invz/invzg fails the hint check (fail-closed). Unlock (bottom->top): [x, z0,z1, zg0,zg1] then the
    deep_quotient operand block ([alpha,value,ood]*n_terms, invz, invzg). Leaves [q0,q1]. Field prelude installed
    by the caller. `below` = stack items beneath the [x,z,zg, operand block] (single-program threading behind the
    per-query openers, HP10-rest): every PICK is offset by `below`; default 0 keeps the stand-alone form (and its
    bytes) identical. Leaves [below.., q0, q1]; the caller drops the `below` items."""
    n_terms = 2 * n_flat + n_sel + 2
    NB = 3 * n_terms + 2
    total = below + 5 + 2 * NB                                  # below + x(1)+z(2)+z*g(2)+block(2*NB)
    invz_abs = below + 5 + 2 * (3 * n_terms)                   # limb pos of invz0 (== deep_quotient's invz slot)
    invzg_abs = below + 5 + 2 * (3 * n_terms + 1)              # limb pos of invzg0
    prog = []
    sp = [total]

    def pk(abs_pos):
        prog.extend([NUM(sp[0] - 1 - abs_pos), OP("PICK")]); sp[0] += 1

    def hint_check(z0_abs, z1_abs, inv_abs):                   # require inv * (x - z) == 1 (GF(p^2)), fail-closed
        pk(inv_abs); pk(inv_abs + 1)                           # invz0, invz1 (copies of the block's inverse)
        pk(below + 0); prog.append(NUM(0)); sp[0] += 1         # x, 0 -> base-lift (x, 0)
        pk(z0_abs); pk(z1_abs)                                 # z0, z1
        prog.extend(ext_sub_stack_prog()); sp[0] -= 2         # (x,0) - (z0,z1) = d = (x-z0, -z1)
        prog.extend(ext_inv_check_prog()); sp[0] -= 4        # inv * d == (1,0), consumes the 4 operands

    hint_check(below + 1, below + 2, invz_abs)                 # invz * (x_k - z) == 1
    hint_check(below + 3, below + 4, invzg_abs)                # invzg * (x_k - z*g) == 1
    assert sp[0] == total, "hint checks not net-0: sp=%d total=%d" % (sp[0], total)
    prog += deep_quotient_prog(n_flat, n_sel, below=below + 5)   # q(x_k) with the validated invz/invzg
    # deep_quotient leaves [below.., x,z0,z1,zg0,zg1, q0,q1]; drop the 5 x/z/z*g -> [below.., q0,q1]
    prog += [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * 5 + [OP("FROMALT"), OP("FROMALT")]
    return prog


def run_deep_query_quotient(n_flat, n_sel, x, z, zg, terms, invz, invzg):
    """Run deep_query_quotient_prog on real cashvm; ((q0,q1), op_cost) with q == q(x_k) if the hints validate,
    or (None, 0) on a fail-closed reject (a forged invz/invzg)."""
    vm = VM()
    try:
        unlock = ([NUM(x % P), NUM(z[0] % P), NUM(z[1] % P), NUM(zg[0] % P), NUM(zg[1] % P)]
                  + deep_quotient_unlock(terms, invz, invzg))
        vm.run(_field_prelude() + unlock + deep_query_quotient_prog(n_flat, n_sel))
        if len(vm.s) != 2:
            return None, 0
        return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost
    except VMError:
        return None, 0


def deep_sum_part_prog(n_part, carry_bound=False):
    """HP12/HP16 thin-shard: one <=3.3KB DEEP-quotient SUM-part. q(x_k) = invz*Sum_z + invzg*Sum_zg, where
    Sum_z = sum over the z-terms of alpha_i*(value_i-ood_i) and Sum_zg the z*g-terms (the invz/invzg is factored
    to the final combine). This part MAC-accumulates n_part terms into ONE carried accumulator, inverse-free:
    acc_out = acc_in + sum_i alpha_i*(value_i-ood_i), via the 0x28 DEEP MAC. The DEEP per-query verify is thus
    sharded into thin inputs (Sum_z 85 terms = 2822B, Sum_zg 53 terms = 1766B, both <=3300B thin-input / <=10000B
    consensus), mirroring HP9.7-9.8 comp_split_trans_part (single-acc carry). Unlock (bottom->top): acc_in(2) then
    [alpha,value,ood]*n_part. Leaves [acc_out0, acc_out1].

    HP9.8 carry_bound=True: the acc carry is SINGLE-SOURCED across the input boundary (R8-B1), mirroring
    comp_split_trans_part_prog. Unlock instead is [carry_out_preimage(16B)@0, carry_in_preimage(16B)@1,
    [alpha,value,ood]*n_part] -- the two 16-byte blobs occupy the same two stack slots acc_in's 2 limbs did, so
    the MAC compute is byte-for-byte unchanged. acc_in is split from carry_in_preimage (the prior part's
    carry_out, read via OP_INPUTBYTECODE in the deploy) instead of a free witness; the computed acc_out is BOUND
    to carry_out_preimage@0 (this part's exposed output) via _comp_producer_bind_prog (split_cells(2) +
    NUMEQUALVERIFY each limb), fail-closed -- a prover cannot expose a carry-out != its computation. Leaves [1]
    on accept. The cross-input read of carry_in is HP12/HP15 (cashvm cannot model OP_INPUTBYTECODE); the split
    arithmetic + producer self-bind + carry-chain is the cashvm-testable part here."""
    NB = 3 * n_part
    total = 2 + 2 * NB                                          # acc_in(2) | carry blobs(2) + operand block(2*NB)
    prog = [PUSH(_DEEP_MAC_FID), DEFINE(_deep_mac_body())]
    sp = [total]

    def pk(abs_pos):
        prog.extend([NUM(sp[0] - 1 - abs_pos), OP("PICK")]); sp[0] += 1

    def pk_ext(ext_idx):
        pk(2 + 2 * ext_idx); pk(2 + 2 * ext_idx + 1)          # operand block starts at limb 2 (above acc_in)

    if carry_bound:                                            # acc_in = split(carry_in_preimage @ stack item 1)
        prog.extend([NUM(sp[0] - 1 - 1), OP("PICK")]); sp[0] += 1
        prog.extend(split_cells_prog(2)); sp[0] += 1           # blob -> [acc_in0, acc_in1] (net +1)
    else:
        pk(0); pk(1)                                           # acc = acc_in (raw limbs)
    for i in range(n_part):
        pk_ext(3 * i); pk_ext(3 * i + 1); pk_ext(3 * i + 2)   # alpha_i, value_i, ood_i
        prog.extend([PUSH(_DEEP_MAC_FID), OP("INVOKE")]); sp[0] -= 6   # acc += alpha*(value-ood)
    if carry_bound:                                            # bind computed acc_out == carry_out_preimage @ 0
        prog += _comp_producer_bind_prog(total)               # -> [witness(total), 1]
        return prog + [OP("TOALT")] + [OP("DROP")] * total + [OP("FROMALT")]   # -> [1] on accept
    prog += [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * total + [OP("FROMALT"), OP("FROMALT")]
    return prog


def deep_sum_part_unlock(operands, acc_in, carry_bound=False, acc_out=None):
    """Push-only witness for deep_sum_part_prog: acc_in(2) then [alpha,value,ood]*n_part (each a GF(p^2) pair;
    value base-lifted (v,0) for trace/selector/range_weight or the ext comp(x_k)). HP9.8 carry_bound=True:
    instead pushes [carry_out_preimage(acc_out)@0, carry_in_preimage(acc_in)@1, [alpha,value,ood]*n_part] -- the
    two 16-byte blobs replace acc_in's 2 limbs at the same slots (acc_out is this part's computed output, required)."""
    if carry_bound:
        assert acc_out is not None, "carry_bound unlock needs the computed acc_out"
        w = [PUSH(_acc_preimage(acc_out)), PUSH(_acc_preimage(acc_in))]
    else:
        w = [NUM(acc_in[0] % P), NUM(acc_in[1] % P)]
    for alpha, value, ood in operands:
        w += [NUM(alpha[0] % P), NUM(alpha[1] % P), NUM(value[0] % P), NUM(value[1] % P),
              NUM(ood[0] % P), NUM(ood[1] % P)]
    return w


def run_deep_sum_part(operands, acc_in, carry_bound=False, acc_out=None):
    """Run one DEEP-quotient sum-part on cashvm; ((acc_out0, acc_out1), op_cost) = acc_in + sum alpha*(value-ood).
    HP9.8 carry_bound=True: run the DEPLOY producer-self-bind form (acc_in from carry_in_preimage, acc_out bound
    to carry_out_preimage); returns (1, op_cost) on accept, (None, 0) on a forged carry-out (fail-closed)."""
    vm = VM()
    try:
        vm.run(_field_prelude() + deep_sum_part_unlock(operands, acc_in, carry_bound, acc_out)
               + deep_sum_part_prog(len(operands), carry_bound))
        if carry_bound:
            if len(vm.s) != 1 or decode_num(vm.s[-1]) != 1:
                return None, 0
            return 1, vm.op_cost
        if len(vm.s) != 2:
            return None, 0
        return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost
    except VMError:
        return None, 0


_DEEP_MAC_LAZY_FID = b"\x29"


def _deep_mac_lazy_body():
    """[acc0,acc1, alpha0,alpha1, value0,value1, ood0,ood1] -> [acc0+r0, acc1+r1] over GF(p^2), RAW (unreduced): the
    lazy DEEP MAC. d=value-ood is reduced (SUBMOD, 8-byte operands); the direct GF(p^2) product r0=a0*d0+EXT_W*a1*d1,
    r1=a0*d1+a1*d0 (all-positive, no Karatsuba subtraction) is added to the accumulators WITHOUT reduction. DEFINE'd
    once (0x29) so the redeem stays small (like the eager 0x28); the single mod-p reduction is done by the caller after
    all INVOKEs. Operands at fixed abs positions (acc0=0..ood1=7). r0/r1 are stashed on the alt (above the field
    prelude's p, net-0) while the 8 operands are dropped, then folded into the accumulators."""
    sp = [8]; prog = []
    def copy(ap): prog.extend([NUM(sp[0] - 1 - ap), OP("PICK")]); sp[0] += 1
    def pick(d): prog.extend([NUM(d), OP("PICK")]); sp[0] += 1
    def over(): prog.append(OP("OVER")); sp[0] += 1
    def mul(): prog.append(OP("MUL")); sp[0] -= 1
    def add(): prog.append(OP("ADD")); sp[0] -= 1
    def pushn(k): prog.append(NUM(k)); sp[0] += 1
    def sm(): prog.extend(SM()); sp[0] -= 1
    copy(4); copy(6); sm()                                   # d0 = value0 - ood0
    copy(5); copy(7); sm()                                   # d1 = value1 - ood1
    over(); copy(2); mul()                                   # d0*alpha0
    pick(1); copy(3); mul(); pushn(EXT_W); mul(); add()      # + d1*alpha1*EXT_W -> r0
    pick(1); copy(2); mul()                                  # d1*alpha0
    pick(3); copy(3); mul(); add()                           # + d0*alpha1 -> r1
    prog += [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * 8 + [OP("FROMALT"), OP("FROMALT")]   # stash r, drop 8 operands, restore
    prog += [OP("SWAP"), NUM(3), OP("ROLL"), OP("ADD"), OP("SWAP"), NUM(2), OP("ROLL"), OP("ADD")]  # acc0+=r0; acc1+=r1
    return prog


def deep_sum_part_lazy_prog(n_part):
    """HP16 op-cost lever: the DEEP sum-part with LAZY (deferred) modular reduction. acc_out = acc_in + sum_i
    alpha_i*(value_i-ood_i) over GF(p^2), EXACTLY == deep_sum_part_prog, but instead of the reduced GF(p^2) MAC (0x28,
    each term a MULMOD = OP_MUL + a 2x-OP_MOD NORM_TAIL) it INVOKEs the RAW lazy MAC (0x29): (value_i-ood_i) reduced
    (SUBMOD) then the raw limb products alpha*(value-ood) accumulated UNREDUCED, reducing acc0/acc1 mod p ONCE at the
    end. IDENTICAL field element (same value mod p, partial sums left unreduced -- BCH BigInt holds the ~18-byte
    accumulator), ZERO soundness/security impact. The 0x29 body is DEFINE'd (redeem stays small like the eager form),
    so the op-cost drops ~3x on the real BCH-2026 VM WITHOUT growing the redeem -> the op-cost-density byte floor of the
    op-cost-bound DEEP shards (the make-or-break wall, ~3773B) collapses to ~1270B, i.e. the shards go BYTE-bound at
    their much smaller content. Unlock (bottom->top): acc_in(2), [alpha0,alpha1,value0,value1,ood0,ood1]*n_part -- SAME
    layout as deep_sum_part_unlock. Leaves [acc_out0, acc_out1] (reduced)."""
    total = 2 + 6 * n_part
    prog = [PUSH(_DEEP_MAC_LAZY_FID), DEFINE(_deep_mac_lazy_body())]
    sp = [total]
    def copy(ap): prog.extend([NUM(sp[0] - 1 - ap), OP("PICK")]); sp[0] += 1
    copy(0); copy(1)                                          # float running acc = acc_in (raw)
    for i in range(n_part):
        b = 2 + 6 * i
        for off in range(6):                                 # copy alpha0,alpha1,value0,value1,ood0,ood1
            copy(b + off)
        prog.extend([PUSH(_DEEP_MAC_LAZY_FID), OP("INVOKE")]); sp[0] -= 6   # acc += raw(alpha*(value-ood))
    prog += [OP("SWAP")] + NORM_TAIL + [OP("SWAP")] + NORM_TAIL             # reduce acc1, acc0 once
    prog += [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * total + [OP("FROMALT"), OP("FROMALT")]
    return prog


def run_deep_sum_part_lazy(operands, acc_in):
    """Run deep_sum_part_lazy_prog on cashvm; ((acc_out0, acc_out1), op_cost) == deep_sum_part (eager). Same unlock
    layout as deep_sum_part_unlock (acc_in + [alpha,value,ood]*n)."""
    vm = VM()
    vm.run(_field_prelude() + deep_sum_part_unlock(operands, acc_in) + deep_sum_part_lazy_prog(len(operands)))
    assert len(vm.s) == 2, "deep_sum_part_lazy left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


def deep_sum_part_blob_prog(n_part, n_terms, term_idx, carry_bound=False):
    """HP12.3/R4-B1: the BLOB-SOURCED DEEP sum-part -- the deploy-SOUND form of deep_sum_part. alpha_i and ood_i are
    read SINGLE-SOURCE from the ONE FS blob (at the baked GLOBAL term index term_idx[i], canonical deep_alphas
    order) instead of a free per-input witness. WHY (R4-B1): alpha/ood are GLOBAL (drawn once from the FS), not
    per-query; the DEEP trace-term (c(x)-c(z))/(x-z) is LINEAR in c(z), so a free per-input ood would let a prover
    commit q==0 (trivially low-degree, FRI passes) and forge acceptance. Single-sourcing them from the committed
    blob closes that. value_i stays a witness here (in the deploy it is single-sourced cross-input from the opener
    inputs, HP10.2/4j). The shard's term indices are NON-contiguous (the z-shard and z*g-shard interleave in the
    blob: trace col c -> term 2c is z, 2c+1 is z*g), so the whole blob is split (split_cells_loop, O(1) bytes;
    4+4*n_terms cells on the stack, < MAX_STACK) and each term's alpha/ood is PICK'd by baked index. MAC-accumulates
    n_part terms into ONE carried accumulator (0x28 DEEP MAC), inverse-free, exactly like deep_sum_part_prog. Unlock
    (bottom->top): acc_in(2), value_i(2)*n_part, blob(1 push = _deep_blob_bytes; in the deploy read cross-input via
    OP_INPUTBYTECODE from the FS covenant). Leaves [acc_out0, acc_out1]. The blob positions are validated == the
    witness-sourced deep_sum_part on real deep proofs (self_test), so a tampered blob ood yields a different sum."""
    assert len(term_idx) == n_part, "term_idx must list the n_part global term indices this shard MACs"
    n_blob = 4 + 4 * n_terms                                    # z(2)+z*g(2)+ood(2*n_terms)+alpha(2*n_terms)
    prog = [PUSH(_DEEP_MAC_FID), DEFINE(_deep_mac_body())]
    prog += list(split_cells_loop(n_blob, prefix=0))           # blob(top) -> n_blob cells on top (free alt)
    blob_base = 2 + 2 * n_part                                  # abs pos of blob cell 0
    ood_base = blob_base + 4                                    # ood_t ext at ood_base + 2*t
    alpha_base = blob_base + 4 + 2 * n_terms                    # alpha_t ext at alpha_base + 2*t
    total = 2 + 2 * n_part + n_blob
    sp = [total]

    def copy(abs_pos):
        prog.extend([NUM(sp[0] - 1 - abs_pos), OP("PICK")]); sp[0] += 1

    if carry_bound:                                           # deploy chain: acc_in = split(carry_in_preimage@1)
        prog.extend([NUM(sp[0] - 1 - 1), OP("PICK")]); sp[0] += 1
        prog.extend(split_cells_prog(2)); sp[0] += 1           # blob -> [acc_in0, acc_in1] (net +1)
    else:
        copy(0); copy(1)                                      # acc = acc_in (raw limbs)
    for i in range(n_part):
        t = term_idx[i]
        copy(alpha_base + 2 * t); copy(alpha_base + 2 * t + 1)     # alpha_t (blob, single-source)
        copy(2 + 2 * i); copy(2 + 2 * i + 1)                       # value_i (witness; opener cross-input in deploy)
        copy(ood_base + 2 * t); copy(ood_base + 2 * t + 1)         # ood_t (blob, single-source)
        prog.extend([PUSH(_DEEP_MAC_FID), OP("INVOKE")]); sp[0] -= 6   # acc += alpha*(value-ood)
    if carry_bound:                                           # bind computed acc_out == carry_out_preimage@0 (R8-B1)
        prog += _comp_producer_bind_prog(total)               # -> [witness(total), 1]
        return prog + [OP("TOALT")] + [OP("DROP")] * total + [OP("FROMALT")]   # -> [1] on accept
    prog += [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * total + [OP("FROMALT"), OP("FROMALT")]
    return prog


def deep_sum_part_blob_unlock(acc_in, values, z, zg, terms_ao, carry_bound=False, acc_out=None):
    """Push-only witness for deep_sum_part_blob_prog (bottom->top): acc_in(2), value_i(2)*n_part, then the FS blob
    (_deep_blob_bytes(z, z*g, ALL terms_ao) -- in the deploy read cross-input, not pushed). terms_ao = (alpha, ood)
    per term in canonical deep_alphas order (ALL n_terms); values = the value ext per shard term (in term_idx order).
    HP9.8 carry_bound=True (deploy chain): instead pushes [carry_out_preimage(acc_out)@0, carry_in_preimage(acc_in)@1,
    value_i(2)*n_part, blob] -- the two 16-byte blobs replace acc_in's 2 limbs at the same slots (acc_out required)."""
    if carry_bound:
        assert acc_out is not None, "carry_bound unlock needs the computed acc_out"
        w = [PUSH(_acc_preimage(acc_out)), PUSH(_acc_preimage(acc_in))]
    else:
        w = [NUM(acc_in[0] % P), NUM(acc_in[1] % P)]
    for v in values:
        w += [NUM(v[0] % P), NUM(v[1] % P)]
    return w + [PUSH(_deep_blob_bytes(z, zg, terms_ao))]


def run_deep_sum_part_blob(acc_in, values, z, zg, terms_ao, term_idx, carry_bound=False, acc_out=None):
    """Run the blob-sourced DEEP sum-part on cashvm; ((acc_out0, acc_out1), op_cost) = acc_in + sum over the shard
    term_idx of alpha_t*(value_i-ood_t), alpha_t/ood_t read from the blob. (None, 0) on a fail-closed reject. HP9.8
    carry_bound=True: the DEPLOY producer self-bind form (acc_in from carry_in_preimage, acc_out bound to
    carry_out_preimage); returns (1, op_cost) on accept, (None, 0) on a forged carry-out (fail-closed)."""
    vm = VM()
    try:
        vm.run(_field_prelude() + deep_sum_part_blob_unlock(acc_in, values, z, zg, terms_ao, carry_bound, acc_out)
               + deep_sum_part_blob_prog(len(values), len(terms_ao), term_idx, carry_bound))
        if carry_bound:
            if len(vm.s) != 1 or decode_num(vm.s[-1]) != 1:
                return None, 0
            return 1, vm.op_cost
        if len(vm.s) != 2:
            return None, 0
        return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost
    except VMError:
        return None, 0


def _deep_term_is_z(t, n_flat, n_sel):
    """HP12.3 Design A: which accumulator a global DEEP term goes to (canonical deep_alphas order). Trace col c ->
    term 2c is the z-term (ood P_c(z)), 2c+1 the z*g-term (ood P_c(z*g)); the n_sel selectors (terms
    2*n_flat..2*n_flat+n_sel-1) are z; range_weight (2*n_flat+n_sel) is z*g; comp (2*n_flat+n_sel+1) is z. Mirrors
    the _zt/_zgt split (query_terms). BAKED (never a witness) -> a prover cannot reroute a term."""
    if t < 2 * n_flat:
        return t % 2 == 0
    if t < 2 * n_flat + n_sel:
        return True
    return t == 2 * n_flat + n_sel + 1


def deep_sum_part_dual_prog(lo, hi, n_flat, n_sel, carry_bound=False, lazy=False):
    """HP12.3/R4-B1 Design A: a CONTIGUOUS-range DUAL-accumulator DEEP sum-part -- the op-cost-optimal deploy form.
    A shard covers the contiguous term range [lo, hi) and reads ONLY its ood[lo:hi]+alpha[lo:hi] SLICE (not the whole
    2+2+2*n_terms+2*n_terms-cell blob), so the on-VM split + op-cost scale with the SHARD, not the transcript -- the
    fix for the op-cost density that made the whole-blob form (deep_sum_part_blob) exceed the (41+unlock)*800 budget.
    Each term is MAC'd into acc_z OR acc_zg by the BAKED structural routing (_deep_term_is_z: the z/z*g split kept
    WITHIN the shard), so both partial sums are produced together and carry as a pair. alpha_i/ood_i are single-source
    from the slice (R4-B1); value_i is a witness here (opener cross-input in the deploy). Unlock (bottom->top):
    acc_z_in(2), acc_zg_in(2), value_i(2)*(hi-lo), slice(1 push = ood[lo:hi]||alpha[lo:hi]). Leaves [acc_z_out(2),
    acc_zg_out(2)]. The z-loop floats acc_z on top, then the zg-loop floats acc_zg above it -- the 0x28 MAC only
    touches the top acc, the deeper one is untouched (no alt stash -> no conflict with the field prelude's P on the
    alt). Validated == the GF(p^2) reference (self_test, real deep proofs).

    HP16.1 lazy=True: the op-cost lever -- INVOKE the RAW lazy MAC (0x29) instead of the reduced 0x28, keeping each
    accumulator UNREDUCED across its loop and reducing it mod p ONCE (SWAP+NORM_TAIL, net-0) right after that loop,
    BEFORE the carry-expose. Mathematically IDENTICAL to the eager form (same field element mod p; the direct-form
    r0=a0*d0+EXT_W*a1*d1, r1=a0*d1+a1*d0 is all-positive so the raw accumulator stays non-negative and NORM_TAIL's
    MOD reduces it exactly) -> ZERO soundness/security impact, and the carry format (32B = 4x8B reduced limbs) is
    byte-identical. The two net-0 reductions keep sp-tracking IDENTICAL to eager, so every PICK depth is unchanged;
    only the DEFINE'd body (0x29) and the two reductions differ. On the real BCH-2026 VM this drops the shard op-cost
    ~2x (op-cost floor ~3913B -> ~1885B per shard) WITHOUT growing the redeem (the 0x29 body is DEFINE'd) -> the
    op-cost-bound DEEP shard goes byte-bound. lazy=False stays the differential-test oracle (== lazy in self_test)."""
    n_r = hi - lo
    n_sl = 4 * n_r                                             # ood[lo:hi](2*n_r) + alpha[lo:hi](2*n_r) cells
    _fid = _DEEP_MAC_LAZY_FID if lazy else _DEEP_MAC_FID       # lazy: raw MAC 0x29 (deferred mod-p reduction)
    prog = [PUSH(_fid), DEFINE(_deep_mac_lazy_body() if lazy else _deep_mac_body())]
    prog += list(split_cells_loop(n_sl, prefix=0))            # slice(top) -> n_sl cells on top
    base = 2 if carry_bound else 4                             # carry: carry_out_pre@0 + carry_in_pre@1 ; else 4 raw acc limbs
    total = base + 2 * n_r + n_sl                              # (acc pair | carry pair)+value(2*n_r)+slice
    sl = base + 2 * n_r                                        # abs pos of slice cell 0
    ood_b = sl                                                 # ood_i @ ood_b + 2*i
    alpha_b = sl + 2 * n_r                                     # alpha_i @ alpha_b + 2*i
    sp = [total]

    def copy(ap):
        prog.extend([NUM(sp[0] - 1 - ap), OP("PICK")]); sp[0] += 1

    def mac_term(i):
        copy(alpha_b + 2 * i); copy(alpha_b + 2 * i + 1)      # alpha_i (slice, single-source)
        copy(base + 2 * i); copy(base + 2 * i + 1)            # value_i (witness; opener cross-input in deploy)
        copy(ood_b + 2 * i); copy(ood_b + 2 * i + 1)          # ood_i (slice, single-source)
        prog.extend([PUSH(_fid), OP("INVOKE")]); sp[0] -= 6   # acc += alpha*(value-ood)  (0x28 eager | 0x29 raw lazy)

    if carry_bound:                                           # acc_z_in/acc_zg_in = split(carry_in_preimage@1) -> 4 limbs on top
        copy(1); prog.extend(split_cells_prog(4, prefix=0)); sp[0] += 3
        az = total                                            # acc_z0@total, acc_z1@total+1, acc_zg0@total+2, acc_zg1@total+3
    else:
        az = 0                                                # acc_z0@0, acc_z1@1, acc_zg0@2, acc_zg1@3 (raw)
    copy(az); copy(az + 1)                                    # acc_z running (floats on top)
    for i in range(n_r):
        if _deep_term_is_z(lo + i, n_flat, n_sel):
            mac_term(i)
    if lazy:                                                  # reduce the RAW acc_z ONCE (net-0) before acc_zg floats above
        prog += [OP("SWAP")] + NORM_TAIL + [OP("SWAP")] + NORM_TAIL
    copy(az + 2); copy(az + 3)                                # acc_zg running (floats above acc_z)
    for i in range(n_r):
        if not _deep_term_is_z(lo + i, n_flat, n_sel):
            mac_term(i)
    if lazy:                                                  # reduce the RAW acc_zg ONCE (net-0) before the carry-expose
        prog += [OP("SWAP")] + NORM_TAIL + [OP("SWAP")] + NORM_TAIL
    if carry_bound:                                           # self-bind computed (acc_z, acc_zg) [top 4] == carry_out_preimage@0
        tb = total + 4                                        # witness + 4 acc_in limbs below the computed accs
        copy(0); prog.extend(split_cells_prog(4, prefix=0)); sp[0] += 3   # carry_out_pre -> [p0,p1,p2,p3]
        copy(tb + 3); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2       # p3 == acc_zg1
        copy(tb + 2); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2       # p2 == acc_zg0
        copy(tb + 1); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2       # p1 == acc_z1
        copy(tb + 0); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2       # p0 == acc_z0
        prog += [OP("2DROP"), OP("2DROP"), NUM(1)]           # drop the 4 computed acc limbs -> [tb items, 1]
        return prog + [OP("TOALT")] + [OP("DROP")] * tb + [OP("FROMALT")]   # -> [1] on accept
    prog += [OP("TOALT")] * 4 + [OP("DROP")] * total + [OP("FROMALT")] * 4   # -> [acc_z(2), acc_zg(2)]
    return prog


def deep_sum_part_dual_unlock(acc_z_in, acc_zg_in, values, ood_slice, alpha_slice, carry_bound=False,
                              acc_z_out=None, acc_zg_out=None):
    """Push-only witness for deep_sum_part_dual_prog (bottom->top): acc_z_in(2), acc_zg_in(2), value_i(2)*(hi-lo),
    then the slice (ood[lo:hi] cells then alpha[lo:hi] cells -- in the deploy read cross-input from the FS blob, not
    pushed). values/ood_slice/alpha_slice are per-term in range order (index i = term lo+i). HP9.8 carry_bound=True
    (deploy chain): instead pushes [carry_out_preimage(32B: acc_z_out||acc_zg_out)@0, carry_in_preimage(32B:
    acc_z_in||acc_zg_in)@1, value_i(2)*(hi-lo), slice] -- the two 32B blobs replace acc's 4 raw limbs (acc_*_out required)."""
    if carry_bound:
        assert acc_z_out is not None and acc_zg_out is not None, "carry_bound unlock needs the computed acc_z_out/acc_zg_out"
        w = [PUSH(_acc_preimage(acc_z_out) + _acc_preimage(acc_zg_out)),      # carry_out_preimage @ 0 (32B)
             PUSH(_acc_preimage(acc_z_in) + _acc_preimage(acc_zg_in))]        # carry_in_preimage @ 1 (32B)
    else:
        w = [NUM(acc_z_in[0] % P), NUM(acc_z_in[1] % P), NUM(acc_zg_in[0] % P), NUM(acc_zg_in[1] % P)]
    for v in values:
        w += [NUM(v[0] % P), NUM(v[1] % P)]
    blob = (b"".join(enc8(c[0] % P) + enc8(c[1] % P) for c in ood_slice)
            + b"".join(enc8(c[0] % P) + enc8(c[1] % P) for c in alpha_slice))
    return w + [PUSH(blob)]


def run_deep_sum_part_dual(lo, hi, n_flat, n_sel, acc_z_in, acc_zg_in, values, ood_slice, alpha_slice,
                           carry_bound=False, acc_z_out=None, acc_zg_out=None, lazy=False):
    """Run the contiguous-range dual sum-part on cashvm; ((acc_z_out, acc_zg_out), op_cost) = the two partial sums
    over [lo,hi) routed by _deep_term_is_z. (None, 0) on a fail-closed reject. HP9.8 carry_bound=True: the DEPLOY
    producer self-bind form (acc_in from carry_in_preimage, computed (acc_z, acc_zg) bound to carry_out_preimage);
    returns (1, op_cost) on accept, (None, 0) on a forged carry-out (fail-closed)."""
    vm = VM()
    try:
        vm.run(_field_prelude() + deep_sum_part_dual_unlock(acc_z_in, acc_zg_in, values, ood_slice, alpha_slice,
                                                            carry_bound, acc_z_out, acc_zg_out)
               + deep_sum_part_dual_prog(lo, hi, n_flat, n_sel, carry_bound, lazy))
        if carry_bound:
            if len(vm.s) != 1 or decode_num(vm.s[-1]) != 1:
                return None, 0
            return 1, vm.op_cost
        if len(vm.s) != 4:
            return None, 0
        return ((decode_num(vm.s[-4]), decode_num(vm.s[-3])), (decode_num(vm.s[-2]), decode_num(vm.s[-1]))), vm.op_cost
    except VMError:
        return None, 0


def deep_sum_part_dual_loop_prog(nz, nzg):
    """HP16.1 THE byte lever (enabled by lazy -> shards byte-bound): the DUAL sum-part with the per-term MAC LOOPED
    via BEGIN/UNTIL instead of nz+nzg unrolled mac_terms, so the shard redeem collapses (~2510B -> ~330B) -- the
    dominant whole-tx duplication (the 70-term MAC logic revealed once per query per window, 12x) is amortized to one
    loop body. Mathematically IDENTICAL to deep_sum_part_dual (== eager, validated on real deep proofs): raw lazy MAC
    (0x29, no NORM_TAIL in the body -> no P-on-alt conflict), reduce each acc ONCE. Operands laid out z-CONTIGUOUS then
    zg-contiguous (the loop consumes a contiguous block); acc_z is reduced BETWEEN the two loops (so the end has no
    alt/P conflict). Unlock (bottom->top): acc_z_in(2), acc_zg_in(2), zg-ops(6*nzg), z-ops(6*nz) [z on top = processed
    first], each op = [alpha0,alpha1,value0,value1,ood0,ood1]. Leaves [acc_z(2), acc_zg(2)].

    KEY MECHANISM (pick-depth invariance): with the running acc on top and the top unprocessed term just below it, all 6
    of that term's operands sit at the SAME pick-depth (7 in the z-loop; 9 in the zg-loop, where acc_z_red(2) sits
    between acc_zg and the zg-ops), because each PICK grows sp by 1 exactly as the next operand's stack offset grows by
    1. After INVOKE the term is CONSUMED (stash the acc(s) transiently to the alt above P, 2DROP the 6 operands, restore).
    The count is PINNED by OP_DEPTH (exit when only the acc_in pair + the running acc remain) -- a prover cannot pad/skip
    terms (the z/zg op counts are structural, baked via nz/nzg). Op-cost stays byte-bound (the loop adds only control ops)."""
    prog = [PUSH(_DEEP_MAC_LAZY_FID), DEFINE(_deep_mac_lazy_body())]
    total = 4 + 6 * (nz + nzg)
    prog += [NUM(total - 1), OP("PICK"), NUM(total - 1), OP("PICK")]            # float acc_z = acc_z_in (both at depth total-1)
    zbody = ([NUM(7), OP("PICK")] * 6 + [PUSH(_DEEP_MAC_LAZY_FID), OP("INVOKE")]
             + [OP("TOALT"), OP("TOALT"), OP("2DROP"), OP("2DROP"), OP("2DROP"), OP("FROMALT"), OP("FROMALT")])
    prog += [OP("BEGIN")] + zbody + [OP("DEPTH"), NUM(6 + 6 * nzg), OP("NUMEQUAL"), OP("UNTIL")]   # z-loop; exit when z-ops gone
    prog += [OP("SWAP")] + NORM_TAIL + [OP("SWAP")] + NORM_TAIL                 # reduce acc_z ONCE (top)
    d = 6 + 6 * nzg
    prog += [NUM(d - 1 - 2), OP("PICK"), NUM(d - 1 - 2), OP("PICK")]            # float acc_zg = acc_zg_in (both at depth d-3)
    zgbody = ([NUM(9), OP("PICK")] * 6 + [PUSH(_DEEP_MAC_LAZY_FID), OP("INVOKE")]
              + [OP("TOALT"), OP("TOALT"), OP("TOALT"), OP("TOALT"),           # stash acc_zg'(2) + acc_z_red(2)
                 OP("2DROP"), OP("2DROP"), OP("2DROP"),                          # drop the 6 zg-ops
                 OP("FROMALT"), OP("FROMALT"), OP("FROMALT"), OP("FROMALT")])   # restore acc_z_red(2), acc_zg'(2)
    prog += [OP("BEGIN")] + zgbody + [OP("DEPTH"), NUM(8), OP("NUMEQUAL"), OP("UNTIL")]   # zg-loop; exit when zg-ops gone
    prog += [OP("SWAP")] + NORM_TAIL + [OP("SWAP")] + NORM_TAIL                 # reduce acc_zg ONCE (top)
    prog += [OP("TOALT"), OP("TOALT"), OP("TOALT"), OP("TOALT"),               # -> [acc_z_red(2), acc_zg_red(2)]; drop acc_in pair
             OP("2DROP"), OP("2DROP"), OP("FROMALT"), OP("FROMALT"), OP("FROMALT"), OP("FROMALT")]
    return prog


def _deep_dual_zsplit(lo, hi, n_flat, n_sel):
    """The z-term and zg-term local indices (i, term lo+i) of a window, for the looped dual's z-contiguous layout."""
    z_idx = [i for i in range(hi - lo) if _deep_term_is_z(lo + i, n_flat, n_sel)]
    zg_idx = [i for i in range(hi - lo) if not _deep_term_is_z(lo + i, n_flat, n_sel)]
    return z_idx, zg_idx


def deep_sum_part_dual_loop_unlock(lo, hi, n_flat, n_sel, acc_z_in, acc_zg_in, values, ood_slice, alpha_slice):
    """Push-only witness for deep_sum_part_dual_loop_prog (bottom->top): acc_z_in(2), acc_zg_in(2), zg-ops(6*nzg),
    z-ops(6*nz) -- ops reordered z-contiguous/zg-contiguous (z on top). values/ood_slice/alpha_slice are per-term in
    range order (index i = term lo+i), same as deep_sum_part_dual_unlock."""
    z_idx, zg_idx = _deep_dual_zsplit(lo, hi, n_flat, n_sel)
    w = [NUM(acc_z_in[0] % P), NUM(acc_z_in[1] % P), NUM(acc_zg_in[0] % P), NUM(acc_zg_in[1] % P)]
    for i in zg_idx + z_idx:                                                    # zg-ops (bottom) then z-ops (top)
        w += [NUM(alpha_slice[i][0] % P), NUM(alpha_slice[i][1] % P), NUM(values[i][0] % P), NUM(values[i][1] % P),
              NUM(ood_slice[i][0] % P), NUM(ood_slice[i][1] % P)]
    return w


def run_deep_sum_part_dual_loop(lo, hi, n_flat, n_sel, acc_z_in, acc_zg_in, values, ood_slice, alpha_slice):
    """Run the LOOPED dual sum-part on cashvm; ((acc_z_out, acc_zg_out), op_cost) == run_deep_sum_part_dual (identical)."""
    z_idx, zg_idx = _deep_dual_zsplit(lo, hi, n_flat, n_sel)
    vm = VM()
    try:
        vm.run(_field_prelude()
               + deep_sum_part_dual_loop_unlock(lo, hi, n_flat, n_sel, acc_z_in, acc_zg_in, values, ood_slice, alpha_slice)
               + deep_sum_part_dual_loop_prog(len(z_idx), len(zg_idx)))
        if len(vm.s) != 4:
            return None, 0
        return ((decode_num(vm.s[-4]), decode_num(vm.s[-3])), (decode_num(vm.s[-2]), decode_num(vm.s[-1]))), vm.op_cost
    except VMError:
        return None, 0


# --- HP16.1 THE realized byte lever: the looped shard consuming BYTE-STRINGS (blob slice + witness) instead of a
#     pre-split PICK-layout, so NO on-VM PICK-depth arithmetic is needed. A byte-level interleave-and-ROUTE reshapes
#     the three term-order strings (alpha, value, ood) into a z-string and a zg-string (chunk = alpha16||value16||ood16
#     per term, routed by the pure-trace z/zg alternation), each then split + MAC'd by the validated single-acc lazy
#     loop. Redeem collapses ~2510B -> ~330B (route + prelude + 2 split loops + 2 mac loops, revealed ONCE per shard).
#     alt layout during the byte-only route: [z_out, zg_out] (no field prelude yet -> the alt is free). Validated == the
#     GF(p^2) reference (self_test, real deep proofs). Pure-trace windows (terms alternate z,zg); a mixed window's
#     sel/range_weight/comp tail keeps the unrolled dual (small).
_DEEP_ROUTE_CHUNK = ([NUM(16), OP("SPLIT"), NUM(2), OP("ROLL"), NUM(16), OP("SPLIT"), NUM(4), OP("ROLL"), NUM(16),
                      OP("SPLIT"), NUM(1), OP("ROLL"), NUM(3), OP("ROLL"), OP("CAT"), NUM(4), OP("ROLL"), OP("CAT")])
_DEEP_ROUTE_REORDER = [NUM(2), OP("ROLL"), NUM(2), OP("ROLL"), OP("SWAP")]     # [O_tail,V_tail,A_tail] -> [A_tail,V_tail,O_tail]


def _deep_route_prog():
    """[alpha_str, value_str, ood_str] (term order, 2n cells, z/zg-alternating) -> [z_str, zg_str] (zg on top). Byte-only.
    Per pair: build chunk_2c (z) -> z_out, chunk_2c+1 (zg) -> zg_out (two alt accumulators). Count pinned by OP_SIZE
    (alpha drained)."""
    append_zg = [OP("FROMALT"), OP("SWAP"), OP("CAT"), OP("TOALT")] + _DEEP_ROUTE_REORDER
    append_z = ([OP("FROMALT"), OP("FROMALT"), NUM(2), OP("ROLL"), OP("CAT"), OP("TOALT"), OP("TOALT")]
                + _DEEP_ROUTE_REORDER)
    body = _DEEP_ROUTE_CHUNK + append_z + _DEEP_ROUTE_CHUNK + append_zg
    return ([PUSH(b""), OP("TOALT"), PUSH(b""), OP("TOALT"), OP("BEGIN")] + body
            + [NUM(2), OP("PICK"), OP("SIZE"), OP("NIP"), NUM(0), OP("NUMEQUAL"), OP("UNTIL"),
               OP("2DROP"), OP("DROP"), OP("FROMALT"), OP("FROMALT"), OP("SWAP")])


def _deep_mac_loop(base_keep):
    """Interleaved [alpha,value,ood] cells on top, `base_keep` items preserved below. acc=(0,0), lazy MAC loop (0x29,
    pick-depth 7, OP_DEPTH-pinned, term consumed after INVOKE), reduce ONCE -> Sum(2) on top. Requires the field
    prelude + the 0x29 DEFINE installed by the caller."""
    body = ([NUM(7), OP("PICK")] * 6 + [PUSH(_DEEP_MAC_LAZY_FID), OP("INVOKE")]
            + [OP("TOALT"), OP("TOALT"), OP("2DROP"), OP("2DROP"), OP("2DROP"), OP("FROMALT"), OP("FROMALT")])
    return ([NUM(0), NUM(0), OP("BEGIN")] + body
            + [OP("DEPTH"), NUM(base_keep + 2), OP("NUMEQUAL"), OP("UNTIL")]
            + [OP("SWAP")] + NORM_TAIL + [OP("SWAP")] + NORM_TAIL)


def deep_sum_part_puretrace_loop_prog(nz, nzg):
    """HP16.1 realized: pure-trace looped shard. [alpha_str, value_str, ood_str] (term order) -> [Sum_z(2), Sum_zg(2)].
    interleave-route -> field prelude + 0x29 DEFINE -> split_cells + single-acc lazy MAC loop for zg then z. == the
    eager deep_sum_part_dual over the same terms. Redeem ~330B (revealed once/shard) vs ~2510B unrolled."""
    prog = list(_deep_route_prog())                            # -> [z_str, zg_str]
    prog += _field_prelude() + [PUSH(_DEEP_MAC_LAZY_FID), DEFINE(_deep_mac_lazy_body())]
    prog += list(split_cells_loop(6 * nzg, prefix=0))          # zg_str -> cells (z_str kept below)
    prog += _deep_mac_loop(base_keep=1)                        # -> [z_str, Sum_zg(2)]
    prog += [NUM(2), OP("ROLL")]                               # z_str -> top
    prog += list(split_cells_loop(6 * nz, prefix=0))           # z_str -> cells (Sum_zg kept below)
    prog += _deep_mac_loop(base_keep=2)                        # -> [Sum_zg(2), Sum_z(2)]
    return prog


def _deep_term_strings(lo, hi, values, ood_slice, alpha_slice):
    """The three term-order byte-strings (alpha, value, ood) a pure-trace looped shard consumes for [lo,hi)."""
    astr = b"".join(enc8(alpha_slice[i][0] % P) + enc8(alpha_slice[i][1] % P) for i in range(hi - lo))
    vstr = b"".join(enc8(values[i][0] % P) + enc8(values[i][1] % P) for i in range(hi - lo))
    ostr = b"".join(enc8(ood_slice[i][0] % P) + enc8(ood_slice[i][1] % P) for i in range(hi - lo))
    return astr, vstr, ostr


def run_deep_sum_part_puretrace_loop(lo, hi, n_flat, n_sel, values, ood_slice, alpha_slice):
    """Run the pure-trace looped shard on cashvm; ((Sum_z, Sum_zg), op_cost) == run_deep_sum_part_dual, or (None, 0).
    [lo,hi) must be a pure-trace window (all terms trace, z/zg-alternating)."""
    z_idx, zg_idx = _deep_dual_zsplit(lo, hi, n_flat, n_sel)
    astr, vstr, ostr = _deep_term_strings(lo, hi, values, ood_slice, alpha_slice)
    vm = VM()
    try:
        vm.run([PUSH(astr), PUSH(vstr), PUSH(ostr)] + deep_sum_part_puretrace_loop_prog(len(z_idx), len(zg_idx)))
        if len(vm.s) != 4:
            return None, 0
        return ((decode_num(vm.s[-2]) % P, decode_num(vm.s[-1]) % P),
                (decode_num(vm.s[-4]) % P, decode_num(vm.s[-3]) % P)), vm.op_cost
    except VMError:
        return None, 0


# --- HP16.1 THE net-positive deploy shard: the COUNTER-DRIVEN multi-block loop. Reads alpha_i/value_i/ood_i DIRECTLY
#     from three blocks (alpha, value, ood; term order) via counter-COMPUTED PICK depths -- NO byte-reshaping (no
#     route/CAT), so the op-cost stays ~ unrolled (real-libauth op-cost FLOOR ~2190B for the 104 trace terms, BOTH z+zg)
#     while the redeem collapses (the per-term MAC logic is one loop body). The route-based looped shard was op-cost-bound
#     because the interleave CAT added ~1.34M op-cost; this reads the operands in place instead. Net: shard goes op-cost-
#     bound at ~2190B vs the unrolled lazy byte-bound 3290B -> -1821B/shard. Derived depth formula: base state
#     [blocks(6N), t, acc0, acc1] (acc on top, t at depth 2); to copy the operand at abs A when `pushed` items already sit
#     above acc this iteration: PICK t (NUM(2+pushed) PICK), 2t (NUM 2 MUL), depth = C - 2t with C = 6N+2+extra+pushed-base
#     (base = A - 2t of the operand; `extra` = items between the blocks and this loop's [t,acc] frame). Two STRIDED loops
#     (z: start=0 step=2 ; zg: start=1 step=2 for a pure-trace window) route by the term parity WITHOUT any on-VM routing.
#     Validated == eager (self_test, real deep proofs; proto_counter_mac.py / proto_counter_dual.py).
def _deep_strided_mac_loop(N, start, step, count, extra, ba=None, bv=None, bo=None, B=None, opspec=None):
    """One strided counter-driven lazy MAC loop: acc = sum over t in {start, start+step, .., start+step*(count-1)} of
    alpha_t*(value_t-ood_t), reading term t's 6 operands from the alpha/value/ood cell-blocks via counter-computed PICK
    depths (abs = base + mult*t + off per operand). Block bases ba/bv/bo default to the [alpha(0),value(2N),ood(4N)]
    witness layout (abs = base + 2t, i.e. mult=2, off=0); the blob-sourced deploy form passes the actual arranged bases.
    `extra` = items sitting between the blocks and this loop's [t,acc] frame (0 for the first loop; 2 for the second).
    B = total block size in limbs (default 6N). opspec (loop#9 value-dedup) overrides the 6 per-operand (base, mult, off)
    triples -- e.g. the deduped shard reads value at a DISTINCT-cell block (mult=1: cell pos = t for the z-loop even
    t=2c, t-1 for the zg-loop odd t=2c+1) while alpha/ood stay per-term (mult=2). Default opspec == the mult=2 form
    (byte-identical to the prior version -> existing callers untouched). Pushes [t,0,0], loops, drops t, reduces acc
    ONCE; leaves [.., acc0_reduced, acc1_reduced] (blocks + extra preserved). Requires the 0x29 DEFINE + field prelude."""
    if ba is None:
        ba, bv, bo = 0, 2 * N, 4 * N
    if B is None:
        B = 6 * N
    if opspec is None:
        opspec = [(ba, 2, 0), (ba + 1, 2, 0), (bv, 2, 0), (bv + 1, 2, 0), (bo, 2, 0), (bo + 1, 2, 0)]
    prog = [NUM(start), NUM(0), NUM(0)]                          # [.., t, acc0, acc1]
    fetch = []
    for pushed, spec in enumerate(opspec):
        if len(spec) == 4 and spec[3] is not None:              # CONSTANT operand (value-source base cells: value1 = 0)
            fetch += [NUM(spec[3])]
            continue
        base, mult, off = spec[0], spec[1], spec[2]
        C = B + 2 + extra + pushed - base - off
        fetch += [NUM(2 + pushed), OP("PICK")]
        if mult != 1:
            fetch += [NUM(mult), OP("MUL")]                     # mult*t ; mult=1 skips the MUL (op-cost + byte saving)
        fetch += [NUM(C), OP("SWAP"), OP("SUB"), OP("PICK")]    # depth = C - mult*t
    body = (fetch + [PUSH(_DEEP_MAC_LAZY_FID), OP("INVOKE")]      # acc += raw(alpha*(value-ood)) ; -> [.., t, acc0, acc1]
            + [NUM(2), OP("ROLL"), NUM(step), OP("ADD"),          # t -> top, += step
               NUM(2), OP("ROLL"), NUM(2), OP("ROLL"),            # -> [.., t', acc0, acc1]
               NUM(2), OP("PICK"), NUM(start + step * count), OP("NUMEQUAL")])   # pinned count: exit when t == end
    prog += [OP("BEGIN")] + body + [OP("UNTIL")]
    prog += [OP("TOALT"), OP("TOALT"), OP("DROP"), OP("FROMALT"), OP("FROMALT")]  # drop t
    prog += [OP("SWAP")] + NORM_TAIL + [OP("SWAP")] + NORM_TAIL                   # reduce acc ONCE
    return prog


def deep_sum_part_counter_dual_prog(N, nz, nzg):
    """HP16.1 net-positive pure-trace dual shard: [alpha-block(2N), value-block(2N), ood-block(2N)] (term order,
    z/zg-alternating) -> [Sum_z(2), Sum_zg(2)]. Two strided counter-driven loops (z: even terms; zg: odd) share the
    blocks; no reshaping. == eager deep_sum_part_dual over the same terms. In the deploy alpha/ood come from the blob
    slice, value from the witness/opener (the blocks are split from those); op-cost-bound at ~2190B << the unrolled 3290B."""
    prog = [PUSH(_DEEP_MAC_LAZY_FID), DEFINE(_deep_mac_lazy_body())]
    prog += _deep_strided_mac_loop(N, 0, 2, nz, extra=0)         # z-terms (even) -> Sum_z (blocks kept)
    prog += _deep_strided_mac_loop(N, 1, 2, nzg, extra=2)        # zg-terms (odd) -> Sum_zg (Sum_z is the extra)
    prog += ([OP("TOALT"), OP("TOALT"), OP("TOALT"), OP("TOALT")] + [OP("DROP")] * (6 * N)
             + [OP("FROMALT"), OP("FROMALT"), OP("FROMALT"), OP("FROMALT")])     # drop blocks -> [Sum_z(2), Sum_zg(2)]
    return prog


def run_deep_sum_part_counter_dual(lo, hi, n_flat, n_sel, values, ood_slice, alpha_slice):
    """Run the counter-driven pure-trace dual shard on cashvm; ((Sum_z, Sum_zg), op_cost) == run_deep_sum_part_dual.
    [lo,hi) must be a pure-trace window (all terms trace, z/zg-alternating)."""
    z_idx, zg_idx = _deep_dual_zsplit(lo, hi, n_flat, n_sel)
    N = hi - lo
    u = []
    for i in range(N):
        u += [NUM(alpha_slice[i][0] % P), NUM(alpha_slice[i][1] % P)]
    for i in range(N):
        u += [NUM(values[i][0] % P), NUM(values[i][1] % P)]
    for i in range(N):
        u += [NUM(ood_slice[i][0] % P), NUM(ood_slice[i][1] % P)]
    vm = VM()
    try:
        vm.run(_field_prelude() + u + deep_sum_part_counter_dual_prog(N, len(z_idx), len(zg_idx)))
        if len(vm.s) != 4:
            return None, 0
        return ((decode_num(vm.s[-4]) % P, decode_num(vm.s[-3]) % P),
                (decode_num(vm.s[-2]) % P, decode_num(vm.s[-1]) % P)), vm.op_cost
    except VMError:
        return None, 0


def _counter_carry_bind_prog():
    """HP9.8/loop#9(c) shared carry-bind tail for the counter-driven deploy shards. The standalone loops leave the
    post-block-drop stack [carry_out_pre(32B)@0, carry_in_pre(32B)@1, Sl_z0@2, Sl_z1@3, Sl_zg0@4, Sl_zg1@5] (Sl_* = the
    partial sums from acc=0). This adds the carry_in (POST-loop, associative -> mathematically identical to threading
    acc_in through the loop init) then self-binds the total (Sum_z, Sum_zg) == carry_out_pre (fail-closed NUMEQUALVERIFY,
    R8-B1; mirrors deep_sum_part_dual_prog carry_bound). Leaves [1] on accept. The carry_out_pre push (the shard's first
    unlock push) is what the next chain part reads via OP_INPUTBYTECODE. carry_in_pre = ZERO for the first shard."""
    prog = []
    sp = [6]
    ADD = [OP("ADD")] + NORM_TAIL

    def pk(pos):
        prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1

    pk(1); prog += list(split_cells_prog(4, prefix=0)); sp[0] += 3   # carry_in_pre -> azi0@6,azi1@7,azgi0@8,azgi1@9
    pk(2); pk(6); prog += ADD; sp[0] -= 1                            # Sum_z0 = Sl_z0 + acc_z_in0
    pk(3); pk(7); prog += ADD; sp[0] -= 1                            # Sum_z1
    pk(4); pk(8); prog += ADD; sp[0] -= 1                            # Sum_zg0
    pk(5); pk(9); prog += ADD; sp[0] -= 1                            # Sum_zg1
    pk(0); prog += list(split_cells_prog(4, prefix=0)); sp[0] += 3   # carry_out_pre -> p0..p3
    pk(13); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2            # p3 == Sum_zg1
    pk(12); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2            # p2 == Sum_zg0
    pk(11); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2            # p1 == Sum_z1
    pk(10); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2            # p0 == Sum_z0
    prog += [OP("DROP")] * sp[0] + [NUM(1)]                          # drop the remaining scratch -> [1]
    return prog


def counter_carry_bind_ci_top_prog():
    """HP16.1 DEPLOY-CHAIN carry bind where carry_in is READ CROSS-INPUT (OP_INPUTBYTECODE from the predecessor's
    carry_out_pre push) and therefore lands on the stack TOP -- unlike _counter_carry_bind_prog where carry_in_pre is a
    push in this input's own unlock (@1). The full-tx assembly wires: [standalone counter-driven loops leaving
    carry_out_pre@0, Sl_z(2), Sl_zg(2)] ++ <read predecessor carry_out cross-input -> carry_in_pre(32B) on TOP> ++ this.
    Adds carry_in (post-loop, associative) then self-binds the total == carry_out_pre (fail-closed NUMEQUALVERIFY).
    -> [1]. Validated on the real BCH-2026 P2SH32 VM: 3-input blob+shardA+tail chain accepts, forged carry_out rejects
    (proto_chain_multi.py). Stack in: [carry_out_pre@0, Sl_z0@1, Sl_z1@2, Sl_zg0@3, Sl_zg1@4, carry_in_pre@5 (top)]."""
    prog = []
    sp = [6]
    ADD = [OP("ADD")] + NORM_TAIL

    def pk(pos):
        prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1

    prog += list(split_cells_prog(4, prefix=0)); sp[0] += 3          # carry_in_pre (top) -> azi0@5,azi1@6,azgi0@7,azgi1@8
    pk(1); pk(5); prog += ADD; sp[0] -= 1                            # Sum_z0 = Sl_z0 + acc_z_in0
    pk(2); pk(6); prog += ADD; sp[0] -= 1                            # Sum_z1
    pk(3); pk(7); prog += ADD; sp[0] -= 1                            # Sum_zg0
    pk(4); pk(8); prog += ADD; sp[0] -= 1                            # Sum_zg1
    pk(0); prog += list(split_cells_prog(4, prefix=0)); sp[0] += 3   # carry_out_pre -> p0..p3
    pk(12); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2            # p3 == Sum_zg1
    pk(11); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2            # p2 == Sum_zg0
    pk(10); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2            # p1 == Sum_z1
    pk(9); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2             # p0 == Sum_z0
    prog += [OP("DROP")] * sp[0] + [NUM(1)]
    return prog


def deep_sum_part_counter_dual_deploy_prog(N, nz, nzg, carry_bound=False):
    """HP16.1 DEPLOY form of the counter-driven dual shard: alpha/ood come from the FS blob slice, value from the
    witness/opener. Stack in (bottom->top): value-cells(2N NUMs), slice (= ood[.](2N cells) || alpha[.](2N cells), read
    cross-input from the blob). Splits the slice into alpha/ood cell-blocks (value stays NUMs -> no value split), arranges
    [value(0), alpha(2N), ood(4N)] via one cheap ROLL, then the counter-driven dual (bases value@0, alpha@2N, ood@4N).
    -> [Sum_z(2), Sum_zg(2)]. == eager deep_sum_part_dual. Real-P2SH32 op-cost 2.671M (op-cost-bound floor ~3301B) for
    104 trace terms << unrolled byte-bound ~6032B (31.7B/term vs 58B/term). Pure-trace windows only.

    loop#9(c) carry_bound=True: the cross-input carry-chain form -- the unlock instead has carry_out_pre(32B)@0 +
    carry_in_pre(32B)@1 at the bottom (below value-cells); the standalone loops run, then _counter_carry_bind_prog adds
    carry_in and self-binds the total == carry_out_pre (fail-closed). Leaves [1]. Enables shardA.carry_out ->
    tail.carry_in -> total for the full single-tx (HP16.1)."""
    prog = [NUM(16 * N), OP("SPLIT")]                            # [value-cells, ood_str, alpha_str]
    prog += list(split_cells_loop(2 * N, prefix=0))             # alpha_str -> alpha-cells  [value-cells, ood_str, alpha-cells]
    prog += [NUM(2 * N), OP("ROLL")] + list(split_cells_loop(2 * N, prefix=0))   # ood_str up -> ood-cells  [value-cells, alpha-cells, ood-cells]
    prog += [PUSH(_DEEP_MAC_LAZY_FID), DEFINE(_deep_mac_lazy_body())]
    prog += _deep_strided_mac_loop(N, 0, 2, nz, 0, ba=2 * N, bv=0, bo=4 * N)     # z-terms (even)
    prog += _deep_strided_mac_loop(N, 1, 2, nzg, 2, ba=2 * N, bv=0, bo=4 * N)    # zg-terms (odd)
    prog += ([OP("TOALT"), OP("TOALT"), OP("TOALT"), OP("TOALT")] + [OP("DROP")] * (6 * N)
             + [OP("FROMALT"), OP("FROMALT"), OP("FROMALT"), OP("FROMALT")])
    if carry_bound:
        prog += _counter_carry_bind_prog()
    return prog


def _counter_carry_unlock(values, ood_slice, alpha_slice, N, carry_bound, acc_z_in, acc_zg_in, acc_z_out, acc_zg_out):
    """Shared push-only unlock for the counter-driven deploy shards. Non-carry: [value-cells(2N), slice]. carry_bound:
    [carry_out_pre(32B)@0, carry_in_pre(32B)@1, value-cells(2N), slice]."""
    vcells = []
    for i in range(N):
        vcells += [NUM(values[i][0] % P), NUM(values[i][1] % P)]
    slice_ = (b"".join(enc8(ood_slice[i][0] % P) + enc8(ood_slice[i][1] % P) for i in range(N))
              + b"".join(enc8(alpha_slice[i][0] % P) + enc8(alpha_slice[i][1] % P) for i in range(N)))
    pre = []
    if carry_bound:
        pre = [PUSH(_acc_preimage(acc_z_out) + _acc_preimage(acc_zg_out)),
               PUSH(_acc_preimage(acc_z_in) + _acc_preimage(acc_zg_in))]
    return pre + vcells + [PUSH(slice_)]


def run_deep_sum_part_counter_dual_deploy(lo, hi, n_flat, n_sel, values, ood_slice, alpha_slice,
                                          carry_bound=False, acc_z_in=None, acc_zg_in=None, acc_z_out=None, acc_zg_out=None):
    """Run the blob-sourced counter-driven deploy shard on cashvm (slice pushed, not cross-input); ((Sum_z, Sum_zg),
    op_cost) == run_deep_sum_part_dual. [lo,hi) must be a pure-trace window. carry_bound=True: the chain form -- returns
    (1, op_cost) on accept (computed total == carry_out_pre), (None, 0) on a forged carry_out (fail-closed)."""
    z_idx, zg_idx = _deep_dual_zsplit(lo, hi, n_flat, n_sel)
    N = hi - lo
    u = _counter_carry_unlock(values, ood_slice, alpha_slice, N, carry_bound, acc_z_in, acc_zg_in, acc_z_out, acc_zg_out)
    vm = VM()
    try:
        vm.run(_field_prelude() + u + deep_sum_part_counter_dual_deploy_prog(N, len(z_idx), len(zg_idx), carry_bound))
        if carry_bound:
            if len(vm.s) != 1 or decode_num(vm.s[-1]) != 1:
                return None, 0
            return 1, vm.op_cost
        if len(vm.s) != 4:
            return None, 0
        return ((decode_num(vm.s[-4]) % P, decode_num(vm.s[-3]) % P),
                (decode_num(vm.s[-2]) % P, decode_num(vm.s[-1]) % P)), vm.op_cost
    except VMError:
        return None, 0


def deep_sum_part_dedup_prog(nf):
    """HP16.1/loop#9 VALUE-SINGLE-SOURCE pure-trace shard [0:2*nf) (R4-B1). The 2*nf trace terms reference only nf
    DISTINCT cells (term 2c and 2c+1 both use ck[c]); the trace cells are BASE field elements (value = (ck[c], 0), so
    the imaginary limb is 0). The value-block is thus nf BASE cells (nf limbs), read in the deploy CROSS-INPUT from the
    trace opener's exposed [nf cells|k] blob (deploy_check 4h; the opener merkle-verifies them vs tp_root, 4i root
    single-source) -> a prover cannot forge value_i. Blocks (bottom->top): value(nf base)@0, alpha(4nf per-term)@nf,
    ood(4nf)@5nf; B=9nf. Counter c=0..nf-1 (step 1): the z-loop does term 2c (alpha/ood @ base+4c, off_zg=0), the zg-loop
    term 2c+1 (base+4c+2, off_zg=2); value0 @ bv+c (mult=1), value1 = CONSTANT 0 (base cell). -> [Sum_z(2), Sum_zg(2)].
    == eager deep_sum_part_dual over the 2*nf trace terms. Validated real-libauth (proto_value_source.py: opener-sourced
    cells, forged-cell reject)."""
    bv, ba, bo = 0, nf, 5 * nf
    B = 9 * nf
    prog = [PUSH(_DEEP_MAC_LAZY_FID), DEFINE(_deep_mac_lazy_body())]
    spec_z = [(ba, 4, 0), (ba + 1, 4, 0), (bv, 1, 0), (None, 0, 0, 0), (bo, 4, 0), (bo + 1, 4, 0)]
    prog += _deep_strided_mac_loop(nf, 0, 1, nf, 0, B=B, opspec=spec_z)             # z-terms (2c) -> Sum_z
    spec_zg = [(ba, 4, 2), (ba + 1, 4, 2), (bv, 1, 0), (None, 0, 0, 0), (bo, 4, 2), (bo + 1, 4, 2)]
    prog += _deep_strided_mac_loop(nf, 0, 1, nf, 2, B=B, opspec=spec_zg)            # zg-terms (2c+1) -> Sum_zg
    prog += ([OP("TOALT"), OP("TOALT"), OP("TOALT"), OP("TOALT")] + [OP("DROP")] * B
             + [OP("FROMALT"), OP("FROMALT"), OP("FROMALT"), OP("FROMALT")])        # drop blocks
    return prog


def run_deep_sum_part_dedup(nf, cells_base, alpha, ood):
    """Run the value-single-source pure-trace shard on cashvm; cells_base = nf BASE trace cells ck[c] (value1=0 baked),
    alpha/ood = 2*nf per-term. ((Sum_z, Sum_zg), op_cost) == run_deep_sum_part_dual over [0:2*nf)."""
    u = []
    for c in range(nf):
        u += [NUM(cells_base[c] % P)]                              # value: nf BASE cells (1 limb each)
    for i in range(2 * nf):
        u += [NUM(alpha[i][0] % P), NUM(alpha[i][1] % P)]          # alpha: per-term
    for i in range(2 * nf):
        u += [NUM(ood[i][0] % P), NUM(ood[i][1] % P)]              # ood: per-term
    vm = VM()
    try:
        vm.run(_field_prelude() + u + deep_sum_part_dedup_prog(nf))
        if len(vm.s) != 4:
            return None, 0
        return ((decode_num(vm.s[-4]) % P, decode_num(vm.s[-3]) % P),
                (decode_num(vm.s[-2]) % P, decode_num(vm.s[-1]) % P)), vm.op_cost
    except VMError:
        return None, 0


def deep_sum_part_tail_counter_deploy_prog(N, n_sel, carry_bound=False):
    """HP16.1/loop#9 DEPLOY form of the counter-driven TAIL shard [2*nf : n_terms). The tail is NOT pure-trace
    (no z/zg alternation): rel 0..n_sel-1 are the n_sel selector terms (ALL z), rel n_sel is range_weight (zg), rel
    n_sel+1 is comp (z). N = n_sel + 2. So instead of the two strided-by-2 loops of the pure-trace deploy form, the
    tail uses THREE strided loops (no reshaping, same in-place counter-computed PICK depths): a step-1 loop over the
    n_sel contiguous sel z-terms (Sum_z_sel), a single-iteration loop for comp (Sum_z_comp), an ext-add -> Sum_z, and
    a single-iteration loop for range_weight -> Sum_zg. Same stack-in as the pure-trace deploy form (bottom->top:
    value-cells(2N NUMs), slice = ood[.](2N cells)||alpha[.](2N cells) read cross-input from the blob); splits the
    slice into alpha/ood cell-blocks, arranges [value(0), alpha(2N), ood(4N)], counter-driven. -> [Sum_z(2), Sum_zg(2)].
    == eager deep_sum_part_dual over the tail (validated, real deep proofs). The routing (which rel is z/zg) is BAKED
    via n_sel (never a witness) -> a prover cannot reroute a term (R4-B1). Byte-bound (op-cost ~798K < the
    (scriptSig+41)*800 budget at its natural ~1.06KB) -> redeem collapses vs the unrolled tail (~1.2KB revealed each)."""
    rw_rel = n_sel                                                # range_weight relative index (zg)
    comp_rel = n_sel + 1                                          # comp relative index (z)
    prog = [NUM(16 * N), OP("SPLIT")]                             # [value-cells, ood_str, alpha_str]
    prog += list(split_cells_loop(2 * N, prefix=0))              # alpha_str -> alpha-cells
    prog += [NUM(2 * N), OP("ROLL")] + list(split_cells_loop(2 * N, prefix=0))   # ood_str -> ood-cells ; [value(0),alpha(2N),ood(4N)]
    prog += [PUSH(_DEEP_MAC_LAZY_FID), DEFINE(_deep_mac_lazy_body())]
    prog += _deep_strided_mac_loop(N, 0, 1, n_sel, extra=0, ba=2 * N, bv=0, bo=4 * N)      # sel z-terms -> Sum_z_sel
    prog += _deep_strided_mac_loop(N, comp_rel, 1, 1, extra=2, ba=2 * N, bv=0, bo=4 * N)   # comp z-term -> Sum_z_comp
    prog += ext_add_stack_prog()                                 # Sum_z = Sum_z_sel + Sum_z_comp
    prog += _deep_strided_mac_loop(N, rw_rel, 1, 1, extra=2, ba=2 * N, bv=0, bo=4 * N)     # range_weight zg-term -> Sum_zg
    prog += ([OP("TOALT"), OP("TOALT"), OP("TOALT"), OP("TOALT")] + [OP("DROP")] * (6 * N)
             + [OP("FROMALT"), OP("FROMALT"), OP("FROMALT"), OP("FROMALT")])   # drop blocks -> [Sum_z(2), Sum_zg(2)]
    if carry_bound:                                              # loop#9(c): chain form (carry_out_pre@0, carry_in_pre@1)
        prog += _counter_carry_bind_prog()
    return prog


def run_deep_sum_part_tail_counter_deploy(lo, hi, n_flat, n_sel, values, ood_slice, alpha_slice,
                                          carry_bound=False, acc_z_in=None, acc_zg_in=None, acc_z_out=None, acc_zg_out=None):
    """Run the blob-sourced counter-driven TAIL deploy shard on cashvm (slice pushed, not cross-input); ((Sum_z,
    Sum_zg), op_cost) == run_deep_sum_part_dual over [lo,hi). [lo,hi) MUST be the DEEP tail: n_sel contiguous z
    selector terms, then range_weight (zg), then comp (z) -- asserted fail-closed via _deep_term_is_z (dev-time
    misuse guard; the deploy routing is baked, never a witness). carry_bound=True: chain form, returns (1, op_cost) on
    accept / (None, 0) on a forged carry_out."""
    N = hi - lo
    assert N == n_sel + 2, "tail window must be n_sel selectors + range_weight + comp"
    assert all(_deep_term_is_z(lo + i, n_flat, n_sel) for i in range(n_sel)), "tail sel terms must all be z"
    assert not _deep_term_is_z(lo + n_sel, n_flat, n_sel), "tail rel n_sel must be range_weight (zg)"
    assert _deep_term_is_z(lo + n_sel + 1, n_flat, n_sel), "tail rel n_sel+1 must be comp (z)"
    u = _counter_carry_unlock(values, ood_slice, alpha_slice, N, carry_bound, acc_z_in, acc_zg_in, acc_z_out, acc_zg_out)
    vm = VM()
    try:
        vm.run(_field_prelude() + u + deep_sum_part_tail_counter_deploy_prog(N, n_sel, carry_bound))
        if carry_bound:
            if len(vm.s) != 1 or decode_num(vm.s[-1]) != 1:
                return None, 0
            return 1, vm.op_cost
        if len(vm.s) != 4:
            return None, 0
        return ((decode_num(vm.s[-4]) % P, decode_num(vm.s[-3]) % P),
                (decode_num(vm.s[-2]) % P, decode_num(vm.s[-1]) % P)), vm.op_cost
    except VMError:
        return None, 0


def deep_dual_slice_read_prog(lo, hi, n_terms):
    """HP16 deploy op-cost form: reconstruct the contiguous DEEP slice ood[lo:hi]||alpha[lo:hi] that
    deep_sum_part_dual_prog consumes, from the ONE FS blob on top of the stack, via two byte-range extracts + CAT.
    The FS-blob layout (_deep_blob_bytes) is z(16)||z*g(16)||ood(16*n_terms)||alpha(16*n_terms), so ood[lo:hi] is
    blob bytes [32+16*lo : 32+16*hi] and alpha[lo:hi] is [32+16*n_terms+16*lo : 32+16*n_terms+16*hi] -- NON-contiguous
    in the blob, hence two extracts + CAT rather than one. Single-sources ood/alpha from the ONE blob (R4-B1: a prover
    cannot substitute a per-input ood/alpha), and lo/hi/n_terms are BAKED (never a witness -> a prover cannot re-window
    the slice to a cheaper/forged subset). This is the op-cost-optimal deploy read: the SPLITs copy only up to the
    alpha-block offset (~32+16*n_terms+16*lo bytes), not the whole blob per term, and the on-VM MAC then scales with
    the shard (hi-lo), not the transcript -- the fix for the whole-blob op-over (deep_sum_part_blob / the reverted
    full-range 4m). In the deploy the blob is read cross-input via OP_INPUTBYTECODE (HP15) and the push prefix stripped
    BEFORE this prog; here (and in self_test) the blob is a raw stack push. Stack: [blob] -> [ood[lo:hi]||alpha[lo:hi]]
    (exactly the deep_sum_part_dual_unlock slice for [lo,hi))."""
    L = 16 * (hi - lo)                                         # slice byte length: (hi-lo) ext cells * 16B, per block
    off_ood = 32 + 16 * lo                                     # ood[lo] byte offset (after the z||z*g 32B prefix)
    off_alpha = 32 + 16 * n_terms + 16 * lo                    # alpha[lo] byte offset (after the ood block)
    return [OP("DUP"),                                         # [blob, blob]
            NUM(off_ood), OP("SPLIT"), OP("NIP"), NUM(L), OP("SPLIT"), OP("DROP"),      # -> [blob, ood[lo:hi]]
            OP("SWAP"),                                                                 # -> [ood[lo:hi], blob]
            NUM(off_alpha), OP("SPLIT"), OP("NIP"), NUM(L), OP("SPLIT"), OP("DROP"),    # -> [ood[lo:hi], alpha[lo:hi]]
            OP("CAT")]                                                                  # -> [ood[lo:hi]||alpha[lo:hi]]


def deep_final_combine_prog(carry_split=False, dual=False, dual_carry=False):
    """HP12/HP16 thin-shard: the FINAL DEEP-quotient combine -- q(x_k) = invz*Sum_z + invzg*Sum_zg from the two
    carried partial sums + the two hint-validated inverses. Unlock (bottom->top): Sum_z(2), Sum_zg(2), invz(2),
    invzg(2). Leaves [q0,q1]. 182B (the thin final input). In the deploy Sum_z/Sum_zg are read cross-input from
    the sum-parts (OP_INPUTBYTECODE, HP15) and invz/invzg are ext_inv_check-validated (HP13.1).

    HP12 carry_split=True: the DEPLOY consumer form -- Sum_z is READ cross-input (the caller's
    OP_0 OP_INPUTBYTECODE.. prefix leaves the 16-byte Sum_z carry_out preimage of the producing sum-part on top),
    and this prog split_cells(2)s it into Sum_z and USES it in q (split-and-use, not a byte-compare -> a forged
    Sum_z yields the wrong q, fail-closed, OBS-2). Unlock (bottom->top) is then Sum_zg(2), invz(2), invzg(2);
    Sum_z arrives on top from the read. Mirrors the fri iii-3 carry_split (fri_partial_witness_redeem). The
    OP_INPUTBYTECODE read + the _field_prelude belong to the deploy redeem assembly (cashvm cannot model
    introspection); the split_cells + combine arithmetic here is the cashvm-testable part.

    HP16.1 dual=True: the FULL 3-input DEPLOY consumer form -- BOTH Sum_z AND Sum_zg are READ cross-input (the
    caller's two OP_INPUTBYTECODE prefixes push the 16-byte Sum_z carry_out of its sum-part input, then the 16-byte
    Sum_zg carry_out on top). This prog split_cells(2)s Sum_zg (top), ROLLs Sum_z up (it sits 2 deep under the two
    Sum_zg limbs) and split_cells(2)s it too, then USES both in q (split-and-use -> a forged Sum_z OR Sum_zg yields
    the wrong q, fail-closed; closes the Sum_zg single-source gap that carry_split left in the per-input witness).
    Unlock (bottom->top) is then only invz(2), invzg(2). The two reads + the _field_prelude belong to the deploy
    redeem assembly (cashvm cannot model introspection); the split_cells + combine here is the cashvm-testable part.

    HP12.3 dual_carry=True: the Design A consumer -- the contiguous dual shards carry ONE 32-byte (Sum_z||Sum_zg)
    pair, so the final READs that single 32-byte carry_out cross-input and split_cells(4)s it into Sum_z + Sum_zg
    (both used in q -> a forged Sum_z OR Sum_zg yields the wrong q, fail-closed). Unlock is then only invz(2), invzg(2)."""
    prog = []
    if dual_carry:
        prog += split_cells_prog(4)                            # top 32B dual carry (Sum_z||Sum_zg) -> Sz0,Sz1,Szg0,Szg1
        i_sz, i_szg, i_ivz, i_ivzg = 4, 6, 0, 2                # [invz@0-1, invzg@2-3, Sum_z@4-5, Sum_zg@6-7]
    elif dual:
        prog += split_cells_prog(2) + [NUM(2), OP("ROLL")] + split_cells_prog(2)   # Sum_zg (top), then Sum_z (rolled up) -> 4 limbs
        i_sz, i_szg, i_ivz, i_ivzg = 6, 4, 0, 2                # [invz@0-1, invzg@2-3, Sum_zg@4-5, Sum_z@6-7]
    elif carry_split:
        prog += split_cells_prog(2)                            # top 16B blob (the read Sum_z carry_out) -> Sum_z0, Sum_z1
        i_sz, i_szg, i_ivz, i_ivzg = 6, 0, 2, 4                # [Sum_zg@0-1, invz@2-3, invzg@4-5, Sum_z@6-7]
    else:
        i_sz, i_szg, i_ivz, i_ivzg = 0, 2, 4, 6                # [Sum_z@0-1, Sum_zg@2-3, invz@4-5, invzg@6-7]
    sp = [8]

    def pk(abs_pos):
        prog.extend([NUM(sp[0] - 1 - abs_pos), OP("PICK")]); sp[0] += 1

    pk(i_sz); pk(i_sz + 1); pk(i_ivz); pk(i_ivz + 1)          # Sum_z, invz
    prog.extend(ext_mul_stack_prog()); sp[0] -= 2             # invz*Sum_z
    pk(i_szg); pk(i_szg + 1); pk(i_ivzg); pk(i_ivzg + 1)      # Sum_zg, invzg
    prog.extend(ext_mul_stack_prog()); sp[0] -= 2             # invzg*Sum_zg
    prog.extend(ext_add_stack_prog()); sp[0] -= 2             # q = invz*Sum_z + invzg*Sum_zg
    prog += [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * 8 + [OP("FROMALT"), OP("FROMALT")]
    return prog


def run_deep_final_combine(Sz, Szg, invz, invzg, carry_split=False, dual=False, dual_carry=False):
    """Run the DEEP-quotient final combine on cashvm; ((q0,q1), op_cost) = invz*Sz + invzg*Szg. carry_split=True
    models the DEPLOY consumer: Sum_z arrives as a 16-byte carry_out preimage on top (the OP_INPUTBYTECODE read),
    split_cells(2)'d in-prog; the unlock is then [Sum_zg, invz, invzg] with Sum_z pushed on top. dual=True models
    the FULL 3-input deploy consumer: Sum_z then Sum_zg arrive as 16-byte carry_out preimages on top (two
    OP_INPUTBYTECODE reads, Sum_zg last/on top); the unlock is only [invz, invzg]. dual_carry=True models the
    Design A consumer: ONE 32-byte carry (Sum_z||Sum_zg) arrives on top (one OP_INPUTBYTECODE read of the last dual
    shard's carry_out), split_cells(4)'d in-prog; the unlock is only [invz, invzg]."""
    vm = VM()
    if dual_carry:
        w = [NUM(invz[0] % P), NUM(invz[1] % P), NUM(invzg[0] % P), NUM(invzg[1] % P),
             PUSH(_acc_preimage(Sz) + _acc_preimage(Szg))]
    elif dual:
        w = [NUM(invz[0] % P), NUM(invz[1] % P), NUM(invzg[0] % P), NUM(invzg[1] % P),
             PUSH(_acc_preimage(Sz)), PUSH(_acc_preimage(Szg))]
    elif carry_split:
        w = [NUM(Szg[0] % P), NUM(Szg[1] % P), NUM(invz[0] % P), NUM(invz[1] % P),
             NUM(invzg[0] % P), NUM(invzg[1] % P), PUSH(_acc_preimage(Sz))]
    else:
        w = [NUM(Sz[0] % P), NUM(Sz[1] % P), NUM(Szg[0] % P), NUM(Szg[1] % P),
             NUM(invz[0] % P), NUM(invz[1] % P), NUM(invzg[0] % P), NUM(invzg[1] % P)]
    try:
        vm.run(_field_prelude() + w + deep_final_combine_prog(carry_split, dual, dual_carry))
        if len(vm.s) != 2:
            return None, 0
        return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost
    except VMError:
        return None, 0


def deep_final_combine_qbound_prog(from_stack=False):
    """HP16.1 the DEPLOY final-combine that also EXPOSES q for the FRI layer-0 read (the q-output-bind, analogous to the
    shards' carry_out-bind). Stack in (bottom->top): q_pre(16B)@0, invz0@1, invz1@2, invzg0@3, invzg1@4, carry32@5 (top,
    the dual shard-chain's carry_out = Sum_z||Sum_zg read cross-input via OP_INPUTBYTECODE). Computes q = invz*Sum_z +
    invzg*Sum_zg over GF(p^2), self-binds q == q_pre (fail-closed NUMEQUALVERIFY -> a forged q rejects), leaves [1]. The
    q_pre push (this input's first unlock push) is what the FRI input reads cross-input as its layer-0 value. invz/invzg
    are hint-validated against x_k, z, z*g by ext_inv_check (HP13.1) in the same redeem (deploy soundness layer). The
    OP_INPUTBYTECODE read + _field_prelude belong to the deploy redeem assembly; the split_cells + GF(p^2) combine + bind
    here are the cashvm-testable part. Validated real BCH-2026 P2SH32: 4-input blob+shardA+tail+final chain (proto_chain4).

    HP11 from_stack=True (tail/final-fusion): the Sum_z||Sum_zg total is ALREADY on the stack as 4 limbs @5..8
    (Sz0@5,Sz1@6,Szg0@7,Szg1@8) -- the fused tail input adds shardA_carry + tail_sum in-place and feeds the total
    DIRECTLY (no 32B carry blob to read cross-input, no split_cells), so the tail's carry_out exposure + the separate
    final input are elided. Byte-identical GF(p^2) combine + q-bind; only the carry SOURCE differs (stack vs blob)."""
    prog = []
    sp = [6]

    def pk(pos):
        prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1

    if from_stack:
        sp[0] = 9                                                   # Sz0@5,Sz1@6,Szg0@7,Szg1@8 already on the stack
    else:
        prog += list(split_cells_prog(4, prefix=0)); sp[0] += 3     # carry -> Sz0@5,Sz1@6,Szg0@7,Szg1@8
    pk(1); pk(2); pk(5); pk(6); prog += list(ext_mul_stack_prog()); sp[0] -= 2   # invz*Sum_z
    pk(3); pk(4); pk(7); pk(8); prog += list(ext_mul_stack_prog()); sp[0] -= 2   # invzg*Sum_zg
    prog += list(ext_add_stack_prog()); sp[0] -= 2                   # q = invz*Sum_z + invzg*Sum_zg -> q0@9, q1@10 (sp=11)
    pk(0); prog += list(split_cells_prog(2, prefix=0)); sp[0] += 1   # q_pre -> p0(=q0)@11, p1(=q1)@12 (sp=13)
    pk(10); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2            # p1 == q1
    pk(9); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2             # p0 == q0
    prog += [OP("DROP")] * sp[0] + [NUM(1)]
    return prog


def run_deep_final_combine_qbound(Sz, Szg, invz, invzg, q_out):
    """Run the q-bound final combine on cashvm (the 32B carry arrives on top = the cross-input read, simulated by a
    push here). Returns (1, op_cost) on accept (computed q == q_out), (None, 0) on a forged q (fail-closed)."""
    w = [PUSH(enc8(q_out[0] % P) + enc8(q_out[1] % P)),
         NUM(invz[0] % P), NUM(invz[1] % P), NUM(invzg[0] % P), NUM(invzg[1] % P),
         PUSH(_acc_preimage(Sz) + _acc_preimage(Szg))]
    vm = VM()
    try:
        vm.run(_field_prelude() + w + deep_final_combine_qbound_prog())
        if len(vm.s) != 1 or decode_num(vm.s[-1]) != 1:
            return None, 0
        return 1, vm.op_cost
    except VMError:
        return None, 0


def _open_deep_leaves_prog(depth, tp_root, sel_root, comp_root, n_trace, n_sel, below, above=0):
    """HP10-rest: open the THREE per-query DEEP leaves -- trace@k (n_trace cells, 16-byte salt), sel@k
    (n_sel+1 cells = n_sel selectors + range_weight, no salt) and comp@k (2 cells cc, unsalted leaf
    b"\\x00"*16 || cc0 || cc1) -- at ONE FS index k against the PINNED roots via the open_all_leaves
    copy-pattern (each block PICK-copied up from its fixed position, roots baked so a prover cannot
    substitute a favourable tree). NO @kn opening: under DEEP q(x_k) reads EVERY value at k (HP10.3,
    prover 5.7). Leaves, bottom->top: [below.., W(3*WB), above.., trace(n_trace), sel(n_sel+1), comp(2)];
    WB=depth+2. `above` = items sitting ABOVE the 3 opener blocks when this runs (e.g. the HP12 split-blob
    cells) -- the copy-pattern PICKs each block from its fixed position, so the sp must start at the actual
    height below+3*WB+above; the opened cells land on top of the `above` items. A tampered leaf / wrong index
    fails the baked-root EQUALVERIFY (fail-closed)."""
    WB = depth + 2
    prog = []
    sp = [below + 3 * WB + above]

    def copy(pos):
        prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1

    def open_leaf(block, root, n, prefix):
        for i in range(WB):
            copy(below + block * WB + i)                        # copy this leaf's witness block to the top
        prog.extend(bound_retain_open_prog(depth, root) + split_cells_prog(n, prefix=prefix))
        sp[0] += n - WB

    open_leaf(0, tp_root, n_trace, 16)                          # trace@k  (16-byte salt)
    open_leaf(1, sel_root, n_sel + 1, 0)                        # sel@k    (n_sel selectors + range_weight)
    open_leaf(2, comp_root, 2, 16)                              # comp@k   (unsalted leaf)
    return prog, WB


def per_query_deep_quotient_prog(depth, tp_root, sel_root, comp_root, n_flat, n_sel):
    """HP10.1/10.2/10.3: the deploy-sound per-query DEEP quotient. Opens trace@k / sel@k / comp@k against
    the pinned tp_root/sel_root/comp_root at ONE FS index k (HP10.2 sel + comp openings, HP10.3 no @kn),
    sources the DEEP-quotient `value` from the OPENED cells (a prover can no longer feed free trace/sel/comp
    values -- the pinned-root EQUALVERIFY fails on a tampered leaf), and computes the hint-validated q(x_k)
    via deep_query_quotient (HP10.1: GF(p^2) inverse hints checked fail-closed). The DEEP masks
    (Pcz/Pczg/sel(z)/range_weight(z*g)/comp(z)), the deep_alphas and invz/invzg are WITNESS here -- their
    single-source binding to the ONE FS blob is the cross-input anchor HP12 (OP_INPUTBYTECODE = HP15); the
    openings + quotient are the fully cashvm-testable part. This standalone gadget also takes the index k (shared
    by the three opener blocks) and x=Dd[k] as witness -- forcing ONE FS-derived k across the openers + x=Dd[k]
    is the FS-assembly step (open_all_leaves_fs + fri_xpos, deploy/HP12), the SAME deferral as open_all_leaves_prog;
    FRI low-degree aggregation independently rejects a mixed-index / wrong-x codeword. Value map (canonical
    deep_alphas order): trace
    term 2c/2c+1 -> trace_cell[c]; selector term 2*n_flat+s -> sel_cell[s]; range_weight term -> sel_cell
    [n_sel] (base-lift); comp term -> cc (ext). Leaves [q0,q1] == native_ct_air_stark._deep_replay.q_at.
    A tampered leaf / wrong index / forged invz/invzg rejects fail-closed."""
    assert len(_SEL_ORDER) == n_sel + 1, "sel leaf (%d) must be n_sel(%d) selectors + range_weight" % (
        len(_SEL_ORDER), n_sel)
    NT = n_flat
    n_terms = 2 * n_flat + n_sel + 2
    # W-region (witness beneath the openers), abs positions:
    #   x(1) z(2) z*g(2) | MA = [alpha0,alpha1, ood0,ood1] * n_terms | HN = [invz0,invz1, invzg0,invzg1]
    ma_base = 5
    hn_base = ma_base + 4 * n_terms
    W = hn_base + 4
    openers, WB = _open_deep_leaves_prog(depth, tp_root, sel_root, comp_root, n_flat, n_sel, below=W)
    cell_base = W + 3 * WB                                      # after openers: [W, blocks(3*WB), trace, sel, comp]
    tr_base = cell_base                                         # trace_cell[c] at tr_base + c  (c in 0..n_flat-1)
    se_base = cell_base + NT                                    # sel_cell[s]   at se_base + s  (s in 0..n_sel)
    cc_base = cell_base + NT + (n_sel + 1)                      # cc0/cc1
    below_total = cc_base + 2                                   # everything beneath the assembled block
    prog = list(openers)
    prog += _field_prelude()                                   # openers ran with a free alt stack; now P->alt for ext ops
    sp = [below_total]

    def copy(abs_pos):
        prog.extend([NUM(sp[0] - 1 - abs_pos), OP("PICK")]); sp[0] += 1

    def push0():
        prog.append(NUM(0)); sp[0] += 1

    for j in range(5):                                         # [x, z0,z1, zg0,zg1] for the hint check
        copy(j)
    for i in range(n_terms):                                   # [alpha_i, value_i, ood_i]; value from the openings
        copy(ma_base + 4 * i); copy(ma_base + 4 * i + 1)       # alpha_i (witness)
        if i < 2 * NT:                                         # trace term -> trace_cell[i//2] (base-lift)
            copy(tr_base + i // 2); push0()
        elif i < 2 * NT + n_sel:                               # selector term -> sel_cell[i-2*NT] (base-lift)
            copy(se_base + (i - 2 * NT)); push0()
        elif i == 2 * NT + n_sel:                              # range_weight -> sel_cell[n_sel] (base-lift)
            copy(se_base + n_sel); push0()
        else:                                                 # comp term -> cc (ext, from comp@k)
            copy(cc_base); copy(cc_base + 1)
        copy(ma_base + 4 * i + 2); copy(ma_base + 4 * i + 3)   # ood_i (witness mask)
    copy(hn_base); copy(hn_base + 1); copy(hn_base + 2); copy(hn_base + 3)   # invz, invzg
    NB = 3 * n_terms + 2
    assert sp[0] == below_total + 5 + 2 * NB, "deep assemble sp=%d expected %d" % (sp[0], below_total + 5 + 2 * NB)
    prog += deep_query_quotient_prog(n_flat, n_sel, below=below_total)       # hint-validated q(x_k)
    # leaves [below_total.., q0, q1]; drop the openers + witness -> [q0, q1]
    prog += [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * below_total + [OP("FROMALT"), OP("FROMALT")]
    return prog


def per_query_deep_quotient_unlock(x, z, zg, terms_ao, invz, invzg,
                                   tk_pre, tk_path, sk_pre, sk_path, ck_pre, ck_path, k):
    """Push-only witness for per_query_deep_quotient_prog (bottom->top): the W-region [x, z0,z1, zg0,zg1,
    (alpha,ood)*n_terms, invz, invzg] then the three opener blocks trace@k, sel@k, comp@k (each =
    bound_open_unlock [sib_{depth-1}..sib_0, preimage, k]; roots baked, index bits derive from k).
    terms_ao = (alpha, ood) per term in canonical deep_alphas order (value comes from the openings)."""
    w = [NUM(x % P), NUM(z[0] % P), NUM(z[1] % P), NUM(zg[0] % P), NUM(zg[1] % P)]
    for alpha, ood in terms_ao:
        w += [NUM(alpha[0] % P), NUM(alpha[1] % P), NUM(ood[0] % P), NUM(ood[1] % P)]
    w += [NUM(invz[0] % P), NUM(invz[1] % P), NUM(invzg[0] % P), NUM(invzg[1] % P)]
    return (w + bound_open_unlock(tk_pre, tk_path, k) + bound_open_unlock(sk_pre, sk_path, k)
            + bound_open_unlock(ck_pre, ck_path, k))


def run_per_query_deep_quotient(depth, tp_root, sel_root, comp_root, n_flat, n_sel, x, z, zg, terms_ao,
                                invz, invzg, tk_pre, tk_path, sk_pre, sk_path, ck_pre, ck_path, k):
    """Run the deploy-sound per-query DEEP quotient on cashvm; ((q0,q1), op_cost) with q == q(x_k) if the
    three leaves open against their pinned roots at k and the inverse hints validate, or (None, 0) on a
    fail-closed reject (a tampered leaf, a wrong index, or a forged invz/invzg)."""
    vm = VM()
    try:
        vm.run(per_query_deep_quotient_unlock(x, z, zg, terms_ao, invz, invzg,
                                              tk_pre, tk_path, sk_pre, sk_path, ck_pre, ck_path, k)
               + per_query_deep_quotient_prog(depth, tp_root, sel_root, comp_root, n_flat, n_sel))
        if len(vm.s) != 2:
            return None, 0
        return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost
    except VMError:
        return None, 0


def _deep_blob_bytes(z, zg, terms_ao):
    """HP12 FS-blob body (single-sourced across the per-query DEEP consumers): z(2) || z*g(2) || ood(2*n_terms)
    || deep_alphas(2*n_terms), each an 8-byte LE field cell (2+2+2*n_terms+2*n_terms = 556 cells for the CT-AIR).
    terms_ao = (alpha, ood) per term in canonical deep_alphas order."""
    b = enc8(z[0] % P) + enc8(z[1] % P) + enc8(zg[0] % P) + enc8(zg[1] % P)
    for _alpha, ood in terms_ao:
        b += enc8(ood[0] % P) + enc8(ood[1] % P)
    for alpha, _ood in terms_ao:
        b += enc8(alpha[0] % P) + enc8(alpha[1] % P)
    return b


def per_query_deep_quotient_blob_prog(depth, tp_root, sel_root, comp_root, n_flat, n_sel):
    """HP12/HP15: the BLOB-SOURCED per-query DEEP quotient -- the deploy-byte-feasible form of
    per_query_deep_quotient. The 138 ood + 138 deep_alphas + z + z*g are single-sourced from the ONE FS blob
    (HP12, R4-B1: a prover cannot substitute a per-input value), so they leave the per-input WITNESS (which
    otherwise blows the 10000B scriptSig cap, HP15.2: 16886B). The blob sits on TOP of the unlock -- a witness
    push here (cashvm), read cross-input via OP_INPUTBYTECODE from the producer input in the deploy (HP15, node
    _linked). split_cells_loop keeps the on-chain 556-cell split ~constant (23B vs 4444B unrolled) so the redeem
    fits: measured 9735B <= 10000B. Unlock (bottom->top): [x, invz(2), invzg(2)] + trace@k + sel@k + comp@k
    opener blocks + [blob]. Redeem: split the blob -> z/z*g/ood/deep_alphas cells; open the 3 leaves (copy-pattern
    with above=n_blob, since the split cells sit above the blocks); assemble [x, z,z*g, [alpha,value,ood]*n_terms,
    invz,invzg] (alpha/ood/z/z*g from the split blob, value from the openings, x/invz/invzg witness);
    hint-validated deep_query_quotient -> q(x_k) == query_terms. Leaves [q0,q1]. A tampered leaf / wrong index /
    forged invz/invzg rejects fail-closed."""
    NT = n_flat
    n_terms = 2 * n_flat + n_sel + 2
    n_blob = 2 + 2 + 2 * n_terms + 2 * n_terms                  # z + z*g + ood + deep_alphas (field cells)
    BW = 5                                                      # bottom witness: x(1), invz(2), invzg(2)
    openers, WB = _open_deep_leaves_prog(depth, tp_root, sel_root, comp_root, n_flat, n_sel, below=BW, above=n_blob)
    prog = list(split_cells_loop(n_blob, prefix=0))            # split the blob (top) FIRST (free alt stack)
    blob_base = BW + 3 * WB
    z_base = blob_base; zg_base = blob_base + 2
    ood_base = blob_base + 4                                    # ood[j] ext at ood_base + 2*j
    alpha_base = blob_base + 4 + 2 * n_terms                    # deep_alphas[j] ext at alpha_base + 2*j
    prog += openers                                            # copy-pattern reaches under the split blob cells
    prog += _field_prelude()                                   # openers done (free alt); P -> alt for the ext ops
    cell_base = blob_base + n_blob
    tr_base = cell_base; se_base = cell_base + NT; cc_base = cell_base + NT + (n_sel + 1)
    below_total = cc_base + 2
    sp = [below_total]

    def copy(abs_pos):
        prog.extend([NUM(sp[0] - 1 - abs_pos), OP("PICK")]); sp[0] += 1

    def push0():
        prog.append(NUM(0)); sp[0] += 1

    copy(0)                                                     # x (witness pos 0)
    copy(z_base); copy(z_base + 1)                             # z (blob)
    copy(zg_base); copy(zg_base + 1)                           # z*g (blob)
    for i in range(n_terms):
        copy(alpha_base + 2 * i); copy(alpha_base + 2 * i + 1)      # alpha_i (blob)
        if i < 2 * NT:                                         # trace term -> trace_cell[i//2] (base-lift)
            copy(tr_base + i // 2); push0()
        elif i < 2 * NT + n_sel:                               # selector term -> sel_cell[i-2*NT] (base-lift)
            copy(se_base + (i - 2 * NT)); push0()
        elif i == 2 * NT + n_sel:                              # range_weight -> sel_cell[n_sel] (base-lift)
            copy(se_base + n_sel); push0()
        else:                                                 # comp term -> cc (ext, from comp@k)
            copy(cc_base); copy(cc_base + 1)
        copy(ood_base + 2 * i); copy(ood_base + 2 * i + 1)         # ood_i (blob)
    copy(1); copy(2); copy(3); copy(4)                             # invz, invzg (witness pos 1..4)
    NB = 3 * n_terms + 2
    assert sp[0] == below_total + 5 + 2 * NB, "blob assemble sp=%d expected %d" % (sp[0], below_total + 5 + 2 * NB)
    prog += deep_query_quotient_prog(n_flat, n_sel, below=below_total)
    prog += [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * below_total + [OP("FROMALT"), OP("FROMALT")]
    return prog


def per_query_deep_quotient_blob_unlock(x, invz, invzg, terms_ao, z, zg,
                                        tk_pre, tk_path, sk_pre, sk_path, ck_pre, ck_path, k):
    """Witness (bottom->top): [x, invz(2), invzg(2)] then the three opener blocks trace@k/sel@k/comp@k then the
    FS blob on top (in the deploy the blob is read via OP_INPUTBYTECODE from the producer, not pushed here)."""
    w = [NUM(x % P), NUM(invz[0] % P), NUM(invz[1] % P), NUM(invzg[0] % P), NUM(invzg[1] % P)]
    w += bound_open_unlock(tk_pre, tk_path, k) + bound_open_unlock(sk_pre, sk_path, k) + bound_open_unlock(ck_pre, ck_path, k)
    return w + [PUSH(_deep_blob_bytes(z, zg, terms_ao))]


def run_per_query_deep_quotient_blob(depth, tp_root, sel_root, comp_root, n_flat, n_sel, x, invz, invzg,
                                     terms_ao, z, zg, tk_pre, tk_path, sk_pre, sk_path, ck_pre, ck_path, k):
    """Run the blob-sourced per-query DEEP consumer on cashvm; ((q0,q1), op_cost) == q(x_k) if the leaves open
    and the hints validate, or (None, 0) on a fail-closed reject."""
    vm = VM()
    try:
        vm.run(per_query_deep_quotient_blob_unlock(x, invz, invzg, terms_ao, z, zg,
                                                   tk_pre, tk_path, sk_pre, sk_path, ck_pre, ck_path, k)
               + per_query_deep_quotient_blob_prog(depth, tp_root, sel_root, comp_root, n_flat, n_sel))
        if len(vm.s) != 2:
            return None, 0
        return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost
    except VMError:
        return None, 0


# ---- HP9.2 (GF(p^2) AIR-eval at z): the residual token-programs need GF(p^2) VALUES on the stack, not single
# limbs. _ext_vstack is a value-stack builder over the HP9.a primitives (ext_add/sub/mul_stack): operands are
# ext-values (2 limbs each), results are ext-values. It is the GF(p^2) counterpart of the base `above`-tracked
# limb builders (sbox_lane_stack_prog). Each residual program mirrors a native_ct_air_prover.*_ext function
# 1:1 (nothing invented) and is cross-checked ==native_gf_p2 / *_ext on real cashvm (HP15.11). ----
def _ext_vstack(op_names, body):
    """GF(p^2) VALUE-stack builder for the AIR-eval at z. Operands are ext-values (2 limbs each, bottom->top in
    op_names). body(m) composes result ext-values on top via: m.copy(name) push a named operand; m.dup() the top
    ext-value; m.swap() the top two; m.const((c0,c1)) push a baked ext constant; m.scalar(c) multiply the top
    ext-value by a baked BASE constant c (base*ext, native_gf_p2.scalar); m.add()/m.sub()/m.mul() consume the top
    TWO ext-values -> their GF(p^2) sum/difference/product via the tested ext_*_stack_prog (sub = deeper-minus-top).
    Leaves the result ext-values, drops the 2*len(op_names) operand limbs (TOALT/DROP/FROMALT, preserving P on the
    alt stack). Generalises _ext_stack (single op) to multi-operand/multi-result; DRY on the HP9.a primitives."""
    prog = []
    above = [0]                                                     # limbs above the operand block
    limbs = [nm + "#%d" % c for nm in op_names for c in (0, 1)]     # bottom->top
    top_index = {nm: i for i, nm in enumerate(reversed(limbs))}

    def copy(name):
        for c in (0, 1):                                            # push [limb0, limb1] (limb1 on top)
            prog.extend([NUM(above[0] + top_index[name + "#%d" % c]), OP("PICK")]); above[0] += 1

    def dup():
        prog.extend([NUM(1), OP("PICK"), NUM(1), OP("PICK")]); above[0] += 2   # copy the top ext-value

    def swap():
        prog.extend([NUM(3), OP("ROLL"), NUM(3), OP("ROLL")])                  # swap the top two ext-values

    def const(val):
        prog.extend([NUM(val[0] % P), NUM(val[1] % P)]); above[0] += 2         # push a baked ext constant

    def scalar(c):                                                             # top ext-value *= base constant c
        c %= P                                                                 # [a0,a1] -> [c*a0, c*a1]
        prog.extend([NUM(1), OP("PICK"), NUM(c)] + MM() + [NUM(1), OP("PICK"), NUM(c)] + MM())
        prog.extend([OP("TOALT"), OP("TOALT"), OP("DROP"), OP("DROP"), OP("FROMALT"), OP("FROMALT")])

    def add(): prog.extend(ext_add_stack_prog()); above[0] -= 2
    def sub(): prog.extend(ext_sub_stack_prog()); above[0] -= 2
    def mul(): prog.extend(ext_mul_stack_prog()); above[0] -= 2

    class _V:                                                       # op namespace passed to body
        pass
    m = _V()
    m.copy, m.dup, m.swap, m.const, m.scalar = copy, dup, swap, const, scalar
    m.add, m.sub, m.mul = add, sub, mul
    body(m)
    assert above[0] % 2 == 0 and above[0] >= 2, "_ext_vstack left %d limbs (expected 2*n_res)" % above[0]
    n_res = above[0] // 2
    prog += [OP("TOALT")] * (2 * n_res) + [OP("DROP")] * (2 * len(op_names)) + [OP("FROMALT")] * (2 * n_res)
    return prog


_SBOX_EXT_OPS = ("s", "rc", "u2", "u4", "u6", "gate")             # each an ext-value (2 limbs), bottom->top


def sbox_lane_ext_residuals_prog():
    """HP9.2: the Poseidon2 S-box-lane residuals at the OOD point z over GF(p^2) -- the deploy counterpart of
    sbox_lane_stack_prog (base) and the GF(p^2) mirror of native_ct_air_prover._round_residuals_ext's per-lane
    S-box residuals (:909-915). Reads [s,rc,u2,u4,u6,gate] (each 2 limbs) from the stack, leaves [c_u2,c_u4,c_u6]
    (each 2 limbs), where x=s+rc and c_u2=gate*(u2-x*x), c_u4=gate*(u4-u2*u2), c_u6=gate*(u6-u4*u2) over GF(p^2).
    At z the selector `gate` is a GF(p^2) value, so gate*(..) is a Karatsuba mul, not a base scalar. Needs the
    field prelude once; drops the 12 operand limbs. Cross-checked ==native_gf_p2/_round_residuals_ext (HP15.11)."""
    def body(m):
        m.copy("s"); m.copy("rc"); m.add()                        # x = s + rc
        m.dup(); m.mul()                                          # x*x
        m.copy("u2"); m.swap(); m.sub()                           # u2 - x*x
        m.copy("gate"); m.mul()                                   # c_u2 = gate*(u2 - x*x)
        m.copy("u2"); m.dup(); m.mul()                            # [c_u2] u2*u2
        m.copy("u4"); m.swap(); m.sub()                           # [c_u2] u4 - u2*u2
        m.copy("gate"); m.mul()                                   # [c_u2] c_u4
        m.copy("u4"); m.copy("u2"); m.mul()                       # [c_u2,c_u4] u4*u2
        m.copy("u6"); m.swap(); m.sub()                           # [c_u2,c_u4] u6 - u4*u2
        m.copy("gate"); m.mul()                                   # [c_u2,c_u4] c_u6
    return _ext_vstack(list(_SBOX_EXT_OPS), body)


def sbox_lane_ext_unlock(s, rc, u2, u4, u6, gate):
    """Push-only GF(p^2) inputs (each (limb0, limb1)) bottom->top in _SBOX_EXT_OPS order."""
    v = dict(s=s, rc=rc, u2=u2, u4=u4, u6=u6, gate=gate)
    out = []
    for n in _SBOX_EXT_OPS:
        out += [NUM(v[n][0] % P), NUM(v[n][1] % P)]
    return out


def run_sbox_lane_ext(s, rc, u2, u4, u6, gate):
    """Run the GF(p^2) S-box lane on cashvm; ([c_u2,c_u4,c_u6] as (limb0,limb1) tuples, op_cost)."""
    vm = VM()
    vm.run(_field_prelude() + sbox_lane_ext_unlock(s, rc, u2, u4, u6, gate) + sbox_lane_ext_residuals_prog())
    assert len(vm.s) == 6, "sbox_lane_ext left %d items, expected 6" % len(vm.s)
    d = [decode_num(x) for x in vm.s]
    return [(d[0], d[1]), (d[2], d[3]), (d[4], d[5])], vm.op_cost


# HP9.5 byte optimisation (DEFINE-fold, like the base stagea_sbox_define:3310): the GF(p^2) S-box body is
# uniform across the 12 lanes (all inputs are stack operands), so DEFINE it ONCE and INVOKE it per lane instead
# of inlining 12x -- ~12x smaller for the S-box portion of the AIR-at-z. FIDs 0x21+ are distinct from the field
# table (MULMOD/ADDMOD/SUBMOD) and the base 0x04/0x05/0x11/0x12 bodies.
_SBOX_EXT_FID = b"\x21"


def stagea_sbox_ext_define():
    """DEFINE the uniform GF(p^2) S-box-lane body once (id 0x21); INVOKE it per lane in the assembler."""
    return [PUSH(_SBOX_EXT_FID), DEFINE(sbox_lane_ext_residuals_prog())]


# HP9.5 state byte optimisation: like the base stagea_state_uniform_body (:3334), the GF(p^2) state body reads a
# PRECOMPUTED ef_j (the external-MDS image ef=M_EXT.y_full computed ONCE for all lanes) + the appended ypj (=
# y_part[j]) so the body is UNIFORM (index-free) -> DEFINE'd once (0x22), INVOKE'd per lane. This drops the
# per-lane 12-term M_EXT dot (the 16.5KB bloat) to a single shared ef precompute + a small uniform body.
_STATE_EXT_FID = b"\x22"
_STATE_EXT_OPS_U = ("ef",) + tuple("yp%d" % k for k in range(WIDTH)) + ("diag", "sj", "isf", "isp", "ypj")


def stagea_state_ext_uniform_body():
    """[ef, yp0..yp{W-1}, diag, sj, isf, isp, ypj] (each 2 limbs) -> [v_j] over GF(p^2). IDENTICAL arithmetic to
    state_lane_ext_residual_prog's combine (v_j = isf*(sj-ef) + isp*(sj-ip), ip = ypj*diag + sum_k yp_k) but ef is
    the precomputed external-MDS image and the ypj*diag term reads the APPENDED 'ypj' (y_part[j]) instead of a
    per-j pick -- so the body is UNIFORM (index-free) and DEFINE/INVOKE-able. diag embeds as ext (diag_j, 0), so
    ypj*diag is a Karatsuba mul (== base scalar). Mirrors the base stagea_state_uniform_body."""
    def body(m):
        m.copy("sj"); m.copy("ef"); m.sub(); m.copy("isf"); m.mul()   # term1 = isf*(sj - ef)
        m.copy("ypj"); m.copy("diag"); m.mul()                        # ypj*diag
        m.copy("yp0")
        for k in range(1, WIDTH):
            m.copy("yp%d" % k); m.add()                               # sum_k yp[k]
        m.add()                                                       # ip = ypj*diag + sum
        m.copy("sj"); m.swap(); m.sub(); m.copy("isp"); m.mul()       # term2 = isp*(sj - ip)
        m.add()                                                       # v_j = term1 + term2
    return _ext_vstack(list(_STATE_EXT_OPS_U), body)


def stagea_state_ext_define():
    """DEFINE the uniform GF(p^2) state-lane body once (id 0x22); INVOKE it per lane in the assembler."""
    return [PUSH(_STATE_EXT_FID), DEFINE(stagea_state_ext_uniform_body())]


def run_state_uniform_ext(ef, y_part, diag, sj, isf, isp, ypj):
    """Run the uniform GF(p^2) state body standalone on cashvm (ef precomputed); (v_j as (limb0,limb1), op_cost)."""
    vals = {"ef": ef, "diag": diag, "sj": sj, "isf": isf, "isp": isp, "ypj": ypj}
    for k in range(WIDTH):
        vals["yp%d" % k] = y_part[k]
    unlock = []
    for n in _STATE_EXT_OPS_U:
        unlock += [NUM(vals[n][0] % P), NUM(vals[n][1] % P)]
    vm = VM()
    vm.run(_field_prelude() + unlock + stagea_state_ext_uniform_body())
    assert len(vm.s) == 2, "state uniform body left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


_STATE_EXT_OPS = tuple(["yf%d" % k for k in range(WIDTH)] + ["yp%d" % k for k in range(WIDTH)]
                       + ["sj", "isf", "isp"])                     # ext operands bottom->top


def state_lane_ext_residual_prog(M_row, diag_j, j):
    """HP9.2: the Poseidon2 linear-layer state-update residual for ONE lane j at the OOD point z over GF(p^2) --
    the GF(p^2) mirror of state_residual_lane_prog (base) / _round_residuals_ext's state term (:918-922) with
    _ext_apply_ext (external MDS) + _int_apply_ext (internal diag+sum). Reads y_full[0..W-1], y_part[0..W-1], sj,
    isf, isp (each 2 limbs) from the stack; M_row=M_EXT[j] and diag_j=MAT_DIAG12[j] are pinned public base
    constants (baked, scaled onto the ext y via m.scalar). Leaves [v_j] where ef=sum_k M_row[k]*y_full[k],
    ip=diag_j*y_part[j]+sum_k y_part[k], v_j=isf*(sj-ef)+isp*(sj-ip) over GF(p^2). Needs the field prelude once;
    drops the operand limbs. Cross-checked ==_ext_apply_ext/_int_apply_ext (HP15.11)."""
    def body(m):
        m.copy("yf0"); m.scalar(M_row[0])                         # ef = sum_k M_row[k]*y_full[k]
        for k in range(1, WIDTH):
            m.copy("yf%d" % k); m.scalar(M_row[k]); m.add()
        m.copy("sj"); m.swap(); m.sub(); m.copy("isf"); m.mul()   # term1 = isf*(sj - ef)
        m.copy("yp%d" % j); m.scalar(diag_j)                      # ip = diag_j*y_part[j] + sum_k y_part[k]
        for k in range(WIDTH):
            m.copy("yp%d" % k); m.add()
        m.copy("sj"); m.swap(); m.sub(); m.copy("isp"); m.mul()   # term2 = isp*(sj - ip)
        m.add()                                                   # v_j = term1 + term2
    return _ext_vstack(list(_STATE_EXT_OPS), body)


def state_lane_ext_unlock(y_full, y_part, sj, isf, isp):
    """Push-only GF(p^2) inputs bottom->top in _STATE_EXT_OPS order (y_full[0..], y_part[0..], sj, isf, isp)."""
    vals = {}
    for k in range(WIDTH):
        vals["yf%d" % k] = y_full[k]; vals["yp%d" % k] = y_part[k]
    vals["sj"], vals["isf"], vals["isp"] = sj, isf, isp
    out = []
    for n in _STATE_EXT_OPS:
        out += [NUM(vals[n][0] % P), NUM(vals[n][1] % P)]
    return out


def run_state_lane_ext(M_row, diag_j, j, y_full, y_part, sj, isf, isp):
    """Run the GF(p^2) state-update residual lane on cashvm; (v_j as (limb0, limb1), op_cost)."""
    vm = VM()
    vm.run(_field_prelude() + state_lane_ext_unlock(y_full, y_part, sj, isf, isp)
           + state_lane_ext_residual_prog(M_row, diag_j, j))
    assert len(vm.s) == 2, "state_lane_ext left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


def hold_ext_residuals_prog(n_held):
    """HP9.2: GF(p^2) held-column HOLD residuals at z -- mirror of native_ct_air_prover._hold_residuals_ext
    (nxt[c]-cur[c] per held col). Reads [cur_0..cur_{n-1}, nxt_0..nxt_{n-1}] (each 2 limbs), leaves the n_held
    ext residuals [nxt_0-cur_0, ...]. Drops the operand limbs."""
    ops = ["c%d" % i for i in range(n_held)] + ["n%d" % i for i in range(n_held)]
    def body(m):
        for i in range(n_held):
            m.copy("n%d" % i); m.copy("c%d" % i); m.sub()        # nxt_i - cur_i
    return _ext_vstack(ops, body)


def hold_ext_unlock(cur_vals, nxt_vals):
    """Push-only GF(p^2) inputs: cur held-cols then nxt held-cols (each (limb0, limb1))."""
    out = []
    for v in list(cur_vals) + list(nxt_vals):
        out += [NUM(v[0] % P), NUM(v[1] % P)]
    return out


def run_hold_ext(cur_vals, nxt_vals):
    """Run the GF(p^2) HOLD residuals on cashvm; ([nxt_i-cur_i] as (limb0, limb1) tuples, op_cost)."""
    n = len(cur_vals)
    assert len(nxt_vals) == n, "hold: cur/nxt length mismatch"
    vm = VM()
    vm.run(_field_prelude() + hold_ext_unlock(cur_vals, nxt_vals) + hold_ext_residuals_prog(n))
    assert len(vm.s) == 2 * n, "hold_ext left %d items, expected %d" % (len(vm.s), 2 * n)
    d = [decode_num(x) for x in vm.s]
    return [(d[2 * i], d[2 * i + 1]) for i in range(n)], vm.op_cost


_RANGE_EXT_OPS = ("b", "cs1", "cs2", "ns0", "ns1", "ns2", "w", "isr", "isf", "ist", "isl")


def range_ext_residuals_prog():
    """HP9.2: GF(p^2) range-check transition residuals at z -- mirror of _range_residuals_ext (b=cur.s0):
    isr*(b*(b-1)), isf*(cs1-b), ist*((ns1-cs1)-ns0*w), ist*(ns2-cs2), isl*(cs1-cs2). Reads the 11 ext operands
    (_RANGE_EXT_OPS order), leaves 5 ext residuals. Drops the operand limbs."""
    def body(m):
        m.copy("b"); m.copy("b"); m.const((1, 0)); m.sub(); m.mul(); m.copy("isr"); m.mul()   # isr*(b*(b-1))
        m.copy("cs1"); m.copy("b"); m.sub(); m.copy("isf"); m.mul()                            # isf*(cs1-b)
        m.copy("ns1"); m.copy("cs1"); m.sub()                                                  # ns1-cs1
        m.copy("ns0"); m.copy("w"); m.mul(); m.sub()                                           # (ns1-cs1)-ns0*w
        m.copy("ist"); m.mul()                                                                 # ist*(..)
        m.copy("ns2"); m.copy("cs2"); m.sub(); m.copy("ist"); m.mul()                          # ist*(ns2-cs2)
        m.copy("cs1"); m.copy("cs2"); m.sub(); m.copy("isl"); m.mul()                          # isl*(cs1-cs2)
    return _ext_vstack(list(_RANGE_EXT_OPS), body)


def range_ext_unlock(b, cs1, cs2, ns0, ns1, ns2, w, isr, isf, ist, isl):
    """Push-only GF(p^2) inputs bottom->top in _RANGE_EXT_OPS order."""
    v = dict(b=b, cs1=cs1, cs2=cs2, ns0=ns0, ns1=ns1, ns2=ns2, w=w, isr=isr, isf=isf, ist=ist, isl=isl)
    out = []
    for n in _RANGE_EXT_OPS:
        out += [NUM(v[n][0] % P), NUM(v[n][1] % P)]
    return out


def run_range_ext(b, cs1, cs2, ns0, ns1, ns2, w, isr, isf, ist, isl):
    """Run the GF(p^2) range residuals on cashvm; ([res0..res4] as (limb0, limb1) tuples, op_cost)."""
    vm = VM()
    vm.run(_field_prelude() + range_ext_unlock(b, cs1, cs2, ns0, ns1, ns2, w, isr, isf, ist, isl)
           + range_ext_residuals_prog())
    assert len(vm.s) == 10, "range_ext left %d items, expected 10" % len(vm.s)
    d = [decode_num(x) for x in vm.s]
    return [(d[2 * i], d[2 * i + 1]) for i in range(5)], vm.op_cost


def chain_ext_residuals_prog(minv_cap_rows):
    """HP9.2: GF(p^2) chain (capacity + chaining) transition residuals at z -- mirror of _chain_residuals_ext.
    Baked minv_cap_rows = [M_EXT_INV[k] for k in range(RATE, WIDTH)] (pinned public base rows). Reads
    cur.s0..s{W-1}, nxt.s0..s{W-1}, isbs, isra, minv_chain_row[0..{W-1}] (each 2 limbs; chain_minv at z is EXT).
    Leaves [isbs*(row.cur_state) for each row] + [isra*(sum_j minv_chain_row[j]*nxt.s_j - cur.s0)]. The capacity
    uses a base row (m.scalar), the chaining uses the ext chain_minv (m.mul). Drops the operand limbs."""
    ops = (["cs%d" % j for j in range(WIDTH)] + ["ns%d" % j for j in range(WIDTH)]
           + ["isbs", "isra"] + ["mc%d" % j for j in range(WIDTH)])
    def body(m):
        for row in minv_cap_rows:                                # capacity: isbs * (row . cur_state)
            m.copy("cs0"); m.scalar(row[0])
            for j in range(1, WIDTH):
                m.copy("cs%d" % j); m.scalar(row[j]); m.add()
            m.copy("isbs"); m.mul()
        m.copy("mc0"); m.copy("ns0"); m.mul()                    # chaining: sum_j minv_chain_row[j] * nxt.s_j
        for j in range(1, WIDTH):
            m.copy("mc%d" % j); m.copy("ns%d" % j); m.mul(); m.add()
        m.copy("cs0"); m.sub()                                   # chained - cur.s0
        m.copy("isra"); m.mul()                                  # isra * (chained - cur.s0)
    return _ext_vstack(ops, body)


def chain_ext_unlock(cur_state, nxt_state, isbs, isra, minv_chain_row):
    """Push-only GF(p^2) inputs bottom->top: cur.s0..s{W-1}, nxt.s0..s{W-1}, isbs, isra, minv_chain_row."""
    out = []
    seq = list(cur_state) + list(nxt_state) + [isbs, isra] + list(minv_chain_row)
    for v in seq:
        out += [NUM(v[0] % P), NUM(v[1] % P)]
    return out


def run_chain_ext(minv_cap_rows, cur_state, nxt_state, isbs, isra, minv_chain_row):
    """Run the GF(p^2) chain residuals on cashvm; ([cap_k..., chaining] as (limb0, limb1) tuples, op_cost)."""
    n_res = len(minv_cap_rows) + 1
    vm = VM()
    vm.run(_field_prelude() + chain_ext_unlock(cur_state, nxt_state, isbs, isra, minv_chain_row)
           + chain_ext_residuals_prog(minv_cap_rows))
    assert len(vm.s) == 2 * n_res, "chain_ext left %d items, expected %d" % (len(vm.s), 2 * n_res)
    d = [decode_num(x) for x in vm.s]
    return [(d[2 * i], d[2 * i + 1]) for i in range(n_res)], vm.op_cost


def _n_boundary_residuals(n_out, range_spec):
    """Boundary residual count = eq root/nf (2) + cm_out (n_out) + per range (link + optional cm-bind) + conservation."""
    return 2 + n_out + sum(1 + (1 if has_cmbind else 0) for _, has_cmbind in range_spec) + 1


def boundary_ext_residuals_prog(minv0_row, n_out, range_spec, root, nf, cm_out):
    """HP9.3: the CT-AIR BOUNDARY residuals at the OOD point z over GF(p^2) -- the GF(p^2) mirror of
    ct_boundary_constraints_ext / the deploy counterpart of assemble_boundary_residuals_prog (base), SAME
    (row, fn) order: eq root/nf/cm_out (s0 - from_base(stmt)), per range block a link (vh - s2) + optional
    cm-bind (vh - M_EXT_INV[0].cur_state), then conservation (vh0 - (vh1+vh2+vh3)). Reads s0..s{W-1}, vh0..vh3
    (HELD_COLS order; each 2 limbs) from the stack; minv0_row=M_EXT_INV[0] and the public statement constants
    root/nf/cm_out (base) are baked (pinned, m.const/m.scalar -- not free witness). Leaves the boundary residual
    vector; drops the operand limbs. Cross-checked ==ct_boundary_constraints_ext (HP15.11)."""
    ops = ["s%d" % k for k in range(WIDTH)] + ["vh%d" % i for i in range(4)]
    def body(m):
        m.copy("s0"); m.const((root % P, 0)); m.sub()            # root eq  = s0 - root
        m.copy("s0"); m.const((nf % P, 0)); m.sub()              # nf eq    = s0 - nf
        for i in range(n_out):
            m.copy("s0"); m.const((cm_out[i] % P, 0)); m.sub()   # cm_out eq = s0 - cm_out_i
        for hv_idx, has_cmbind in range_spec:
            m.copy("vh%d" % hv_idx); m.copy("s2"); m.sub()       # link = vh - s2
            if has_cmbind:
                m.copy("s0"); m.scalar(minv0_row[0])             # cm-bind = vh - M_EXT_INV[0].cur_state
                for k in range(1, WIDTH):
                    m.copy("s%d" % k); m.scalar(minv0_row[k]); m.add()
                m.copy("vh%d" % hv_idx); m.swap(); m.sub()       # vh - matvec
        m.copy("vh1"); m.copy("vh2"); m.add(); m.copy("vh3"); m.add()   # vh1 + vh2 + vh3
        m.copy("vh0"); m.swap(); m.sub()                         # conservation = vh0 - (vh1+vh2+vh3)
    return _ext_vstack(ops, body)


def boundary_ext_unlock(cur_state, held_vals):
    """Push-only GF(p^2) inputs bottom->top: cur.s0..s{W-1} then held vh0..vh3 (HELD_COLS order)."""
    out = []
    for v in list(cur_state) + list(held_vals):
        out += [NUM(v[0] % P), NUM(v[1] % P)]
    return out


def run_boundary_ext(minv0_row, n_out, range_spec, root, nf, cm_out, cur_state, held_vals):
    """Run the GF(p^2) boundary residuals on cashvm; ([bound_v...] as (limb0, limb1) tuples, op_cost)."""
    n_res = _n_boundary_residuals(n_out, range_spec)
    vm = VM()
    vm.run(_field_prelude() + boundary_ext_unlock(cur_state, held_vals)
           + boundary_ext_residuals_prog(minv0_row, n_out, range_spec, root, nf, cm_out))
    assert len(vm.s) == 2 * n_res, "boundary_ext left %d items, expected %d" % (len(vm.s), 2 * n_res)
    d = [decode_num(x) for x in vm.s]
    return [(d[2 * i], d[2 * i + 1]) for i in range(n_res)], vm.op_cost


def compose_ext_prog(n_t, n_b, compose_looped=False):
    """HP9.4: the CT-AIR composition comp(z) at the OOD point z over GF(p^2) -- the deploy counterpart of
    compose_stack_prog (base) and the GF(p^2) mirror of native_ct_air_stark._compose_at_ext (:223-226) with the
    per-transition factor qf=zl*ZHz_inv folded in: comp = qf * sum_j(trans_v_j * alpha_T_j) + sum_b(bound_v_b *
    bound_invX_b * alpha_B_b). At z EVERY factor is GF(p^2) (trans/bound residuals are the AIR-eval at z, alphas
    ext, qf=(z-last)/Z_H(z), invX=(z-H[row])^-1) -- so each product is a Karatsuba mul, not the base*ext scalar
    the base compose uses. Reads (bottom->top) [tv_j, ta_j]*n_t, qf, [bv_b, bix_b, ba_b]*n_b (each 2 limbs);
    leaves [comp0, comp1]; drops the operand limbs. compose_looped=True uses the DEFINE/INVOKE multiply-accumulate
    fold (byte cut). Cross-checked ==_compose_at_ext combination (HP15.11)."""
    assert n_t >= 1 and n_b >= 1, "compose_ext needs n_t>=1 and n_b>=1 (real AIR: both hold)"
    if compose_looped:
        return compose_ext_looped_prog(n_t, n_b)
    ops = []
    for j in range(n_t):
        ops += ["tv%d" % j, "ta%d" % j]
    ops += ["qf"]
    for b in range(n_b):
        ops += ["bv%d" % b, "bix%d" % b, "ba%d" % b]

    def body(m):
        m.copy("tv0"); m.copy("ta0"); m.mul()                    # transition: sum_j trans_v_j * alpha_T_j
        for j in range(1, n_t):
            m.copy("tv%d" % j); m.copy("ta%d" % j); m.mul(); m.add()
        m.copy("qf"); m.mul()                                    # * qf = comp_transition
        m.copy("bv0"); m.copy("bix0"); m.mul(); m.copy("ba0"); m.mul()   # boundary: sum_b bv_b*bix_b*ba_b
        for b in range(1, n_b):
            m.copy("bv%d" % b); m.copy("bix%d" % b); m.mul(); m.copy("ba%d" % b); m.mul(); m.add()
        m.add()                                                  # comp = comp_transition + comp_boundary
    return _ext_vstack(ops, body)


_COMPOSE_MAC_T_FID = b"\x26"                                      # multiply-accumulate bodies for the looped compose
_COMPOSE_MAC_B_FID = b"\x27"
_COMPOSE_MAC_T_LAZY_FID = b"\x2a"                                 # HP11.3: raw/deferred-reduction transition MAC (0x2a)


def _compose_mac_t_body():
    """[acc, tv, ta] -> acc + tv*ta over GF(p^2) (transition multiply-accumulate)."""
    def body(m):
        m.copy("tv"); m.copy("ta"); m.mul(); m.copy("acc"); m.add()
    return _ext_vstack(["acc", "tv", "ta"], body)


def _compose_mac_t_lazy_body():
    """HP11.3 op-cost lever: the LAZY transition MAC (0x2a). [acc0,acc1, tv0,tv1, ta0,ta1] -> [acc0+r0, acc1+r1] over
    GF(p^2) RAW (unreduced): r0=tv0*ta0+EXT_W*tv1*ta1, r1=tv0*ta1+tv1*ta0 (the all-positive GF(p^2) product, no
    Karatsuba subtraction) is added to the accumulators WITHOUT reduction; the single mod-p reduction is done by the
    caller after all INVOKEs (== _compose_mac_t_body summed, mod p -- BCH BigInt holds the raw accumulator). Mirrors
    _deep_mac_lazy_body (0x29) minus the value-ood step (the comp transition MAC is just tv*ta). DEFINE'd once so the
    redeem stays small like the eager 0x26; op-cost drops ~4.3x on the real BCH-2026 VM WITHOUT growing the redeem ->
    the op-cost-bound transition parts (e.g. the sbox part) go byte-lighter (smaller op-budget pad). Validated ==eager
    over random + edge {0,1,P-1} + n=1..74. r0/r1 are stashed on the alt while the 4
    operands are dropped (the acc is kept), then folded into the running accumulators."""
    sp = [6]; prog = []                                          # frame: acc0@0,acc1@1, tv0@2,tv1@3, ta0@4,ta1@5
    def copy(ap): prog.extend([NUM(sp[0] - 1 - ap), OP("PICK")]); sp[0] += 1   # abs-frame PICK (robust to pushes)
    def mul(): prog.append(OP("MUL")); sp[0] -= 1
    def add(): prog.append(OP("ADD")); sp[0] -= 1
    def pushn(k): prog.append(NUM(k)); sp[0] += 1
    copy(2); copy(4); mul()                                      # tv0*ta0
    copy(3); copy(5); mul(); pushn(EXT_W); mul(); add()          # r0 = tv0*ta0 + EXT_W*tv1*ta1
    copy(2); copy(5); mul()                                      # tv0*ta1
    copy(3); copy(4); mul(); add()                               # r1 = tv0*ta1 + tv1*ta0
    prog += [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * 4 + [OP("FROMALT"), OP("FROMALT")]   # drop 4 operands, keep acc
    prog += [OP("SWAP"), NUM(3), OP("ROLL"), OP("ADD"), OP("SWAP"), NUM(2), OP("ROLL"), OP("ADD")]  # acc0+=r0; acc1+=r1
    return prog


def _compose_mac_b_body():
    """[acc, bv, bix, ba] -> acc + bv*bix*ba over GF(p^2) (boundary multiply-accumulate)."""
    def body(m):
        m.copy("bv"); m.copy("bix"); m.mul(); m.copy("ba"); m.mul(); m.copy("acc"); m.add()
    return _ext_vstack(["acc", "bv", "bix", "ba"], body)


def stagea_compose_mac_define():
    """DEFINE the two uniform GF(p^2) multiply-accumulate bodies once (0x26 transition, 0x27 boundary)."""
    return ([PUSH(_COMPOSE_MAC_T_FID), DEFINE(_compose_mac_t_body())]
            + [PUSH(_COMPOSE_MAC_B_FID), DEFINE(_compose_mac_b_body())])


def compose_ext_looped_prog(n_t, n_b, below=0):
    """HP9.5: the DEFINE/INVOKE-folded GF(p^2) composition (byte cut for the 74 inlined terms) -- SAME result as
    compose_ext_prog: comp = qf*sum_j(tv_j*ta_j) + sum_b(bv_b*bix_b*ba_b). Reads the SAME interleaved operand
    block [tv_j,ta_j]*n_t, qf, [bv_b,bix_b,ba_b]*n_b; accumulates via the uniform MAC bodies (0x26/0x27) INVOKE'd
    per term instead of inlining. Installs the MAC DEFINEs at entry (net-0). Leaves [comp0, comp1]; drops the
    block. 2-level nesting (MAC body uses inline ext ops -> MM)."""
    NB = 2 * n_t + 1 + 3 * n_b                                    # operand block ext-count (interleaved)
    prog = list(stagea_compose_mac_define())
    sp = [below + 2 * NB]

    def pk_at(ext_idx):
        prog.extend([NUM(sp[0] - 1 - (below + 2 * ext_idx)), OP("PICK")]); sp[0] += 1
        prog.extend([NUM(sp[0] - 1 - (below + 2 * ext_idx + 1)), OP("PICK")]); sp[0] += 1

    prog.extend([NUM(0), NUM(0)]); sp[0] += 2                     # acc_T = 0
    for j in range(n_t):                                         # acc_T += tv_j * ta_j
        pk_at(2 * j); pk_at(2 * j + 1)
        prog.extend([PUSH(_COMPOSE_MAC_T_FID), OP("INVOKE")]); sp[0] -= 4
    pk_at(2 * n_t)                                               # qf
    prog.extend(ext_mul_stack_prog()); sp[0] -= 2                # comp_transition = acc_T * qf
    prog.extend([NUM(0), NUM(0)]); sp[0] += 2                     # acc_B = 0
    for b in range(n_b):                                         # acc_B += bv_b * bix_b * ba_b
        pk_at(2 * n_t + 1 + 3 * b); pk_at(2 * n_t + 2 + 3 * b); pk_at(2 * n_t + 3 + 3 * b)
        prog.extend([PUSH(_COMPOSE_MAC_B_FID), OP("INVOKE")]); sp[0] -= 6
    prog.extend(ext_add_stack_prog()); sp[0] -= 2                # comp = comp_transition + comp_boundary
    assert sp[0] == below + 2 * NB + 2, "compose_looped left sp=%d, expected %d" % (sp[0], below + 2 * NB + 2)
    return prog + [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * (2 * NB) + [OP("FROMALT"), OP("FROMALT")]


def compose_ext_unlock(trans_v, alpha_T, qf, bound_v, bound_invX, alpha_B):
    """Push-only GF(p^2) inputs bottom->top: [tv_j, ta_j]*n_t, qf, [bv_b, bix_b, ba_b]*n_b (each (limb0, limb1))."""
    seq = []
    for tv, ta in zip(trans_v, alpha_T):
        seq += [tv, ta]
    seq += [qf]
    for bv, bix, ba in zip(bound_v, bound_invX, alpha_B):
        seq += [bv, bix, ba]
    out = []
    for v in seq:
        out += [NUM(v[0] % P), NUM(v[1] % P)]
    return out


def run_compose_ext(trans_v, alpha_T, qf, bound_v, bound_invX, alpha_B, compose_looped=False):
    """Run the GF(p^2) composition primitive on cashvm; (comp as (limb0, limb1), op_cost)."""
    n_t, n_b = len(trans_v), len(bound_v)
    assert len(alpha_T) == n_t and len(bound_invX) == n_b and len(alpha_B) == n_b, "compose_ext arity mismatch"
    vm = VM()
    vm.run(_field_prelude() + compose_ext_unlock(trans_v, alpha_T, qf, bound_v, bound_invX, alpha_B)
           + compose_ext_prog(n_t, n_b, compose_looped=compose_looped))
    assert len(vm.s) == 2, "compose_ext left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


def compose_feed_ext_prog(n_t, n_b, below=0):
    """HP9.5: chain the GF(p^2) assembled residuals into comp(z) -- deploy counterpart of compose_feed_prog,
    all ext. Feed block bottom->top: trans_v(n_t), bound_v(n_b), alpha_T(n_t), qf, bound_invX(n_b), alpha_B(n_b)
    (each 2 limbs). PICK-copies the feed values into compose_ext_prog's interleaved layout [tv_j,ta_j]*n_t, qf,
    [bv_b,bix_b,ba_b]*n_b, composes (reusing the tested compose_ext -- no arithmetic duplicated), leaves
    [comp0, comp1], drops the feed block. `below` = items beneath the feed block (PICK offset, kept)."""
    names = ([("tv", j) for j in range(n_t)] + [("bv", b) for b in range(n_b)]
             + [("ta", j) for j in range(n_t)] + [("qf",)]
             + [("bix", b) for b in range(n_b)] + [("ba", b) for b in range(n_b)])
    idx = {nm: i for i, nm in enumerate(names)}     # ext-index within the feed block
    BLOCK = len(names)
    prog = []
    sp = [below + 2 * BLOCK]

    def pk(nm):                                     # copy an ext feed-value to top ([limb0, limb1])
        i = idx[nm]
        prog.extend([NUM(sp[0] - 1 - (below + 2 * i)), OP("PICK")]); sp[0] += 1
        prog.extend([NUM(sp[0] - 1 - (below + 2 * i + 1)), OP("PICK")]); sp[0] += 1

    for j in range(n_t):                            # compose_ext layout: [tv_j, ta_j]
        pk(("tv", j)); pk(("ta", j))
    pk(("qf",))
    for b in range(n_b):                            # [bv_b, bix_b, ba_b]
        pk(("bv", b)); pk(("bix", b)); pk(("ba", b))
    prog += compose_ext_prog(n_t, n_b)              # consumes the arranged copies, leaves comp (2 limbs)
    sp[0] = below + 2 * BLOCK + 2
    return prog + [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * (2 * BLOCK) + [OP("FROMALT"), OP("FROMALT")]


def compose_feed_ext_unlock(trans_v, bound_v, alpha_T, qf, bound_invX, alpha_B):
    """Push-only GF(p^2) feed block bottom->top: trans_v, bound_v, alpha_T, qf, bound_invX, alpha_B."""
    seq = list(trans_v) + list(bound_v) + list(alpha_T) + [qf] + list(bound_invX) + list(alpha_B)
    out = []
    for v in seq:
        out += [NUM(v[0] % P), NUM(v[1] % P)]
    return out


def run_compose_feed_ext(trans_v, bound_v, alpha_T, qf, bound_invX, alpha_B):
    """Run the GF(p^2) compose-feed on cashvm; (comp as (limb0, limb1), op_cost)."""
    n_t, n_b = len(trans_v), len(bound_v)
    vm = VM()
    vm.run(_field_prelude() + compose_feed_ext_unlock(trans_v, bound_v, alpha_T, qf, bound_invX, alpha_B)
           + compose_feed_ext_prog(n_t, n_b))
    assert len(vm.s) == 2, "compose_feed_ext left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


def compose_prog(trans_v, trans_a, qf_trans, bound_v, bound_invX, bound_a):
    """HP2.5: the per-query CT-AIR composition as a cashvm program, leaving [comp0, comp1]
    (the GF(p^2) composition value) on the stack:
      comp_c = qf_trans * sum_j(trans_v_j * alpha_j[c]) + sum_b(bound_v_b*invX_b*alpha_b[c])
    for c in {0,1}. alpha*q is a SCALAR multiply (alpha ext, q base) -> two base
    accumulators, no Karatsuba. qf_trans=(x-last)*Z_H(x)^-1 is shared by all transition
    residuals. Equals native_ct_air_stark.verify()'s comp_x, which the FRI layer-0 opening
    is required to match (so the AIR is bound to the committed FRI)."""
    qf_trans %= P
    prog = _field_prelude()
    for c in (0, 1):                                   # comp0 then comp1 (the two ext limbs)
        prog += [NUM(0)]                               # acc = 0
        for v, a in zip(trans_v, trans_a):
            prog += [NUM(v % P), NUM(a[c] % P)] + MM() + AM()                 # acc += v*alpha[c]
        prog += [NUM(qf_trans)] + MM()                                        # acc *= qf_trans
        for v, ix, a in zip(bound_v, bound_invX, bound_a):
            prog += [NUM(v % P), NUM(ix % P)] + MM() + [NUM(a[c] % P)] + MM() + AM()
    return prog


def run_compose(trans_v, trans_a, qf_trans, bound_v, bound_invX, bound_a):
    vm = VM()
    vm.run(compose_prog(trans_v, trans_a, qf_trans, bound_v, bound_invX, bound_a))
    assert len(vm.s) == 2, "compose left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


def _compose_layout(n_t, n_b):
    """flat operand names bottom->top: per transition [tv,ta0,ta1], then qf, then per boundary
    [bv,bix,ba0,ba1]."""
    names = []
    for j in range(n_t):
        names += ["tv%d" % j, "ta%d_0" % j, "ta%d_1" % j]
    names += ["qf"]
    for b in range(n_b):
        names += ["bv%d" % b, "bix%d" % b, "ba%d_0" % b, "ba%d_1" % b]
    return names


def compose_stack_prog(n_t, n_b):
    """HP2.5 DEPLOYABLE CT-AIR composition: the n_t transition residuals (+ GF(p^2) alphas),
    qf_trans, and n_b boundary residuals (+ invX + alphas) are READ FROM THE STACK by PICK
    (depth-tracked) instead of baked like compose_prog. Identical arithmetic -- two base-field
    accumulators (alpha[c] scalar, no Karatsuba) -- so it reproduces run_compose's (comp0,comp1)
    exactly. The residual VALUES are witness here so the composition can be measured in isolation;
    in the full shard they are COMPUTED on-chain from the opened trace (the AIR-constraint
    fragments) and bound to the FRI layer-0 opening (3.7). Needs the field prelude once; leaves
    [comp0, comp1] and drops the input block. ~41B logic per residual, amortizable into a loop."""
    names = _compose_layout(n_t, n_b)
    top_index = {nm: i for i, nm in enumerate(reversed(names))}
    prog = []
    above = [0]

    def pick(nm):
        prog.extend([NUM(above[0] + top_index[nm]), OP("PICK")]); above[0] += 1

    def num(v):
        prog.append(NUM(v % P)); above[0] += 1

    def mm(): prog.extend(MM()); above[0] -= 1
    def am(): prog.extend(AM()); above[0] -= 1

    for c in (0, 1):
        num(0)                                                      # acc = 0
        for j in range(n_t):
            pick("tv%d" % j); pick("ta%d_%d" % (j, c)); mm(); am()  # acc += tv*ta[c]
        pick("qf"); mm()                                            # acc *= qf_trans
        for b in range(n_b):
            pick("bv%d" % b); pick("bix%d" % b); mm(); pick("ba%d_%d" % (b, c)); mm(); am()
    assert above[0] == 2, "compose_stack left %d intermediates (expected 2)" % above[0]
    return prog + [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * len(names) + [OP("FROMALT"), OP("FROMALT")]


def compose_stack_unlock(trans_v, trans_a, qf_trans, bound_v, bound_invX, bound_a):
    """Push-only operands for compose_stack_prog, in _compose_layout order."""
    w = []
    for v, a in zip(trans_v, trans_a):
        w += [NUM(v % P), NUM(a[0] % P), NUM(a[1] % P)]
    w += [NUM(qf_trans % P)]
    for v, ix, a in zip(bound_v, bound_invX, bound_a):
        w += [NUM(v % P), NUM(ix % P), NUM(a[0] % P), NUM(a[1] % P)]
    return w


def run_compose_stack(trans_v, trans_a, qf_trans, bound_v, bound_invX, bound_a):
    """Run the deployable composition on cashvm; ((comp0,comp1), op_cost)."""
    vm = VM()
    vm.run(_field_prelude() + compose_stack_unlock(trans_v, trans_a, qf_trans, bound_v, bound_invX, bound_a)
           + compose_stack_prog(len(trans_v), len(bound_v)))
    assert len(vm.s) == 2, "compose_stack left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


# ---- HP2.3: selector commitment (pinned root) + Merkle opening -----------------
# The CT-AIR selectors are PUBLIC (they depend only on the membership depth D), so the
# verifier binds them via a SHA256-Merkle commitment whose root is a hardcoded constant
# (A4 decision: cheaper than closed-form / naive Horner, no trace coset re-layout). The
# prover opens the selector row at the FS-derived query index k; the shard SHA256s the
# opened values and walks the path to the pinned root -> a wrong selector value changes
# the leaf hash and the path no longer reaches the root (fail-closed). The same Merkle-
# path program serves the trace openings (HP3.1/3.3) and FRI-layer openings (HP3.5b).
def selector_row_values(lay, r):
    """The 33 public selector values at trace row r, in the canonical commit order the
    shard must reproduce: 8 indicators + rc[12] + chain_minv[12] + range_weight."""
    vals = [lay["is_full"][r], lay["is_partial"][r], lay["is_block_start"][r],
            lay["is_reabsorb"][r], lay["is_range"][r], lay["is_range_first"][r],
            lay["is_range_step"][r], lay["is_range_last"][r]]
    vals += [lay["rc"][k][r] for k in range(WIDTH)]
    vals += [lay["chain_minv"][r][j] for j in range(WIDTH)]
    vals += [lay["range_weight"][r]]
    return [v % P for v in vals]


def selector_preimage(lay, r):
    """Leaf preimage = the row's selector values, each as 8 LE bytes, concatenated."""
    return b"".join(enc8(v) for v in selector_row_values(lay, r))


def build_selector_commitment(lay, T):
    """SHA256-Merkle commitment of the public selector columns over all T rows. Returns
    (root_bytes, tree, preimages). The root is deterministic from the layout -> the
    deployed shard hardcodes it (HP3.8 params-pin)."""
    preimages = [selector_preimage(lay, r) for r in range(T)]
    leaves = [SHA(pre) for pre in preimages]
    tree = smerkle(leaves)
    return sm_root(tree), tree, preimages


# 8 round/range indicator columns, in the canonical order selector_row_values commits them.
_SEL_COSET_KEYS = ("is_full", "is_partial", "is_block_start", "is_reabsorb",
                   "is_range", "is_range_first", "is_range_step", "is_range_last")


def selector_row_values_coset(sv, i):
    """HP2 (Gap A): the 33 public selector values at FRI-COSET-domain index i, read from the
    low-degree-extended vectors sv = native_ct_air_stark._selector_vectors (H -> coset D), in the
    SAME canonical order as selector_row_values (the H-row form): 8 indicators + rc[WIDTH] +
    chain_minv[WIDTH] + range_weight. These are exactly the values the composition consumes at the
    FRI index (native_ct_air_stark._pub_at_idx(sv,i) + range_weight[i]) -- the D-coset, NOT the
    H-domain build_selector_commitment reads."""
    vals = [sv[key][i] for key in _SEL_COSET_KEYS]
    vals += [sv["rc"][k][i] for k in range(WIDTH)]
    vals += [sv["chain_minv"][j][i] for j in range(WIDTH)]
    vals += [sv["range_weight"][i]]
    return [v % P for v in vals]


def selector_preimage_coset(sv, i):
    """Leaf preimage for the D-coset selector commitment: the D-coset selector values at i, each as
    8 LE bytes, concatenated (same encoding as selector_preimage, over the FRI domain)."""
    return b"".join(enc8(v) for v in selector_row_values_coset(sv, i))


def build_selector_commitment_coset(sv, n):
    """HP2 (Gap A): SHA256-Merkle commitment of the public selector columns over the FRI COSET
    domain D (all n = N indices). The composition reads the selectors as their coset-D LDE at the
    FRI index k (_pub_at_idx(sv,k)); the H-domain build_selector_commitment commits the wrong domain
    for that binding, so the shard opens THIS commitment at the FS-derived k against a pinned root
    (fail-closed) -- otherwise the selectors are free witness (gate=0 -> all residuals 0 -> forged
    accept). Returns (root, tree, preimages); the deployed shard hardcodes the root (params-pin)."""
    preimages = [selector_preimage_coset(sv, i) for i in range(n)]
    leaves = [SHA(pre) for pre in preimages]
    tree = smerkle(leaves)
    return sm_root(tree), tree, preimages


def merkle_path_prog(preimage, path, root):
    """Generic SHA256 Merkle-path verifier (reused for selector / trace / FRI openings):
    leaf = SHA256(preimage); for each (sib,bit): leaf = SHA256(leaf+sib) if bit==0 else
    SHA256(sib+leaf); require(leaf == root). A wrong preimage or path fails EQUALVERIFY."""
    prog = [PUSH(preimage), OP("SHA256")]
    for sib, bit in path:
        if bit == 0:
            prog += [PUSH(sib), OP("CAT"), OP("SHA256")]
        else:
            prog += [PUSH(sib), OP("SWAP"), OP("CAT"), OP("SHA256")]
    prog += [PUSH(root), OP("EQUALVERIFY")]
    return prog


def run_merkle_path(preimage, path, root):
    """Run the Merkle-path verifier; (True, op_cost) if it accepts, (False, 0) if it
    fails EQUALVERIFY (fail-closed)."""
    vm = VM()
    try:
        vm.run(merkle_path_prog(preimage, path, root))
        return True, vm.op_cost
    except VMError:
        return False, 0


def merkle_verify_stack_prog(depth, trunc=0):
    """HP3.10 DEPLOYABLE Merkle-path verifier. Where merkle_path_prog BAKES the preimage,
    siblings, root and hardcodes each swap from a known bit (the cashvm logic-test form), the
    deployable shard cannot do that: the data lives in the push-only unlock (or a linked
    sibling input via OP_INPUTBYTECODE) and the direction bits MUST be derived from the
    FS-bound query index k, never taken as free witness -- otherwise a prover could choose
    favourable directions and forge an opening (3.2 fail-closed). So this reads the data from
    the stack and derives bit_i = k mod 2 per level (k //= 2), exactly m_path's i&1 / i//=2
    convention, conditionally swapping (OP_IF) before each CAT+SHA256.

    Stack precondition (bottom->top), supplied by the unlock + prior shard logic:
        [root, sib_{d-1}, ..., sib_1, sib_0, preimage, k]
    Leaves [] on success (EQUALVERIFY aborts the script on any mismatch), alt stack clean.

    SOUNDNESS: k must be the verifier-derived index (fs_idx_tokens, HP3.12) in the full shard;
    it is only supplied as a stack item here so the opener can be measured/tested in isolation.
    Reproduces merkle_path_prog's root exactly; a wrong sibling OR a wrong k fails EQUALVERIFY.

    BYTE-LEVER N3 (trunc): if trunc>0, every SHA256 is truncated to `trunc` bytes (NUM(trunc) SPLIT DROP keeps the
    first `trunc` bytes), so the tree hashes n-byte nodes -> siblings/root are `trunc` bytes not 32 (config
    MERKLE_HASH_BYTES; collision-resistance n*4 bit, guarded >=100-bit in native_ct_air_config). trunc=0 keeps full
    32B and is BYTE-IDENTICAL to the pre-N3 program (no SPLIT emitted) -- current callers pass no trunc, unchanged."""
    assert trunc == 0 or 4 * trunc >= 100, (                    # misuse-resistant (sharp-edges): reject a width whose
        "merkle trunc=%d -> %d-bit collision-resistance < 100-bit (unsafe truncation)" % (trunc, 4 * trunc))
    tr = [NUM(trunc), OP("SPLIT"), OP("DROP")] if trunc else []   # keep first `trunc` bytes of the 32B hash
    prog = [OP("TOALT"), OP("SHA256")] + tr                     # k -> alt ; leaf = (trunc of) SHA256(preimage)
    for _ in range(depth):
        prog += [OP("FROMALT"), OP("DUP"), NUM(2), OP("MOD"),   # [.., sib, H, bit]   bit = k mod 2
                 OP("SWAP"), NUM(2), OP("DIV"), OP("TOALT")]    # k //= 2 back to alt
        prog += [OP("NOT"), OP("IF"), OP("SWAP"), OP("ENDIF"),  # bit==0 -> [H, sib] (else sib||H)
                 OP("CAT"), OP("SHA256")] + tr
    prog += [OP("FROMALT"), OP("DROP"), OP("EQUALVERIFY")]      # drop spent k (==0) ; H == root
    return prog


def merkle_verify_stack_unlock(preimage, path, root, k):
    """The push-only unlock witness for merkle_verify_stack_prog: [root, sib_{d-1}..sib_0,
    preimage, k] (siblings pushed in reverse so sib_0 ends up just below the leaf). path =
    [(sib_i, bit_i)] from stark.m_path; the bits are NOT pushed (the verifier derives them)."""
    sibs = [s for s, _ in path]
    return [PUSH(root)] + [PUSH(s) for s in reversed(sibs)] + [PUSH(preimage), NUM(k)]


def run_merkle_verify_stack(preimage, path, root, k):
    """Run the deployable opener on cashvm; (True, op_cost) if it accepts, (False, 0) on a
    fail-closed reject (wrong sibling or wrong index)."""
    vm = VM()
    try:
        vm.run(merkle_verify_stack_unlock(preimage, path, root, k) + merkle_verify_stack_prog(len(path)))
        return True, vm.op_cost
    except VMError:
        return False, 0


def merkle_verify_retain_prog(depth, trunc=0):
    """HP2 (2.12): like merkle_verify_stack_prog but RETAINS the opened preimage on the stack after
    the pinned-root check, instead of leaving []. The shard needs the opened trace / selector leaf's
    field cells for the residuals/composition. A copy of the preimage is stashed on the alt stack
    (below k) via OVER before the verify-only opener runs (which pushes k above it and cleans only k),
    then restored. Stack precondition (bottom->top): [root, sib_{d-1}..sib_0, preimage, k]; on success
    leaves [preimage] (a wrong sibling/index still fails EQUALVERIFY fail-closed), alt stack clean.
    trunc>0: N3 truncated-hash tree (roots/siblings n bytes), forwarded to merkle_verify_stack_prog."""
    return [OP("OVER"), OP("TOALT")] + merkle_verify_stack_prog(depth, trunc) + [OP("FROMALT")]


def split_cells_prog(n, prefix=0):
    """HP2 (2.14/2.19): split the top-of-stack Merkle preimage -- `prefix` salt bytes followed by n
    concatenated 8-byte LE field cells (the _leaf / selector_preimage_coset format) -- into the n
    field numbers, leaving [cell_0, ..., cell_{n-1}] (bottom->top). Each 8-byte slice is 0x00-padded
    and BIN2NUM-re-encoded minimal (libauth rejects non-minimal numbers); the salt prefix is dropped."""
    prog = []
    if prefix:
        prog += [NUM(prefix), OP("SPLIT"), OP("NIP")]                    # drop the salt prefix
    for i in range(n):
        if i < n - 1:
            prog += [NUM(8), OP("SPLIT"),                                # [.., cell_bytes, rest]
                     OP("SWAP"), PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM"), OP("SWAP")]  # [.., cell, rest]
        else:
            prog += [PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM")]           # last 8 bytes -> cell
    return prog


def split_cells_loop(n, prefix=0):
    """HP12 byte lever: split `prefix` salt bytes + n concatenated 8-byte LE field cells into [cell_0..cell_{n-1}]
    (bottom->top) -- IDENTICAL result to split_cells_prog, but a BEGIN/UNTIL loop so the redeem stays ~constant
    (~23B) instead of unrolled ~n*8B (split_cells(556)=4444B -> loop=23B). The decisive lever for the DEEP
    per-query consumer: it reads the FS blob (z+z*g+138 ood+138 deep_alphas = 556 field cells) via
    OP_INPUTBYTECODE (HP12/HP15) and must split it on-chain; the unrolled split blows the 10000B redeem, the loop
    fits. Mirrors the HP3.10 merkle_verify_loop amortization. The iteration count n is PINNED (a counter on the
    alt stack, exit at n) -- never a witness flag, so a prover cannot pad/skip cells. Each pass splits 8 bytes,
    0x00-pads + BIN2NUM (minimal, libauth-safe) and tucks the cell below the remaining blob (== split_cells's
    per-cell op); after n passes the blob is exhausted (empty rest dropped). Stack: [blob] -> [cell_0..cell_{n-1}]."""
    prog = []
    if prefix:
        prog += [NUM(prefix), OP("SPLIT"), OP("NIP")]                    # drop the salt prefix (once)
    body = [NUM(8), OP("SPLIT"), OP("SWAP"), PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM"), OP("SWAP")]  # [..,rest]->[..,cell,rest']
    prog += ([NUM(0), OP("TOALT"), OP("BEGIN")] + body
             + [OP("FROMALT"), OP("1ADD"), OP("DUP"), OP("TOALT"), NUM(n), OP("NUMEQUAL"), OP("UNTIL"),
                OP("FROMALT"), OP("DROP"), OP("DROP")])                  # pinned count; clean counter + drop empty rest
    return prog


def merkle_verify_loop_prog(depth, n_opens):
    """HP3.10 logic amortization: ONE OP_BEGIN/UNTIL loop body (the deployable opener) verifies
    n_opens same-depth openings, each reading its witness block from the unlock, so the redeem
    (verifier logic) stays ~constant (~200B) however many openings a query/layer needs instead
    of replicating the opener per opening -- the decisive lever for the <100KB total-tx fit
    (measured: 190..201B for n_opens 1..20 on the real VM). The iteration count is PINNED
    (n_opens), never a witness flag: a counter on the alt stack BELOW k (the opener cleans k
    each iteration, so the counter survives) increments per pass and the loop exits at n_opens.
    A prover cannot skip or pad openings -- too few witness blocks underflow the opener, too
    many leave a non-empty stack; both reject (fail-closed count binding). All openings must
    share `depth` (FRI layers of different depth use one loop each). Leaves [] (append the
    script's terminal, or chain the next shard stage)."""
    return ([NUM(0), OP("TOALT"), OP("BEGIN")] + merkle_verify_stack_prog(depth)
            + [OP("FROMALT"), OP("1ADD"), OP("DUP"), OP("TOALT"), NUM(n_opens),
               OP("NUMEQUAL"), OP("UNTIL"), OP("FROMALT"), OP("DROP")])


def opener_commit_prog(depth, n_cells, prefix, trunc=0):
    """HP5 OPENER core (single leaf open + commit + index-bind). Open a Merkle leaf at the COMMITTED index k
    against a pinned root, then prove BOTH: the committed cells == the opened leaf's field cells (5.3
    blob==split) AND the leaf was opened at EXACTLY the committed k (5.4 k==Oeffnungs-Index -- by construction:
    the committed k is fed to the opener, so a wrong committed k opens the leaf at the wrong index and the path
    fails). The opener commits [cell_0..cell_{n_cells-1} | k] as its first push (the blob): a prover cannot
    commit different cells (they mismatch the opened preimage under the pinned root) nor a different index (the
    path fails at it) -- fail-closed. Reuses the validated merkle_verify_retain_prog + split_cells_prog; the
    committed cells sit at the bottom of the alt stack and survive the opener's net-zero alt usage. The deploy
    opener_input_prog reads root (tp_root/sel_root) single-source from the FS blob (HP9.2) and k from the FS
    input, and loops this over the trace@k / trace@kn / selector leaves of each slot in its query range.

    Stack precondition (bottom->top): [root, sib_{depth-1}..sib_0, preimage, blob] where
    blob = enc8(cell_0) .. enc8(cell_{n_cells-1}) enc8(k). Leaves [1] on accept; fails closed on any mismatch."""
    pad = [PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM")]           # unsigned 8-byte LE -> num
    # split the blob (top): trailing 8 bytes = k (feed the opener), the leading cells -> alt (committed, LIFO)
    prog = [PUSH(encode_num(n_cells * 8)), OP("SPLIT")]       # [.., preimage, cells_bytes, k_bytes]
    prog += pad + [OP("SWAP")]                                # k_bytes -> k ; [.., preimage, k, cells_bytes]
    for i in range(n_cells):
        if i < n_cells - 1:
            prog += [PUSH(encode_num(8)), OP("SPLIT"), OP("SWAP")] + pad + [OP("TOALT")]  # cell_i -> alt
        else:
            prog += pad + [OP("TOALT")]                       # last cell -> alt (alt top = committed_{n_cells-1})
    # main is now [root, sibs, preimage, k] -> open @ the committed k and retain the opened preimage
    prog += merkle_verify_retain_prog(depth, trunc)          # [preimage] ; wrong sib/k -> EQUALVERIFY (fail-closed, N3)
    prog += split_cells_prog(n_cells, prefix=prefix)          # [opened_0 .. opened_{n_cells-1}]
    for _ in range(n_cells):
        prog += [OP("FROMALT"), OP("NUMEQUALVERIFY")]         # opened_j == committed_j (LIFO matched)
    prog += [NUM(1)]
    return prog


def _opener_from_blob_body(depth, n_cells, prefix, trunc=0):
    """One FROM-BLOB opening (the deploy-optimal opener core). Precondition (bottom->top): [root, sib_{depth-1}..sib_0,
    (salt if prefix>0,) blob=enc8(cell_0..cell_{n-1})||enc8(k)]. Splits the blob into cells_bytes + k, DERIVES the
    preimage = (salt ++) cells_bytes and merkle-verifies SHA256(preimage) @k against root -- so the cells are
    MERKLE-BOUND to the leaf (a forged cell -> wrong preimage -> EQUALVERIFY fails, fail-closed) WITHOUT a separate
    commit-check (merkle IS the binding). The blob stays in the scriptSig, read cross-input by the per-query DEEP
    consumer; this saves the ~n_cells*8 B the commit form duplicated (blob's cells + a separate preimage push). Leaves
    [] and is net-zero on the alt stack (merkle_verify_stack's k-climb + the salt-CAT's k-stash are both net-zero)."""
    body = [NUM(n_cells * 8), OP("SPLIT")]                        # blob -> [.., (salt,) cells_bytes, k_bytes]
    body += [PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM")]            # k_bytes(8) -> k (unsigned num, minimal)
    if prefix:
        body += [OP("TOALT"), OP("CAT"), OP("FROMALT")]         # preimage = salt ++ cells_bytes ; keep k on top
    return body + merkle_verify_stack_prog(depth, trunc)        # SHA256(preimage)@k == root (fail-closed, N3 trunc), leaves []


def looped_opener_from_blob_prog(depth, n_cells, n_opens, prefix=0, trunc=0):
    """HP16 openers lever (deploy-optimal): verify n_opens same-(depth,n_cells) FROM-BLOB openings in ONE pinned-count
    OP_BEGIN/UNTIL loop, so the opener redeem (~merkle-verify only) is revealed ONCE for a whole query set instead of
    per query. Each opening derives its preimage from the exposed blob (no duplicated preimage push) and merkle-binds
    the cells (see _opener_from_blob_body) -- smaller than a commit-based opener (saves ~n_cells*8 B per opening: no
    duplicated cells, no split_cells+NUMEQUALVERIFY) AND sound (merkle IS the commit binding). The body is net-zero on
    the alt stack, so the loop counter on the alt BOTTOM survives each iteration (the merkle_verify_loop pattern). The
    count n_opens is PINNED: too few witness blocks underflow, too many leave a non-empty stack -- both reject
    fail-closed, so a prover cannot skip or pad openings. Each witness block (bottom->top): [root, sib_{depth-1}..sib_0,
    (salt if prefix>0,) blob=enc8(cell_0..cell_{n-1})||enc8(k)]; blocks stacked last-processed at the bottom. Leaves [1]."""
    body = _opener_from_blob_body(depth, n_cells, prefix, trunc)
    return ([NUM(0), OP("TOALT"), OP("BEGIN")] + body
            + [OP("FROMALT"), OP("1ADD"), OP("DUP"), OP("TOALT"), NUM(n_opens),
               OP("NUMEQUAL"), OP("UNTIL"), OP("FROMALT"), OP("DROP"), NUM(1)])


def merkle_verify_loop_unlock(opens):
    """Push-only witness for merkle_verify_loop_prog: the per-open unlock blocks concatenated
    with the last-processed open at the bottom (first-processed on top). opens =
    [(preimage, path, root, k), ...] in processing order."""
    w = []
    for i in range(len(opens) - 1, -1, -1):
        w += merkle_verify_stack_unlock(*opens[i])
    return w


def run_merkle_verify_loop(opens, depth, n_opens):
    """Run the pinned-count looped opener on cashvm; (True, op_cost) on accept, (False, 0) on a
    fail-closed reject (wrong opening, or a witness whose block count != n_opens)."""
    vm = VM()
    try:
        vm.run(merkle_verify_loop_unlock(opens) + merkle_verify_loop_prog(depth, n_opens) + [NUM(1)])
        return True, vm.op_cost
    except VMError:
        return False, 0


def ext_fold_prog(fv0, fv1, fw0, fw1, b0, b1, inv2, i2x, twox):
    """HP3.5: one GF(p^2) FRI fold step on the BCH-VM, leaving [folded0, folded1]:
       folded = (fv+fw)*inv2 + beta*(fv-fw)*inv2x   over GF(p^2)
    fv=(fv0,fv1), fw=(fw0,fw1), beta=(b0,b1) ext; inv2, inv2x base. The inverses are
    HINT-validated (inv2*2==1, inv2x*(2*xpos)==1, twox=2*xpos) exactly like
    structures_fri.FOLD -> a wrong hint fails NUMEQUALVERIFY (fail-closed). Computed in two
    passes (folded0 then folded1) with re-pushed literals (no deep PICK juggling); op-cost
    packing is HP3-final. od = (fv-fw)*inv2x; beta*od via the Karatsuba c0=od0*b0+7*od1*b1,
    c1=(od0+od1)(b0+b1)-od0*b0-od1*b1."""
    return _field_prelude() + ext_fold_logic(fv0, fv1, fw0, fw1, b0, b1, inv2, i2x, twox)


def ext_fold_logic(fv0, fv1, fw0, fw1, b0, b1, inv2, i2x, twox):
    """The ext_fold tokens WITHOUT the field prelude, so several folds can run in one
    program (FRI fold chain) under a single MULMOD/ADDMOD/SUBMOD definition."""
    fv0 %= P; fv1 %= P; fw0 %= P; fw1 %= P; b0 %= P; b1 %= P
    inv2 %= P; i2x %= P; twox %= P
    prog = []
    # hint checks (fail-closed)
    prog += [NUM(inv2), NUM(2)] + MM() + [NUM(1), OP("NUMEQUALVERIFY")]
    prog += [NUM(i2x), NUM(twox)] + MM() + [NUM(1), OP("NUMEQUALVERIFY")]
    # folded0 = inv2*(fv0+fw0) + od0*b0 + 7*od1*b1   (od_k = i2x*(fv_k-fw_k))
    prog += [NUM(fv0), NUM(fw0)] + AM() + [NUM(inv2)] + MM()                              # [e0]
    prog += [NUM(fv0), NUM(fw0)] + SM() + [NUM(i2x)] + MM() + [NUM(b0)] + MM()            # [e0, od0*b0]
    prog += ([NUM(fv1), NUM(fw1)] + SM() + [NUM(i2x)] + MM() + [NUM(b1)] + MM()
             + [NUM(EXT_W % P)] + MM())                                                   # [e0, od0b0, 7od1b1]
    prog += AM() + AM()                                                                   # [folded0]
    # folded1 = inv2*(fv1+fw1) + (od0+od1)*(b0+b1) - od0*b0 - od1*b1
    prog += [NUM(fv1), NUM(fw1)] + AM() + [NUM(inv2)] + MM()                              # [folded0, e1]
    prog += ([NUM(fv0), NUM(fw0)] + SM() + [NUM(fv1), NUM(fw1)] + SM() + AM()
             + [NUM(i2x)] + MM())                                                         # [.., s_od=od0+od1]
    prog += [NUM(b0), NUM(b1)] + AM() + MM()                                              # [folded0,e1, part1]
    prog += [NUM(fv0), NUM(fw0)] + SM() + [NUM(i2x)] + MM() + [NUM(b0)] + MM() + SM()     # part1 - od0b0
    prog += [NUM(fv1), NUM(fw1)] + SM() + [NUM(i2x)] + MM() + [NUM(b1)] + MM() + SM()     # - od1b1 = o1
    prog += AM()                                                                          # [folded0, folded1]
    return prog


def run_ext_fold(fv0, fv1, fw0, fw1, b0, b1, inv2, i2x, twox):
    vm = VM()
    vm.run(ext_fold_prog(fv0, fv1, fw0, fw1, b0, b1, inv2, i2x, twox))
    assert len(vm.s) == 2, "ext_fold left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


_FOLD_OPS = ("fw0", "fw1", "b0", "b1", "inv2", "i2x", "twox", "fv0", "fv1")  # bottom->top; fv ON TOP
# fv on top so the chain composes: each fold leaves [folded0, folded1] on top (= the next fv),
# directly above the next layer's operand block, forming the next 9-operand window with no juggling.


def ext_fold_stack_prog():
    """HP3.10 DEPLOYABLE GF(p^2) FRI fold: the nine operands (fv0,fv1,fw0,fw1,b0,b1,inv2,i2x,
    twox) are READ FROM THE STACK (the carried running value + a linked sibling open + the
    FS-derived beta/inverse) instead of re-pushed as literals like ext_fold_logic. The arithmetic
    is identical -- only operand access changes from NUM(value) to PICK(depth) -- so it reproduces
    (folded0,folded1) exactly and stays fail-closed (the hint-validated inverses inv2*2==1,
    i2x*twox==1 reject a bad witness). Needs the field prelude (p on alt + MULMOD/ADDMOD/SUBMOD)
    once; leaves [folded0, folded1] and drops the nine operands. The PICK depth is tracked
    mechanically (above = intermediates over the operand block) so the access is exact."""
    prog = []
    above = [0]
    top_index = {n: i for i, n in enumerate(reversed(_FOLD_OPS))}  # twox=0 (top) .. fv0=8 (bottom)

    def pick(name):
        prog.extend([NUM(above[0] + top_index[name]), OP("PICK")]); above[0] += 1

    def num(v):
        prog.append(NUM(v % P)); above[0] += 1

    def mm(): prog.extend(MM()); above[0] -= 1
    def am(): prog.extend(AM()); above[0] -= 1
    def sm(): prog.extend(SM()); above[0] -= 1
    def neqv(): prog.append(OP("NUMEQUALVERIFY")); above[0] -= 2

    pick("inv2"); num(2); mm(); num(1); neqv()                                        # inv2*2 == 1
    pick("i2x"); pick("twox"); mm(); num(1); neqv()                                   # i2x*twox == 1
    pick("fv0"); pick("fw0"); am(); pick("inv2"); mm()                                # e0
    pick("fv0"); pick("fw0"); sm(); pick("i2x"); mm(); pick("b0"); mm()               # od0*b0
    pick("fv1"); pick("fw1"); sm(); pick("i2x"); mm(); pick("b1"); mm(); num(EXT_W); mm()  # 7*od1*b1
    am(); am()                                                                        # folded0
    pick("fv1"); pick("fw1"); am(); pick("inv2"); mm()                                # e1
    pick("fv0"); pick("fw0"); sm(); pick("fv1"); pick("fw1"); sm(); am(); pick("i2x"); mm()  # s_od*i2x
    pick("b0"); pick("b1"); am(); mm()                                                # (od0+od1)*(b0+b1)
    pick("fv0"); pick("fw0"); sm(); pick("i2x"); mm(); pick("b0"); mm(); sm()         # - od0*b0
    pick("fv1"); pick("fw1"); sm(); pick("i2x"); mm(); pick("b1"); mm(); sm()         # - od1*b1
    am()                                                                              # folded1
    assert above[0] == 2, "ext_fold_stack left %d intermediates (expected 2)" % above[0]
    # stash the 2 results on the alt stack (above p), drop the 9 operands, restore them
    prog += [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * 9 + [OP("FROMALT"), OP("FROMALT")]
    return prog


def ext_fold_stack_unlock(fv0, fv1, fw0, fw1, b0, b1, inv2, i2x, twox):
    """Push-only operands for ext_fold_stack_prog, bottom->top in _FOLD_OPS order."""
    v = dict(fv0=fv0, fv1=fv1, fw0=fw0, fw1=fw1, b0=b0, b1=b1, inv2=inv2, i2x=i2x, twox=twox)
    return [NUM(v[n] % P) for n in _FOLD_OPS]


def run_ext_fold_stack(fv0, fv1, fw0, fw1, b0, b1, inv2, i2x, twox):
    """Run the deployable fold on cashvm; ((folded0,folded1), op_cost), or raises (fail-closed)."""
    vm = VM()
    vm.run(_field_prelude() + ext_fold_stack_unlock(fv0, fv1, fw0, fw1, b0, b1, inv2, i2x, twox)
           + ext_fold_stack_prog())
    assert len(vm.s) == 2, "ext_fold_stack left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


def ext_fold_chain_prog(n_layers):
    """DEPLOYABLE FRI fold CHAIN: n_layers sequential GF(p^2) folds. Because ext_fold_stack reads
    fv ON TOP and leaves [folded0, folded1] on top (= the next layer's fv), the running value
    flows straight into the next fold with no juggling -- the field prelude is shared once and
    each fold's logic (~50B) amortizes over the chain (the pinned-count loop form, proven for the
    opener, applies identically). The per-layer operand blocks come from the witness below the
    carried value. Leaves the final [fv0, fv1]."""
    return _field_prelude() + ext_fold_stack_prog() * n_layers


def ext_fold_chain_unlock(layers, fv0, fv1):
    """Witness for ext_fold_chain_prog: the per-layer blocks (fw0,fw1,b0,b1,inv2,i2x,twox) for
    layers n-1..0 (so layer 0's block sits just under the initial running value), then the
    initial fv0, fv1 on top. layers = [(fw0,fw1,b0,b1,inv2,i2x,twox), ...] in fold order."""
    w = []
    for layer in reversed(layers):
        w += [NUM(x % P) for x in layer]
    return w + [NUM(fv0 % P), NUM(fv1 % P)]


def run_ext_fold_chain(layers, fv0, fv1):
    """Run the deployable fold chain on cashvm; ((fv0,fv1), op_cost), or raises (fail-closed)."""
    vm = VM()
    vm.run(ext_fold_chain_unlock(layers, fv0, fv1) + ext_fold_chain_prog(len(layers)))
    assert len(vm.s) == 2, "ext_fold_chain left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


# ---- HP3.6: runtime modexp (the verifier DERIVES x = offset*omega^k itself) -----
# The query index k is recomputed from the Fiat-Shamir transcript on-chain (HP3.12), so
# it is a RUNTIME value -> the modexp must extract its bits at runtime (OP_BEGIN/UNTIL
# square-and-multiply), not unroll known bits. Mirrors the deployed fused/gen_verifier.py
# modexp() exactly; uses inline OP_MUL + P-OP_MOD (positive operands, no normalization).
_MODT = [PUSH(encode_num(P)), OP("MOD")]


def _modexp_loop():
    """Square-and-multiply loop for base^exp mod P, assuming [base, exp] on the stack (exp on top);
    leaves [result]. Field muls use the self-contained _MODT (PUSH(P), MOD) -- no INVOKE table, so no
    field prelude is required. Shared by modexp_prog (baked inputs) and fri_xpos_prog (on-stack exp)."""
    return ([OP("TOALT"), OP("TOALT"), NUM(1), OP("FROMALT"), OP("FROMALT")]  # [r=1, base, exp]
            + [OP("BEGIN"),
               OP("DUP"), NUM(2), OP("DIV"), OP("TOALT"),                     # e/2 -> alt
               NUM(2), OP("MOD"),                                             # bit = e%2
               OP("IF"), OP("DUP"), OP("ROT"), OP("MUL")] + _MODT + [OP("SWAP"), OP("ENDIF"),
               OP("DUP"), OP("MUL")] + _MODT + [                             # base = base^2
               OP("FROMALT"),                                                # e = e/2
               OP("DUP"), NUM(0), OP("NUMEQUAL"),
               OP("UNTIL"),
               OP("2DROP")])                                                  # drop base, e -> [result]


def modexp_prog(base, exp):
    """base^exp mod P via a runtime square-and-multiply loop (baked base/exp), leaving [result]."""
    return [NUM(base % P), NUM(exp % P)] + _modexp_loop()


def xpos_prog(omega, exp, offset):
    """x = offset * omega^exp mod P (the FRI/AIR query point the verifier binds itself)."""
    prog = modexp_prog(omega, exp)
    prog += [NUM(offset % P), OP("MUL")] + _MODT
    return prog


def run_modexp(base, exp):
    vm = VM()
    vm.run(modexp_prog(base, exp))
    assert len(vm.s) == 1, "modexp left %d items, expected 1" % len(vm.s)
    return decode_num(vm.s[-1]), vm.op_cost


def run_xpos(omega, exp, offset):
    vm = VM()
    vm.run(xpos_prog(omega, exp, offset))
    assert len(vm.s) == 1, "xpos left %d items, expected 1" % len(vm.s)
    return decode_num(vm.s[-1]), vm.op_cost


def fri_xpos_prog(oN, off, li):
    """HP2 (2.24): the per-FRI-layer domain point xpos_li = (off * oN^ii_li)^(2^li) mod P, derived
    on-chain from the fold index ii_li (2.23) on the stack. Mirrors verify:270
    xpos = pow(mul(off, pow(oN, ii)), 2**li). oN (FRI domain generator), off (coset offset) and the
    layer exponent 2^li are pinned; ii_li is derived (no free witness). Input: [ii_li] (top); leaves
    [xpos_li]. Reuses the square-and-multiply loop (_modexp_loop, self-contained via _MODT -> no field
    prelude). 2*xpos_li is the fold point the FRI fold consumes (twox, 2.27)."""
    prog = [PUSH(encode_num(oN % P)), OP("SWAP")] + _modexp_loop()   # [oN^ii_li]  (base=oN, exp=ii_li)
    prog += [NUM(off % P), OP("MUL")] + _MODT                        # [off * oN^ii_li]
    prog += [PUSH(encode_num(2 ** li))] + _modexp_loop()             # [(off*oN^ii_li)^(2^li)]
    return prog


def run_fri_xpos(oN, off, li, ii):
    """Run the per-layer xpos derivation on cashvm; (xpos_li, op_cost). No field prelude (self-contained)."""
    vm = VM()
    vm.run([NUM(ii % P)] + fri_xpos_prog(oN, off, li))
    assert len(vm.s) == 1, "fri_xpos left %d items, expected 1" % len(vm.s)
    return decode_num(vm.s[-1]), vm.op_cost


def _fri_coset_twox_prog(base_depth, m_stride, oN, off, exp2):
    """HP1.9-FOLD8 / HP7.1b: derive the fold domain point twox = 2*(off*oN^(base+m_stride))^exp2 mod P
    on-chain from the round base index (PICK-copied at depth base_depth) + the PINNED coset offset
    m_stride and layer exponent exp2 = 2^(li0+f) -- NEVER baked (a baked twox lets a prover solve it per
    fold so any value hits the committed leaf -> FRI vacuum -> value-minting). Net stack effect +1 (twox
    on top); base is only read. Reuses the self-contained square-and-multiply loop (_modexp_loop via _MODT,
    so no field prelude of its own; its balanced alt use for the exponent never touches a resident P)."""
    t = [NUM(base_depth), OP("PICK")]                                      # copy base
    t += [NUM(m_stride % P), OP("ADD")] + _MODT                            # gidx = (base + m*stride) mod P
    t += [PUSH(encode_num(oN % P)), OP("SWAP")] + _modexp_loop()           # oN^gidx  (base=oN, exp=gidx)
    t += [NUM(off % P), OP("MUL")] + _MODT                                 # off * oN^gidx
    t += [PUSH(encode_num(exp2))] + _modexp_loop()                         # (off*oN^gidx)^exp2 = xpos
    t += [NUM(2), OP("MUL")] + _MODT                                       # twox = 2*xpos
    return t


def fri_coset_fold_prog(s, li0, stride, oN, off, betas_round):
    """HP1.9-FOLD8: fold ONE 2^s-coset (ethSTARK 3.11.1 layer-skipping) down to ONE GF(p^2) value on the
    BCH-VM -- s sequential fold-by-2 steps applied to the 2^s opened coset values (the round's byte win:
    one committed layer per `s` folds). Precondition (bottom->top): [i2x_0..i2x_{K-1}, base, coset] with
    K=2^s-1 inverse HINTS (witness) in processing order, base = the DERIVED round leaf index, coset = the
    2^s split GF(p^2) values (c0_0,c0_1,...). Leaves [i2x_block, base, folded0, folded1] (the caller drops
    the K+1 lower items after the round). Per butterfly (level f, coset-index m): fw=cur[m+2^(s-1-f)],
    fv=cur[m]; beta=betas_round[f] (FS-pinned, single-source); inv2 pinned; twox DERIVED on-chain
    (_fri_coset_twox_prog, HP7.1b) from base+m*stride; i2x a witness hint checked i2x*twox==1 by
    ext_fold_stack (fail-closed). Results accumulate on the MAIN stack (never the alt, so ext_fold's MULMOD
    always sees a clean alt=[P]); each level ends by dropping the consumed cur values in a feld-op-free
    TOALT/DROP/FROMALT window. The PICK depths are m-invariant within a level (the coset position offset
    cancels the accumulated result offset). Needs the field prelude (ext_fold_stack MULMOD/ADDMOD/SUBMOD).
    Validated == the reference _coset_fold on real prove(fold_step=3) proofs (bl4/8/16)."""
    prog = []
    cnt = 1 << s
    K = (1 << s) - 1
    H = K + 1 + 2 * cnt                                                     # i2x block + base + coset limbs
    inv2 = pow(2, P - 2, P)
    oi = 0
    for f in range(s):
        h = cnt // 2
        exp2 = 1 << (li0 + f)
        for m in range(h):
            b0, b1 = betas_round[f][0] % P, betas_round[f][1] % P
            b = 0
            prog += [NUM((2 * h - 1) + b), OP("PICK")]; b += 1             # fw0
            prog += [NUM((2 * h - 2) + b), OP("PICK")]; b += 1             # fw1
            prog += [NUM(b0), NUM(b1), NUM(inv2)]; b += 3                  # b0, b1, inv2 (pinned)
            prog += [NUM((H + b - 1) - oi), OP("PICK")]; b += 1            # i2x_oi (witness hint at position oi)
            prog += _fri_coset_twox_prog((H + b - 1) - K, m * stride, oN, off, exp2); b += 1  # twox (base@pos K)
            prog += [NUM((2 * cnt - 1) + b), OP("PICK")]; b += 1           # fv0
            prog += [NUM((2 * cnt - 2) + b), OP("PICK")]; b += 1           # fv1
            prog += ext_fold_stack_prog()                                 # consume 9-block -> [folded0,folded1]
            H += 2; oi += 1
        nres = 2 * h; ncur = 2 * cnt
        prog += [OP("TOALT")] * nres + [OP("DROP")] * ncur + [OP("FROMALT")] * nres
        H = K + 1 + nres
        cnt = h
    return prog


def fri_coset_fold_unlock(base, coset, i2x_list):
    """Push-only witness for fri_coset_fold_prog: [i2x_0..i2x_{K-1}, base, c0_0,c0_1,...,c_{2^s-1}_1]."""
    w = [NUM(x % P) for x in i2x_list] + [NUM(base % P)]
    for v in coset:
        w += [NUM(v[0] % P), NUM(v[1] % P)]
    return w


def run_fri_coset_fold(base, coset, s, li0, stride, oN, off, betas_round, i2x_list):
    """Run the deployable coset fold on cashvm; ((folded0, folded1), op_cost). Raises (fail-closed) on a
    wrong i2x hint (i2x*twox != 1). The K+1 lower items (i2x block + base) stay below the [folded0,folded1]."""
    vm = VM()
    vm.run(_field_prelude() + fri_coset_fold_unlock(base, coset, i2x_list)
           + fri_coset_fold_prog(s, li0, stride, oN, off, betas_round))
    K = (1 << s) - 1
    assert len(vm.s) == K + 3, "fri_coset_fold left %d items, expected %d" % (len(vm.s), K + 3)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


def fri_coset_open_fold_prog(depth, s, li0, stride, oN, off, betas_round, trunc=0):
    """HP1.9-FOLD8: the full per-round FRI verification core -- open ONE 2^s-coset leaf (Merkle-verify
    against the FS-committed round root, direction bits DERIVED from the base index) + split into 2^s
    GF(p^2) values + fold the coset to one value. This realises the byte win on-chain: ONE authentication
    path per committed round (vs one per layer in fold-2). Precondition (bottom->top):
    [i2x_0..i2x_{K-1}, base, root, sib_{d-1}..sib_0, coset_preimage, k]  (k = the Merkle leaf index = base;
    in the deployable chain both come from the ONE derived FRI index). Leaves [i2x_block, base, folded0,
    folded1]. A wrong sibling / wrong index / tampered coset value fails the Merkle EQUALVERIFY
    (fail-closed); a wrong i2x hint fails i2x*twox==1. Needs the field prelude (installed by the caller)."""
    return (merkle_verify_retain_prog(depth, trunc)                       # [.., coset_preimage]  (Merkle-bound, N3)
            + split_cells_prog(2 * (1 << s), prefix=16)                   # [.., c0_0,c0_1,...]  (2^s values)
            + fri_coset_fold_prog(s, li0, stride, oN, off, betas_round))  # [.., folded0, folded1]


def fri_coset_open_fold_unlock(base, coset, path, root, i2x_list):
    """Push-only witness for fri_coset_open_fold_prog:
    [i2x_block, base, root, sib_{d-1}..sib_0, coset_preimage, k=base]."""
    preimage = b"\x00" * 16 + b"".join(enc8(v[0] % P) + enc8(v[1] % P) for v in coset)
    sibs = [bytes.fromhex(sh) for sh, _ in path]
    return ([NUM(x % P) for x in i2x_list] + [NUM(base % P), PUSH(root)]
            + [PUSH(sh) for sh in reversed(sibs)] + [PUSH(preimage), NUM(base)])


def run_fri_coset_open_fold(base, coset, path, root, s, li0, stride, oN, off, betas_round, i2x_list):
    """Run the per-round open+fold on cashvm; ((folded0, folded1), op_cost). Raises (fail-closed) on a
    tampered coset/sibling/index or a wrong i2x hint. The K+1 lower items stay below [folded0, folded1]."""
    vm = VM()
    vm.run(_field_prelude() + fri_coset_open_fold_unlock(base, coset, path, root, i2x_list)
           + fri_coset_open_fold_prog(len(path), s, li0, stride, oN, off, betas_round))
    K = (1 << s) - 1
    assert len(vm.s) == K + 3, "fri_coset_open_fold left %d items, expected %d" % (len(vm.s), K + 3)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


def fri_coset_bind_prog(s, stride):
    """HP1.9-FOLD8 roll_bind: bind the carried value (the layer-0 composition, or the previous round's
    fold output) to the coset element at the query's DERIVED position pos = ci // stride, so the folded
    chain stays tied to the FRI sequence (the fold-8 analog of fri_roll_bind, which binds to one of TWO
    leaves; here one of 2^s coset elements). Precondition (bottom->top): [carried0, carried1,
    c0_0,c0_1,...,c_{2^s-1}_1, ci]. Branchless index-select (same select as fri_final_bind, but the
    position is ci//stride DIV, not ii%n MOD, and it binds the CARRIED value not the terminal fold):
    require sum_p (pos==p)*(carried_c - coset[p][c]) == 0 -> carried_c == coset[pos][c] (fail-closed).
    pos is DERIVED (integer DIV, ci from the FRI index chain), never free witness -> a prover cannot pick
    which coset element the carried value is checked against. Leaves []. Needs the field prelude."""
    L = 1 << s
    prog = []
    sp = [2 + 2 * L + 1]                                         # carried(2) + coset(2L) + ci(1)

    def pk(i): prog.extend([NUM(sp[0] - 1 - i), OP("PICK")]); sp[0] += 1
    def num(v): prog.append(NUM(v % P)); sp[0] += 1
    def mm(): prog.extend(MM()); sp[0] -= 1
    def am(): prog.extend(AM()); sp[0] -= 1
    def sm(): prog.extend(SM()); sp[0] -= 1
    def neq(): prog.append(OP("NUMEQUAL")); sp[0] -= 1
    def neqv(): prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2

    idx_pos = 2 + 2 * L                                          # ci (-> pos) is the top of the block
    prog += [PUSH(encode_num(stride)), OP("DIV")]               # ci -> pos = ci // stride (net 0: +push -div)
    for c in (0, 1):
        num(0)                                                  # acc = 0
        for p in range(L):
            pk(idx_pos); num(p); neq()                          # eq = (pos == p)  (1 or 0)
            pk(c); pk(2 + 2 * p + c); sm()                      # carried_c - coset[p][c]
            mm()                                                # eq * diff
            am()                                                # acc += eq*(carried_c - coset[p][c])
        num(0); neqv()                                          # require acc == 0 -> carried_c == coset[pos][c]
    assert sp[0] == 2 + 2 * L + 1, "coset_bind left sp=%d, expected block" % sp[0]
    return prog + [OP("DROP")] * (2 + 2 * L + 1)                # drop [carried, coset, pos] -> []


def run_fri_coset_bind(carried, coset, ci, s, stride):
    """Run the coset roll-bind on cashvm; (True, op_cost) on accept (carried == coset[ci//stride]),
    raises VMError (fail-closed) if carried != the position-selected coset element."""
    vm = VM()
    w = [NUM(carried[0] % P), NUM(carried[1] % P)]
    for v in coset:
        w += [NUM(v[0] % P), NUM(v[1] % P)]
    w += [NUM(ci)]
    vm.run(_field_prelude() + w + fri_coset_bind_prog(s, stride))
    assert len(vm.s) == 0, "fri_coset_bind left %d items, expected 0" % len(vm.s)
    return True, vm.op_cost


# ---- HP1.9-FOLD8 HP3.10 LOOP: runtime-DEPTH coset open (one body for every FRI-layer depth) -------
# The FRI committed-round Merkle depth shrinks per round (deploy: 17,14,11,8,5); a runtime-depth opener
# lets ONE loop body open every round (vs one baked opener per depth). Reuses the merkle_verify_stack
# per-step body but reads the depth d from the stack (OP_BEGIN/UNTIL down-counter dc=d->0).
def merkle_verify_runtime_prog():
    """Verify a Merkle path whose depth d sits on top of the stack at runtime (down-counter dc=d..0 on
    alt below k). Precondition main (bottom->top): [root, sib_{d-1}..sib_0, preimage, k, d]; leaves [].
    Direction bits are DERIVED from k (k mod 2 per level, k//=2) exactly like merkle_verify_stack_prog --
    never free witness. A wrong sibling OR wrong index fails EQUALVERIFY (fail-closed)."""
    step = [OP("FROMALT"), OP("DUP"), NUM(2), OP("MOD"),                # bit = k mod 2
            OP("SWAP"), NUM(2), OP("DIV"), OP("TOALT"),                 # k //= 2 back to alt
            OP("NOT"), OP("IF"), OP("SWAP"), OP("ENDIF"), OP("CAT"), OP("SHA256")]
    dec = [OP("FROMALT"), OP("FROMALT"), OP("1SUB"), OP("DUP"), OP("TOALT"),   # dc -= 1
           OP("SWAP"), OP("TOALT"), NUM(0), OP("NUMEQUAL")]                    # restore [dc,k]; exit dc==0
    return ([OP("TOALT"), OP("TOALT"), OP("SHA256"), OP("BEGIN")] + step + dec
            + [OP("UNTIL"), OP("FROMALT"), OP("DROP"), OP("FROMALT"), OP("DROP"), OP("EQUALVERIFY")])


def merkle_verify_runtime_unlock(preimage, path, root, k):
    """Push-only witness for merkle_verify_runtime_prog: merkle_verify_stack_unlock + NUM(depth) on top."""
    return merkle_verify_stack_unlock(preimage, path, root, k) + [NUM(len(path))]


def run_merkle_verify_runtime(preimage, path, root, k):
    """Run the runtime-depth opener on cashvm; (True, op_cost) on accept, (False, 0) on fail-closed reject."""
    vm = VM()
    try:
        vm.run(merkle_verify_runtime_unlock(preimage, path, root, k) + merkle_verify_runtime_prog())
        return (len(vm.s) == 0), vm.op_cost
    except VMError:
        return False, 0


def fri_coset_open_runtime_prog(s):
    """HP1.9-FOLD8 HP3.10: open a 2^s-coset leaf whose Merkle DEPTH is on the stack at runtime, retaining
    the coset. Precondition (bottom->top): [root, sib_{d-1}..sib_0, coset_preimage, k, d]. Copies the
    preimage to the alt (below the verify's dc/k), runs merkle_verify_runtime, restores it, splits into
    2^s GF(p^2) values (2*2^s cells). Leaves [c0_0,c0_1,...,c_{2^s-1}_1]. Wrong sibling/index -> EQUALVERIFY."""
    return ([NUM(2), OP("PICK"), OP("TOALT")]                           # stash coset_preimage on alt
            + merkle_verify_runtime_prog()                             # verify (runtime depth)
            + [OP("FROMALT")]                                          # restore preimage
            + split_cells_prog(2 * (1 << s), prefix=16))              # -> 2*2^s cells


def fri_coset_open_runtime_unlock(coset, path, root, k):
    """Push-only witness for fri_coset_open_runtime_prog: [root, sibs, coset_preimage, k, depth]."""
    preimage = b"\x00" * 16 + b"".join(enc8(v[0] % P) + enc8(v[1] % P) for v in coset)
    sibs = [bytes.fromhex(sh) for sh, _ in path]
    return [PUSH(root)] + [PUSH(sib) for sib in reversed(sibs)] + [PUSH(preimage), NUM(k), NUM(len(sibs))]


# ---- HP1.9-FOLD8 HP3.10 LOOP: DEFINE-modexp + runtime-param coset fold (+HP11 L1 op-cost lever) --------
# The fold's twox derives (off*oN^gidx)^exp2 via the square-and-multiply modexp loop. HP11 L1 SHARES the
# oN^gidx base across the round (gm_derive_sink_prog: g_m = oN^base*(oN^stride)^m -> 2 modexp for the 4 g_m
# instead of 7 per-butterfly oN^gidx), leaving 2 (g_m) + 7 (^exp2) modexp/round. Inlining the 48-byte
# _modexp_loop() is byte-heavy; instead DEFINE it ONCE as function id 0x04 (distinct from the field-prelude
# MULMOD/ADDMOD/SUBMOD 0x01/0x02/0x03) and INVOKE it (3 B each). modexp uses inline _MODT (never the alt
# MULMOD) so it coexists with the field prelude (P on alt) unchanged. Validated == the baked
# fri_coset_fold_prog / _coset_fold oracle (byte-identical twox; wrong-i2x reject; fail-closed preserved).
_MODEXP_FID = b"\x04"


def modexp_define():
    """Define the square-and-multiply modexp loop as INVOKE-able function 0x04 (once per program)."""
    return [PUSH(_MODEXP_FID), DEFINE(_modexp_loop())]


def _modexp_invoke():
    """[base, exp] -> [base^exp mod P] via the DEFINE'd modexp (3 bytes vs 48 inline)."""
    return [PUSH(_MODEXP_FID), OP("INVOKE")]


def gm_derive_sink_prog(oN):
    """HP11 L1 (op-cost lever): derive the 4 DISTINCT coset base points g_m = oN^(base+m*stride) =
    oN^base * (oN^stride)^m ON-CHAIN from the round's base/stride once, and sink them below the param block
    so the fold's twox PICKS them instead of re-deriving oN^gidx via modexp per butterfly (7 modexp#1/round
    -> 2). Pure algebraic identity -> twox stays BYTE-IDENTICAL to the modexp path (validated == _coset_fold
    oracle over real fold-8 proofs); base (== ci%stride) and stride (== carried) are already consensus-bound,
    so the derived g_m grant the prover NO new freedom (no witness, no new binding). Precondition
    [stride,pe,betas(6),i2x(7),base,coset(16)] (32 items; base@16, stride@31 from top); leaves
    [g0,g1,g2,g3, <same 32-block>]. Uses the DEFINE'd modexp (0x04); coexists with the field prelude (P on
    alt) since the modexp exponent stash is balanced and never touches a resident P."""
    p = [NUM(16), OP("PICK")] + _modexp_pow(oN)                          # A = oN^base
    p += [NUM(32), OP("PICK")] + _modexp_pow(oN)                         # S = oN^stride (stride is a power of two)
    p += [NUM(1), OP("PICK")]                                            # g0 = A
    p += [NUM(2), OP("PICK"), NUM(2), OP("PICK"), OP("MUL")] + _MODT     # g1 = A*S       = oN^(base+stride)
    p += [NUM(0), OP("PICK"), NUM(3), OP("PICK"), OP("MUL")] + _MODT     # g2 = g1*S      = oN^(base+2*stride)
    p += [NUM(0), OP("PICK"), NUM(4), OP("PICK"), OP("MUL")] + _MODT     # g3 = g2*S      = oN^(base+3*stride)
    p += [NUM(5), OP("ROLL"), OP("DROP")]                               # drop A
    p += [NUM(4), OP("ROLL"), OP("DROP")]                               # drop S -> [block(32), g0,g1,g2,g3]
    p += [NUM(35), OP("ROLL")] * 32                                     # sink g0..g3 below the 32-item block
    return p


def _modexp_pow(oN):
    """[.., exp] -> [.., oN^exp mod P] via the DEFINE'd modexp (0x04). Used by gm_derive_sink for A=oN^base,
    S=oN^stride (the base is the fixed FRI domain generator oN)."""
    return [PUSH(encode_num(oN % P)), OP("SWAP")] + _modexp_invoke()


def _fri_twox_L1(Hh, b, m, f, off):
    """HP11 L1 twox (net +1): pick the pre-derived g_m = oN^(base+m*stride) (gm_derive_sink placed g0..g3 just
    below the param block) instead of deriving oN^gidx via modexp per butterfly. Then off*g_m, exp2 = pe*2^f,
    (off*g_m)^exp2 via the DEFINE'd modexp (power-of-two exponent), 2*. g_m at depth Hh+b+11-m (the 4 g_m sit
    just below stride@Hh+b+7); pe at Hh+b+6 (+1 after the g_m push). Adding g_m below the param block shifts
    NOTHING in the working set or the betas/i2x/pe picks -- only this g_m pick references the new items."""
    t = [NUM(Hh + b + 11 - m), OP("PICK")]                              # g_m = oN^(base+m*stride)  (pre-derived)
    t += [NUM(off % P), OP("MUL")] + _MODT                             # off * g_m
    t += [NUM(Hh + b + 7), OP("PICK"), NUM(1 << f), OP("MUL")]         # exp2 = pe * 2^f  (pe@Hh+b+6, +1 after g_m)
    t += _modexp_invoke()                                             # (off*g_m)^exp2   (power-of-two exponent)
    t += [NUM(2), OP("MUL")] + _MODT                                  # twox = 2*xpos
    return t


def fri_coset_fold_loop_prog(s, oN, off):
    """HP1.9-FOLD8 HP3.10 (+HP11 L1): the runtime-param coset fold (s=3) with DEFINE-modexp INVOKE -- identical
    output to the committed baked fri_coset_fold_prog but reads the per-round params (stride, pe=2^li0,
    betas[3]) from a param block at the BOTTOM of the working set instead of baking them. HP11 L1 op-cost
    lever: gm_derive_sink_prog first derives the 4 DISTINCT coset base points g_m = oN^(base+m*stride) via
    oN^base*(oN^stride)^m (2 modexp/round instead of 7) and sinks them below the param block; _fri_twox_L1
    then PICKS g_m instead of re-deriving oN^gidx per butterfly. twox stays byte-identical (algebraic
    identity) -> fold output unchanged (validated == _coset_fold oracle). Precondition (bottom->top):
    [stride, pe, b0_0,b0_1,b1_0,b1_1,b2_0,b2_1, i2x_0..i2x_{K-1}, base, coset]. Leaves
    [g0,g1,g2,g3, param block, i2x_block, base, folded0, folded1] (the 4 g_m are dropped by the caller).
    Needs the field prelude + the modexp definition (caller installs)."""
    assert s == 3, "the HP3.10 loop body uses the uniform s=3 fold"
    prog = gm_derive_sink_prog(oN)                                       # HP11 L1: g0..g3 = oN^(base+m*stride) at bottom
    cnt = 1 << s
    K = (1 << s) - 1
    Hh = K + 1 + 2 * cnt
    inv2 = pow(2, P - 2, P)
    oi = 0
    for f in range(s):
        h = cnt // 2
        for m in range(h):
            b = 0
            prog += [NUM((2 * h - 1) + b), OP("PICK")]; b += 1          # fw0
            prog += [NUM((2 * h - 2) + b), OP("PICK")]; b += 1          # fw1
            prog += [NUM(Hh + b + 5 - 2 * f), OP("PICK")]; b += 1       # b_f_0 (param)
            prog += [NUM(Hh + b + 4 - 2 * f), OP("PICK")]; b += 1       # b_f_1 (param)
            prog += [NUM(inv2)]; b += 1                                 # inv2 (pinned)
            prog += [NUM((Hh + b - 1) - oi), OP("PICK")]; b += 1        # i2x_oi
            prog += _fri_twox_L1(Hh, b, m, f, off); b += 1             # HP11 L1: pick pre-derived g_m (no modexp#1)
            prog += [NUM((2 * cnt - 1) + b), OP("PICK")]; b += 1        # fv0
            prog += [NUM((2 * cnt - 2) + b), OP("PICK")]; b += 1        # fv1
            prog += ext_fold_stack_prog()                             # -> [folded0, folded1]
            Hh += 2; oi += 1
        nres = 2 * h; ncur = 2 * cnt
        prog += [OP("TOALT")] * nres + [OP("DROP")] * ncur + [OP("FROMALT")] * nres
        Hh = K + 1 + nres
        cnt = h
    return prog


def fri_loop_body_prog(oN, off):
    """HP1.9-FOLD8 HP3.10: the UNIFORM carried-on-top per-round loop body (s=3). The carried state
    [ci, stride, pe, folded0, folded1] flows on TOP; each round's witness sits just below it. Resolves the
    alt==[P] constraint: carried is stashed to alt only during the FIELD-OP-FREE open, then restored; the
    bind uses a FIELD-OP-FREE runtime-depth PICK (coset[pos], pos=ci//stride); the next-carried is sunk
    BELOW the fold block via OP_ROLL so the fold works unchanged; cleanup leaves [<later>, next_carried].
    Entry (bottom->top): [<later rounds' witness>, stride_w, pe_w, betas(6), i2x(7), base, root, sib_{d-1}..
    sib_0, preimage, k, d, ci, stride, pe, folded0, folded1]. Leaves [<later>, next_ci, next_stride,
    next_pe, folded'0, folded'1]. DEFINE this once (a P2S loop uses ONE INVOKE per round). Needs the field
    prelude + the modexp definition. The witness supplies stride_w/pe_w -- CHECKED == the carried structural
    stride/pe (bound, not free); ci = prev base (Merkle-index-bound via base == ci % stride); stride/=8,
    pe*=8, ci=base each round (structural, pinned round count). base == ci % stride is the FRI-index
    consistency guard (reference verify:415) -- without it a prover opens a different committed leaf."""
    p = [OP("TOALT")] * 5                                              # stash carried to alt (field-op-free)
    p += fri_coset_open_runtime_prog(3)                              # open (runtime depth) -> [.., block(32)]
    p += [OP("FROMALT")] * 5                                          # restore carried -> [block(32), carried(5)]
    # idx: sw0,pw1,betas2-7,i2x8-14,base15,coset16-31,ci32,str33,pe34,f035,f136
    p += [NUM(36), OP("PICK"), NUM(4), OP("PICK"), OP("NUMEQUALVERIFY")]    # stride_w == carried stride
    p += [NUM(35), OP("PICK"), NUM(3), OP("PICK"), OP("NUMEQUALVERIFY")]    # pe_w == carried pe
    p += [NUM(4), OP("PICK"), NUM(4), OP("PICK"), OP("MOD"),          # ci % stride  (FRI index consistency)
          NUM(22), OP("PICK"), OP("NUMEQUALVERIFY")]                 # base == ci % stride  (verify:415)
    # bind folded == coset[pos], pos = ci // stride  (field-op-free runtime-depth PICK; non-destructive)
    p += [NUM(4), OP("PICK"), NUM(4), OP("PICK"), OP("DIV")]          # pos = ci // stride
    p += [OP("DUP"), NUM(2), OP("MUL"), NUM(20), OP("SWAP"), OP("SUB"), OP("PICK")]  # coset[pos][1] (D=20-2pos)
    p += [NUM(2), OP("PICK"), OP("NUMEQUALVERIFY")]                   # f1 == coset[pos][1]
    p += [OP("DUP"), NUM(2), OP("MUL"), NUM(21), OP("SWAP"), OP("SUB"), OP("PICK")]  # coset[pos][0] (D=21-2pos)
    p += [NUM(3), OP("PICK"), OP("NUMEQUALVERIFY")]                   # f0 == coset[pos][0]
    p += [OP("DROP")]                                                 # drop pos
    # compute next-carried [next_ci=base, next_stride=stride/8, next_pe=pe*8]
    p += [NUM(21), OP("PICK")]                                        # next_ci = base
    p += [NUM(4), OP("PICK"), NUM(8), OP("DIV")]                      # next_stride = stride / 8
    p += [NUM(4), OP("PICK"), NUM(8), OP("MUL")]                      # next_pe = pe * 8
    # sink next3 below block+carried (37): move-top-to-bottom-of-40 x3 = OP(39,ROLL)x39 each
    p += [NUM(39), OP("ROLL")] * 39
    p += [NUM(39), OP("ROLL")] * 39
    p += [NUM(39), OP("ROLL")] * 39
    p += [OP("DROP")] * 5                                             # drop old carried -> [next3, block(32)]
    p += fri_coset_fold_loop_prog(3, oN, off)                        # fold -> [next3, g0..g3,params,i2x,base,folded'(2)]
    p += [OP("TOALT")] * 2 + [OP("DROP")] * 20 + [OP("FROMALT")] * 2  # cleanup (HP11 L1: +4 g_m) -> [next_ci,next_str,next_pe,folded'0,folded'1]
    return p


def fri_loop_round_witness(stride, pe, betas_round, base, coset, path, root, i2x_list):
    """Push-only per-round witness for fri_loop_body_prog (below the carried, bottom->top):
    [stride, pe, betas(6), i2x(7), base, root, sib_{d-1}..sib_0, preimage, k=base, d]."""
    preimage = b"\x00" * 16 + b"".join(enc8(v[0] % P) + enc8(v[1] % P) for v in coset)
    sibs = [bytes.fromhex(sh) for sh, _ in path]
    w = [NUM(stride % P), NUM(pe % P)]
    for bt in betas_round:
        w += [NUM(bt[0] % P), NUM(bt[1] % P)]
    w += [NUM(x % P) for x in i2x_list] + [NUM(base % P)]
    w += [PUSH(root)] + [PUSH(sib) for sib in reversed(sibs)] + [PUSH(preimage), NUM(base), NUM(len(sibs))]
    return w


def fri_index_consistency_prog():
    """HP1.9-FOLD8 HP3.10 (reference verify:415-416): verify the opened Merkle leaf index equals the carried
    FRI index -- base == ci % stride. Precondition (bottom->top): [ci, stride, base]; leaves []. Without this
    a prover opens a DIFFERENT genuinely-committed leaf (base authenticity-bound by the Merkle open, but not
    index-bound) and substitutes the trace-consistency anchor (RULES-20a Agent-A 8/10). It also forces
    base < stride, which bounds pos = base // next_stride < 2^s downstream and defeats Merkle high-bit
    inflation. fri_loop_body_prog embeds this inline; the s2 tail / any single-round opener uses it standalone."""
    return [OP("TOALT"), OP("MOD"), OP("FROMALT"), OP("NUMEQUALVERIFY")]   # base == ci % stride


def run_fri_index_consistency(ci, stride, base):
    """Run the index-consistency check; (True, op_cost) on accept, raises VMError (fail-closed) on base != ci%stride."""
    vm = VM()
    vm.run([NUM(ci % P), NUM(stride % P), NUM(base % P)] + fri_index_consistency_prog())
    assert len(vm.s) == 0, "fri_index_consistency left %d items, expected 0" % len(vm.s)
    return True, vm.op_cost


# ---- HP1.9-FOLD8 HP3.10 LOOP: the byte-amortized DEFINE/INVOKE s=3 loop redeem ---------------------
_LOOPBODY_FID = b"\x05"                                             # loop-body fid (distinct from modexp 0x04)


def fri_loop_defines(oN, off):
    """DEFINE the modexp (0x04) + the carried-on-top loop body (0x05) as INVOKE-able functions ONCE. Emitted
    at the shard/standalone ENTRY (exactly like stagea_sbox_define/stagea_state_define) so the per-query
    redeem only INVOKEs. shard_verify_prog runs all nq queries in ONE shared VM/ftable, so a per-query
    DEFINE would raise 'function already defined' (cashvm:263) at query 2 -- hoisting is mandatory for the
    multi-query fold-8 shard. Net-0 on the main stack (the bodies are captured from program tokens, not the
    stack -> prover-unforgeable)."""
    return modexp_define() + [PUSH(_LOOPBODY_FID), DEFINE(fri_loop_body_prog(oN, off))]


def fri_loop_s3_redeem(n_rounds, oN, off, defines_installed=False):
    """The s=3 FRI-fold loop redeem: INVOKE the DEFINE'd carried-on-top loop body (0x05) n_rounds times. Each
    INVOKE consumes one round's witness block (below the carried) + the carried [ci,stride,pe,folded] on top,
    leaving the next carried -- so the redeem stays ~constant (body defined once + ~3 B/INVOKE) however many
    s=3 rounds a query needs, instead of replicating the ~2.3 KB body per round. This is the &lt;100KB lever
    (deploy: 6 s=3 rounds). defines_installed=False (standalone) prepends fri_loop_defines; True (the shard or
    the standalone per_query hoisted the defines at its entry) emits ONLY the INVOKEs -- REQUIRED because
    shard_verify runs all nq queries in one VM and a per-query DEFINE 0x04/0x05 would raise 'function already
    defined' at query 2 (F1). The caller installs the field prelude + the pre-stacked round witnesses
    (fri_loop_round_witness, last round deepest) + the initial carried, then this redeem. Nested INVOKE (body
    0x05 contains INVOKE modexp 0x04) is supported. Validated == the inline body chain."""
    defs = [] if defines_installed else fri_loop_defines(oN, off)
    return defs + [PUSH(_LOOPBODY_FID), OP("INVOKE")] * n_rounds


def qf_bound_prog(x, T, last, zh_inv, hd_vals, bound_invX):
    """HP2 (2.9-2.11): from the verifier-derived FRI/AIR domain point x (xpos_prog, x=Dd[k]),
    validate the hint inverses and compute the composition NORMALIZERS on-chain, leaving
    [qf_trans, binvX_0, ..., binvX_{m-1}] (bottom->top). zh_inv (=Z_H(x)^-1) and each bound_invX are
    witness HINTS, each inverse-constrained hint*value==1 fail-closed (so a prover cannot supply a
    favourable normalizer as free witness): zh_inv*(x^T-1)==1 with x^T via modexp_prog, and
    bound_invX[r]*(x-Hd[row_r])==1. Then qf_trans=(x-last)*zh_inv (verify:253, compose:408) and each
    bound_invX[r]=1/(x-Hd[row_r]) (verify:315). x/T/last/Hd are verifier-derived/pinned; zh_inv and
    bound_invX are the only witness inputs and both are inverse-constrained. Needs one field prelude."""
    x %= P; last %= P; zh_inv %= P
    prog = _field_prelude()
    prog += modexp_prog(x, T)                                          # [x^T]  (alt-scratch above P, restored)
    prog += [NUM(1)] + SM()                                            # [x^T - 1]
    prog += [NUM(zh_inv)] + MM() + [NUM(1), OP("NUMEQUALVERIFY")]      # zh_inv*(x^T-1) == 1  -> []
    prog += [NUM(x), NUM(last)] + SM() + [NUM(zh_inv)] + MM()          # [qf_trans = (x-last)*zh_inv]
    for hdv, binv in zip(hd_vals, bound_invX):
        prog += ([NUM(binv % P), NUM(x), NUM(hdv % P)] + SM() + MM()
                 + [NUM(1), OP("NUMEQUALVERIFY"), NUM(binv % P)])      # binv*(x-Hd)==1 ; leave binv
    return prog


def run_qf_bound(x, T, last, zh_inv, hd_vals, bound_invX):
    """Run qf_bound_prog on cashvm; ([qf_trans, binvX_0, ...], op_cost). Raises VMError (fail-closed)
    if any hint inverse is wrong (hint*value != 1)."""
    vm = VM()
    vm.run(qf_bound_prog(x, T, last, zh_inv, hd_vals, bound_invX))
    return [decode_num(v) for v in vm.s], vm.op_cost


def qf_bound_from_stack_prog(T, last, hd_vals, below=0):
    """HP2 (2.31c-iii-a): the deployable qf_bound -- same normalizers as qf_bound_prog but reading the
    verifier-DERIVED domain point x FROM THE STACK (not baked) and the inverse HINTS from the witness
    block, so nothing is a baked test constant. Stack precondition (bottom->top): [zh_inv, binvX_0..
    binvX_{m-1}, x] (the hints pushed by the unlock, x derived on-stack by fri_xpos_prog li=0). Validates
    zh_inv*(x^T-1)==1 and each binvX_r*(x-Hd[row_r])==1 (NUMEQUALVERIFY, fail-closed -- a prover cannot
    supply a favourable normalizer), computes qf_trans=(x-last)*zh_inv, and leaves a clean
    [qf_trans, binvX_0, ..., binvX_{m-1}] (drops x and zh_inv). T/last/Hd are pinned; x is derived; the
    only witness is the inverse-constrained hints. Needs one field prelude (installed by the caller);
    x^T uses the self-contained _modexp_loop (_MODT), the rest uses the field ops (P on alt). `below` =
    stack items beneath the [zh_inv,binvX,x] block (single-program threading, 2.31c-iii-b-mono): PICK
    indices are offset by `below`, and the final DROP removes only this block (the `below` items stay)."""
    m = len(hd_vals)
    BLOCK = m + 2                                               # [zh_inv, binvX_0..binvX_{m-1}, x]
    idx = {"zh": below, "x": below + m + 1}
    for r in range(m):
        idx["b%d" % r] = below + 1 + r
    prog = []
    sp = [below + BLOCK]

    def pk(nm): prog.extend([NUM(sp[0] - 1 - idx[nm]), OP("PICK")]); sp[0] += 1
    def pkpos(pos): prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1
    def num(v): prog.append(NUM(v % P)); sp[0] += 1
    def mm(): prog.extend(MM()); sp[0] -= 1
    def sm(): prog.extend(SM()); sp[0] -= 1
    def neqv(): prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2

    pk("x"); num(T); prog.extend(_modexp_loop()); sp[0] -= 1    # [x^T]  (base=x, exp=T; loop nets -1)
    num(1); sm()                                                # x^T - 1
    pk("zh"); mm(); num(1); neqv()                              # zh_inv*(x^T - 1) == 1
    pk("x"); num(last); sm(); pk("zh"); mm()                    # [qf_trans = (x - last)*zh_inv]
    for r in range(m):
        pk("b%d" % r); pk("x"); num(hd_vals[r]); sm(); mm(); num(1); neqv()   # binvX_r*(x - Hd_r) == 1
    assert sp[0] == below + BLOCK + 1, "qf_bound_from_stack sp=%d expected %d" % (sp[0], below + BLOCK + 1)
    pkpos(below + BLOCK)                                        # copy qf_trans (bottom of the output)
    for r in range(m):
        pkpos(below + 1 + r)                                   # copy binvX_0..binvX_{m-1}
    R = m + 1                                                   # TOALT*R/DROP*BLOCK+1/FROMALT*R preserves order
    return prog + [OP("TOALT")] * R + [OP("DROP")] * (BLOCK + 1) + [OP("FROMALT")] * R


def run_qf_derive(oN, off, T, last, hd_vals, k, zh_inv, bound_invX):
    """Derive x=Dd[k] from the FS index k (fri_xpos_prog li=0 reuse) then the composition normalizers
    on-chain: ([qf_trans, binvX_0, ...], op_cost) on accept, raises VMError (fail-closed) if any hint
    inverse is wrong. The unlock pushes only [zh_inv, binvX_0.., k] -- x is derived, not supplied."""
    vm = VM()
    unlock = [NUM(zh_inv % P)] + [NUM(b % P) for b in bound_invX] + [NUM(k)]
    vm.run(unlock + fri_xpos_prog(oN, off, 0) + _field_prelude() + qf_bound_from_stack_prog(T, last, hd_vals))
    return [decode_num(v) for v in vm.s], vm.op_cost


def _fs_n_betas(fri_roots, N):
    """Number of FRI fold betas the transcript draws (one per non-final layer): mirrors
    fs_transcript_prog's `for fr in fri_roots: absorb; if size<=8 break; beta; size//=2`."""
    size = N; nb = 0
    for _ in fri_roots:
        if size <= 8:
            break
        nb += 1; size //= 2
    return nb


def compose_from_fs_alphas_prog(n_t, n_b, tp_root, root, nf, cm_out, fri_roots, nonce, N, n_queries):
    """HP2 (2.31c-iii-b, alpha binding): compute the composition with the GF(p^2) constraint-combination
    alphas DERIVED from the Fiat-Shamir transcript instead of taken as free witness. The alphas depend
    only on the pinned statement (tp_root, root, nf, cm_out absorbed before the FRI section), so a
    prover cannot choose them (Frozen-Heart, zk-circuit FS-2). The unlock pushes only the residual
    values + normalizers [trans_v(n_t), bound_v(n_b), qf_trans, bound_invX(n_b)]; fs_transcript_prog
    then derives [alphas(2*(n_t+n_b)), betas, idx, state] above them, and this prog PICK-copies the
    residuals (witness) + the derived alphas (FS output) into compose_stack_prog's _compose_layout order
    and composes. Needs one field prelude (FS uses only SHA/int ops, so it is prelude-safe); leaves
    [.., comp0, comp1]. Reproduces verify's comp_x with NO witness alpha."""
    W = n_t + 2 * n_b + 1                                        # witness: trans_v, bound_v, qf, bound_invX
    fs_out = 2 * (n_t + n_b) + 2 * _fs_n_betas(fri_roots, N) + n_queries + 1
    prog = _field_prelude()
    prog += fs_transcript_prog(tp_root, root, nf, cm_out, fri_roots, nonce, N, n_t + n_b, n_queries)
    sp = [W + fs_out]                                            # depth after witness + FS output

    def copy(pos): prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1

    for j in range(n_t):                                         # -> _compose_layout order (copies)
        copy(j)                                                  # trans_v[j]  (witness)
        copy(W + 2 * j); copy(W + 2 * j + 1)                    # trans_a[j] pair (FS-derived alpha)
    copy(n_t + n_b)                                             # qf_trans  (witness)
    for b in range(n_b):
        copy(n_t + b)                                           # bound_v[b]  (witness)
        copy(n_t + n_b + 1 + b)                                 # bound_invX[b]  (witness)
        copy(W + 2 * n_t + 2 * b); copy(W + 2 * n_t + 2 * b + 1)   # bound_a[b] pair (FS-derived alpha)
    prog += compose_stack_prog(n_t, n_b)                        # consumes the arranged block -> [comp0, comp1]
    return prog


def compose_from_fs_alphas_unlock(trans_v, bound_v, qf_trans, bound_invX):
    """Push-only witness for compose_from_fs_alphas_prog: [trans_v, bound_v, qf_trans, bound_invX].
    The GF(p^2) alphas are NOT supplied -- they are FS-derived from the pinned statement."""
    return ([NUM(v % P) for v in trans_v] + [NUM(v % P) for v in bound_v]
            + [NUM(qf_trans % P)] + [NUM(v % P) for v in bound_invX])


def run_compose_from_fs_alphas(trans_v, bound_v, qf_trans, bound_invX,
                               tp_root, root, nf, cm_out, fri_roots, nonce, N, n_queries):
    """Run the FS-alpha composition on cashvm; ((comp0, comp1), op_cost). The alphas are derived from
    the transcript (no witness alpha), so a forged constraint-combination challenge cannot enter."""
    n_t, n_b = len(trans_v), len(bound_v)
    vm = VM()
    vm.run(compose_from_fs_alphas_unlock(trans_v, bound_v, qf_trans, bound_invX)
           + compose_from_fs_alphas_prog(n_t, n_b, tp_root, root, nf, cm_out, fri_roots, nonce, N, n_queries))
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


def qf_derive_from_fs_prog(n_t, n_b, T, last, oN, off, hd_vals,
                           tp_root, root, nf, cm_out, fri_roots, nonce, N, n_queries, query_i=0):
    """HP2 (2.31c-iii-b-mono): bind the query index k to the FULL Fiat-Shamir transcript, then derive
    x=Dd[k] and the composition normalizers -- so the OPENED position is not free witness (a prover
    cannot choose a favourable query). fs_transcript_prog derives the real query indices (after
    absorbing the pinned statement + fri_roots + grind nonce); this extracts idx_{query_i} = k, derives
    x (fri_xpos_prog li=0), and runs qf_bound_from_stack (hints witness, inverse-constrained). The
    unlock pushes only [zh_inv, binvX_0..binvX_{m-1}] -- NO k, NO x, NO alpha. Needs one field prelude
    (FS is SHA/int-only, so prelude-safe). Leaves [.., qf_trans, binvX_0..binvX_{m-1}] on top (the
    hints + FS output stay beneath)."""
    m = len(hd_vals)
    HB = m + 1                                                  # hints block [zh_inv, binvX_0..binvX_{m-1}]
    nbet = _fs_n_betas(fri_roots, N)
    fs_out = 2 * (n_t + n_b) + 2 * nbet + n_queries + 1
    idx_pos = HB + 2 * (n_t + n_b) + 2 * nbet + query_i        # position of idx_{query_i} in the FS output
    prog = _field_prelude()
    prog += fs_transcript_prog(tp_root, root, nf, cm_out, fri_roots, nonce, N, n_t + n_b, n_queries)
    sp = [HB + fs_out]

    def copy(pos): prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1

    copy(0)                                                     # zh_inv (witness)
    for r in range(m):
        copy(1 + r)                                            # binvX_0..binvX_{m-1} (witness)
    copy(idx_pos)                                              # k = idx_{query_i}  (FS-derived, not witness)
    prog += fri_xpos_prog(oN, off, 0)                         # k -> x = Dd[k]  (net 0)
    prog += qf_bound_from_stack_prog(T, last, hd_vals, below=HB + fs_out)
    return prog


def qf_derive_from_fs_unlock(zh_inv, bound_invX):
    """Push-only witness for qf_derive_from_fs_prog: [zh_inv, binvX_0..binvX_{m-1}] -- the inverse hints
    only. k, x and the alphas are all derived from the transcript, not supplied."""
    return [NUM(zh_inv % P)] + [NUM(b % P) for b in bound_invX]


def run_qf_derive_from_fs(n_t, n_b, T, last, oN, off, hd_vals, tp_root, root, nf, cm_out, fri_roots,
                          nonce, N, n_queries, zh_inv, bound_invX, query_i=0):
    """Run the FS-index-bound qf derivation on cashvm; ([qf_trans, binvX_0..], op_cost) on accept
    (the last 1+len(bound_invX) items), raises VMError (fail-closed) on a wrong hint or a k/x mismatch."""
    vm = VM()
    vm.run(qf_derive_from_fs_unlock(zh_inv, bound_invX)
           + qf_derive_from_fs_prog(n_t, n_b, T, last, oN, off, hd_vals, tp_root, root, nf, cm_out,
                                    fri_roots, nonce, N, n_queries, query_i))
    out = 1 + len(bound_invX)
    return [decode_num(v) for v in vm.s[-out:]], vm.op_cost


def kn_from_k_prog(shift, N):
    """HP2 (2.7c): derive the next-row FRI index kn = (k + shift) % N from the query index k on the
    stack (shift = N//T, and N, are pinned). Mirrors native_ct_air_stark.verify:245 kn=(k+shift)%N.
    Input [.., k] (top); leaves [.., k, kn] -- k preserved for the @k openers, kn for the @kn openers.
    Pure integer ops (no field prelude): DUP k, add the pinned shift, reduce mod the pinned N. kn is
    fully determined by the FS-derived k, so a prover cannot choose the next-row position either."""
    return [OP("DUP"), PUSH(encode_num(shift)), OP("ADD"), PUSH(encode_num(N)), OP("MOD")]


def run_kn_from_k(k, shift, N):
    """Run the next-row-index derivation on cashvm; ([k, kn], op_cost). No field prelude (pure integer)."""
    vm = VM()
    vm.run([NUM(k)] + kn_from_k_prog(shift, N))
    assert len(vm.s) == 2, "kn_from_k left %d items, expected 2" % len(vm.s)
    return [decode_num(x) for x in vm.s], vm.op_cost


def _open_leaves_at_k_prog(depth, sel_root, n_trace, n_sel, shift, N, tp_root, wbase, sp_start):
    """HP2/HP3.5b-ii-b-1: the four-leaf opener CORE. The query index k is ALREADY on the stack top --
    either copied from the FS output by open_all_leaves_fs_prog (FS-derived k), or, in the query loop
    (3.5b-ii-b), a runtime PICK of idx_{counter} from the shared FS output. Derive kn=(k+shift)%N and open
    the four leaves (trace@k, trace@kn, D-coset selector@k, selector@kn) against the pinned roots via the
    index-driven retaining opener + split, leaving 2*n_trace+2*n_sel cells in leaf order. `wbase` = the
    absolute base of the four [sibs, preimage] witness blocks (WB=depth+1 each); `sp_start` = the stack
    depth with k on top. bound_retain_open already consumes the index from the stack, so a runtime k needs
    NO new logic -- the same opener works for a baked-derived or a loop-runtime k. No field prelude
    (SHA256/int only). A wrong k or a tampered sibling fails the Merkle check (fail-closed)."""
    WB = depth + 1
    prog = []; sp = [sp_start]

    def copy(pos): prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1

    prog += kn_from_k_prog(shift, N); sp[0] += 1               # [.., k, kn]  (kn_from_k DUPs k, nets +1)
    k_pos = sp_start - 1; kn_pos = sp_start                    # k on top before kn_from_k; kn lands just above

    def open_leaf(block, idx_p, rt, n, prefix):
        for i in range(WB):
            copy(wbase + block * WB + i)                      # copy this leaf's [sibs, preimage]
        copy(idx_p)                                           # copy the index (k or kn) on top
        prog.extend(bound_retain_open_prog(depth, rt) + split_cells_prog(n, prefix=prefix))
        sp[0] += n - (WB + 1)                                 # WB+1 copies consumed, n cells left

    open_leaf(0, k_pos, tp_root, n_trace, 16)                 # trace@k
    open_leaf(1, kn_pos, tp_root, n_trace, 16)                # trace@kn
    open_leaf(2, k_pos, sel_root, n_sel, 0)                   # D-coset selector@k
    open_leaf(3, kn_pos, sel_root, n_sel, 0)                  # selector@kn
    return prog


def open_all_leaves_fs_prog(depth, sel_root, n_trace, n_sel, shift, n_t, n_b,
                            tp_root, root, nf, cm_out, fri_roots, nonce, N, n_queries, query_i=0, below=0):
    """HP2 (2.31c-iii-b-mono, FS-bound opener supply): open the four per-query leaves at the FS-DERIVED
    indices k and kn=(k+shift)%N (not witness indices) so the opened POSITIONS are bound to the
    transcript -- a prover cannot open a favourable query/row. fs_transcript_prog derives k; kn_from_k
    derives kn; then the four openers (copy pattern, baked roots) run with the derived k/kn copied in as
    each opener's index. The unlock pushes only the four [sib_{depth-1}..sib_0, preimage] blocks
    (WB=depth+1, NO index). Leaves the 2*n_trace+2*n_sel bound cells in leaf order above the spent
    witness + FS output + [k, kn]. No field prelude (SHA256/int only). `below` = stack items beneath the
    four witness blocks (single-program threading into the core, 2.31c-iii-b-mono part 2c): PICK indices
    are offset by `below` and the cells are produced at base `below`+4*WB+fs_out+2."""
    WB = depth + 1                                              # sibs(depth) + preimage per leaf (no index)
    nbet = _fs_n_betas(fri_roots, N)
    fs_out = 2 * (n_t + n_b) + 2 * nbet + n_queries + 1
    idx_pos = below + 4 * WB + 2 * (n_t + n_b) + 2 * nbet + query_i   # position of idx_{query_i} in the FS output
    prog = fs_transcript_prog(tp_root, root, nf, cm_out, fri_roots, nonce, N, n_t + n_b, n_queries)
    sp0 = below + 4 * WB + fs_out                              # depth after fs_transcript (witness + FS output)
    prog += [NUM(sp0 - 1 - idx_pos), OP("PICK")]              # copy k = idx_{query_i} (FS-derived) to the top
    prog += _open_leaves_at_k_prog(depth, sel_root, n_trace, n_sel, shift, N, tp_root,
                                   wbase=below, sp_start=sp0 + 1)   # open the four leaves at the derived k/kn
    return prog


def open_all_leaves_fs_unlock(tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path):
    """Push-only witness for open_all_leaves_fs_prog: the four leaves' [sib_{depth-1}..sib_0, preimage]
    blocks (NO index -- k/kn are FS-derived). Order: trace@k, trace@kn, selector@k, selector@kn."""
    def blk(pre, path):
        return [PUSH(s) for s, _ in reversed(path)] + [PUSH(pre)]
    return blk(tk_pre, tk_path) + blk(tn_pre, tn_path) + blk(sk_pre, sk_path) + blk(sn_pre, sn_path)


def run_open_all_leaves_fs(depth, sel_root, n_trace, n_sel, shift, n_t, n_b, tp_root, root, nf, cm_out,
                           fri_roots, nonce, N, n_queries, tk_pre, tk_path, tn_pre, tn_path,
                           sk_pre, sk_path, sn_pre, sn_path, query_i=0):
    """Run the FS-index-bound four-leaf opener supply on cashvm; ([2*n_trace+2*n_sel cells in leaf
    order], op_cost) on accept, raises VMError on a fail-closed reject. The cells are opened at the
    FS-derived k/kn, so the opened positions are transcript-bound (not free witness)."""
    vm = VM()
    vm.run(open_all_leaves_fs_unlock(tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path)
           + open_all_leaves_fs_prog(depth, sel_root, n_trace, n_sel, shift, n_t, n_b, tp_root, root, nf,
                                     cm_out, fri_roots, nonce, N, n_queries, query_i))
    ncells = 2 * n_trace + 2 * n_sel
    return [decode_num(x) for x in vm.s[-ncells:]], vm.op_cost


# ---- HP3.12: Fiat-Shamir transcript recomputation (Frozen-Heart-safe) ----------
# The shard DERIVES every challenge (alpha, beta, query index) from the SHA256 transcript
# on-chain -- it never trusts a witness challenge -- so a cheating prover cannot forge the
# random-linear-combination / FRI-fold / query challenges (Trail of Bits "Frozen Heart").
# Mirrors stark.FS exactly: s0=b"STARK-v0"; absorb(d): s=SHA256(s+d); absorb_int(v):
# absorb(v.to_bytes(8,'little')); challenge: s=SHA256(s+b"chal"), return int(s[:8] LE) % P;
# challenge_idx(N): s=SHA256(s+b"idx"), return int(s[:8] LE) % N. The 8-byte LE slice is padded
# with one 0x00 (force positive) and then OP_BIN2NUM re-encodes it as a MINIMAL Script number --
# required because the deployable VM (libauth BCH-2026) rejects non-minimally-encoded numbers in
# arithmetic (MOD/LESSTHAN); cashvm implements BIN2NUM identically so both VMs agree.
def fs_absorb_tokens(data):
    """tokens operating on the state s (top of stack): s' = SHA256(s + data)."""
    return [PUSH(data), OP("CAT"), OP("SHA256")]


def fs_challenge_tokens():
    """tokens (s on top) -> [challenge, s'] (s' on top for chaining). challenge =
    int(SHA256(s+b'chal')[:8] LE) % P."""
    return ([PUSH(b"chal"), OP("CAT"), OP("SHA256"), OP("DUP"),
             NUM(8), OP("SPLIT"), OP("DROP"), PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM")]
            + _MODT + [OP("SWAP")])


def fs_idx_tokens(N):
    """tokens (s on top) -> [idx, s']. idx = int(SHA256(s+b'idx')[:8] LE) % N."""
    return ([PUSH(b"idx"), OP("CAT"), OP("SHA256"), OP("DUP"),
             NUM(8), OP("SPLIT"), OP("DROP"), PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM"),
             PUSH(encode_num(N)), OP("MOD"), OP("SWAP")])


def grind_check_tokens(nonce, grind_b):
    """HP3.9: grinding (proof-of-work) check. tokens (s on top) -> [s'] after requiring
    int(SHA256(s+nonce)[:8] LE) < 2^(64-grind_b) and advancing the transcript to
    s' = SHA256(s+nonce) (mirrors stark.verify's grind gate). A nonce that does not meet
    the PoW target fails VERIFY (fail-closed)."""
    target = 1 << (64 - grind_b)
    return ([PUSH(nonce), OP("CAT"), OP("SHA256"), OP("DUP"),                   # [s', s']
             NUM(8), OP("SPLIT"), OP("DROP"), PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM"),  # [s', num]
             PUSH(encode_num(target)), OP("LESSTHAN"), OP("VERIFY")])            # [s']


def _folds_to_final(n):
    """Number of fold-by-2 steps to bring FRI layer size n down to <=8 (the commit stop rule, shared by
    fold-2 and fold-8; mirrors native_ct_air_stark._fri_folds_to_final). The TOTAL beta count = _folds_to_final(N),
    fold-INDEPENDENT (fold-8 draws s betas/round, fold-2 draws 1/layer, both halve size the same total)."""
    f = 0
    while (n >> f) > 8:
        f += 1
    return f


def fs_transcript_prog(tp_root, root, nf, cm_out, fri_roots, nonce, N, n_ext_alphas, n_queries,
                       fold_step=1, grind_b=None, deep=False, comp_root=None, masks=None):
    """HP2 (Gap B) + HP1.9-FOLD8 (HP4): reproduce verify()'s FULL Fiat-Shamir transcript in BCH-VM tokens and
    DERIVE the constraint-combination alphas, the FRI fold betas and the query-index SEQUENCE on-chain -- so the
    shard never trusts a witness challenge/index (Frozen-Heart, zk-circuit FS-2). Order mirrors verify():
    absorb tp_root, root, nf, cm_out -> n_ext_alphas ext challenges (2 base squeezes each, native
    _ext_challenge); absorb b"fri"; then the FRI commit loop -- fold_step=1 (fold-2, verify:338-343) absorbs
    ONE root per layer + draws ONE beta while size>8; fold_step=s (fold-8 layer-skip, verify:344-353) absorbs
    ONE root per ROUND + draws s betas (size>>=1 each) -- absorb the grind nonce; draw n_queries idx. Leaves
    bottom->top: [alpha bases (2*n_ext_alphas), beta bases (2 per fold), idx_0..idx_{nq-1}, final state].
    fold_step=1 is byte-identical to the classic fold-2 transcript (the 3 fold-2 callers pass the default);
    the fold-8 deploy FS (HP4.1) passes fold_step=FOLD. root/nf/cm absorbed as 8-byte LE; tp_root/root/nf/cm
    pinned, fri_roots+nonce are witness. The absorb SEQUENCE (1 root:1 beta vs 1 root:s betas) makes the
    derived betas/idx fold-DEPENDENT -- the deploy fold-8 FS MUST pass fold_step=FOLD to match verify()."""
    prog = [PUSH(b"STARK-v0")] + fs_absorb_tokens(tp_root)
    prog += fs_absorb_tokens(enc8(root % P)) + fs_absorb_tokens(enc8(nf % P))
    for cm in cm_out:
        prog += fs_absorb_tokens(enc8(cm % P))
    for _ in range(2 * n_ext_alphas):
        prog += fs_challenge_tokens()
    if deep:                                                  # HP11 DEEP transcript segment (mirrors prove():311-349)
        prog += fs_absorb_tokens(comp_root)                              # HP11.2 comp_root AFTER the AIR-alphas
        prog += fs_challenge_tokens() + fs_challenge_tokens()            # HP11.3 draw z=(z0,z1); state on top
        prog += [OP("SWAP"), OP("DUP"), NUM(0), OP("NUMEQUAL"), OP("ADD"), OP("SWAP")]   # z[1] -> 1 if z[1]==0
        for m0, m1 in masks:                                            # HP11.5 masks (prove:342-346 order)
            prog += fs_absorb_tokens(enc8(m0 % P)) + fs_absorb_tokens(enc8(m1 % P))
        for _ in range(2 * len(masks)):                                # HP11.6 draw deep_alphas (2 squeezes/term)
            prog += fs_challenge_tokens()
    prog += fs_absorb_tokens(b"fri")
    size = N; ri = 0
    while True:
        prog += fs_absorb_tokens(fri_roots[ri]); ri += 1     # ONE root per committed round (fold-8) / layer (fold-2)
        s = min(fold_step, _folds_to_final(size))            # fold_step=1 -> classic fold-2 (1 beta/layer)
        if s == 0:
            break                                            # final layer (size<=8): root absorbed, no beta
        for _ in range(s):                                   # fold-8: s betas per committed round, halving each
            prog += fs_challenge_tokens() + fs_challenge_tokens()   # one ext beta = 2 base squeezes
            size >>= 1
    if grind_b is None:
        prog += fs_absorb_tokens(nonce)                      # plain absorb (fold-2 test callers, no PoW gate)
    else:                                                    # HP4.3: ENFORCE the grinding PoW (verify:357-359)
        prog += grind_check_tokens(nonce, grind_b)           # s'=SHA256(s+nonce) AND int(s'[:8])<2^(64-grind_b), fail-closed
    for _ in range(n_queries):
        prog += fs_idx_tokens(N)
    return prog


def _absorb_from_blob(s, length):
    """HP4.4 FS-input keystone: absorb blob[s:s+length] into the running FS state, reading the field FROM the
    committed blob (kept on the alt stack) instead of from a baked argument. [state] on main + [blob] on
    alt-top -> state' = SHA256(state + blob[s:s+length]), with [blob] re-stashed on alt for the next field.
    Structurally identical to fs_absorb_tokens(blob[s:s+length]) -- so the transcript the FS input derives its
    challenges from is the SAME blob object it commits (absorb==commit, Frozen-Heart / zk-circuit FS-2): a
    prover cannot commit statement=X but derive challenges from Y. The offset/length are the HP2.4 blob layout
    (config-invariant), never witness."""
    return [OP("FROMALT"), OP("DUP"), PUSH(encode_num(s)), OP("SPLIT"), OP("NIP"),
            PUSH(encode_num(length)), OP("SPLIT"), OP("DROP"), OP("SWAP"), OP("TOALT"),
            OP("CAT"), OP("SHA256")]


def _read_from_blob(s, length):
    """HP11.4: read blob[s:s+length] as an unsigned LE number and leave it on the main stack (the blob stays on
    alt-top) WITHOUT absorbing it into the FS state -- the value-read counterpart of _absorb_from_blob, used where
    a committed blob field is needed as an OPERAND (the committed z*g, bound == oT*z) rather than a transcript
    absorb. Same config-invariant offset/length blob addressing (never witness)."""
    return [OP("FROMALT"), OP("DUP"), PUSH(encode_num(s)), OP("SPLIT"), OP("NIP"),
            PUSH(encode_num(length)), OP("SPLIT"), OP("DROP"), OP("SWAP"), OP("TOALT"),
            PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM")]


def fs_input_prog(N, n_ext_alphas, n_queries, n_out, n_r, fold_step, grind_b, deep=False, n_terms=0, oT=None):
    """HP4 FS-INPUT -- the deploy covenant's first, soundness-critical input. The FS input is a FIXED covenant,
    so the per-proof statement/roots are WITNESS (the blob), not baked: the redeem reproduces verify()'s FULL
    Fiat-Shamir transcript reading tp_root/root/nf/cm_out/fri_roots FROM the committed blob via
    _absorb_from_blob (absorb==commit, Frozen-Heart), draws the alphas/FRI betas/query idx, grinds with the
    witness nonce, and PROVES the derived alphas+betas+idx == the blob's committed fs_out (recompute-binding,
    HP4.2). A prover therefore cannot commit statement=X with challenges=derived(Y), cannot pick favourable
    challenges/queries, and must grind. unlock = [nonce, blob]; blob = HP2.4 layout
    [root(8) | nf(8) | cm_out(8*n_out) | tp_root(32) | fri_roots(32*n_r) | fs_out(alphas 16*n_ext_alphas,
    betas 16*_folds_to_final(N), idx 8*n_queries)]. Leaves [1] on accept; fails closed (VERIFY) on any
    mismatch. fold_step mirrors verify()/fs_transcript_prog (1 = fold-2, FOLD = fold-8 deploy). Validated on
    the real cashvm vs REAL proofs (self_test + scratchpad hp4_4_fs_input.py): honest -> accept; tampered
    committed alpha / statement root / nonce -> reject.
    HP11 (deep=True): the blob prefix additionally carries comp_root(32) | z*g(16) | mask_block(16*n_terms) after
    the fri_roots, and fs_out gains z(16) + deep_alphas(16*n_terms) between the alphas and the betas. The redeem
    absorbs comp_root after the AIR-alphas, draws z (z[1] forced != 0), BINDS the committed z*g == oT*z
    (fail-closed, NOT absorbed), absorbs the masks, draws the deep_alphas -- all before b"fri" -- and the
    recompute-binding then proves derived z + deep_alphas == the committed blob values. deep=False FS behavior
    unchanged. HP11.8-thin: the deep_alpha draws + the MASK-ABSORB + the committed-value-extract + the recompute-bind
    are ALL counter-free BEGIN/UNTIL loops (the extract pins len(fs_out)==8*M so its drain binds ALL M committed
    values -- HP17 fix; == unrolled, all paths), so the covenant is O(1) in the redeem: 10728B -> 5031B -> 921B demo,
    under the <=1650B THIN-SHARD target (not just the <=10000B consensus cap), and betas/queries/n_terms growth no
    longer inflates it. The mask-absorb drains a copy of the 16*n_terms mask block extracted NON-DESTRUCTIVELY onto
    the MAIN stack (prefix restored to alt), so it needs no alt-offset tracking. NOTE (cashvm/BCH): OP_SIZE does NOT
    consume its operand -- a drain-to-empty loop must keep the remaining blob on TOP for the SIZE test (an OVER+SIZE
    leaks one copy per iteration -> the stack grows and the loop never terminates)."""
    nq = n_queries
    n_beta = _folds_to_final(N)
    na2 = 2 * n_ext_alphas
    n_deep = (2 + 2 * n_terms) if deep else 0                   # HP11: z(2 limbs) + deep_alphas(2/term), derived+bound
    M = na2 + n_deep + 2 * n_beta + nq                          # committed fs_out values (alphas, [z, deep_alphas], betas, idx)
    tp_off = 16 + 8 * n_out                                    # tp_root offset in the blob
    cr_off = 48 + 8 * n_out + 32 * n_r                        # HP11.1 comp_root, right after the fri_roots
    zg_off = cr_off + 32                                       # HP11.4 committed z*g (bound == oT*z; not absorbed)
    mask_off = zg_off + 16                                     # HP11.5 mask block (16 bytes = 2 limbs per DEEP term)
    prefix_len = 8 + 8 + 8 * n_out + 32 + 32 * n_r + ((32 + 16 + 16 * n_terms) if deep else 0)
    pad = [PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM")]           # unsigned 8-byte LE -> num (fs_challenge semantics)
    # unlock [nonce, blob]: split off fs_out; extract the M committed values (0x00-pad BIN2NUM) -> alt; then
    # stash the prefix on alt-top for _absorb_from_blob to read.
    ch_fid, idx_fid = b"\x18", b"\x19"                        # HP10.5: DEFINE the uniform FS draws once (byte cut)
    prog = [PUSH(ch_fid), DEFINE(fs_challenge_tokens()), PUSH(idx_fid), DEFINE(fs_idx_tokens(N))]
    prog += [PUSH(encode_num(prefix_len)), OP("SPLIT")]        # [nonce, prefix, fs_out]
    # HP11.8 (HP17 fix): PIN len(fs_out) == 8*M before draining it. WITHOUT this pin a prover FRONT-pads fs_out
    # (M attacker cells followed by M correct derived copies): the drain-to-empty extract pushes 2M to the alt stack
    # (attacker cells at the BOTTOM), the DEPTH==0 recompute-bind pops only the top M (the correct copies) and
    # CLEANSTACK discards the alt-bottom surplus -> the attacker's front cells (which the cross-input consumers read
    # front-aligned at prefix_len) stay UNBOUND == a Frozen-Heart / FS-2 break (found in the HP17 soundness audit).
    # The size pin forces fs_out to be EXACTLY the M derived values, so the counter-free drain binds ALL of them.
    prog += [OP("SIZE"), PUSH(encode_num(8 * M)), OP("NUMEQUALVERIFY")]   # fail-closed length bind (M' == M)
    # extract the M committed fs_out values (8B each) to the alt via a BEGIN/UNTIL loop until fs_out is drained
    # (SIZE==0) -- counter-free (an alt counter would collide with the values pushed to alt); length pinned above,
    # so the drain is exactly M -> == the unrolled range(M) extract (binds the SAME front M values).
    prog += ([OP("BEGIN"), PUSH(encode_num(8)), OP("SPLIT"), OP("SWAP")] + pad
             + [OP("TOALT"), OP("SIZE"), NUM(0), OP("NUMEQUAL"), OP("UNTIL"), OP("DROP")])   # each 8B -> alt; drop empty tail
    prog += [OP("TOALT")]                                      # prefix -> alt-top (above the committed block)
    # transcript-from-blob (verify() order): tp_root, root, nf, cm_out absorbed FROM the prefix (absorb==commit)
    prog += [PUSH(b"STARK-v0")]
    prog += _absorb_from_blob(tp_off, 32)                      # tp_root FIRST
    prog += _absorb_from_blob(0, 8)                            # root
    prog += _absorb_from_blob(8, 8)                            # nf
    for i in range(n_out):
        prog += _absorb_from_blob(16 + 8 * i, 8)              # cm_out[i]
    prog += [PUSH(ch_fid), OP("INVOKE")] * na2               # alphas (accumulate below the state; DEFINE/INVOKE loop)
    if deep:                                                 # HP11 DEEP transcript segment (mirrors fs_transcript_prog)
        prog += _absorb_from_blob(cr_off, 32)                            # HP11.2 comp_root AFTER the AIR-alphas
        prog += [PUSH(ch_fid), OP("INVOKE"), PUSH(ch_fid), OP("INVOKE")]  # HP11.3 draw z=(z0,z1); state on top
        prog += [OP("SWAP"), OP("DUP"), NUM(0), OP("NUMEQUAL"), OP("ADD"), OP("SWAP")]   # z[1] -> 1 if z[1]==0
        # HP11.4 BIND committed z*g == oT*z, fail-closed (NOT absorbed): compute oT*z0/oT*z1 from the derived z
        # (PICK copies -> z stays below the state for the recompute-binding), read the committed z*g limbs,
        # NUMEQUALVERIFY. Blocks a prover-substituted z*g that the per-query DEEP inputs (HP12.3) would read.
        prog += [NUM(2), OP("PICK"), NUM(oT % P), OP("MUL")] + _MODT      # zg0_c = oT*z0 mod P (above the state)
        prog += [NUM(2), OP("PICK"), NUM(oT % P), OP("MUL")] + _MODT      # zg1_c = oT*z1 mod P
        prog += _read_from_blob(zg_off + 8, 8) + [OP("NUMEQUALVERIFY")]   # zg1_c == committed z*g[1]
        prog += _read_from_blob(zg_off, 8) + [OP("NUMEQUALVERIFY")]       # zg0_c == committed z*g[0]
        # HP11.8-thin: loop the mask-absorb (was 2*n_terms unrolled _absorb_from_blob, ~14B each). Extract the mask
        # block prefix[mask_off : mask_off+16*n_terms] to MAIN once (non-destructive -- the prefix returns to alt for
        # the later fri_root absorbs), then absorb each 8-byte cell into the FS state via a BEGIN/UNTIL loop draining
        # the block (exit at SIZE==0). The block is sliced at BAKED offsets from the fs_out-length-pinned prefix, so
        # its size is FIXED (not witness) -> the drain is exactly 2*n_terms absorbs in the SAME order == the unrolled
        # form (byte-identical FS state), with NO front-pad risk. Extract-to-main keeps the loop entirely off the alt
        # blob (no FROMALT in the body) -> no counter/offset conflict. O(1) redeem regardless of n_terms.
        prog += [OP("FROMALT"), OP("DUP"), PUSH(encode_num(mask_off)), OP("SPLIT"), OP("NIP"),
                 PUSH(encode_num(16 * n_terms)), OP("SPLIT"), OP("DROP"), OP("SWAP"), OP("TOALT")]   # -> [.., state, mask_block]
        prog += [OP("BEGIN"), PUSH(encode_num(8)), OP("SPLIT"),                    # [.., state, cell, rest]
                 NUM(2), OP("ROLL"), NUM(2), OP("ROLL"), OP("CAT"), OP("SHA256"),  # state || cell -> new state; [.., rest, new_state]
                 OP("SWAP"), OP("SIZE"), NUM(0), OP("NUMEQUAL"), OP("UNTIL")]      # rest back on top for the non-destructive SIZE; loop until drained
        prog += [OP("DROP")]                                            # drop the empty rest tail -> [.., state]
        prog += ([NUM(0), OP("TOALT"), OP("BEGIN"), PUSH(ch_fid), OP("INVOKE"),   # HP11.6/11.8 draw deep_alphas
                  OP("FROMALT"), OP("1ADD"), OP("DUP"), OP("TOALT"), NUM(2 * n_terms), OP("NUMEQUAL"),
                  OP("UNTIL"), OP("FROMALT"), OP("DROP")])                          # pinned-count BEGIN/UNTIL loop:
        # HP11.8 byte lever == the unrolled [PUSH(ch_fid),INVOKE]*2*n_terms (identical challenge draws + order, so
        # the FS output is byte-identical) but ~constant instead of ~3B*2*n_terms -> the DEEP FS covenant fits the
        # <=10000B consensus cap. The fs_challenge body is main-stack-only, so the loop counter sits on the alt
        # stack ABOVE the committed blob (the body never touches alt) and is cleaned (FROMALT DROP) leaving the blob
        # on alt-top for the b"fri" + fri_root absorbs. The count 2*n_terms is PINNED (config), never witness, so a
        # prover cannot pad/skip deep_alpha draws (fail-closed via the recompute-binding).
    prog += fs_absorb_tokens(b"fri")
    size = N; ri = 0
    while True:
        prog += _absorb_from_blob(48 + 8 * n_out + 32 * ri, 32); ri += 1   # fri_root per committed round
        s = min(fold_step, _folds_to_final(size))
        if s == 0:
            break
        for _ in range(s):
            prog += [PUSH(ch_fid), OP("INVOKE"), PUSH(ch_fid), OP("INVOKE")]   # s betas/round (fold-8), 1 (fold-2)
            size >>= 1
    prog += [OP("FROMALT"), OP("DROP")]                        # done reading the blob -> alt = [committed..]
    # grind with the WITNESS nonce (bottom of main, depth na2+2*n_beta+1 below the state): s'=SHA256(state+nonce)
    # and require the PoW (verify:357-359, fail-closed). Inlined (the nonce is on the stack, not baked).
    prog += [PUSH(encode_num(na2 + n_deep + 2 * n_beta + 1)), OP("ROLL")]  # nonce -> top; state now 2nd
    # PIN the nonce length = 8 (stark.grind returns i.to_bytes(8, 'little')): a fixed-length nonce makes the
    # FS unlock's push layout deterministic, so a cross-input reader (the OPENER's OP_INPUTBYTECODE tp_root
    # read, HP5.2) cannot be fed a length-padded nonce that shifts its absolute read offset onto an
    # attacker-chosen tp_root (push-encoding malleability, agent-gegencheck HP5.2). Fail-closed.
    prog += [OP("SIZE"), NUM(8), OP("NUMEQUALVERIFY")]        # nonce is exactly 8 bytes
    prog += [OP("CAT"), OP("SHA256")]                          # s' = SHA256(state + nonce)
    target = 1 << (64 - grind_b)
    prog += [OP("DUP"), NUM(8), OP("SPLIT"), OP("DROP"), PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM"),
             PUSH(encode_num(target)), OP("LESSTHAN"), OP("VERIFY")]       # PoW gate, leaves s'
    prog += [PUSH(idx_fid), OP("INVOKE")] * nq               # query idx (accumulate below the state; DEFINE/INVOKE loop)
    prog += [OP("DROP")]                                      # drop the final state -> [derived_0..derived_{M-1}]
    # HP11.8: bind derived == committed via a BEGIN/UNTIL loop until the main stack is drained (DEPTH==0) --
    # counter-free. Main holds EXACTLY the M derived challenges here, and the extract's length pin (SIZE==8*M above)
    # made the alt block EXACTLY the M committed values, so this pops all M (LIFO) and NUMEQUALVERIFYs each against
    # a derived challenge -- every committed value is bound (no unbound surplus). == the unrolled range(M) bind.
    prog += [OP("BEGIN"), OP("FROMALT"), OP("NUMEQUALVERIFY"), OP("DEPTH"), NUM(0), OP("NUMEQUAL"), OP("UNTIL")]
    prog += [NUM(1)]
    return prog


def fs_bound_open_prog(N, depth, root):
    """SOUNDNESS capstone (3.2/3.12/3.14): the query index is DERIVED from the Fiat-Shamir
    transcript (s = SHA256("STARK-v0" || root); idx = fs_idx(s, N)) and never taken as free
    witness; the Merkle opening is verified against the PINNED root at that derived index. A
    prover cannot pick a favourable position -- idx is fixed by the committed root, and a path
    for any other leaf fails the opener (fail-closed). The unlock supplies only [sib_{d-1}..sib_0,
    preimage]; the root, N and the FS seed are pinned in the redeem. Reuses the deployable opener
    (merkle_verify_stack_prog) and fs_idx_tokens; depends on OP_BIN2NUM for libauth minimality."""
    prog = [PUSH(b"STARK-v0"), PUSH(root), OP("CAT"), OP("SHA256")]   # s = SHA256(s0 || root)
    prog += fs_idx_tokens(N) + [OP("DROP")]                          # derive idx, drop s' -> [.., k]
    prog += merkle_verify_stack_prog(depth)[:-1]                     # opener up to the root check
    return prog + [PUSH(root), OP("EQUALVERIFY"), NUM(1)]            # pinned-root check + accept


def fs_bound_open_unlock(preimage, path):
    """Push-only witness for fs_bound_open_prog: [sib_{d-1}..sib_0, preimage] -- no index (it is
    derived) and no root (pinned). path = [(sib_i, bit_i)] from stark.m_path (bits unused here)."""
    return [PUSH(s) for s, _ in reversed(path)] + [PUSH(preimage)]


def run_fs_bound_open(N, depth, root, preimage, path):
    """Run the FS-bound opener on cashvm; (True, op_cost) if it accepts, (False, 0) on a fail-
    closed reject (a path for the wrong leaf -- i.e. not the FS-derived index)."""
    vm = VM()
    try:
        vm.run(fs_bound_open_unlock(preimage, path) + fs_bound_open_prog(N, depth, root))
        return True, vm.op_cost
    except VMError:
        return False, 0


def fri_index_chain_prog(halves):
    """HP2 (2.23): derive the FRI fold-index chain on-chain from the FS query index k. Mirrors verify()'s
    ci=k; ii=ci%half; ci=ii (query_fri_terms:350-363): with the per-layer half-sizes pinned
    (half_li = sizes[li]//2 = N//2^(li+1)), the running index is reduced mod each half, so
    ii_li = ((k % half_0) % half_1) ... % half_li. Pure integer OP_MOD -- k is the FS-derived index
    (< N, minimally encoded by fs_idx_tokens) and each half is a pinned minimal number, so no field
    prelude is needed and no free witness enters (a prover cannot pick ii; it is fixed by k). Input:
    [k] (top); leaves [ii_0, ii_1, ..., ii_{L-1}] (bottom->top) and consumes k."""
    prog = []
    L = len(halves)
    for li, half in enumerate(halves):
        prog += [PUSH(encode_num(half)), OP("MOD")]              # running %= half_li  -> ii_li
        if li < L - 1:
            prog += [OP("DUP")]                                   # keep ii_li (output) + copy as next running
    return prog


def fri_index_chain_unlock(k):
    """Push-only input for fri_index_chain_prog: the FS-derived query index [k]."""
    return [PUSH(encode_num(k))]


def run_fri_index_chain(k, halves):
    """Run the FRI index chain on cashvm; ([ii_0..ii_{L-1}], op_cost). No field prelude (pure integer)."""
    vm = VM()
    vm.run(fri_index_chain_unlock(k) + fri_index_chain_prog(halves))
    assert len(vm.s) == len(halves), "fri_index_chain left %d items, expected %d" % (len(vm.s), len(halves))
    return [decode_num(x) for x in vm.s], vm.op_cost


def fri_open_value_prog(depth):
    """HP2 (2.25): open one FRI leaf (v@ii or w@(ii+half)) against the FS-bound layer root with the
    Merkle direction bits DERIVED from the (2.23) fold index -- NOT baked -- and split the opened GF(p^2)
    leaf into its two limbs, so the fold (2.27) binds to the Merkle-verified value. Stack precondition
    (bottom->top): [root, sib_{d-1}..sib_0, preimage, index] with preimage = 16 zero salt bytes +
    enc8(v0) + enc8(v1) (the _leaf_ext FRI leaf) and index = ii (v) or ii+half (w). On success leaves
    [v0, v1]; a wrong sibling OR a wrong index fails EQUALVERIFY (fail-closed). Reuses the index-driven
    retaining opener (merkle_verify_retain_prog, which derives bit_i = index mod 2) + split_cells_prog
    (2 cells, 16-byte salt prefix) -- no new opener logic. No field prelude (SHA256/SPLIT/BIN2NUM only)."""
    return merkle_verify_retain_prog(depth) + split_cells_prog(2, prefix=16)


def fri_open_value_unlock(v0, v1, path, root, index):
    """Push-only unlock for fri_open_value_prog: [root, sib_{d-1}..sib_0, preimage, index] with
    preimage = 16 zero salt bytes + enc8(v0) + enc8(v1) (the FRI GF(p^2) leaf, _leaf_ext format).
    Siblings pushed in reverse (sib_0 just below the preimage); the direction bits are DERIVED, not pushed."""
    preimage = b"\x00" * 16 + enc8(v0 % P) + enc8(v1 % P)
    sibs = [s for s, _ in path]
    return [PUSH(root)] + [PUSH(s) for s in reversed(sibs)] + [PUSH(preimage), NUM(index)]


def run_fri_open_value(v0, v1, path, root, index):
    """Run the FRI leaf opener on cashvm; ([v0, v1], op_cost) on accept, raises VMError on a fail-closed
    reject (wrong sibling, wrong index, or tampered value)."""
    vm = VM()
    vm.run(fri_open_value_unlock(v0, v1, path, root, index) + fri_open_value_prog(len(path)))
    assert len(vm.s) == 2, "fri_open_value left %d items, expected 2" % len(vm.s)
    return [decode_num(x) for x in vm.s], vm.op_cost


def fri_open_vw_prog(depth):
    """HP3.5b-i: open BOTH FRI leaves of one layer -- v@ii and w@(ii+half) -- from the witness against
    the (pinned, FS-absorbed) layer root, the Merkle direction bits DERIVED from the index, leaving
    [v0, v1, w0, w1] (bottom->top) ready for the fold. Composes two fri_open_value opens with an alt
    stash: process w (the top witness block) -> [w0,w1], TOALT both onto the alt, process v -> [v0,v1],
    FROMALT both back -> [v0,v1,w0,w1]. The alt stash is balanced (two TOALT / two FROMALT) with no field
    op between, so it is field-prelude-safe (a resident P on the alt stays beneath and is restored). No
    field prelude needed here (SHA256/SPLIT only). A wrong sibling or index fails EQUALVERIFY (fail-closed)."""
    return (fri_open_value_prog(depth)                          # process w (top block) -> [w0, w1]
            + [OP("TOALT"), OP("TOALT")]                        # stash w0, w1 on the alt
            + fri_open_value_prog(depth)                        # process v -> [.., v0, v1]
            + [OP("FROMALT"), OP("FROMALT")])                   # restore -> [v0, v1, w0, w1]


def fri_open_vw_unlock(v0, v1, vpath, w0, w1, wpath, root, ii, half):
    """Push-only witness for fri_open_vw_prog: the v open block (root, sibs, preimage, ii) at the bottom,
    then the w open block (root, sibs, preimage, ii+half) on top (w is processed first). v/w are the
    prover-supplied GF(p^2) FRI values (witness), the root is pinned (FS-absorbed at 2.3)."""
    return (fri_open_value_unlock(v0, v1, vpath, root, ii)
            + fri_open_value_unlock(w0, w1, wpath, root, ii + half))


def run_fri_open_vw(v0, v1, vpath, w0, w1, wpath, root, ii, half):
    """Run the two-leaf FRI opener on cashvm; ([v0, v1, w0, w1], op_cost) on accept, raises VMError on a
    fail-closed reject (wrong sibling, wrong index, or a tampered value)."""
    vm = VM()
    vm.run(fri_open_vw_unlock(v0, v1, vpath, w0, w1, wpath, root, ii, half) + fri_open_vw_prog(len(vpath)))
    assert len(vm.s) == 4, "fri_open_vw left %d items, expected 4" % len(vm.s)
    return [decode_num(x) for x in vm.s], vm.op_cost


def fri_fold_from_vfw_prog(b0, b1, inv2, i2x, twox):
    """HP3.5b-i: fold one FRI layer given the opened [fv0, fv1, fw0, fw1] on the stack (the fri_open_vw
    output) and the layer's FS-derived fold operands (beta b0/b1, inv2=inv(2), i2x=inv(2*xpos),
    twox=2*xpos), leaving [folded0, folded1]. ext_fold_stack consumes its operands in _FOLD_OPS order
    (fw0,fw1,b0,b1,inv2,i2x,twox,fv0,fv1 -- fv ON TOP so the fold chain flows), so the opened
    [fv0,fv1,fw0,fw1] is re-arranged by PICK-copy into a fresh fold block (copy fw0,fw1, push the
    operands, copy fv0,fv1); the fold consumes that block, then the four originals are dropped (TOALT the
    2 results, DROP*4, FROMALT). The PICKs are top-relative so items beneath [fv,fw] are unaffected.
    Needs the field prelude (installed by the caller). The operands are pinned/FS-derived (deterministic,
    not free witness); the fold's hint checks (inv2*2==1, i2x*twox==1) are fail-closed."""
    return ([NUM(1), OP("PICK"), NUM(1), OP("PICK")]                    # copy fw0, fw1 -> top
            + [NUM(b0 % P), NUM(b1 % P), NUM(inv2 % P), NUM(i2x % P), NUM(twox % P)]   # fold operands
            + [NUM(10), OP("PICK"), NUM(10), OP("PICK")]                # copy fv0, fv1 -> top9 = _FOLD_OPS
            + ext_fold_stack_prog()                                     # consume -> [fv0,fv1,fw0,fw1, folded]
            + [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * 4 + [OP("FROMALT"), OP("FROMALT")])  # -> [folded]


def run_fri_fold_from_vfw(fv0, fv1, fw0, fw1, b0, b1, inv2, i2x, twox):
    """Run the layer fold on cashvm from the opened [fv0,fv1,fw0,fw1]; ((folded0,folded1), op_cost), or
    raises (fail-closed on a wrong inverse hint). Field prelude installed here for the isolated test."""
    vm = VM()
    vm.run(_field_prelude() + [NUM(fv0 % P), NUM(fv1 % P), NUM(fw0 % P), NUM(fw1 % P)]
           + fri_fold_from_vfw_prog(b0, b1, inv2, i2x, twox))
    assert len(vm.s) == 2, "fri_fold_from_vfw left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


def fri_roll_bind_prog(threshold):
    """HP3.5b-i: bind a value to the index-selected one of the two just-opened GF(p^2) leaves, adapted to
    the [val0,val1,fv0,fv1,fw0,fw1, idx] stack order the FRI chain produces -- the value being bound (the
    layer-0 composition, or the previous layer's fold output) sits BELOW the just-opened [fv,fw], with the
    derived index on top. Consumes idx to derive the bit idx>=threshold (integer LESSTHAN+NOT); on
    idx>=threshold requires val==fw, else val==fv (NUMEQUALVERIFY, fail-closed); then drops val (stash
    fv/fw on the alt, DROP val, restore) leaving [fv0,fv1,fw0,fw1] for the fold. The SAME block does the
    layer-0 comp==k-selected-leaf bind (val=comp, idx=k, threshold=half_0, verify:266-268) AND the rolling
    folded_{li-1}==next-layer-selected bind (val=folded, idx=ii_{li-1}, threshold=nh_li, verify:274-278).
    idx is DERIVED (from k / the FRI index chain), never free witness; threshold is pinned. No field
    prelude (integer LESSTHAN + NUMEQUALVERIFY + stack ops)."""
    return ([PUSH(encode_num(threshold)), OP("LESSTHAN"), OP("NOT"), OP("IF")]        # idx -> bit=(idx>=threshold)
            + [NUM(5), OP("PICK"), NUM(2), OP("PICK"), OP("NUMEQUALVERIFY"),          # bit=1: val0==fw0
               NUM(4), OP("PICK"), NUM(1), OP("PICK"), OP("NUMEQUALVERIFY")]          #        val1==fw1
            + [OP("ELSE")]
            + [NUM(5), OP("PICK"), NUM(4), OP("PICK"), OP("NUMEQUALVERIFY"),          # bit=0: val0==fv0
               NUM(4), OP("PICK"), NUM(3), OP("PICK"), OP("NUMEQUALVERIFY")]          #        val1==fv1
            + [OP("ENDIF")]
            + [OP("TOALT"), OP("TOALT"), OP("TOALT"), OP("TOALT")]                    # stash fv0,fv1,fw0,fw1
            + [OP("DROP"), OP("DROP")]                                               # drop val (bound, checked)
            + [OP("FROMALT"), OP("FROMALT"), OP("FROMALT"), OP("FROMALT")])           # restore [fv0,fv1,fw0,fw1]


def run_fri_roll_bind(val, fv, fw, idx, threshold):
    """Run the index-selected value bind on cashvm from [val,fv,fw,idx]; ([fv0,fv1,fw0,fw1], op_cost) on
    accept (val == the idx-selected leaf), raises VMError on a fail-closed reject. No field prelude."""
    vm = VM()
    vm.run([NUM(val[0] % P), NUM(val[1] % P), NUM(fv[0] % P), NUM(fv[1] % P), NUM(fw[0] % P), NUM(fw[1] % P),
            NUM(idx)] + fri_roll_bind_prog(threshold))
    assert len(vm.s) == 4, "fri_roll_bind left %d items, expected 4" % len(vm.s)
    return [decode_num(x) for x in vm.s], vm.op_cost


def _fri_chain_deployable_body(layers, k, final):
    """HP3.5b-i/ii: the FRI chain BODY -- the composition is ALREADY on the stack as [comp0, comp1] and no
    field prelude is emitted (the caller installed it). Per layer: open v@ii + w@(ii+half) from the witness
    (fri_open_vw, direction bits derived); bind the carried value == the index-selected leaf (fri_roll_bind:
    comp==k-selected at layer 0, else folded_{li-1}==ii-selected of this layer); fold (fri_fold_from_vfw).
    The last fold is bound to the FS-committed final layer (fri_final_bind). Consumes the two carried
    [comp0, comp1] items and leaves [1] on top of whatever sits beneath -- the SAME stack contract as
    fri_chain_prog(comp_on_stack=True), so it is a drop-in for the mapped-core stage D. Reused by
    fri_chain_deployable_tokens (standalone = prelude + baked comp + this body) and _mapped_core_stages
    (deployable_final=... stage D). v/w/paths + the final layer are prover-supplied (Merkle-/select-/final-
    bound, fail-closed); idx/threshold/beta/xpos/roots are pinned/FS-derived (deterministic). The openings
    are supplied inline here (the witness-in-unlock byte split is 3.5b-iii)."""
    inv2 = pow(2, P - 2, P)
    toks = []
    for li, L in enumerate(layers):
        fv = L["v"]; fw = L["w"]
        vp = [(bytes.fromhex(s), b) for s, b in L["vp"]]
        wp = [(bytes.fromhex(s), b) for s, b in L["wp"]]
        idx = k if li == 0 else layers[li - 1]["ii"]
        twox = (2 * L["xpos"]) % P; i2x = pow(twox, P - 2, P)
        toks += fri_open_vw_unlock(fv[0], fv[1], vp, fw[0], fw[1], wp, bytes.fromhex(L["root"]), L["ii"], L["half"])
        toks += fri_open_vw_prog(len(vp))
        toks += [NUM(idx)] + fri_roll_bind_prog(L["half"])
        toks += fri_fold_from_vfw_prog(L["beta"][0], L["beta"][1], inv2, i2x, twox)
    fb = []
    for f in final:
        fb += [NUM(f[0] % P), NUM(f[1] % P)]
    toks += fb + [NUM(layers[-1]["ii"])] + fri_final_bind_prog(len(final)) + [NUM(1)]
    return toks


def fri_chain_deployable_tokens(comp, layers, k, final):
    """HP3.5b-i: the FULL deployable FRI chain -- reproduces verify()'s FRI fold verification (257-282)
    from the Merkle-opened v/w with the composition and EVERY fold target bound by DERIVED index
    selection (fri_roll_bind) instead of the baked comp_tgt/fold_tgt of fri_chain_prog. Standalone form:
    the field prelude + the baked composition [comp0,comp1] + the shared _fri_chain_deployable_body (open +
    index-select-bind + fold per layer, terminal fold bound to the final layer). Leaves [1] on accept.
    comp = the composition [comp0,comp1]; v/w/paths + the final layer are prover-supplied (Merkle-/select-/
    final-bound, fail-closed); idx/threshold/beta/xpos/roots are pinned/FS-derived (deterministic)."""
    return _field_prelude() + [NUM(comp[0] % P), NUM(comp[1] % P)] + _fri_chain_deployable_body(layers, k, final)


def run_fri_chain_deployable(comp, layers, k, final):
    """Run the full deployable FRI chain on cashvm; (True, op_cost) if it accepts (clean [1]), (False, 0)
    on a fail-closed reject (comp != FRI layer-0, a tampered opening, a broken fold, or a wrong final)."""
    vm = VM()
    try:
        vm.run(fri_chain_deployable_tokens(comp, layers, k, final))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except VMError:
        return False, 0


def _fri_chain_deployable_witness_unlock(layers):
    """HP3.5b-iii-1: push-only witness for the witness-driven FRI chain -- per layer the two leaf blocks
    [v_sibs (reversed), v_preimage, w_sibs (reversed), w_preimage] (WB=depth+1 each; NO root, NO index).
    preimage = 16 salt bytes + enc8(v0)+enc8(v1) (the _leaf_ext FRI leaf). v/w/paths are Merkle-bound
    (safe as witness); the layer roots are pinned (baked) and ii is derived from k, so nothing free enters."""
    toks = []
    for ly in layers:
        v0, v1 = ly["v"]; w0, w1 = ly["w"]
        if "p" in ly:                                           # HP6.1 pair-leaf: ONE leaf = the coset (v,w)
            pp = [bytes.fromhex(s) for s, _ in ly["p"]]
            toks += [PUSH(s) for s in reversed(pp)] + [PUSH(b"\x00" * 16 + enc8(v0 % P) + enc8(v1 % P)
                                                            + enc8(w0 % P) + enc8(w1 % P))]
        else:
            vp = [bytes.fromhex(s) for s, _ in ly["vp"]]
            wp = [bytes.fromhex(s) for s, _ in ly["wp"]]
            toks += [PUSH(s) for s in reversed(vp)] + [PUSH(b"\x00" * 16 + enc8(v0 % P) + enc8(v1 % P))]
            toks += [PUSH(s) for s in reversed(wp)] + [PUSH(b"\x00" * 16 + enc8(w0 % P) + enc8(w1 % P))]
    return toks


def fri_chain_deployable_witness_redeem(comp, layers, k, final):
    """HP3.5b-iii-1: the WITNESS-DRIVEN deployable FRI chain redeem -- the SAME verification as
    _fri_chain_deployable_body (per layer open v@ii / w@(ii+half), bind comp/folded == index-selected leaf,
    fold; terminal bind to the FS-committed final layer) but the v/w openings are READ FROM the push-only
    unlock (_fri_chain_deployable_witness_unlock, at wbase=0) instead of inline in the redeem, the layer
    roots are BAKED, and the fold-index chain ii is DERIVED from k (fri_index_chain) -- so a thin-shard input
    carries its FRI openings in the witness (3.5b-iii). Only v/w/paths are witness (Merkle-bound by the baked
    root + fold-bound + roll_bind-index-selected); root/ii/half/beta/xpos stay pinned/FS-derived (NOT free).
    comp and k are baked here (per-input standalone form; per_query supplies comp on-stack + FS-derived k =
    iii-1a-integrate). Leaves clean [1] on accept; fail-closed (tampered v/w, wrong fold, wrong final). Betas
    + xpos stay FS-deterministic (pinned; iii-1b derives xpos). Validated == run_fri_chain_deployable."""
    L = len(layers)
    halves = [ly["half"] for ly in layers]
    pair = "p" in layers[0]                                      # HP6.1: pair-leaf format (1 coset-leaf/layer)
    WB = [len(ly["p" if pair else "vp"]) + 1 for ly in layers]   # sibs(depth)+preimage per leaf, per layer
    wstart = []; acc = 0
    for li in range(L):
        wstart.append(acc); acc += (1 if pair else 2) * WB[li]   # pair = 1 leaf/layer; 2-leaf = v-block + w-block
    nW = acc
    inv2 = pow(2, P - 2, P)
    prog = _field_prelude()
    sp = [nW]

    def copy(pos): prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1
    def num(v): prog.append(NUM(v % P)); sp[0] += 1

    num(k); prog += [OP("DUP")]; sp[0] += 1                      # k at nW (kept for roll_bind l0) + a copy
    prog += fri_index_chain_prog(halves); sp[0] += L - 1         # consumes the k copy, leaves [ii_0..ii_{L-1}]
    num(comp[0]); num(comp[1])                                   # carried [comp0, comp1]
    k_pos = nW
    def ii_pos(li): return nW + 1 + li                          # ii_li on the derived chain

    for li, ly in enumerate(layers):
        root = bytes.fromhex(ly["root"]); depth = len(ly["p" if pair else "vp"]); half = ly["half"]
        b0, b1 = ly["beta"]; twox = (2 * ly["xpos"]) % P; i2x = pow(twox, P - 2, P)
        if pair:                                               # HP6.1: ONE pair-leaf open -> [v0,v1,w0,w1]
            for i in range(WB[li]): copy(wstart[li] + i)        # pair leaf: [pair_sibs, pair_preimage]
            copy(ii_pos(li))                                    # index = ii_li (derived)
            prog += bound_retain_open_prog(depth, root) + split_cells_prog(4, prefix=16); sp[0] += 4 - (WB[li] + 1)
        else:
            for i in range(WB[li]): copy(wstart[li] + i)             # v leaf: [sibs, preimage]
            copy(ii_pos(li))                                         # index = ii_li (derived)
            prog += bound_retain_open_prog(depth, root) + split_cells_prog(2, prefix=16); sp[0] += 2 - (WB[li] + 1)
            for i in range(WB[li]): copy(wstart[li] + WB[li] + i)    # w leaf: [sibs, preimage]
            copy(ii_pos(li)); prog += [NUM(half), OP("ADD")]        # index = ii_li + half (copy +1, [NUM,ADD] net 0)
            prog += bound_retain_open_prog(depth, root) + split_cells_prog(2, prefix=16); sp[0] += 2 - (WB[li] + 1)
        copy(k_pos if li == 0 else ii_pos(li - 1))              # roll_bind idx = k (l0) / ii_{li-1}
        prog += fri_roll_bind_prog(half); sp[0] += -3           # [val,fv,fw,idx](7) -> [fv,fw](4)
        prog += fri_fold_from_vfw_prog(b0, b1, inv2, i2x, twox); sp[0] += -2   # [fv,fw](4) -> [folded](2)
    for f in final:
        num(f[0]); num(f[1])
    copy(ii_pos(L - 1))                                          # ii_{L-1} for the final-layer select
    prog += fri_final_bind_prog(len(final)); sp[0] -= (2 + 2 * len(final) + 1)
    below = nW + 1 + L                                           # [witness(nW), k, ii chain(L)] remain
    assert sp[0] == below, "witness FRI redeem pre-clean sp=%d expected %d" % (sp[0], below)
    return prog + [NUM(1)] + [OP("TOALT")] + [OP("DROP")] * below + [OP("FROMALT")]   # clean -> [1]


def run_fri_chain_deployable_witness(comp, layers, k, final):
    """Run the witness-driven deployable FRI chain on cashvm; (True, op_cost) if it accepts (clean [1]),
    (False, 0) on a fail-closed reject (comp != FRI layer-0, a tampered v/w opening, a broken fold, or a
    wrong final). Same accept as run_fri_chain_deployable (baked v/w) -- v/w now from the witness."""
    vm = VM()
    try:
        vm.run(_fri_chain_deployable_witness_unlock(layers)
               + fri_chain_deployable_witness_redeem(comp, layers, k, final))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except (VMError, IndexError):                              # IndexError = out-of-range OP_PICK (a truncated
        return False, 0                                       # witness) -> a hard script abort on the real BCH VM = reject


def _fri_partial_witness_unlock(layers, a, b):
    """HP3.5b-iii-2: push-only witness for a PARTIAL witness-driven FRI chain (only FRI layers [a..b)) --
    per layer [v_sibs (reversed), v_preimage, w_sibs (reversed), w_preimage]. The FRI witness is ~4.5KB > the
    1650B standard input, so the chain is byte-split into contiguous layer-subset inputs, each carrying its
    layers' openings in its own witness (Merkle-bound -> safe). NO root, NO index (roots baked, ii derived)."""
    toks = []
    for ly in layers[a:b]:
        v0, v1 = ly["v"]; w0, w1 = ly["w"]
        if "p" in ly:                                           # HP6.1 pair-leaf: ONE leaf = the coset (v,w)
            pp = [bytes.fromhex(s) for s, _ in ly["p"]]
            toks += [PUSH(s) for s in reversed(pp)] + [PUSH(b"\x00" * 16 + enc8(v0 % P) + enc8(v1 % P)
                                                            + enc8(w0 % P) + enc8(w1 % P))]
        else:
            vp = [bytes.fromhex(s) for s, _ in ly["vp"]]; wp = [bytes.fromhex(s) for s, _ in ly["wp"]]
            toks += [PUSH(s) for s in reversed(vp)] + [PUSH(b"\x00" * 16 + enc8(v0 % P) + enc8(v1 % P))]
            toks += [PUSH(s) for s in reversed(wp)] + [PUSH(b"\x00" * 16 + enc8(w0 % P) + enc8(w1 % P))]
    return toks


def fri_partial_witness_redeem(layers, a, b, carry_val, carry_idx, final, wbase=0, carry_split=False):
    """HP3.5b-iii-2/iii-3: the PARTIAL witness-driven FRI chain redeem -- verify ONLY FRI layers [a..b) in one thin-
    shard input. Takes a folded-carry IN (carry_val = comp for a=0, else folded_{a-1}) + the running index
    carry_idx (= ii_{a-1}, or k for a=0). Derives [ii_a..ii_{b-1}] from carry_idx (fri_index_chain over
    halves[a..b)); per layer opens v@ii / w@(ii+half) from the witness (baked roots), binds carry/folded ==
    index-selected leaf (roll_bind idx = carry_idx at layer a, else ii_{prev}), folds. When b==len(layers) the
    terminal fold binds to the FS-committed final layer -> accept [1]. Otherwise it leaves the carry OUT
    [folded_{b-1}(2), ii_{b-1}] on top of whatever sits beneath, for the NEXT input (the deploy links this via
    OP_INPUTBYTECODE, iii-3; carry baked here = standalone/per-input form). Soundness: only v/w/paths are
    witness (Merkle-/fold-/index-bound); roots/ii/half/beta/xpos pinned/derived. Validated: partial[0,c) +
    partial[c,L) with the (folded,ii) carry == run_fri_chain_deployable_witness (full chain), fail-closed."""
    L = len(layers); sub = layers[a:b]; nb = len(sub); halves = [ly["half"] for ly in sub]
    pair = "p" in sub[0]                                         # HP6.1: pair-leaf format (1 coset-leaf/layer)
    WB = [len(ly["p" if pair else "vp"]) + 1 for ly in sub]      # sibs(depth)+preimage per leaf, per sub-layer
    wstart = []; acc = 0
    for i in range(nb):
        wstart.append(acc); acc += (1 if pair else 2) * WB[i]   # pair-leaf = 1 leaf/layer; 2-leaf = v + w
    nW = acc
    inv2 = pow(2, P - 2, P)
    prog = _field_prelude()
    sp = [0]                                                    # set per mode below
    # wbase = items BENEATH the FRI witness that must be preserved (a producer's carry_preimage sits at
    # wbase=0..wbase-1). carry_split (iii-3 Option C deploy consumer): the 24-byte carry_preimage sits on
    # TOP of the FRI witness (read via OP_INPUTBYTECODE from the producer input); split_cells(3) recovers
    # (folded0,folded1,ii) as FIELD values that are USED as carry_val/carry_idx -- NOT byte-compared against
    # a separately-baked value (which would let a prover fold an unrelated poly Q while a byte-check still
    # passes; the OBS-2/FS-2 soundness fix, agent a8275b + Opus).

    def copy(pos): prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1
    def num(v): prog.append(NUM(v % P)); sp[0] += 1

    if carry_split:
        assert wbase == 0 and carry_val is None and carry_idx is None, \
            "carry_split sources the carry from the split preimage on top (wbase=0, no baked carry_val/idx)"
        sp[0] = nW + 1                                          # [witness(nW), carry_preimage(24B)]
        prog += split_cells_prog(3, prefix=0); sp[0] += 3 - 1   # preimage -> [folded0, folded1, ii] (field values)
        prog += [OP("DUP")]; sp[0] += 1                         # copy ii for the index chain
        prog += fri_index_chain_prog(halves); sp[0] += nb - 1   # -> [f0,f1,ii, ii_a..ii_{b-1}]
        copy(nW); copy(nW + 1)                                  # copy folded0,folded1 on top (== carry_val)
        idx0_pos = nW + 2; ii_base = nW + 3; below = nW + 3 + nb   # + the [folded0,folded1,ii] kept beneath
    else:
        sp[0] = wbase + nW
        num(carry_idx); prog += [OP("DUP")]; sp[0] += 1        # running index (roll_bind idx for layer a) + copy
        prog += fri_index_chain_prog(halves); sp[0] += nb - 1  # consumes the copy, leaves [ii_a..ii_{b-1}]
        num(carry_val[0]); num(carry_val[1])                   # carried value (comp / folded_{a-1})
        idx0_pos = wbase + nW; ii_base = wbase + nW + 1; below = nW + 1 + nb
    def ii_pos(i): return ii_base + i                          # ii_{a+i} on the derived chain

    for i, ly in enumerate(sub):
        root = bytes.fromhex(ly["root"]); depth = len(ly["p" if pair else "vp"]); half = ly["half"]
        b0, b1 = ly["beta"]; twox = (2 * ly["xpos"]) % P; i2x = pow(twox, P - 2, P)
        if pair:                                               # HP6.1: ONE pair-leaf open -> [v0,v1,w0,w1]
            for j in range(WB[i]): copy(wbase + wstart[i] + j)  # pair leaf: [pair_sibs, pair_preimage]
            copy(ii_pos(i))                                     # index = ii_{a+i}
            prog += bound_retain_open_prog(depth, root) + split_cells_prog(4, prefix=16); sp[0] += 4 - (WB[i] + 1)
        else:
            for j in range(WB[i]): copy(wbase + wstart[i] + j)     # v leaf: [sibs, preimage]
            copy(ii_pos(i))                                         # index = ii_{a+i}
            prog += bound_retain_open_prog(depth, root) + split_cells_prog(2, prefix=16); sp[0] += 2 - (WB[i] + 1)
            for j in range(WB[i]): copy(wbase + wstart[i] + WB[i] + j)   # w leaf: [sibs, preimage]
            copy(ii_pos(i)); prog += [NUM(half), OP("ADD")]        # index = ii_{a+i} + half
            prog += bound_retain_open_prog(depth, root) + split_cells_prog(2, prefix=16); sp[0] += 2 - (WB[i] + 1)
        copy(idx0_pos if i == 0 else ii_pos(i - 1))            # roll_bind idx = carry_idx (layer a) / ii_{prev}
        prog += fri_roll_bind_prog(half); sp[0] += -3
        prog += fri_fold_from_vfw_prog(b0, b1, inv2, i2x, twox); sp[0] += -2
    if b == L:                                                 # LAST FRI input: terminal final-layer bind
        for f in final:
            num(f[0]); num(f[1])
        copy(ii_pos(nb - 1))
        prog += fri_final_bind_prog(len(final)); sp[0] -= (2 + 2 * len(final) + 1)
        assert sp[0] == wbase + below, "partial FRI (last) pre-clean sp=%d expected %d" % (sp[0], wbase + below)
        return prog + [NUM(1)] + [OP("TOALT")] + [OP("DROP")] * below + [OP("FROMALT")]   # clean -> [wbase.., 1]
    else:                                                      # carry OUT: [folded0, folded1, ii_{b-1}]
        copy(ii_pos(nb - 1))                                   # ii_{b-1} = running index for the next input
        assert sp[0] == wbase + below + 3, "partial FRI (carry) sp=%d expected %d" % (sp[0], wbase + below + 3)
        return prog + [OP("TOALT")] * 3 + [OP("DROP")] * below + [OP("FROMALT")] * 3   # -> [wbase.., folded0,folded1,ii]


def run_fri_partial_witness(layers, a, b, carry_val, carry_idx, final):
    """Run a PARTIAL witness-driven FRI chain on cashvm. For the LAST input (b==len(layers)): (True, op_cost)
    on accept, (False, 0) on a fail-closed reject. For a non-last input (b<len): ([folded0, folded1, ii_{b-1}],
    op_cost) = the carry OUT for the next input, or (None, 0) on reject. Validated: chaining the carry of
    partial[0,c) into partial[c,L) == run_fri_chain_deployable_witness (the full chain)."""
    L = len(layers)
    vm = VM()
    try:
        vm.run(_fri_partial_witness_unlock(layers, a, b)
               + fri_partial_witness_redeem(layers, a, b, carry_val, carry_idx, final))
    except (VMError, IndexError):
        return (False, 0) if b == L else (None, 0)
    if b == L:
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    if len(vm.s) != 3:
        return None, 0
    return [decode_num(x) for x in vm.s], vm.op_cost


def fri_carry_preimage(folded0, folded1, ii):
    """HP3.5b-iii-3: the 24-byte cross-input FRI carry commitment = enc8(folded0) + enc8(folded1) + enc8(ii)
    (three 8-byte LE limbs). The producer BINDS this to its computed carry-out; the consumer reads it via
    OP_INPUTBYTECODE and OP_EQUALVERIFYs its baked carry-in. split_cells_prog(3) recovers the three values."""
    return enc8(folded0 % P) + enc8(folded1 % P) + enc8(ii % P)


def fri_partial_producer_unlock(carry_preimage, layers, a, b):
    """Push-only witness for a PRODUCER FRI input (iii-3): the 24-byte carry_preimage (fri_carry_preimage of
    the carry-out this input computes) at the BOTTOM, then the FRI witness for layers [a..b). The next input
    (consumer) reads this carry_preimage via OP_INPUTBYTECODE (the carry_preimage is input 0's first push)."""
    return [PUSH(carry_preimage)] + _fri_partial_witness_unlock(layers, a, b)


def fri_partial_producer_redeem(layers, a, b, carry_val, carry_idx):
    """HP3.5b-iii-3: the PRODUCER FRI input redeem -- run the embeddable partial-FRI [a..b) (wbase=1, so the
    carry_preimage sits beneath the FRI witness) then BIND the computed carry-out (folded0, folded1, ii_{b-1})
    to the 24-byte carry_preimage in the unlock: split_cells_prog(3) the carry_preimage and NUMEQUALVERIFY each
    limb == the computed value. The carry_preimage is thus bound to THIS input's on-chain computation -- a
    prover cannot supply a free/forged carry-out (it rejects at the producer, not just the consumer). b must be
    < len(layers) (a non-terminal FRI input; the terminal input final-binds via fri_partial_witness_redeem[.,L)
    and has no carry-out). Leaves [1] on accept. Validated: the 2-input link accepts on real libauth; a forged
    carry_preimage rejects here."""
    assert b < len(layers), "producer FRI input must be non-terminal (b < len(layers))"
    prog = fri_partial_witness_redeem(layers, a, b, carry_val, carry_idx, None, wbase=1)
    sp = [4]                                                    # after the partial: [carry_preimage@0, f0@1, f1@2, ii@3]

    def copy(pos): prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1

    copy(0)                                                     # copy the carry_preimage to the top
    prog += split_cells_prog(3, prefix=0); sp[0] += 3 - 1       # -> [.., folded0', folded1', ii'] (3 recovered limbs)
    copy(3); prog += [OP("NUMEQUALVERIFY")]; sp[0] -= 2         # ii'      == computed ii
    copy(2); prog += [OP("NUMEQUALVERIFY")]; sp[0] -= 2         # folded1' == computed folded1
    copy(1); prog += [OP("NUMEQUALVERIFY")]; sp[0] -= 2         # folded0' == computed folded0
    prog += [OP("DROP")] * 4 + [NUM(1)]; sp[0] += -3           # drop [carry_preimage, folded0, folded1, ii] -> [1]
    assert sp[0] == 1, "producer redeem left sp=%d expected 1" % sp[0]
    return prog


def run_fri_partial_producer(carry_preimage, layers, a, b, carry_val, carry_idx):
    """Run a producer FRI input on cashvm; (True, op_cost) on accept (clean [1]), (False, 0) on a fail-closed
    reject (a forged carry_preimage != the computed carry-out, or a tampered FRI opening)."""
    vm = VM()
    try:
        vm.run(fri_partial_producer_unlock(carry_preimage, layers, a, b)
               + fri_partial_producer_redeem(layers, a, b, carry_val, carry_idx))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except (VMError, IndexError):
        return False, 0


def fri_select_bind_prog(threshold):
    """HP2 (2.26/2.28): bind a value to the index-selected one of two GF(p^2) leaves. Input block
    (bottom->top): [a0, a1, b0, b1, val0, val1, idx]. Derives the bit idx>=threshold (integer LESSTHAN);
    on idx>=threshold requires val==b, else val==a, via NUMEQUALVERIFY (fail-closed). CONSUMES val0/val1
    and idx, PRESERVES [a0, a1, b0, b1] for the next stage. The direction bit is DERIVED, never baked, so
    a prover cannot rebind to the wrong leaf. Used by (2.26) comp==FRI-layer-0 leaf (a=fv, b=fw, idx=k,
    threshold=half_0, verify:266-268) and (2.28) folded==next-layer v/w (a=next.v, b=next.w, idx=ii,
    threshold=nh, verify:274-278). No field prelude (integer LESSTHAN + NUMEQUALVERIFY only)."""
    def _cmp(idx0, idx1):                                        # verify val0==leaf@idx0, val1==leaf@idx1
        b = []; s = [6]                                          # stack [a0,a1,b0,b1,val0,val1] after IF
        def pk(i): b.extend([NUM(s[0] - 1 - i), OP("PICK")]); s[0] += 1
        pk(5); pk(idx1); b.append(OP("NUMEQUALVERIFY")); s[0] -= 2   # val1 == leaf_1
        pk(4); pk(idx0); b.append(OP("NUMEQUALVERIFY")); s[0] -= 2   # val0 == leaf_0
        return b
    geq = [PUSH(encode_num(threshold)), OP("LESSTHAN"), OP("NOT")]   # idx -> (idx >= threshold)
    return (geq + [OP("IF")] + _cmp(2, 3)                        # idx>=threshold: val == b (idx 2,3)
            + [OP("ELSE")] + _cmp(0, 1)                          # idx<threshold:  val == a (idx 0,1)
            + [OP("ENDIF"), OP("DROP"), OP("DROP")])             # drop val0, val1 -> [a0,a1,b0,b1]


def fri_select_bind_unlock(a, b, val, idx):
    """Push-only input for fri_select_bind_prog: [a0, a1, b0, b1, val0, val1, idx]."""
    return [NUM(a[0] % P), NUM(a[1] % P), NUM(b[0] % P), NUM(b[1] % P),
            NUM(val[0] % P), NUM(val[1] % P), NUM(idx)]


def run_fri_select_bind(a, b, val, idx, threshold):
    """Run the index-selected binding on cashvm; ([a0,a1,b0,b1], op_cost) on accept, raises VMError on a
    fail-closed reject (val != the idx-selected leaf). No field prelude."""
    vm = VM()
    vm.run(fri_select_bind_unlock(a, b, val, idx) + fri_select_bind_prog(threshold))
    assert len(vm.s) == 4, "fri_select_bind left %d items, expected 4" % len(vm.s)
    return [decode_num(x) for x in vm.s], vm.op_cost


def fri_final_bind_prog(n_final):
    """HP2 (2.29): bind the terminal fold output to the FS-committed final FRI layer (verify:280
    if folded != final[ii % len(final)] return False). The final layer (n_final GF(p^2) values,
    prover-provided in the clear, its Merkle root FS-absorbed at 2.3) is selected at the DERIVED
    position pos = ii % n_final and required to equal the last fold output. Input block (bottom->top):
    [folded0, folded1, f0_0, f0_1, ..., f_{n-1}_0, f_{n-1}_1, ii]. Branchless index-select (static PICK,
    no dynamic-depth juggling): for each limb c require sum_p (pos==p)*(folded_c - final[p][c]) == 0 --
    exactly one term survives (p==pos), so this is folded_c == final[pos][c] (fail-closed). pos is
    DERIVED (integer MOD), never free witness, so a prover cannot pick which final entry is checked.
    Needs the field prelude (installed by the caller); leaves []."""
    L = n_final
    idx_pos = 2 + 2 * L                                          # ii (-> pos) is the top of the block
    prog = []
    sp = [2 + 2 * L + 1]                                         # the unlock pushed the block (ii on top)

    def pk(i): prog.extend([NUM(sp[0] - 1 - i), OP("PICK")]); sp[0] += 1
    def num(v): prog.append(NUM(v % P)); sp[0] += 1
    def mm(): prog.extend(MM()); sp[0] -= 1
    def am(): prog.extend(AM()); sp[0] -= 1
    def sm(): prog.extend(SM()); sp[0] -= 1
    def neq(): prog.append(OP("NUMEQUAL")); sp[0] -= 1
    def neqv(): prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2

    prog += [PUSH(encode_num(L)), OP("MOD")]                     # ii -> pos (net 0: +push -mod), pos at idx_pos
    for c in (0, 1):
        num(0)                                                  # acc = 0
        for p in range(L):
            pk(idx_pos); num(p); neq()                          # eq = (pos == p)  (1 or 0)
            pk(c); pk(2 + 2 * p + c); sm()                      # folded_c - final[p][c]
            mm()                                                # eq * diff
            am()                                                # acc += eq*(folded_c - final[p][c])
        num(0); neqv()                                          # require acc == 0  -> folded_c == final[pos][c]
    assert sp[0] == 2 + 2 * L + 1, "final_bind left sp=%d, expected block" % sp[0]
    return prog + [OP("DROP")] * (2 + 2 * L + 1)                # drop the block -> []


def fri_final_bind_unlock(folded, final, ii):
    """Push-only input for fri_final_bind_prog: [folded0, folded1, f0_0, f0_1, ..., f_{n-1}_1, ii]."""
    w = [NUM(folded[0] % P), NUM(folded[1] % P)]
    for f in final:
        w += [NUM(f[0] % P), NUM(f[1] % P)]
    return w + [NUM(ii)]


def run_fri_final_bind(folded, final, ii):
    """Run the terminal final-layer binding on cashvm; (True, op_cost) on accept, raises VMError on a
    fail-closed reject (folded != final[ii % len(final)])."""
    vm = VM()
    vm.run(_field_prelude() + fri_final_bind_unlock(folded, final, ii) + fri_final_bind_prog(len(final)))
    assert len(vm.s) == 0, "fri_final_bind left %d items, expected 0" % len(vm.s)
    return True, vm.op_cost


def _fri_loop_chain_body(rounds, k, final, oN, off, defines_installed=False):
    """HP3.10 fold-8: the FRI chain BODY as a stage-D drop-in for a FOLD-8 proof (query_fri_terms_fold8) --
    the fold-8 analog of _fri_chain_deployable_body (which is fold-2). The composition is ALREADY on the
    stack as [comp0, comp1] (stage-C output) and no field prelude is emitted (the caller installed it).
    Stashes comp to the alt (field-op-free), pushes the s=3 round witnesses inline (last round DEEPEST),
    restores comp, builds the initial carried [ci=k, stride_0, pe_0=2^li0_0, comp0, comp1] (comp binds to
    FRI layer-0 in round 0's body via folded==coset[k//stride_0]), runs fri_loop_s3_redeem(n) (the byte-
    amortized DEFINE/INVOKE s=3 loop -- the <100KB lever), then juggles the terminal carried to
    [folded0',folded1', final(2L), ii=ci'] (ci' == the last round's base, since next_ci=base per round) and
    fri_final_bind_prog binds folded'==final[ci'%L]. Consumes the two carried [comp0,comp1] and leaves [1]
    on top of whatever sits beneath -- the SAME [comp0,comp1]->[1] contract as _fri_chain_deployable_body,
    so it is a drop-in for the mapped-core stage D (fri_looped fold-8 branch). rounds = the query's rounds;
    k = the FS-derived query index; final = the proof's final FRI layer; oN/off = the FRI domain params.
    For the DEPLOY config N=2^21 (=8^7) a query is 6 s=3 rounds + this final bind, with NO s<3 tail. The
    round openings are inline here (the witness-in-unlock byte split is the deploy-assembler step, 3.5b-iii).
    Validated == verify() (accept + tamper comp/coset/final -> reject) on a real fold-8 proof in self_test."""
    assert rounds and all(r["s"] == 3 for r in rounds), (           # F2: enforce the 8^m no-tail precondition
        "fold-8 loop chain requires an 8^m domain (all s=3 rounds, no s<3 tail); got s-profile %r"
        % [r["s"] for r in rounds])                                 # deploy N=2^21=8^7 has no tail; reject non-8^m
    s3 = rounds
    n = len(s3); r0 = s3[0]; L = len(final)
    prog = [OP("TOALT"), OP("TOALT")]                            # stash comp1, comp0 to alt (field-op-free)
    for r in reversed(s3):                                       # round witnesses, last round DEEPEST
        prog += fri_loop_round_witness(r["stride"], 1 << r["li0"], r["betas"], r["base"], r["coset"],
                                       r["path"], bytes.fromhex(r["root"]), r["i2x"])
    prog += [OP("FROMALT"), OP("FROMALT")]                       # restore comp0, comp1 -> [<ws>, comp0, comp1]
    prog += [NUM(k % P), NUM(r0["stride"] % P), NUM((1 << r0["li0"]) % P),
             NUM(4), OP("ROLL"), NUM(4), OP("ROLL")]             # carried [ci=k, stride_0, pe_0, comp0, comp1]
    prog += fri_loop_s3_redeem(n, oN, off, defines_installed=defines_installed)   # -> [.., ci',str',pe',f0',f1']
    prog += [OP("TOALT"), OP("TOALT"), OP("DROP"), OP("DROP"),
             OP("FROMALT"), OP("FROMALT")]                       # -> [.., ci', folded0', folded1']
    for f in final:
        prog += [NUM(f[0] % P), NUM(f[1] % P)]                   # push final (2L cells)
    prog += [NUM(2 * L + 2), OP("ROLL")]                        # ci' (depth 2L+2) -> top = ii
    prog += fri_final_bind_prog(L)                              # folded'==final[ci'%L]; drops the block
    return prog + [NUM(1)]                                      # stage-D contract: [1] on accept


def run_fri_loop_chain(rounds, k, comp, final, oN, off, below=0):
    """Run the fold-8 loop chain body as the standalone stage-D drop-in on cashvm: field prelude +
    [`below` synthetic items] + [comp0,comp1] + _fri_loop_chain_body. (True, op_cost) on a clean [<below>,1]
    accept, (False, 0) on a fail-closed reject (tampered comp / coset / final, or a broken fold). comp = the
    composition [comp0, comp1]. `below` > 0 exercises BELOW-INVARIANCE: in the mapped-core stage D the
    opener/extras witness (total_below) sits beneath comp, and the body's top-relative PICK/ROLL/juggle must
    leave [1] on top of those untouched `below` items (the fold-2 _fri_chain_deployable_body relies on the
    same property; _mapped_core_stages then drops total_below and keeps [1])."""
    vm = VM()
    try:
        vm.run(_field_prelude() + [NUM((7 * i + 3) % P) for i in range(below)]
               + [NUM(comp[0] % P), NUM(comp[1] % P)] + _fri_loop_chain_body(rounds, k, final, oN, off))
        return (len(vm.s) == below + 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except (VMError, IndexError):                                # F5: a pathological witness stride can push a
        return False, 0                                         # runtime PICK out of range -> fail-closed reject


def _fri_loop_chain_redeem(rounds, k, final, oN, off, fri_root_last, defines_installed=False):
    """HP3.10(vi) UNLOCK-SPLIT deploy byte form of the fold-8 loop chain: the round openings live in the
    UNLOCK (scriptSig data, _fri_loop_chain_unlock), and THIS is the DEPTH-INVARIANT redeem (P2SH script) --
    fri_loop_defines body + carried-build + n INVOKE + juggle + final-bind + HP11 F3 final-ROOT-bind. Assumes
    the stack is [fri_root_last(32B), <round witnesses last-round-deepest>, comp0, comp1] (supplied by the
    unlock; fri_root_last at the BOTTOM, untouched by the top-relative loop until F3). = _fri_loop_chain_body
    minus the comp-stash + inline witness push (moved to the unlock). Below-invariant (the carried-build's
    ROLL and the loop's PICK/ROLL are top-relative, so the unlock witnesses beneath are untouched until the
    loop consumes them). This is the &lt;100KB lever in its true P2SH shape: the ~2.3 KB loop body is DEFINE'd
    once in the redeem (amortized), the depth-scaling openings are cheap scriptSig data. defines_installed=
    False (per-input deploy: each FRI input is a separate VM) prepends fri_loop_defines; True (a shared-VM
    caller hoisted them) emits INVOKE-only. Validated == the inline _fri_loop_chain_body (accept + tamper
    comp/coset/final -> reject) in self_test."""
    s3 = [r for r in rounds if r["s"] == 3]
    assert s3 and all(r["s"] == 3 for r in rounds), "fold-8 loop redeem requires an 8^m domain (all s=3)"
    n = len(s3); r0 = s3[0]; L = len(final)
    prog = [] if defines_installed else fri_loop_defines(oN, off)
    prog += [NUM(k % P), NUM(r0["stride"] % P), NUM((1 << r0["li0"]) % P),
             NUM(4), OP("ROLL"), NUM(4), OP("ROLL")]             # carried [ci=k, stride_0, pe_0, comp0, comp1]
    prog += fri_loop_s3_redeem(n, oN, off, defines_installed=True)   # INVOKE-only (defines above)
    prog += [OP("TOALT"), OP("TOALT"), OP("DROP"), OP("DROP"), OP("FROMALT"), OP("FROMALT")]
    for f in final:
        prog += [NUM(f[0] % P), NUM(f[1] % P)]                   # push final (2L cells)
    prog += [NUM(2 * L + 2), OP("ROLL")]
    prog += fri_final_bind_prog(L)                              # folded'==final[ci'%L]; stack now [fri_root_last]
    # HP11 F3: root-bind the baked `final` to the FS-single-sourced fri_roots[-1] (merkle(final)==fri_root_last),
    # closing the per-input-final-divergence gap -- across the nq SEPARATE FRI inputs a prover could otherwise
    # feed final_i != final_j (each self-bound only folded==final[pos]) so a high-degree composition escapes.
    # fri_root_last sits at the unlock bottom; in the deploy it is read cross-input via OP_INPUTBYTECODE from
    # the FS blob (HP9.3, single-source); here a witness push so the primitive is testable in isolation.
    for f in final:
        prog += [PUSH(enc8(f[0] % P) + enc8(f[1] % P))]        # bake the L leaf pre-images (enc8||enc8 body)
    prog += fri_final_root_bind_prog(L)                        # merkle(final) == fri_root_last (fail-closed)
    return prog + [NUM(1)]                                      # [1] on accept


def _fri_loop_chain_unlock(rounds, comp, fri_root_last):
    """HP3.10(vi) UNLOCK-SPLIT witness (scriptSig): [fri_root_last(32B), <round witnesses last-round-deepest>,
    comp0, comp1]. fri_root_last (fri_roots[-1], the FS-single-sourced final commitment) is at the BOTTOM so
    the top-relative loop leaves it untouched until the HP11 F3 final-root-bind consumes it. The round openings
    (coset preimage + Merkle sibs) are the depth-scaling data; comp is the composition supplied by stage-C /
    the producer input (comp==FRI-layer-0, bound in round 0)."""
    s3 = [r for r in rounds if r["s"] == 3]
    w = [PUSH(fri_root_last)]                                   # HP11 F3: fri_roots[-1] at the unlock bottom
    for r in reversed(s3):
        w += fri_loop_round_witness(r["stride"], 1 << r["li0"], r["betas"], r["base"], r["coset"],
                                    r["path"], bytes.fromhex(r["root"]), r["i2x"])
    return w + [NUM(comp[0] % P), NUM(comp[1] % P)]


def run_fri_loop_chain_split(rounds, k, comp, final, oN, off, fri_root_last):
    """Run the UNLOCK-SPLIT deploy form on cashvm: field prelude + unlock (witnesses, fri_root_last at the
    bottom) + redeem (defines + loop + HP11 F3 final-root-bind). (True, op_cost) on a clean [1] accept,
    (False, 0) on a fail-closed reject (incl. a wrong fri_root_last or tampered final). Validated == the inline
    run_fri_loop_chain + F3 accept/fail-closed in self_test."""
    vm = VM()
    try:
        vm.run(_field_prelude() + _fri_loop_chain_unlock(rounds, comp, fri_root_last)
               + _fri_loop_chain_redeem(rounds, k, final, oN, off, fri_root_last))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except (VMError, IndexError):
        return False, 0


def fri_loop_chain_multi_redeem(queries, oN, off, final, fri_root_last):
    """HP16 FRI AGGREGATION (<100KB lever): verify N fold-8 FRI chains (N queries) in ONE input, hoisting the ~2.3KB
    fri_loop_defines (the 0x04/0x05 round body) ONCE instead of once per query. queries = [(rounds, k), ...]. Each
    per-query chain runs defines_installed=True (INVOKE-only) and consumes its own witness block; the top-relative
    fold is below-invariant, so the deeper query blocks stay untouched until consumed (validated == the single-query
    _fri_loop_chain_redeem, with a tampered comp/query rejecting fail-closed). The per-query op-cost (~1 query-fold)
    caps aggregation at ~4 queries/input under the (41+scriptSig)*800 CHIP-2021-05 budget; nq=6 -> ~2 inputs, saving
    ~(queries_per_input-1)*2.3KB of DEFINE bytes per input. Each query's F3 final-root-bind still binds its `final`
    to the shared fri_root_last, so the per-input final-divergence gap (HP7.4c) stays closed under aggregation. The
    caller prepends the field prelude; leaves [1] on accept."""
    prog = fri_loop_defines(oN, off)                                # DEFINE the round body ONCE for all queries
    for (rounds, k) in queries:
        prog += _fri_loop_chain_redeem(rounds, k, final, oN, off, fri_root_last, defines_installed=True)[:-1]
    return prog + [NUM(1)]


def fri_loop_chain_multi_unlock(queries, fri_root_last):
    """Witness for fri_loop_chain_multi_redeem: queries = [(rounds, comp), ...]. The per-query witness blocks
    (_fri_loop_chain_unlock) are stacked with the FIRST-processed query on TOP (the loop consumes the stack top
    first, so the first redeem chain finds its block on top and the rest sit beneath, below-invariant)."""
    w = []
    for (rounds, comp) in reversed(queries):
        w += _fri_loop_chain_unlock(rounds, comp, fri_root_last)
    return w


def run_fri_loop_chain_multi(queries, final, oN, off, fri_root_last):
    """Run the N-query aggregated FRI on cashvm; (True, op_cost) on a clean [1] accept, (False, 0) on a fail-closed
    reject. queries = [(rounds, k, comp), ...]. Validated == N single-query run_fri_loop_chain_split in self_test."""
    rk = [(r, k) for (r, k, _c) in queries]
    rc = [(r, c) for (r, _k, c) in queries]
    vm = VM()
    try:
        vm.run(_field_prelude() + fri_loop_chain_multi_unlock(rc, fri_root_last)
               + fri_loop_chain_multi_redeem(rk, oN, off, final, fri_root_last))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except (VMError, IndexError):
        return False, 0


def fri_final_root_bind_prog(n_final):
    """HP7.4c: bind the prover's clear final FRI layer to its COMMITMENT fri_roots[-1] (== merkle(final),
    stark.py:69-75). fri_roots[-1] is FS-absorbed (verify:340/347) but the clear proof["final"] was NEVER
    checked to equal it (native_ct_air_stark verify, pre-HP7.4c): unqueried final slots are free and, across
    nq SEPARATE FRI-fold inputs each supplying its own `final` witness, a prover could feed final_i != final_j
    (per-input divergence) so a high-degree composition escapes -- the shard fri_final_bind_prog only checks
    folded == final[pos]. This recomputes the exact commitment root from the L=n_final leaves on the BCH-VM:
    leaf_j = SHA256(0x00*16 || enc8(v_j0) || enc8(v_j1)) = _leaf_ext(final[j], b"\\x00"*16); adjacent pairs
    are folded H(left||right) up the tree; require the root == the FS-single-sourced fri_roots[-1] (HP9.3, in
    the deploy read via OP_INPUTBYTECODE from the FS blob -- a pushed stack item here so the primitive is
    testable in isolation). `final` stays a WITNESS but is now root-bound, so every FRI input MUST use the one
    committed final. n_final is a power of 2 (FRI final-layer size = N / 2^folds with N a power of 2 -> always
    2^h), so the commitment tree (merkle()'s duplicate-last-if-odd never triggers) is a perfect binary tree ==
    the adjacent-pair fold built here.

    Stack precondition (bottom->top): [fri_root_last(32B), pre_0, pre_1, ..., pre_{L-1}] where pre_j =
    enc8(final[j][0]) || enc8(final[j][1]) (the 16-byte leaf body, verify-leaf format). Leaves [] -- the final
    EQUALVERIFY aborts fail-closed on any mismatch (a tampered final OR a wrong root). Pure SHA256/CAT: needs
    NO field prelude, and its alt usage is balanced (TOALT x L, then FROMALT x L) so it also composes cleanly
    above a field prelude's resident P."""
    if n_final < 1 or (n_final & (n_final - 1)) != 0:
        raise ValueError("fri_final_root_bind_prog: n_final must be a power of 2, got %d" % n_final)
    salt = b"\x00" * 16
    prog = [OP("TOALT")] * n_final                              # park pre_0..pre_{L-1} on alt (pop in order 0..L-1)
    for j in range(n_final):
        prog += [OP("FROMALT"), PUSH(salt), OP("SWAP"), OP("CAT"), OP("SHA256")]   # leaf_j = SHA256(salt||pre_j)
        t = j
        while t & 1:                                           # combines_after(j) = trailing 1-bits of j
            prog += [OP("CAT"), OP("SHA256")]                  # H(left_deeper || right_top): adjacent-pair fold
            t >>= 1
    return prog + [OP("EQUALVERIFY")]                          # computed root == committed fri_root_last


def fri_final_root_bind_unlock(final, fri_root_last):
    """Push-only witness for fri_final_root_bind_prog: [fri_root_last, pre_0, ..., pre_{L-1}] with pre_j the
    16-byte leaf body enc8(final[j][0]) || enc8(final[j][1]) (verify-leaf format, stark.py _leaf_ext)."""
    w = [PUSH(fri_root_last)]
    for v in final:
        w += [PUSH(enc8(v[0] % P) + enc8(v[1] % P))]
    return w


def run_fri_final_root_bind(final, fri_root_last):
    """Run the final-layer commitment binding on cashvm (pure SHA256, no field prelude); (True, op_cost) on
    accept, raises VMError on a fail-closed reject (merkle(final) != fri_root_last)."""
    vm = VM()
    vm.run(fri_final_root_bind_unlock(final, fri_root_last) + fri_final_root_bind_prog(len(final)))
    assert len(vm.s) == 0, "fri_final_root_bind left %d items, expected 0" % len(vm.s)
    return True, vm.op_cost


def fri_chain_prog(qfri, comp_x, prelude=True, comp_on_stack=False):
    """HP3.5b/3.5c: verify one query's FULL FRI fold chain on the BCH-VM. Per layer: open
    v@ii and w@(ii+half) against the (FS-bound) layer root via Merkle; at layer 0 require
    the composition value equals the opened FRI value at index k (the AIR<->FRI binding);
    fold (v,w,beta,inv2x) over GF(p^2) and require the result equals the next layer's
    opened value, or the committed final layer (3.5c). A tampered FRI value fails its
    Merkle open or the fold-target check (fail-closed). Single field prelude for all folds.
    prelude=False skips the field prelude (a prior stage installed it); comp_on_stack=True takes the
    layer-0 composition from the stack (two limbs left by compose_prog, comp1 on top) instead of the
    baked comp_x, so compose can be chained straight into the FRI binding (HP1 assembly seam)."""
    inv2 = pow(2, P - 2, P)
    prog = _field_prelude() if prelude else []
    for L in qfri["layers"]:
        v0, v1 = L["v"]; w0, w1 = L["w"]; root = bytes.fromhex(L["root"])
        pre_v = b"\x00" * 16 + enc8(v0 % P) + enc8(v1 % P)
        pre_w = b"\x00" * 16 + enc8(w0 % P) + enc8(w1 % P)
        prog += merkle_path_prog(pre_v, [(bytes.fromhex(s), b) for s, b in L["vp"]], root)
        prog += merkle_path_prog(pre_w, [(bytes.fromhex(s), b) for s, b in L["wp"]], root)
        if L["comp_tgt"] is not None:                                   # layer 0: comp == fri value
            ct0, ct1 = L["comp_tgt"]
            if comp_on_stack:                                           # consume compose's [comp0, comp1]
                prog += [NUM(ct1 % P), OP("NUMEQUALVERIFY"), NUM(ct0 % P), OP("NUMEQUALVERIFY")]
            else:
                prog += [NUM(comp_x[0] % P), NUM(ct0 % P), OP("NUMEQUALVERIFY"),
                         NUM(comp_x[1] % P), NUM(ct1 % P), OP("NUMEQUALVERIFY")]
        twox = (2 * L["xpos"]) % P; i2x = pow(twox, P - 2, P)
        prog += ext_fold_logic(v0, v1, w0, w1, L["beta"][0], L["beta"][1], inv2, i2x, twox)
        ft0, ft1 = L["fold_tgt"]                                        # folded == next/final
        prog += [NUM(ft1 % P), OP("NUMEQUALVERIFY"), NUM(ft0 % P), OP("NUMEQUALVERIFY")]
    prog += [NUM(1)]                                                    # script result: true
    return prog


def run_fri_chain(qfri, comp_x):
    vm = VM()
    try:
        vm.run(fri_chain_prog(qfri, comp_x))
        return (len(vm.s) >= 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except VMError:
        return False, 0


def assemble_compose_fri_prog(term, qfri):
    """HP1 per-query ASSEMBLY (compose->FRI seam): compose_prog computes the GF(p^2) composition
    and leaves [comp0, comp1] on the stack; the FRI chain (field prelude skipped, comp read from
    the stack) binds that value to the opened FRI layer-0 target and folds the whole chain under a
    single field prelude. Reproduces a real native_ct_air_stark query end-to-end -- the composition
    is COMPUTED and flows on-stack into the AIR<->FRI binding, not handed in as a literal. term is a
    query_terms() entry, qfri the index-aligned query_fri_terms() entry for the same query."""
    prog = compose_prog(term["trans_v"], term["trans_a"], term["qf_trans"],
                        term["bound_v"], term["bound_invX"], term["bound_a"])
    prog += fri_chain_prog(qfri, None, prelude=False, comp_on_stack=True)
    return prog


def run_assemble_compose_fri(term, qfri):
    """Run the assembled compose->FRI shard on cashvm; (True, op_cost) if it accepts, (False, 0)
    on a fail-closed reject (compose != FRI layer-0, a tampered FRI value, or a broken fold)."""
    vm = VM()
    try:
        vm.run(assemble_compose_fri_prog(term, qfri))
        return (len(vm.s) >= 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except VMError:
        return False, 0


# ---- HP2 (2.21a): assemble the FULL transition residual vector on-VM ------------------
# The opened trace cells (@k/@kn) and opened D-coset selectors are pushed as ONE persistent
# input block; the shard derives the round inputs (isr, y_full) on-chain and reuses the
# validated per-class residual progs (sbox/state/chain/hold/range) on PICK-copied input
# blocks, accumulating the residuals above the fixed block. Because a copy PICKs a value at
# its ABSOLUTE block index via PICK(sp-1-idx), residuals stacked above the block never shift a
# block value's reach. Reproduces native_ct_air_prover.ct_transition_residuals exactly.
_TRANS_ASM_OPS = (
    tuple("s%d" % k for k in range(WIDTH))          # cur state @k
    + tuple("u2_%d" % k for k in range(WIDTH))      # cur S-box aux @k
    + tuple("u4_%d" % k for k in range(WIDTH))
    + tuple("u6_%d" % k for k in range(WIDTH))
    + tuple("vh%d" % k for k in range(4))           # cur held (HELD_COLS order)
    + tuple("ns%d" % k for k in range(WIDTH))       # nxt state @kn
    + tuple("nvh%d" % k for k in range(4))          # nxt held @kn
    + ("isf", "isp")                                 # round-phase selectors
    + tuple("rc%d" % k for k in range(WIDTH))       # round constants (selector)
    + ("isbs", "isra")                               # sponge chain selectors
    + tuple("cm%d" % k for k in range(WIDTH))       # chain_minv (selector)
    + ("is_range", "is_range_first", "is_range_step", "is_range_last")
    + ("w_next",)                                    # range weight @kn (selector)
)


_SBOX_FID = b"\x11"                                              # HP10.5: the uniform S-box lane body, DEFINE'd once


def stagea_sbox_define():
    """DEFINE the (uniform, index-free) S-box lane body ONCE per program (place at the shard entry, next to
    _field_prelude). HP10.5 stage-A byte cut: assemble_transition then INVOKEs it per lane instead of inlining
    sbox_lane_stack_prog() 12x -- the body reads the top-6 [s,rc,u2,u4,u6,gate] block emit() pushes, identical
    for every lane, so this is a pure body-consolidation (no depth change, the emit sources are unchanged)."""
    return [PUSH(_SBOX_FID), DEFINE(sbox_lane_stack_prog())]


_STATE_FID = b"\x12"                                             # HP10.5: the uniform state-lane body, DEFINE'd once
_STATE_OPS_U = ("ef",) + tuple("yp%d" % k for k in range(WIDTH)) + ("diag", "sj", "isf", "isp", "ypj")


def stagea_state_uniform_body():
    """[block(18): ef,yp0..yp11,diag,sj,isf,isp,ypj] -> [v_j]. IDENTICAL arithmetic to
    state_lane_from_ef_stack_prog (v_j = isf*(sj-ef) + isp*(sj-ip), ip = ypj*diag + sum_k yp_k) but the
    yp_j*diag term reads the APPENDED 'ypj' (= y_part[j], a fixed top cell) instead of the per-j
    pick('yp%d'%j) -- so the body is UNIFORM (index-free) and DEFINE/INVOKE-able (assemble_transition appends
    yp_j as an extra source per state lane). Validated == the per-j body for all 12 lanes x both phases."""
    top = {nm: i for i, nm in enumerate(reversed(_STATE_OPS_U))}
    prog = []; above = [0]

    def pick(nm): prog.extend([NUM(above[0] + top[nm]), OP("PICK")]); above[0] += 1
    def num(v): prog.append(NUM(v % P)); above[0] += 1
    def mm(): prog.extend(MM()); above[0] -= 1
    def am(): prog.extend(AM()); above[0] -= 1
    def sm(): prog.extend(SM()); above[0] -= 1

    pick("sj"); pick("ef"); sm(); pick("isf"); mm()             # term1 = isf*(sj - ef)
    pick("ypj"); pick("diag"); mm()                            # yp_j*diag (appended ypj)
    num(0)
    for k in range(WIDTH):
        pick("yp%d" % k); am()                                 # sum_k yp[k]
    am()                                                       # ip = yp_j*diag + sum
    pick("sj"); prog.append(OP("SWAP")); sm(); pick("isp"); mm()   # term2 = isp*(sj - ip)
    am()                                                       # v_j
    assert above[0] == 1, "state uniform body left %d intermediates" % above[0]
    return prog + [OP("TOALT")] + [OP("DROP")] * len(_STATE_OPS_U) + [OP("FROMALT")]


def stagea_state_define():
    """DEFINE the uniform state-lane body ONCE per program (place at the shard entry, next to _field_prelude)."""
    return [PUSH(_STATE_FID), DEFINE(stagea_state_uniform_body())]


def assemble_transition_residuals_prog(diag, minv_cap_rows, below=0, sbox_looped=False, state_looped=False):
    """HP2 (2.21a): assemble the FULL transition residual vector trans_v (round 4*WIDTH + chain
    WIDTH-RATE+1 + hold len(HELD_COLS) + range 5 = ct_num_transition_residuals) on the stack from the
    opened trace cells @k/@kn and opened selectors (the _TRANS_ASM_OPS block pushed by the unlock).
    On-chain it (1) derives isr=isf+isp and y_full[k]=u6_k*(s_k+rc_k) into the block, then (2) reuses
    the validated per-class residual progs on PICK-copied input blocks (y_part[k]=y_full[0] if k==0 else
    s_k needs no storage). The external MDS is applied via the STRUCTURED M4-block form (matmul_external_prog:
    ef = M_EXT.y_full computed once for all lanes -- the M4 algorithm IS M_EXT); diag and the inverse-MDS
    capacity rows are BAKED public constants; all cells/selectors are opened. The M_EXT matrix is thus no
    longer a data argument (removed) -- it is realized structurally in the opcodes, unforgeable by design.
    Reproduces ct_transition_residuals(cur, nxt, pub_x, w_next) exactly.
    Needs one field prelude; leaves [trans_v_0..trans_v_{n-1}] (bottom->top) and drops the block.
    `below` = number of stack items BENEATH this block (single-program threading, 2.31): the block sits
    on top of `below` prior items, so every PICK index is offset by `below` and the final DROP removes
    only this block+derivations (the residuals are stashed to alt, the `below` items stay untouched)."""
    idx = {nm: below + i for i, nm in enumerate(_TRANS_ASM_OPS)}
    NB = len(_TRANS_ASM_OPS)
    idx["isr"] = below + NB
    for k in range(WIDTH):
        idx["yfull%d" % k] = below + NB + 1 + k
    for k in range(WIDTH):
        idx["ef%d" % k] = below + NB + 1 + WIDTH + k     # ef = M_EXT.y_full (structured M4-block, computed once)
    BLOCK = NB + 1 + WIDTH + WIDTH
    prog = []
    sp = [below + NB]                                            # stack size (below items + the NB-value block)

    def pk(nm): prog.extend([NUM(sp[0] - 1 - idx[nm]), OP("PICK")]); sp[0] += 1
    def num(v): prog.append(NUM(v % P)); sp[0] += 1
    def mm(): prog.extend(MM()); sp[0] -= 1
    def am(): prog.extend(AM()); sp[0] -= 1

    # (1) derivations appended to the block: isr = isf+isp ; y_full[k] = u6_k*(s_k+rc_k) ; then the external
    #     MDS image ef = M_EXT.y_full computed ONCE for all lanes via the STRUCTURED M4-block form
    #     (matmul_external_prog: ADDMOD + x2/x4-as-adds, no generic WIDTH*WIDTH dot). Each state lane below
    #     then reads its ef_j instead of recomputing the M_EXT-row dot -- SAME residual, fewer field muls.
    pk("isf"); pk("isp"); am()                                   # -> isr
    for k in range(WIDTH):
        pk("s%d" % k); pk("rc%d" % k); am(); pk("u6_%d" % k); mm()   # -> y_full[k]
    assert sp[0] == below + NB + 1 + WIDTH, "yfull derivation left sp=%d, expected %d" % (sp[0], below + NB + 1 + WIDTH)
    prog.extend(matmul_external_prog(idx["yfull0"], sp[0])); sp[0] += WIDTH   # -> ef_0..ef_{WIDTH-1} on top (y preserved)
    assert sp[0] == below + BLOCK, "derivation+ef left sp=%d, expected %d" % (sp[0], below + BLOCK)

    # (2) residual emission: push each prog's input block (copies/baked) in its _*_OPS order, then
    #     the prog tokens (which PICK within the just-pushed top block and drop it, leaving r_out)
    def emit(sources, prog_tokens, r_out):
        base = sp[0]
        for kind, val in sources:
            pk(val) if kind == "blk" else num(val)
        prog.extend(prog_tokens)
        sp[0] = base + r_out

    for k in range(WIDTH):                                        # round: 12 S-box lanes
        gate = "isr" if k == 0 else "isf"
        emit([("blk", "s%d" % k), ("blk", "rc%d" % k), ("blk", "u2_%d" % k),
              ("blk", "u4_%d" % k), ("blk", "u6_%d" % k), ("blk", gate)],
             ([PUSH(_SBOX_FID), OP("INVOKE")] if sbox_looped else sbox_lane_stack_prog()), 3)
    for j in range(WIDTH):                                        # round: 12 state lanes (read precomputed ef_j)
        src = [("blk", "ef%d" % j)]                               # ef_j = (M_EXT.y_full)[j] from matmul_external
        src += [("blk", "yfull0" if m == 0 else "s%d" % m) for m in range(WIDTH)]   # y_part
        src += [("num", diag[j]), ("blk", "ns%d" % j), ("blk", "isf"), ("blk", "isp")]
        if state_looped:
            src += [("blk", "yfull0" if j == 0 else "s%d" % j)]  # append ypj = y_part[j] -> uniform DEFINE/INVOKE body
            emit(src, [PUSH(_STATE_FID), OP("INVOKE")], 1)
        else:
            emit(src, state_lane_from_ef_stack_prog(j), 1)
    emit([("blk", "s%d" % m) for m in range(WIDTH)]               # chain (WIDTH-RATE capacity + 1)
         + [("blk", "ns%d" % m) for m in range(WIDTH)]
         + [("blk", "cm%d" % m) for m in range(WIDTH)]
         + [("blk", "isbs"), ("blk", "isra")],
         chain_residual_stack_prog(minv_cap_rows), len(minv_cap_rows) + 1)
    emit([("blk", "vh%d" % m) for m in range(4)]                  # hold (len HELD_COLS = 4)
         + [("blk", "nvh%d" % m) for m in range(4)],
         hold_residual_stack_prog(4), 4)
    emit([("blk", "s0"), ("blk", "s1"), ("blk", "s2"),           # range (5)
          ("blk", "is_range"), ("blk", "is_range_first"), ("blk", "is_range_step"), ("blk", "is_range_last"),
          ("blk", "ns0"), ("blk", "ns1"), ("blk", "ns2"), ("blk", "w_next")],
         range_residual_stack_prog(), 5)

    R = 4 * WIDTH + len(minv_cap_rows) + 10                       # 36 sbox + 12 state + (cap+1) + 4 + 5
    assert sp[0] == below + BLOCK + R, "assembly left sp=%d, expected %d" % (sp[0], below + BLOCK + R)
    return prog + [OP("TOALT")] * R + [OP("DROP")] * BLOCK + [OP("FROMALT")] * R


def assemble_transition_unlock(cur, nxt, pub_x, w_next, held_cols):
    """Push-only opened cells + selectors for assemble_transition_residuals_prog, in _TRANS_ASM_OPS
    order. cur/nxt are the opened trace rows @k/@kn; pub_x the opened D-coset selector row; held_cols
    the HELD_COLS name list (single source, passed in to keep the shard prover-import-free)."""
    W = WIDTH
    vals = ([cur["s%d" % k] for k in range(W)]
            + [cur["u2_%d" % k] for k in range(W)]
            + [cur["u4_%d" % k] for k in range(W)]
            + [cur["u6_%d" % k] for k in range(W)]
            + [cur[c] for c in held_cols]
            + [nxt["s%d" % k] for k in range(W)]
            + [nxt[c] for c in held_cols]
            + [pub_x["is_full"], pub_x["is_partial"]]
            + [pub_x["rc"][k] for k in range(W)]
            + [pub_x["is_block_start"], pub_x["is_reabsorb"]]
            + [pub_x["chain_minv"][k] for k in range(W)]
            + [pub_x["is_range"], pub_x["is_range_first"], pub_x["is_range_step"], pub_x["is_range_last"]]
            + [w_next])
    assert len(vals) == len(_TRANS_ASM_OPS), "trans unlock arity %d != %d" % (len(vals), len(_TRANS_ASM_OPS))
    assert len(held_cols) == 4, "trans unlock expects 4 held cols, got %d" % len(held_cols)
    return [NUM(v % P) for v in vals]


def run_assemble_transition(diag, minv_cap_rows, cur, nxt, pub_x, w_next, held_cols, sbox_looped=False,
                            state_looped=False):
    """Run the deployable transition-residual assembly on cashvm; ([trans_v...], op_cost). sbox_looped/
    state_looped=True DEFINE the S-box / state body once + INVOKE it per lane (== the unrolled trans_v, byte cut)."""
    R = 4 * WIDTH + len(minv_cap_rows) + 10
    vm = VM()
    vm.run(_field_prelude() + (stagea_sbox_define() if sbox_looped else []) + (stagea_state_define() if state_looped else [])
           + assemble_transition_unlock(cur, nxt, pub_x, w_next, held_cols)
           + assemble_transition_residuals_prog(diag, minv_cap_rows, sbox_looped=sbox_looped, state_looped=state_looped))
    assert len(vm.s) == R, "assemble_transition left %d items, expected %d" % (len(vm.s), R)
    return [decode_num(x) for x in vm.s], vm.op_cost


def _derive_m4_ext():
    """The 4x4 external-MDS block M4, DERIVED from the reference native_poseidon2._matmul_m4 by applying it to the
    unit vectors (no hand-transcription -- mirrors _derive_ext_matrix's derivation of the dense M_EXT). The Poseidon2
    external layer factors as M4-per-4-block + per-lane block-sum broadcast (native_poseidon2._matmul_external), so
    ef = M_EXT.y_full needs only 4-term M4 rows + block sums, not the dense 144-term matvec."""
    import native_poseidon2 as _P2M
    M = [[0] * 4 for _ in range(4)]
    for k in range(4):
        s = [0] * WIDTH
        s[k] = 1
        _P2M._matmul_m4(s)
        for r in range(4):
            M[r][k] = s[r]
    return M


_M4_EXT = _derive_m4_ext()


def assemble_transition_ext_prog(m_ext, diag, minv_cap_rows, below=0, sbox_looped=False, state_looped=False):
    """HP9.5: assemble the FULL GF(p^2) transition residual vector trans_v at the OOD point z -- the deploy
    counterpart of assemble_transition_residuals_prog and the GF(p^2) mirror of ct_transition_residuals_ext.
    Reads the _TRANS_ASM_OPS block (the OOD cells @z + selectors @z and next-row @z*g, each 2 limbs), derives
    isr=isf+isp and y_full[k]=u6_k*(s_k+rc_k) over GF(p^2), then emits round (12 S-box lanes + 12 state lanes),
    chain, hold, range via the tested GF(p^2) leaf progs on PICK-copied operand blocks (same emit idiom as the
    base). m_ext=M_EXT, diag=MAT_DIAG12, minv_cap_rows are pinned public constants (baked). Leaves the 62 ext
    trans_v; drops the block. `below` offsets the PICKs (single-program threading). sbox_looped=True DEFINEs the
    uniform S-box body once (0x21) at entry and INVOKEs it per lane (byte cut; assembly runs once so no fid
    collision). state_looped=True precomputes ef=M_EXT.y_full ONCE for all lanes via the M4-block factorization
    (HP16 byte/op-cost cut: M4 per 4-block + block-sum broadcast == the dense 144-term matvec, ~1/3 the ext-scalars)
    and INVOKEs the uniform state body (0x22) per lane. Cross-checked ==ct_transition_residuals_ext (HP15.11)."""
    W = WIDTH
    base_ops = list(_TRANS_ASM_OPS)
    order = base_ops + ["isr"] + ["yf%d" % k for k in range(W)]   # block ext-values (base + derivations)
    if state_looped:                                             # M4-block ef: mm per 4-block, stored block-sums, ef (shared)
        order += (["mm%d" % k for k in range(W)] + ["stor%d" % l for l in range(4)]
                  + ["ef%d" % k for k in range(W)])
    idx = {nm: i for i, nm in enumerate(order)}
    BLOCK = len(order)
    n_deriv0 = len(base_ops) + 1 + W                              # base + isr + y_full (before ef)
    prog = []
    if sbox_looped:
        prog += stagea_sbox_ext_define()                         # DEFINE the S-box body once (net-0 on stack)
    if state_looped:
        prog += stagea_state_ext_define()                        # DEFINE the uniform state body once (net-0)
    sp = [below + 2 * len(base_ops)]                              # limbs on the stack (below + base block)

    def pk(nm):                                                   # copy an ext operand to top ([limb0, limb1])
        i = idx[nm]
        prog.extend([NUM(sp[0] - 1 - (below + 2 * i)), OP("PICK")]); sp[0] += 1
        prog.extend([NUM(sp[0] - 1 - (below + 2 * i + 1)), OP("PICK")]); sp[0] += 1

    def eadd(): prog.extend(ext_add_stack_prog()); sp[0] -= 2
    def emul(): prog.extend(ext_mul_stack_prog()); sp[0] -= 2

    def escalar(s, name):                                        # push base s * ext block[name] (one ext value)
        prog.append(NUM(s % P)); sp[0] += 1
        i = idx[name]
        prog.extend([NUM(sp[0] - 1 - (below + 2 * i)), OP("PICK")]); sp[0] += 1
        prog.extend([NUM(sp[0] - 1 - (below + 2 * i + 1)), OP("PICK")]); sp[0] += 1
        prog.extend(ext_scalar_stack_prog()); sp[0] -= 1         # [s,a0,a1] -> [c0,c1]

    pk("isf"); pk("isp"); eadd()                                 # -> isr (ext-index len(base_ops))
    for k in range(W):
        pk("s%d" % k); pk("rc%d" % k); eadd(); pk("u6_%d" % k); emul()   # -> y_full[k]
    assert sp[0] == below + 2 * n_deriv0, "yf derivation left sp=%d, expected %d" % (sp[0], below + 2 * n_deriv0)
    if state_looped:                                            # ef = M_EXT.y_full via the M4-block factorization
        for blk in range(0, W, 4):                              # M4 per 4-block: mm[blk+r] = sum_k M4[r][k]*yf[blk+k]
            for r in range(4):
                escalar(_M4_EXT[r][0], "yf%d" % blk)
                for kk in range(1, 4):
                    escalar(_M4_EXT[r][kk], "yf%d" % (blk + kk)); eadd()
        for l in range(4):                                     # stored[l] = mm[l] + mm[4+l] + mm[8+l] (block sums)
            pk("mm%d" % l); pk("mm%d" % (4 + l)); eadd(); pk("mm%d" % (8 + l)); eadd()
        for i in range(W):                                     # ef[i] = mm[i] + stored[i%4]  (== M_EXT[i].y_full)
            pk("mm%d" % i); pk("stor%d" % (i % 4)); eadd()
    assert sp[0] == below + 2 * BLOCK, "block build left sp=%d, expected %d" % (sp[0], below + 2 * BLOCK)

    def emit(src_names, leaf_prog, r_out):                       # push operands (leaf order) then run the leaf
        b = sp[0]
        for nm in src_names:
            pk(nm)
        prog.extend(leaf_prog)
        sp[0] = b + 2 * r_out

    _sbox_body = [PUSH(_SBOX_EXT_FID), OP("INVOKE")] if sbox_looped else sbox_lane_ext_residuals_prog()
    for k in range(W):                                            # 12 S-box lanes (3 residuals each)
        gate = "isr" if k == 0 else "isf"
        emit(["s%d" % k, "rc%d" % k, "u2_%d" % k, "u4_%d" % k, "u6_%d" % k, gate], list(_sbox_body), 3)
    if state_looped:                                             # 12 state lanes via the uniform body (ef precomputed)
        for j in range(W):
            b = sp[0]
            pk("ef%d" % j)                                       # ef
            pk("yf0")                                            # yp0 = y_full[0]
            for k in range(1, W):
                pk("s%d" % k)                                    # yp1..yp{W-1} = s_k
            prog.extend([NUM(diag[j] % P), NUM(0)]); sp[0] += 2  # diag as ext (diag_j, 0)
            pk("ns%d" % j); pk("isf"); pk("isp")                 # sj, isf, isp
            pk("yf0" if j == 0 else "s%d" % j)                   # ypj = y_part[j]
            prog.extend([PUSH(_STATE_EXT_FID), OP("INVOKE")])
            sp[0] = b + 2                                        # 1 residual
    else:
        for j in range(W):                                       # 12 state lanes (unrolled; y_part[0]=y_full[0])
            yf = ["yf%d" % k for k in range(W)]
            yp = ["yf0" if k == 0 else "s%d" % k for k in range(W)]
            emit(yf + yp + ["ns%d" % j, "isf", "isp"], state_lane_ext_residual_prog(m_ext[j], diag[j], j), 1)
    emit(["s%d" % k for k in range(W)] + ["ns%d" % k for k in range(W)] + ["isbs", "isra"]
         + ["cm%d" % k for k in range(W)], chain_ext_residuals_prog(minv_cap_rows), len(minv_cap_rows) + 1)
    emit(["vh%d" % k for k in range(4)] + ["nvh%d" % k for k in range(4)], hold_ext_residuals_prog(4), 4)
    emit(["s0", "s1", "s2", "ns0", "ns1", "ns2", "w_next",
          "is_range", "is_range_first", "is_range_step", "is_range_last"], range_ext_residuals_prog(), 5)

    R = 4 * W + len(minv_cap_rows) + 10                          # 62
    assert sp[0] == below + 2 * BLOCK + 2 * R, "assembly left sp=%d, expected %d" % (sp[0], below + 2 * BLOCK + 2 * R)
    return prog + [OP("TOALT")] * (2 * R) + [OP("DROP")] * (2 * BLOCK) + [OP("FROMALT")] * (2 * R)


def _trans_cell_values(cur, nxt, pub_x, w_next, held_cols):
    """The GF(p^2) OOD value of each _TRANS_ASM_OPS cell, as a name->(limb0,limb1) dict (single source for
    assemble_transition_ext_unlock AND the HP9.7 split-part unlocks). cur @z, nxt @z*g, pub_x selectors @z,
    w_next @z*g -- exactly the mapping assemble_transition_unlock used."""
    W = WIDTH
    assert len(held_cols) == 4, "trans_ext cell values expect 4 held cols, got %d" % len(held_cols)
    vals = ([cur["s%d" % k] for k in range(W)]
            + [cur["u2_%d" % k] for k in range(W)] + [cur["u4_%d" % k] for k in range(W)]
            + [cur["u6_%d" % k] for k in range(W)] + [cur[c] for c in held_cols]
            + [nxt["s%d" % k] for k in range(W)] + [nxt[c] for c in held_cols]
            + [pub_x["is_full"], pub_x["is_partial"]] + [pub_x["rc"][k] for k in range(W)]
            + [pub_x["is_block_start"], pub_x["is_reabsorb"]] + [pub_x["chain_minv"][k] for k in range(W)]
            + [pub_x["is_range"], pub_x["is_range_first"], pub_x["is_range_step"], pub_x["is_range_last"]]
            + [w_next])
    assert len(vals) == len(_TRANS_ASM_OPS), "trans cell values arity %d != %d" % (len(vals), len(_TRANS_ASM_OPS))
    return dict(zip(_TRANS_ASM_OPS, vals))


def assemble_transition_ext_unlock(cur, nxt, pub_x, w_next, held_cols):
    """Push-only OOD cells + selectors (GF(p^2)) for assemble_transition_ext_prog, in _TRANS_ASM_OPS order
    (the GF(p^2) mirror of assemble_transition_unlock: cur @z, nxt @z*g, pub_x selectors @z, w_next @z*g)."""
    cv = _trans_cell_values(cur, nxt, pub_x, w_next, held_cols)
    out = []
    for nm in _TRANS_ASM_OPS:
        out += [NUM(cv[nm][0] % P), NUM(cv[nm][1] % P)]
    return out


def run_assemble_transition_ext(m_ext, diag, minv_cap_rows, cur, nxt, pub_x, w_next, held_cols,
                                sbox_looped=False, state_looped=False):
    """Run the GF(p^2) transition-residual assembly on cashvm; ([trans_v...] as (limb0, limb1) tuples, op_cost)."""
    R = 4 * WIDTH + len(minv_cap_rows) + 10
    vm = VM()
    vm.run(_field_prelude() + assemble_transition_ext_unlock(cur, nxt, pub_x, w_next, held_cols)
           + assemble_transition_ext_prog(m_ext, diag, minv_cap_rows, sbox_looped=sbox_looped,
                                          state_looped=state_looped))
    assert len(vm.s) == 2 * R, "assemble_transition_ext left %d items, expected %d" % (len(vm.s), 2 * R)
    d = [decode_num(x) for x in vm.s]
    return [(d[2 * i], d[2 * i + 1]) for i in range(R)], vm.op_cost


def _ext_dup():
    """[.., a0, a1] -> [.., a0, a1, a0, a1] : copy the top GF(p^2) value (2 limbs)."""
    return [NUM(1), OP("PICK"), NUM(1), OP("PICK")]


def ext_zeval_hint_check_prog(log2T, last, hd_vals):
    """HP13.2: validate the GF(p^2) z-EVAL inverse hints comp_at_z_ext consumes, on-chain, fail-closed -- the
    ext counterpart of qf_bound_prog (which does it for the base-field per-query point x). comp_at_z_ext takes
    qf=(z-last)*ZHz_inv (ZHz_inv=1/(z^T-1)) and each bound_invX[r]=(z-Hd[row_r])^-1 as FREE witness; unchecked, a
    prover forges a favourable normalizer -> forged comp(z) -> forged accept (the DEEP-quotient trace term is
    linear in comp(z)). This checks: qf*(z^T - 1) == (z - last)  and  bound_invX[r]*(z - Hd[row_r]) == (1,0), all
    over GF(p^2). z^T is computed by repeated ext-squaring (T a pinned power of 2 -> log2T squarings; ZHz_inv
    reduces to the low-degree z^T-1). Reuses ext_mul/ext_sub/ext_inv_check (HP13.1, DRY). NET-0, PICK-based:
    the stack [z0,z1, qf0,qf1, binvX_0(2)..binvX_{m-1}(2)] (m=len(hd_vals)) is left UNCHANGED, so it slots in
    front of comp_at_z_ext's existing use of qf/bound_invX (nothing recomputed, only forced to the unique value).
    A forged qf or bound_invX fails a NUMEQUALVERIFY (fail-closed). Field prelude installed by the caller."""
    m = len(hd_vals)
    total = 4 + 2 * m
    prog = []
    sp = [total]

    def copy(abs_pos):
        prog.extend([NUM(sp[0] - 1 - abs_pos), OP("PICK")]); sp[0] += 1

    # transition: qf*(z^T - 1) == (z - last)
    copy(0); copy(1)                                            # z on top
    for _ in range(log2T):                                     # z -> z^2 -> ... -> z^T
        prog.extend(_ext_dup()); sp[0] += 2
        prog.extend(ext_mul_stack_prog()); sp[0] -= 2          # square: dup(+2) then mul(4->2)
    prog.extend([NUM(1), NUM(0)]); sp[0] += 2                  # (1,0)
    prog.extend(ext_sub_stack_prog()); sp[0] -= 2             # z^T - (1,0) = Z_H(z)
    copy(2); copy(3)                                           # qf -> [.., ZH, qf]
    prog.extend(ext_mul_stack_prog()); sp[0] -= 2            # qf*Z_H(z) = p
    copy(0); copy(1)                                           # z -> [.., p, z]
    prog.extend([NUM(last % P), NUM(0)]); sp[0] += 2          # (last,0)
    prog.extend(ext_sub_stack_prog()); sp[0] -= 2            # z - (last,0) = (z-last)
    prog.extend(ext_sub_stack_prog()); sp[0] -= 2            # p - (z-last) = diff
    prog.extend([NUM(0), OP("NUMEQUALVERIFY"), NUM(0), OP("NUMEQUALVERIFY")]); sp[0] -= 2   # diff == (0,0)
    # boundary: each bound_invX[r]*(z - Hd[row_r]) == (1,0)
    for r, hd in enumerate(hd_vals):
        copy(4 + 2 * r); copy(4 + 2 * r + 1)                  # bound_invX[r]
        copy(0); copy(1)                                      # z -> [.., binvX, z]
        prog.extend([NUM(hd % P), NUM(0)]); sp[0] += 2        # (Hd[row_r], 0)
        prog.extend(ext_sub_stack_prog()); sp[0] -= 2         # z - (Hd,0) = d
        prog.extend(ext_inv_check_prog()); sp[0] -= 4         # bound_invX[r]*d == (1,0)
    assert sp[0] == total, "ext_zeval_hint_check not net-0: sp=%d total=%d" % (sp[0], total)
    return prog


def run_zeval_hint_check(log2T, last, hd_vals, z, qf, bound_invX):
    """Run ext_zeval_hint_check_prog standalone on cashvm; (True, op_cost) if every GF(p^2) z-eval hint validates
    (clean empty stack after dropping the inputs), (False, 0) on a fail-closed reject (a forged qf/bound_invX)."""
    vm = VM()
    total = 4 + 2 * len(hd_vals)
    unlock = [NUM(z[0] % P), NUM(z[1] % P), NUM(qf[0] % P), NUM(qf[1] % P)]
    for b in bound_invX:
        unlock += [NUM(b[0] % P), NUM(b[1] % P)]
    try:
        vm.run(_field_prelude() + unlock + ext_zeval_hint_check_prog(log2T, last, hd_vals)
               + [OP("DROP")] * total)
        return len(vm.s) == 0, vm.op_cost
    except VMError:
        return False, 0


def comp_at_z_ext_prog(m_ext, diag, minv_cap_rows, minv0_row, n_out, range_spec, root, nf, cm_out, n_t, n_b,
                       sbox_looped=False, state_looped=False, compose_looped=False):
    """HP9.5: the FULL AIR-eval comp(z) on-chain over GF(p^2) -- the deploy realization of _compose_at_ext.
    Unlock (bottom->top): [alpha_T(n_t), qf, bound_invX(n_b), alpha_B(n_b)] (compose params) ; [boundary OOD:
    s0..s{W-1}, vh0..vh3 (W+4)] ; [transition OOD: _TRANS_ASM_OPS (101)]. Stages: (1) assemble_transition_ext
    (reads the transition OOD on top) -> n_t trans_v ; (2) boundary_ext on the PICK-copied boundary OOD ->
    n_b bound_v ; (3) interleave trans_v+alpha_T, qf, bound_v+bound_invX+alpha_B into compose_ext -> comp(z) ;
    (4) drop the working blocks, leave [comp0, comp1]. qf=zl*ZHz_inv and bound_invX=(z-H[row])^-1 are the DEEP
    hints; all pinned public constants baked. Cross-checked ==_compose_at_ext end-to-end (HP15.11)."""
    W = WIDTH
    NCP = n_t + 1 + 2 * n_b                       # compose params: alpha_T(n_t), qf, bound_invX(n_b), alpha_B(n_b)
    NBND = W + 4                                   # boundary OOD: s0..s{W-1}, vh0..vh3
    prog = []

    below_t = 2 * (NCP + NBND)                     # (1) transition assembly (transition OOD on top)
    prog += assemble_transition_ext_prog(m_ext, diag, minv_cap_rows, below=below_t,
                                         sbox_looped=sbox_looped, state_looped=state_looped)
    sp = [below_t + 2 * n_t]                        # trans_v on top

    def pk_at(ext_idx):                            # copy the ext-value at absolute ext-index (from bottom) to top
        prog.extend([NUM(sp[0] - 1 - 2 * ext_idx), OP("PICK")]); sp[0] += 1
        prog.extend([NUM(sp[0] - 1 - (2 * ext_idx + 1)), OP("PICK")]); sp[0] += 1

    for k in range(W):                             # (2) boundary_ext on PICK-copied boundary OOD (s0..s{W-1}, vh)
        pk_at(NCP + k)
    for i in range(4):
        pk_at(NCP + W + i)
    prog += boundary_ext_residuals_prog(minv0_row, n_out, range_spec, root, nf, cm_out)
    sp[0] = below_t + 2 * n_t + 2 * n_b            # bound_v on top (its 16-ext operand copy consumed)

    tv0 = NCP + NBND                               # trans_v base ext-index ; bound_v base ext-index
    bv0 = NCP + NBND + n_t
    for j in range(n_t):                           # (3) interleave into compose_ext layout, compose
        pk_at(tv0 + j); pk_at(j)                   # tv_j, ta_j=alpha_T[j]
    pk_at(n_t)                                     # qf
    for b in range(n_b):
        pk_at(bv0 + b); pk_at(n_t + 1 + b); pk_at(n_t + 1 + n_b + b)   # bv_b, bix_b, ba_b
    prog += compose_ext_prog(n_t, n_b, compose_looped=compose_looped)   # consumes the interleaved copies, leaves comp

    drop_n = 2 * (NCP + NBND + n_t + n_b)          # (4) drop CP + BND + trans_v + bound_v, keep comp
    return prog + [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * drop_n + [OP("FROMALT"), OP("FROMALT")]


def comp_at_z_ext_unlock(cur, nxt, pub_x, w_next, alpha_T, qf, bound_invX, alpha_B, held_cols):
    """Push-only inputs for comp_at_z_ext_prog, bottom->top: alpha_T, qf, bound_invX, alpha_B, boundary OOD
    (cur.s0..s{W-1}, cur held vh0..vh3), transition OOD (assemble_transition_ext_unlock order)."""
    W = WIDTH
    out = []
    for v in list(alpha_T) + [qf] + list(bound_invX) + list(alpha_B):
        out += [NUM(v[0] % P), NUM(v[1] % P)]
    for v in [cur["s%d" % k] for k in range(W)] + [cur[c] for c in held_cols]:
        out += [NUM(v[0] % P), NUM(v[1] % P)]
    out += assemble_transition_ext_unlock(cur, nxt, pub_x, w_next, held_cols)
    return out


def run_comp_at_z_ext(m_ext, diag, minv_cap_rows, minv0_row, n_out, range_spec, root, nf, cm_out,
                      cur, nxt, pub_x, w_next, alpha_T, qf, bound_invX, alpha_B, held_cols,
                      sbox_looped=False, state_looped=False, compose_looped=False):
    """Run the full GF(p^2) comp(z) assembly on cashvm; (comp as (limb0, limb1), op_cost)."""
    n_t = 4 * WIDTH + len(minv_cap_rows) + 10
    n_b = _n_boundary_residuals(n_out, range_spec)
    vm = VM()
    vm.run(_field_prelude()
           + comp_at_z_ext_unlock(cur, nxt, pub_x, w_next, alpha_T, qf, bound_invX, alpha_B, held_cols)
           + comp_at_z_ext_prog(m_ext, diag, minv_cap_rows, minv0_row, n_out, range_spec, root, nf, cm_out, n_t, n_b,
                                sbox_looped=sbox_looped, state_looped=state_looped, compose_looped=compose_looped))
    assert len(vm.s) == 2, "comp_at_z_ext left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


def _token_nbytes(tok):
    """BCH-script byte size of one cashvm token (the token->byte model, NOT libauth-measured; real bytes
    = HP16). PUSHN: OP_0/OP_1..16/OP_1NEGATE = 1B, else 1 length byte + encode_num bytes (PUSHDATA1 beyond
    75). PUSH: 1 length byte + data (PUSHDATA1 beyond 75, PUSHDATA2 beyond 255). DEFINE: OP_DEFINE + the
    inline body. Every other opcode is 1 byte."""
    kind = tok[0]
    if kind == "PUSHN":
        i = tok[1]
        if i == 0 or i == -1 or 1 <= i <= 16:
            return 1
        L = len(encode_num(i))
        return 1 + L if L <= 75 else 2 + L
    if kind == "PUSH":
        L = len(tok[1])
        if L == 0:
            return 1
        if L <= 75:
            return 1 + L
        if L <= 255:
            return 2 + L
        return 3 + L
    if kind == "DEFINE":
        return 1 + _prog_nbytes(tok[1].tokens)
    return 1


def _prog_nbytes(tokens):
    """Token->byte size of a cashvm program (the make-or-break <=10000B/input + <100KB/tx metric, in the
    token->byte model; real libauth bytes are HP16)."""
    return sum(_token_nbytes(t) for t in tokens)


# ---- HP9.7: split comp(z) (~27KB) into standalone <=10000B parts ----------------------------------------
# comp(z) = qf * sum_j(trans_v_j*alpha_T_j) + sum_b(bound_v_b*bound_invX_b*alpha_B_b) is a sum of independent
# GF(p^2) multiply-accumulate terms. The 62 transition terms are produced by atomic "jobs" (12 S-box lanes,
# 12 state lanes, chain, hold, range -- in the assemble_transition_ext order); a split part owns a CONTIGUOUS
# slice of jobs, computes their trans_v (via the tested GF(p^2) leaf progs), and accumulates them (MAC body
# 0x26) into a running transition accumulator acc_T carried between parts. A final part multiplies acc_T by qf
# and adds the boundary accumulator (MAC body 0x27) -> comp(z). Job (not family) granularity lets the big
# state family split by lane so every part fits <=10000B. Every part is a standalone input, value-identical to
# comp_at_z_ext_prog (HP9.5). The carry single-source (OP_INPUTBYTECODE), part-presence binding, and comp(z)
# aggregation are HP9.8/9.9/9.10.


def _trans_family_cells(fam):
    """The _TRANS_ASM_OPS OOD cell names a transition family's on-chain compute reads (the derived
    isr/y_full/ef are built by the part, not read). Mirrors the emit() sources in
    assemble_transition_ext_prog (sbox also reads isp to derive the lane-0 gate isr = isf + isp)."""
    W = WIDTH
    if fam == "sbox":
        return (["s%d" % k for k in range(W)] + ["u2_%d" % k for k in range(W)]
                + ["u4_%d" % k for k in range(W)] + ["u6_%d" % k for k in range(W)]
                + ["rc%d" % k for k in range(W)] + ["isf", "isp"])
    if fam == "state":
        return (["s%d" % k for k in range(W)] + ["u6_%d" % k for k in range(W)]
                + ["rc%d" % k for k in range(W)] + ["ns%d" % k for k in range(W)] + ["isf", "isp"])
    if fam == "chain":
        return (["s%d" % k for k in range(W)] + ["ns%d" % k for k in range(W)]
                + ["isbs", "isra"] + ["cm%d" % k for k in range(W)])
    if fam == "hold":
        return ["vh%d" % k for k in range(4)] + ["nvh%d" % k for k in range(4)]
    if fam == "range":
        return ["s0", "s1", "s2", "ns0", "ns1", "ns2", "w_next",
                "is_range", "is_range_first", "is_range_step", "is_range_last"]
    raise ValueError("unknown transition family %r" % fam)


def _trans_jobs(minv_cap_rows):
    """The ordered atomic residual-producing transition units (== assemble_transition_ext emit order): the 12
    S-box lanes (3 residuals each), the 12 state lanes (1 each), then chain (cap+1), hold (4), range (5). A
    split part owns a CONTIGUOUS slice of this list, so its alpha_T offset is well-defined and the state
    family (too big for one <=10000B input) can be split by lane."""
    return ([("sbox", k) for k in range(WIDTH)] + [("state", j) for j in range(WIDTH)]
            + [("chain", None), ("hold", None), ("range", None)])


def _job_nres(job, minv_cap_rows):
    """Residual count of one transition job (== its emit r_out)."""
    fam = job[0]
    if fam == "chain":
        return len(minv_cap_rows) + 1
    return {"sbox": 3, "state": 1, "hold": 4, "range": 5}[fam]


def _job_parts_label(jobs):
    """Short human label for a job slice (family + lane range), e.g. 'sbox0-11', 'state6-11', 'chain+hold+range'."""
    parts, i = [], 0
    while i < len(jobs):
        f = jobs[i][0]
        j = i
        while j < len(jobs) and jobs[j][0] == f:
            j += 1
        lanes = [jobs[k][1] for k in range(i, j) if jobs[k][1] is not None]
        if not lanes:
            parts.append(f)
        elif len(lanes) == 1:
            parts.append("%s%d" % (f, lanes[0]))
        else:
            parts.append("%s%d-%d" % (f, lanes[0], lanes[-1]))
        i = j
    return "+".join(parts)


def _trans_part_base_ops(jobs):
    """The _TRANS_ASM_OPS OOD cells a part's jobs read (single source for the prog + the unlock). A state lane
    needs all s/rc/u6 (for the shared y_full) + its own ns + isf/isp; an S-box lane needs its s/rc/u2/u4/u6 +
    isf (+ isp for the lane-0 gate isr = isf+isp); chain/hold/range read their whole family cells."""
    W = WIDTH
    need = set()
    for (f, idx) in jobs:
        if f == "sbox":
            need.update(["s%d" % idx, "rc%d" % idx, "u2_%d" % idx, "u4_%d" % idx, "u6_%d" % idx, "isf"])
            if idx == 0:
                need.add("isp")
        elif f == "state":
            need.update(["s%d" % k for k in range(W)] + ["rc%d" % k for k in range(W)]
                        + ["u6_%d" % k for k in range(W)] + ["ns%d" % idx, "isf", "isp"])
        else:
            need.update(_trans_family_cells(f))
    return [nm for nm in _TRANS_ASM_OPS if nm in need]


def comp_split_trans_part_prog(jobs, part_n_res, m_ext, diag, minv_cap_rows, sbox_looped=False, state_looped=False,
                               carry_bound=False, mac_lazy=False):
    """HP9.7: one standalone <=10000B transition split-part. `jobs` is a CONTIGUOUS slice of _trans_jobs; the
    part computes those jobs' trans_v (via the tested GF(p^2) leaf progs) and multiply-accumulates them (0x26)
    into the carried accumulator: acc_out = acc_in + sum_i(trans_v_i * alpha_T[i]). Unlock (bottom->top):
    acc_in (2 limbs), the part's alpha_T slice (part_n_res ext), the OOD cells the jobs read (_TRANS_ASM_OPS
    subset). Leaves [acc_out0, acc_out1]; drops the rest. Same trans_v arithmetic + alphas as
    assemble_transition_ext + compose_ext -> the parts' acc chain to comp_at_z_ext's transition term (HP9.5);
    split only for the 10000B consensus input cap. isr is derived only if the part owns S-box lane 0; y_full
    (all W) + ef (only this part's state lanes) only if the part owns a state lane.

    HP9.8 carry_bound=True: the acc carry is SINGLE-SOURCED across the input boundary. Unlock instead is
    [carry_out_preimage(16B)@0, carry_in_preimage(16B)@1, alpha, OOD] (the two 16-byte blobs occupy the same
    two stack slots that acc_in's 2 limbs did, so the compute is byte-for-byte unchanged). acc_in is split from
    carry_in_preimage (the prior part's carry_out, read via OP_INPUTBYTECODE in the deploy) instead of a free
    witness; the computed acc_out is BOUND to carry_out_preimage@0 (this part's exposed output) via
    _comp_producer_bind_prog (split_cells(2) + NUMEQUALVERIFY each limb), fail-closed -- a prover cannot expose
    a carry-out != its computation (R8-B1). Leaves [1] on accept.

    HP11.3 mac_lazy=True: MAC the trans_v via the RAW lazy body (0x2a) -- accumulate the GF(p^2) products unreduced,
    reduce acc0/acc1 mod p ONCE after the loop (== _compose_mac_t_body summed, mod p; ZERO soundness impact, validated
    ==eager). Default False = byte-identical (the DEFINE'd body just changes; the per-term INVOKE count is the same, so
    the redeem length is unchanged). The value is the ~4.3x op-cost drop, which lets an OP-COST-BOUND part (e.g. the
    sbox part) shrink its op-budget pad -> fewer deploy bytes (byte-BOUND parts are unaffected -> they need the token
    loop instead)."""
    W = WIDTH
    sbox_lanes = [k for (f, k) in jobs if f == "sbox"]
    state_lanes = [j for (f, j) in jobs if f == "state"]
    has_state = len(state_lanes) > 0
    need_isr = 0 in sbox_lanes
    base_ops = _trans_part_base_ops(jobs)
    order = list(base_ops)                                        # + on-chain-derived cells (built by the part)
    if need_isr:
        order.append("isr")                                       # isr = isf + isp (lane-0 S-box gate)
    if has_state:
        order += ["yf%d" % k for k in range(W)]                   # y_full[k] = u6_k*(s_k+rc_k) (all, for ef)
        if state_looped:                                          # M4-block ef: all 12 mm + 4 block-sums, then this part's ef
            order += (["mm%d" % k for k in range(W)] + ["stor%d" % l for l in range(4)]
                      + ["ef%d" % j for j in state_lanes])
    e0 = 1 + part_n_res                                           # ext-index of the OOD block (acc_in + alpha below)
    aidx = {nm: e0 + i for i, nm in enumerate(order)}
    prog = []
    if sbox_looped and sbox_lanes:
        prog += stagea_sbox_ext_define()
    if state_looped and has_state:
        prog += stagea_state_ext_define()
    mac_fid = _COMPOSE_MAC_T_LAZY_FID if mac_lazy else _COMPOSE_MAC_T_FID   # HP11.3: raw (0x2a) vs reduced (0x26) MAC
    prog += [PUSH(mac_fid), DEFINE(_compose_mac_t_lazy_body() if mac_lazy else _compose_mac_t_body())]
    sp = [2 * (e0 + len(base_ops))]                               # limbs: acc_in + alpha + base OOD block

    def pk_at(ext_idx):
        prog.extend([NUM(sp[0] - 1 - 2 * ext_idx), OP("PICK")]); sp[0] += 1
        prog.extend([NUM(sp[0] - 1 - (2 * ext_idx + 1)), OP("PICK")]); sp[0] += 1

    def eadd(): prog.extend(ext_add_stack_prog()); sp[0] -= 2
    def emul(): prog.extend(ext_mul_stack_prog()); sp[0] -= 2

    def escalar(s, name):                                        # push base s, pick ext block[name], scalar
        prog.append(NUM(s % P)); sp[0] += 1
        ei = aidx[name]
        prog.extend([NUM(sp[0] - 1 - 2 * ei), OP("PICK")]); sp[0] += 1
        prog.extend([NUM(sp[0] - 1 - (2 * ei + 1)), OP("PICK")]); sp[0] += 1
        prog.extend(ext_scalar_stack_prog()); sp[0] -= 1

    if need_isr:                                                 # --- build the derived cells the jobs need ---
        pk_at(aidx["isf"]); pk_at(aidx["isp"]); eadd()          # isr
    if has_state:
        for k in range(W):
            pk_at(aidx["s%d" % k]); pk_at(aidx["rc%d" % k]); eadd(); pk_at(aidx["u6_%d" % k]); emul()   # y_full[k]
        if state_looped:                                         # ef = M_EXT.y_full via the M4-block factorization
            for blk in range(0, W, 4):                           # M4 per 4-block: mm[blk+r] = sum_k M4[r][k]*yf[blk+k]
                for r in range(4):
                    escalar(_M4_EXT[r][0], "yf%d" % blk)
                    for kk in range(1, 4):
                        escalar(_M4_EXT[r][kk], "yf%d" % (blk + kk)); eadd()
            for l in range(4):                                   # stored[l] = mm[l] + mm[4+l] + mm[8+l] (block sums)
                pk_at(aidx["mm%d" % l]); pk_at(aidx["mm%d" % (4 + l)]); eadd()
                pk_at(aidx["mm%d" % (8 + l)]); eadd()
            for j in state_lanes:                                # ef[j] = mm[j] + stored[j%4] (== M_EXT[j].y_full)
                pk_at(aidx["mm%d" % j]); pk_at(aidx["stor%d" % (j % 4)]); eadd()
    assert sp[0] == 2 * (e0 + len(order)), "split trans block sp=%d, expected %d" % (sp[0], 2 * (e0 + len(order)))

    def emit(src_names, leaf_prog, r_out):                       # --- compute the jobs' trans_v ---
        b = sp[0]
        for nm in src_names:
            pk_at(aidx[nm])
        prog.extend(leaf_prog)
        sp[0] = b + 2 * r_out

    _sbox_body = ([PUSH(_SBOX_EXT_FID), OP("INVOKE")] if (sbox_looped and sbox_lanes)
                  else sbox_lane_ext_residuals_prog())
    for (f, idx) in jobs:
        if f == "sbox":
            gate = "isr" if idx == 0 else "isf"
            emit(["s%d" % idx, "rc%d" % idx, "u2_%d" % idx, "u4_%d" % idx, "u6_%d" % idx, gate], list(_sbox_body), 3)
        elif f == "state":
            if state_looped:
                b = sp[0]
                pk_at(aidx["ef%d" % idx]); pk_at(aidx["yf0"])
                for k in range(1, W):
                    pk_at(aidx["s%d" % k])
                prog.extend([NUM(diag[idx] % P), NUM(0)]); sp[0] += 2
                pk_at(aidx["ns%d" % idx]); pk_at(aidx["isf"]); pk_at(aidx["isp"])
                pk_at(aidx["yf0"] if idx == 0 else aidx["s%d" % idx])
                prog.extend([PUSH(_STATE_EXT_FID), OP("INVOKE")]); sp[0] = b + 2
            else:
                yf = ["yf%d" % k for k in range(W)]
                yp = ["yf0" if k == 0 else "s%d" % k for k in range(W)]
                emit(yf + yp + ["ns%d" % idx, "isf", "isp"], state_lane_ext_residual_prog(m_ext[idx], diag[idx], idx), 1)
        elif f == "chain":
            emit(["s%d" % k for k in range(W)] + ["ns%d" % k for k in range(W)] + ["isbs", "isra"]
                 + ["cm%d" % k for k in range(W)], chain_ext_residuals_prog(minv_cap_rows), len(minv_cap_rows) + 1)
        elif f == "hold":
            emit(["vh%d" % k for k in range(4)] + ["nvh%d" % k for k in range(4)], hold_ext_residuals_prog(4), 4)
        elif f == "range":
            emit(["s0", "s1", "s2", "ns0", "ns1", "ns2", "w_next",
                  "is_range", "is_range_first", "is_range_step", "is_range_last"], range_ext_residuals_prog(), 5)
    assert sp[0] == 2 * (e0 + len(order) + part_n_res), "split trans compute sp=%d, exp %d" % (sp[0], 2 * (e0 + len(order) + part_n_res))

    tv0 = e0 + len(order)                                        # --- MAC the computed trans_v into acc_in ---
    if carry_bound:                                             # acc_in = split(carry_in_preimage @ stack item 1)
        prog.extend([NUM(sp[0] - 1 - 1), OP("PICK")]); sp[0] += 1
        prog.extend(split_cells_prog(2)); sp[0] += 1            # blob -> [acc_in0, acc_in1] (net +1)
    else:
        pk_at(0)                                                # acc = acc_in (raw limbs @ ext 0)
    for i in range(part_n_res):
        pk_at(tv0 + i)                                           # trans_v_i
        pk_at(1 + i)                                             # alpha_T[i] (unlock slot 1+i)
        prog.extend([PUSH(mac_fid), OP("INVOKE")]); sp[0] -= 4
    if mac_lazy:                                               # HP11.3: reduce the raw accumulator mod p ONCE (sp-neutral)
        prog += [OP("SWAP")] + NORM_TAIL + [OP("SWAP")] + NORM_TAIL
    total_below = e0 + len(order) + part_n_res                  # acc_in + alpha + block + trans_v (ext)
    assert sp[0] == 2 * total_below + 2, "split trans MAC sp=%d, expected %d" % (sp[0], 2 * total_below + 2)
    if carry_bound:                                            # bind computed acc_out == carry_out_preimage @ 0
        prog += _comp_producer_bind_prog(2 * total_below)      # -> [witness(2*total_below), 1]
        return prog + [OP("TOALT")] + [OP("DROP")] * (2 * total_below) + [OP("FROMALT")]   # -> [1]
    return prog + [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * (2 * total_below) + [OP("FROMALT"), OP("FROMALT")]


def _acc_preimage(acc):
    """HP9.8: the 16-byte cross-input carry commitment for a split transition accumulator = enc8(acc0)+enc8(acc1)
    (two 8-byte LE limbs). The producing part BINDS its computed acc_out to this; the next part reads it via
    OP_INPUTBYTECODE and split_cells(2)s it into its carry-in. Mirrors fri_carry_preimage (3-limb)."""
    return enc8(acc[0] % P) + enc8(acc[1] % P)


def comp_split_trans_part_unlock(jobs, acc_in, alpha_slice, cur, nxt, pub_x, w_next, held_cols,
                                 carry_bound=False, acc_out=None):
    """Push-only inputs for comp_split_trans_part_prog, bottom->top: acc_in, alpha_slice (part_n_res ext), the
    jobs' OOD cells (_TRANS_ASM_OPS subset -- single-sourced via _trans_cell_values). HP9.8 carry_bound=True:
    instead pushes [carry_out_preimage(acc_out)@0, carry_in_preimage(acc_in)@1, alpha, OOD] -- the two 16-byte
    blobs replace acc_in's 2 limbs at the same slots (acc_out is this part's computed output, required)."""
    base_ops = _trans_part_base_ops(jobs)
    cv = _trans_cell_values(cur, nxt, pub_x, w_next, held_cols)
    cells = list(alpha_slice) + [cv[nm] for nm in base_ops]
    if carry_bound:
        assert acc_out is not None, "carry_bound unlock needs the computed acc_out"
        out = [PUSH(_acc_preimage(acc_out)), PUSH(_acc_preimage(acc_in))]
    else:
        out = [NUM(acc_in[0] % P), NUM(acc_in[1] % P)]
    for v in cells:
        out += [NUM(v[0] % P), NUM(v[1] % P)]
    return out


def comp_split_final_part_prog(minv0_row, n_out, range_spec, root, nf, cm_out, n_b,
                               carry_bound=False, comp_bound=False):
    """HP9.7: the final standalone <=10000B split-part. Reads the carried full transition accumulator acc_T,
    forms comp_transition = acc_T*qf, computes the boundary bound_v (boundary_ext_residuals_prog), MACs the
    boundary terms (0x27) into acc_B, and leaves comp = comp_transition + acc_B = comp(z). Unlock
    (bottom->top): acc_T (2 limbs), qf (1 ext), bound_invX (n_b ext), alpha_B (n_b ext), boundary OOD
    (s0..s{W-1}, vh0..vh3). Value-identical to comp_at_z_ext's boundary+compose tail (HP9.5).

    HP9.8 carry_bound=True: acc_T is split from a carry_in_preimage(16B) pushed on TOP of the unlock (the last
    transition part's carry-out, read via OP_INPUTBYTECODE) instead of 2 raw limbs at the bottom, so it is
    single-sourced (R8-B1); the operands (qf, bound_invX, alpha_B, s, vh) shift down one ext slot. Leaves comp(z).

    HP9.10 comp_bound=True (requires carry_bound; the deploy form): the two 16-byte blobs
    [comp_preimage@0, carry_in_preimage@1] occupy ext 0 (aligned, like a transition part); acc_T is split from
    carry_in@1; the computed comp(z) is BOUND to comp_preimage@0 via _comp_producer_bind_prog (split_cells(2) +
    NUMEQUALVERIFY, fail-closed) -- the AIR-eval-once comp(z) is thus bound to the committed composition
    (comp==comp_root), so a prover cannot output a comp != the FS-committed value. Leaves [1] on accept.
    (comp_preimage's single-source from the FS blob comp_root is HP11/HP12.)"""
    W = WIDTH
    if comp_bound and not carry_bound:
        raise ValueError("comp_bound requires carry_bound (the deploy final part reads acc_T via OP_INPUTBYTECODE)")
    if comp_bound:                                             # [comp_preimage@0, carry_in@1] = ext 0; operands @ ext 1..
        TU = 2 + 2 * n_b + W + 4                                 # blob-ext(1) + qf + bix + ba + s + vh
        e_qf, e_bix, e_ba, e_s, e_vh = 1, 2, 2 + n_b, 2 + 2 * n_b, 2 + 2 * n_b + W
        sp = [2 * TU]
    elif carry_bound:                                         # operands @ ext 0..; carry_in_preimage on TOP
        TU = 1 + 2 * n_b + W + 4
        e_qf, e_bix, e_ba, e_s, e_vh = 0, 1, 1 + n_b, 1 + 2 * n_b, 1 + 2 * n_b + W
        sp = [2 * TU + 1]
    else:                                                     # acc_T @ ext 0 (raw); operands @ ext 1..
        TU = 2 + 2 * n_b + W + 4
        e_qf, e_bix, e_ba, e_s, e_vh = 1, 2, 2 + n_b, 2 + 2 * n_b, 2 + 2 * n_b + W
        sp = [2 * TU]
    prog = [PUSH(_COMPOSE_MAC_B_FID), DEFINE(_compose_mac_b_body())]   # boundary MAC body 0x27

    def pk_at(ext_idx):
        prog.extend([NUM(sp[0] - 1 - 2 * ext_idx), OP("PICK")]); sp[0] += 1
        prog.extend([NUM(sp[0] - 1 - (2 * ext_idx + 1)), OP("PICK")]); sp[0] += 1

    if comp_bound:                                             # acc_T = split(carry_in_preimage @ item 1)
        prog.extend([NUM(sp[0] - 1 - 1), OP("PICK")]); sp[0] += 1
        prog.extend(split_cells_prog(2)); sp[0] += 1           # -> acc_T on top
        pk_at(e_qf); prog.extend(ext_mul_stack_prog()); sp[0] -= 2             # comp_transition = acc_T*qf (ext TU)
    elif carry_bound:                                         # acc_T = split(carry_in_preimage @ top)
        prog.extend(split_cells_prog(2)); sp[0] += 1           # blob(1) -> 2 limbs (net +1); acc_T on top
        pk_at(e_qf); prog.extend(ext_mul_stack_prog()); sp[0] -= 2             # comp_transition = acc_T*qf (ext TU)
    else:
        pk_at(0); pk_at(e_qf); prog.extend(ext_mul_stack_prog()); sp[0] -= 2   # comp_transition = acc_T*qf (ext TU)
    b = sp[0]
    for k in range(W):
        pk_at(e_s + k)
    for i in range(4):
        pk_at(e_vh + i)
    prog += boundary_ext_residuals_prog(minv0_row, n_out, range_spec, root, nf, cm_out)
    sp[0] = b + 2 * n_b                                          # bound_v (n_b ext) on top (ext TU+1..TU+n_b)
    prog.extend([NUM(0), NUM(0)]); sp[0] += 2                    # acc_B = 0 (ext TU+1+n_b)
    for bi in range(n_b):
        pk_at(TU + 1 + bi)                                      # bound_v_bi
        pk_at(e_bix + bi)                                       # bound_invX_bi
        pk_at(e_ba + bi)                                        # alpha_B_bi
        prog.extend([PUSH(_COMPOSE_MAC_B_FID), OP("INVOKE")]); sp[0] -= 6
    pk_at(TU)                                                    # comp_transition copy on top
    prog.extend(ext_add_stack_prog()); sp[0] -= 2               # comp = acc_B + comp_transition (comp(z), on top)
    total_below = TU + 1 + n_b                                   # unlock + comp_transition + bound_v (ext)
    assert sp[0] == 2 * total_below + 2, "split final sp=%d, expected %d" % (sp[0], 2 * total_below + 2)
    if comp_bound:                                             # bind computed comp(z) == comp_preimage @ item 0
        prog += _comp_producer_bind_prog(2 * total_below)      # -> [witness(2*total_below), 1]
        return prog + [OP("TOALT")] + [OP("DROP")] * (2 * total_below) + [OP("FROMALT")]   # -> [1]
    return prog + [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * (2 * total_below) + [OP("FROMALT"), OP("FROMALT")]


def comp_split_final_part_unlock(acc_T, qf, bound_invX, alpha_B, cur, held_cols, n_b,
                                 carry_bound=False, comp_bound=False, comp=None):
    """Push-only inputs for comp_split_final_part_prog, bottom->top: acc_T, qf, bound_invX(n_b), alpha_B(n_b),
    cur.s0..s{W-1}, cur held vh0..vh3. HP9.8 carry_bound=True: acc_T is dropped from the bottom and its
    carry_in_preimage(16B) is pushed on TOP instead. HP9.10 comp_bound=True (needs the computed comp): the
    unlock is [comp_preimage(comp)@0, carry_in_preimage(acc_T)@1, qf, bound_invX, alpha_B, s, vh] -- both 16-byte
    blobs at the bottom (ext 0). _acc_preimage is the generic enc8(v0)+enc8(v1) encoder (reused for comp)."""
    W = WIDTH
    assert len(bound_invX) == n_b and len(alpha_B) == n_b, "final part arity mismatch"
    assert len(held_cols) == 4, "final part expects 4 held cols"
    operands = ([qf] + list(bound_invX) + list(alpha_B)
                + [cur["s%d" % k] for k in range(W)] + [cur[c] for c in held_cols])
    if comp_bound:
        assert comp is not None, "comp_bound unlock needs the computed comp(z)"
        out = [PUSH(_acc_preimage(comp)), PUSH(_acc_preimage(acc_T))]   # comp_preimage@0, carry_in_preimage@1
        for v in operands:
            out += [NUM(v[0] % P), NUM(v[1] % P)]
        return out
    seq = operands if carry_bound else ([acc_T] + operands)
    out = []
    for v in seq:
        out += [NUM(v[0] % P), NUM(v[1] % P)]
    if carry_bound:
        out += [PUSH(_acc_preimage(acc_T))]                    # carry_in_preimage on top (read via OP_INPUTBYTECODE)
    return out


def run_comp_split(job_parts, m_ext, diag, minv_cap_rows, minv0_row, n_out, range_spec, root, nf, cm_out,
                   cur, nxt, pub_x, w_next, alpha_T, qf, bound_invX, alpha_B, held_cols,
                   sbox_looped=False, state_looped=False, carry_bound=False, comp_bound=False, mac_lazy=False):
    """Run the split comp(z) as a pipeline of standalone parts on cashvm; (comp as (limb0,limb1), stats) with
    stats = [(label, op_cost, n_bytes)] per part. `job_parts` is a list of contiguous slices of
    _trans_jobs(minv_cap_rows) covering it in order (each slice = one transition part), then the boundary+combine
    final part. The parts' acc_T carry chains to comp_at_z_ext's transition term -> comp == run_comp_at_z_ext.

    HP9.8 carry_bound=True: run the DEPLOY carry-single-source form -- each transition part exposes its acc_out
    as a carry_out_preimage and self-binds its computation to it (fail-closed), reads acc_in from the prior
    part's preimage; the final part reads the last acc_T from a preimage. Each transition part is run twice (once
    unbound to obtain the acc value that forms its exposed preimage, once bound to verify it accepts [1]); the
    stats/bytes reported are the BOUND form. comp is still == run_comp_at_z_ext."""
    flat = [j for grp in job_parts for j in grp]
    assert flat == _trans_jobs(minv_cap_rows), "job_parts must cover _trans_jobs in order"
    n_b = _n_boundary_residuals(n_out, range_spec)
    stats = []
    acc = (0, 0)
    off = 0
    for grp in job_parts:
        pnr = sum(_job_nres(j, minv_cap_rows) for j in grp)
        prog = comp_split_trans_part_prog(grp, pnr, m_ext, diag, minv_cap_rows, sbox_looped, state_looped,
                                          mac_lazy=mac_lazy)
        unlock = comp_split_trans_part_unlock(grp, acc, alpha_T[off:off + pnr], cur, nxt, pub_x, w_next, held_cols)
        vm = VM(); vm.run(_field_prelude() + unlock + prog)
        assert len(vm.s) == 2, "split trans part %s left %d items" % (_job_parts_label(grp), len(vm.s))
        acc_out = (decode_num(vm.s[-2]), decode_num(vm.s[-1]))
        if carry_bound:                                        # run the DEPLOY bound form; verify accept [1]
            bprog = comp_split_trans_part_prog(grp, pnr, m_ext, diag, minv_cap_rows, sbox_looped, state_looped,
                                               carry_bound=True, mac_lazy=mac_lazy)
            bunlock = comp_split_trans_part_unlock(grp, acc, alpha_T[off:off + pnr], cur, nxt, pub_x, w_next,
                                                   held_cols, carry_bound=True, acc_out=acc_out)
            bvm = VM(); bvm.run(_field_prelude() + bunlock + bprog)
            assert len(bvm.s) == 1 and decode_num(bvm.s[-1]) != 0, \
                "carry-bound trans part %s did not accept" % _job_parts_label(grp)
            stats.append((_job_parts_label(grp), bvm.op_cost, _prog_nbytes(bunlock + bprog)))
        else:
            stats.append((_job_parts_label(grp), vm.op_cost, _prog_nbytes(unlock + prog)))
        acc = acc_out
        off += pnr
    fprog = comp_split_final_part_prog(minv0_row, n_out, range_spec, root, nf, cm_out, n_b, carry_bound=carry_bound)
    funlock = comp_split_final_part_unlock(acc, qf, bound_invX, alpha_B, cur, held_cols, n_b, carry_bound=carry_bound)
    vm = VM(); vm.run(_field_prelude() + funlock + fprog)
    assert len(vm.s) == 2, "split final part left %d items" % len(vm.s)
    comp = (decode_num(vm.s[-2]), decode_num(vm.s[-1]))
    if comp_bound:                                             # HP9.10: run the DEPLOY comp-bound final; verify accept [1]
        cfprog = comp_split_final_part_prog(minv0_row, n_out, range_spec, root, nf, cm_out, n_b,
                                            carry_bound=True, comp_bound=True)
        cfunlock = comp_split_final_part_unlock(acc, qf, bound_invX, alpha_B, cur, held_cols, n_b,
                                                carry_bound=True, comp_bound=True, comp=comp)
        cvm = VM(); cvm.run(_field_prelude() + cfunlock + cfprog)
        assert len(cvm.s) == 1 and decode_num(cvm.s[-1]) != 0, "comp-bound final part did not accept"
        stats.append(("final", cvm.op_cost, _prog_nbytes(cfunlock + cfprog)))
    else:
        stats.append(("final", vm.op_cost, _prog_nbytes(funlock + fprog)))
    return comp, stats


def comp_split_default_parts(minv_cap_rows):
    """The recommended HP9.7 job partition: sbox (all 12 lanes) | state (all 12 lanes) | chain+hold+range, then the
    final boundary+combine part. Measured max ~8.3KB per part at the DEEP config (each <=10000B). HP16: the M4-block
    ef precompute makes the full 12-lane state part fit in one input (8255B) -- so the state family is no longer split
    0-5/6-11, dropping one whole P2SH32 input (~5.3KB scriptSig + overhead). Single source for the split shape
    (HP9.8-9.10 + HP16 read it here)."""
    J = _trans_jobs(minv_cap_rows)
    return [J[0:WIDTH], J[WIDTH:2 * WIDTH], J[2 * WIDTH:]]


def assemble_boundary_residuals_prog(minv0_row, n_out, range_spec, below=0):
    """HP2 (2.21b): assemble the FULL boundary residual vector bound_v on the stack, evaluated at the
    query point cur=q.ck, in ct_boundary_constraints order: eq root/nf/cm_out (cur.s0 - statement value),
    then per range block a link (cur[hc] - cur.s2) and an optional cm-bind (cur[hc] - M_EXT_INV[0].cur.s),
    then conservation. The unlock block is the opened cur state (s0..s_{WIDTH-1}) + held cells (vh0..vh3 =
    HELD_COLS order) + the public statement values (root, nf, cm_out0..cm_out_{n_out-1}); M_EXT_INV[0] is
    baked. eq/link residuals are a single SUBMOD (a-b); the cm-bind residuals reuse
    cmbind_residual_stack_prog and conservation reuses conservation_stack_prog -- all on PICK-copied input
    blocks (same absolute-index PICK(sp-1-idx) as 2.21a). range_spec = [(hv_idx, has_cmbind)] per range
    block (from meta["range"]); n_out from N_OUT. Reproduces query_terms' bound_v exactly. Needs one field
    prelude; leaves [bound_v_0..] (bottom->top) and drops the block. `below` = stack items beneath this
    block (single-program threading, 2.31): PICK indices are offset by `below`, the DROP leaves them."""
    ops = (tuple("s%d" % k for k in range(WIDTH))
           + tuple("vh%d" % k for k in range(4))
           + ("root", "nf") + tuple("cmout%d" % i for i in range(n_out)))
    idx = {nm: below + i for i, nm in enumerate(ops)}
    BLOCK = len(ops)
    prog = []
    sp = [below + BLOCK]

    def pk(nm): prog.extend([NUM(sp[0] - 1 - idx[nm]), OP("PICK")]); sp[0] += 1

    def emit(sources, prog_tokens, r_out):
        base = sp[0]
        for nm in sources:
            pk(nm)
        prog.extend(prog_tokens)
        sp[0] = base + r_out

    R = 0
    emit(["s0", "root"], SM(), 1); R += 1                          # root eq  = s0 - root
    emit(["s0", "nf"], SM(), 1); R += 1                            # nf eq    = s0 - nf
    for i in range(n_out):
        emit(["s0", "cmout%d" % i], SM(), 1); R += 1              # cm_out eq = s0 - cm_out_i
    for hv_idx, has_cmbind in range_spec:
        emit(["vh%d" % hv_idx, "s2"], SM(), 1); R += 1            # link = vh - s2
        if has_cmbind:
            emit(["vh%d" % hv_idx] + ["s%d" % m for m in range(WIDTH)],
                 cmbind_residual_stack_prog(minv0_row), 1); R += 1  # cm-bind = vh - M_EXT_INV[0].s
    emit(["vh0", "vh1", "vh2", "vh3"], conservation_stack_prog(), 1); R += 1   # conservation
    assert sp[0] == below + BLOCK + R, "boundary assembly left sp=%d, expected %d" % (sp[0], below + BLOCK + R)
    return prog + [OP("TOALT")] * R + [OP("DROP")] * BLOCK + [OP("FROMALT")] * R


def assemble_boundary_unlock(cur, stmt, n_out, held_cols):
    """Push-only opened state + held + public statement values for assemble_boundary_residuals_prog, in
    block order (s0..s_{WIDTH-1}, vh0..vh3=held_cols, root, nf, cm_out0..cm_out_{n_out-1})."""
    assert len(held_cols) == 4, "boundary unlock expects 4 held cols, got %d" % len(held_cols)
    vals = ([cur["s%d" % k] for k in range(WIDTH)]
            + [cur[c] for c in held_cols]
            + [stmt["root"], stmt["nf"]]
            + [stmt["cm_out"][i] for i in range(n_out)])
    return [NUM(v % P) for v in vals]


def run_assemble_boundary(minv0_row, cur, stmt, n_out, range_spec, held_cols):
    """Run the deployable boundary-residual assembly on cashvm; ([bound_v...], op_cost)."""
    vm = VM()
    vm.run(_field_prelude() + assemble_boundary_unlock(cur, stmt, n_out, held_cols)
           + assemble_boundary_residuals_prog(minv0_row, n_out, range_spec))
    return [decode_num(x) for x in vm.s], vm.op_cost


def compose_feed_prog(n_t, n_b, below=0, looped=False):
    """HP2 (2.22): chain the assembled residuals into the composition. The natural feed block (the
    on-stack outputs of the prior steps -- trans_v (2.21a), bound_v (2.21b), the FS-derived GF(p^2)
    alphas, qf_trans and bound_invX (qf_bound_prog)) is arranged, by PICK-copy, into compose_stack_prog's
    interleaved _compose_layout order and composed; comp_c = qf_trans*sum_j(trans_v_j*alpha_j[c]) +
    sum_b(bound_v_b*invX_b*alpha_b[c]). Reuses the validated compose_stack_prog (no arithmetic duplicated).
    Feed block bottom->top: trans_v(n_t), bound_v(n_b), trans_a pairs(2*n_t), qf(1), bound_invX(n_b),
    bound_a pairs(2*n_b). Needs one field prelude; leaves [comp0, comp1] and drops the feed block. `below`
    = stack items beneath the feed block (single-program threading, 2.31): PICK offset by `below`, kept.
    looped=True (HP10.5) emits the equivalent DEFINE/INVOKE fold (compose_feed_looped_prog) -- SAME stack
    effect (consume the block, leave [comp0, comp1], preserve `below`); the 4 fold bodies must be DEFINE'd
    once at the program entry (compose_feed_loop_defines). Validated == the unrolled form in self_test."""
    if looped:
        return compose_feed_looped_prog(n_t, n_b, below)
    names = ([("tv", j) for j in range(n_t)] + [("bv", b) for b in range(n_b)]
             + [("ta", j, c) for j in range(n_t) for c in (0, 1)] + [("qf",)]
             + [("bix", b) for b in range(n_b)] + [("ba", b, c) for b in range(n_b) for c in (0, 1)])
    idx = {nm: below + i for i, nm in enumerate(names)}
    BLOCK = len(names)
    prog = []
    sp = [below + BLOCK]

    def pk(nm): prog.extend([NUM(sp[0] - 1 - idx[nm]), OP("PICK")]); sp[0] += 1

    for j in range(n_t):                                            # -> _compose_layout order (copies)
        pk(("tv", j)); pk(("ta", j, 0)); pk(("ta", j, 1))
    pk(("qf",))
    for b in range(n_b):
        pk(("bv", b)); pk(("bix", b)); pk(("ba", b, 0)); pk(("ba", b, 1))
    prog += compose_stack_prog(n_t, n_b)                            # consumes the arranged copies, leaves 2
    sp[0] = below + BLOCK + 2
    return prog + [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * BLOCK + [OP("FROMALT"), OP("FROMALT")]


def compose_feed_unlock(trans_v, bound_v, trans_a, qf_trans, bound_invX, bound_a):
    """Push-only feed block for compose_feed_prog, bottom->top: trans_v, bound_v, trans_a pairs, qf,
    bound_invX, bound_a pairs."""
    w = [NUM(v % P) for v in trans_v] + [NUM(v % P) for v in bound_v]
    for a in trans_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    w += [NUM(qf_trans % P)]
    w += [NUM(v % P) for v in bound_invX]
    for a in bound_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    return w


def run_compose_feed(trans_v, bound_v, trans_a, qf_trans, bound_invX, bound_a):
    """Run the deployable compose-feed on cashvm; ((comp0, comp1), op_cost)."""
    n_t, n_b = len(trans_v), len(bound_v)
    vm = VM()
    vm.run(_field_prelude() + compose_feed_unlock(trans_v, bound_v, trans_a, qf_trans, bound_invX, bound_a)
           + compose_feed_prog(n_t, n_b))
    assert len(vm.s) == 2, "compose_feed left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


# ---- HP10.2/HP10.5 compose-feed LOOP: fuse the feed arrangement + compose_stack into a DEFINE/INVOKE
# fold over the natural feed block (no _compose_layout copies). comp_c = qf*sum_j(tv_j*ta_j[c]) +
# sum_b(bv_b*bix_b*ba_b[c]) for c in {0,1}; == compose_feed_prog. The 4 bodies (transfold/boundfold x c) are
# DEFINE'd ONCE per PROGRAM (the callers are per-query, so a per-call DEFINE would duplicate -- HP10.5); the
# fold reads tv/ta/bv/bix/ba at DYNAMIC depth (below-INDEPENDENT: PICK depth = sp-1-idx and `below` cancels).
_CFT = {0: b"\x13", 1: b"\x14"}                                     # compose transition-fold fids (c=0/1)
_CFB = {0: b"\x15", 1: b"\x16"}                                     # compose boundary-fold fids (c=0/1)


def _compose_transfold_body(c, extra, n_t, n_b):
    """[.., acc, j] -> [.., acc + tv_j*ta_j[c]]. tv_j @ (BLOCK+1+e)-j ; ta_j[c] @ (BLOCK+2-n_t-n_b-c+e)-2j."""
    B = 3 * n_t + 4 * n_b + 1
    d_tv = B + 1 + extra; d_ta = B + 2 - n_t - n_b - c + extra
    return ([OP("DUP"), NUM(d_tv), OP("SWAP"), OP("SUB"), OP("PICK"), OP("SWAP")]
            + [OP("DUP"), NUM(2), OP("MUL"), NUM(d_ta), OP("SWAP"), OP("SUB"), OP("PICK"), OP("SWAP")]
            + [OP("DROP")] + MM() + AM())


def _compose_boundfold_body(c, extra, n_t, n_b):
    """[.., acc, b] -> [.., acc + bv_b*bix_b*ba_b[c]]. bv@(B+1-n_t+e)-b, bix@(B+1-3n_t-n_b+e)-b, ba@(B+2-3n_t-2n_b-c+e)-2b."""
    B = 3 * n_t + 4 * n_b + 1
    d_bv = B + 1 - n_t + extra; d_bix = B + 1 - 3 * n_t - n_b + extra; d_ba = B + 2 - 3 * n_t - 2 * n_b - c + extra
    return ([OP("DUP"), NUM(d_bv), OP("SWAP"), OP("SUB"), OP("PICK"), OP("SWAP")]
            + [OP("DUP"), NUM(d_bix), OP("SWAP"), OP("SUB"), OP("PICK"), OP("SWAP")]
            + [OP("DUP"), NUM(2), OP("MUL"), NUM(d_ba), OP("SWAP"), OP("SUB"), OP("PICK"), OP("SWAP")]
            + [OP("DROP")] + MM() + MM() + AM())


def compose_feed_loop_defines(n_t, n_b):
    """DEFINE the 4 compose fold bodies ONCE per program (place at the shard entry, next to _field_prelude)."""
    return ([PUSH(_CFT[0]), DEFINE(_compose_transfold_body(0, 0, n_t, n_b)),
             PUSH(_CFT[1]), DEFINE(_compose_transfold_body(1, 1, n_t, n_b)),
             PUSH(_CFB[0]), DEFINE(_compose_boundfold_body(0, 0, n_t, n_b)),
             PUSH(_CFB[1]), DEFINE(_compose_boundfold_body(1, 1, n_t, n_b))])


def compose_feed_looped_prog(n_t, n_b, below=0):
    """Looped compose_feed (fold form). Precondition: the natural feed block (compose_feed_unlock order,
    BLOCK=3n_t+4n_b+1) on top of `below` items, the 4 fold bodies DEFINE'd (compose_feed_loop_defines).
    Leaves [comp0, comp1], drops the feed block, preserves the `below` items. Depths are below-independent
    (PICK depth = sp-1-idx, below cancels); comp1 runs with comp0 on the stack -> extra=+1."""
    B = 3 * n_t + 4 * n_b + 1

    def _pass(c, extra):
        d_qf = B - 3 * n_t - n_b + extra
        p = [NUM(0)]                                                # acc_c = 0 on top of the block
        for j in range(n_t):
            p += [NUM(j), PUSH(_CFT[c]), OP("INVOKE")]              # acc += tv_j*ta_j[c]
        p += [NUM(d_qf), OP("PICK")] + MM()                        # acc *= qf
        for b in range(n_b):
            p += [NUM(b), PUSH(_CFB[c]), OP("INVOKE")]             # acc += bv_b*bix_b*ba_b[c]
        return p
    return (_pass(0, 0) + _pass(1, 1)
            + [OP("TOALT"), OP("TOALT")] + [OP("DROP")] * B + [OP("FROMALT"), OP("FROMALT")])


def run_compose_feed_looped(trans_v, bound_v, trans_a, qf_trans, bound_invX, bound_a):
    """Run the looped compose-feed on cashvm; ((comp0,comp1), op_cost). == run_compose_feed (validated)."""
    n_t, n_b = len(trans_v), len(bound_v)
    vm = VM()
    vm.run(_field_prelude() + compose_feed_loop_defines(n_t, n_b)
           + compose_feed_unlock(trans_v, bound_v, trans_a, qf_trans, bound_invX, bound_a)
           + compose_feed_looped_prog(n_t, n_b))
    assert len(vm.s) == 2, "compose_feed_looped left %d items, expected 2" % len(vm.s)
    return (decode_num(vm.s[-2]), decode_num(vm.s[-1])), vm.op_cost


# ---- HP2 (2.31c): bind the opened trace-leaf cells to the committed trace root ----------
# The 2.31a core consumes the cur/nxt cells as free witness; on-chain they MUST be the Merkle-
# opened trace row at the FS-derived index k, else a cheating prover forges the cells (gate-free
# residuals). The trace leaf is the SAME format the oracle commits (native_ct_air_stark._leaf):
# a 16-byte salt followed by enc8 of each FLAT_COLS column (enc == enc8 = stark.enc, so the
# preimage is byte-identical). The deployable retaining opener + cell split (reused, DRY) verify
# it against the pinned tp_root at k and yield the FLAT_COLS field cells -- the pinned-root
# EQUALVERIFY makes a wrong sibling/index or a tampered leaf fail-closed.
def trace_leaf_preimage(row, salt, flat_cols):
    """Trace Merkle-leaf preimage = 16-byte salt + concat(enc8(row[c]) for c in flat_cols),
    byte-identical to native_ct_air_stark._leaf([row[c] for c in FLAT_COLS], salt)."""
    return salt + b"".join(enc8(row[c] % P) for c in flat_cols)


def run_trace_open(row, salt, path, root, k, flat_cols):
    """Open a trace leaf @k against the pinned trace root at the FS-derived index k (retaining the
    preimage) and split it into the FLAT_COLS field cells the residual assembly consumes; reuses
    merkle_verify_retain_prog + split_cells_prog (16-byte salt prefix). Returns ([cell values in
    FLAT_COLS order], op_cost) on accept; raises VMError on a fail-closed reject (wrong sibling/
    index or a tampered leaf)."""
    pre = trace_leaf_preimage(row, salt, flat_cols)
    vm = VM()
    vm.run(merkle_verify_stack_unlock(pre, path, root, k)
           + merkle_verify_retain_prog(len(path)) + split_cells_prog(len(flat_cols), prefix=16))
    return [decode_num(x) for x in vm.s], vm.op_cost


def run_selector_open(sv, i, path, root, k):
    """Open a D-coset selector leaf @i against the pinned selector root at the FS-derived index k and
    split it into the 33 selector_row_values_coset cells the residual assembly consumes (no salt
    prefix). Reuses merkle_verify_retain_prog + split_cells_prog (DRY). Returns ([33 cells in
    selector_row_values_coset order], op_cost); raises VMError on a fail-closed reject."""
    pre = selector_preimage_coset(sv, i)
    n = len(selector_row_values_coset(sv, i))
    vm = VM()
    vm.run(merkle_verify_stack_unlock(pre, path, root, k)
           + merkle_verify_retain_prog(len(path)) + split_cells_prog(n, prefix=0))
    return [decode_num(x) for x in vm.s], vm.op_cost


def bound_retain_open_prog(depth, root):
    """HP2 (2.31c-ii-open): retaining Merkle opener with the pinned root BAKED into the redeem, not
    taken from the witness. run_trace_open/run_selector_open push the root (isolated testing), but the
    deployable bound shard MUST pin the root so a prover cannot substitute a favourable Merkle tree
    (soundness). Stack precondition (bottom->top): [sib_{d-1}..sib_0, preimage, k]; on success leaves
    [preimage] (a wrong sibling/index, a tampered leaf, or a leaf that only opens under a DIFFERENT
    root all fail EQUALVERIFY, fail-closed). Reuses merkle_verify_runtime_prog's runtime-depth,
    index-derived path LOOP (HP10.4: `depth` is a baked config constant NUM(depth), so the per-level hash
    steps collapse from an unrolled `depth`x chain to one BEGIN/UNTIL loop -- ~140B/leaf saved, x4 leaves/
    opener; validated == the unrolled form on a real depth-12 tree, fail-closed identical) minus its
    witness-root check, plus the baked-root check pattern (DRY)."""
    return ([OP("OVER"), OP("TOALT"), NUM(depth)] + merkle_verify_runtime_prog()[:-1]
            + [PUSH(root), OP("EQUALVERIFY"), OP("FROMALT")])


def bound_open_unlock(preimage, path, k):
    """Push-only witness for bound_retain_open_prog (the root is baked, NOT pushed): [sib_{d-1}..sib_0,
    preimage, k]. path = [(sib_i, bit_i)] from m_path; the direction bits are derived from k, not pushed."""
    sibs = [s for s, _ in path]
    return [PUSH(s) for s in reversed(sibs)] + [PUSH(preimage), NUM(k)]


def run_bound_open(preimage, path, root, k, n_cells, prefix):
    """Open a leaf against the PINNED (baked) root at the FS index k and split it into n_cells field
    cells; generic over the leaf type (trace: prefix=16 salt, n=len(FLAT_COLS); selector: prefix=0,
    n=33). Returns ([cells], op_cost) on accept; raises VMError on a fail-closed reject (wrong leaf/
    index, or a leaf under a different root -- the root cannot be forged, it is baked)."""
    vm = VM()
    vm.run(bound_open_unlock(preimage, path, k) + bound_retain_open_prog(len(path), root)
           + split_cells_prog(n_cells, prefix=prefix))
    return [decode_num(x) for x in vm.s], vm.op_cost


def run_opener_commit(root, path, preimage, cells, k, prefix):
    """Run opener_commit_prog on cashvm (the opener-input PRODUCER: commit [cells|k] as its blob, Merkle-bound ==
    the opened leaf @k). Unlock (bottom->top): root, sib_{d-1}..sib_0, preimage, blob (blob = enc8(cells)||enc8(k)).
    Returns True on accept, False on a fail-closed reject (forged committed cell / wrong index / tampered leaf).
    The exposed blob is what the deploy per-query DEEP sum-part reads cross-input (deploy_check section 4g)."""
    sibs = [s for s, _ in path]
    blob = b"".join(enc8(c % P) for c in cells) + enc8(k)
    vm = VM()
    try:
        vm.run([PUSH(root)] + [PUSH(s) for s in reversed(sibs)] + [PUSH(preimage), PUSH(blob)]
               + opener_commit_prog(len(path), len(cells), prefix))
        return len(vm.s) == 1 and decode_num(vm.s[-1]) == 1
    except VMError:
        return False


def looped_opener_from_blob_unlock(opens):
    """Push-only witness for looped_opener_from_blob_prog: opens = [(root, path, salt, cells, k), ...] in processing
    order; the per-open blocks concatenated with the last-processed at the BOTTOM (first-processed on top, since the
    loop consumes the stack top first). Each block bottom->top: [root, sib_{d-1}..sib_0, (salt if non-empty,) blob].
    salt = the leaf's hiding prefix (b"" for prefix=0 leaves); blob = enc8(cells)||enc8(k) (the preimage is derived
    on-chain as salt++blob[:-8], not pushed)."""
    w = []
    for (root, path, salt, cells, k) in reversed(opens):
        sibs = [s for s, _ in path]
        blob = b"".join(enc8(c % P) for c in cells) + enc8(k)
        block = [PUSH(root)] + [PUSH(s) for s in reversed(sibs)]
        if salt:
            block += [PUSH(salt)]
        w += block + [PUSH(blob)]
    return w


def run_looped_opener_from_blob(opens, depth, n_cells, n_opens, prefix, trunc=0):
    """Run looped_opener_from_blob_prog on cashvm; True on accept, False on a fail-closed reject (forged cell / wrong
    index / tampered leaf / witness block count != n_opens). All opens must share (depth, n_cells, prefix). trunc>0
    verifies against N3 truncated-hash trees (roots/siblings n bytes; the opens must be built at that width)."""
    vm = VM()
    try:
        vm.run(looped_opener_from_blob_unlock(opens) + looped_opener_from_blob_prog(depth, n_cells, n_opens, prefix, trunc))
        return len(vm.s) == 1 and decode_num(vm.s[-1]) == 1
    except VMError:
        return False


def open_all_leaves_prog(depth, tp_root, sel_root, n_trace, n_sel, below=0):
    """HP2 (2.31c-ii-open-b): open all four per-query leaves -- trace@k, trace@kn, D-coset selector@k,
    selector@kn -- in ONE program so the opened cells are produced Merkle-BOUND (pinned roots) on a
    single stack in LEAF ORDER, ready for the mapped core. The unlock pushes the four witness blocks
    bottom->top: W_tk, W_tn, W_sk, W_sn, each = bound_open_unlock's [sib_{depth-1}..sib_0, preimage, k]
    (WB = depth+2 items; both trees have N leaves so the depth is uniform). Since the retaining opener
    consumes its TOP witness and leaves the cells on top (which would bury the next witness), each stage
    PICK-COPIES its witness block up from its fixed bottom position and runs bound_retain_open_prog +
    split (roots BAKED, so the originals stay for a clean drop and the direction bits derive from k).
    The openers use only SHA256/SPLIT/integer ops (no field op), so they run before the field prelude
    with a free, balanced alt stack. Leaves, bottom->top: [W(4*WB) untouched, trace_k(n_trace),
    trace_kn(n_trace), sel_k(n_sel), sel_kn(n_sel)] -- 2*n_trace+2*n_sel bound cells above the spent
    witness. A wrong sibling / index / leaf fails the baked-root EQUALVERIFY (fail-closed). `below` =
    stack items beneath the four witness blocks (single-program threading, 2.31c-ii-open-b-feed): the
    witness sits above `below` prior items (the composition extras), so every PICK index is offset by
    `below` and the cells are produced at base `below`+4*WB."""
    WB = depth + 2                                               # sibs(depth) + preimage + k per leaf
    prog = []
    sp = [below + 4 * WB]

    def copy(pos): prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1

    def open_leaf(block, root, n, prefix):
        for i in range(WB):
            copy(below + block * WB + i)                        # copy this leaf's witness block to the top
        prog.extend(bound_retain_open_prog(depth, root) + split_cells_prog(n, prefix=prefix))
        sp[0] += n - WB                                          # WB copies consumed, n cells left

    open_leaf(0, tp_root, n_trace, 16)                          # trace@k  (16-byte salt)
    open_leaf(1, tp_root, n_trace, 16)                          # trace@kn
    open_leaf(2, sel_root, n_sel, 0)                            # D-coset selector@k  (no salt)
    open_leaf(3, sel_root, n_sel, 0)                            # selector@kn
    return prog


def open_all_leaves_unlock(tk_pre, tk_path, k, tn_pre, tn_path, kn, sk_pre, sk_path, sn_pre, sn_path):
    """Push-only witness for open_all_leaves_prog: the four leaves' [sibs, preimage, index] blocks in
    order (trace@k with k, trace@kn with kn, selector@k with k, selector@kn with kn). Roots are baked."""
    return (bound_open_unlock(tk_pre, tk_path, k) + bound_open_unlock(tn_pre, tn_path, kn)
            + bound_open_unlock(sk_pre, sk_path, k) + bound_open_unlock(sn_pre, sn_path, kn))


def run_open_all_leaves(depth, tp_root, sel_root, n_trace, n_sel,
                        tk_pre, tk_path, k, tn_pre, tn_path, kn, sk_pre, sk_path, sn_pre, sn_path):
    """Run the four-leaf opener supply on cashvm; ([the 2*n_trace+2*n_sel bound cells in leaf order],
    op_cost) on accept, raises VMError on a fail-closed reject. The spent witness blocks (4*(depth+2))
    remain beneath the cells."""
    vm = VM()
    vm.run(open_all_leaves_unlock(tk_pre, tk_path, k, tn_pre, tn_path, kn, sk_pre, sk_path, sn_pre, sn_path)
           + open_all_leaves_prog(depth, tp_root, sel_root, n_trace, n_sel))
    WB = depth + 2
    return [decode_num(x) for x in vm.s[4 * WB:]], vm.op_cost


# The 33 D-coset selector cells in commit order (selector_row_values_coset): 8 indicators + rc[WIDTH]
# + chain_minv[WIDTH] (named cm here, matching _TRANS_ASM_OPS) + range_weight.
_SEL_ORDER = (list(_SEL_COSET_KEYS)
              + ["rc%d" % k for k in range(WIDTH)]
              + ["cm%d" % k for k in range(WIDTH)]
              + ["range_weight"])


def _opened_cell_positions(flat_cols, held_cols):
    """Absolute stack positions of every _TRANS_ASM_OPS cell (the boundary s/held cells are the same
    "s%d"/"vh%d" entries) in the opened-leaf flat layout the unlock pushes bottom->top:
    trace_k(FLAT_COLS) + trace_kn(FLAT_COLS) + sel_k(_SEL_ORDER) + sel_kn(_SEL_ORDER). Derived from
    the canonical column/selector orders (no hardcoded indices) so the map stays correct if a layout
    changes. w_next is range_weight @kn (from sel_kn); every other selector is @k (sel_k); cur/held
    from trace_k; nxt/held from trace_kn."""
    NT = len(flat_cols); NS = len(_SEL_ORDER)
    tk = {c: i for i, c in enumerate(flat_cols)}
    tn = {c: NT + i for i, c in enumerate(flat_cols)}
    sk = {s: 2 * NT + i for i, s in enumerate(_SEL_ORDER)}
    sn = {s: 2 * NT + NS + i for i, s in enumerate(_SEL_ORDER)}
    pos = {}
    for k in range(WIDTH):
        pos["s%d" % k] = tk["s%d" % k]; pos["ns%d" % k] = tn["s%d" % k]
    for pre in ("u2_", "u4_", "u6_"):
        for k in range(WIDTH):
            pos[pre + str(k)] = tk[pre + str(k)]
    for i in range(4):
        pos["vh%d" % i] = tk[held_cols[i]]; pos["nvh%d" % i] = tn[held_cols[i]]
    pos["isf"] = sk["is_full"]; pos["isp"] = sk["is_partial"]
    pos["isbs"] = sk["is_block_start"]; pos["isra"] = sk["is_reabsorb"]
    for k in range(WIDTH):
        pos["rc%d" % k] = sk["rc%d" % k]; pos["cm%d" % k] = sk["cm%d" % k]
    for s in ("is_range", "is_range_first", "is_range_step", "is_range_last"):
        pos[s] = sk[s]
    pos["w_next"] = sn["range_weight"]
    return pos


# ---- HP2 (2.31): thread the per-query verification core on ONE unified BCH-VM stack ------
# Chains the proven building blocks -- residual assembly (2.21a trans_v + 2.21b bound_v) ->
# composition (2.22) -> FRI fold chain (2.26-2.30) -- for ONE query on a SINGLE field prelude,
# MAIN-STACK-ONLY. The alt stack is reserved for P (the field prelude puts P on alt; MULMOD/
# ADDMOD/SUBMOD read it via FROMALT), so a value parked on alt above P would be popped by a field
# op instead of P -> corrupt arithmetic. Threading therefore keeps every value on the MAIN stack:
# the unlock pushes ONE flat witness region, and each stage PICK-COPIES its input block to the top
# (the copies, being literal PICKs, are bound to the witness) and runs the offset-aware (`below`)
# prog, stacking trans_v then bound_v then the composition value comp above the untouched witness.
def per_query_core_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec, qfri):
    """HP2 (2.31): verify ONE query end-to-end on one unified stack. The unlock pushes, bottom->top:
    the transition cells (_TRANS_ASM_OPS order), the boundary cells (s0..s_{WIDTH-1}, held, root, nf,
    cm_out), then the composition extras (trans_a pairs, qf_trans, bound_invX, bound_a pairs). Stage A
    PICK-copies the transition block up and assembles trans_v (2.21a, below=witness); stage B copies
    the boundary block up and assembles bound_v (2.21b); stage C copies the extras up so the compose
    feed block [trans_v, bound_v, trans_a, qf, bound_invX, bound_a] is contiguous and composes it into
    comp (2.22); stage D runs the FRI fold chain (baked qfri, prelude skipped, comp read from the
    stack) which binds comp to the opened FRI layer-0 leaf and folds the chain (2.26-2.30). Reproduces
    native_ct_air_stark.verify for one query; a tampered opened cell perturbs trans_v/bound_v so comp
    no longer equals the FRI layer-0 leaf and the layer-0 NUMEQUALVERIFY rejects (fail-closed). Needs
    one field prelude (installed by the caller); drops the witness and leaves exactly [1] on accept.
    Byte-minimisation (loop/witness-in-unlock/thin-shard) is HP3 -- 2.31 is correctness-first."""
    NB_t = len(_TRANS_ASM_OPS)
    NB_b = WIDTH + 4 + 2 + n_out                                 # s0..s_{W-1}, vh0..3, root, nf, cm_out
    n_t = 4 * WIDTH + len(minv_cap_rows) + 10                    # ct_num_transition_residuals
    n_b = 2 + n_out + sum(1 + (1 if has_cmbind else 0) for _, has_cmbind in range_spec) + 1
    E = 2 * n_t + 1 + n_b + 2 * n_b                              # trans_a pairs, qf, bound_invX, bound_a pairs
    Wn = NB_t + NB_b + E                                         # total flat witness depth
    prog = []
    sp = [Wn]

    def copy(pos):                                              # PICK-copy the value at absolute stack pos to top
        prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1

    for i in range(NB_t):                                       # stage A: transition block -> trans_v
        copy(i)
    prog += assemble_transition_residuals_prog(diag, minv_cap_rows, below=Wn)
    sp[0] = Wn + n_t

    for i in range(NB_b):                                       # stage B: boundary block -> bound_v
        copy(NB_t + i)
    prog += assemble_boundary_residuals_prog(minv0_row, n_out, range_spec, below=Wn + n_t)
    sp[0] = Wn + n_t + n_b

    for i in range(E):                                         # stage C: extras -> contiguous compose feed
        copy(NB_t + NB_b + i)
    prog += compose_feed_prog(n_t, n_b, below=Wn)
    sp[0] = Wn + 2                                             # [comp0, comp1] on top of the witness

    prog += fri_chain_prog(qfri, None, prelude=False, comp_on_stack=True)   # stage D: bind comp + fold
    return prog + [OP("TOALT")] + [OP("DROP")] * Wn + [OP("FROMALT")]        # drop witness -> clean [1]


def per_query_core_unlock(cur, nxt, pub_x, w_next, stmt, trans_a, qf_trans, bound_invX, bound_a,
                          held_cols, n_out):
    """Push-only flat witness for per_query_core_prog, bottom->top: the transition cells
    (assemble_transition_unlock), the boundary cells (assemble_boundary_unlock -- cur state/held are
    supplied again here; on-chain these free-witness cells are replaced by the trace/selector openers
    (2.12-2.19) + index/inverse derivation (2.8-2.11) in the front-end continuation 2.31c), then the
    composition extras in compose feed order (trans_a pairs, qf, bound_invX, bound_a pairs)."""
    w = assemble_transition_unlock(cur, nxt, pub_x, w_next, held_cols)
    w += assemble_boundary_unlock(cur, stmt, n_out, held_cols)
    for a in trans_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    w += [NUM(qf_trans % P)]
    w += [NUM(v % P) for v in bound_invX]
    for a in bound_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    return w


def run_per_query_core(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                       cur, nxt, pub_x, w_next, stmt, trans_a, qf_trans, bound_invX, bound_a,
                       held_cols, qfri):
    """Run the threaded per-query verification core on cashvm; (True, op_cost) if the query verifies
    end-to-end (clean stack [1]), (False, 0) on a fail-closed reject (a tampered cell -> comp != FRI
    layer-0, a bad opening, or a broken fold)."""
    vm = VM()
    try:
        vm.run(_field_prelude()
               + per_query_core_unlock(cur, nxt, pub_x, w_next, stmt, trans_a, qf_trans,
                                       bound_invX, bound_a, held_cols, n_out)
               + per_query_core_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec, qfri))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except VMError:
        return False, 0


def _comp_producer_bind_prog(total_below, k_pos=None):
    """HP3.5b-iii-2 (compose-INPUT / thin-shard): stage-D' -- instead of folding the FRI, BIND the computed
    composition value comp=(comp0,comp1) [on top] to the comp_preimage sitting at absolute position 0 (the
    compose-input's first unlock push). split_cells_prog recovers the limbs and NUMEQUALVERIFY each == the
    computed comp -> a forged/inconsistent comp is rejected AT the producer. Leaves [witness(total_below).., 1];
    the caller's cleanup then drops the witness (incl comp_preimage) -> [1].
    k_pos=None: the LEGACY 2-limb form (16-byte comp_preimage = enc8(comp0)+enc8(comp1); compose_producer bound_fs).
    k_pos given: the DEPLOY 3-limb form (24-byte comp_preimage = fri_carry_preimage(comp0,comp1,k) =
    enc8(comp0)+enc8(comp1)+enc8(k)) -- ALSO binds the third limb == the FS-derived query index k at absolute
    `k_pos` (compose's own on-chain k, e.g. cell_base-2). This carries a TRANSCRIPT-BOUND k across the input
    boundary (FS-2): the consumer FRI-input reads the 24-byte preimage via OP_INPUTBYTECODE, split_cells(3)s it,
    and USES (comp0,comp1) as carry_val + k as carry_idx (fri_partial_witness_redeem carry_split) -- so comp is
    threaded as a FIELD value (OBS-2) and k is the compose-derived FS index, not a prover-chosen one."""
    prog = []
    n_limb = 2 if k_pos is None else 3
    sp = [total_below + 2]                                       # [comp_preimage@0, witness.., comp0, comp1]

    def copy(abspos):
        prog.extend([NUM(sp[0] - 1 - abspos), OP("PICK")]); sp[0] += 1

    copy(0)                                                      # copy comp_preimage to the top
    prog += split_cells_prog(n_limb, prefix=0); sp[0] += n_limb - 1   # -> [.., comp0', comp1'(, k')] recovered limbs
    if k_pos is not None:
        copy(k_pos); prog += [OP("NUMEQUALVERIFY")]; sp[0] -= 2  # k' == the FS-derived query index k (transcript-bound)
    copy(total_below + 1); prog += [OP("NUMEQUALVERIFY")]; sp[0] -= 2   # comp1' == computed comp1
    copy(total_below);     prog += [OP("NUMEQUALVERIFY")]; sp[0] -= 2   # comp0' == computed comp0
    prog += [OP("2DROP"), NUM(1)]; sp[0] += -1                   # drop comp0,comp1 -> [1] (witness kept for cleanup)
    assert sp[0] == total_below + 1, "comp-producer-bind sp=%d expected %d" % (sp[0], total_below + 1)
    return prog


def _mapped_core_stages(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                        flat_cols, held_cols, root, nf, cm_out, qfri,
                        cell_base, extras_base, total_below, extras_src=None, deployable_final=None,
                        comp_out=False, comp_k_pos=None, compose_looped=False,
                        sbox_looped=False, state_looped=False, fri_looped=False, oN=None, off=None):
    """Shared per-query core threading (2.31c-ii / 2.31c-ii-open-b-feed): PICK-copy the opened cells
    (at absolute base `cell_base`, in the canonical leaf-order positions from _opened_cell_positions)
    into the _TRANS_ASM_OPS / boundary block order and thread trans_v -> bound_v -> compose -> FRI on
    one field prelude (installed by the caller), reproducing verify(). `extras_base` = absolute base of
    the composition extras (trans_a pairs, qf, bound_invX, bound_a pairs) -- or, when `extras_src` is
    given (a list of E absolute positions), the E extras are copied from those per-source positions
    (2c-ii: alphas from the FS output, qf/bound_invX from the derived qf_bound). root/nf/cm_out are PINNED
    (public). `total_below` = stack items beneath the computed residuals (the whole witness: cells +
    extras [+ spent opener witness]); the `below` offsets and the final DROP*total_below key off it, so
    the same logic works whether the cells arrive as unlock witness (per_query_mapped_prog: cell_base=0,
    extras_base=n_cells) or from the in-program openers (per_query_bound_prog: cells above the extras +
    spent witness). Leaves exactly [1] on accept; a tampered cell -> comp != FRI layer-0 (fail-closed).
    `deployable_final` (the proof's final FRI layer): when given, stage D uses the DEPLOYABLE FRI chain
    (_fri_chain_deployable_body: DERIVED index-selection + Merkle-bound v/w openings, 2.36-2.38) instead of
    the baked fri_chain_prog(qfri) -- same [comp0,comp1]->[1] contract. Default None keeps the baked chain
    (byte-identical for the mapped/bound/bound_fs callers)."""
    n_t = 4 * WIDTH + len(minv_cap_rows) + 10
    n_b = 2 + n_out + sum(1 + (1 if has_cmbind else 0) for _, has_cmbind in range_spec) + 1
    E = 2 * n_t + 1 + n_b + 2 * n_b
    pos = _opened_cell_positions(flat_cols, held_cols)
    prog = []
    sp = [total_below]

    def copy(p): prog.extend([NUM(sp[0] - 1 - p), OP("PICK")]); sp[0] += 1
    def num(v): prog.append(NUM(v % P)); sp[0] += 1

    for nm in _TRANS_ASM_OPS:                                    # stage A: mapped transition block -> trans_v
        copy(cell_base + pos[nm])
    prog += assemble_transition_residuals_prog(diag, minv_cap_rows, below=total_below,
                                               sbox_looped=sbox_looped, state_looped=state_looped)
    sp[0] = total_below + n_t

    for k in range(WIDTH):                                       # stage B: boundary block -- cur s/held copied,
        copy(cell_base + pos["s%d" % k])                        #          public root/nf/cm_out PINNED
    for i in range(4):
        copy(cell_base + pos["vh%d" % i])
    num(root); num(nf)
    for cm in cm_out:
        num(cm)
    prog += assemble_boundary_residuals_prog(minv0_row, n_out, range_spec, below=total_below + n_t)
    sp[0] = total_below + n_t + n_b

    for i in range(E):                                          # stage C: extras -> compose feed (contiguous
        copy((extras_base + i) if extras_src is None else extras_src[i])   #  witness, or per-source derived)
    prog += compose_feed_prog(n_t, n_b, below=total_below, looped=compose_looped)
    sp[0] = total_below + 2

    assert not (fri_looped and deployable_final is None), (                 # F4: fri_looped implies deployable --
        "fri_looped stage D requires deployable (a fold-8 final layer); got deployable_final=None")   # else the
    if comp_out:                                                            # baked-chain branch would KeyError on qfri['layers']
        prog += _comp_producer_bind_prog(total_below, comp_k_pos)          # stage D' (iii-2 compose-INPUT): bind comp to the producer comp_preimage@0 (no fold; FRI is a separate input)
    elif deployable_final is None:                                          # stage D: bind comp + fold
        prog += fri_chain_prog(qfri, None, prelude=False, comp_on_stack=True)   # baked comp_tgt/fold_tgt
    elif fri_looped:                                                        # HP3.10 stage D: fold-8 DEFINE/INVOKE loop
        assert oN is not None and off is not None, "fri_looped stage D needs the FRI domain params oN/off"
        prog += _fri_loop_chain_body(qfri["rounds"], qfri["k"], deployable_final, oN, off,
                                     defines_installed=True)               # defines hoisted at shard/per_query entry (F1)
    else:                                                                   # deployable (3.5b-i/ii): fold-2 derived
        prog += _fri_chain_deployable_body(qfri["layers"], qfri["k"], deployable_final)  # index-select + Merkle
    return prog + [OP("TOALT")] + [OP("DROP")] * total_below + [OP("FROMALT")]   # drop witness -> clean [1]


def per_query_mapped_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                          flat_cols, held_cols, root, nf, cm_out, qfri):
    """HP2 (2.31c-ii): verify ONE query on one unified stack from the OPENED-leaf cells (in the order
    the trace/selector openers produce them) rather than a pre-arranged block, reproducing verify().
    The unlock pushes the opened cells bottom->top in LEAF ORDER -- trace_k(FLAT_COLS) +
    trace_kn(FLAT_COLS) + sel_k(_SEL_ORDER) + sel_kn(_SEL_ORDER) -- then the composition extras. Each
    core stage PICK-copies its input block from the MAPPED opened-cell positions
    (_opened_cell_positions, derived from the canonical orders) into the assembly block order: stage A
    the _TRANS_ASM_OPS transition block, stage B the boundary block (cur s/held copied from trace_k;
    the PUBLIC statement root/nf/cm_out are PINNED as baked constants, not witness), stage C the
    compose feed. The FRI chain (baked qfri, prelude skipped, comp from the stack) binds comp to the
    opened FRI layer-0 leaf and folds. Reuses the offset-aware assembly/compose progs exactly as the
    2.31a core (DRY) -- only the copy SOURCES differ (leaf order -> block order). In the full shard the
    leaf cells come from the trace opener (2.31c-i) + selector opener (run_selector_open) at the FS
    index, so cur/nxt/pub_x/w_next are Merkle-bound. Needs one field prelude (installed by the caller);
    drops the witness and leaves exactly [1] on accept; a tampered opened cell -> comp != FRI layer-0
    -> fail-closed reject."""
    NT = len(flat_cols); NS = len(_SEL_ORDER)
    n_cells = 2 * NT + 2 * NS                                    # trace_k + trace_kn + sel_k + sel_kn
    n_t = 4 * WIDTH + len(minv_cap_rows) + 10                    # ct_num_transition_residuals
    n_b = 2 + n_out + sum(1 + (1 if has_cmbind else 0) for _, has_cmbind in range_spec) + 1
    E = 2 * n_t + 1 + n_b + 2 * n_b                              # trans_a pairs, qf, bound_invX, bound_a pairs
    # 2.31c-ii layout: opened cells at [0..n_cells-1], composition extras at [n_cells..n_cells+E-1].
    return _mapped_core_stages(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                               flat_cols, held_cols, root, nf, cm_out, qfri,
                               cell_base=0, extras_base=n_cells, total_below=n_cells + E)


def per_query_mapped_unlock(tk_cells, tn_cells, sk_cells, sn_cells,
                            trans_a, qf_trans, bound_invX, bound_a):
    """Push-only leaf-order opened cells for per_query_mapped_prog, bottom->top: trace_k(FLAT_COLS) +
    trace_kn(FLAT_COLS) + sel_k(_SEL_ORDER) + sel_kn(_SEL_ORDER) + the composition extras (trans_a
    pairs, qf, bound_invX, bound_a pairs). In the full shard these cells are the outputs of the trace/
    selector openers at the FS index (Merkle-bound); here they are supplied as the opener outputs."""
    w = [NUM(v % P) for v in tk_cells] + [NUM(v % P) for v in tn_cells]
    w += [NUM(v % P) for v in sk_cells] + [NUM(v % P) for v in sn_cells]
    for a in trans_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    w += [NUM(qf_trans % P)]
    w += [NUM(v % P) for v in bound_invX]
    for a in bound_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    return w


def run_per_query_mapped(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                         flat_cols, held_cols, tk_cells, tn_cells, sk_cells, sn_cells,
                         root, nf, cm_out, trans_a, qf_trans, bound_invX, bound_a, qfri):
    """Run the mapped per-query core on cashvm; (True, op_cost) if the query verifies end-to-end from
    the leaf-order opened cells (clean stack [1]), (False, 0) on a fail-closed reject."""
    vm = VM()
    try:
        vm.run(_field_prelude()
               + per_query_mapped_unlock(tk_cells, tn_cells, sk_cells, sn_cells,
                                         trans_a, qf_trans, bound_invX, bound_a)
               + per_query_mapped_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                                       flat_cols, held_cols, root, nf, cm_out, qfri))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except VMError:
        return False, 0


def per_query_bound_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                         flat_cols, held_cols, depth, tp_root, sel_root, root, nf, cm_out, qfri):
    """HP2 (2.31c-ii-open-b-feed): the FULLY-BOUND per-query verify. Opens all four leaves (roots
    PINNED) so cur/nxt/pub_x/w_next are Merkle-bound, then runs the mapped core over the opened cells.
    The unlock pushes [composition extras(E), the four leaf witness blocks W(4*(depth+2))];
    open_all_leaves_prog(below=E) opens the leaves producing the 170 cells at base E+4*WB in leaf order;
    the field prelude is installed (the openers ran pre-prelude with a free alt); _mapped_core_stages
    reads the cells (cell_base=E+4*WB) + the extras (extras_base=0), pins root/nf/cm_out, binds comp to
    the FRI layer-0 leaf and folds; the cleanup drops the whole witness -> [1]. Reuses
    open_all_leaves_prog + _mapped_core_stages (DRY, the same core the 2.31c-ii per_query_mapped_prog
    uses). A tampered leaf fails the baked-root open; a tampered cell -> comp != FRI layer-0
    (fail-closed). Only the composition extras (alphas/qf/bound_invX) + qfri remain witness/baked -- their
    on-chain derivation is 2.31c-iii."""
    NT = len(flat_cols); NS = len(_SEL_ORDER)
    n_cells = 2 * NT + 2 * NS
    n_t = 4 * WIDTH + len(minv_cap_rows) + 10
    n_b = 2 + n_out + sum(1 + (1 if has_cmbind else 0) for _, has_cmbind in range_spec) + 1
    E = 2 * n_t + 1 + n_b + 2 * n_b
    WB = depth + 2
    cell_base = E + 4 * WB                                       # extras(E) + spent opener witness(4*WB)
    prog = open_all_leaves_prog(depth, tp_root, sel_root, NT, NS, below=E)   # 170 cells at [cell_base ..]
    prog += _field_prelude()
    prog += _mapped_core_stages(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                                flat_cols, held_cols, root, nf, cm_out, qfri,
                                cell_base=cell_base, extras_base=0, total_below=cell_base + n_cells)
    return prog


def per_query_bound_unlock(trans_a, qf_trans, bound_invX, bound_a,
                           tk_pre, tk_path, k, tn_pre, tn_path, kn, sk_pre, sk_path, sn_pre, sn_path):
    """Push-only witness for per_query_bound_prog: the composition extras (trans_a pairs, qf,
    bound_invX, bound_a pairs) at the bottom, then the four leaf opener blocks (open_all_leaves_unlock).
    The trace/selector roots and the public root/nf/cm_out are baked in the redeem, not pushed."""
    w = []
    for a in trans_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    w += [NUM(qf_trans % P)]
    w += [NUM(v % P) for v in bound_invX]
    for a in bound_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    w += open_all_leaves_unlock(tk_pre, tk_path, k, tn_pre, tn_path, kn, sk_pre, sk_path, sn_pre, sn_path)
    return w


def run_per_query_bound(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                        flat_cols, held_cols, depth, tp_root, sel_root, root, nf, cm_out,
                        trans_a, qf_trans, bound_invX, bound_a,
                        tk_pre, tk_path, k, tn_pre, tn_path, kn, sk_pre, sk_path, sn_pre, sn_path, qfri):
    """Run the fully-bound per-query verify on cashvm; (True, op_cost) if the query verifies end-to-end
    from the Merkle-opened cells (clean stack [1]), (False, 0) on a fail-closed reject (a tampered leaf
    fails the baked-root open, a tampered cell -> comp != FRI layer-0)."""
    vm = VM()
    try:
        vm.run(per_query_bound_unlock(trans_a, qf_trans, bound_invX, bound_a,
                                      tk_pre, tk_path, k, tn_pre, tn_path, kn, sk_pre, sk_path, sn_pre, sn_path)
               + per_query_bound_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                                      flat_cols, held_cols, depth, tp_root, sel_root, root, nf, cm_out, qfri))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except VMError:
        return False, 0


def per_query_bound_fs_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols,
                            held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out, fri_roots,
                            nonce, N, n_queries, qfri, query_i=0):
    """HP2 (2.31c-iii-b-mono part 2c): per-query verify with the OPENED POSITIONS bound to the FS
    transcript -- the openers run at the FS-DERIVED k/kn (open_all_leaves_fs), then the mapped core
    consumes the opened cells. A prover cannot open a favourable query/row (k/kn are transcript-derived,
    not witness). The unlock pushes [extras(E), opener witness(4*(depth+1))]; open_all_leaves_fs
    (below=E) derives k/kn from the transcript and opens the four leaves -> 170 cells at cell_base; the
    field prelude is installed; the mapped core reads the cells (cell_base) + the composition extras
    (extras_base=0), pins root/nf/cm_out, binds comp to FRI layer-0 and folds; the cleanup drops the
    whole witness -> [1]. Reuses open_all_leaves_fs_prog + _mapped_core_stages (DRY). The composition
    extras (alphas/qf/bound_invX) are still witness here; deriving them from the SAME transcript (the
    FS output is already on the stack) is the final zero-free-witness step."""
    NT = len(flat_cols); NS = len(_SEL_ORDER)
    n_cells = 2 * NT + 2 * NS
    n_t = 4 * WIDTH + len(minv_cap_rows) + 10
    n_b = 2 + n_out + sum(1 + (1 if has_cmbind else 0) for _, has_cmbind in range_spec) + 1
    E = 2 * n_t + 1 + n_b + 2 * n_b
    WB = depth + 1
    fs_out = 2 * (n_t + n_b) + 2 * _fs_n_betas(fri_roots, N) + n_queries + 1
    cell_base = E + 4 * WB + fs_out + 2                          # extras(E) + opener_W(4*WB) + FS-out + [k,kn]
    prog = open_all_leaves_fs_prog(depth, sel_root, NT, NS, shift, n_t, n_b, tp_root, root, nf, cm_out,
                                   fri_roots, nonce, N, n_queries, query_i, below=E)
    prog += _field_prelude()
    prog += _mapped_core_stages(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                                flat_cols, held_cols, root, nf, cm_out, qfri,
                                cell_base=cell_base, extras_base=0, total_below=cell_base + n_cells)
    return prog


def per_query_bound_fs_unlock(trans_a, qf_trans, bound_invX, bound_a,
                              tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path):
    """Push-only witness for per_query_bound_fs_prog: the composition extras (trans_a pairs, qf,
    bound_invX, bound_a pairs) at the bottom, then the four leaf [sibs, preimage] blocks (NO index --
    k/kn are FS-derived). The trace/selector roots + root/nf/cm_out are baked."""
    w = []
    for a in trans_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    w += [NUM(qf_trans % P)]
    w += [NUM(v % P) for v in bound_invX]
    for a in bound_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    w += open_all_leaves_fs_unlock(tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path)
    return w


def run_per_query_bound_fs(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols,
                           held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out, fri_roots,
                           nonce, N, n_queries, trans_a, qf_trans, bound_invX, bound_a,
                           tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path, qfri, query_i=0):
    """Run the position-bound per-query verify on cashvm; (True, op_cost) if the query verifies from the
    FS-index-opened cells (clean stack [1]), (False, 0) on a fail-closed reject (an opener at the wrong
    FS index, a tampered cell -> comp != FRI layer-0)."""
    vm = VM()
    try:
        vm.run(per_query_bound_fs_unlock(trans_a, qf_trans, bound_invX, bound_a,
                                         tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path)
               + per_query_bound_fs_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                                         flat_cols, held_cols, depth, sel_root, shift, tp_root, root, nf,
                                         cm_out, fri_roots, nonce, N, n_queries, qfri, query_i))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except VMError:
        return False, 0


def comp_preimage(comp0, comp1):
    """HP3.5b-iii-2: the 16-byte compose-value commitment = enc8(comp0) + enc8(comp1) (two 8-byte LE limbs).
    The compose-INPUT (producer) binds this to its on-chain-computed comp; the consumer FRI-input reads it via
    OP_INPUTBYTECODE and binds comp==FRI-layer-0 (iii-3). split_cells_prog(2, prefix=0) recovers the two limbs."""
    return enc8(comp0 % P) + enc8(comp1 % P)


def compose_producer_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols,
                          held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out, fri_roots,
                          nonce, N, n_queries, qfri, query_i=0, compose_looped=False,
                          sbox_looped=False, state_looped=False):
    """HP3.5b-iii-2 compose-INPUT (thin-shard producer): open the four leaves at the FS-derived k/kn, run the
    mapped core A/B/C to COMPUTE comp=(comp0,comp1) from the opened cells (== verify's comp_x), then BIND comp
    to the 16-byte comp_preimage at the bottom of the unlock (producer pattern, iii-3) -- NO FRI fold (the FRI
    is a separate input, cross-linked by the consumer reading comp_preimage == FRI-layer-0). The unlock is
    [comp_preimage(16B)@0, composition extras(E), four leaf [sibs,preimage] blocks (4*(depth+1))]; comp_out=True
    routes stage D to _comp_producer_bind_prog. Same layout as per_query_bound_fs_prog with everything shifted
    +1 for comp_preimage@0 (extras_base=1, opener below=1+E). Leaves [1] on accept; a forged comp_preimage, a
    tampered opened cell (-> comp mismatch), or a wrong FS index reject (fail-closed). qfri is unused in the
    comp_out path (no fold); passed for _mapped_core_stages signature compatibility."""
    NT = len(flat_cols); NS = len(_SEL_ORDER)
    n_cells = 2 * NT + 2 * NS
    n_t = 4 * WIDTH + len(minv_cap_rows) + 10
    n_b = 2 + n_out + sum(1 + (1 if has_cmbind else 0) for _, has_cmbind in range_spec) + 1
    E = 2 * n_t + 1 + n_b + 2 * n_b
    WB = depth + 1
    fs_out = 2 * (n_t + n_b) + 2 * _fs_n_betas(fri_roots, N) + n_queries + 1
    cell_base = 1 + E + 4 * WB + fs_out + 2                      # comp_preimage(1) + extras(E) + opener_W(4*WB) + FS-out + [k,kn]
    prog = open_all_leaves_fs_prog(depth, sel_root, NT, NS, shift, n_t, n_b, tp_root, root, nf, cm_out,
                                   fri_roots, nonce, N, n_queries, query_i, below=1 + E)
    prog += _field_prelude()
    if compose_looped:                                          # HP10.5: DEFINE the 4 fold bodies ONCE (this input's entry)
        prog += compose_feed_loop_defines(n_t, n_b)
    if sbox_looped:                                            # HP10.5: DEFINE the uniform S-box body once (this input's entry)
        prog += stagea_sbox_define()
    if state_looped:                                           # HP10.5: DEFINE the uniform state body once (this input's entry)
        prog += stagea_state_define()
    prog += _mapped_core_stages(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                                flat_cols, held_cols, root, nf, cm_out, qfri,
                                cell_base=cell_base, extras_base=1, total_below=cell_base + n_cells,
                                comp_out=True, compose_looped=compose_looped,
                                sbox_looped=sbox_looped, state_looped=state_looped)
    return prog


def compose_producer_unlock(comp_pre, trans_a, qf_trans, bound_invX, bound_a,
                            tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path):
    """Push-only witness for compose_producer_prog: the 16-byte comp_preimage at the BOTTOM, then the
    composition extras (trans_a pairs, qf, bound_invX, bound_a pairs), then the four leaf [sibs, preimage]
    blocks (k/kn FS-derived). Mirrors per_query_bound_fs_unlock + comp_preimage@0. Roots/root/nf/cm_out baked."""
    w = [PUSH(comp_pre)]
    for a in trans_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    w += [NUM(qf_trans % P)]
    w += [NUM(v % P) for v in bound_invX]
    for a in bound_a:
        w += [NUM(a[0] % P), NUM(a[1] % P)]
    w += open_all_leaves_fs_unlock(tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path)
    return w


def run_compose_producer(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols,
                         held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out, fri_roots,
                         nonce, N, n_queries, comp_pre, trans_a, qf_trans, bound_invX, bound_a,
                         tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path, qfri, query_i=0,
                         compose_looped=False, sbox_looped=False, state_looped=False):
    """Run the compose-INPUT (producer) on cashvm; (True, op_cost) if the query's comp is computed from the
    FS-index-opened cells and matches the bound comp_preimage (clean stack [1]), (False, 0) on a fail-closed
    reject (forged comp_preimage, tampered cell -> comp mismatch, or wrong FS index)."""
    vm = VM()
    try:
        vm.run(compose_producer_unlock(comp_pre, trans_a, qf_trans, bound_invX, bound_a,
                                       tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path)
               + compose_producer_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols,
                                       held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out, fri_roots,
                                       nonce, N, n_queries, qfri, query_i, compose_looped=compose_looped,
                                       sbox_looped=sbox_looped, state_looped=state_looped))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except VMError:
        return False, 0


def per_query_full_fs_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols,
                           held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out, fri_roots,
                           nonce, N, n_queries, qfri, oN, off, T, last, hd_vals, query_i=0, prelude=True,
                           deployable=False, final=None, sbox_looped=False, state_looped=False,
                           fri_looped=False):
    """HP2 (2.31c-iii-b-mono part 2c-ii): the ZERO-free-witness per-query verify -- the composition
    extras are DERIVED, not witness. open_all_leaves_fs runs the FS transcript ONCE (pre-prelude) and
    thereby puts BOTH the query index k (for the openers) AND the GF(p^2) alphas (the FS output) on the
    stack; the four leaves open at the FS-derived k/kn (positions transcript-bound). After the field
    prelude, x=Dd[k] is derived (fri_xpos_prog li=0) and qf_bound_from_stack derives qf_trans +
    bound_invX -- the ONLY remaining witness are the inverse-constrained hints (zh_inv, bound_invX), each
    forced to the unique inverse by NUMEQUALVERIFY, so a prover cannot choose a favourable normalizer.
    The mapped core then composes with a MULTI-SOURCE extras feed: trans_v/bound_v computed on-chain, the
    alphas from the FS output, qf/bound_invX from the derived qf_bound; comp is bound to the FRI layer-0
    leaf and folded. Nothing in the composition is free witness -- the alphas are Frozen-Heart bound to
    the pinned statement, k is transcript-bound, qf/inverses are inverse-constrained. Reuses
    open_all_leaves_fs_prog + fri_xpos_prog + qf_bound_from_stack_prog + _mapped_core_stages (DRY; emits
    no raw arithmetic). The unlock pushes only [zh_inv, bound_invX(n_b), opener witness(4*(depth+1))].
    (The FRI qfri is still baked/bound here; deriving the FRI betas is the separate 2.23-2.29 step.)
    deployable=True (final = proof's final FRI layer) threads the DEPLOYABLE FRI chain into stage D
    (derived index-selection + Merkle-bound v/w openings, 2.36-2.38 at the shard level) instead of the
    baked qfri comp_tgt/fold_tgt; the unlock is unchanged (the FRI openings are inline in the redeem, the
    witness-in-unlock byte split is 3.5b-iii). Default deployable=False keeps the baked chain (the shard
    aggregation still uses it; the shard switch-over is 3.5b-ii)."""
    NT = len(flat_cols); NS = len(_SEL_ORDER)
    n_cells = 2 * NT + 2 * NS
    n_t = 4 * WIDTH + len(minv_cap_rows) + 10
    n_b = 2 + n_out + sum(1 + (1 if has_cmbind else 0) for _, has_cmbind in range_spec) + 1
    E = 2 * n_t + 1 + n_b + 2 * n_b
    m = len(hd_vals)
    assert m == n_b, "qf_bound hd_vals (%d) must match n_b (%d)" % (m, n_b)
    HB = n_b + 1                                                # hints block: zh_inv + bound_invX(n_b)
    WB = depth + 1                                              # sibs(depth) + preimage per leaf (no index)
    fs_out = 2 * (n_t + n_b) + 2 * _fs_n_betas(fri_roots, N) + n_queries + 1
    FS_base = HB + 4 * WB                                       # start of the FS output (alphas first)
    cell_base = HB + 4 * WB + fs_out + 2                        # hints + opener_W + FS-out + [k,kn]
    D0 = cell_base + n_cells                                    # main depth after openers + prelude (P->alt)
    total_below = D0 + n_b + 1                                  # + the derived [qf_trans, bound_invX] block
    extras_src = ([FS_base + 2 * j + c for j in range(n_t) for c in (0, 1)]        # trans_a pairs (FS output)
                  + [D0]                                                            # qf_trans (derived)
                  + [D0 + 1 + b for b in range(n_b)]                               # bound_invX (derived)
                  + [FS_base + 2 * n_t + 2 * b + c for b in range(n_b) for c in (0, 1)])  # bound_a pairs (FS)
    assert len(extras_src) == E, "extras_src=%d != E=%d" % (len(extras_src), E)
    prog = open_all_leaves_fs_prog(depth, sel_root, NT, NS, shift, n_t, n_b, tp_root, root, nf, cm_out,
                                   fri_roots, nonce, N, n_queries, query_i, below=HB)
    if prelude:
        prog += _field_prelude()                                # shard aggregation installs it ONCE (prelude=False)
        if sbox_looped:                                        # HP10.5: standalone (prelude=True) installs the stage-A
            prog += stagea_sbox_define()                      # DEFINEs here; when run from the shard (prelude=False) the
        if state_looped:                                      # shard installs them at its entry (no per-query collision)
            prog += stagea_state_define()
        if fri_looped:                                         # HP3.10 F1: standalone installs the FRI-loop DEFINEs
            prog += fri_loop_defines(oN, off)                 # (0x04/0x05) here; the shard hoists them at its entry
    sp = [D0]                                                   # derive qf_trans + bound_invX from x=Dd[k]

    def copy(p): prog.extend([NUM(sp[0] - 1 - p), OP("PICK")]); sp[0] += 1

    copy(0)                                                     # zh_inv (inverse-constrained hint)
    for r in range(n_b):
        copy(1 + r)                                            # bound_invX_r (inverse-constrained hint)
    copy(cell_base - 2)                                         # k = idx_{query_i} (FS-derived on the stack)
    prog += fri_xpos_prog(oN, off, 0)                          # k -> x = Dd[k]  (net 0)
    prog += qf_bound_from_stack_prog(T, last, hd_vals, below=D0)   # -> [qf_trans, bound_invX_0..] at D0
    if deployable:
        assert final is not None, "deployable per-query verify needs the proof's final FRI layer"
    prog += _mapped_core_stages(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                                flat_cols, held_cols, root, nf, cm_out, qfri,
                                cell_base=cell_base, extras_base=0, total_below=total_below,
                                extras_src=extras_src, deployable_final=(final if deployable else None),
                                sbox_looped=sbox_looped, state_looped=state_looped,
                                fri_looped=fri_looped, oN=oN, off=off)
    return prog


def per_query_full_fs_unlock(zh_inv, bound_invX, tk_pre, tk_path, tn_pre, tn_path,
                             sk_pre, sk_path, sn_pre, sn_path):
    """Push-only witness for per_query_full_fs_prog: the inverse-constrained hints [zh_inv,
    bound_invX(n_b)] at the bottom, then the four leaf [sibs, preimage] blocks (NO index, NO alpha, NO
    qf -- k/kn are FS-derived, the alphas are FS-derived, qf is derived from x=Dd[k]). The trace/selector
    roots + root/nf/cm_out are baked in the redeem, not pushed."""
    return ([NUM(zh_inv % P)] + [NUM(v % P) for v in bound_invX]
            + open_all_leaves_fs_unlock(tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path))


def run_per_query_full_fs(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols,
                          held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out, fri_roots,
                          nonce, N, n_queries, qfri, oN, off, T, last, hd_vals, zh_inv, bound_invX,
                          tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path, query_i=0,
                          deployable=False, final=None, sbox_looped=False, state_looped=False):
    """Run the zero-free-witness per-query verify on cashvm; (True, op_cost) if the query verifies with
    ALL composition extras derived (clean stack [1]), (False, 0) on a fail-closed reject (a wrong inverse
    hint fails qf_bound's NUMEQUALVERIFY; a tampered leaf fails the baked-root open; a wrong FS index
    mismatches the opened positions)."""
    vm = VM()
    try:
        vm.run(per_query_full_fs_unlock(zh_inv, bound_invX, tk_pre, tk_path, tn_pre, tn_path,
                                        sk_pre, sk_path, sn_pre, sn_path)
               + per_query_full_fs_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                                        flat_cols, held_cols, depth, sel_root, shift, tp_root, root, nf,
                                        cm_out, fri_roots, nonce, N, n_queries, qfri, oN, off, T, last,
                                        hd_vals, query_i, deployable=deployable, final=final,
                                        sbox_looped=sbox_looped, state_looped=state_looped))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except VMError:
        return False, 0


def compose_producer_full_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols,
                               held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out, fri_roots,
                               nonce, N, n_queries, qfri, oN, off, T, last, hd_vals, query_i=0, prelude=True,
                               compose_looped=False, sbox_looped=False, state_looped=False):
    """HP3.5b-iii-2 DEPLOYABLE compose-INPUT (zero-free-witness alphas, Frozen-Heart -- agent OBS-1 fix). Like
    compose_producer_prog but the composition extras are DERIVED, not free witness: mirrors per_query_full_fs_prog
    (2c-ii) -- the GF(p^2) alphas come from the FS output (open_all_leaves_fs runs the transcript once), and
    qf_trans + bound_invX are derived from x=Dd[k] via qf_bound_from_stack (the only witness are the
    inverse-constrained hints zh_inv/bound_invX, each forced to the unique inverse by NUMEQUALVERIFY). A prover
    thus CANNOT choose favourable alphas -- they are Frozen-Heart-bound to the pinned statement. comp_out=True with
    comp_k_pos=cell_base-2 binds the computed comp + the FS-derived query index k to the 24-byte comp_preimage@0 =
    fri_carry_preimage(comp0,comp1,k) (producer, iii-3 Option C) instead of folding the FRI. Layout = the
    per_query_full_fs layout with EVERYTHING shifted +1 for comp_preimage@0 (openers below=1+HB, FS_base/cell_base
    +1, hint copies +1). Unlock = [comp_preimage(24B)@0, zh_inv, bound_invX(n_b), opener witness (4*(depth+1))].
    Leaves [1] on accept; a forged comp_preimage (comp OR k limb), a wrong inverse hint, a tampered leaf, or a wrong
    FS index reject (fail-closed). The consumer FRI-input reads the 24B comp_preimage, split_cells(3)s it, and USES
    (comp0,comp1) as carry_val + k as carry_idx (fri_partial_witness_redeem carry_split) -- comp threaded as a FIELD
    value (OBS-2), k transcript-bound (FS-2). This is the deploy-sound compose-INPUT (replaces compose_producer's
    free-witness alphas)."""
    NT = len(flat_cols); NS = len(_SEL_ORDER)
    n_cells = 2 * NT + 2 * NS
    n_t = 4 * WIDTH + len(minv_cap_rows) + 10
    n_b = 2 + n_out + sum(1 + (1 if has_cmbind else 0) for _, has_cmbind in range_spec) + 1
    E = 2 * n_t + 1 + n_b + 2 * n_b
    assert len(hd_vals) == n_b, "qf_bound hd_vals (%d) must match n_b (%d)" % (len(hd_vals), n_b)
    HB = n_b + 1                                                # hints: zh_inv + bound_invX(n_b)
    WB = depth + 1
    fs_out = 2 * (n_t + n_b) + 2 * _fs_n_betas(fri_roots, N) + n_queries + 1
    FS_base = 1 + HB + 4 * WB                                   # +1 for comp_preimage@0 (start of FS output = alphas)
    cell_base = 1 + HB + 4 * WB + fs_out + 2                    # comp_preimage + hints + opener_W + FS-out + [k,kn]
    D0 = cell_base + n_cells
    total_below = D0 + n_b + 1                                  # + the derived [qf_trans, bound_invX] block
    extras_src = ([FS_base + 2 * j + c for j in range(n_t) for c in (0, 1)]        # trans_a pairs (FS output)
                  + [D0]                                                            # qf_trans (derived)
                  + [D0 + 1 + b for b in range(n_b)]                               # bound_invX (derived)
                  + [FS_base + 2 * n_t + 2 * b + c for b in range(n_b) for c in (0, 1)])  # bound_a pairs (FS)
    assert len(extras_src) == E, "extras_src=%d != E=%d" % (len(extras_src), E)
    prog = open_all_leaves_fs_prog(depth, sel_root, NT, NS, shift, n_t, n_b, tp_root, root, nf, cm_out,
                                   fri_roots, nonce, N, n_queries, query_i, below=1 + HB)   # +1 comp_preimage
    if prelude:
        prog += _field_prelude()
    if compose_looped:                                         # HP10.5: DEFINE the 4 fold bodies once (this input's entry)
        prog += compose_feed_loop_defines(n_t, n_b)
    if sbox_looped:                                            # HP10.5: DEFINE the uniform S-box body once (this input's entry)
        prog += stagea_sbox_define()
    if state_looped:                                           # HP10.5: DEFINE the uniform state body once (this input's entry)
        prog += stagea_state_define()
    sp = [D0]                                                   # derive qf_trans + bound_invX from x=Dd[k]

    def copy(p): prog.extend([NUM(sp[0] - 1 - p), OP("PICK")]); sp[0] += 1

    copy(1)                                                     # zh_inv (abs 1, above comp_preimage@0)
    for r in range(n_b):
        copy(2 + r)                                            # bound_invX_r (abs 2+r)
    copy(cell_base - 2)                                         # k = idx_{query_i} (FS-derived)
    prog += fri_xpos_prog(oN, off, 0)                          # k -> x = Dd[k]
    prog += qf_bound_from_stack_prog(T, last, hd_vals, below=D0)   # -> [qf_trans, bound_invX] at D0
    prog += _mapped_core_stages(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                                flat_cols, held_cols, root, nf, cm_out, qfri,
                                cell_base=cell_base, extras_base=0, total_below=total_below,
                                extras_src=extras_src, comp_out=True, comp_k_pos=cell_base - 2,   # 3-limb: bind k@cell_base-2
                                compose_looped=compose_looped,
                                sbox_looped=sbox_looped, state_looped=state_looped)
    return prog


def compose_producer_full_unlock(comp_pre, zh_inv, bound_invX, tk_pre, tk_path, tn_pre, tn_path,
                                 sk_pre, sk_path, sn_pre, sn_path):
    """Push-only witness for compose_producer_full_prog: [comp_preimage(24B)=fri_carry_preimage(comp0,comp1,k)@0,
    zh_inv, bound_invX(n_b), four leaf [sibs, preimage] blocks]. NO alpha/qf witness (all derived); k/kn FS-derived;
    roots/root/nf/cm_out baked. comp_pre carries comp AND the FS-derived k (3 limbs) for the consumer's carry_split."""
    return ([PUSH(comp_pre), NUM(zh_inv % P)] + [NUM(v % P) for v in bound_invX]
            + open_all_leaves_fs_unlock(tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path))


def run_compose_producer_full(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols,
                              held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out, fri_roots,
                              nonce, N, n_queries, qfri, oN, off, T, last, hd_vals, comp_pre, zh_inv,
                              bound_invX, tk_pre, tk_path, tn_pre, tn_path, sk_pre, sk_path, sn_pre, sn_path,
                              query_i=0, compose_looped=False, sbox_looped=False, state_looped=False):
    """Run the deployable compose-INPUT (FS-derived alphas) on cashvm; (True, op_cost) if comp is computed from
    the FS-index-opened cells with FS-derived extras and matches the bound comp_preimage (clean [1]), (False, 0)
    on a fail-closed reject (forged comp_preimage, wrong inverse hint, tampered cell, or wrong FS index)."""
    vm = VM()
    try:
        vm.run(compose_producer_full_unlock(comp_pre, zh_inv, bound_invX, tk_pre, tk_path, tn_pre, tn_path,
                                            sk_pre, sk_path, sn_pre, sn_path)
               + compose_producer_full_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols,
                                            held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out,
                                            fri_roots, nonce, N, n_queries, qfri, oN, off, T, last, hd_vals,
                                            query_i, compose_looped=compose_looped,
                                            sbox_looped=sbox_looped, state_looped=state_looped))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except VMError:
        return False, 0


def shard_verify_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols,
                      held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out, fri_roots, nonce,
                      N, n_queries, qfris, oN, off, T, last, hd_vals, deployable=False, final=None,
                      sbox_looped=False, state_looped=False, fri_looped=False):
    """HP2 (2.31b): the FULL shard -- aggregate the zero-free-witness per-query verify (per_query_full_fs)
    over ALL nq queries at their FS-DERIVED indices, binding the query count. This is the round-5
    soundness fix: verify() draws nq indices and rejects unless every query sits at one (verify():239-241,
    244); binding only ONE query would collapse the soundness margin (100 -> ~20 bit). Query i is verified
    at idx_i (FS-derived by query_i=i, not witness) so a prover cannot choose which rows to open, and all
    nq are covered. Each per-query prog leaves [1] on accept (VMError on reject, fail-closed); NUM(1)
    NUMEQUALVERIFY asserts it == 1 and clears the accept bit so the next query's witness is on top --
    per_query_full_fs's PICKs are top-relative, so no below-threading is needed and per_query_full_fs is
    reused UNCHANGED (DRY). The count is PINNED (nq unrolled progs): too few witness blocks underflow the
    last opener, too many leave a non-clean stack -- both reject (fail-closed count binding, exactly like
    merkle_verify_loop_prog). qfris = the nq per-query FRI terms. deployable=True (final = the proof's final
    FRI layer) runs each per-query via the deployable FRI chain (derived index-selection + Merkle-bound
    openings) -> 2.36-2.38 at the SHARD level; default deployable=False keeps the baked qfri targets
    (logic-test regression). Leaves [1] iff all nq queries verify.
    NOTE: cashvm models algorithmic correctness + stack consistency, NOT the per-input byte/cost budget;
    the byte-amortized loop form (ONE OP_BEGIN/UNTIL body with a runtime index + the FS run once shared)
    is HP3 (3.10). Here the unrolled form proves the multi-query aggregation LOGIC + count binding."""
    assert len(qfris) == n_queries, "qfris (%d) != n_queries (%d)" % (len(qfris), n_queries)
    prog = _field_prelude()                                     # define the field fns + P on alt ONCE (a
    if sbox_looped:                                            # HP10.5: stage-A bodies DEFINE'd at the shard ENTRY (next to
        prog += stagea_sbox_define()                          # the prelude) -- assemble_transition runs PER-QUERY, so a
    if state_looped:                                           # per-call DEFINE would collide at query 2 (duplicate fid)
        prog += stagea_state_define()
    if fri_looped:                                             # HP3.10 F1: hoist the FRI-loop DEFINEs (0x04/0x05) to the
        prog += fri_loop_defines(oN, off)                     # shard ENTRY -- _fri_loop_chain_body runs per-query, so a
    for i in range(n_queries):                                  # per-call DEFINE would collide at query 2 (second define would fail; P stays resident)
        prog += per_query_full_fs_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                                       flat_cols, held_cols, depth, sel_root, shift, tp_root, root, nf,
                                       cm_out, fri_roots, nonce, N, n_queries, qfris[i], oN, off, T, last,
                                       hd_vals, query_i=i, prelude=False, deployable=deployable, final=final,
                                       sbox_looped=sbox_looped, state_looped=state_looped, fri_looped=fri_looped)
        if i < n_queries - 1:
            prog += [NUM(1), OP("NUMEQUALVERIFY")]              # assert query i accepted (==1) and clear
    return prog


def shard_verify_unlock(query_blocks):
    """Push-only witness for shard_verify_prog: the nq per-query witness blocks (each from
    per_query_full_fs_unlock) with query 0 on TOP (it is verified first) -- so pushed in reverse (query
    nq-1 at the bottom). Each block = [zh_inv, bound_invX(n_b), opener witness(4*(depth+1))]."""
    w = []
    for blk in reversed(query_blocks):
        w += blk
    return w


def run_shard_verify(diag, minv_cap_rows, minv0_row, n_out, range_spec, flat_cols, held_cols,
                     depth, sel_root, shift, tp_root, root, nf, cm_out, fri_roots, nonce, N, n_queries,
                     qfris, oN, off, T, last, hd_vals, query_blocks, deployable=False, final=None,
                     sbox_looped=False, state_looped=False):
    """Run the full multi-query shard verify on cashvm; (True, op_cost) if ALL nq queries verify at their
    FS-derived indices with a clean stack [1], (False, 0) on a fail-closed reject (a bad query, or a
    witness-block count != nq -> underflow / non-clean stack)."""
    vm = VM()
    try:
        vm.run(shard_verify_unlock(query_blocks)
               + shard_verify_prog(diag, minv_cap_rows, minv0_row, n_out, range_spec,
                                   flat_cols, held_cols, depth, sel_root, shift, tp_root, root, nf, cm_out,
                                   fri_roots, nonce, N, n_queries, qfris, oN, off, T, last, hd_vals,
                                   deployable=deployable, final=final,
                                   sbox_looped=sbox_looped, state_looped=state_looped))
        return (len(vm.s) == 1 and decode_num(vm.s[-1]) != 0), vm.op_cost
    except (VMError, IndexError):                              # too-few witness blocks underflow the last
        return False, 0                                       # opener (out-of-range PICK) -> fail-closed reject


# ---- HP4: translate the tested cashvm token programs to libauth CashAssembly ---------
# The cashvm token program IS the validated logic; for the on-VM byte measurement (AK1)
# the SAME tokens are emitted as CashAssembly and assembled by libauth (cashAssemblyToBin).
# Direct opcode map -> no hand-transcription, so the measured program is exactly the tested
# one. The field functions use OP_DEFINE/OP_INVOKE (verified live in libauth's BCH-2026
# instruction set, bch-2026-functions.js): defining the MULMOD/ADDMOD/SUBMOD table once and
# invoking it is far smaller than inlining the 10-op NORM_TAIL at every field op, so the
# deployable shard keeps the function table (inlining stays only a fallback if a target VM
# lacks functions).
_OP2ASM = {
    "MUL": "OP_MUL", "ADD": "OP_ADD", "SUB": "OP_SUB", "MOD": "OP_MOD", "DIV": "OP_DIV",
    "1ADD": "OP_1ADD", "1SUB": "OP_1SUB", "NEGATE": "OP_NEGATE",
    "SHA256": "OP_SHA256", "HASH256": "OP_HASH256", "CAT": "OP_CAT", "SPLIT": "OP_SPLIT",
    "BIN2NUM": "OP_BIN2NUM",
    "SIZE": "OP_SIZE", "DUP": "OP_DUP", "DROP": "OP_DROP", "2DROP": "OP_2DROP",
    "SWAP": "OP_SWAP", "OVER": "OP_OVER", "ROT": "OP_ROT", "NIP": "OP_NIP", "TUCK": "OP_TUCK",
    "2DUP": "OP_2DUP", "DEPTH": "OP_DEPTH", "PICK": "OP_PICK", "ROLL": "OP_ROLL",
    "TOALT": "OP_TOALTSTACK", "FROMALT": "OP_FROMALTSTACK",
    "EQUAL": "OP_EQUAL", "EQUALVERIFY": "OP_EQUALVERIFY", "VERIFY": "OP_VERIFY",
    "NUMEQUAL": "OP_NUMEQUAL", "NUMEQUALVERIFY": "OP_NUMEQUALVERIFY",
    "NOT": "OP_NOT", "0NOTEQUAL": "OP_0NOTEQUAL", "LESSTHAN": "OP_LESSTHAN",
    "GREATERTHAN": "OP_GREATERTHAN", "BOOLAND": "OP_BOOLAND",
    "BEGIN": "OP_BEGIN", "UNTIL": "OP_UNTIL", "IF": "OP_IF", "ELSE": "OP_ELSE",
    "ENDIF": "OP_ENDIF", "INVOKE": "OP_INVOKE",
}


def tokens_to_asm(tokens):
    """Emit a cashvm token program as a libauth CashAssembly string (assembled with
    cashAssemblyToBin in the HP4 harness). A cashvm DEFINE bakes the body into the token and
    pushes only the function id; libauth OP_DEFINE instead consumes the body as on-stack
    bytecode -- it pops the id (top), then the body (second). The faithful emission is thus
    `<body> OP_SWAP OP_DEFINE`: the preceding PUSH(id) leaves the id on top, the body's
    compiled bytecode is pushed via the CashAssembly `<...>` push (verified on the real BCH-
    2026 VM: `<...>` pushes the assembled bytecode, not its evaluation), OP_SWAP reorders to
    [body, id], and OP_DEFINE registers byte-for-byte the same function table the tested token
    program builds (same duplicate-id rejection). The bodies used here (MULMOD/ADDMOD/SUBMOD)
    are pure-opcode, so the recursive emit needs no nested `<...>`. Raises if a token has no
    mapping."""
    parts = []
    for t in tokens:
        k = t[0]
        if k == "PUSH":
            parts.append("OP_0" if len(t[1]) == 0 else "<0x%s>" % t[1].hex())
        elif k == "PUSHN":
            e = encode_num(t[1])
            parts.append("OP_0" if len(e) == 0 else "<0x%s>" % e.hex())
        elif k == "DEFINE":
            parts.append("<%s> OP_SWAP OP_DEFINE" % tokens_to_asm(t[1].tokens))
        elif k in _OP2ASM:
            parts.append(_OP2ASM[k])
        else:
            raise ValueError("no CashAssembly mapping for token %r" % (t,))
    return " ".join(parts)


def _ref_sbox_residuals(s, rc, u2, u4, u6, gate):
    """Reference residuals (the on-chain program must reproduce these exactly)."""
    u = (s + rc) % P
    return [(gate * ((u2 - u * u) % P)) % P,
            (gate * ((u4 - u2 * u2) % P)) % P,
            (gate * ((u6 - u4 * u2) % P)) % P]


def self_test():
    import native_ct_air_prover as CT
    import native_poseidon2 as P2
    import random
    # --- 1) the VM program matches the reference on random field values ---
    rng = random.Random(0x5B0C)
    for _ in range(50):
        vals = [rng.randrange(0, P) for _ in range(5)] + [rng.choice([0, 1])]
        got, _oc = run_sbox_lane(*vals)
        assert got == _ref_sbox_residuals(*vals), "VM S-box residuals != reference"

    # --- 2) on a REAL Poseidon2 round (full round, lane active) the residuals VANISH;
    #        tampering a committed aux cell makes that residual non-zero (fail-closed) ---
    states, aux = P2.permutation_trace(list(range(P2.WIDTH)))   # KAT input, real trace
    r, lane = 1, 5                                              # round 1 = full, lane 5 active
    s = states[r][lane]; rc = CT.RC[r][lane]
    u2 = aux[r]["x2"][lane]; u4 = aux[r]["x4"][lane]; u6 = aux[r]["x6"][lane]
    got, oc = run_sbox_lane(s, rc, u2, u4, u6, 1)
    assert got == [0, 0, 0], "valid Poseidon2 S-box residuals not all zero: %s" % got
    # tamper u2 -> c_u2 != 0 (the constraint catches a corrupted committed aux)
    gt, _ = run_sbox_lane(s, rc, (u2 + 1) % P, u4, u6, 1)
    assert gt[0] != 0, "tampered u2 not caught by c_u2"
    gt, _ = run_sbox_lane(s, rc, u2, (u4 + 1) % P, u6, 1)
    assert gt[1] != 0, "tampered u4 not caught by c_u4"
    gt, _ = run_sbox_lane(s, rc, u2, u4, (u6 + 1) % P, 1)
    assert gt[2] != 0, "tampered u6 not caught by c_u6"
    # gate=0 (inactive lane / non-round row) -> residuals forced 0 even if aux is wrong
    gz, _ = run_sbox_lane(s, rc, (u2 + 1) % P, (u4 + 1) % P, (u6 + 1) % P, 0)
    assert gz == [0, 0, 0], "gate=0 did not neutralize the residuals"

    # --- HP9.2: GF(p^2) S-box-lane residual (sbox_lane_ext) == native_ct_air_prover._round_residuals_ext.
    #     The DEEP AIR-eval at z runs over GF(p^2) (DEEP_ALI_resolution.md sec 7); cross-check the deploy
    #     GF(p^2) program against the Python GF(p^2) reference on random field elements AND on the shared
    #     _round_residuals_ext (per-lane slice) -- the HP15.11 per-prog VM==Python-GF(p^2) check. ---
    import native_gf_p2 as _F2
    _ev = lambda: (rng.randrange(0, P), rng.randrange(0, P))
    for _ in range(30):                                        # VM Karatsuba stack arithmetic == the ref formula
        s_, rc_, u2_, u4_, u6_, g_ = _ev(), _ev(), _ev(), _ev(), _ev(), _ev()
        got, _oc = run_sbox_lane_ext(s_, rc_, u2_, u4_, u6_, g_)
        x_ = _F2.add(s_, rc_)
        ref = [_F2.mul(g_, _F2.sub(u2_, _F2.mul(x_, x_))),     # exactly _round_residuals_ext:913-915
               _F2.mul(g_, _F2.sub(u4_, _F2.mul(u2_, u2_))),
               _F2.mul(g_, _F2.sub(u6_, _F2.mul(u4_, u2_)))]
        assert got == ref, "VM GF(p^2) S-box residuals != native_gf_p2 reference"
    for _ in range(5):                                         # direct vs the SHARED reference _round_residuals_ext
        WI = P2.WIDTH
        cur_e = {}; nxt_e = {}
        for k in range(WI):
            cur_e["s%d" % k] = _ev(); nxt_e["s%d" % k] = _ev()
            cur_e["u2_%d" % k] = _ev(); cur_e["u4_%d" % k] = _ev(); cur_e["u6_%d" % k] = _ev()
        isf_e, isp_e = _ev(), _ev(); rc_e = [_ev() for _ in range(WI)]
        ref_all = CT._round_residuals_ext(cur_e, nxt_e, isf_e, isp_e, rc_e)
        for k in (0, 5):                                       # lane 0 gate = isf+isp (:912), lane k>0 = isf
            gate_k = _F2.add(isf_e, isp_e) if k == 0 else isf_e
            got, _ = run_sbox_lane_ext(cur_e["s%d" % k], rc_e[k], cur_e["u2_%d" % k],
                                       cur_e["u4_%d" % k], cur_e["u6_%d" % k], gate_k)
            assert got == ref_all[3 * k:3 * k + 3], "sbox_lane_ext lane %d != _round_residuals_ext" % k
    print("HP9.2 GF(p^2) S-box-lane residual == native_gf_p2 / _round_residuals_ext: OK (35 random ext vectors)")

    # --- HP9.2: GF(p^2) state-update residual lane (state_lane_ext) == _ext_apply_ext / _int_apply_ext
    #     (native_ct_air_prover). Random ext y_full/y_part, EVERY lane j; v_j = isf*(sj-ef)+isp*(sj-ip). ---
    for j in range(P2.WIDTH):
        yf = [_ev() for _ in range(P2.WIDTH)]; yp = [_ev() for _ in range(P2.WIDTH)]
        sj_, isf_, isp_ = _ev(), _ev(), _ev()
        ef = CT._ext_apply_ext(yf)[j]; ip = CT._int_apply_ext(yp)[j]
        ref = _F2.add(_F2.mul(isf_, _F2.sub(sj_, ef)), _F2.mul(isp_, _F2.sub(sj_, ip)))
        got, _ = run_state_lane_ext(CT.M_EXT[j], P2.MAT_DIAG12[j], j, yf, yp, sj_, isf_, isp_)
        assert got == ref, "state_lane_ext lane %d != _ext_apply_ext/_int_apply_ext reference" % j
    print("HP9.2 GF(p^2) state-update residual lane == _ext_apply_ext/_int_apply_ext: OK (all %d lanes)" % P2.WIDTH)

    # --- HP9.2: GF(p^2) hold / range / chain transition residuals == native_ct_air_prover *_ext refs
    #     (the rest of ct_transition_residuals_ext; HP15.11 per-prog VM==Python-GF(p^2) checks). ---
    HC = CT.HELD_COLS
    for _ in range(10):
        cv = [_ev() for _ in HC]; nv = [_ev() for _ in HC]
        cur_h = {c: cv[i] for i, c in enumerate(HC)}; nxt_h = {c: nv[i] for i, c in enumerate(HC)}
        got, _ = run_hold_ext(cv, nv)
        assert got == CT._hold_residuals_ext(cur_h, nxt_h), "hold_ext != _hold_residuals_ext"
    for _ in range(20):
        b, cs1, cs2, ns0, ns1, ns2, w = (_ev() for _ in range(7))
        isr, isf, ist, isl = (_ev() for _ in range(4))
        cur_r = {"s0": b, "s1": cs1, "s2": cs2}; nxt_r = {"s0": ns0, "s1": ns1, "s2": ns2}
        got, _ = run_range_ext(b, cs1, cs2, ns0, ns1, ns2, w, isr, isf, ist, isl)
        assert got == CT._range_residuals_ext(cur_r, nxt_r, isr, isf, ist, isl, w), "range_ext != _range_residuals_ext"
    minv_cap = [CT.M_EXT_INV[k] for k in range(P2.RATE, P2.WIDTH)]
    for _ in range(10):
        cs = [_ev() for _ in range(P2.WIDTH)]; ns = [_ev() for _ in range(P2.WIDTH)]
        isbs, isra = _ev(), _ev(); mc = [_ev() for _ in range(P2.WIDTH)]
        cur_c = {"s%d" % j: cs[j] for j in range(P2.WIDTH)}; nxt_c = {"s%d" % j: ns[j] for j in range(P2.WIDTH)}
        got, _ = run_chain_ext(minv_cap, cs, ns, isbs, isra, mc)
        assert got == CT._chain_residuals_ext(cur_c, nxt_c, isbs, isra, mc), "chain_ext != _chain_residuals_ext"
    print("HP9.2 GF(p^2) hold/range/chain transition residuals == _hold/_range/_chain_residuals_ext: OK")

    # --- HP9.3: GF(p^2) boundary residuals (boundary_ext) == native_ct_air_prover.ct_boundary_constraints_ext.
    #     Real meta/stmt from _demo_witness; the (row, fn) closures evaluated at random ext cur cells == the
    #     deploy program (baked pinned statement constants + M_EXT_INV[0]). HP15.11 per-prog check. ---
    _tf9, _st9 = CT.build_ct_trace(CT._demo_witness(depth=2))
    _fc9, _T9, _meta9 = CT.build_full_flat_trace(_tf9)
    _rspec9 = [(CT.HELD_COLS.index("vh_" + rm["vname"]), rm["src"] is not None) for rm in _meta9["range"]]
    _cons9 = CT.ct_boundary_constraints_ext(_meta9, _st9)
    for _ in range(10):
        cur9 = {"s%d" % k: _ev() for k in range(P2.WIDTH)}
        for hc in CT.HELD_COLS:
            cur9[hc] = _ev()
        ref9 = [fn(cur9) for (_row, fn) in _cons9]
        state9 = [cur9["s%d" % k] for k in range(P2.WIDTH)]
        held9 = [cur9[hc] for hc in CT.HELD_COLS]
        got9, _ = run_boundary_ext(CT.M_EXT_INV[0], CT.N_OUT, _rspec9,
                                   _st9["root"], _st9["nf"], _st9["cm_out"], state9, held9)
        assert got9 == ref9, "boundary_ext != ct_boundary_constraints_ext"
    print("HP9.3 GF(p^2) boundary residuals == ct_boundary_constraints_ext: OK (%d constraints)" % len(_cons9))

    # --- HP9.4: GF(p^2) composition primitive (compose_ext) == _compose_at_ext's combination
    #     (native_ct_air_stark:223-226 with qf=zl*ZHz_inv folded): comp = qf*sum_j(tv_j*ta_j) +
    #     sum_b(bv_b*bix_b*ba_b). Real AIR arities (n_t transition residuals, n_b boundary). ---
    _nt9 = CT.ct_num_transition_residuals(); _nb9 = len(_cons9)
    for _ in range(20):
        tv = [_ev() for _ in range(_nt9)]; ta = [_ev() for _ in range(_nt9)]; qf9 = _ev()
        bv = [_ev() for _ in range(_nb9)]; bix = [_ev() for _ in range(_nb9)]; ba = [_ev() for _ in range(_nb9)]
        ref9 = _F2.ZERO
        for v, a in zip(tv, ta):
            ref9 = _F2.add(ref9, _F2.mul(_F2.mul(v, qf9), a))
        for v, ix, a in zip(bv, bix, ba):
            ref9 = _F2.add(ref9, _F2.mul(_F2.mul(v, ix), a))
        got9, _ = run_compose_ext(tv, ta, qf9, bv, bix, ba)
        assert got9 == ref9, "compose_ext != _compose_at_ext combination"
    gotL9, _ = run_compose_ext(tv, ta, qf9, bv, bix, ba, compose_looped=True)   # MAC DEFINE/INVOKE fold == unrolled
    assert gotL9 == ref9, "compose_ext_looped != unrolled"
    print("HP9.4 GF(p^2) composition (compose_ext) == _compose_at_ext combination: OK (n_t=%d n_b=%d; loop==unrolled)"
          % (_nt9, _nb9))

    # --- HP9.5: GF(p^2) FULL transition assembly (assemble_transition_ext) == ct_transition_residuals_ext.
    #     The deploy AIR-at-z transition vector (derive isr/y_full over GF(p^2), then the 62 residuals via the
    #     tested ext leaves) reproduces the reference at random OOD cells/selectors. HP15.11 end-to-end check. ---
    _minvcap9 = [CT.M_EXT_INV[k] for k in range(P2.RATE, P2.WIDTH)]
    for _ in range(2):
        curA = {}
        for k in range(P2.WIDTH):
            curA["s%d" % k] = _ev(); curA["u2_%d" % k] = _ev(); curA["u4_%d" % k] = _ev(); curA["u6_%d" % k] = _ev()
        for hc in CT.HELD_COLS:
            curA[hc] = _ev()
        nxtA = {"s%d" % k: _ev() for k in range(P2.WIDTH)}
        for hc in CT.HELD_COLS:
            nxtA[hc] = _ev()
        pubA = {"is_full": _ev(), "is_partial": _ev(), "is_block_start": _ev(), "is_reabsorb": _ev(),
                "is_range": _ev(), "is_range_first": _ev(), "is_range_step": _ev(), "is_range_last": _ev(),
                "rc": [_ev() for _ in range(P2.WIDTH)], "chain_minv": [_ev() for _ in range(P2.WIDTH)]}
        wnA = _ev()
        refA = CT.ct_transition_residuals_ext(curA, nxtA, pubA, wnA)
        gotA, _ = run_assemble_transition_ext(CT.M_EXT, P2.MAT_DIAG12, _minvcap9, curA, nxtA, pubA, wnA, CT.HELD_COLS)
        assert gotA == refA, "assemble_transition_ext != ct_transition_residuals_ext"
    for _slo, _sto in [(True, False), (False, True), (True, True)]:   # DEFINE-fold (sbox/state) == unrolled (byte cut)
        gotL, _ = run_assemble_transition_ext(CT.M_EXT, P2.MAT_DIAG12, _minvcap9, curA, nxtA, pubA, wnA,
                                              CT.HELD_COLS, sbox_looped=_slo, state_looped=_sto)
        assert gotL == refA, "looped(sbox=%s,state=%s) assemble_transition_ext != unrolled" % (_slo, _sto)
    print("HP9.5 GF(p^2) transition assembly == ct_transition_residuals_ext: OK (%d residuals; sbox/state-loop==unrolled)"
          % len(refA))

    # --- HP9.5: GF(p^2) compose-feed (compose_feed_ext) reorders [trans_v, bound_v, alpha_T, qf, bound_invX,
    #     alpha_B] into compose_ext's layout and composes == the _compose_at_ext combination. ---
    for _ in range(10):
        tvf = [_ev() for _ in range(_nt9)]; bvf = [_ev() for _ in range(_nb9)]
        taf = [_ev() for _ in range(_nt9)]; qff = _ev()
        bixf = [_ev() for _ in range(_nb9)]; baf = [_ev() for _ in range(_nb9)]
        reff = _F2.ZERO
        for v, a in zip(tvf, taf):
            reff = _F2.add(reff, _F2.mul(_F2.mul(v, qff), a))
        for v, ix, a in zip(bvf, bixf, baf):
            reff = _F2.add(reff, _F2.mul(_F2.mul(v, ix), a))
        gotf, _ = run_compose_feed_ext(tvf, bvf, taf, qff, bixf, baf)
        assert gotf == reff, "compose_feed_ext != _compose_at_ext combination"
    print("HP9.5 GF(p^2) compose-feed (compose_feed_ext) == _compose_at_ext combination: OK")

    # --- HP9.5: FULL GF(p^2) comp(z) assembly (comp_at_z_ext) == native_ct_air_stark._compose_at_ext
    #     END-TO-END: transition + boundary + compose over GF(p^2) at a real OOD point reproduces the DEEP
    #     AIR-eval-once (the one AIR<->trace<->comp binding) on real cashvm. HP15.11 end-to-end check. ---
    import native_ct_air_stark as _STK
    curZ = {}
    for k in range(P2.WIDTH):
        curZ["s%d" % k] = _ev(); curZ["u2_%d" % k] = _ev(); curZ["u4_%d" % k] = _ev(); curZ["u6_%d" % k] = _ev()
    for hc in CT.HELD_COLS:
        curZ[hc] = _ev()
    nxtZ = {"s%d" % k: _ev() for k in range(P2.WIDTH)}
    for hc in CT.HELD_COLS:
        nxtZ[hc] = _ev()
    pubZ = {"is_full": _ev(), "is_partial": _ev(), "is_block_start": _ev(), "is_reabsorb": _ev(),
            "is_range": _ev(), "is_range_first": _ev(), "is_range_step": _ev(), "is_range_last": _ev(),
            "rc": [_ev() for _ in range(P2.WIDTH)], "chain_minv": [_ev() for _ in range(P2.WIDTH)]}
    wnZ = _ev(); zZ = _ev(); lastZ = rng.randrange(0, P); zhZ = _ev()
    aTZ = [_ev() for _ in range(_nt9)]; aBZ = [_ev() for _ in range(_nb9)]
    HdZ = {row: (row * 7 + 3) % P for (row, _fn) in _cons9}
    refZ = _STK._compose_at_ext(curZ, nxtZ, zZ, wnZ, lastZ, zhZ, HdZ, pubZ, aTZ, _cons9, aBZ)
    qfZ = _F2.mul(_F2.sub(zZ, _F2.from_base(lastZ)), zhZ)
    bixZ = [_F2.inv(_F2.sub(zZ, _F2.from_base(HdZ[row]))) for (row, _fn) in _cons9]
    gotZ, _ocZ = run_comp_at_z_ext(CT.M_EXT, P2.MAT_DIAG12, _minvcap9, CT.M_EXT_INV[0], CT.N_OUT, _rspec9,
                                   _st9["root"], _st9["nf"], _st9["cm_out"], curZ, nxtZ, pubZ, wnZ,
                                   aTZ, qfZ, bixZ, aBZ, CT.HELD_COLS)
    assert gotZ == refZ, "comp_at_z_ext != _compose_at_ext (end-to-end)"
    print("HP9.5 GF(p^2) FULL comp(z) assembly == _compose_at_ext (end-to-end): OK (op_cost=%d)" % _ocZ)
    gotZL, _ = run_comp_at_z_ext(CT.M_EXT, P2.MAT_DIAG12, _minvcap9, CT.M_EXT_INV[0], CT.N_OUT, _rspec9,
                                 _st9["root"], _st9["nf"], _st9["cm_out"], curZ, nxtZ, pubZ, wnZ, aTZ, qfZ, bixZ, aBZ,
                                 CT.HELD_COLS, sbox_looped=True, state_looped=True, compose_looped=True)
    assert gotZL == refZ, "fully DEFINE-folded comp(z) != unrolled"
    print("HP9.5 GF(p^2) comp(z) fully DEFINE-folded (sbox+state+compose) == unrolled: OK (make-or-break byte cut)")

    # --- HP9.7: SPLIT comp(z) into standalone <=10000B parts (job-partitioned MAC-accumulator pipeline) ==
    #     comp_at_z_ext == _compose_at_ext, and each part <=10000B. The transition parts accumulate acc_T
    #     (carried); the final part does qf*acc_T + boundary. Value-identical split for the consensus input
    #     cap (make-or-break: comp(z) is ~27KB > 10000B; the 5-part split is ~7.6KB max). ---
    _split9 = comp_split_default_parts(_minvcap9)               # sbox | state0-5 | state6-11 | chain+hold+range
    for _slo, _sto in [(False, False), (True, True)]:
        _cs9, _stt9 = run_comp_split(_split9, CT.M_EXT, P2.MAT_DIAG12, _minvcap9, CT.M_EXT_INV[0], CT.N_OUT, _rspec9,
                                     _st9["root"], _st9["nf"], _st9["cm_out"], curZ, nxtZ, pubZ, wnZ,
                                     aTZ, qfZ, bixZ, aBZ, CT.HELD_COLS, sbox_looped=_slo, state_looped=_sto)
        assert _cs9 == refZ, "comp_split (sbox_looped=%s,state_looped=%s) != _compose_at_ext" % (_slo, _sto)
    for _lbl9, _oc9, _nbb9 in _stt9:
        assert _nbb9 <= 10000, "HP9.7 split part %s is %dB > 10000B" % (_lbl9, _nbb9)
    print("HP9.7 GF(p^2) comp(z) SPLIT into <=10000B parts == _compose_at_ext: OK (%d parts, max %dB: %s)"
          % (len(_stt9), max(nb for _, _, nb in _stt9), ", ".join("%s=%dB" % (l, nb) for l, _o, nb in _stt9)))

    # --- HP9.8: SPLIT CARRY single-source (OP_INPUTBYTECODE). Each transition part exposes its acc_out as a
    #     carry_out_preimage and BINDS its computed acc_out to it (split_cells+NUMEQUALVERIFY, fail-closed); acc_in
    #     is split from the prior part's preimage; the final part reads the last acc_T from a preimage. The carried
    #     acc_T thus cannot be forged across the input boundary (R8-B1) -- a prover can't decouple comp(z). ---
    for _slo, _sto in [(False, False), (True, True)]:
        _csb, _stb = run_comp_split(_split9, CT.M_EXT, P2.MAT_DIAG12, _minvcap9, CT.M_EXT_INV[0], CT.N_OUT, _rspec9,
                                    _st9["root"], _st9["nf"], _st9["cm_out"], curZ, nxtZ, pubZ, wnZ,
                                    aTZ, qfZ, bixZ, aBZ, CT.HELD_COLS, sbox_looped=_slo, state_looped=_sto,
                                    carry_bound=True)
        assert _csb == refZ, "carry-bound split (sbox_looped=%s,state_looped=%s) != _compose_at_ext" % (_slo, _sto)
    for _lbl8, _oc8, _nb8 in _stb:
        assert _nb8 <= 10000, "HP9.8 bound part %s is %dB > 10000B" % (_lbl8, _nb8)
    _g8 = _split9[0]                                            # tamper: forged exposed carry_out_preimage -> reject
    _pnr8 = sum(_job_nres(_j, _minvcap9) for _j in _g8)
    _vm8 = VM(); _vm8.run(_field_prelude()
                          + comp_split_trans_part_unlock(_g8, (0, 0), aTZ[0:_pnr8], curZ, nxtZ, pubZ, wnZ, CT.HELD_COLS)
                          + comp_split_trans_part_prog(_g8, _pnr8, CT.M_EXT, P2.MAT_DIAG12, _minvcap9, True, True))
    _acc8 = (decode_num(_vm8.s[-2]), decode_num(_vm8.s[-1]))
    _pb8 = comp_split_trans_part_prog(_g8, _pnr8, CT.M_EXT, P2.MAT_DIAG12, _minvcap9, True, True, carry_bound=True)
    _ub8 = comp_split_trans_part_unlock(_g8, (0, 0), aTZ[0:_pnr8], curZ, nxtZ, pubZ, wnZ, CT.HELD_COLS,
                                        carry_bound=True, acc_out=((_acc8[0] + 1) % P, _acc8[1]))
    _rej8 = False
    try:
        _vm8b = VM(); _vm8b.run(_field_prelude() + _ub8 + _pb8)
        _rej8 = not (len(_vm8b.s) == 1 and decode_num(_vm8b.s[-1]) != 0)
    except VMError:
        _rej8 = True
    assert _rej8, "HP9.8: a forged carry_out_preimage (!= computed acc_out) was NOT rejected"
    print("HP9.8 split carry single-source (acc_out==exposed preimage self-bind) == _compose_at_ext: OK "
          "(%d parts <=10000B, max %dB; forged carry-out rejected fail-closed)"
          % (len(_stb), max(nb for _, _, nb in _stb)))

    # --- HP9.10 (core): the final split-part BINDS its computed comp(z) to a comp_preimage (the committed
    #     composition comp_root) via _comp_producer_bind_prog -- the AIR-eval-once comp(z) == comp_root, so a
    #     prover can't output comp != the FS-committed value. (comp_preimage's single-source from the FS blob
    #     comp_root is HP11/HP12; presence/count-binding is HP9.9.) ---
    for _slo, _sto in [(False, False), (True, True)]:
        _csc, _stc = run_comp_split(_split9, CT.M_EXT, P2.MAT_DIAG12, _minvcap9, CT.M_EXT_INV[0], CT.N_OUT, _rspec9,
                                    _st9["root"], _st9["nf"], _st9["cm_out"], curZ, nxtZ, pubZ, wnZ,
                                    aTZ, qfZ, bixZ, aBZ, CT.HELD_COLS, sbox_looped=_slo, state_looped=_sto,
                                    carry_bound=True, comp_bound=True)
        assert _csc == refZ, "comp-bound split (sbox_looped=%s,state_looped=%s) != _compose_at_ext" % (_slo, _sto)
    for _lbl10, _oc10, _nbb10 in _stc:
        assert _nbb10 <= 10000, "HP9.10 bound part %s is %dB > 10000B" % (_lbl10, _nbb10)

    # --- HP11.3: the LAZY transition MAC (mac_lazy=True: 0x2a raw GF(p^2) accumulate + a single mod-p reduction) is
    #     FIELD-IDENTICAL to the eager 0x26 -- a ZERO-soundness op-cost lever (~4.3x less op-cost on the MAC) that lets
    #     an OP-COST-BOUND transition part (the sbox part) shrink its op-budget pad. Validated == _compose_at_ext at the
    #     deploy config (sbox/state looped, carry+comp bound); byte-bound parts are unaffected. ---
    _csL, _stL = run_comp_split(_split9, CT.M_EXT, P2.MAT_DIAG12, _minvcap9, CT.M_EXT_INV[0], CT.N_OUT, _rspec9,
                                _st9["root"], _st9["nf"], _st9["cm_out"], curZ, nxtZ, pubZ, wnZ,
                                aTZ, qfZ, bixZ, aBZ, CT.HELD_COLS, sbox_looped=True, state_looped=True,
                                carry_bound=True, comp_bound=True, mac_lazy=True)
    assert _csL == refZ, "HP11.3 lazy comp-MAC (mac_lazy=True) != _compose_at_ext"
    for _lblL, _ocL, _nbL in _stL:
        assert _nbL <= 10000, "HP11.3 lazy part %s is %dB > 10000B" % (_lblL, _nbL)
    print("HP11.3 lazy transition MAC (0x2a raw + reduce-once, mac_lazy=True) == eager 0x26 == _compose_at_ext: OK "
          "(field-identical op-cost lever; %d parts <=10000B)" % len(_stL))

    _acc10, _off10 = (0, 0), 0                                  # tamper: forged comp_preimage -> reject
    for _g in _split9:
        _pnr = sum(_job_nres(_j, _minvcap9) for _j in _g)
        _vm = VM(); _vm.run(_field_prelude()
                            + comp_split_trans_part_unlock(_g, _acc10, aTZ[_off10:_off10 + _pnr], curZ, nxtZ, pubZ, wnZ, CT.HELD_COLS)
                            + comp_split_trans_part_prog(_g, _pnr, CT.M_EXT, P2.MAT_DIAG12, _minvcap9, True, True))
        _acc10 = (decode_num(_vm.s[-2]), decode_num(_vm.s[-1])); _off10 += _pnr
    _cfp = comp_split_final_part_prog(CT.M_EXT_INV[0], CT.N_OUT, _rspec9, _st9["root"], _st9["nf"], _st9["cm_out"],
                                      _nb9, carry_bound=True, comp_bound=True)
    _cfu = comp_split_final_part_unlock(_acc10, qfZ, bixZ, aBZ, curZ, CT.HELD_COLS, _nb9,
                                        carry_bound=True, comp_bound=True, comp=((refZ[0] + 1) % P, refZ[1]))
    _rej10 = False
    try:
        _vmb = VM(); _vmb.run(_field_prelude() + _cfu + _cfp)
        _rej10 = not (len(_vmb.s) == 1 and decode_num(_vmb.s[-1]) != 0)
    except VMError:
        _rej10 = True
    assert _rej10, "HP9.10: a forged comp_preimage (!= computed comp) was NOT rejected"
    print("HP9.10 comp(z) binding to comp_preimage (final self-bind) == _compose_at_ext: OK "
          "(%d parts <=10000B, max %dB; forged comp rejected fail-closed)"
          % (len(_stc), max(nb for _, _, nb in _stc)))

    # --- HP2.2: linear-layer state-update residual (MDS external / diag internal) ---
    W = P2.WIDTH; diag = P2.MAT_DIAG12

    def _ref_state(y_full, y_part, j, sj, isf, isp):
        ef = CT._ext_apply(y_full); ip = CT._int_apply(y_part)
        return (isf * ((sj - ef[j]) % P) + isp * ((sj - ip[j]) % P)) % P

    # 1) VM program == reference (M_EXT row . y_full / diag . y_part) on random values
    for _ in range(20):
        yf = [rng.randrange(0, P) for _ in range(W)]
        yp = [rng.randrange(0, P) for _ in range(W)]
        j = rng.randrange(0, W); sj = rng.randrange(0, P)
        isf, isp = rng.choice([0, 1]), rng.choice([0, 1])
        got, _oc = run_state_lane(CT.M_EXT[j], yf, yp, diag[j], j, sj, isf, isp)
        assert got == _ref_state(yf, yp, j, sj, isf, isp), "VM state residual != reference"

    # 2) FULL round (isf=1): build y_full like _round_residuals; nxt state == M_EXT.y_full
    rf = 1                                                  # round 1 is a full round
    yf = [(aux[rf]["x6"][k] * ((states[rf][k] + CT.RC[rf][k]) % P)) % P for k in range(W)]
    yp = [yf[0] if k == 0 else states[rf][k] for k in range(W)]
    for j in range(W):
        v, ocs = run_state_lane(CT.M_EXT[j], yf, yp, diag[j], j, states[rf + 1][j], 1, 0)
        assert v == 0, "valid full-round state residual lane %d != 0 (got %d)" % (j, v)
    # tamper the next-row state cell -> residual != 0
    vt, _ = run_state_lane(CT.M_EXT[0], yf, yp, diag[0], 0, (states[rf + 1][0] + 1) % P, 1, 0)
    assert vt != 0, "tampered full-round next state not caught"

    # 3) PARTIAL round (isp=1): only lane 0 is S-boxed, rest pass through; nxt == int(y_part)
    rp = 10                                                 # round 10 is a partial round
    yp2 = [(aux[rp]["x6"][0] * ((states[rp][0] + CT.RC[rp][0]) % P)) % P if k == 0
           else states[rp][k] for k in range(W)]
    yf2 = [(aux[rp]["x6"][k] * ((states[rp][k] + CT.RC[rp][k]) % P)) % P for k in range(W)]
    for j in range(W):
        v, _ = run_state_lane(CT.M_EXT[j], yf2, yp2, diag[j], j, states[rp + 1][j], 0, 1)
        assert v == 0, "valid partial-round state residual lane %d != 0 (got %d)" % (j, v)
    vt, _ = run_state_lane(CT.M_EXT[3], yf2, yp2, diag[3], 3, (states[rp + 1][3] + 1) % P, 0, 1)
    assert vt != 0, "tampered partial-round next state not caught"

    # --- HP3.5b-iii-0a: STRUCTURED external MDS (matmul_external_prog, M4-block ADDMOD-only) computes the
    #     SAME ef = M_EXT.y as the generic per-lane 12-term dot (CT._ext_apply) but ~3.9x cheaper on the VM
    #     (measured) -- the compose optimization lever; 0b threads it into the state residual. Validate the
    #     structured form == the reference on random + the real full-round y (correctness-preserving). ---
    for _ in range(20):
        yv = [rng.randrange(0, P) for _ in range(W)]
        efv, _ = run_matmul_external(yv)
        assert efv == list(CT._ext_apply(yv)), "structured M_EXT (M4-block) != CT._ext_apply (correctness broken)"
    ef_struct, oc_mm_struct = run_matmul_external(yf)          # yf = the real full-round input (from HP2.2 above)
    assert ef_struct == list(CT._ext_apply(yf)), "structured M_EXT != reference on the real full-round y"
    print("HP3.5b-iii-0a structured external MDS (M4-block, ADDMOD-only) == generic M_EXT.y (CT._ext_apply): OK")
    print("  structured op_cost = %d ; ~3.9x cheaper than the generic 12-term dot (measured); 21 vectors exact"
          % oc_mm_struct)

    # --- HP3.5b-iii-0b: state_lane_from_ef reads a PRECOMPUTED ef_j (from matmul_external) instead of the
    #     generic M_EXT-row dot -> v_j IDENTICAL to run_state_lane. Validate on the real full-round AND
    #     partial-round state (ef = CT._ext_apply(y_full)); a wrong next-state -> residual != 0. ---
    ef_full = list(CT._ext_apply(yf))                         # ef = M_EXT.y_full for the real full round (rf)
    for j in range(W):
        v_from, _ = run_state_lane_from_ef(ef_full[j], yp, diag[j], j, states[rf + 1][j], 1, 0)
        v_gen, _ = run_state_lane(CT.M_EXT[j], yf, yp, diag[j], j, states[rf + 1][j], 1, 0)
        assert v_from == v_gen == 0, "from_ef full-round lane %d: from_ef=%d gen=%d (expect 0==0)" % (j, v_from, v_gen)
    ef_part = list(CT._ext_apply(yf2))                        # partial round (rp): isf=0, ip path
    for j in range(W):
        v_from, _ = run_state_lane_from_ef(ef_part[j], yp2, diag[j], j, states[rp + 1][j], 0, 1)
        v_gen, _ = run_state_lane(CT.M_EXT[j], yf2, yp2, diag[j], j, states[rp + 1][j], 0, 1)
        assert v_from == v_gen == 0, "from_ef partial-round lane %d: from_ef=%d gen=%d" % (j, v_from, v_gen)
    vft, _ = run_state_lane_from_ef(ef_full[0], yp, diag[0], 0, (states[rf + 1][0] + 1) % P, 1, 0)
    assert vft != 0, "from_ef did not catch a tampered next state"
    print("HP3.5b-iii-0b state_lane_from_ef (reads precomputed ef, no MDS dot) == run_state_lane v_j: OK")
    print("  all %d lanes v_j identical (full + partial round, valid->0) ; tampered next-state -> !=0" % W)

    # --- HP2.4 range + HP2.4b conservation on a REAL flat CT-AIR trace ---
    trace_f, _stmt = CT.build_ct_trace(CT._demo_witness(depth=2))
    fc, T, meta = CT.build_full_flat_trace(trace_f)
    lay = CT.ct_public_layout(meta, T)
    rmv = meta["range"][1]; off = rmv["offset"]; r = off + 5      # mid-block (is_range_step active)
    cur = {"s0": fc["s0"][r], "s1": fc["s1"][r], "s2": fc["s2"][r]}
    nxt = {"s0": fc["s0"][r + 1], "s1": fc["s1"][r + 1], "s2": fc["s2"][r + 1]}
    se = (lay["is_range"][r], lay["is_range_first"][r], lay["is_range_step"][r], lay["is_range_last"][r])
    wn = lay["range_weight"][r + 1]
    ref = CT._range_residuals(cur, nxt, se[0], se[1], se[2], se[3], wn)
    got, ocr = run_range(cur["s0"], cur["s1"], cur["s2"], se[0], se[1], se[2], se[3],
                         nxt["s0"], nxt["s1"], nxt["s2"], wn)
    assert got == ref, "VM range residuals != reference"
    assert got == [0, 0, 0, 0, 0], "valid range residuals not all zero: %s" % got
    gt, _ = run_range((cur["s0"] + 2) % P, cur["s1"], cur["s2"], 1, se[1], se[2], se[3],
                      nxt["s0"], nxt["s1"], nxt["s2"], wn)
    assert gt[0] != 0, "range booleanity tamper not caught"
    for _ in range(20):
        a = [rng.randrange(0, P) for _ in range(3)]; nx = [rng.randrange(0, P) for _ in range(3)]
        sel = [rng.choice([0, 1]) for _ in range(4)]; w = rng.randrange(0, P)
        cu = {"s0": a[0], "s1": a[1], "s2": a[2]}; nu = {"s0": nx[0], "s1": nx[1], "s2": nx[2]}
        rf = CT._range_residuals(cu, nu, sel[0], sel[1], sel[2], sel[3], w)
        gg, _ = run_range(a[0], a[1], a[2], sel[0], sel[1], sel[2], sel[3], nx[0], nx[1], nx[2], w)
        assert gg == rf, "VM range != reference (random)"

    co = meta["cons_row"]
    vin = fc["vh_value_in"][co]; o0 = fc["vh_value_out0"][co]
    o1 = fc["vh_value_out1"][co]; fee = fc["vh_fee"][co]
    cons, occ = run_conservation(vin, o0, o1, fee)
    assert cons == 0, "valid conservation residual != 0 (got %d)" % cons
    ctp, _ = run_conservation(vin, (o0 + 1) % P, o1, fee)
    assert ctp != 0, "conservation tamper not caught"
    for _ in range(20):
        vs = [rng.randrange(0, P) for _ in range(4)]
        gg, _ = run_conservation(*vs)
        assert gg == (vs[0] - (vs[1] + vs[2] + vs[3])) % P, "VM conservation != reference (random)"

    # --- 2.20b: A3 held-value HOLD residuals (nxt[c]-cur[c]) on the REAL flat CT-AIR trace ---
    HC = CT.HELD_COLS
    hr = meta["range"][0]["offset"] + 3                          # a real transition row; held cols constant
    hcur = {c: fc[c][hr] for c in HC}; hnxt = {c: fc[c][hr + 1] for c in HC}
    href = CT._hold_residuals(hcur, hnxt)
    hcv = [hcur[c] for c in HC]; hnv = [hnxt[c] for c in HC]
    hgot, _och = run_hold_stack(hcv, hnv)
    assert hgot == href, "VM hold residuals != reference"
    assert hgot == [0] * len(HC), "valid hold residuals not all zero: %s" % hgot
    hbad = list(hnv); hbad[0] = (hbad[0] + 1) % P               # tamper a held next-cell -> non-constant
    hgt, _ = run_hold_stack(hcv, hbad)
    assert hgt[0] != 0, "hold tamper (non-constant held col) not caught"
    for _ in range(20):                                          # VM == reference on random values
        cv = [rng.randrange(0, P) for _ in range(len(HC))]
        nv = [rng.randrange(0, P) for _ in range(len(HC))]
        gg, _ = run_hold_stack(cv, nv)
        assert gg == [(nv[i] - cv[i]) % P for i in range(len(HC))], "VM hold != reference (random)"

    # --- 2.20c: A2 CHAIN residuals (capacity isbs·(M_EXT_INV[k]·cur) + chaining
    #     isra·(chain_minv·nxt - cur.s0)) on the REAL flat CT-AIR trace ---
    W = P2.WIDTH
    minv_cap = [CT.M_EXT_INV[k] for k in range(P2.RATE, W)]       # pinned inverse-MDS capacity rows
    def _statevec(row):
        return [fc["s%d" % j][row] for j in range(W)]
    rbs = next(r for r in range(T - 1) if lay["is_block_start"][r] == 1)      # capacity active
    cbs = {"s%d" % j: fc["s%d" % j][rbs] for j in range(W)}
    nbs = {"s%d" % j: fc["s%d" % j][rbs + 1] for j in range(W)}
    cref = CT._chain_residuals(cbs, nbs, lay["is_block_start"][rbs], lay["is_reabsorb"][rbs],
                               lay["chain_minv"][rbs])
    cgot, _occ = run_chain_stack(minv_cap, _statevec(rbs), _statevec(rbs + 1),
                                 lay["chain_minv"][rbs], lay["is_block_start"][rbs], lay["is_reabsorb"][rbs])
    assert cgot == cref, "VM chain residuals != reference (block-start row)"
    assert cgot == [0] * (len(minv_cap) + 1), "valid chain residuals not all zero: %s" % cgot
    cbad = _statevec(rbs); cbad[3] = (cbad[3] + 1) % P            # tamper a cur state cell
    cgt, _ = run_chain_stack(minv_cap, cbad, _statevec(rbs + 1),
                             lay["chain_minv"][rbs], lay["is_block_start"][rbs], lay["is_reabsorb"][rbs])
    assert cgt[:len(minv_cap)] != [0] * len(minv_cap), "chain capacity tamper (cur state) not caught"
    rra = next(r for r in range(T - 1) if lay["is_reabsorb"][r] == 1)         # chaining active
    cbad2 = _statevec(rra); cbad2[0] = (cbad2[0] + 1) % P        # tamper cur.s0 -> chaining != 0
    cgt2, _ = run_chain_stack(minv_cap, cbad2, _statevec(rra + 1),
                              lay["chain_minv"][rra], lay["is_block_start"][rra], lay["is_reabsorb"][rra])
    assert cgt2[-1] != 0, "chain chaining tamper (cur.s0) not caught"
    for _ in range(15):                                          # VM == reference on random values
        cs = [rng.randrange(0, P) for _ in range(W)]; ns = [rng.randrange(0, P) for _ in range(W)]
        cm = [rng.randrange(0, P) for _ in range(W)]; bb = rng.choice([0, 1]); ra = rng.choice([0, 1])
        cu = {"s%d" % j: cs[j] for j in range(W)}; nu = {"s%d" % j: ns[j] for j in range(W)}
        rr = CT._chain_residuals(cu, nu, bb, ra, cm)
        gg, _ = run_chain_stack(minv_cap, cs, ns, cm, bb, ra)
        assert gg == rr, "VM chain != reference (random)"

    # --- HP10.2/HP10.5: the LOOPED compose_feed (DEFINE/INVOKE fold over the natural block) == the unrolled
    #     compose_feed, across n_t/n_b (deploy 62/12 + smaller). Proves the loop's generalized below-free
    #     depths reproduce the composition exactly before it is wired into the per-query core. ---
    for (nt_c, nb_c) in ((62, 12), (30, 7), (3, 2)):
        tvc = [rng.randrange(P) for _ in range(nt_c)]; bvc = [rng.randrange(P) for _ in range(nb_c)]
        tac = [[rng.randrange(P), rng.randrange(P)] for _ in range(nt_c)]
        bac = [[rng.randrange(P), rng.randrange(P)] for _ in range(nb_c)]
        qfc = rng.randrange(P); bixc = [rng.randrange(P) for _ in range(nb_c)]
        (cu0, cu1), _ = run_compose_feed(tvc, bvc, tac, qfc, bixc, bac)
        (cl0, cl1), _ = run_compose_feed_looped(tvc, bvc, tac, qfc, bixc, bac)
        assert (cu0 % P, cu1 % P) == (cl0 % P, cl1 % P), \
            "looped compose_feed != unrolled (n_t=%d n_b=%d)" % (nt_c, nb_c)
    print("HP10.2/10.5 looped compose_feed (DEFINE/INVOKE fold) == unrolled compose_feed: OK (62/12, 30/7, 3/2)")

    # HP10.5: the S-box loop (DEFINE(sbox_lane_stack_prog) once + 12x INVOKE in assemble_transition) == the
    # unrolled trans_v on a REAL transition row -- a uniform-body consolidation (the emit sources are unchanged).
    _r = meta["range"][0]["offset"] + 3
    _cur = {c: fc[c][_r] for c in fc}; _nxt = {c: fc[c][_r + 1] for c in fc}
    _pubx = {"is_full": lay["is_full"][_r], "is_partial": lay["is_partial"][_r], "rc": [CT.RC[0][k] for k in range(W)],
             "is_block_start": lay["is_block_start"][_r], "is_reabsorb": lay["is_reabsorb"][_r],
             "chain_minv": lay["chain_minv"][_r], "is_range": lay["is_range"][_r], "is_range_first": lay["is_range_first"][_r],
             "is_range_step": lay["is_range_step"][_r], "is_range_last": lay["is_range_last"][_r]}
    _wn = lay["range_weight"][_r + 1]
    _tvu, _ = run_assemble_transition(diag, minv_cap, _cur, _nxt, _pubx, _wn, HC, sbox_looped=False)
    _tvl, _ = run_assemble_transition(diag, minv_cap, _cur, _nxt, _pubx, _wn, HC, sbox_looped=True)
    assert _tvu == _tvl, "HP10.5 S-box loop trans_v != unrolled"
    _tvs, _ = run_assemble_transition(diag, minv_cap, _cur, _nxt, _pubx, _wn, HC, state_looped=True)
    assert _tvu == _tvs, "HP10.5 state loop trans_v != unrolled"
    _tvb, _ = run_assemble_transition(diag, minv_cap, _cur, _nxt, _pubx, _wn, HC, sbox_looped=True, state_looped=True)
    assert _tvu == _tvb, "HP10.5 sbox+state combined loop trans_v != unrolled"
    print("HP10.5 stage-A loops (S-box + state, DEFINE/INVOKE) in assemble_transition == unrolled trans_v: OK (%d residuals)" % len(_tvu))

    # --- 2.20d: BOUNDARY residuals reproduce verify's bound_v at a REAL query point on the BCH-VM.
    #     eq (cur[a]-b) via the difference primitive, cm-bind via the new prog, conservation via its
    #     prog, assembled in ct_boundary_constraints order (bound_v = [fn(cur=q.ck)]). ---
    import native_ct_air_stark as STK
    pfb = STK.prove(CT._demo_witness(depth=2), seed=7)
    tb = STK.query_terms(pfb)[0]                                 # a real query's boundary residual vector
    stmtb = pfb["stmt"]; curk = pfb["queries"][0]["ck"]         # opened trace row @k (full column dict)
    minv0 = CT.M_EXT_INV[0]                                      # baked inverse-external-MDS row 0
    metab, _Tb = CT.ct_build_layout(stmtb["depth"])            # same layout builder verify/query_terms use
    def _eq(a, b):                                               # eq boundary residual a-b (difference primitive)
        g, _ = run_hold_stack([b], [a]); return g[0]
    ref_bv = [_eq(curk["s0"], stmtb["root"]), _eq(curk["s0"], stmtb["nf"])]
    for i in range(CT.N_OUT):
        ref_bv.append(_eq(curk["s0"], stmtb["cm_out"][i]))
    for rmv in metab["range"]:
        hc = "vh_" + rmv["vname"]
        ref_bv.append(_eq(curk[hc], curk["s2"]))               # link
        if rmv["src"] is not None:
            g, _ = run_cmbind_stack(minv0, curk[hc], [curk["s%d" % j] for j in range(W)])
            ref_bv.append(g[0])                                 # cm-bind
    g, _ = run_conservation_stack(curk["vh_value_in"], curk["vh_value_out0"],
                                  curk["vh_value_out1"], curk["vh_fee"])
    ref_bv.append(g)
    assert ref_bv == tb["bound_v"], "VM boundary residuals != verify bound_v (%s vs %s)" % (ref_bv, tb["bound_v"])
    # cm-bind fail-closed: a tampered source-state cell breaks the cm-bind residual
    rmv0 = next(rm for rm in metab["range"] if rm["src"] is not None)
    st0 = [curk["s%d" % j] for j in range(W)]
    gok, _ = run_cmbind_stack(minv0, curk["vh_" + rmv0["vname"]], st0)
    stbc = list(st0); stbc[2] = (stbc[2] + 1) % P
    gtm, _ = run_cmbind_stack(minv0, curk["vh_" + rmv0["vname"]], stbc)
    assert gtm != gok, "cm-bind state tamper not caught"
    for _ in range(15):                                         # cm-bind VM == reference on random values
        vhr = rng.randrange(0, P); st = [rng.randrange(0, P) for _ in range(W)]
        g, _ = run_cmbind_stack(minv0, vhr, st)
        assert g[0] == (vhr - sum(minv0[j] * st[j] for j in range(W))) % P, "VM cm-bind != reference (random)"

    # --- GF(p^2) Karatsuba ext-mul on the BCH-VM (the extension multiply the FRI fold
    #     needs, HP3.5) -- must match native_gf_p2.mul exactly ---
    import native_gf_p2 as F2
    oce = 0
    for _ in range(30):
        a = (rng.randrange(0, P), rng.randrange(0, P))
        b = (rng.randrange(0, P), rng.randrange(0, P))
        got, oce = run_ext_mul(a[0], a[1], b[0], b[1])
        assert got == F2.mul(a, b), "VM ext-mul != native_gf_p2.mul"
    gu, _ = run_ext_mul(0, 1, 0, 1)                       # u * u == EXT_W (= (EXT_W, 0))
    assert gu == F2.mul(F2.U, F2.U) and gu == (EXT_W % P, 0), "u^2 != W on the VM"

    # --- HP13.1: GF(p^2) inverse-hint check -- every DEEP division 1/(x_k-z) / 1/(x_k-z*g) is hint-validated
    #     (hint*(x_k-z)==1) fail-closed; the GF(p^2) counterpart of the base i2x*twox==1 fold hint ---
    for _ in range(20):
        d = (rng.randrange(1, P), rng.randrange(0, P))
        h = F2.inv(d)
        ok_h, _ = run_ext_inv_check(h[0], h[1], d[0], d[1])
        assert ok_h, "VM ext_inv_check rejected an honest GF(p^2) inverse hint"
        bad_h, _ = run_ext_inv_check((h[0] + 1) % P, h[1], d[0], d[1])
        assert not bad_h, "VM ext_inv_check accepted a forged GF(p^2) inverse hint (not fail-closed)"
    print("HP13.1 GF(p^2) inverse-hint check (hint*(x-z)==1 fail-closed) == native_gf_p2.inv: OK "
          "(honest accept; forged hint rejected)")

    # --- HP10.1: DEEP-quotient per-term deep_term = alpha*(inv*(value-ood)) over GF(p^2) -- the atomic building
    #     block accumulated across the 138 DEEP terms into q(x_k) (native_ct_air_stark._deep_replay.q_at:500-506) ---
    for _ in range(12):
        _al = (rng.randrange(0, P), rng.randrange(0, P)); _iv = (rng.randrange(0, P), rng.randrange(0, P))
        _va = (rng.randrange(0, P), rng.randrange(0, P)); _od = (rng.randrange(0, P), rng.randrange(0, P))
        _gt, _ = run_deep_term(_al, _iv, _va, _od)
        assert _gt == F2.mul(_al, F2.mul(_iv, F2.sub(_va, _od))), "VM deep_term != alpha*(inv*(value-ood))"
    print("HP10.1 deep_term (alpha*(inv*(value-ood)) GF(p^2), DEEP-quotient per-term) == native_gf_p2: OK")

    # --- HP10.1: the FULL per-query DEEP quotient q(x_k) (deep_quotient MAC engine, invz/invzg factored out and
    #     applied once each) == native_ct_air_stark's q(x_k) (query_terms under deep=True). Real deep proof, no mock ---
    import native_ct_air_stark as _STKd
    import native_ct_air_prover as _CTd
    _pfq = _STKd.prove(_CTd._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=3, fold_step=3, deep=True, seed=0xF54A)
    assert _pfq.get("deep") and _STKd.verify(_pfq)[0], "HP10.1 deep proof did not verify"
    _qtq = _STKd.query_terms(_pfq); _stq = _pfq["stmt"]; _mq, _Tq = _STKd.ct_build_layout(_stq["depth"])
    _Nq, _oTq, _oNq, _offq, _Hdq, _Ddq, _lastq = _STKd._setup(_Tq, _pfq["blowup"])
    _layq = _STKd.ct_public_layout(_mq, _Tq); _svq = _STKd._selector_vectors(_layq, _Tq, _Nq, _oTq, _oNq, _offq)
    _zq = tuple(_pfq["z"]); _zgq = tuple(_pfq["zg"]); _czq = tuple(_pfq["comp_z"]); _rwq = tuple(_pfq["rw_zg"])
    _daq = [tuple(a) for a in _pfq["deep_alphas"]]; _pzq = _STKd._ood_pub_at(_layq, _Tq, _oTq, _zq)
    _selq = [(_svq[key], _pzq[key]) for key in ("is_full", "is_partial", "is_block_start", "is_reabsorb",
             "is_range", "is_range_first", "is_range_step", "is_range_last")]
    _selq += [(_svq["rc"][kk], _pzq["rc"][kk]) for kk in range(_STKd.WIDTH)]
    _selq += [(_svq["chain_minv"][j], _pzq["chain_minv"][j]) for j in range(_STKd.WIDTH)]
    _nfq = len(_STKd.FLAT_COLS); _nsq = len(_selq)
    for _qi, _q in enumerate(_pfq["queries"]):
        _k = _q["k"]; _terms = []
        for _c in _STKd.FLAT_COLS:
            _cke = F2.from_base(_q["ck"][_c])
            _terms.append((_daq[len(_terms)], _cke, tuple(_pfq["Pcz"][_c])))
            _terms.append((_daq[len(_terms)], _cke, tuple(_pfq["Pczg"][_c])))
        for _dv, _m in _selq:
            _terms.append((_daq[len(_terms)], F2.from_base(_dv[_k]), _m))
        _terms.append((_daq[len(_terms)], F2.from_base(_svq["range_weight"][_k]), _rwq))
        _terms.append((_daq[len(_terms)], tuple(_q["cc"]), _czq))
        _ivz = F2.inv(F2.sub(F2.from_base(_Ddq[_k]), _zq)); _ivzg = F2.inv(F2.sub(F2.from_base(_Ddq[_k]), _zgq))
        _gq, _ = run_deep_quotient(_nfq, _nsq, _terms, _ivz, _ivzg)
        assert _gq == tuple(_qtq[_qi]["comp_x"]), "deep_quotient q(x_k) != query_terms comp_x (query %d)" % _qi
        _gqh, _ = run_deep_query_quotient(_nfq, _nsq, _Ddq[_k], _zq, _zgq, _terms, _ivz, _ivzg)
        assert _gqh == tuple(_qtq[_qi]["comp_x"]), "deep_query_quotient (hint-validated) != q(x_k) (query %d)" % _qi
        assert run_deep_query_quotient(_nfq, _nsq, _Ddq[_k], _zq, _zgq, _terms,
                                       ((_ivz[0] + 1) % P, _ivz[1]), _ivzg)[0] is None, \
            "deep_query_quotient accepted a forged invz (query %d)" % _qi
        assert run_deep_query_quotient(_nfq, _nsq, _Ddq[_k], _zq, _zgq, _terms, _ivz,
                                       (_ivzg[0], (_ivzg[1] + 1) % P))[0] is None, \
            "deep_query_quotient accepted a forged invzg (query %d)" % _qi
    print("HP10.1 deep_quotient (MAC engine, invz/invzg factored) == query_terms q(x_k) for %d real queries: OK "
          "(%d bytes redeem, <=10000B)" % (len(_pfq["queries"]), _prog_nbytes(deep_quotient_prog(_nfq, _nsq))))
    print("HP10.1 deep_query_quotient (hint-validated: ext_inv_check invz/invzg + deep_quotient) == q(x_k): OK "
          "(forged invz/invzg rejected fail-closed, %d bytes)" % _prog_nbytes(deep_query_quotient_prog(_nfq, _nsq)))

    # --- HP10.2: the per-query comp(x_k) opening against comp_root -- under DEEP the composition value cc is
    #     OPENED (from the FS-committed comp tree at the FS-derived index k) and fed to the DEEP quotient's
    #     comp-term, not recomputed. The comp leaf is unsalted (b"\x00"*16 || enc8(cc0) || enc8(cc1)); the generic
    #     bound opener (run_bound_open, prefix=16 salt, n_cells=2) verifies it against the pinned comp_root and
    #     exposes cc. Real deep proof (q["cc"]/q["cp"]); a forged cc fails the pinned-root open (fail-closed) ---
    for _qc in _pfq["queries"]:
        _kc = _qc["k"]; _ccq = tuple(_qc["cc"])
        _cpre = b"\x00" * 16 + enc8(_ccq[0]) + enc8(_ccq[1])
        _cpath = [(bytes.fromhex(_sh), _bb) for _sh, _bb in _qc["cp"]]
        _cells, _ = run_bound_open(_cpre, _cpath, bytes.fromhex(_pfq["comp_root"]), _kc, 2, prefix=16)
        assert _cells == [_ccq[0], _ccq[1]], "comp(x_k) opening exposed the wrong value (query k=%d)" % _kc
        _rejc = False
        try:
            run_bound_open(b"\x00" * 16 + enc8((_ccq[0] + 1) % P) + enc8(_ccq[1]),
                           _cpath, bytes.fromhex(_pfq["comp_root"]), _kc, 2, prefix=16)
        except VMError:
            _rejc = True
        assert _rejc, "a forged comp(x_k) value opened against comp_root (query k=%d)" % _kc
    print("HP10.2 comp(x_k) opening against comp_root (DEEP: comp opened at the FS index, exposes cc for the "
          "quotient's comp-term): OK (honest accept + exposes cc; forged comp value rejected fail-closed)")

    # --- HP10.1/10.2/10.3 (HP10-rest): the deploy-sound per-query DEEP quotient -- open trace@k / sel@k /
    #     comp@k against the pinned roots at ONE index k (HP10.2 sel + comp openings; HP10.3 no @kn), source the
    #     DEEP-quotient `value` from the OPENED cells, and compute the hint-validated q(x_k). == query_terms on
    #     the real deep proof; a tampered trace/comp leaf, a wrong index, or a forged invz reject fail-closed.
    #     The masks/deep_alphas/invz/invzg are witness (single-source blob binding = HP12/HP15); the openings +
    #     quotient are the fully cashvm-testable part ---
    _tprq = bytes.fromhex(_pfq["tp_root"]); _cmrq = bytes.fromhex(_pfq["comp_root"])
    _selrq, _seltq, _ = build_selector_commitment_coset(_svq, _Nq)
    _depq = len(_pfq["queries"][0]["pk"])

    def _deep_ao(_q):                                            # (alpha, ood) per term, canonical deep_alphas order
        _ao = []
        for _c in _STKd.FLAT_COLS:
            _ao.append((_daq[len(_ao)], tuple(_pfq["Pcz"][_c])))
            _ao.append((_daq[len(_ao)], tuple(_pfq["Pczg"][_c])))
        for _dv, _m in _selq:
            _ao.append((_daq[len(_ao)], _m))
        _ao.append((_daq[len(_ao)], _rwq)); _ao.append((_daq[len(_ao)], _czq))
        return _ao

    def _deep_wit(_q):                                           # the three opener preimages + paths at k
        _kk = _q["k"]
        _tp = trace_leaf_preimage(_q["ck"], bytes.fromhex(_q["sk"]), _STKd.FLAT_COLS)
        _th = [(bytes.fromhex(_s), _b) for _s, _b in _q["pk"]]
        _sp = selector_preimage_coset(_svq, _kk); _sh = sm_path(_seltq, _kk)
        _ccp = tuple(_q["cc"]); _cp = b"\x00" * 16 + enc8(_ccp[0]) + enc8(_ccp[1])
        _ch = [(bytes.fromhex(_s), _b) for _s, _b in _q["cp"]]
        return _tp, _th, _sp, _sh, _cp, _ch

    for _dqi, _dq in enumerate(_pfq["queries"]):                # honest accept, every query (catches position bugs)
        _k = _dq["k"]; _x = _Ddq[_k]
        _ivz = F2.inv(F2.sub(F2.from_base(_x), _zq)); _ivzg = F2.inv(F2.sub(F2.from_base(_x), _zgq))
        _w = _deep_wit(_dq)
        _gqo, _ = run_per_query_deep_quotient(_depq, _tprq, _selrq, _cmrq, _nfq, _nsq, _x, _zq, _zgq,
                                              _deep_ao(_dq), _ivz, _ivzg, *_w, _k)
        assert _gqo == tuple(_qtq[_dqi]["comp_x"]), "opened per-query DEEP q(x_k) != query_terms (query %d)" % _dqi
    # tamper matrix on query 0: tampered trace/comp leaf, wrong index, forged invz -> fail-closed reject
    _dq0 = _pfq["queries"][0]; _k0 = _dq0["k"]; _x0 = _Ddq[_k0]; _ao0 = _deep_ao(_dq0)
    _ivz0 = F2.inv(F2.sub(F2.from_base(_x0), _zq)); _ivzg0 = F2.inv(F2.sub(F2.from_base(_x0), _zgq))
    _t0, _th0, _s0, _sh0, _c0, _ch0 = _deep_wit(_dq0); _cc0 = tuple(_dq0["cc"])
    _btk = trace_leaf_preimage({**_dq0["ck"], "s0": (_dq0["ck"]["s0"] + 1) % P},
                               bytes.fromhex(_dq0["sk"]), _STKd.FLAT_COLS)
    _bck = b"\x00" * 16 + enc8((_cc0[0] + 1) % P) + enc8(_cc0[1])
    assert run_per_query_deep_quotient(_depq, _tprq, _selrq, _cmrq, _nfq, _nsq, _x0, _zq, _zgq, _ao0, _ivz0,
                                       _ivzg0, _btk, _th0, _s0, _sh0, _c0, _ch0, _k0)[0] is None, \
        "per-query DEEP accepted a tampered trace leaf"
    assert run_per_query_deep_quotient(_depq, _tprq, _selrq, _cmrq, _nfq, _nsq, _x0, _zq, _zgq, _ao0, _ivz0,
                                       _ivzg0, _t0, _th0, _s0, _sh0, _bck, _ch0, _k0)[0] is None, \
        "per-query DEEP accepted a tampered comp leaf"
    _bsk = bytes([_s0[0] ^ 1]) + _s0[1:]                        # tampered sel leaf (flip one preimage byte) -> reject
    assert run_per_query_deep_quotient(_depq, _tprq, _selrq, _cmrq, _nfq, _nsq, _x0, _zq, _zgq, _ao0, _ivz0,
                                       _ivzg0, _t0, _th0, _bsk, _sh0, _c0, _ch0, _k0)[0] is None, \
        "per-query DEEP accepted a tampered sel leaf"
    assert run_per_query_deep_quotient(_depq, _tprq, _selrq, _cmrq, _nfq, _nsq, _x0, _zq, _zgq, _ao0, _ivz0,
                                       _ivzg0, _t0, _th0, _s0, _sh0, _c0, _ch0, (_k0 + 1) % _Nq)[0] is None, \
        "per-query DEEP accepted a wrong index"
    assert run_per_query_deep_quotient(_depq, _tprq, _selrq, _cmrq, _nfq, _nsq, _x0, _zq, _zgq, _ao0,
                                       ((_ivz0[0] + 1) % P, _ivz0[1]), _ivzg0, _t0, _th0, _s0, _sh0, _c0,
                                       _ch0, _k0)[0] is None, "per-query DEEP accepted a forged invz"
    assert run_per_query_deep_quotient(_depq, _tprq, _selrq, _cmrq, _nfq, _nsq, _x0, _zq, _zgq, _ao0, _ivz0,
                                       (_ivzg0[0], (_ivzg0[1] + 1) % P), _t0, _th0, _s0, _sh0, _c0,
                                       _ch0, _k0)[0] is None, "per-query DEEP accepted a forged invzg"
    print("HP10.1/10.2/10.3 per_query_deep_quotient (open trace@k/sel@k/comp@k vs pinned roots -> hint-validated "
          "q(x_k)) == query_terms for %d real queries: OK (tampered trace/comp leaf, wrong index, forged invz "
          "reject fail-closed; %d bytes redeem, <=10000B)"
          % (len(_pfq["queries"]), _prog_nbytes(per_query_deep_quotient_prog(_depq, _tprq, _selrq, _cmrq,
                                                                             _nfq, _nsq))))

    # --- HP10.1 (FRI-layer-0 bind): the per-query DEEP verify is complete only once q(x_k) is bound to FRI
    #     layer-0. Under DEEP the FRI folds q (NOT comp), so the EXISTING fold-8 chain (_fri_loop_chain_body,
    #     query_fri_terms_fold8) is DEEP-agnostic -- fed the OPENED q it folds to the committed final and binds
    #     it. The opened per_query_deep_quotient q, run through that chain, accepts for every real query; a
    #     tampered q (!= FRI layer-0) rejects fail-closed. This closes q==FRI-layer-0 (the byte budget forces the
    #     fold into a SEPARATE FRI input consuming q cross-input, HP12/HP15; the fold itself is the reused chain) ---
    _qffq = {_qq["k"]: _qq for _qq in _STKd.query_fri_terms_fold8(_pfq)}
    _finalq = _pfq["final"]; _friq = 0
    for _fq in _pfq["queries"]:
        _fk = _fq["k"]; _fx = _Ddq[_fk]
        _fivz = F2.inv(F2.sub(F2.from_base(_fx), _zq)); _fivzg = F2.inv(F2.sub(F2.from_base(_fx), _zgq))
        _fqv, _ = run_per_query_deep_quotient(_depq, _tprq, _selrq, _cmrq, _nfq, _nsq, _fx, _zq, _zgq,
                                              _deep_ao(_fq), _fivz, _fivzg, *_deep_wit(_fq), _fk)
        _fok, _ = run_fri_loop_chain(_qffq[_fk]["rounds"], _fk, _fqv, _finalq, _oNq, _offq)
        assert _fok, "opened DEEP q(x_k) did not fold through the FRI chain (q != FRI layer-0, k=%d)" % _fk
        _fbad, _ = run_fri_loop_chain(_qffq[_fk]["rounds"], _fk, ((_fqv[0] + 1) % P, _fqv[1]),
                                      _finalq, _oNq, _offq)
        assert not _fbad, "the FRI chain accepted a tampered q as layer-0 (k=%d)" % _fk
        _friq += 1
    assert _friq > 0, "HP10.1 FRI-layer-0 bind exercised no query"
    print("HP10.1 FRI-layer-0 bind: the opened per_query_deep_quotient q(x_k) folds through the existing fold-8 "
          "FRI chain (_fri_loop_chain_body) to accept for %d real queries (q==FRI layer-0; DEEP folds q not comp); "
          "a tampered q rejects fail-closed" % _friq)

    # --- HP13.2: validate the GF(p^2) z-EVAL inverse hints comp_at_z_ext consumes (qf=(z-last)*ZHz_inv,
    #     bound_invX[r]=(z-Hd[row])^-1) fail-closed -- the ext counterpart of qf_bound_prog (base). Real deep
    #     proof: honest hints accept; a forged qf (favourable normalizer) or any forged bound_invX rejects. ---
    _bcq = _STKd.ct_boundary_constraints(_mq, _stq); _rowsq = [_row for _row, _fn in _bcq]
    _hdq = [_Hdq[_row] % P for _row in _rowsq]
    _zhzi = F2.inv(F2.sub(F2.power(_zq, _Tq), F2.ONE))
    _qfz = F2.mul(F2.sub(_zq, F2.from_base(_lastq)), _zhzi)
    _binvxz = [F2.inv(F2.sub(_zq, F2.from_base(_Hdq[_row]))) for _row in _rowsq]
    _l2t = _Tq.bit_length() - 1
    assert (1 << _l2t) == _Tq, "T=%d not a power of 2" % _Tq
    assert run_zeval_hint_check(_l2t, _lastq, _hdq, _zq, _qfz, _binvxz)[0], "honest z-eval hints rejected"
    assert not run_zeval_hint_check(_l2t, _lastq, _hdq, _zq, ((_qfz[0] + 1) % P, _qfz[1]), _binvxz)[0], \
        "forged qf accepted"
    assert not run_zeval_hint_check(_l2t, _lastq, _hdq, _zq, (_qfz[0], (_qfz[1] + 1) % P), _binvxz)[0], \
        "forged qf (limb1) accepted"
    _bxbad = list(_binvxz); _bxbad[0] = ((_bxbad[0][0] + 1) % P, _bxbad[0][1])
    assert not run_zeval_hint_check(_l2t, _lastq, _hdq, _zq, _qfz, _bxbad)[0], "forged bound_invX accepted"
    assert not run_zeval_hint_check(_l2t, _lastq, _hdq, ((_zq[0] + 1) % P, _zq[1]), _qfz, _binvxz)[0], \
        "wrong z accepted"
    print("HP13.2 z-eval GF(p^2) hint validation (qf*(z^T-1)==(z-last) + bound_invX*(z-Hd)==1, ext counterpart of "
          "qf_bound): OK (honest accept; forged qf/bound_invX/z reject fail-closed; %d bytes redeem, T=%d)"
          % (_prog_nbytes(ext_zeval_hint_check_prog(_l2t, _lastq, _hdq)), _Tq))

    # --- HP12 byte lever: split_cells_loop == unrolled split_cells. The DEEP per-query consumer reads the FS
    #     blob (z+z*g+138 ood+138 deep_alphas = 556 field cells) via OP_INPUTBYTECODE (HP12/HP15) and splits it
    #     on-chain; the unrolled split(556)=4444B blows the redeem, the BEGIN/UNTIL loop is ~constant ~23B, so the
    #     blob-sourced consumer (~8.9KB) fits <=10000B in ONE input (no per-query split needed). ---
    for _nl, _pfx in [(1, 0), (33, 0), (52, 16), (138, 0), (556, 0), (556, 16)]:
        _bl = b"\x00" * _pfx + b"".join(enc8((7 * _i * _i + 3) % P) for _i in range(_nl))
        _exp = [(7 * _i * _i + 3) % P for _i in range(_nl)]
        _vml = VM(); _vml.run([PUSH(_bl)] + split_cells_loop(_nl, _pfx))
        _vmu = VM(); _vmu.run([PUSH(_bl)] + split_cells_prog(_nl, prefix=_pfx))
        assert [decode_num(_x) for _x in _vml.s] == _exp, "split_cells_loop != cells (n=%d pfx=%d)" % (_nl, _pfx)
        assert [decode_num(_x) for _x in _vmu.s] == _exp, "split_cells unroll != cells (n=%d pfx=%d)" % (_nl, _pfx)
    print("HP12 split_cells_loop (byte-amortized blob split) == unrolled split_cells for n in {1,33,52,138,556}: "
          "OK (556-cell DEEP blob: loop=%dB vs unrolled=%dB -> blob-sourced per-query consumer fits <=10000B)"
          % (_prog_nbytes(split_cells_loop(556, 0)), _prog_nbytes(split_cells_prog(556, prefix=0))))

    # --- HP12/HP15: the BLOB-SOURCED per-query DEEP consumer -- ood/deep_alphas/z/z*g single-sourced from the ONE
    #     FS blob (split on-chain via split_cells_loop) instead of the per-input witness (HP15.2: 16886B witness
    #     blew the cap). == query_terms + FITS <=10000B in ONE input. The blob is a witness push here; the deploy
    #     reads it cross-input via OP_INPUTBYTECODE (HP15, node _linked). Tampered leaf / forged invz reject. ---
    for _bqi, _bq in enumerate(_pfq["queries"]):
        _bk = _bq["k"]; _bx = _Ddq[_bk]
        _bivz = F2.inv(F2.sub(F2.from_base(_bx), _zq)); _bivzg = F2.inv(F2.sub(F2.from_base(_bx), _zgq))
        _bgot, _ = run_per_query_deep_quotient_blob(_depq, _tprq, _selrq, _cmrq, _nfq, _nsq, _bx, _bivz, _bivzg,
                                                    _deep_ao(_bq), _zq, _zgq, *_deep_wit(_bq), _bk)
        assert _bgot == tuple(_qtq[_bqi]["comp_x"]), "blob-sourced per-query DEEP q(x_k) != query_terms (q %d)" % _bqi
    _bq0 = _pfq["queries"][0]; _bk0 = _bq0["k"]; _bx0 = _Ddq[_bk0]; _bao0 = _deep_ao(_bq0)
    _bivz0 = F2.inv(F2.sub(F2.from_base(_bx0), _zq)); _bivzg0 = F2.inv(F2.sub(F2.from_base(_bx0), _zgq))
    _bt0, _bth0, _bs0, _bsh0, _bc0, _bch0 = _deep_wit(_bq0)
    _bbtk = trace_leaf_preimage({**_bq0["ck"], "s0": (_bq0["ck"]["s0"] + 1) % P}, bytes.fromhex(_bq0["sk"]),
                                _STKd.FLAT_COLS)
    assert run_per_query_deep_quotient_blob(_depq, _tprq, _selrq, _cmrq, _nfq, _nsq, _bx0, _bivz0, _bivzg0, _bao0,
                                            _zq, _zgq, _bbtk, _bth0, _bs0, _bsh0, _bc0, _bch0, _bk0)[0] is None, \
        "blob consumer accepted a tampered trace leaf"
    assert run_per_query_deep_quotient_blob(_depq, _tprq, _selrq, _cmrq, _nfq, _nsq, _bx0,
                                            ((_bivz0[0] + 1) % P, _bivz0[1]), _bivzg0, _bao0, _zq, _zgq, _bt0,
                                            _bth0, _bs0, _bsh0, _bc0, _bch0, _bk0)[0] is None, \
        "blob consumer accepted a forged invz"
    print("HP12/HP15 blob-sourced per_query_deep_quotient (ood/deep_alphas/z/z*g from the split FS blob via "
          "split_cells_loop) == query_terms for %d real queries: OK (tampered trace / forged invz reject fail-"
          "closed; redeem %d bytes <=10000B -> the DEEP per-query consumer FITS in ONE input)"
          % (len(_pfq["queries"]), _prog_nbytes(per_query_deep_quotient_blob_prog(_depq, _tprq, _selrq, _cmrq,
                                                                                  _nfq, _nsq))))

    # --- HP12/HP16 thin-shard: the DEEP quotient shards into <=3.3KB SUM-parts. q = invz*Sum_z + invzg*Sum_zg;
    #     part_z (85 z-terms, 2822B) + part_zg (53 z*g-terms, 1766B) each carry ONE ext accumulator (HP9.7-9.8
    #     comp_split pattern), the final combine (182B) applies invz/invzg. == query_terms + each part <=3300B, so
    #     the DEEP per-query verify FITS the thin-shard covenant (L3 std 1650B / consensus 10000B). The acc carry
    #     chains across sub-parts (2-sub-part Sum_z == single). The cross-input carry read is HP15 (OP_INPUTBYTECODE). ---
    _zt = [2 * _c for _c in range(_nfq)] + [2 * _nfq + _s for _s in range(_nsq)] + [2 * _nfq + _nsq + 1]
    _zgt = [2 * _c + 1 for _c in range(_nfq)] + [2 * _nfq + _nsq]
    for _spqi, _spq in enumerate(_pfq["queries"]):
        _spk = _spq["k"]; _spx = _Ddq[_spk]
        _spivz = F2.inv(F2.sub(F2.from_base(_spx), _zq)); _spivzg = F2.inv(F2.sub(F2.from_base(_spx), _zgq))
        _spck = _spq["ck"]; _spterms = []
        for _c in _STKd.FLAT_COLS:
            _cke = F2.from_base(_spck[_c])
            _spterms.append((_daq[len(_spterms)], _cke, tuple(_pfq["Pcz"][_c])))
            _spterms.append((_daq[len(_spterms)], _cke, tuple(_pfq["Pczg"][_c])))
        for _dv, _m in _selq:
            _spterms.append((_daq[len(_spterms)], F2.from_base(_dv[_spk]), _m))
        _spterms.append((_daq[len(_spterms)], F2.from_base(_svq["range_weight"][_spk]), _rwq))
        _spterms.append((_daq[len(_spterms)], tuple(_spq["cc"]), _czq))
        _zsl = [_spterms[_i] for _i in _zt]; _zgsl = [_spterms[_i] for _i in _zgt]
        _Sz, _ocSz = run_deep_sum_part(_zsl, F2.ZERO)
        _Szg, _ = run_deep_sum_part(_zgsl, F2.ZERO)
        # HP16 op-cost lever: the LAZY (deferred-reduction) sum-part == the eager form, mathematically identical
        # (accumulate raw, reduce mod p once) -> ~3.7x lower op-cost -> the op-cost-bound DEEP shard floor collapses.
        _Szl, _ocSzl = run_deep_sum_part_lazy(_zsl, F2.ZERO)
        _Szgl, _ = run_deep_sum_part_lazy(_zgsl, F2.ZERO)
        assert _Szl == _Sz and _Szgl == _Szg, "HP16 lazy deep_sum_part != eager (q %d)" % _spqi
        if _spqi == 0:
            print("HP16 LAZY deep_sum_part (deferred mod-reduction: raw accumulate, reduce once) == eager sum-part: "
                  "OK (identical field element; op_cost %d -> %d = %.2fx lower -> the op-cost-bound DEEP shard floor "
                  "collapses, security-neutral)" % (_ocSz, _ocSzl, _ocSz / _ocSzl if _ocSzl else 0))
        _spq_got, _ = run_deep_final_combine(_Sz, _Szg, _spivz, _spivzg)
        assert _spq_got == tuple(_qtq[_spqi]["comp_x"]), "thin-shard split q(x_k) != query_terms (q %d)" % _spqi
        _spq_cs, _ = run_deep_final_combine(_Sz, _Szg, _spivz, _spivzg, carry_split=True)   # HP12 deploy consumer form
        assert _spq_cs == _spq_got, "HP12 carry_split final-combine (Sum_z read cross-input) != non-split (q %d)" % _spqi
        _spq_dl, _ = run_deep_final_combine(_Sz, _Szg, _spivz, _spivzg, dual=True)          # HP16.1 full 3-input consumer form
        assert _spq_dl == _spq_got, "HP16.1 dual final-combine (Sum_z + Sum_zg BOTH read cross-input) != non-split (q %d)" % _spqi
        _spq_dc, _ = run_deep_final_combine(_Sz, _Szg, _spivz, _spivzg, dual_carry=True)    # Design A: ONE 32B (Sum_z||Sum_zg) carry
        assert _spq_dc == _spq_got, "HP12.3 Design A dual_carry final-combine (one 32B carry read) != non-split (q %d)" % _spqi
        # HP12.3/R4-B1: the blob-sourced sum-part reads alpha/ood single-source from the FS blob (not a free witness).
        _ao98 = [(_t[0], _t[2]) for _t in _spterms]                                          # (alpha, ood) all n_terms
        _vz98 = [_spterms[_i][1] for _i in _zt]; _vzg98 = [_spterms[_i][1] for _i in _zgt]   # values per shard term
        _Szbl, _ = run_deep_sum_part_blob(F2.ZERO, _vz98, _zq, _zgq, _ao98, _zt)
        _Szgbl, _ = run_deep_sum_part_blob(F2.ZERO, _vzg98, _zq, _zgq, _ao98, _zgt)
        assert _Szbl == _Sz and _Szgbl == _Szg, \
            "HP12.3/R4-B1 blob-sourced sum-part (alpha/ood single-source from blob) != witness-sourced (q %d)" % _spqi
        _aobad = list(_ao98)
        _aobad[_zt[0]] = (_aobad[_zt[0]][0], ((_aobad[_zt[0]][1][0] + 1) % P, _aobad[_zt[0]][1][1]))
        assert run_deep_sum_part_blob(F2.ZERO, _vz98, _zq, _zgq, _aobad, _zt)[0] != _Sz, \
            "HP12.3/R4-B1 tampered blob ood produced the honest sum -> not single-sourced (q %d)" % _spqi
        # blob-sourced DEPLOY producer form (carry_bound): acc_out self-bound to carry_out_preimage (forged -> reject).
        assert run_deep_sum_part_blob(F2.ZERO, _vz98, _zq, _zgq, _ao98, _zt, carry_bound=True, acc_out=_Sz)[0] == 1 \
            and run_deep_sum_part_blob(F2.ZERO, _vzg98, _zq, _zgq, _ao98, _zgt, carry_bound=True, acc_out=_Szg)[0] == 1, \
            "HP12.3 blob-sourced carry_bound producer MUST accept the honest acc_out (q %d)" % _spqi
        assert run_deep_sum_part_blob(F2.ZERO, _vz98, _zq, _zgq, _ao98, _zt, carry_bound=True, acc_out=((_Sz[0] + 1) % P, _Sz[1]))[0] is None \
            and run_deep_sum_part_blob(F2.ZERO, _vz98, _zq, _zgq, _ao98, _zt, carry_bound=True, acc_out=(_Sz[0], (_Sz[1] + 1) % P))[0] is None, \
            "HP12.3 blob-sourced carry_bound forged acc_out MUST reject (q %d)" % _spqi
        # HP12.3 Design A: contiguous-range dual-acc shard (op-cost-optimal -- reads only its ood/alpha slice).
        _allv = [_t[1] for _t in _spterms]; _allo = [_t[2] for _t in _spterms]; _alla = [_t[0] for _t in _spterms]
        _ntq3 = len(_spterms); _midq3 = _ntq3 // 2
        (_azf, _azgf), _ocdf = run_deep_sum_part_dual(0, _ntq3, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv, _allo, _alla)
        assert _azf == _Sz and _azgf == _Szg, "HP12.3 Design A full-range dual != (Sum_z, Sum_zg) (q %d)" % _spqi
        (_az1, _azg1), _ = run_deep_sum_part_dual(0, _midq3, _nfq, _nsq, F2.ZERO, F2.ZERO,
                                                  _allv[:_midq3], _allo[:_midq3], _alla[:_midq3])
        (_az2, _azg2), _ = run_deep_sum_part_dual(_midq3, _ntq3, _nfq, _nsq, _az1, _azg1,
                                                  _allv[_midq3:], _allo[_midq3:], _alla[_midq3:])
        assert _az2 == _Sz and _azg2 == _Szg, "HP12.3 Design A contiguous-range carry-chain != single (q %d)" % _spqi
        # HP16.1 STEP 2: the LAZY (deferred-reduction) dual sum-part == the eager dual, mathematically identical (raw
        # accumulate, reduce each acc mod p ONCE before carry-expose) -> ~2x lower shard op-cost, ZERO security impact.
        (_azl, _azgl), _ocdl = run_deep_sum_part_dual(0, _ntq3, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv, _allo, _alla, lazy=True)
        assert _azl == _Sz and _azgl == _Szg, "HP16.1 lazy dual sum-part != eager (Sum_z, Sum_zg) (q %d)" % _spqi
        (_azl1, _azgl1), _ = run_deep_sum_part_dual(0, _midq3, _nfq, _nsq, F2.ZERO, F2.ZERO,
                                                    _allv[:_midq3], _allo[:_midq3], _alla[:_midq3], lazy=True)
        (_azl2, _azgl2), _ = run_deep_sum_part_dual(_midq3, _ntq3, _nfq, _nsq, _azl1, _azgl1,
                                                    _allv[_midq3:], _allo[_midq3:], _alla[_midq3:], lazy=True)
        assert _azl2 == _Sz and _azgl2 == _Szg, "HP16.1 lazy dual carry-chain != single (q %d)" % _spqi
        assert run_deep_sum_part_dual(0, _ntq3, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv, _allo, _alla,
                                      carry_bound=True, acc_z_out=_Sz, acc_zg_out=_Szg, lazy=True)[0] == 1, \
            "HP16.1 lazy dual carry_bound honest MUST accept (q %d)" % _spqi
        assert run_deep_sum_part_dual(0, _ntq3, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv, _allo, _alla,
                                      carry_bound=True, acc_z_out=((_Sz[0] + 1) % P, _Sz[1]), acc_zg_out=_Szg, lazy=True)[0] is None \
            and run_deep_sum_part_dual(0, _ntq3, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv, _allo, _alla,
                                       carry_bound=True, acc_z_out=_Sz, acc_zg_out=(_Szg[0], (_Szg[1] + 1) % P), lazy=True)[0] is None, \
            "HP16.1 lazy dual carry_bound forged carry-out MUST reject (q %d)" % _spqi
        # HP16.1 THE byte lever: the LOOPED dual (per-term MAC via BEGIN/UNTIL) == eager dual -> the shard redeem
        # collapses (the 70-term MAC logic revealed once, not unrolled), the dominant whole-tx duplication.
        (_azL, _azgL), _ = run_deep_sum_part_dual_loop(0, _ntq3, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv, _allo, _alla)
        assert (_azL, _azgL) == (_Sz, _Szg), "HP16.1 looped dual sum-part != eager (Sum_z, Sum_zg) (q %d)" % _spqi
        (_azL1, _azgL1), _ = run_deep_sum_part_dual_loop(0, _midq3, _nfq, _nsq, F2.ZERO, F2.ZERO,
                                                         _allv[:_midq3], _allo[:_midq3], _alla[:_midq3])
        (_azL2, _azgL2), _ = run_deep_sum_part_dual_loop(_midq3, _ntq3, _nfq, _nsq, _azL1, _azgL1,
                                                         _allv[_midq3:], _allo[_midq3:], _alla[_midq3:])
        assert (_azL2, _azgL2) == (_Sz, _Szg), "HP16.1 looped dual carry-chain != single (q %d)" % _spqi
        if _spqi == 0:
            _rb_un = _prog_nbytes(deep_sum_part_dual_prog(0, _ntq3, _nfq, _nsq))
            _zi0, _zgi0 = _deep_dual_zsplit(0, _ntq3, _nfq, _nsq)
            _rb_lp = _prog_nbytes(deep_sum_part_dual_loop_prog(len(_zi0), len(_zgi0)))
            print("HP16.1 LOOPED dual sum-part (per-term MAC via BEGIN/UNTIL, OP_DEPTH-pinned, lazy 0x29 raw) == eager "
                  "dual + carry-chain: OK (identical (Sum_z, Sum_zg); redeem %dB -> %dB = -%dB/shard, the shard-redeem "
                  "duplication collapses -> whole-tx headroom)" % (_rb_un, _rb_lp, _rb_un - _rb_lp))
        # HP16.1 realized: the pure-trace looped shard (byte-string interleave-route -> split -> single-acc lazy loop),
        # the deploy form (alpha/ood from the blob slice, value from the witness/opener; NO on-VM PICK-depth arithmetic).
        _ptw = 2 * _nfq                                                              # pure-trace window [0, 2*nf)
        (_ez_pt, _ezg_pt), _ = run_deep_sum_part_dual(0, _ptw, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv[:_ptw], _allo[:_ptw], _alla[:_ptw])
        _pt_got, _ = run_deep_sum_part_puretrace_loop(0, _ptw, _nfq, _nsq, _allv[:_ptw], _allo[:_ptw], _alla[:_ptw])
        assert _pt_got == (_ez_pt, _ezg_pt), "HP16.1 pure-trace looped shard != eager dual (q %d)" % _spqi
        # HP16.1 THE net-positive deploy shard: counter-driven multi-block dual (no reshaping; op-cost-bound ~2190B <<
        # unrolled 3290B). Same pure-trace window, == eager.
        _cd_got, _occd = run_deep_sum_part_counter_dual(0, _ptw, _nfq, _nsq, _allv[:_ptw], _allo[:_ptw], _alla[:_ptw])
        assert _cd_got == (_ez_pt, _ezg_pt), "HP16.1 counter-driven dual shard != eager dual (q %d)" % _spqi
        _dep_got, _ = run_deep_sum_part_counter_dual_deploy(0, _ptw, _nfq, _nsq, _allv[:_ptw], _allo[:_ptw], _alla[:_ptw])
        assert _dep_got == (_ez_pt, _ezg_pt), "HP16.1 blob-sourced counter-driven deploy shard != eager dual (q %d)" % _spqi
        # loop#9 VALUE-SINGLE-SOURCE shard: the 2*nf trace terms reference only nf distinct BASE cells (term 2c & 2c+1
        # both = ck[c], value1=0). The value-block is nf base cells (counter c, value1 const 0, alpha/ood mult=4). ==
        # eager; in the deploy the cells are read cross-input from the trace opener (R4-B1, merkle-verified vs tp_root).
        _cellsb = [_allv[2 * _c][0] for _c in range(_nfq)]         # nf BASE trace cells (real part; imag = 0)
        _dd_got, _ = run_deep_sum_part_dedup(_nfq, _cellsb, _alla[:_ptw], _allo[:_ptw])
        assert _dd_got == (_ez_pt, _ezg_pt), "loop#9 value-single-source shard != eager dual (q %d)" % _spqi
        if _spqi == 0:
            assert all(_allv[2 * _c] == _allv[2 * _c + 1] for _c in range(_nfq)), "value-source assumption broken: term 2c != 2c+1 value"
            assert all(_allv[2 * _c][1] == 0 for _c in range(_nfq)), "value-source assumption broken: trace cell imag != 0"
            print("loop#9 VALUE-SINGLE-SOURCE shard (nf BASE cells, counter c, value1 const 0, alpha/ood mult=4) == "
                  "eager dual over %d trace terms: OK (R4-B1 value single-source from the trace opener 4h, "
                  "merkle-verified vs tp_root; real-libauth forged-cell reject in proto_value_source)" % _ptw)
        # loop#9 TAIL counter-driven deploy shard [2*nf : n_terms) (sel z-block + range_weight zg + comp z; 3 strided
        # loops + ext-add, no reshaping). == eager deep_sum_part_dual over the tail; byte-bound (op-cost ~798K).
        (_ez_tl, _ezg_tl), _ = run_deep_sum_part_dual(_ptw, _ntq3, _nfq, _nsq, F2.ZERO, F2.ZERO,
                                                      _allv[_ptw:], _allo[_ptw:], _alla[_ptw:])
        _tlc_got, _octl = run_deep_sum_part_tail_counter_deploy(_ptw, _ntq3, _nfq, _nsq,
                                                                _allv[_ptw:], _allo[_ptw:], _alla[_ptw:])
        assert _tlc_got == (_ez_tl, _ezg_tl), "loop#9 counter-driven tail deploy shard != eager dual (q %d)" % _spqi
        # loop#9(c) carry_bound chain form (in+out): shardA (carry_in=predecessor) and tail (carry_in=shardA total).
        # Post-loop-add of carry_in (associative == threading acc_in) + self-bind total == carry_out_pre (fail-closed).
        _cin_z, _cin_zg = (0x1234567 % P, 0x7654321 % P), (0x1111111 % P, 0x2222222 % P)   # simulated predecessor carry
        (_Sza_c, _Szga_c), _ = run_deep_sum_part_dual(0, _ptw, _nfq, _nsq, _cin_z, _cin_zg, _allv[:_ptw], _allo[:_ptw], _alla[:_ptw])
        _ok_ca, _ = run_deep_sum_part_counter_dual_deploy(0, _ptw, _nfq, _nsq, _allv[:_ptw], _allo[:_ptw], _alla[:_ptw],
                                                          carry_bound=True, acc_z_in=_cin_z, acc_zg_in=_cin_zg,
                                                          acc_z_out=_Sza_c, acc_zg_out=_Szga_c)
        assert _ok_ca == 1, "loop#9(c) counter-driven shardA carry_bound honest reject (q %d)" % _spqi
        _bad_ca, _ = run_deep_sum_part_counter_dual_deploy(0, _ptw, _nfq, _nsq, _allv[:_ptw], _allo[:_ptw], _alla[:_ptw],
                                                           carry_bound=True, acc_z_in=_cin_z, acc_zg_in=_cin_zg,
                                                           acc_z_out=(_Sza_c[0] ^ 1, _Sza_c[1]), acc_zg_out=_Szga_c)
        assert _bad_ca is None, "loop#9(c) counter-driven shardA carry_bound forged carry_out NOT rejected (q %d)" % _spqi
        (_Szt_c, _Szgt_c), _ = run_deep_sum_part_dual(_ptw, _ntq3, _nfq, _nsq, _Sza_c, _Szga_c, _allv[_ptw:], _allo[_ptw:], _alla[_ptw:])
        _ok_ct, _ = run_deep_sum_part_tail_counter_deploy(_ptw, _ntq3, _nfq, _nsq, _allv[_ptw:], _allo[_ptw:], _alla[_ptw:],
                                                          carry_bound=True, acc_z_in=_Sza_c, acc_zg_in=_Szga_c,
                                                          acc_z_out=_Szt_c, acc_zg_out=_Szgt_c)
        assert _ok_ct == 1, "loop#9(c) counter-driven tail carry_bound honest reject (q %d)" % _spqi
        _bad_ct, _ = run_deep_sum_part_tail_counter_deploy(_ptw, _ntq3, _nfq, _nsq, _allv[_ptw:], _allo[_ptw:], _alla[_ptw:],
                                                           carry_bound=True, acc_z_in=_Sza_c, acc_zg_in=_Szga_c,
                                                           acc_z_out=_Szt_c, acc_zg_out=(_Szgt_c[0] ^ 1, _Szgt_c[1]))
        assert _bad_ct is None, "loop#9(c) counter-driven tail carry_bound forged carry_out NOT rejected (q %d)" % _spqi
        if _spqi == 0:
            # the shardA->tail carry-chain total == the single-pass eager sum over ALL terms (deploy consistency)
            (_Sall, _Sgall), _ = run_deep_sum_part_dual(0, _ntq3, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv, _allo, _alla)
            (_Sa0, _Sga0), _ = run_deep_sum_part_dual(0, _ptw, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv[:_ptw], _allo[:_ptw], _alla[:_ptw])
            (_Sc, _Sgc), _ = run_deep_sum_part_dual(_ptw, _ntq3, _nfq, _nsq, _Sa0, _Sga0, _allv[_ptw:], _allo[_ptw:], _alla[_ptw:])
            assert (_Sc, _Sgc) == (_Sall, _Sgall), "loop#9(c) shardA->tail carry-chain total != single-pass eager"
            print("loop#9(c) counter-driven carry_bound chain (shardA carry_out -> tail carry_in -> total, post-loop-add "
                  "== threaded acc_in): OK (honest accept + forged carry_out reject BOTH shards; chain total == single-pass "
                  "eager over all %d terms) -- unblocks the full single-tx _p2sh_multi (HP16.1)" % _ntq3)
            # HP16.1 ci-on-top deploy-chain bind (carry_in READ cross-input -> lands on TOP): the standalone loops leave
            # [co@0, Sl_z, Sl_zg]; push ci on top (cashvm sim of the OP_INPUTBYTECODE read) then counter_carry_bind_ci_top.
            _ci_z, _ci_zg = (0x9a % P, 0xbc % P), (0xde % P, 0xf0 % P)
            (_St_z, _St_zg), _ = run_deep_sum_part_dual(0, _ptw, _nfq, _nsq, _ci_z, _ci_zg, _allv[:_ptw], _allo[:_ptw], _alla[:_ptw])
            _vc = []
            for _i in range(_ptw):
                _vc += [NUM(_allv[_i][0] % P), NUM(_allv[_i][1] % P)]
            _sl = (b"".join(enc8(_allo[_i][0] % P) + enc8(_allo[_i][1] % P) for _i in range(_ptw))
                   + b"".join(enc8(_alla[_i][0] % P) + enc8(_alla[_i][1] % P) for _i in range(_ptw)))
            _cop = _acc_preimage(_St_z) + _acc_preimage(_St_zg)          # carry_out_pre (the total)
            _cip = _acc_preimage(_ci_z) + _acc_preimage(_ci_zg)          # carry_in_pre (read cross-input in deploy)

            _zict, _zgict = _deep_dual_zsplit(0, _ptw, _nfq, _nsq)

            def _run_citop(cop):
                _vm = VM()
                try:
                    _vm.run(_field_prelude() + [PUSH(cop)] + _vc + [PUSH(_sl)]
                            + deep_sum_part_counter_dual_deploy_prog(_ptw, len(_zict), len(_zgict))  # carry_bound=False -> [co, Sl_z, Sl_zg]
                            + [PUSH(_cip)] + counter_carry_bind_ci_top_prog())
                    return len(_vm.s) == 1 and decode_num(_vm.s[-1]) == 1
                except VMError:
                    return False
            assert _run_citop(_cop), "HP16.1 ci-on-top deploy-chain bind honest reject"
            assert not _run_citop(bytes([_cop[0] ^ 1]) + _cop[1:]), "HP16.1 ci-on-top bind forged carry_out NOT rejected"
            print("HP16.1 ci-on-top deploy-chain carry bind (carry_in read cross-input -> stack top; add + self-bind total "
                  "== carry_out_pre): OK (honest accept + forged reject) -- real 3-input blob+shardA+tail chain verified "
                  "on libauth (proto_chain_multi)")
            # HP16.1 final-combine q-bind: q = invz*Sum_z + invzg*Sum_zg from the chain total (32B carry read cross-input)
            # + self-bind q == q_pre so the FRI can read q. (invz/invzg valid GF(p^2); their hint-validation is HP13.)
            _ivz, _ivzg = (2, 3), (5, 7)
            _qref, _ = run_deep_final_combine(_St_z, _St_zg, _ivz, _ivzg, dual_carry=True)
            _okq, _ = run_deep_final_combine_qbound(_St_z, _St_zg, _ivz, _ivzg, _qref)
            assert _okq == 1, "HP16.1 final-combine q-bind honest reject"
            _badq, _ = run_deep_final_combine_qbound(_St_z, _St_zg, _ivz, _ivzg, (_qref[0] ^ 1, _qref[1]))
            assert _badq is None, "HP16.1 final-combine q-bind forged q NOT rejected"
            print("HP16.1 final-combine q-bind (q = invz*Sum_z + invzg*Sum_zg from the cross-input chain total; self-bind "
                  "q == q_pre for the FRI layer-0 read): OK (honest accept + forged q reject) -- real 4-input "
                  "blob+shardA+tail+final chain verified on libauth (proto_chain4)")
        if _spqi == 0:
            _rb_tlu = _prog_nbytes(deep_sum_part_dual_prog(_ptw, _ntq3, _nfq, _nsq, lazy=True))
            _rb_tlc = _prog_nbytes(deep_sum_part_tail_counter_deploy_prog(_ntq3 - _ptw, _nsq))
            print("loop#9 counter-driven TAIL deploy shard [%d:%d] (sel z-block step-1 loop + comp/range_weight single "
                  "+ ext-add, NO reshaping) == eager dual: OK (identical (Sum_z, Sum_zg); redeem %dB -> %dB, byte-bound "
                  "op-cost ~%d < budget)" % (_ptw, _ntq3, _rb_tlu, _rb_tlc, _octl))
        if _spqi == 0:
            _zic, _zgic = _deep_dual_zsplit(0, _ptw, _nfq, _nsq)
            print("HP16.1 NET-POSITIVE counter-driven dual shard (operands read in place via counter-computed PICK "
                  "depths, NO reshaping/route -> op-cost ~ unrolled, redeem collapses) == eager dual over %d trace "
                  "terms: OK (identical (Sum_z, Sum_zg); real-libauth op-cost floor ~2190B << unrolled 3290B = "
                  "-1821B/shard, whole-tx projected ~87.5KB < 100000)" % _ptw)
        if _spqi == 0:
            _zip, _zgip = _deep_dual_zsplit(0, _ptw, _nfq, _nsq)
            _rb_pt = _prog_nbytes(deep_sum_part_puretrace_loop_prog(len(_zip), len(_zgip)))
            print("HP16.1 REALIZED pure-trace looped shard (byte-string interleave-route + split + single-acc lazy loop, "
                  "deploy form: alpha/ood from blob slice, value witness/opener, NO PICK-depth arithmetic) == eager dual "
                  "over %d trace terms: OK (identical (Sum_z, Sum_zg); full-shard redeem collapses to %dB revealed once)"
                  % (_ptw, _rb_pt))
        if _spqi == 0:
            print("HP16.1 STEP 2 LAZY dual sum-part (deferred mod-reduction in the DEPLOYED deep_sum_part_dual: raw "
                  "accumulate, reduce each acc once before carry-expose) == eager dual + carry-chain + carry_bound "
                  "(honest accept / forged reject): OK (identical (Sum_z, Sum_zg); op_cost %d -> %d = %.2fx lower, "
                  "security-neutral, carry format 32B unchanged)" % (_ocdf, _ocdl, _ocdf / _ocdl if _ocdl else 0))
        # HP12.3 Design A DEPLOY producer form (carry_bound): (acc_z, acc_zg) self-bound to the 32B carry_out (forged -> reject).
        assert run_deep_sum_part_dual(0, _ntq3, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv, _allo, _alla,
                                      carry_bound=True, acc_z_out=_Sz, acc_zg_out=_Szg)[0] == 1, \
            "HP12.3 Design A carry_bound dual honest MUST accept (q %d)" % _spqi
        assert run_deep_sum_part_dual(0, _ntq3, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv, _allo, _alla,
                                      carry_bound=True, acc_z_out=((_Sz[0] + 1) % P, _Sz[1]), acc_zg_out=_Szg)[0] is None \
            and run_deep_sum_part_dual(0, _ntq3, _nfq, _nsq, F2.ZERO, F2.ZERO, _allv, _allo, _alla,
                                       carry_bound=True, acc_z_out=_Sz, acc_zg_out=(_Szg[0], (_Szg[1] + 1) % P))[0] is None, \
            "HP12.3 Design A carry_bound dual forged carry-out MUST reject (q %d)" % _spqi
        # HP16 Design A DEPLOY op-cost form: the partial shard reads ONLY its ood[lo:hi]+alpha[lo:hi] slice from the
        # ONE FS blob (deep_dual_slice_read_prog: two byte-range extracts + CAT) instead of a witness slice -- op-cost
        # scales with the shard. Verify: (a) reconstructed slice == the witness slice; (b) the partial shard accepts
        # on the reconstructed slice == the GF(p^2) partial reference over a contiguous tail window [_midq3, _ntq3).
        _aoq3 = [(_t[0], _t[2]) for _t in _spterms]                                    # (alpha, ood) per term (blob order)
        _blobq3 = _deep_blob_bytes(F2.ZERO, F2.ZERO, _aoq3)
        _vmsr = VM(); _vmsr.run([PUSH(_blobq3)] + deep_dual_slice_read_prog(_midq3, _ntq3, _ntq3))
        _expsr = (b"".join(enc8(_c[0] % P) + enc8(_c[1] % P) for _c in _allo[_midq3:_ntq3])
                  + b"".join(enc8(_c[0] % P) + enc8(_c[1] % P) for _c in _alla[_midq3:_ntq3]))
        assert len(_vmsr.s) == 1 and _vmsr.s[-1] == _expsr, \
            "HP16 deep_dual_slice_read reconstructed slice != the deep_sum_part_dual witness slice (q %d)" % _spqi
        _psz, _pszg = F2.ZERO, F2.ZERO
        for _t in range(_midq3, _ntq3):
            _tm = F2.mul(_aoq3[_t][0], F2.sub(_allv[_t], _aoq3[_t][1]))
            if _deep_term_is_z(_t, _nfq, _nsq): _psz = F2.add(_psz, _tm)
            else: _pszg = F2.add(_pszg, _tm)
        _psz = (_psz[0] % P, _psz[1] % P); _pszg = (_pszg[0] % P, _pszg[1] % P)
        _srredeem = deep_dual_slice_read_prog(_midq3, _ntq3, _ntq3) + deep_sum_part_dual_prog(_midq3, _ntq3, _nfq, _nsq, carry_bound=True)

        def _mk_sr_unlock(cz, czg):
            _u = [PUSH(_acc_preimage(cz) + _acc_preimage(czg)), PUSH(_acc_preimage(F2.ZERO) + _acc_preimage(F2.ZERO))]
            for _t in range(_midq3, _ntq3):
                _u += [NUM(_allv[_t][0] % P), NUM(_allv[_t][1] % P)]
            return _u + [PUSH(_blobq3)]

        def _run_sr(cz, czg):
            _vm = VM()
            try:
                _vm.run(_field_prelude() + _mk_sr_unlock(cz, czg) + _srredeem)
                return len(_vm.s) == 1 and decode_num(_vm.s[-1]) == 1
            except VMError:
                return False
        assert _run_sr(_psz, _pszg), "HP16 partial dual shard on the slice-read blob MUST accept the honest carry_out (q %d)" % _spqi
        assert not _run_sr(((_psz[0] + 1) % P, _psz[1]), _pszg) \
            and not _run_sr(_psz, (_pszg[0], (_pszg[1] + 1) % P)), \
            "HP16 partial dual shard forged carry_out MUST reject on the slice-read blob (q %d)" % _spqi
        _zo = [_spterms[_i] for _i in _zt]; _hf = len(_zo) // 2
        _Sza, _ = run_deep_sum_part(_zo[:_hf], F2.ZERO); _Szb, _ = run_deep_sum_part(_zo[_hf:], _Sza)
        assert _Szb == _Sz, "carry-chained Sum_z != single-part (q %d)" % _spqi
        # HP9.8: the DEPLOY producer self-binds acc_out to carry_out_preimage (forged carry-out -> reject),
        #        and the bound carry-chain (part-A carry_out feeds part-B carry_in) == the single-part sum (R8-B1).
        _zgo = [_spterms[_i] for _i in _zgt]
        assert run_deep_sum_part(_zo, F2.ZERO, carry_bound=True, acc_out=_Sz)[0] == 1 \
            and run_deep_sum_part(_zgo, F2.ZERO, carry_bound=True, acc_out=_Szg)[0] == 1, "HP9.8 bound accept (q %d)" % _spqi
        assert run_deep_sum_part(_zo, F2.ZERO, carry_bound=True, acc_out=((_Sz[0] + 1) % P, _Sz[1]))[0] is None \
            and run_deep_sum_part(_zo, F2.ZERO, carry_bound=True, acc_out=(_Sz[0], (_Sz[1] + 1) % P))[0] is None, \
            "HP9.8 forged carry-out MUST reject (q %d)" % _spqi
        assert run_deep_sum_part(_zo[:_hf], F2.ZERO, carry_bound=True, acc_out=_Sza)[0] == 1 \
            and run_deep_sum_part(_zo[_hf:], _Sza, carry_bound=True, acc_out=_Szb)[0] == 1, "HP9.8 bound carry-chain accept (q %d)" % _spqi
    _bz98 = _prog_nbytes(deep_sum_part_prog(len(_zt), carry_bound=True))
    _bzg98 = _prog_nbytes(deep_sum_part_prog(len(_zgt), carry_bound=True))
    assert max(_bz98, _bzg98) <= 3300, "HP9.8 carry_bound part exceeds thin cap: Sum_z=%dB Sum_zg=%dB" % (_bz98, _bzg98)
    print("HP12/HP16 DEEP-quotient thin-shard split (Sum_z-part + Sum_zg-part + final combine, HP9.7-9.8 acc carry) "
          "== query_terms for %d real queries: OK (carry-chain 2-sub-parts == single; part bytes Sum_z=%dB "
          "Sum_zg=%dB final=%dB all <=3300B -> DEEP per-query verify shards into thin covenant inputs)"
          % (len(_pfq["queries"]), _prog_nbytes(deep_sum_part_prog(len(_zt))),
             _prog_nbytes(deep_sum_part_prog(len(_zgt))), _prog_nbytes(deep_final_combine_prog())))
    print("HP9.8 DEEP thin-shard carry single-source: OK (producer self-binds acc_out==carry_out_preimage, "
          "forged carry-out rejects, bound carry-chain==single; carry_bound bytes Sum_z=%dB Sum_zg=%dB <=3300B)"
          % (_bz98, _bzg98))
    _ntq98 = 2 * _nfq + _nsq + 2
    _bzbl = _prog_nbytes(deep_sum_part_blob_prog(len(_zt), _ntq98, _zt))
    _bzblc = _prog_nbytes(deep_sum_part_blob_prog(len(_zt), _ntq98, _zt, carry_bound=True))
    assert _bzblc <= 10000, "HP12.3 blob-sourced carry_bound z-shard %dB must be <=10000B" % _bzblc
    print("HP12.3/R4-B1 blob-sourced DEEP sum-part: OK (alpha_i/ood_i single-source from the ONE FS blob at the "
          "baked global term index, NOT a free per-input witness -> a prover cannot substitute a per-input ood to "
          "commit q==0; == witness-sourced for %d real queries; tampered blob ood -> different sum; carry_bound "
          "producer self-binds acc_out (forged rejects); z-shard redeem=%dB (carry_bound %dB <=10000B))"
          % (len(_pfq["queries"]), _bzbl, _bzblc))
    _bd3 = _prog_nbytes(deep_sum_part_dual_prog(0, _ntq98, _nfq, _nsq))
    _bd3c = _prog_nbytes(deep_sum_part_dual_prog(0, _ntq98, _nfq, _nsq, carry_bound=True))
    print("HP12.3/R4-B1 Design A contiguous-range dual-acc sum-part: OK (reads ONLY its ood/alpha slice not the whole "
          "blob -> op-cost + on-VM split scale with the shard, the op-cost-density fix; acc_z/acc_zg routed by baked "
          "_deep_term_is_z; full-range dual == (Sum_z, Sum_zg) + contiguous carry-chain == single for %d real queries; "
          "carry_bound producer self-binds (acc_z, acc_zg) to a 32B carry_out (forged rejects); full-range redeem=%dB "
          "(carry_bound %dB))" % (len(_pfq["queries"]), _bd3, _bd3c))
    print("HP12 DEEP final-combine cross-input consumer (carry_split: Sum_z split_cells'd from the read carry_out "
          "+ USED in q, not byte-compared) == non-split combine for %d real queries: OK "
          "(real-libauth producer->consumer link + fail-closed is native_shard_deploy_check section 4f)"
          % len(_pfq["queries"]))
    print("HP16.1 DEEP final-combine DUAL cross-input consumer (dual: BOTH Sum_z + Sum_zg split_cells'd from the two "
          "read carry_outs + USED in q, closing the Sum_zg single-source gap carry_split left in the witness) == "
          "non-split combine for %d real queries: OK (real-libauth 3-input producer->producer->consumer link is "
          "native_shard_deploy_check section 4k)" % len(_pfq["queries"]))
    # opener-input PRODUCER (opener_commit_prog): Merkle-binds the committed [cells|k] blob == the opened comp leaf
    # @k against the pinned comp_root -- the real producer whose exposed blob the deploy_check 4g consumer reads.
    _ocr = bytes.fromhex(_pfq["comp_root"]); _otr = bytes.fromhex(_pfq["tp_root"]); _oN = 1 << len(_pfq["queries"][0]["cp"])
    _lop_tr = []                                                # HP16: collect the trace openings for the looped-opener aggregation test
    for _oqi, _oq in enumerate(_pfq["queries"]):
        _ok_ = _oq["k"]; _occ = tuple(_oq["cc"]); _op = [(bytes.fromhex(_s), _b) for _s, _b in _oq["cp"]]
        _opre = b"\x00" * 16 + enc8(_occ[0] % P) + enc8(_occ[1] % P)
        assert run_opener_commit(_ocr, _op, _opre, [_occ[0], _occ[1]], _ok_, 16), "opener_commit comp honest reject (q %d)" % _oqi
        assert not run_opener_commit(_ocr, _op, _opre, [(_occ[0] + 1) % P, _occ[1]], _ok_, 16), "opener_commit forged comp cell accepted (q %d)" % _oqi
        assert not run_opener_commit(_ocr, _op, _opre, [_occ[0], _occ[1]], (_ok_ + 1) % _oN, 16), "opener_commit wrong index accepted (q %d)" % _oqi
        # also the TRACE leaf (52 cells, the main sum-part value source): bind all 52 committed cells == the opened leaf @k
        _tcells = [_oq["ck"][_c] for _c in _STKd.FLAT_COLS]
        _tpre = trace_leaf_preimage(_oq["ck"], bytes.fromhex(_oq["sk"]), _STKd.FLAT_COLS)
        _tpath = [(bytes.fromhex(_s), _b) for _s, _b in _oq["pk"]]
        assert run_opener_commit(_otr, _tpath, _tpre, _tcells, _ok_, 16), "opener_commit trace honest reject (q %d)" % _oqi
        assert not run_opener_commit(_otr, _tpath, _tpre, [(_tcells[0] + 1) % P] + _tcells[1:], _ok_, 16), "opener_commit forged trace cell accepted (q %d)" % _oqi
        _lop_tr.append((_otr, _tpath, _tpre[:16], list(_tcells), _ok_))   # HP16: (root, path, salt(16), cells, k) for from-blob
        # also the SEL leaf (33 D-coset selector cells, prefix=0 / no salt): bind all 33 committed cells == opened leaf @k
        _scells = selector_row_values_coset(_svq, _ok_)
        _spre = selector_preimage_coset(_svq, _ok_)
        _spath = sm_path(_seltq, _ok_)
        assert run_opener_commit(_selrq, _spath, _spre, _scells, _ok_, 0), "opener_commit sel honest reject (q %d)" % _oqi
        assert not run_opener_commit(_selrq, _spath, _spre, [(_scells[0] + 1) % P] + _scells[1:], _ok_, 0), "opener_commit forged sel cell accepted (q %d)" % _oqi
    # HP16 openers lever: the FROM-BLOB looped opener merkle-verifies ALL trace openings in ONE pinned-count loop --
    # the <100KB lever. Each opening derives its preimage from the exposed blob (no duplicated preimage push) so the
    # cells are merkle-bound WITHOUT a separate commit-check (smaller than the commit form). A forged cell -> wrong
    # preimage -> merkle reject; a wrong opening count rejects fail-closed (pinned-count binding).
    _ndep = len(_lop_tr[0][1]); _nq_op = len(_lop_tr)
    assert run_looped_opener_from_blob(_lop_tr, _ndep, 52, _nq_op, 16), "looped from-blob opener honest reject"
    _lop_forge = [(_r, _pa, _sa, ([(_c[0] + 1) % P] + _c[1:]) if _i == 0 else _c, _kk)
                  for _i, (_r, _pa, _sa, _c, _kk) in enumerate(_lop_tr)]
    assert not run_looped_opener_from_blob(_lop_forge, _ndep, 52, _nq_op, 16), "looped from-blob opener forged cell accepted"
    assert not run_looped_opener_from_blob(_lop_tr[:-1], _ndep, 52, _nq_op, 16), "looped from-blob opener under-count accepted"
    assert not run_looped_opener_from_blob(_lop_tr, _ndep, 52, _nq_op - 1, 16), "looped from-blob opener over-count accepted"
    _rloop = _prog_nbytes(looped_opener_from_blob_prog(_ndep, 52, _nq_op, 16))
    _uloop = _prog_nbytes(looped_opener_from_blob_unlock(_lop_tr))
    print("HP16 from-blob looped opener (%d trace openings in ONE pinned-count loop, preimage derived from blob) "
          "merkle-binds all openings: OK (forged cell / under+over count reject fail-closed; redeem=%dB constant + "
          "witness=%dB, no duplicated preimage push)"
          % (_nq_op, _rloop, _uloop))
    print("opener_commit_prog (opener-input producer: commit [cells|k] Merkle-bound == opened leaf @k) for %d real "
          "queries, comp(2)+trace(52)+sel(33) leaves: OK (honest accept; forged cell / wrong index reject fail-closed; "
          "comp %dB / trace %dB / sel %dB redeem)"
          % (len(_pfq["queries"]), _prog_nbytes(opener_commit_prog(len(_pfq["queries"][0]["cp"]), 2, 16)),
             _prog_nbytes(opener_commit_prog(len(_pfq["queries"][0]["pk"]), 52, 16)),
             _prog_nbytes(opener_commit_prog(len(sm_path(_seltq, _pfq["queries"][0]["k"])), 33, 0))))

    # --- HP2.5: the FULL per-query composition (GF(p^2) comp == verify's comp_x) ---
    import native_ct_air_stark as STK
    pf = STK.prove(CT._demo_witness(depth=2), seed=2026)
    terms = STK.query_terms(pf)
    occ5 = 0
    for t in terms[:3]:                                   # several real queries
        got, occ5 = run_compose(t["trans_v"], t["trans_a"], t["qf_trans"],
                                t["bound_v"], t["bound_invX"], t["bound_a"])
        assert got == t["comp_x"], "VM composition != verify comp_x (%s vs %s)" % (got, t["comp_x"])
    # tamper one transition residual -> the composition value changes (catches a bad opening)
    tt = terms[0]; tv = list(tt["trans_v"]); tv[0] = (tv[0] + 1) % P
    gtm, _ = run_compose(tv, tt["trans_a"], tt["qf_trans"], tt["bound_v"], tt["bound_invX"], tt["bound_a"])
    assert gtm != tt["comp_x"], "tampered residual did not change the composition"
    # the proof whose comp_x we reproduced must itself verify (comp_x == FRI layer-0)
    okv, _why = STK.verify(pf)
    assert okv, "the proof we reproduced the composition of must verify: %s" % _why

    # --- 2.21a: assemble the FULL transition residual vector on the BCH-VM from opened cells +
    #     selectors + baked MDS constants; reproduce verify's trans_v at a REAL query point ---
    W = P2.WIDTH
    pft = STK.prove(CT._demo_witness(depth=2), seed=11)
    stmtt = pft["stmt"]; Dt = stmtt["depth"]
    metat, Tt = CT.ct_build_layout(Dt)
    Nt, oTt, oNt, offt, Hdt, Ddt, lastt = STK._setup(Tt, pft["blowup"])
    layt = CT.ct_public_layout(metat, Tt)
    svt = STK._selector_vectors(layt, Tt, Nt, oTt, oNt, offt)
    shiftt = Nt // Tt
    qt = pft["queries"][0]; kt = qt["k"]; knt = (kt + shiftt) % Nt
    curt = qt["ck"]; nxtt = qt["cn"]
    pubt = STK._pub_at_idx(svt, kt); wnt = svt["range_weight"][knt]
    reft = CT.ct_transition_residuals(curt, nxtt, pubt, wnt)
    assert len(reft) == CT.ct_num_transition_residuals(), "oracle trans_v arity mismatch"
    minvcap = [CT.M_EXT_INV[kk] for kk in range(P2.RATE, W)]
    gott, _oct = run_assemble_transition(P2.MAT_DIAG12, minvcap, curt, nxtt, pubt, wnt, CT.HELD_COLS)
    assert gott == reft, "VM assembled trans_v != verify trans_v"
    curtb = dict(curt); curtb["u2_0"] = (curtb["u2_0"] + 1) % P     # tamper a committed aux cell
    gtb, _ = run_assemble_transition(P2.MAT_DIAG12, minvcap, curtb, nxtt, pubt, wnt, CT.HELD_COLS)
    assert gtb != reft, "tampered aux cell (u2_0) not caught by assembled trans_v"

    # --- 2.21b: assemble the FULL boundary residual vector on the BCH-VM at a real query point;
    #     reproduce verify's bound_v (eq inline SUBMOD, cm-bind + conservation via their progs) ---
    tbb = STK.query_terms(pft)[0]
    curb = pft["queries"][0]["ck"]; stmtb2 = pft["stmt"]
    rspec = [(CT.HELD_COLS.index("vh_" + rm["vname"]), rm["src"] is not None) for rm in metat["range"]]
    gotb, _ocb = run_assemble_boundary(CT.M_EXT_INV[0], curb, stmtb2, CT.N_OUT, rspec, CT.HELD_COLS)
    assert gotb == tbb["bound_v"], "VM assembled bound_v != verify bound_v (%s vs %s)" % (gotb, tbb["bound_v"])
    curbb = dict(curb); curbb["vh_value_in"] = (curbb["vh_value_in"] + 1) % P   # tamper a held cell
    gbb, _ = run_assemble_boundary(CT.M_EXT_INV[0], curbb, stmtb2, CT.N_OUT, rspec, CT.HELD_COLS)
    assert gbb != tbb["bound_v"], "tampered held cell not caught by assembled bound_v"

    # --- 2.22: chain the ASSEMBLED trans_v (2.21a) + bound_v (2.21b) + FS alphas + qf/invX into the
    #     composition on the BCH-VM; reproduce verify's comp_x ---
    gotcx, _oc22 = run_compose_feed(gott, gotb, tbb["trans_a"], tbb["qf_trans"], tbb["bound_invX"], tbb["bound_a"])
    assert gotcx == tbb["comp_x"], "VM compose(assembled trans_v/bound_v) != verify comp_x (%s vs %s)" % (gotcx, tbb["comp_x"])
    gtvf = list(gott); gtvf[0] = (gtvf[0] + 1) % P                              # tamper a transition residual
    gc2f, _ = run_compose_feed(gtvf, gotb, tbb["trans_a"], tbb["qf_trans"], tbb["bound_invX"], tbb["bound_a"])
    assert gc2f != tbb["comp_x"], "tampered trans_v not caught by compose"

    # --- 2.31: thread the per-query verification core (residual assembly -> compose -> FRI fold chain)
    #     for ONE real query on ONE unified stack, MAIN-STACK-ONLY under a single field prelude.
    #     Reproduces native_ct_air_stark.verify's accept for the query; a tampered opened cell perturbs
    #     the composition so comp != FRI layer-0 and the fold chain rejects (fail-closed). ---
    qfri31 = STK.query_fri_terms(pft)[0]                        # index-aligned with query_terms[0] (query 0)
    args31 = (P2.MAT_DIAG12, minvcap, CT.M_EXT_INV[0], CT.N_OUT, rspec)
    extra31 = (stmtt, tbb["trans_a"], tbb["qf_trans"], tbb["bound_invX"], tbb["bound_a"], CT.HELD_COLS, qfri31)
    ok31, _oc31 = run_per_query_core(*args31, curt, nxtt, pubt, wnt, *extra31)
    assert ok31, "per-query core thread rejected a valid query (clean-stack accept failed)"
    ct31 = dict(curt); ct31["u2_0"] = (ct31["u2_0"] + 1) % P    # tamper a committed aux cell (transition only)
    okt31, _ = run_per_query_core(*args31, ct31, nxtt, pubt, wnt, *extra31)
    assert not okt31, "per-query core accepted a tampered transition aux cell (u2_0)"
    cb31 = dict(curt); cb31["vh_value_in"] = (cb31["vh_value_in"] + 1) % P      # tamper a held/boundary cell
    okb31, _ = run_per_query_core(*args31, cb31, nxtt, pubt, wnt, *extra31)
    assert not okb31, "per-query core accepted a tampered boundary held cell (vh_value_in)"
    import copy as _copy31                                      # tamper an opened FRI leaf -> fold chain rejects
    qf31bad = _copy31.deepcopy(qfri31); qf31bad["layers"][0]["v"] = ((qf31bad["layers"][0]["v"][0] + 1) % P,
                                                                     qf31bad["layers"][0]["v"][1])
    okf31, _ = run_per_query_core(*args31, curt, nxtt, pubt, wnt, stmtt, tbb["trans_a"], tbb["qf_trans"],
                                  tbb["bound_invX"], tbb["bound_a"], CT.HELD_COLS, qf31bad)
    assert not okf31, "per-query core accepted a tampered FRI layer-0 value"

    # --- 2.31c(i): bind the opened TRACE leaf cells to the committed trace root. Open trace@k and
    #     @kn against the pinned tp_root at the FS-derived index and split into the FLAT_COLS field
    #     cells the 2.31a core consumes -- reproducing ck/cn (cells no longer free witness). The
    #     pinned-root EQUALVERIFY makes a tampered leaf or a wrong index fail-closed. ---
    tprt = bytes.fromhex(pft["tp_root"])
    pk_k = [(bytes.fromhex(s), b) for s, b in qt["pk"]]
    pk_n = [(bytes.fromhex(s), b) for s, b in qt["pn"]]
    ckc, _ock = run_trace_open(curt, bytes.fromhex(qt["sk"]), pk_k, tprt, kt, CT.FLAT_COLS)
    assert ckc == [curt[c] % P for c in CT.FLAT_COLS], "opened trace@k cells != ck"
    cnc, _ = run_trace_open(nxtt, bytes.fromhex(qt["sn"]), pk_n, tprt, knt, CT.FLAT_COLS)
    assert cnc == [nxtt[c] % P for c in CT.FLAT_COLS], "opened trace@kn cells != cn"
    badrow = dict(curt); badrow["s0"] = (badrow["s0"] + 1) % P     # tampered cell -> pinned-root reject
    try:
        run_trace_open(badrow, bytes.fromhex(qt["sk"]), pk_k, tprt, kt, CT.FLAT_COLS)
        raise AssertionError("trace open accepted a tampered leaf")
    except VMError:
        pass
    try:                                                            # wrong index (derived bits) -> reject
        run_trace_open(curt, bytes.fromhex(qt["sk"]), pk_k, tprt, (kt + 1) % Nt, CT.FLAT_COLS)
        raise AssertionError("trace open accepted a wrong index")
    except VMError:
        pass

    # --- 2.31c(ii): feed the OPENED leaf cells into the per-query core via the programmatic cell map.
    #     Open trace@k/@kn + D-coset selectors@k/@kn (real, Merkle-bound to their roots), then verify
    #     the mapped core reproduces verify()'s accept -- cur/nxt/pub_x/w_next now flow from the
    #     openers, not free witness. A tampered opened cell -> comp != FRI layer-0 -> fail-closed. ---
    dscr, dsct, _dscp = build_selector_commitment_coset(svt, Nt)
    tkc, _otk = run_trace_open(curt, bytes.fromhex(qt["sk"]), pk_k, tprt, kt, CT.FLAT_COLS)
    tnc, _ = run_trace_open(nxtt, bytes.fromhex(qt["sn"]), pk_n, tprt, knt, CT.FLAT_COLS)
    skc, _ = run_selector_open(svt, kt, sm_path(dsct, kt), dscr, kt)
    snc, _ = run_selector_open(svt, knt, sm_path(dsct, knt), dscr, knt)
    assert skc == selector_row_values_coset(svt, kt), "opened selector@k cells != selector_row_values_coset"
    m_args = (P2.MAT_DIAG12, minvcap, CT.M_EXT_INV[0], CT.N_OUT, rspec, CT.FLAT_COLS, CT.HELD_COLS)
    m_pin = (stmtt["root"], stmtt["nf"], stmtt["cm_out"], tbb["trans_a"], tbb["qf_trans"],
             tbb["bound_invX"], tbb["bound_a"], qfri31)
    okm, _ocm = run_per_query_mapped(*m_args, tkc, tnc, skc, snc, *m_pin)
    assert okm, "mapped per-query core rejected a valid query (opened cells, clean-stack accept failed)"
    tkc_b = list(tkc); tkc_b[0] = (tkc_b[0] + 1) % P               # tamper opened cur s0 -> reject
    okmt, _ = run_per_query_mapped(*m_args, tkc_b, tnc, skc, snc, *m_pin)
    assert not okmt, "mapped core accepted a tampered opened trace cell (s0)"
    skc_b = list(skc); skc_b[8] = (skc_b[8] + 1) % P              # tamper opened selector rc0 -> reject
    okms, _ = run_per_query_mapped(*m_args, tkc, tnc, skc_b, snc, *m_pin)
    assert not okms, "mapped core accepted a tampered opened selector cell (rc0)"

    # --- 2.31c-ii-open (prereq): baked-root bound opener -- the pinned root is hardcoded in the redeem,
    #     NOT taken from the witness, so a prover cannot substitute a favourable Merkle tree. The opened
    #     cells reproduce the real trace/selector cells; a tampered leaf, a wrong index, or a valid leaf
    #     under a DIFFERENT baked root all fail-closed. ---
    tbc, _ = run_bound_open(trace_leaf_preimage(curt, bytes.fromhex(qt["sk"]), CT.FLAT_COLS),
                            pk_k, tprt, kt, len(CT.FLAT_COLS), 16)
    assert tbc == [curt[c] % P for c in CT.FLAT_COLS], "baked-root trace open cells != ck"
    sbc, _ = run_bound_open(selector_preimage_coset(svt, kt), sm_path(dsct, kt), dscr, kt, len(_SEL_ORDER), 0)
    assert sbc == selector_row_values_coset(svt, kt), "baked-root selector open cells != coset"
    badpre = trace_leaf_preimage({**curt, "s0": (curt["s0"] + 1) % P}, bytes.fromhex(qt["sk"]), CT.FLAT_COLS)
    try:                                                          # tampered leaf -> reject
        run_bound_open(badpre, pk_k, tprt, kt, len(CT.FLAT_COLS), 16)
        raise AssertionError("baked-root open accepted a tampered leaf")
    except VMError:
        pass
    wrongroot = bytes(bytearray(tprt)[:-1] + bytes([tprt[-1] ^ 1]))
    try:                                                          # valid leaf under a WRONG baked root -> reject
        run_bound_open(trace_leaf_preimage(curt, bytes.fromhex(qt["sk"]), CT.FLAT_COLS),
                       pk_k, wrongroot, kt, len(CT.FLAT_COLS), 16)
        raise AssertionError("baked-root open accepted a leaf under a wrong (unforgeable) root")
    except VMError:
        pass

    # --- 2.31c-ii-open-b: open ALL FOUR leaves (trace@k/@kn + D-coset selectors@k/@kn) in ONE program
    #     via the copy pattern, producing the 170 cells Merkle-bound (pinned roots) on a single stack in
    #     leaf order -- the multi-leaf opener supply for the fully-bound per-query verify. A tampered
    #     leaf in any of the four fails the baked-root check (fail-closed). ---
    depth_o = len(pk_k)
    assert depth_o == len(sm_path(dsct, kt)), "trace/selector Merkle depth differ (uniform-block assumption)"
    tkp = trace_leaf_preimage(curt, bytes.fromhex(qt["sk"]), CT.FLAT_COLS)
    tnp = trace_leaf_preimage(nxtt, bytes.fromhex(qt["sn"]), CT.FLAT_COLS)
    skp = selector_preimage_coset(svt, kt); snp = selector_preimage_coset(svt, knt)
    pkn_s = sm_path(dsct, kt); pnn_s = sm_path(dsct, knt)
    all_cells, _oal = run_open_all_leaves(depth_o, tprt, dscr, len(CT.FLAT_COLS), len(_SEL_ORDER),
                                          tkp, pk_k, kt, tnp, pk_n, knt, skp, pkn_s, snp, pnn_s)
    expect_cells = ([curt[c] % P for c in CT.FLAT_COLS] + [nxtt[c] % P for c in CT.FLAT_COLS]
                    + selector_row_values_coset(svt, kt) + selector_row_values_coset(svt, knt))
    assert all_cells == expect_cells, "four-leaf opener supply cells != real leaf-order cells"
    tkp_b = trace_leaf_preimage({**curt, "s0": (curt["s0"] + 1) % P}, bytes.fromhex(qt["sk"]), CT.FLAT_COLS)
    try:                                                          # tampered trace@k leaf -> reject
        run_open_all_leaves(depth_o, tprt, dscr, len(CT.FLAT_COLS), len(_SEL_ORDER),
                            tkp_b, pk_k, kt, tnp, pk_n, knt, skp, pkn_s, snp, pnn_s)
        raise AssertionError("four-leaf opener accepted a tampered trace leaf")
    except VMError:
        pass
    snp_b = selector_preimage_coset(svt, (knt + 1) % Nt)         # a different selector row opened at knt
    try:                                                          # tampered selector@kn leaf -> reject
        run_open_all_leaves(depth_o, tprt, dscr, len(CT.FLAT_COLS), len(_SEL_ORDER),
                            tkp, pk_k, kt, tnp, pk_n, knt, skp, pkn_s, snp_b, pnn_s)
        raise AssertionError("four-leaf opener accepted a tampered selector leaf")
    except VMError:
        pass

    # --- 3.5b-ii-b-1: the runtime-k opener core (_open_leaves_at_k_prog) with the query index k supplied
    #     ON THE STACK (loop-ready) -- opens the four leaves at k/kn exactly like the FS-derived opener, but
    #     k comes from the stack (in the query loop: a runtime PICK of idx_{counter} from the shared FS
    #     output) rather than a baked query_i. open_all_leaves_fs_prog is byte-identical (it now calls this
    #     helper; verified new==HEAD). Validated: cells == real leaf-order cells; a wrong k or a tampered
    #     sibling rejects (Merkle position bind). No field prelude. ---
    _WBb1 = depth_o + 1
    b1_unlock = open_all_leaves_fs_unlock(tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s)  # 4 blocks, NO index
    _b1_open = lambda: _open_leaves_at_k_prog(depth_o, dscr, len(CT.FLAT_COLS), len(_SEL_ORDER), shiftt, Nt,
                                              tprt, wbase=0, sp_start=4 * _WBb1 + 1)
    _vmb1 = VM(); _vmb1.run(b1_unlock + [NUM(kt)] + _b1_open())
    _ncb1 = 2 * len(CT.FLAT_COLS) + 2 * len(_SEL_ORDER)
    assert [decode_num(x) for x in _vmb1.s[-_ncb1:]] == expect_cells, \
        "runtime-k opener cells != real leaf-order cells"
    try:                                                          # wrong k -> reject (Merkle position bind)
        VM().run(b1_unlock + [NUM((kt + 1) % Nt)] + _b1_open())
        raise AssertionError("runtime-k opener accepted a wrong k")
    except VMError:
        pass
    _b1_bad = list(b1_unlock); _b1_bad[0] = PUSH(bytes(32))       # tampered first sibling
    try:
        VM().run(_b1_bad + [NUM(kt)] + _b1_open())
        raise AssertionError("runtime-k opener accepted a tampered sibling")
    except VMError:
        pass
    print("3.5b-ii-b-1 runtime-k opener (_open_leaves_at_k_prog, k on stack, loop-ready): OK")
    print("  cells == real leaf-order (170) ; wrong-k + tampered-sibling reject ; FS opener byte-identical")

    # --- 2.31c-ii-open-b-feed: the FULLY-BOUND per-query verify -- open all four leaves (roots pinned)
    #     so cur/nxt/pub_x/w_next are Merkle-bound, then run the mapped core over the opened cells and
    #     reproduce verify()'s accept. A tampered leaf fails the baked-root open (fail-closed). Only the
    #     composition extras remain witness (2.31c-iii binds them on-chain). ---
    b_args = (P2.MAT_DIAG12, minvcap, CT.M_EXT_INV[0], CT.N_OUT, rspec, CT.FLAT_COLS, CT.HELD_COLS,
              depth_o, tprt, dscr, stmtt["root"], stmtt["nf"], stmtt["cm_out"])
    b_ext = (tbb["trans_a"], tbb["qf_trans"], tbb["bound_invX"], tbb["bound_a"])
    b_leaves = (tkp, pk_k, kt, tnp, pk_n, knt, skp, pkn_s, snp, pnn_s)
    okb, _ocb = run_per_query_bound(*b_args, *b_ext, *b_leaves, qfri31)
    assert okb, "fully-bound per-query verify rejected a valid query (clean-stack accept failed)"
    okbt, _ = run_per_query_bound(*b_args, *b_ext, tkp_b, pk_k, kt, tnp, pk_n, knt, skp, pkn_s, snp, pnn_s, qfri31)
    assert not okbt, "fully-bound per-query accepted a tampered trace leaf"
    okbs, _ = run_per_query_bound(*b_args, *b_ext, tkp, pk_k, kt, tnp, pk_n, knt, skp, pkn_s, snp_b, pnn_s, qfri31)
    assert not okbs, "fully-bound per-query accepted a tampered selector leaf"

    # --- 2.31c-iii-a: derive x=Dd[k] from the FS index k (fri_xpos li=0 reuse) then the composition
    #     normalizers qf_trans + bound_invX via qf_bound_from_stack (x on the stack, hints witness, each
    #     inverse-constrained hint*value==1 fail-closed) -- reproducing verify()'s qf_trans/bound_invX
    #     from k with NO baked x, so the normalizers are no longer free witness. ---
    bcons_d = STK.ct_boundary_constraints(metat, stmtt)
    hd_vals_d = [Hdt[row] for row, _f in bcons_d]
    zhinv_d = pow((pow(Ddt[kt], Tt, P) - 1) % P, P - 2, P)
    qd, _oqd = run_qf_derive(oNt, offt, Tt, lastt, hd_vals_d, kt, zhinv_d, tbb["bound_invX"])
    assert qd == [tbb["qf_trans"] % P] + [b % P for b in tbb["bound_invX"]], \
        "derived qf_trans/bound_invX != verify (%s vs %s)" % (qd, [tbb["qf_trans"]] + list(tbb["bound_invX"]))
    try:                                                          # wrong zh_inv hint -> fail-closed
        run_qf_derive(oNt, offt, Tt, lastt, hd_vals_d, kt, (zhinv_d + 1) % P, tbb["bound_invX"])
        raise AssertionError("qf_derive accepted a wrong zh_inv hint")
    except VMError:
        pass
    bad_binv = list(tbb["bound_invX"]); bad_binv[0] = (bad_binv[0] + 1) % P
    try:                                                          # wrong bound_invX hint -> fail-closed
        run_qf_derive(oNt, offt, Tt, lastt, hd_vals_d, kt, zhinv_d, bad_binv)
        raise AssertionError("qf_derive accepted a wrong bound_invX hint")
    except VMError:
        pass

    # --- 2.31c-iii-b (alpha binding): compose with the GF(p^2) constraint-combination alphas DERIVED
    #     from the FS transcript (a function of the PINNED statement only) instead of witness -- a
    #     prover cannot choose the challenges (Frozen-Heart). Reproduces verify's comp_x with NO witness
    #     alpha; a tampered residual still changes comp (the composition binds the residual). ---
    fr_b = [bytes.fromhex(r) for r in pft["fri_roots"]]; tpb_b = bytes.fromhex(pft["tp_root"]); non_b = bytes.fromhex(pft["nonce"])
    compfs, _ocfs = run_compose_from_fs_alphas(tbb["trans_v"], tbb["bound_v"], tbb["qf_trans"], tbb["bound_invX"],
                                               tpb_b, stmtt["root"], stmtt["nf"], stmtt["cm_out"], fr_b, non_b, Nt, pft["nq"])
    assert compfs == tbb["comp_x"], "FS-alpha composition != verify comp_x (%s vs %s)" % (compfs, tbb["comp_x"])
    tv_fb = list(tbb["trans_v"]); tv_fb[0] = (tv_fb[0] + 1) % P
    cbad_fs, _ = run_compose_from_fs_alphas(tv_fb, tbb["bound_v"], tbb["qf_trans"], tbb["bound_invX"],
                                            tpb_b, stmtt["root"], stmtt["nf"], stmtt["cm_out"], fr_b, non_b, Nt, pft["nq"])
    assert cbad_fs != tbb["comp_x"], "tampered trans_v not caught by the FS-alpha composition"

    # --- 2.31c-iii-b-mono (query-index binding): bind the query index k to the FULL FS transcript,
    #     then derive x=Dd[k] + qf_trans/bound_invX -- the OPENED position is no longer free witness (a
    #     prover cannot pick a favourable query). Reproduces query 0's normalizers with k FS-derived
    #     (unlock = hints only, no k/x/alpha); a wrong hint (for the FS-derived x) fails closed. ---
    n_tt = len(tbb["trans_v"]); n_btt = len(tbb["bound_v"])
    qfs, _oqfs = run_qf_derive_from_fs(n_tt, n_btt, Tt, lastt, oNt, offt, hd_vals_d,
                                       tpb_b, stmtt["root"], stmtt["nf"], stmtt["cm_out"], fr_b, non_b,
                                       Nt, pft["nq"], zhinv_d, tbb["bound_invX"], query_i=0)
    assert qfs == [tbb["qf_trans"] % P] + [b % P for b in tbb["bound_invX"]], \
        "FS-index-bound qf_trans/bound_invX != verify (query 0)"
    try:                                                          # wrong hint (for the FS-derived x) -> reject
        run_qf_derive_from_fs(n_tt, n_btt, Tt, lastt, oNt, offt, hd_vals_d,
                              tpb_b, stmtt["root"], stmtt["nf"], stmtt["cm_out"], fr_b, non_b,
                              Nt, pft["nq"], (zhinv_d + 1) % P, tbb["bound_invX"], query_i=0)
        raise AssertionError("FS-index qf accepted a wrong zh_inv hint")
    except VMError:
        pass

    # --- 2.31c-iii-b-mono (next-row index): derive kn=(k+shift)%N from the FS-derived query index k on
    #     chain (pinned shift=N//T, N) -- so the @kn opener position is also FS-bound, not free witness.
    #     kn matches verify's kn; opening trace@kn at the DERIVED kn reproduces cn. ---
    kk_out, _okn = run_kn_from_k(kt, shiftt, Nt)
    assert kk_out == [kt, knt], "kn_from_k != [k, (k+shift)%%N] (%s vs %s)" % (kk_out, [kt, knt])
    cn_derived, _ = run_trace_open(nxtt, bytes.fromhex(qt["sn"]), pk_n, tprt, kk_out[1], CT.FLAT_COLS)
    assert cn_derived == [nxtt[c] % P for c in CT.FLAT_COLS], "trace@kn opened at the derived kn != cn"

    # --- 2.31c-iii-b-mono (FS-bound opener supply): open the 4 leaves at the FS-DERIVED k/kn (not
    #     witness indices) -- the opened POSITIONS are transcript-bound. The 170 cells == the real
    #     leaf-order cells (opened at k=idx_0, kn=(k+shift)%N); opening query-0 leaves at query-1's
    #     FS index fails the baked-root check (position binding, fail-closed). ---
    n_tf = len(tbb["trans_v"]); n_bf = len(tbb["bound_v"])
    fs_cells, _ofsc = run_open_all_leaves_fs(depth_o, dscr, len(CT.FLAT_COLS), len(_SEL_ORDER), shiftt,
                                             n_tf, n_bf, tpb_b, stmtt["root"], stmtt["nf"], stmtt["cm_out"],
                                             fr_b, non_b, Nt, pft["nq"],
                                             tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, query_i=0)
    assert fs_cells == expect_cells, "FS-bound opener supply cells != real leaf-order cells (query 0)"
    try:                                                          # query-0 leaves at query-1's FS index -> reject
        run_open_all_leaves_fs(depth_o, dscr, len(CT.FLAT_COLS), len(_SEL_ORDER), shiftt,
                               n_tf, n_bf, tpb_b, stmtt["root"], stmtt["nf"], stmtt["cm_out"],
                               fr_b, non_b, Nt, pft["nq"],
                               tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, query_i=1)
        raise AssertionError("FS opener accepted query-0 leaves at the query-1 FS index")
    except VMError:
        pass

    # --- 2.31c-iii-b-mono part 2c (position-bound per-query verify): the openers run at the FS-DERIVED
    #     k/kn (open_all_leaves_fs), then the mapped core -- the opened positions are transcript-bound, so
    #     a prover cannot open a favourable query/row. Reproduces verify's accept for query 0; a tampered
    #     leaf and a wrong FS index reject. (The compose extras are still witness here; the final step
    #     derives them from the same transcript.) ---
    fsb = (P2.MAT_DIAG12, minvcap, CT.M_EXT_INV[0], CT.N_OUT, rspec, CT.FLAT_COLS, CT.HELD_COLS,
           depth_o, dscr, shiftt, tpb_b, stmtt["root"], stmtt["nf"], stmtt["cm_out"], fr_b, non_b, Nt, pft["nq"])
    fse = (tbb["trans_a"], tbb["qf_trans"], tbb["bound_invX"], tbb["bound_a"])
    okfs, _ofs = run_per_query_bound_fs(*fsb, *fse, tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, qfri31, query_i=0)
    assert okfs, "position-bound per-query verify (FS-index openers) rejected a valid query"
    okfst, _ = run_per_query_bound_fs(*fsb, *fse, tkp_b, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, qfri31, query_i=0)
    assert not okfst, "position-bound per-query accepted a tampered trace leaf"
    okfsq, _ = run_per_query_bound_fs(*fsb, *fse, tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, qfri31, query_i=1)
    assert not okfsq, "position-bound per-query accepted query-0 leaves at the query-1 FS index"

    # --- 3.5b-iii-2 compose-INPUT (thin-shard producer): open the four leaves at the FS-derived k/kn, COMPUTE
    #     comp=(comp0,comp1) via the mapped core A/B/C (no FRI fold), and BIND comp to the 16-byte comp_preimage
    #     at the bottom of the unlock (iii-3 producer, 2 limbs). Honest comp accepts (clean [1]); a forged
    #     comp_preimage, a tampered trace leaf (-> comp mismatch), and a wrong FS index each reject (fail-closed).
    #     The comp_preimage is what the FRI-input reads cross-input (comp==FRI-layer-0). comp_out=False default
    #     keeps per_query_bound/mapped/full_fs byte-identical (asserted above). ---
    _cpre = comp_preimage(tbb["comp_x"][0], tbb["comp_x"][1])
    okcp, _ocp = run_compose_producer(*fsb, _cpre, *fse, tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, qfri31, query_i=0)
    assert okcp, "compose-INPUT (producer) rejected a valid query (comp==comp_x + comp_preimage bind)"
    okcpf, _ = run_compose_producer(*fsb, comp_preimage((tbb["comp_x"][0] + 1) % P, tbb["comp_x"][1]), *fse,
                                    tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, qfri31, query_i=0)
    assert not okcpf, "compose-INPUT accepted a forged comp_preimage (limb0)"
    okcpf2, _ = run_compose_producer(*fsb, comp_preimage(tbb["comp_x"][0], (tbb["comp_x"][1] + 1) % P), *fse,
                                     tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, qfri31, query_i=0)
    assert not okcpf2, "compose-INPUT accepted a forged comp_preimage (limb1)"
    okcpt, _ = run_compose_producer(*fsb, _cpre, *fse, tkp_b, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, qfri31, query_i=0)
    assert not okcpt, "compose-INPUT accepted a tampered trace leaf (comp mismatch)"
    okcpq, _ = run_compose_producer(*fsb, _cpre, *fse, tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, qfri31, query_i=1)
    assert not okcpq, "compose-INPUT accepted query-0 data at the query-1 FS index"
    print("3.5b-iii-2 compose-INPUT (thin-shard producer: comp from opened cells + comp_preimage bind): OK")
    print("  honest accept ; forged comp_preimage (both limbs) / tampered leaf / wrong FS index all reject (fail-closed). op_cost = %d" % _ocp)
    # HP10.5: the looped compose (DEFINE/INVOKE fold, compose_feed_loop_defines at this input's entry) wired
    # END-TO-END through the compose-INPUT == the unrolled path (honest accept + forged comp reject, fail-closed).
    okcp_l, _ = run_compose_producer(*fsb, _cpre, *fse, tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s,
                                     qfri31, query_i=0, compose_looped=True)
    assert okcp_l, "HP10.5 looped compose-INPUT rejected the valid query (should == unrolled accept)"
    okcpf_l, _ = run_compose_producer(*fsb, comp_preimage((tbb["comp_x"][0] + 1) % P, tbb["comp_x"][1]), *fse,
                                      tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, qfri31, query_i=0, compose_looped=True)
    assert not okcpf_l, "HP10.5 looped compose-INPUT accepted a forged comp_preimage"
    print("HP10.5 looped compose (DEFINE/INVOKE fold) wired through compose-INPUT == unrolled: OK (accept + forged reject)")

    # --- 2.31c-iii-b-mono part 2c-ii (ZERO-free-witness per-query): ALL composition extras are DERIVED
    #     -- the GF(p^2) alphas from the FS output on the stack (Frozen-Heart), qf_trans + bound_invX from
    #     x=Dd[k] (qf_bound_from_stack); the only remaining witness are the inverse-constrained hints
    #     (zh_inv, bound_invX). Reproduces verify's accept for query 0; a wrong inverse hint (zh_inv or
    #     bound_invX), a tampered leaf, and a wrong FS index each reject (fail-closed). ---
    ffa = (qfri31, oNt, offt, Tt, lastt, hd_vals_d)
    ffo = (tkp, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s)
    okff, _off = run_per_query_full_fs(*fsb, *ffa, zhinv_d, tbb["bound_invX"], *ffo, query_i=0)
    assert okff, "zero-free-witness per-query (derived extras) rejected a valid query"
    okffz, _ = run_per_query_full_fs(*fsb, *ffa, (zhinv_d + 1) % P, tbb["bound_invX"], *ffo, query_i=0)
    assert not okffz, "zero-free-witness per-query accepted a wrong zh_inv hint"
    okffb, _ = run_per_query_full_fs(*fsb, *ffa, zhinv_d, bad_binv, *ffo, query_i=0)
    assert not okffb, "zero-free-witness per-query accepted a wrong bound_invX hint"
    okfft, _ = run_per_query_full_fs(*fsb, *ffa, zhinv_d, tbb["bound_invX"],
                                     tkp_b, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, query_i=0)
    assert not okfft, "zero-free-witness per-query accepted a tampered trace leaf"
    okffq, _ = run_per_query_full_fs(*fsb, *ffa, zhinv_d, tbb["bound_invX"], *ffo, query_i=1)
    assert not okffq, "zero-free-witness per-query accepted query-0 data at the query-1 FS index"

    # --- 3.5b-iii-2-full DEPLOYABLE compose-INPUT (FS-derived alphas / Frozen-Heart -- agent OBS-1 fix): like
    #     the compose-INPUT producer above but ALL composition extras are DERIVED (alphas from the FS output,
    #     qf/bound_invX from x=Dd[k]), so a prover cannot choose favourable alphas; comp bound to comp_preimage.
    #     Honest accepts; a forged comp_preimage, a wrong inverse hint (zh_inv/bound_invX), a tampered trace leaf,
    #     and a wrong FS index each reject (fail-closed). Reuses per_query_full_fs's derivation shifted +1. ---
    _cpreF = fri_carry_preimage(tbb["comp_x"][0], tbb["comp_x"][1], qfri31["k"])   # 24B/3-limb: comp+k (Option C)
    okcpF, _ocpF = run_compose_producer_full(*fsb, *ffa, _cpreF, zhinv_d, tbb["bound_invX"], *ffo, query_i=0)
    assert okcpF, "deployable compose-INPUT (FS-derived alphas, 3-limb comp+k) rejected a valid query"
    # HP10.5: the looped compose (DEFINE/INVOKE fold) through the DEPLOYABLE FS-alphas compose-INPUT == unrolled
    # (agent-gegencheck SAFE: bit-identical comp over 2076 differential + per-cell-tamper checks). Honest accept +
    # forged comp reject, fail-closed -- so the deploy CAN run the loop (byte-cut) with no soundness change.
    okcpF_l, _ = run_compose_producer_full(*fsb, *ffa, _cpreF, zhinv_d, tbb["bound_invX"], *ffo,
                                           query_i=0, compose_looped=True)
    assert okcpF_l, "HP10.5 looped deployable compose-INPUT rejected the valid query (should == unrolled accept)"
    assert not run_compose_producer_full(*fsb, *ffa,
                                         fri_carry_preimage((tbb["comp_x"][0] + 1) % P, tbb["comp_x"][1], qfri31["k"]),
                                         zhinv_d, tbb["bound_invX"], *ffo, query_i=0, compose_looped=True)[0], \
        "HP10.5 looped deployable compose-INPUT accepted a forged comp_preimage"
    print("HP10.5 looped compose through the DEPLOYABLE compose-INPUT (compose_producer_full) == unrolled: OK")
    # HP10.5 stage-A DEPLOY-THREADING: the S-box + state loops (DEFINE/INVOKE in assemble_transition) threaded
    # END-TO-END through the DEPLOYABLE compose-INPUT -- the deploy COMPUTE input where the transition assembly
    # runs. The stagea bodies (0x11/0x12) are DEFINE'd at the input entry; == the unrolled path (agent-gegencheck
    # SAFE: bit-identical trans_v over 4608 differential + per-cell-tamper checks). Honest accept + forged reject.
    okcpF_sa, _ = run_compose_producer_full(*fsb, *ffa, _cpreF, zhinv_d, tbb["bound_invX"], *ffo,
                                            query_i=0, sbox_looped=True, state_looped=True)
    assert okcpF_sa, "HP10.5 stage-A-looped deployable compose-INPUT rejected the valid query (should == unrolled accept)"
    assert not run_compose_producer_full(*fsb, *ffa,
                                         fri_carry_preimage((tbb["comp_x"][0] + 1) % P, tbb["comp_x"][1], qfri31["k"]),
                                         zhinv_d, tbb["bound_invX"], *ffo, query_i=0,
                                         sbox_looped=True, state_looped=True)[0], \
        "HP10.5 stage-A-looped deployable compose-INPUT accepted a forged comp_preimage"
    # all three stage loops active at once (fids 0x11/0x12 + compose 0x13-0x16 coexist, disjoint, no collision):
    okcpF_all, _ = run_compose_producer_full(*fsb, *ffa, _cpreF, zhinv_d, tbb["bound_invX"], *ffo,
                                             query_i=0, compose_looped=True, sbox_looped=True, state_looped=True)
    assert okcpF_all, "HP10.5 compose+sbox+state all-looped deployable compose-INPUT rejected the valid query"
    print("HP10.5 stage-A (S-box+state) loops threaded through the DEPLOYABLE compose-INPUT == unrolled: OK (+ all-3-loops combined)")
    assert not run_compose_producer_full(*fsb, *ffa,
                                         fri_carry_preimage((tbb["comp_x"][0] + 1) % P, tbb["comp_x"][1], qfri31["k"]),
                                         zhinv_d, tbb["bound_invX"], *ffo, query_i=0)[0], \
        "deployable compose-INPUT accepted a forged comp_preimage (comp limb0)"
    assert not run_compose_producer_full(*fsb, *ffa,
                                         fri_carry_preimage(tbb["comp_x"][0], tbb["comp_x"][1], (qfri31["k"] + 1)),
                                         zhinv_d, tbb["bound_invX"], *ffo, query_i=0)[0], \
        "deployable compose-INPUT accepted a forged comp_preimage (k limb != FS-derived k)"
    assert not run_compose_producer_full(*fsb, *ffa, _cpreF, (zhinv_d + 1) % P, tbb["bound_invX"], *ffo, query_i=0)[0], \
        "deployable compose-INPUT accepted a wrong zh_inv hint"
    assert not run_compose_producer_full(*fsb, *ffa, _cpreF, zhinv_d, bad_binv, *ffo, query_i=0)[0], \
        "deployable compose-INPUT accepted a wrong bound_invX hint"
    assert not run_compose_producer_full(*fsb, *ffa, _cpreF, zhinv_d, tbb["bound_invX"],
                                         tkp_b, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, query_i=0)[0], \
        "deployable compose-INPUT accepted a tampered trace leaf (comp mismatch)"
    assert not run_compose_producer_full(*fsb, *ffa, _cpreF, zhinv_d, tbb["bound_invX"], *ffo, query_i=1)[0], \
        "deployable compose-INPUT accepted query-0 data at the query-1 FS index"
    print("3.5b-iii-2-full DEPLOYABLE compose-INPUT (FS-alphas/Frozen-Heart + 24B comp_preimage=comp+k bind, Option C): OK")
    print("  honest accept ; forged comp / forged k / wrong zh_inv / wrong bound_invX / tampered leaf / wrong FS index all reject. op_cost = %d" % _ocpF)

    # --- 3.5b-i-thread (deployable FRI chain in the per-query core): per_query_full_fs(deployable=True)
    #     runs stage D via _fri_chain_deployable_body -- DERIVED index-selection (fri_roll_bind) + Merkle-
    #     bound v/w openings -- instead of the baked qfri comp_tgt/fold_tgt, delivering 2.36-2.38 at the
    #     per-query level (shard-level once the aggregation flips in 3.5b-ii). Reproduces verify's accept for
    #     query 0 (clean main [1] / alt [P]); a tampered FRI v value, a tampered final[ii%n_final] entry, and
    #     a comp-mismatching trace leaf each reject (fail-closed). The baked default path stays byte-identical
    #     (the mapped/bound/bound_fs + baked full_fs asserts above are unchanged). ---
    import copy as _cpd
    _finalL = pft["final"]
    okdp, _odp = run_per_query_full_fs(*fsb, *ffa, zhinv_d, tbb["bound_invX"], *ffo, query_i=0,
                                       deployable=True, final=_finalL)
    assert okdp and STK.verify(pft)[0], "deployable-chain per-query rejected a valid query (or oracle failed)"
    _vmdp = VM()
    _vmdp.run(per_query_full_fs_unlock(zhinv_d, tbb["bound_invX"], *ffo)
              + per_query_full_fs_prog(*fsb, *ffa, query_i=0, deployable=True, final=_finalL))
    assert [decode_num(x) for x in _vmdp.s] == [1] and [decode_num(x) for x in _vmdp.alt] == [P], \
        "deployable-chain per-query left a non-clean stack (expect main [1] / alt [P])"
    _q0dp = _cpd.deepcopy(qfri31)
    _q0dp["layers"][3]["v"] = ((_q0dp["layers"][3]["v"][0] + 1) % P, _q0dp["layers"][3]["v"][1])
    assert not run_per_query_full_fs(*fsb, _q0dp, oNt, offt, Tt, lastt, hd_vals_d, zhinv_d,
                                     tbb["bound_invX"], *ffo, query_i=0, deployable=True, final=_finalL)[0], \
        "deployable-chain per-query accepted a tampered FRI v value"
    _fchk = qfri31["layers"][-1]["ii"] % len(_finalL)
    _fbad = _cpd.deepcopy(_finalL); _fbad[_fchk] = ((_fbad[_fchk][0] + 1) % P, _fbad[_fchk][1])
    assert not run_per_query_full_fs(*fsb, *ffa, zhinv_d, tbb["bound_invX"], *ffo, query_i=0,
                                     deployable=True, final=_fbad)[0], \
        "deployable-chain per-query accepted a tampered final[ii%%n_final] entry"
    assert not run_per_query_full_fs(*fsb, *ffa, zhinv_d, tbb["bound_invX"],
                                     tkp_b, pk_k, tnp, pk_n, skp, pkn_s, snp, pnn_s, query_i=0,
                                     deployable=True, final=_finalL)[0], \
        "deployable-chain per-query accepted a comp-mismatching trace leaf"
    print("3.5b-i-thread deployable FRI chain threaded into the per-query core (deployable=True): OK")
    print("  accept + clean main [1] / alt [P] + oracle ; tampered FRI v / final[ii%%n_final] / comp-mismatch")
    print("  leaf all rejected (fail-closed) ; baked default path byte-identical. op_cost = %d" % _odp)

    # --- HP3.10 FRI-loop primitive (byte-amortized <100KB loop, ported+validated): wire the first loop
    #     primitive into the committed suite (closes the coverage gap flagged in HP10.6 -- the loop cluster
    #     was scratchpad-only). The FRI-index-consistency guard (fri_index_consistency_prog, reference
    #     verify:415) enforces base == ci % stride inside fri_loop_body_prog: without it a prover opens a
    #     DIFFERENT genuinely-committed leaf and substitutes the trace-consistency anchor (RULES-20a Agent-A
    #     8/10). Pure-arithmetic guard -> synthetic [ci,stride,base] boundary test (no proof data needed);
    #     base==ci%stride accepts, base!=ci%stride fails NUMEQUALVERIFY (fail-closed, VMError). ---
    _ic_ci, _ic_str = 100000, 8                                  # stride is a power of the fold (8); ci arbitrary
    _okic, _ = run_fri_index_consistency(_ic_ci, _ic_str, _ic_ci % _ic_str)   # base == ci%stride -> accept
    assert _okic, "HP3.10 FRI index-consistency rejected a valid base == ci%%stride"
    try:
        run_fri_index_consistency(_ic_ci, _ic_str, (_ic_ci % _ic_str + 1) % _ic_str)   # base != ci%stride
        _icteeth = False
    except VMError:
        _icteeth = True
    assert _icteeth, "HP3.10 FRI index-consistency accepted base != ci%%stride (guard has no teeth)"
    print("HP3.10 FRI index-consistency guard (base==ci%%stride, verify:415; fri_loop_body relies on it): OK (accept + fail-closed)")

    # --- HP3.10 FRI-fold loop MATH: the runtime-param s=3 coset fold (fri_coset_fold_loop_prog -- the fold
    #     core of the byte-amortized <100KB loop, with modexp-derived twox) == the verifier oracle _coset_fold,
    #     per s=3 round of a REAL fold-8 proof (query_fri_terms_fold8 gives coset/base/betas/i2x/stride). This
    #     is the hardest FRI-loop primitive; validating its fold == verify()'s fold closes the core of the
    #     coverage gap (HP10.6). No mocks: a real fold_step=3 proof. Precondition (loop docstring): [stride,
    #     pe=2^li0, betas(6), i2x(7), base, coset(16)] -> leaves [.., folded0, folded1]. ---
    _pf310 = STK.prove(CT._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=3, fold_step=3, seed=0x310)
    assert STK.verify(_pf310)[0], "HP3.10 fold-loop test proof must itself verify"
    _D310 = _pf310["stmt"]["depth"]; _m310, _T310 = CT.ct_build_layout(_D310)
    _N310, _oT310, _oN310, _off310, _Hd310, _Dd310, _last310 = STK._setup(_T310, _pf310["blowup"])
    _inv2310 = STK.inv(2); _nfold310 = 0
    for _qt310 in STK.query_fri_terms_fold8(_pf310):
        for _r310 in _qt310["rounds"]:
            if _r310["s"] != 3:                                  # the uniform s=3 body; the tail s<3 round is separate
                continue
            _orc = STK._coset_fold(_r310["coset"], _r310["base"], _r310["li0"], 3,
                                   _r310["betas"], _off310, _oN310, _N310, _inv2310)   # verifier oracle
            _wpre = [NUM(_r310["stride"] % P), NUM((1 << _r310["li0"]) % P)]           # stride, pe=2^li0
            for _bt in _r310["betas"]:
                _wpre += [NUM(_bt[0] % P), NUM(_bt[1] % P)]                            # 3 betas = 6 cells
            _wpre += [NUM(_x % P) for _x in _r310["i2x"]] + [NUM(_r310["base"] % P)]   # 7 i2x hints + base
            for _cv in _r310["coset"]:
                _wpre += [NUM(_cv[0] % P), NUM(_cv[1] % P)]                            # 8 coset GF(p^2) = 16 cells
            _vm310 = VM()
            _vm310.run(_field_prelude() + modexp_define() + _wpre + fri_coset_fold_loop_prog(3, _oN310, _off310))
            assert (decode_num(_vm310.s[-2]) % P, decode_num(_vm310.s[-1]) % P) == (_orc[0] % P, _orc[1] % P), \
                "HP3.10 fri_coset_fold_loop_prog != _coset_fold oracle (round li0=%d)" % _r310["li0"]
            _nfold310 += 1
    assert _nfold310 > 0, "HP3.10 fold-loop test exercised no s=3 rounds"
    print("HP3.10 FRI-fold loop (runtime-param s=3 coset fold, modexp twox) == _coset_fold oracle: OK (%d rounds, real fold-8 proof)" % _nfold310)

    # --- HP3.10 FULL FRI-loop body chain: fri_loop_s3_redeem (DEFINE(fri_loop_body_prog) + n INVOKE) over the
    #     s=3 rounds of the SAME real fold-8 proof. Each INVOKE opens the coset (runtime-depth Merkle), checks
    #     stride/pe == carried + base==ci%stride, binds folded==coset[ci//stride], folds, threads the carried.
    #     After the s=3 rounds the carried folded == the last s=3 round's fold_tgt (verify's fold chain). This is
    #     the make-or-break byte-amortized <100KB loop's body -- validating it end-to-end closes the FRI-loop
    #     coverage gap (HP10.6). Witnesses pushed last-round-DEEPEST + the initial carried [k, stride, pe, comp_x];
    #     a tampered coset breaks the Merkle open (fail-closed). No mocks. ---
    _bq310 = 0
    for _qt310 in STK.query_fri_terms_fold8(_pf310):
        _s3 = [_r for _r in _qt310["rounds"] if _r["s"] == 3]
        if not _s3:
            continue
        _w310 = []
        for _r in reversed(_s3):                                 # last round deepest (round 0 just below carried)
            _w310 += fri_loop_round_witness(_r["stride"], 1 << _r["li0"], _r["betas"], _r["base"], _r["coset"],
                                            _r["path"], bytes.fromhex(_r["root"]), _r["i2x"])
        _cx310 = _qt310["comp_x"]; _r0310 = _s3[0]
        _car310 = [NUM(_qt310["k"] % P), NUM(_r0310["stride"] % P), NUM((1 << _r0310["li0"]) % P),
                   NUM(_cx310[0] % P), NUM(_cx310[1] % P)]                        # initial carried
        _vmb310 = VM()
        _vmb310.run(_field_prelude() + _w310 + _car310 + fri_loop_s3_redeem(len(_s3), _oN310, _off310))
        assert (decode_num(_vmb310.s[-2]) % P, decode_num(_vmb310.s[-1]) % P) == \
            (_s3[-1]["fold_tgt"][0] % P, _s3[-1]["fold_tgt"][1] % P), \
            "HP3.10 fri_loop_s3_redeem folded != the fold chain's fold_tgt"
        _wbad310 = []                                            # tamper the deepest round's coset[0] -> Merkle reject
        for _i310, _r in enumerate(reversed(_s3)):
            _cs310 = [((_c[0] + 1) % P, _c[1]) if (_i310 == 0 and _j310 == 0) else _c
                      for _j310, _c in enumerate(_r["coset"])]
            _wbad310 += fri_loop_round_witness(_r["stride"], 1 << _r["li0"], _r["betas"], _r["base"], _cs310,
                                               _r["path"], bytes.fromhex(_r["root"]), _r["i2x"])
        try:
            _vmt310 = VM(); _vmt310.run(_field_prelude() + _wbad310 + _car310 + fri_loop_s3_redeem(len(_s3), _oN310, _off310))
            _teeth310 = (decode_num(_vmt310.s[-2]) % P, decode_num(_vmt310.s[-1]) % P) != \
                (_s3[-1]["fold_tgt"][0] % P, _s3[-1]["fold_tgt"][1] % P)
        except VMError:
            _teeth310 = True                                    # tampered coset -> runtime Merkle open EQUALVERIFY (fail-closed)
        assert _teeth310, "HP3.10 FRI-loop body chain accepted a tampered coset (no teeth)"
        _bq310 += 1
    assert _bq310 > 0, "HP3.10 FRI-loop body chain exercised no query"
    print("HP3.10 FRI-loop body chain (fri_loop_s3_redeem: runtime open + carried + comp-bind + fold + next-carried) == fold chain: OK (%d queries, fail-closed on tamper)" % _bq310)

    # --- HP3.10 FINAL BIND: bind the loop's terminal fold output to the FS-committed final FRI layer
    #     (fri_final_bind_prog, verify:280 folded==final[ii%n_final]; pos DERIVED via MOD, branchless
    #     index-select, never free witness). For the DEPLOY config N=2^21 (=8^7) the fold chain is 6 s=3
    #     rounds + this final bind, with NO s2/s1 tail (only non-8^k domains like 2^20 have an s<3 tail),
    #     so the s=3 body chain + this final bind cover the whole deploy per-query FRI. The last s=3 round's
    #     fold_tgt == final[base % n_final]; run_fri_final_bind accepts it, a wrong fold output rejects
    #     (fail-closed). ---
    _final310 = _pf310["final"]; _fb310 = 0
    for _qt310 in STK.query_fri_terms_fold8(_pf310):
        _s3 = [_r for _r in _qt310["rounds"] if _r["s"] == 3]
        if not _s3:
            continue
        _lr310 = _s3[-1]                                          # last s=3 round: its fold_tgt is the final element
        _okfb310, _ = run_fri_final_bind(_lr310["fold_tgt"], _final310, _lr310["base"])   # folded==final[base%n_final]
        assert _okfb310, "HP3.10 final-bind rejected the valid terminal fold output"
        try:
            run_fri_final_bind(((_lr310["fold_tgt"][0] + 1) % P, _lr310["fold_tgt"][1]), _final310, _lr310["base"])
            _fbteeth310 = False
        except VMError:
            _fbteeth310 = True
        assert _fbteeth310, "HP3.10 final-bind accepted a wrong terminal fold output (no teeth)"
        _fb310 += 1
    assert _fb310 > 0, "HP3.10 final-bind exercised no query"
    print("HP3.10 FRI-loop final bind (folded==final[ii%%n_final], verify:280; deploy N=2^21 = 6 s=3 rounds + final, no tail): OK (%d queries, fail-closed)" % _fb310)

    # --- HP3.10 fold-8 STAGE-D DROP-IN: _fri_loop_chain_body (comp on top -> stash + inline round witnesses
    #     -> carried -> fri_loop_s3_redeem -> juggle -> final-bind) == verify() on the SAME real fold-8 proof.
    #     The fold-8 analog of _fri_chain_deployable_body (fold-2): [comp0,comp1] -> [1] on accept. Validated
    #     accept for every query + fail-closed on a tampered composition / last-s=3-round coset / final layer.
    #     The deploy stage-D (fri_looped fold-8 branch) uses this in place of the unrolled fold-2 chain. No
    #     mocks: real prove(fold_step=3) proof + query_fri_terms_fold8 + real Merkle paths. ---
    _lc310 = 0
    for _qt310 in STK.query_fri_terms_fold8(_pf310):
        _k310 = _qt310["k"]; _cx310 = _qt310["comp_x"]; _rn310 = _qt310["rounds"]
        _acc310, _ = run_fri_loop_chain(_rn310, _k310, _cx310, _final310, _oN310, _off310)
        assert _acc310, "HP3.10 _fri_loop_chain_body rejected a valid fold-8 query"
        _abl310, _ = run_fri_loop_chain(_rn310, _k310, _cx310, _final310, _oN310, _off310, below=17)  # below-invariance
        assert _abl310, "HP3.10 _fri_loop_chain_body not below-invariant (breaks with total_below beneath comp)"
        _bc310, _ = run_fri_loop_chain(_rn310, _k310, ((_cx310[0] + 1) % P, _cx310[1]), _final310, _oN310, _off310)
        assert not _bc310, "HP3.10 _fri_loop_chain_body accepted a tampered composition"
        _li310 = max(_i for _i, _r in enumerate(_rn310) if _r["s"] == 3)       # tamper last s=3 round's coset[0]
        _tr310 = [dict(_r) for _r in _rn310]
        _tr310[_li310]["coset"] = [((_c[0] + 1) % P, _c[1]) if _j == 0 else _c
                                   for _j, _c in enumerate(_rn310[_li310]["coset"])]
        _bx310, _ = run_fri_loop_chain(_tr310, _k310, _cx310, _final310, _oN310, _off310)
        assert not _bx310, "HP3.10 _fri_loop_chain_body accepted a tampered coset"
        _tf310 = [((_f[0] + 1) % P, _f[1]) for _f in _final310]                # tamper ALL final entries
        _bf310, _ = run_fri_loop_chain(_rn310, _k310, _cx310, _tf310, _oN310, _off310)
        assert not _bf310, "HP3.10 _fri_loop_chain_body accepted a tampered final layer"
        _lc310 += 1
    assert _lc310 > 0, "HP3.10 fold-8 stage-D drop-in exercised no query"
    print("HP3.10 _fri_loop_chain_body (fold-8 stage-D drop-in: comp->carried->loop->final-bind) == verify(): OK (%d queries, below-invariant, fail-closed on tampered comp/coset/final)" % _lc310)

    # --- HP3.10 F1 (agent-gegencheck): the SHARD runs all nq queries in ONE VM / ONE ftable, so a per-query
    #     DEFINE of the FRI-loop fids 0x04/0x05 collides at query 2 ('function already defined', cashvm:263) --
    #     exactly like the sbox/state loops, which is why fri_loop_defines is HOISTED to the shard/per_query
    #     entry and the per-query redeem uses defines_installed=True (INVOKE-only). Validate on REAL fold-8
    #     queries: two chain bodies run in ONE VM with the defines hoisted ONCE -> accept; the un-hoisted form
    #     (defines_installed default False, x2) collides -> VMError (proves both the bug and the fix). ---
    _q310mq = STK.query_fri_terms_fold8(_pf310)
    assert len(_q310mq) >= 2, "HP3.10 F1 multi-query test needs a proof with >=2 queries"

    def _chain310(_qt, _di):                                          # [comp0,comp1] + chain body -> [.., 1]
        return ([NUM(_qt["comp_x"][0] % P), NUM(_qt["comp_x"][1] % P)]
                + _fri_loop_chain_body(_qt["rounds"], _qt["k"], _final310, _oN310, _off310, defines_installed=_di))
    _vmmq310 = VM()
    _vmmq310.run(_field_prelude() + fri_loop_defines(_oN310, _off310)      # HOIST the defines ONCE (shard-entry style)
                 + _chain310(_q310mq[0], True) + [NUM(1), OP("NUMEQUALVERIFY")]   # query 0 accept + clear the bit
                 + _chain310(_q310mq[1], True))                                   # query 1 reuses the hoisted defines
    assert len(_vmmq310.s) == 1 and decode_num(_vmmq310.s[-1]) != 0, \
        "HP3.10 F1 hoisted multi-query chain (2 queries, one VM) did not accept"
    try:                                                             # un-hoisted: per-query DEFINE collides at query 2
        _vmc310 = VM()
        _vmc310.run(_field_prelude() + _chain310(_q310mq[0], False) + [NUM(1), OP("NUMEQUALVERIFY")]
                    + _chain310(_q310mq[1], False))
        _f1collide310 = False
    except VMError:
        _f1collide310 = True
    assert _f1collide310, "HP3.10 F1: un-hoisted per-query DEFINE should collide ('function already defined')"
    print("HP3.10 F1 fix (fri_loop_defines hoisted, per-query redeem defines_installed=True): OK (2 real queries share one VM; un-hoisted collides -> hoist mandatory for the nq>1 fold-8 shard)")

    # --- HP3.10(vi) UNLOCK-SPLIT deploy byte form: _fri_loop_chain_redeem (the DEPTH-INVARIANT P2SH script:
    #     defines + carried + INVOKE + juggle + final-bind) + _fri_loop_chain_unlock (the scriptSig round
    #     openings) == the inline _fri_loop_chain_body (accept + tamper comp/coset/final parity) on the real
    #     fold-8 proof. This is the <100KB lever's true P2SH shape -- the ~2.3KB loop body DEFINE'd once
    #     (amortized redeem ~3.1KB fixed), the depth-scaling openings as cheap scriptSig data (~4.8KB @deploy
    #     -> ~7.9KB/query < 10000B; whole-tx ~85KB < 100KB, matching hp19o real-libauth 7637B). ---
    _frl310 = bytes.fromhex(_pf310["fri_roots"][-1])            # HP11 F3: the FS-single-sourced final commitment root
    _sp310 = 0
    _mq310 = []                                                 # HP16: collect the queries for the FRI aggregation test
    for _qt310 in STK.query_fri_terms_fold8(_pf310):
        _k310 = _qt310["k"]; _cx310 = _qt310["comp_x"]; _rn310 = _qt310["rounds"]
        _mq310.append((_rn310, _k310, _cx310))
        _sa310, _ = run_fri_loop_chain_split(_rn310, _k310, _cx310, _final310, _oN310, _off310, _frl310)
        _ia310, _ = run_fri_loop_chain(_rn310, _k310, _cx310, _final310, _oN310, _off310)
        assert _sa310 and _ia310 and _sa310 == _ia310, "HP3.10(vi) unlock-split != inline on a valid query"
        _sbc310, _ = run_fri_loop_chain_split(_rn310, _k310, ((_cx310[0] + 1) % P, _cx310[1]), _final310, _oN310, _off310, _frl310)
        assert not _sbc310, "HP3.10(vi) unlock-split accepted a tampered composition"
        _sli310 = max(_i for _i, _r in enumerate(_rn310) if _r["s"] == 3)
        _str310 = [dict(_r) for _r in _rn310]
        _str310[_sli310]["coset"] = [((_c[0] + 1) % P, _c[1]) if _j == 0 else _c
                                     for _j, _c in enumerate(_rn310[_sli310]["coset"])]
        _sbx310, _ = run_fri_loop_chain_split(_str310, _k310, _cx310, _final310, _oN310, _off310, _frl310)
        assert not _sbx310, "HP3.10(vi) unlock-split accepted a tampered coset"
        _stf310 = [((_f[0] + 1) % P, _f[1]) for _f in _final310]
        _sbf310, _ = run_fri_loop_chain_split(_rn310, _k310, _cx310, _stf310, _oN310, _off310, _frl310)
        assert not _sbf310, "HP3.10(vi) unlock-split accepted a tampered final layer"
        _wrl310 = bytearray(_frl310); _wrl310[0] ^= 1           # HP11 F3: a wrong fri_root_last must reject
        _sbr310, _ = run_fri_loop_chain_split(_rn310, _k310, _cx310, _final310, _oN310, _off310, bytes(_wrl310))
        assert not _sbr310, "HP3.10 F3 unlock-split accepted a WRONG fri_root_last (final-root-bind broken)"
        _sp310 += 1
    assert _sp310 > 0, "HP3.10(vi) unlock-split exercised no query"
    print("HP3.10(vi) unlock-split deploy byte form (_fri_loop_chain_redeem depth-invariant + _fri_loop_chain_unlock scriptSig, +HP11 F3 final-root-bind) == inline: OK (%d queries, fail-closed comp/coset/final + wrong-fri_root_last)" % _sp310)

    # HP16 FRI AGGREGATION: verify ALL fold-8 queries in ONE input (fri_loop_defines hoisted once) == the per-query
    # split -- the <100KB FRI lever (6 separate FRI inputs -> ~2 aggregated at ~3 queries/input under the 10000B cap).
    # A tampered comp in any query rejects fail-closed (below-invariant, per-query F3 root-bind to the shared frl).
    _amok310, _amoc310 = run_fri_loop_chain_multi(_mq310, _final310, _oN310, _off310, _frl310)
    assert _amok310, "HP16 aggregated multi-query FRI rejected all-valid queries"
    _mqbad310 = [((_r[0], _r[1], ((_r[2][0] + 1) % P, _r[2][1])) if _i == 0 else _r) for _i, _r in enumerate(_mq310)]
    _ambad310, _ = run_fri_loop_chain_multi(_mqbad310, _final310, _oN310, _off310, _frl310)
    assert not _ambad310, "HP16 aggregated multi-query FRI accepted a tampered composition"
    _amrb310 = _prog_nbytes(fri_loop_chain_multi_redeem([(r, k) for (r, k, _c) in _mq310], _oN310, _off310, _final310, _frl310))
    _amsep310 = sum(_prog_nbytes(_field_prelude() + _fri_loop_chain_redeem(r, k, _final310, _oN310, _off310, _frl310)) for (r, k, _c) in _mq310)
    print("HP16 FRI aggregation (%d fold-8 queries in ONE input, fri_loop_defines hoisted once) == per-query split: OK "
          "(tampered comp reject fail-closed; %d-separate redeem=%dB vs aggregated=%dB -> defines amortized -%dB, op_cost=%d)"
          % (len(_mq310), len(_mq310), _amsep310, _amrb310, _amsep310 - _amrb310, _amoc310))

    # --- 2.31b (full shard): aggregate the zero-free-witness per-query verify over ALL nq queries at
    #     their FS-derived indices, binding the query count (round-5 soundness: binding only ONE query
    #     collapses the security margin 100->~20 bit). All nq accept; a tampered leaf or a wrong hint in
    #     any query rejects; a wrong witness-block count (too few -> underflow, too many -> non-clean
    #     stack) rejects. (The byte-amortized OP_BEGIN/UNTIL loop form is HP3.) ---
    _qterms = STK.query_terms(pft); _qfris = STK.query_fri_terms(pft)

    def _qblock(i, salt_flip=False, zh_bump=0):
        qi = pft["queries"][i]; ki = qi["k"]; kni = (ki + shiftt) % Nt
        zhi = (pow((pow(Ddt[ki], Tt, P) - 1) % P, P - 2, P) + zh_bump) % P
        sk = bytearray(bytes.fromhex(qi["sk"]))
        if salt_flip:
            sk[0] ^= 1                                          # corrupt the trace salt -> leaf hash != committed
        return per_query_full_fs_unlock(
            zhi, _qterms[i]["bound_invX"],
            trace_leaf_preimage(qi["ck"], bytes(sk), CT.FLAT_COLS),
            [(bytes.fromhex(s), b) for s, b in qi["pk"]],
            trace_leaf_preimage(qi["cn"], bytes.fromhex(qi["sn"]), CT.FLAT_COLS),
            [(bytes.fromhex(s), b) for s, b in qi["pn"]],
            selector_preimage_coset(svt, ki), sm_path(dsct, ki),
            selector_preimage_coset(svt, kni), sm_path(dsct, kni))

    q_blocks = [_qblock(i) for i in range(pft["nq"])]
    shb = (P2.MAT_DIAG12, minvcap, CT.M_EXT_INV[0], CT.N_OUT, rspec, CT.FLAT_COLS, CT.HELD_COLS,
           depth_o, dscr, shiftt, tpb_b, stmtt["root"], stmtt["nf"], stmtt["cm_out"], fr_b, non_b, Nt, pft["nq"])
    sha = (_qfris, oNt, offt, Tt, lastt, hd_vals_d)
    oksh, _osh = run_shard_verify(*shb, *sha, q_blocks)
    assert oksh and STK.verify(pft)[0], "full shard rejected a valid all-queries proof (or oracle failed)"
    assert not run_shard_verify(*shb, *sha,
                                [_qblock(2, salt_flip=True) if i == 2 else b for i, b in enumerate(q_blocks)])[0], \
        "full shard accepted a tampered query-2 trace leaf"
    assert not run_shard_verify(*shb, *sha,
                                [_qblock(1, zh_bump=1) if i == 1 else b for i, b in enumerate(q_blocks)])[0], \
        "full shard accepted a wrong zh_inv hint in query 1"
    assert not run_shard_verify(*shb, *sha, q_blocks[:-1])[0], \
        "full shard accepted too few query blocks (count not bound)"
    assert not run_shard_verify(*shb, *sha, q_blocks + [q_blocks[0]])[0], \
        "full shard accepted too many query blocks (count not bound)"
    # 2.32: the accepted shard's nq queries span BOTH comp-bit branches (verify():267 tgt = fw if k>=half
    #       else fv) -- the demo's 4 idxs cover k>=N/2 (1082) and k<N/2 (510,812,10), so the accept above
    #       exercises both branches.
    _half = Nt // 2
    assert any(q["k"] < _half for q in pft["queries"]) and any(q["k"] >= _half for q in pft["queries"]), \
        "shard queries do not span both comp-bit branches (need k<N/2 and k>=N/2)"
    # 2.39: a grind-failing nonce (the FS PoW check inside each per-query transcript) rejects the shard.
    _bn = bytearray(non_b); _bn[0] ^= 1
    assert not run_shard_verify(*(shb[:15] + (bytes(_bn),) + shb[16:]), *sha, q_blocks)[0], \
        "shard accepted a grind-failing nonce"
    # HP10.5 stage-A DEPLOY-THREADING through the MONOLITH shard: the S-box + state DEFINEs are hoisted to the
    # shard ENTRY (assemble_transition runs PER-QUERY, so a per-call DEFINE would collide at query 2 -- the DEFINEs
    # sit once next to _field_prelude, each per-query INVOKEs). All nq accept (== unrolled); the count binding still
    # holds (too few / too many query blocks reject, fail-closed). Proves the shard-entry DEFINE placement is correct.
    oksh_sa, _ = run_shard_verify(*shb, *sha, q_blocks, sbox_looped=True, state_looped=True)
    assert oksh_sa, "HP10.5 stage-A-looped shard rejected a valid all-queries proof (should == unrolled accept)"
    assert not run_shard_verify(*shb, *sha, q_blocks[:-1], sbox_looped=True, state_looped=True)[0], \
        "HP10.5 stage-A-looped shard accepted too few query blocks (count not bound)"
    assert not run_shard_verify(*shb, *sha, q_blocks + [q_blocks[0]], sbox_looped=True, state_looped=True)[0], \
        "HP10.5 stage-A-looped shard accepted too many query blocks (count not bound)"
    print("HP10.5 stage-A (S-box+state) loops threaded through the shard (DEFINEs at shard entry) == unrolled: OK (count-bound)")

    # --- 3.5b-ii-a (deployable shard): flip shard_verify to the deployable per-query chain. With
    #     deployable=True + final, each per-query runs stage D via _fri_chain_deployable_body (derived
    #     index-selection + Merkle-bound v/w openings) instead of the baked qfri targets -> 2.36-2.38 at the
    #     SHARD level. All nq accept (clean [1], oracle); a FRI-internal tamper in ONE query rejects; the
    #     count binding still holds (too few / too many query blocks reject). The baked default (final=None)
    #     shard asserts above stay byte-identical (regression). ---
    _fL = pft["final"]
    okds, _ods = run_shard_verify(*shb, *sha, q_blocks, deployable=True, final=_fL)
    assert okds and STK.verify(pft)[0], "deployable shard rejected a valid all-queries proof (or oracle failed)"
    _qf_bad = _cpd.deepcopy(_qfris)
    _qf_bad[2]["layers"][2]["w"] = ((_qf_bad[2]["layers"][2]["w"][0] + 1) % P, _qf_bad[2]["layers"][2]["w"][1])
    assert not run_shard_verify(*shb, _qf_bad, oNt, offt, Tt, lastt, hd_vals_d, q_blocks,
                                deployable=True, final=_fL)[0], \
        "deployable shard accepted a FRI-tampered query (2.36-2.38 at the shard level)"
    assert not run_shard_verify(*shb, *sha, q_blocks[:-1], deployable=True, final=_fL)[0], \
        "deployable shard accepted too few query blocks (count not bound)"
    assert not run_shard_verify(*shb, *sha, q_blocks + [q_blocks[0]], deployable=True, final=_fL)[0], \
        "deployable shard accepted too many query blocks (count not bound)"
    print("3.5b-ii-a deployable shard (shard_verify deployable=True): OK")
    print("  all %d queries accept (clean [1] + oracle) ; FRI-tampered query rejects (2.36-2.38 shard-level) ;"
          % pft["nq"])
    print("  count binding intact ; baked default (final=None) byte-identical. op_cost = %d" % _ods)

    # --- 2.31 threading enabler: the assembly progs are offset-aware (`below` items beneath the block
    #     are preserved and every PICK index is shifted), so they compose on ONE unified stack ---
    _dm = [7, 11, 13, 17, 19]; Bn = len(_dm)
    vmo = VM()
    vmo.run(_field_prelude() + [NUM(d) for d in _dm]
            + assemble_transition_unlock(curt, nxtt, pubt, wnt, CT.HELD_COLS)
            + assemble_transition_residuals_prog(P2.MAT_DIAG12, minvcap, below=Bn))
    go = [decode_num(x) for x in vmo.s]
    assert go[:Bn] == [d % P for d in _dm] and go[Bn:] == reft, "transition offset (below=%d) wrong" % Bn
    vmo = VM()
    vmo.run(_field_prelude() + [NUM(d) for d in _dm]
            + assemble_boundary_unlock(curb, stmtb2, CT.N_OUT, CT.HELD_COLS)
            + assemble_boundary_residuals_prog(CT.M_EXT_INV[0], CT.N_OUT, rspec, below=Bn))
    go = [decode_num(x) for x in vmo.s]
    assert go[:Bn] == [d % P for d in _dm] and go[Bn:] == tbb["bound_v"], "boundary offset (below=%d) wrong" % Bn
    vmo = VM()
    vmo.run(_field_prelude() + [NUM(d) for d in _dm]
            + compose_feed_unlock(gott, gotb, tbb["trans_a"], tbb["qf_trans"], tbb["bound_invX"], tbb["bound_a"])
            + compose_feed_prog(len(gott), len(gotb), below=Bn))
    go = [decode_num(x) for x in vmo.s]
    assert go[:Bn] == [d % P for d in _dm], "compose offset: below items not preserved"
    assert (go[Bn], go[Bn + 1]) == tbb["comp_x"], "compose offset: comp differs from below=0"

    # --- 2.23: derive the FRI fold-index chain on the BCH-VM from k; reproduce verify's ii sequence ---
    qft = STK.query_fri_terms(pft)
    lyr = qft[0]["layers"]
    halves = [ly["half"] for ly in lyr]
    ref_ii = [ly["ii"] for ly in lyr]
    kf = qft[0]["k"]
    gotii, _ocii = run_fri_index_chain(kf, halves)
    assert gotii == ref_ii, "VM FRI index chain != verify ii sequence (%s vs %s)" % (gotii, ref_ii)
    ci = kf                                                     # independent running-mod cross-check
    for li in range(len(halves)):
        assert gotii[li] == ci % halves[li], "ii_%d != running mod" % li
        assert 0 <= gotii[li] < halves[li], "ii_%d out of range" % li
        ci = gotii[li]

    # --- 2.24: derive the per-FRI-layer domain point xpos from ii on the BCH-VM (verify:270) ---
    for li, ly in enumerate(lyr):
        xg, _ocx = run_fri_xpos(oNt, offt, li, ly["ii"])
        assert xg == ly["xpos"], "VM xpos layer %d != verify xpos (%s vs %s)" % (li, xg, ly["xpos"])

    # --- 2.25: open FRI v@ii and w@(ii+half) per layer against fri_roots with INDEX-derived bits ---
    froots_hex = pft["fri_roots"]
    q0f = pft["queries"][0]
    for li, ly in enumerate(lyr):
        rootb = bytes.fromhex(froots_hex[li])
        vp = [(bytes.fromhex(s), b) for s, b in q0f["fri"][li]["vp"]]
        wp = [(bytes.fromhex(s), b) for s, b in q0f["fri"][li]["wp"]]
        fv = q0f["fri"][li]["v"]; fw = q0f["fri"][li]["w"]
        vg, _ = run_fri_open_value(fv[0], fv[1], vp, rootb, ly["ii"])
        assert vg == [fv[0] % P, fv[1] % P], "FRI v open layer %d wrong value" % li
        wg, _ = run_fri_open_value(fw[0], fw[1], wp, rootb, ly["ii"] + ly["half"])
        assert wg == [fw[0] % P, fw[1] % P], "FRI w open layer %d wrong value" % li
    r0 = bytes.fromhex(froots_hex[0]); vp0 = [(bytes.fromhex(s), b) for s, b in q0f["fri"][0]["vp"]]
    v0f = q0f["fri"][0]["v"]
    try:                                                        # fail-closed: a wrong index rejects
        run_fri_open_value(v0f[0], v0f[1], vp0, r0, lyr[0]["ii"] + 1)
        raise AssertionError("FRI open accepted a wrong index")
    except VMError:
        pass
    try:                                                        # fail-closed: a tampered value rejects
        run_fri_open_value((v0f[0] + 1) % P, v0f[1], vp0, r0, lyr[0]["ii"])
        raise AssertionError("FRI open accepted a tampered value")
    except VMError:
        pass

    # --- 3.5b-i: two-leaf FRI opener + layer fold, deployable (v/w from the WITNESS). fri_open_vw opens
    #     BOTH v@ii and w@(ii+half) -> [fv0,fv1,fw0,fw1]; fri_fold_from_vfw re-arranges into _FOLD_OPS
    #     order (fw..fv, fv ON TOP -- root cause of an earlier operand-order confusion, now pinned) and
    #     folds -> [folded0,folded1] == verify's fold_tgt. All 8 layers + tamper (w value, i2x hint). ---
    inv2f = pow(2, P - 2, P)
    for li, ly in enumerate(lyr):
        rootb = bytes.fromhex(froots_hex[li])
        vp = [(bytes.fromhex(s), b) for s, b in q0f["fri"][li]["vp"]]
        wp = [(bytes.fromhex(s), b) for s, b in q0f["fri"][li]["wp"]]
        fv = q0f["fri"][li]["v"]; fw = q0f["fri"][li]["w"]
        vw, _ = run_fri_open_vw(fv[0], fv[1], vp, fw[0], fw[1], wp, rootb, ly["ii"], ly["half"])
        assert vw == [fv[0] % P, fv[1] % P, fw[0] % P, fw[1] % P], "fri_open_vw layer %d wrong [fv,fw]" % li
        twoxf = (2 * ly["xpos"]) % P; i2xf = pow(twoxf, P - 2, P)
        vm = VM()
        vm.run(_field_prelude()
               + fri_open_vw_unlock(fv[0], fv[1], vp, fw[0], fw[1], wp, rootb, ly["ii"], ly["half"])
               + fri_open_vw_prog(len(vp))
               + fri_fold_from_vfw_prog(ly["beta"][0], ly["beta"][1], inv2f, i2xf, twoxf))
        folded = (decode_num(vm.s[-2]), decode_num(vm.s[-1]))
        assert len(vm.s) == 2 and folded == tuple(x % P for x in ly["fold_tgt"]), \
            "deployable open+fold layer %d folded != verify fold_tgt" % li
    ly0d = lyr[0]; vp0d = [(bytes.fromhex(s), b) for s, b in q0f["fri"][0]["vp"]]
    wp0d = [(bytes.fromhex(s), b) for s, b in q0f["fri"][0]["wp"]]
    fv0d = q0f["fri"][0]["v"]; fw0d = q0f["fri"][0]["w"]; r0d = bytes.fromhex(froots_hex[0])
    try:                                                        # tampered w -> Merkle open fails
        run_fri_open_vw(fv0d[0], fv0d[1], vp0d, (fw0d[0] + 1) % P, fw0d[1], wp0d, r0d, ly0d["ii"], ly0d["half"])
        raise AssertionError("fri_open_vw accepted a tampered w value")
    except VMError:
        pass
    twox0d = (2 * ly0d["xpos"]) % P
    try:                                                        # wrong i2x inverse hint -> fold fails
        run_fri_fold_from_vfw(fv0d[0], fv0d[1], fw0d[0], fw0d[1], ly0d["beta"][0], ly0d["beta"][1],
                              inv2f, (pow(twox0d, P - 2, P) + 1) % P, twox0d)
        raise AssertionError("fri_fold_from_vfw accepted a wrong i2x hint")
    except VMError:
        pass

    # --- 3.5b-i part2: fri_roll_bind (val == index-selected leaf; the SAME block for the layer-0
    #     comp-bind AND the rolling folded==next bind) + the FULL deployable fri_chain (open+bind+fold per
    #     layer + final-bind, every check DERIVED, openings Merkle-bound). Reproduces verify's FRI accept;
    #     a wrong comp / a tampered FRI value / a wrong final each reject (2.36-2.38 at the chain level). ---
    for li in range(len(lyr) - 1):                              # rolling: folded_li == ii-selected next leaf
        rb, _ = run_fri_roll_bind(lyr[li]["fold_tgt"], lyr[li + 1]["v"], lyr[li + 1]["w"],
                                  lyr[li]["ii"], lyr[li + 1]["half"])
        assert rb == [lyr[li + 1]["v"][0] % P, lyr[li + 1]["v"][1] % P,
                      lyr[li + 1]["w"][0] % P, lyr[li + 1]["w"][1] % P], "roll_bind layer %d wrong [fv,fw]" % li
    h0r = lyr[0]["half"]
    rc0, _ = run_fri_roll_bind(qft[0]["comp_x"], lyr[0]["v"], lyr[0]["w"], qft[0]["k"], h0r)   # layer-0 comp-bind
    assert rc0 == [lyr[0]["v"][0] % P, lyr[0]["v"][1] % P, lyr[0]["w"][0] % P, lyr[0]["w"][1] % P], "comp roll_bind"
    if tuple(lyr[0]["v"]) != tuple(lyr[0]["w"]):                # fail-closed: a wrong-branch value rejects
        try:
            run_fri_roll_bind(lyr[0]["w"], lyr[0]["v"], lyr[0]["w"], h0r - 1, h0r)   # idx<half selects fv, val=fw
            raise AssertionError("roll_bind accepted the wrong-branch leaf")
        except VMError:
            pass
    okfc, _ocfc = run_fri_chain_deployable(qft[0]["comp_x"], lyr, qft[0]["k"], pft["final"])
    assert okfc and STK.verify(pft)[0], "deployable fri_chain rejected a valid proof (or oracle failed)"
    import copy as _cpfc
    assert not run_fri_chain_deployable(((qft[0]["comp_x"][0] + 1) % P, qft[0]["comp_x"][1]),
                                        lyr, qft[0]["k"], pft["final"])[0], "fri_chain accepted a wrong comp"
    lyr_bad = _cpfc.deepcopy(lyr); lyr_bad[3]["v"] = ((lyr_bad[3]["v"][0] + 1) % P, lyr_bad[3]["v"][1])
    assert not run_fri_chain_deployable(qft[0]["comp_x"], lyr_bad, qft[0]["k"], pft["final"])[0], \
        "fri_chain accepted a tampered FRI v value"
    _fchk = lyr[-1]["ii"] % len(pft["final"])                  # the entry THIS query binds: final[ii%n_final]
    final_bad = _cpfc.deepcopy(pft["final"]); final_bad[_fchk] = ((final_bad[_fchk][0] + 1) % P, final_bad[_fchk][1])
    assert not run_fri_chain_deployable(qft[0]["comp_x"], lyr, qft[0]["k"], final_bad)[0], \
        "fri_chain accepted a tampered final layer (the ii%n_final-selected entry)"
    # --- 3.5b-iii-1a: the WITNESS-DRIVEN deployable FRI chain (v/w from the push-only unlock, roots baked,
    #     ii derived from k via fri_index_chain) reproduces run_fri_chain_deployable's accept EXACTLY and is
    #     fail-closed. v/w are Merkle-bound (baked root) + fold-bound + index-selected; nothing free enters. ---
    okfcw, _ocfcw = run_fri_chain_deployable_witness(qft[0]["comp_x"], lyr, qft[0]["k"], pft["final"])
    assert okfcw == okfc and okfcw, "witness-driven fri_chain != baked fri_chain accept (or rejected a valid proof)"
    assert not run_fri_chain_deployable_witness(((qft[0]["comp_x"][0] + 1) % P, qft[0]["comp_x"][1]),
                                                lyr, qft[0]["k"], pft["final"])[0], "witness fri_chain accepted a wrong comp"
    assert not run_fri_chain_deployable_witness(qft[0]["comp_x"], lyr_bad, qft[0]["k"], pft["final"])[0], \
        "witness fri_chain accepted a tampered FRI v value (from the unlock)"
    assert not run_fri_chain_deployable_witness(qft[0]["comp_x"], lyr, qft[0]["k"], final_bad)[0], \
        "witness fri_chain accepted a tampered final layer"
    print("3.5b-iii-1a witness-driven FRI chain (v/w from unlock, roots baked, ii derived) == baked fri_chain "
          "accept ; wrong comp / tampered v / tampered final all reject (fail-closed). op_cost = %d" % _ocfcw)
    # --- 3.5b-iii-2: PARTIAL witness-driven FRI chain -- the FRI witness (~4.5KB > 1650B) is byte-split into
    #     contiguous layer-subset thin-shard inputs linked by the (folded, running-ii) cross-input carry.
    #     Validate partial[0,c) + partial[c,L) reproduces the FULL witness chain accept + is fail-closed on a
    #     wrong carry (a forged folded value OR running index breaks the fold chain -> reject). ---
    _Lq = len(lyr); _cq = _Lq // 2
    _carry, _ = run_fri_partial_witness(lyr, 0, _cq, qft[0]["comp_x"], qft[0]["k"], pft["final"])
    assert _carry is not None and len(_carry) == 3, "partial FRI [0,c) did not leave the (folded, ii) carry"
    _folded_c = (_carry[0], _carry[1]); _ii_c = _carry[2]
    _acc2, _ocpf = run_fri_partial_witness(lyr, _cq, _Lq, _folded_c, _ii_c, pft["final"])
    assert _acc2 is True, "partial FRI [c,L) rejected a valid split (the (folded,ii) carry composition is broken)"
    assert run_fri_partial_witness(lyr, _cq, _Lq, ((_folded_c[0] + 1) % P, _folded_c[1]), _ii_c, pft["final"])[0] is False, \
        "partial FRI accepted a WRONG folded carry (cross-input carry not fold-bound)"
    assert run_fri_partial_witness(lyr, _cq, _Lq, _folded_c, (_ii_c + 1), pft["final"])[0] is False, \
        "partial FRI accepted a WRONG running-index carry"
    print("3.5b-iii-2 partial FRI chain (layer-subset [0,%d)+[%d,%d) + (folded,ii) cross-input carry) == full "
          "witness chain accept ; wrong folded / wrong ii carry reject (fail-closed). op_cost = %d" % (_cq, _cq, _Lq, _ocpf))
    # --- 3.5b-iii-5c (HP6.1) PAIR-LEAF: the SAME partial FRI chain against a pairleaf=True proof -- the opener
    #     opens ONE coset-pair leaf/layer (bound_retain_open + split_cells(4)) instead of two (v@ii, w@ii+half),
    #     halving the per-layer Merkle paths. flag-gated auto-detect ("p" in ly). Validate accept + fail-closed. ---
    _pfp = STK.prove(CT._demo_witness(depth=2), seed=11, pairleaf=True)
    _qfp = STK.query_fri_terms(_pfp)[0]; _lyp = _qfp["layers"]; _Lp = len(_lyp); _cp = _Lp // 2
    assert "p" in _lyp[0] and "vp" not in _lyp[0], "pairleaf layers must carry the single pair-path 'p'"
    _cyp, _ = run_fri_partial_witness(_lyp, 0, _cp, _qfp["comp_x"], _qfp["k"], _pfp["final"])
    assert _cyp is not None and len(_cyp) == 3, "pair-leaf partial FRI [0,c) did not leave the (folded, ii) carry"
    _accp, _ocp = run_fri_partial_witness(_lyp, _cp, _Lp, (_cyp[0], _cyp[1]), _cyp[2], _pfp["final"])
    assert _accp is True, "pair-leaf partial FRI [c,L) rejected a valid split"
    assert run_fri_partial_witness(_lyp, _cp, _Lp, ((_cyp[0] + 1) % P, _cyp[1]), _cyp[2], _pfp["final"])[0] is False, \
        "pair-leaf partial FRI accepted a WRONG folded carry"
    _lyp_t = [dict(_l) for _l in _lyp]; _zt = dict(_lyp_t[_cp])
    _zt["v"] = ((_zt["v"][0] + 1) % P, _zt["v"][1]); _lyp_t[_cp] = _zt   # tamper a pair-leaf v limb (Merkle binding)
    assert run_fri_partial_witness(_lyp_t, _cp, _Lp, (_cyp[0], _cyp[1]), _cyp[2], _pfp["final"])[0] is not True, \
        "pair-leaf partial FRI accepted a TAMPERED pair-leaf value (Merkle leaf binding broken)"
    print("3.5b-iii-5c PAIR-LEAF (HP6.1): partial FRI (1 coset-leaf/layer, split_cells(4)) == accept ; wrong-carry "
          "+ tampered-pair-value reject (fail-closed) ; pair-path %d sibs (vs 2 leaves). op_cost = %d" % (len(_lyp[0]["p"]), _ocp))
    # --- 3.5b-iii-3 enabler: the EMBEDDABLE partial FRI (wbase>0) preserves `wbase` items BENEATH the FRI
    #     witness and leaves [below.., folded0, folded1, ii] with the SAME carry -- the iii-3 producer input
    #     needs this (the carry_preimage it binds to its computed carry-out sits beneath the FRI witness). ---
    _sent = [0xABCDE12345, 0x67890]
    _vmemb = VM(); _vmemb.run([NUM(x) for x in _sent] + _fri_partial_witness_unlock(lyr, 0, _cq)
                              + fri_partial_witness_redeem(lyr, 0, _cq, qft[0]["comp_x"], qft[0]["k"], pft["final"],
                                                           wbase=len(_sent)))
    _oemb = [decode_num(x) for x in _vmemb.s]
    assert _oemb[:len(_sent)] == _sent and _oemb[len(_sent):] == list(_carry), \
        "embeddable partial FRI (wbase>0) did not preserve the below items + the same (folded,ii) carry (%s)" % _oemb
    print("3.5b-iii-3 embeddable partial FRI (wbase>0): preserves below items + leaves the same (folded,ii) carry: OK")
    # --- 3.5b-iii-3 producer FRI input: the embeddable partial [0,c) + carry_preimage binding (split_cells(3)
    #     == computed carry-out). The carry_preimage is bound to the on-chain computation, so a forged carry-out
    #     rejects AT the producer (not just the consumer). The consumer (deploy_check) reads it cross-input. ---
    _cpre = fri_carry_preimage(_carry[0], _carry[1], _carry[2])
    _pacc, _opp = run_fri_partial_producer(_cpre, lyr, 0, _cq, qft[0]["comp_x"], qft[0]["k"])
    assert _pacc, "producer FRI input rejected the honest carry_preimage"
    assert not run_fri_partial_producer(fri_carry_preimage((_carry[0] + 1) % P, _carry[1], _carry[2]),
                                        lyr, 0, _cq, qft[0]["comp_x"], qft[0]["k"])[0], \
        "producer FRI input accepted a forged carry_preimage"
    print("3.5b-iii-3 producer FRI input (partial + carry_preimage binding): honest accepts, forged rejects (fail-closed). op_cost = %d" % _opp)

    # --- 2.26: bind comp == FRI-layer-0 leaf, leaf chosen by the derived k>=half_0 bit (verify:266-268) ---
    half0 = lyr[0]["half"]
    fv0v = q0f["fri"][0]["v"]; fw0v = q0f["fri"][0]["w"]
    compx = qft[0]["comp_x"]; kq = qft[0]["k"]
    assert tuple(compx) == tuple(fw0v if kq >= half0 else fv0v), "oracle: comp_x != k-selected FRI layer-0 leaf"
    resb, _ocb = run_fri_select_bind(fv0v, fw0v, compx, kq, half0)
    assert resb == [fv0v[0] % P, fv0v[1] % P, fw0v[0] % P, fw0v[1] % P], "comp-bind did not preserve fv/fw"
    rgt, _ = run_fri_select_bind(fv0v, fw0v, fw0v, half0, half0)          # k>=half_0 branch selects fw
    assert rgt == [fv0v[0] % P, fv0v[1] % P, fw0v[0] % P, fw0v[1] % P], "fw-branch accept failed"
    rlt, _ = run_fri_select_bind(fv0v, fw0v, fv0v, half0 - 1, half0)      # k<half_0 branch selects fv
    assert rlt == [fv0v[0] % P, fv0v[1] % P, fw0v[0] % P, fw0v[1] % P], "fv-branch accept failed"
    if tuple(fv0v) != tuple(fw0v):                              # fail-closed: the wrong leaf per branch rejects
        for bad_k, bad_comp in ((half0, fv0v), (half0 - 1, fw0v)):
            try:
                run_fri_select_bind(fv0v, fw0v, bad_comp, bad_k, half0)
                raise AssertionError("comp-bind accepted the wrong leaf for the branch")
            except VMError:
                pass

    # --- 2.27: FRI fold with DERIVED beta (2.4 FS) + DERIVED twox=2*xpos (2.24); reproduce fold_tgt.
    #     The deployable ext_fold_stack_prog hint-validates inv2*2==1 and i2x*twox==1 (fail-closed). ---
    inv2v = pow(2, P - 2, P)
    for li, ly in enumerate(lyr):
        fv = ly["v"]; fw = ly["w"]; beta = ly["beta"]
        twox = (2 * ly["xpos"]) % P; i2x = pow(twox, P - 2, P)
        fld, _ocf = run_ext_fold_stack(fv[0], fv[1], fw[0], fw[1], beta[0], beta[1], inv2v, i2x, twox)
        assert list(fld) == [ly["fold_tgt"][0] % P, ly["fold_tgt"][1] % P], "fold layer %d != fold_tgt" % li
    ly0 = lyr[0]; twox0 = (2 * ly0["xpos"]) % P                 # fail-closed: a wrong i2x hint rejects
    try:
        run_ext_fold_stack(ly0["v"][0], ly0["v"][1], ly0["w"][0], ly0["w"][1], ly0["beta"][0], ly0["beta"][1],
                           inv2v, (pow(twox0, P - 2, P) + 1) % P, twox0)
        raise AssertionError("fold accepted a wrong i2x hint")
    except VMError:
        pass

    # --- 2.28: bind folded(li) == opened v/w(li+1), leaf chosen by the derived ii>=nh bit (verify:274-278).
    #     Reuses the generic index-selected binding (fri_select_bind) -- same shape as 2.26. ---
    for li in range(len(lyr) - 1):                              # non-final layers
        ii = lyr[li]["ii"]; nh = lyr[li + 1]["half"]
        nv = lyr[li + 1]["v"]; nw = lyr[li + 1]["w"]; folded = lyr[li]["fold_tgt"]
        assert tuple(folded) == tuple(nw if ii >= nh else nv), "oracle: fold_tgt != ii-selected next v/w (L%d)" % li
        resf, _ = run_fri_select_bind(nv, nw, folded, ii, nh)  # folded == select(next v/w); preserve next v/w
        assert resf == [nv[0] % P, nv[1] % P, nw[0] % P, nw[1] % P], "fold-target bind lost next v/w (L%d)" % li
        if tuple(nv) != tuple(nw):                             # fail-closed: the non-selected leaf rejects
            try:
                run_fri_select_bind(nv, nw, (nw if ii < nh else nv), ii, nh)
                raise AssertionError("fold-target bind accepted the wrong leaf (L%d)" % li)
            except VMError:
                pass

    # --- 2.29: bind the terminal fold output to the FS-committed final FRI layer (verify:280) ---
    Lf = len(pft["final"])
    for qi, qd in enumerate(qft):
        ll = qd["layers"][-1]; pos = ll["ii"] % Lf
        assert tuple(ll["fold_tgt"]) == tuple(pft["final"][pos]), "oracle: last fold_tgt != final[ii mod L] (q%d)" % qi
        ok29, _oc29 = run_fri_final_bind(ll["fold_tgt"], pft["final"], ll["ii"])
        assert ok29, "final bind rejected the valid terminal fold (q%d)" % qi
    ll0 = qft[0]["layers"][-1]                                  # fail-closed: a tampered terminal fold rejects
    try:
        run_fri_final_bind(((ll0["fold_tgt"][0] + 1) % P, ll0["fold_tgt"][1]), pft["final"], ll0["ii"])
        raise AssertionError("final bind accepted a tampered terminal fold")
    except VMError:
        pass

    # --- 2.29b (HP7.4c): bind `final` to its COMMITMENT merkle(final)==fri_roots[-1] on the BCH-VM. Closes
    # the per-input-final divergence + the free unqueried slots that folded==final[pos] alone leaves open
    # (the oracle verify() carries the identical "final root" reference check). Same _leaf_ext leaf format. ---
    fri_root_last = bytes.fromhex(pft["fri_roots"][-1])
    assert (Lf & (Lf - 1)) == 0, "final size %d not a power of 2 (fri_final_root_bind precondition)" % Lf
    ok29b, _oc29b = run_fri_final_root_bind(pft["final"], fri_root_last)
    assert ok29b, "final-root bind rejected the honest committed final layer"
    for jf in range(Lf):                                       # tamper ANY slot (incl. unqueried) -> reject
        bad_final = [list(v) for v in pft["final"]]
        bad_final[jf][0] = (bad_final[jf][0] + 1) % P
        try:
            run_fri_final_root_bind(bad_final, fri_root_last)
            raise AssertionError("final-root bind accepted a tampered final slot %d" % jf)
        except VMError:
            pass
    bad_root = bytearray(fri_root_last); bad_root[0] ^= 1        # a wrong committed root -> reject
    try:
        run_fri_final_root_bind(pft["final"], bytes(bad_root))
        raise AssertionError("final-root bind accepted against a wrong fri_roots[-1]")
    except VMError:
        pass

    # --- HP2.3: selector commitment (pinned root) + Merkle opening on the BCH-VM ---
    root, stree, preimgs = build_selector_commitment(lay, T)   # lay/T = the real trace layout
    kk = meta["range"][1]["offset"] + 5
    path = sm_path(stree, kk)
    okv2, ocm = run_merkle_path(preimgs[kk], path, root)
    assert okv2, "VM selector Merkle open rejected a valid opening"
    bad_pre = bytearray(preimgs[kk]); bad_pre[0] ^= 1
    okb, _ = run_merkle_path(bytes(bad_pre), path, root)
    assert not okb, "VM accepted a tampered selector leaf (selector forgery not caught)"
    bad_root = bytearray(root); bad_root[0] ^= 1
    okr, _ = run_merkle_path(preimgs[kk], path, bytes(bad_root))
    assert not okr, "VM accepted against a wrong pinned selector root"
    # the committed leaf IS the authentic public layout selectors the composition consumes
    assert preimgs[kk] == selector_preimage(CT.ct_public_layout(meta, T), kk), \
        "committed selector leaf != public layout"

    # --- HP3.5: GF(p^2) FRI fold step on the BCH-VM (hint-validated inverses) ---
    ocf = 0
    for _ in range(20):
        fv = (rng.randrange(0, P), rng.randrange(0, P)); fw = (rng.randrange(0, P), rng.randrange(0, P))
        beta = (rng.randrange(0, P), rng.randrange(0, P)); xpos = rng.randrange(1, P)
        i2 = pow(2, P - 2, P); twox = (2 * xpos) % P; i2x = pow(twox, P - 2, P)
        ref = F2.add(F2.scalar(i2, F2.add(fv, fw)), F2.mul(beta, F2.scalar(i2x, F2.sub(fv, fw))))
        got, ocf = run_ext_fold(fv[0], fv[1], fw[0], fw[1], beta[0], beta[1], i2, i2x, twox)
        assert got == ref, "VM ext-fold != reference (%s vs %s)" % (got, ref)
    bad_hint = False
    try:
        run_ext_fold(1, 2, 3, 4, 5, 6, (pow(2, P - 2, P) + 1) % P, pow(2, P - 2, P), 2)
    except VMError:
        bad_hint = True
    assert bad_hint, "tampered inv2 hint not rejected by the FRI fold (fail-open)"

    # --- HP3.6: runtime modexp + xpos (the verifier derives x = offset*omega^k itself) ---
    ocx = 0
    for _ in range(15):
        bse = rng.randrange(2, P); ex = rng.randrange(0, 1 << 14)
        got, _o = run_modexp(bse, ex)
        assert got == pow(bse, ex, P), "VM modexp != pow(base,exp,P)"
    metaP, TP = CT.ct_build_layout(pf["stmt"]["depth"])
    NP, oTP, oNP, offP, HdP, DdP, lastP = STK._setup(TP, pf["blowup"])
    for q in pf["queries"][:3]:
        kk2 = q["k"]
        gx, ocx = run_xpos(oNP, kk2, offP)
        assert gx == DdP[kk2], "VM xpos != Dd[k] (%d vs %d)" % (gx, DdP[kk2])

    # HP2 (Gap A): D-coset selector commitment -- the composition consumes the selectors as their
    # LDE on the FRI coset D (_pub_at_idx at index k), NOT the H-row domain; the shard opens this
    # coset commitment at the FS-derived k against a pinned root (fail-closed selector binding).
    layP = CT.ct_public_layout(metaP, TP)
    svP = STK._selector_vectors(layP, TP, NP, oTP, oNP, offP)
    dsc_root, dsc_tree, dsc_pre = build_selector_commitment_coset(svP, NP)
    kdc = pf["queries"][0]["k"]
    okdc, _ = run_merkle_verify_stack(dsc_pre[kdc], sm_path(dsc_tree, kdc), dsc_root, kdc)
    assert okdc, "VM D-coset selector opener rejected a valid opening"
    baddc = bytearray(dsc_pre[kdc]); baddc[0] ^= 1
    okdcb, _ = run_merkle_verify_stack(bytes(baddc), sm_path(dsc_tree, kdc), dsc_root, kdc)
    assert not okdcb, "VM accepted a tampered D-coset selector leaf (selector forgery not caught)"
    pub_k = STK._pub_at_idx(svP, kdc); vals_k = selector_row_values_coset(svP, kdc)
    assert (vals_k[0], vals_k[4], vals_k[8:8 + WIDTH]) == \
        (pub_k["is_full"] % P, pub_k["is_range"] % P, [r % P for r in pub_k["rc"]]), \
        "D-coset selector leaf inconsistent with the values the composition consumes (_pub_at_idx)"

    # HP2 (Gap B): the shard DERIVES the FRI fold betas + the query-index sequence from the full FS
    # transcript on-chain (verify:217-239), never trusting a witness beta/index (Frozen-Heart).
    from stark import FS as _FS
    tpb = bytes.fromhex(pf["tp_root"]); nonceb = bytes.fromhex(pf["nonce"])
    frs = [bytes.fromhex(r) for r in pf["fri_roots"]]; cmo = pf["stmt"]["cm_out"]
    nT = len(terms[0]["trans_a"]); nB = len(terms[0]["bound_a"]); nqp = pf["nq"]
    fsr = _FS(); fsr.absorb(tpb); fsr.absorb_int(pf["stmt"]["root"]); fsr.absorb_int(pf["stmt"]["nf"])
    for cm in cmo:
        fsr.absorb_int(cm)
    for _ in range(nT + nB):
        fsr.challenge(); fsr.challenge()
    fsr.absorb(b"fri"); betas_ref = []; sz = NP
    for fr in frs:
        fsr.absorb(fr)
        if sz <= 8:
            break
        betas_ref.append((fsr.challenge(), fsr.challenge())); sz //= 2
    fsr.absorb(nonceb); idxs_ref = [fsr.challenge_idx(NP) for _ in range(nqp)]
    assert betas_ref == [tuple(b) for b in pf["betas"]], "native FS transcript betas != proof betas"
    assert idxs_ref == [q["k"] for q in pf["queries"]], "native FS index sequence != proof queries"
    vmfs = VM(); vmfs.run(fs_transcript_prog(tpb, pf["stmt"]["root"], pf["stmt"]["nf"], cmo, frs,
                                             nonceb, NP, nT + nB, nqp))
    assert vmfs.s[-1] == fsr.s, "VM FS transcript state != native FS"
    fbase = 2 * (nT + nB)
    for i, (b0, b1) in enumerate(betas_ref):
        assert decode_num(vmfs.s[fbase + 2 * i]) == b0 and decode_num(vmfs.s[fbase + 2 * i + 1]) == b1, \
            "VM FS derived beta[%d] != native" % i
    ibase = fbase + 2 * len(betas_ref)
    for i, kref in enumerate(idxs_ref):
        assert decode_num(vmfs.s[ibase + i]) == kref, "VM FS derived query index[%d] != native" % i

    # HP4 FS-INPUT (deploy covenant's first, soundness-critical input) on the DEPLOY fold-8 path: fs_input_prog
    # reproduces verify()'s transcript reading statement/roots FROM the committed HP2.4 blob (absorb==commit
    # Frozen-Heart), draws alphas/betas/idx, grinds the WITNESS nonce, and proves derived == committed
    # (recompute-binding). A dedicated fold-8+grind proof exercises the load-bearing fold_step>1 loop (s betas
    # per round, s shrinking 3->2->1 -> subsumes the fold-2 tail; self_test's pf is fold-2). The committed
    # fs_out is the fold-8 FS derivation (fs_transcript_prog fold_step=3, grind state-transparent). unlock =
    # [nonce, blob]; honest -> accept, a tampered committed alpha / statement root / nonce -> reject.
    pfi = STK.prove(CT._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=3, fold_step=3, seed=0xF54A)
    assert STK.verify(pfi)[0], "dedicated fold-8 FS-input proof did not verify"
    si = pfi["stmt"]; meta_i, T_i = STK.ct_build_layout(si["depth"]); N_i = STK._setup(T_i, pfi["blowup"])[0]
    ne_i = STK.ct_num_transition_residuals() + len(STK.ct_boundary_constraints(meta_i, si))
    tp_i = bytes.fromhex(pfi["tp_root"]); nonce_i = bytes.fromhex(pfi["nonce"])
    fri_i = [bytes.fromhex(r) for r in pfi["fri_roots"]]; nq_i = pfi["nq"]
    vmi8 = VM(); vmi8.run(fs_transcript_prog(tp_i, si["root"], si["nf"], si["cm_out"], fri_i, nonce_i,
                                             N_i, ne_i, nq_i, fold_step=3))   # derive the fold-8 fs_out
    M_i = 2 * ne_i + 2 * _folds_to_final(N_i) + nq_i
    out_i = [decode_num(vmi8.s[i]) % P for i in range(M_i)]
    blob_i = enc8(si["root"] % P) + enc8(si["nf"] % P)
    for cm in si["cm_out"]:
        blob_i += enc8(cm % P)
    blob_i += tp_i
    for fr in fri_i:
        blob_i += fr
    for v in out_i:
        blob_i += enc8(v)
    prog_i = fs_input_prog(N_i, ne_i, nq_i, len(si["cm_out"]), len(fri_i), 3, pfi["grind_b"])

    def _run_fs_input(nonce_b, blob_b):
        vmi = VM()
        try:
            vmi.run([PUSH(nonce_b), PUSH(blob_b)] + prog_i)
        except (VMError, IndexError):
            return False
        return len(vmi.s) == 1 and vmi.s[-1] not in (b"", b"\x00")

    assert _run_fs_input(nonce_i, blob_i), "fold-8 FS-input rejected an honest [nonce, blob] (transcript-from-blob)"
    fi_aoff = 8 + 8 + 8 * len(si["cm_out"]) + 32 + 32 * len(fri_i)   # start of the committed alphas in the blob
    fi_bad_a = bytearray(blob_i)
    fi_a0 = int.from_bytes(fi_bad_a[fi_aoff:fi_aoff + 8], "little")
    fi_bad_a[fi_aoff:fi_aoff + 8] = enc8((fi_a0 + 1) % P)
    assert not _run_fs_input(nonce_i, bytes(fi_bad_a)), \
        "fold-8 FS-input accepted a tampered committed alpha (recompute-binding broken)"
    fi_bad_r = bytearray(blob_i)
    fi_r0 = int.from_bytes(fi_bad_r[0:8], "little")
    fi_bad_r[0:8] = enc8((fi_r0 + 1) % P)
    assert not _run_fs_input(nonce_i, bytes(fi_bad_r)), \
        "fold-8 FS-input accepted a tampered committed statement root (absorb==commit Frozen-Heart broken)"
    fi_bad_n = bytes([nonce_i[0] ^ 0xFF]) + nonce_i[1:]
    assert not _run_fs_input(fi_bad_n, blob_i), \
        "fold-8 FS-input accepted a tampered nonce (grind PoW gate broken)"
    assert not _run_fs_input(nonce_i + b"\x00", blob_i), \
        "fold-8 FS-input accepted a length-padded (9-byte) nonce (nonce-length pin broken -- push malleability)"

    # HP11 DEEP FS-INPUT (deep=True): the deploy FS covenant reproduces prove()'s DEEP transcript. Blob prefix
    # gains comp_root(32) | z*g(16) | mask_block(16*n_terms) after the fri_roots; fs_out gains z(16) + deep_alphas
    # (16*n_terms) between the alphas and the betas. The redeem absorbs comp_root after the AIR-alphas, draws z
    # (z[1] forced != 0), BINDS committed z*g == oT*z (fail-closed, not absorbed), absorbs the masks, draws the
    # deep_alphas, then the recompute-binding proves derived z + deep_alphas == committed. REAL deep proof, no mock.
    pfd = STK.prove(CT._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=3, fold_step=3, deep=True, seed=0xF54A)
    assert pfd.get("deep") and STK.verify(pfd)[0], "dedicated DEEP FS-input proof did not verify"
    sd = pfd["stmt"]; nod = len(sd["cm_out"]); meta_d, T_d = STK.ct_build_layout(sd["depth"])
    Nd, oTd = STK._setup(T_d, pfd["blowup"])[:2]
    ned = STK.ct_num_transition_residuals() + len(STK.ct_boundary_constraints(meta_d, sd))
    tpd = bytes.fromhex(pfd["tp_root"]); nonced = bytes.fromhex(pfd["nonce"])
    frid = [bytes.fromhex(r) for r in pfd["fri_roots"]]; nrd = len(frid); nqd = pfd["nq"]
    crd = bytes.fromhex(pfd["comp_root"])
    masksd = []
    for _c in STK.FLAT_COLS:
        masksd.append((pfd["Pcz"][_c][0], pfd["Pcz"][_c][1])); masksd.append((pfd["Pczg"][_c][0], pfd["Pczg"][_c][1]))
    for _m in pfd["sel_z"]:
        masksd.append((_m[0], _m[1]))
    masksd.append((pfd["rw_zg"][0], pfd["rw_zg"][1])); masksd.append((pfd["comp_z"][0], pfd["comp_z"][1]))
    ntd = len(masksd)
    vmtd = VM(); vmtd.run(fs_transcript_prog(tpd, sd["root"], sd["nf"], sd["cm_out"], frid, nonced, Nd, ned, nqd,
                                             fold_step=3, deep=True, comp_root=crd, masks=masksd))
    Md = 2 * ned + (2 + 2 * ntd) + 2 * _folds_to_final(Nd) + nqd
    outd = [decode_num(vmtd.s[i]) % P for i in range(Md)]
    prefd = enc8(sd["root"] % P) + enc8(sd["nf"] % P)
    for cm in sd["cm_out"]:
        prefd += enc8(cm % P)
    prefd += tpd
    for fr in frid:
        prefd += fr
    prefd += crd + enc8(pfd["zg"][0]) + enc8(pfd["zg"][1])
    for _m0, _m1 in masksd:
        prefd += enc8(_m0) + enc8(_m1)
    blobd = prefd + b"".join(enc8(v) for v in outd)
    progd = fs_input_prog(Nd, ned, nqd, nod, nrd, 3, pfd["grind_b"], deep=True, n_terms=ntd, oT=oTd)

    def _run_deep(nb, bb):
        vm = VM()
        try:
            vm.run([PUSH(nb), PUSH(bb)] + progd)
        except (VMError, IndexError):
            return False
        return len(vm.s) == 1 and vm.s[-1] not in (b"", b"\x00")

    assert _run_deep(nonced, blobd), "HP11 DEEP FS-input rejected an honest [nonce, blob]"
    _crd_off = 48 + 8 * nod + 32 * nrd; _zgd_off = _crd_off + 32; _maskd_off = _zgd_off + 16; _fsd_off = len(prefd)

    def _flip_d(base, off):
        bb = bytearray(base); bb[off] ^= 0x01; return bytes(bb)

    assert not _run_deep(nonced, _flip_d(blobd, _crd_off)), "HP11: tampered comp_root accepted (absorb==commit broken)"
    assert not _run_deep(nonced, _flip_d(blobd, _zgd_off)), "HP11.4: tampered z*g accepted (z*g==oT*z bind broken)"
    assert not _run_deep(nonced, _flip_d(blobd, _zgd_off + 8)), "HP11.4: tampered z*g[1] accepted (bind broken)"
    assert not _run_deep(nonced, _flip_d(blobd, _maskd_off)), "HP11.5: tampered mask accepted (absorb==commit broken)"
    assert not _run_deep(nonced, _flip_d(blobd, _fsd_off + 8 * (2 * ned))), \
        "HP11.7: tampered committed z accepted (recompute-binding broken)"
    assert not _run_deep(nonced, _flip_d(blobd, _fsd_off + 8 * (2 * ned + 2))), \
        "HP11.7: tampered committed deep_alpha accepted (recompute-binding broken)"
    assert not _run_deep(nonced, _flip_d(blobd, _fsd_off)), "HP11: tampered committed alpha accepted (regression)"
    # HP11.8/HP17 length attacks on the counter-free extract, all caught by the fs_out size pin (SIZE == 8*M):
    # back-padding (extra tail cell), truncation (missing cell), AND front-padding -- the HP17 Frozen-Heart attack:
    # M attacker cells followed by M correct derived copies. Without the pin the drain-to-empty extract + DEPTH==0
    # bind would ACCEPT it (binding only the top M correct copies, leaving the attacker's front cells -- which the
    # cross-input consumers read front-aligned -- unbound). The size pin rejects all three, fail-closed.
    _fs_len = len(blobd) - _fsd_off                                       # honest fs_out byte length = 8*M
    assert not _run_deep(nonced, blobd + b"\x00" * 8), "HP11.8: back-padded fs_out accepted (size pin broken)"
    assert not _run_deep(nonced, blobd[:-8]), "HP11.8: truncated fs_out accepted (size pin broken)"
    assert not _run_deep(nonced, blobd[:_fsd_off] + b"\x00" * _fs_len + blobd[_fsd_off:]), \
        "HP11.8/HP17: FRONT-padded fs_out accepted -- attacker front challenges left unbound (Frozen-Heart); size pin must reject"
    _nbd = _prog_nbytes(progd)
    assert _nbd <= 10000, "HP11.8: fs_input(deep) demo %dB must be <=10000B (consensus cap)" % _nbd
    assert _nbd <= 1650, "HP11.8-thin: fs_input(deep) demo %dB must be <=1650B (the thin-shard target)" % _nbd
    print("HP11 DEEP FS-input (comp_root/z*g/masks absorbed, z+deep_alphas recompute-bound, z*g==oT*z fail-closed):")
    print("  OK -- honest accept; forged comp_root / z*g / mask / committed z / deep_alpha / alpha all REJECT. "
          "n_terms=%d." % ntd)
    print("  program = %d bytes (demo, HP11.8-thin: the deep_alpha draws + mask-absorb + committed-value-extract + "
          "recompute-bind are ALL counter-free BEGIN/UNTIL loops == unrolled; 10728B -> 5031B -> %dB) -> under the "
          "<=1650B THIN-SHARD target (not just the <=10000B consensus cap). The mask-absorb drains the 16*n_terms "
          "block non-destructively extracted onto MAIN (no alt-offset tracking), so all DEEP blocks are O(1) in the "
          "redeem and stay thin at deploy scale as betas/queries/n_terms grow." % (_nbd, _nbd))

    # HP5 OPENER core (single trace leaf open + commit + index-bind): open the trace row at the committed k
    # against tp_root, prove the committed cells == the opened leaf (5.3 blob==split) and that it was opened at
    # exactly the committed k (5.4 k==open-idx). Uses the real proof's query-0 trace opening (ck, salt sk, path
    # pk) -> real cashvm, no mocks. First reconstruct the trace preimage and CONFIRM it is a valid opening via
    # the already-validated opener (self-checks the leaf format = salt || concat(enc(cell)) over FLAT_COLS).
    oc_q0 = pf["queries"][0]; oc_kq = oc_q0["k"]
    oc_salt = bytes.fromhex(oc_q0["sk"])
    oc_cells = [oc_q0["ck"][c] % P for c in STK.FLAT_COLS]
    oc_pre = oc_salt + b"".join(enc8(v) for v in oc_cells)
    oc_path = [(bytes.fromhex(sh), b) for sh, b in oc_q0["pk"]]
    oc_sibs = [s for s, _ in oc_path]
    oc_ncell = len(STK.FLAT_COLS); oc_pfx = len(oc_salt)
    assert run_merkle_verify_stack(oc_pre, oc_path, tpb, oc_kq)[0], \
        "reconstructed trace preimage/path is not a valid opening (leaf format wrong)"
    oc_blob = b"".join(enc8(v) for v in oc_cells) + enc8(oc_kq)
    oc_prog = opener_commit_prog(len(oc_path), oc_ncell, oc_pfx)

    def _run_opener(root_b, sibs_b, pre_b, blob_b):
        vmo = VM()
        try:
            vmo.run([PUSH(root_b)] + [PUSH(s) for s in reversed(sibs_b)]
                    + [PUSH(pre_b), PUSH(blob_b)] + oc_prog)
        except (VMError, IndexError):
            return False
        return len(vmo.s) == 1 and vmo.s[-1] not in (b"", b"\x00")

    assert _run_opener(tpb, oc_sibs, oc_pre, oc_blob), "OPENER rejected an honest trace-leaf open+commit"
    oc_badc = bytearray(oc_blob)                              # tamper a committed cell -> opened != committed
    oc_c0 = int.from_bytes(oc_badc[0:8], "little"); oc_badc[0:8] = enc8((oc_c0 + 1) % P)
    assert not _run_opener(tpb, oc_sibs, oc_pre, bytes(oc_badc)), \
        "OPENER accepted a tampered committed cell (blob != opened preimage, 5.3 broken)"
    oc_badcl = bytearray(oc_blob)                            # tamper the LAST committed cell (LIFO coverage)
    oc_loff = (oc_ncell - 1) * 8; oc_cl = int.from_bytes(oc_badcl[oc_loff:oc_loff + 8], "little")
    oc_badcl[oc_loff:oc_loff + 8] = enc8((oc_cl + 1) % P)
    assert not _run_opener(tpb, oc_sibs, oc_pre, bytes(oc_badcl)), \
        "OPENER accepted a tampered last committed cell (blob != opened preimage, 5.3 broken)"
    oc_badk = bytearray(oc_blob); oc_koff = oc_ncell * 8      # tamper committed k -> opened at wrong index
    oc_badk[oc_koff:oc_koff + 8] = enc8((oc_kq + 1) % P)
    assert not _run_opener(tpb, oc_sibs, oc_pre, bytes(oc_badk)), \
        "OPENER accepted a tampered committed k (opened at wrong index, 5.4 broken)"
    oc_bads = [bytearray(s) for s in oc_sibs]; oc_bads[0][0] ^= 1   # tamper a sibling -> forged path
    assert not _run_opener(tpb, [bytes(s) for s in oc_bads], oc_pre, oc_blob), \
        "OPENER accepted a tampered Merkle sibling (forged path)"

    # ---- BYTE REDUCTION LEVER N3: truncated-hash Merkle verify. The FRI/opener
    # trees may hash n-byte nodes (config MERKLE_HASH_BYTES; collision-resistance = n*4 bit, guarded >=100-bit in
    # native_ct_air_config) so every sibling shrinks 33B -> n+1 B, security-neutral (a truncated tree is as binding as a
    # full one down to its collision-resistance). Validate the DEPLOYABLE verifier at the N3 target width 26B (=104-bit,
    # matching the SECURITY_BITS query term): a truncated tree opens+accepts, a forged sibling rejects fail-closed, nodes
    # are 26B. trunc=0 (all current callers) stays BYTE-IDENTICAL (no SPLIT emitted). Prover-pipeline integration + the
    # config flip that realizes the whole-tx bytes is HP11, co-designed with the FS-blob/root layout (HP6).
    assert merkle_verify_stack_prog(5, trunc=0) == merkle_verify_stack_prog(5), \
        "N3: trunc=0 must be byte-identical to the pre-N3 program (current callers unchanged)"
    n3_W = 26                                                   # N3 target: 2*lambda/8 = 26B -> 104-bit collision-resistance
    def _n3_htr(b): return SHA(b)[:n3_W]                        # truncated node hash (mirrors stark.Hf at n3_W)
    n3_D = 13; n3_N = 1 << n3_D; n3_k = 12345 % n3_N
    n3_cells = [(i * 7 + 3) % P for i in range(len(STK.FLAT_COLS))]
    n3_pre = b"".join(enc8(c) for c in n3_cells)
    n3_leaves = [_n3_htr(b"\x07" * (8 * len(n3_cells)) + enc8(i)) for i in range(n3_N)]
    n3_leaves[n3_k] = _n3_htr(n3_pre)
    n3_layer = n3_leaves[:]; n3_tree = [n3_layer]               # truncated-hash Merkle tree (mirrors stark.merkle at n3_W)
    while len(n3_layer) > 1:
        if len(n3_layer) % 2: n3_layer = n3_layer + [n3_layer[-1]]
        n3_layer = [_n3_htr(n3_layer[i] + n3_layer[i + 1]) for i in range(0, len(n3_layer), 2)]
        n3_tree.append(n3_layer)
    n3_root = n3_tree[-1][0]; n3_path = []; n3_i = n3_k
    for n3_d in range(len(n3_tree) - 1):
        n3_lay = n3_tree[n3_d]; n3_j = n3_i ^ 1
        if n3_j >= len(n3_lay): n3_j = n3_i
        n3_path.append((n3_lay[n3_j], n3_i & 1)); n3_i //= 2
    n3_sibs = [s for s, _ in n3_path]

    def _run_n3(sibs):
        n3_vm = VM()
        try:
            n3_vm.run([PUSH(n3_root)] + [PUSH(s) for s in reversed(sibs)] + [PUSH(n3_pre), NUM(n3_k)]
                      + merkle_verify_stack_prog(n3_D, trunc=n3_W) + [NUM(1)])
        except (VMError, IndexError):
            return False
        return len(n3_vm.s) == 1 and n3_vm.s[-1] not in (b"", b"\x00")

    assert _run_n3(n3_sibs), "N3: truncated-hash (%dB) Merkle verify rejected an honest opening" % n3_W
    n3_badsib = [bytearray(s) for s in n3_sibs]; n3_badsib[0][0] ^= 1
    assert not _run_n3([bytes(s) for s in n3_badsib]), \
        "N3: truncated-hash Merkle verify accepted a FORGED sibling (fail-open, soundness broken)"
    assert all(len(s) == n3_W for s in n3_sibs) and len(n3_root) == n3_W, \
        "N3: truncated node width != %dB (byte saving not realized)" % n3_W
    print("HP11/N3 truncated-hash Merkle verify (%dB=%d-bit CR): honest accept + forged-reject fail-closed, node %dB<33B: OK"
          % (n3_W, n3_W * 4, n3_W + 1))

    # N3 also carries through the DEPLOYABLE looped opener (looped_opener_from_blob_prog -> _opener_from_blob_body ->
    # merkle_verify_stack_prog). Validate the full from-blob opener at 26B: 2 openings on a truncated tree accept, a
    # forged cell (derived preimage mismatch) rejects fail-closed. Confirms the whole deploy opener path is N3-capable.
    n3l_D = 10; n3l_N = 1 << n3l_D; n3l_nc = 4
    n3l_base = [b"\x05" * (8 * n3l_nc) for _ in range(n3l_N)]
    n3l_spec = []
    for _o in range(2):
        _kk = (_o * 137 + 11) % n3l_N
        _cc = [(i * 9 + 2 + _o) % P for i in range(n3l_nc)]
        n3l_base[_kk] = b"".join(enc8(c) for c in _cc)
        n3l_spec.append((_kk, _cc))
    n3l_layer = [_n3_htr(pre) for pre in n3l_base]; n3l_tree = [n3l_layer]   # truncated tree, leaf = trunc(SHA(cells))
    while len(n3l_layer) > 1:
        if len(n3l_layer) % 2: n3l_layer = n3l_layer + [n3l_layer[-1]]
        n3l_layer = [_n3_htr(n3l_layer[i] + n3l_layer[i + 1]) for i in range(0, len(n3l_layer), 2)]
        n3l_tree.append(n3l_layer)
    n3l_root = n3l_tree[-1][0]

    def _n3l_path(idx):
        p = []; i = idx
        for d in range(len(n3l_tree) - 1):
            lay = n3l_tree[d]; j = i ^ 1
            if j >= len(lay): j = i
            p.append((lay[j], i & 1)); i //= 2
        return p

    n3l_opens = [(n3l_root, _n3l_path(_kk), b"", _cc, _kk) for (_kk, _cc) in n3l_spec]
    assert run_looped_opener_from_blob(n3l_opens, n3l_D, n3l_nc, len(n3l_opens), 0, trunc=n3_W), \
        "N3: truncated-hash looped DEPLOY opener rejected honest openings"
    n3l_forge = [(n3l_root, _n3l_path(_kk), b"", ([(c + 1) % P for c in _cc] if _i == 0 else _cc), _kk)
                 for _i, (_kk, _cc) in enumerate(n3l_spec)]
    assert not run_looped_opener_from_blob(n3l_forge, n3l_D, n3l_nc, len(n3l_opens), 0, trunc=n3_W), \
        "N3: truncated-hash looped DEPLOY opener accepted a FORGED cell (fail-open, soundness broken)"
    print("HP11/N3 truncated-hash DEPLOY opener (looped_opener_from_blob, %dB nodes): openings accept + forged-cell reject: OK" % n3_W)

    # N3 through the RETAINING opener (merkle_verify_retain_prog -> used by the FRI coset opener fri_coset_open_fold_prog
    # + the trace/selector openers): the same truncated tree opens and RETAINS the preimage; split recovers the exact
    # cells; a forged sibling rejects fail-closed. Confirms the retain-based (FRI + trace/sel) opener surface is N3-capable.
    n3r_vm = VM()
    n3r_vm.run([PUSH(n3_root)] + [PUSH(s) for s in reversed(n3_sibs)] + [PUSH(n3_pre), NUM(n3_k)]
               + merkle_verify_retain_prog(n3_D, trunc=n3_W) + split_cells_prog(len(n3_cells)))
    assert [decode_num(v) for v in n3r_vm.s] == n3_cells, \
        "N3: retain+split of a truncated-hash leaf != cells (retain opener broken under truncation)"
    n3r_bad = True
    try:
        n3r_bs = [bytearray(s) for s in n3_sibs]; n3r_bs[0][0] ^= 1
        VM().run([PUSH(n3_root)] + [PUSH(bytes(s)) for s in reversed(n3r_bs)] + [PUSH(n3_pre), NUM(n3_k)]
                 + merkle_verify_retain_prog(n3_D, trunc=n3_W) + split_cells_prog(len(n3_cells)))
    except VMError:
        n3r_bad = False
    assert not n3r_bad, "N3: retaining opener accepted a forged sibling under truncation (fail-open)"
    print("HP11/N3 truncated-hash RETAIN opener (merkle_verify_retain_prog, FRI-coset + trace/sel path): retain+split + forged-reject: OK")

    # HP5.2 second trace leaf: the same opener_commit_prog opens trace@kn = (k + shift) % N (the query's paired
    # row cn/sn/pn) -- opener_commit_prog is index-agnostic (opens at the committed index), so the new thing is
    # the kn DERIVATION shift = N // T (config-baked): the deploy binds the second leaf's index to the first
    # (kn is not free witness). The run_merkle_verify_stack precondition self-checks the derivation (a wrong
    # shift opens at the wrong index and the path fails -> fail-loud, no guessed value).
    oc_shift = NP // TP; oc_kn = (oc_kq + oc_shift) % NP
    oc_saltn = bytes.fromhex(oc_q0["sn"])
    oc_cellsn = [oc_q0["cn"][c] % P for c in STK.FLAT_COLS]
    oc_pren = oc_saltn + b"".join(enc8(v) for v in oc_cellsn)
    oc_pathn = [(bytes.fromhex(sh), b) for sh, b in oc_q0["pn"]]
    oc_sibsn = [s for s, _ in oc_pathn]
    assert run_merkle_verify_stack(oc_pren, oc_pathn, tpb, oc_kn)[0], \
        "trace@kn=(k+shift)%N reconstruction is not a valid opening (kn derivation shift=N//T or leaf format wrong)"
    oc_blobn = b"".join(enc8(v) for v in oc_cellsn) + enc8(oc_kn)
    oc_progn = opener_commit_prog(len(oc_pathn), len(STK.FLAT_COLS), len(oc_saltn))

    def _run_opener_n(blob_b):
        vmn = VM()
        try:
            vmn.run([PUSH(tpb)] + [PUSH(s) for s in reversed(oc_sibsn)]
                    + [PUSH(oc_pren), PUSH(blob_b)] + oc_progn)
        except (VMError, IndexError):
            return False
        return len(vmn.s) == 1 and vmn.s[-1] not in (b"", b"\x00")

    assert _run_opener_n(oc_blobn), "OPENER rejected an honest trace@kn open+commit (paired row)"
    oc_badkn = bytearray(oc_blobn); oc_knoff = len(STK.FLAT_COLS) * 8
    oc_badkn[oc_knoff:oc_knoff + 8] = enc8((oc_kn + 1) % P)
    assert not _run_opener_n(bytes(oc_badkn)), \
        "OPENER accepted a tampered committed kn (opened at wrong paired index)"

    # HP5.2 selector leaf: the SAME opener_commit_prog opens the D-coset SELECTOR at k against sel_root
    # (dsc_root) -> the opener is generic across ALL leaf types a slot opens (trace@k, trace@kn, selector). The
    # selector is PUBLIC (unsalted, prefix=0), unlike the salted private trace; reuses the D-coset commitment
    # (dsc_root/dsc_tree/dsc_pre) built above. Confirms opener_commit_prog needs no per-leaf-type special case.
    oc_dpath = sm_path(dsc_tree, kdc)                        # sm_path returns [(sib_bytes, bit)] (not hex)
    oc_selc = selector_row_values_coset(svP, kdc)
    oc_selpre = dsc_pre[kdc]
    oc_selsibs = [sh for sh, _ in oc_dpath]
    assert run_merkle_verify_stack(oc_selpre, oc_dpath, dsc_root, kdc)[0], \
        "selector D-coset reconstruction is not a valid opening"
    oc_selblob = b"".join(enc8(v % P) for v in oc_selc) + enc8(kdc)
    oc_selprog = opener_commit_prog(len(oc_dpath), len(oc_selc), 0)

    def _run_opener_sel(blob_b):
        vms = VM()
        try:
            vms.run([PUSH(dsc_root)] + [PUSH(s) for s in reversed(oc_selsibs)]
                    + [PUSH(oc_selpre), PUSH(blob_b)] + oc_selprog)
        except (VMError, IndexError):
            return False
        return len(vms.s) == 1 and vms.s[-1] not in (b"", b"\x00")

    assert _run_opener_sel(oc_selblob), "OPENER rejected an honest selector open+commit"
    oc_selbad = bytearray(oc_selblob); oc_sv0 = int.from_bytes(oc_selbad[0:8], "little")
    oc_selbad[0:8] = enc8((oc_sv0 + 1) % P)
    assert not _run_opener_sel(bytes(oc_selbad)), "OPENER accepted a tampered committed selector cell"

    # HP2 (2.8-2.11): derive x=Dd[k] (xpos, HP3.6) then the hint-validated normalizers ZHx_inv,
    # qf_trans, bound_invX the composition needs -- a prover cannot supply favourable normalizers.
    kqi = pf["queries"][0]["k"]; xq = DdP[kqi]
    zhinv = pow((pow(xq, TP, P) - 1) % P, P - 2, P)
    bcons = STK.ct_boundary_constraints(metaP, pf["stmt"])
    hd_vals = [HdP[row] for row, _f in bcons]
    qbvals, _ = run_qf_bound(xq, TP, lastP, zhinv, hd_vals, terms[0]["bound_invX"])
    assert qbvals[0] == terms[0]["qf_trans"] % P, "VM qf_trans != verify qf_trans"
    assert qbvals[1:] == [b % P for b in terms[0]["bound_invX"]], "VM bound_invX != verify bound_invX"
    bad_qb = True
    try:
        run_qf_bound(xq, TP, lastP, (zhinv + 1) % P, hd_vals, terms[0]["bound_invX"])
    except VMError:
        bad_qb = False
    assert not bad_qb, "VM accepted a wrong Z_H(x)^-1 hint (inverse not enforced fail-closed)"

    # HP2 (2.12/2.14): the retaining opener leaves the opened preimage; split_cells_prog extracts the
    # field cells the residuals/composition consume. Validate on the D-coset selector leaf (33 cells).
    dpath = sm_path(dsc_tree, kdc); ncell = len(selector_row_values_coset(svP, kdc))
    vmrs = VM()
    vmrs.run(merkle_verify_stack_unlock(dsc_pre[kdc], dpath, dsc_root, kdc)
             + merkle_verify_retain_prog(len(dpath)) + split_cells_prog(ncell))
    assert [decode_num(v) for v in vmrs.s] == selector_row_values_coset(svP, kdc), \
        "retain+split of the D-coset selector leaf != selector_row_values_coset"
    badrs = bytearray(dsc_pre[kdc]); badrs[0] ^= 1
    okrs = True
    try:
        VM().run(merkle_verify_stack_unlock(bytes(badrs), dpath, dsc_root, kdc)
                 + merkle_verify_retain_prog(len(dpath)) + split_cells_prog(ncell))
    except VMError:
        okrs = False
    assert not okrs, "retaining opener accepted a tampered leaf (not fail-closed)"

    # --- HP3.12: Fiat-Shamir transcript recomputation matches native FS (Frozen-Heart) ---
    from stark import FS as _FS
    tp = bytes.fromhex(pf["tp_root"])
    fsn = _FS(); fsn.absorb(tp); fsn.absorb_int(pf["stmt"]["root"]); fsn.absorb_int(pf["stmt"]["nf"])
    for cm in pf["stmt"]["cm_out"]:
        fsn.absorb_int(cm)
    nat_ch = [fsn.challenge() for _ in range(4)]
    nat_state = fsn.s
    prog = [PUSH(b"STARK-v0")] + fs_absorb_tokens(tp)
    prog += fs_absorb_tokens(enc8(pf["stmt"]["root"] % P)) + fs_absorb_tokens(enc8(pf["stmt"]["nf"] % P))
    for cm in pf["stmt"]["cm_out"]:
        prog += fs_absorb_tokens(enc8(cm % P))
    for _ in range(4):
        prog += fs_challenge_tokens()
    vm = VM(); vm.run(prog); ocfs = vm.op_cost
    assert vm.s[-1] == nat_state, "VM FS transcript state != native FS"
    assert [decode_num(vm.s[i]) for i in range(-5, -1)] == nat_ch, "VM FS challenges != native FS"
    # the query-index derivation matches FS.challenge_idx (verifier binds k itself, HP3.4)
    fsi = _FS(); fsi.absorb(tp); nat_idx = fsi.challenge_idx(NP)
    vm2 = VM(); vm2.run([PUSH(b"STARK-v0")] + fs_absorb_tokens(tp) + fs_idx_tokens(NP))
    assert decode_num(vm2.s[-2]) == nat_idx, "VM FS query index != native challenge_idx"

    # --- HP3.9: grinding (proof-of-work) check on the BCH-VM ---
    from stark import grind as _grind
    s_pre = SHA(b"grind-test-transcript-state")
    gb = 8; target_g = 1 << (64 - gb)
    nonce_ok = _grind(s_pre, gb)                       # real PoW nonce (stark.grind)
    vmg = VM(); vmg.run([PUSH(s_pre)] + grind_check_tokens(nonce_ok, gb)); ocg = vmg.op_cost
    assert len(vmg.s) == 1 and vmg.s[-1] == SHA(s_pre + nonce_ok), "grind state != SHA256(s+nonce)"
    bad_nonce = None
    for i in range(100000):
        cand = i.to_bytes(8, "little")
        if int.from_bytes(SHA(s_pre + cand)[:8], "little") >= target_g:
            bad_nonce = cand; break
    assert bad_nonce is not None, "could not find a PoW-failing nonce"
    grind_rejected = False
    try:
        VM().run([PUSH(s_pre)] + grind_check_tokens(bad_nonce, gb))
    except VMError:
        grind_rejected = True
    assert grind_rejected, "grind accepted a nonce failing the PoW (fail-open)"

    # --- HP3.5b/3.5c: the FULL per-query FRI fold chain on the BCH-VM ---
    import copy
    fris = STK.query_fri_terms(pf)
    ocfc = 0
    for qf in fris[:2]:
        okfc, ocfc = run_fri_chain(qf, qf["comp_x"])
        assert okfc, "VM FRI fold chain rejected a valid query (k=%d)" % qf["k"]
    qbad = copy.deepcopy(fris[0])
    L0 = qbad["layers"][0]; L0["v"] = ((L0["v"][0] + 1) % P, L0["v"][1])
    okb2, _ = run_fri_chain(qbad, qbad["comp_x"])
    assert not okb2, "VM FRI fold chain accepted a tampered FRI layer value"
    # tamper the composition target -> layer-0 AIR<->FRI binding fails
    qbad2 = copy.deepcopy(fris[0])
    okb3, _ = run_fri_chain(qbad2, ((qbad2["comp_x"][0] + 1) % P, qbad2["comp_x"][1]))
    assert not okb3, "VM FRI chain accepted a composition value != FRI layer-0"

    # --- HP1: assembled compose->FRI seam (compose flows on-stack into the FRI layer-0 binding) ---
    for ti, qfa in zip(terms, fris):                       # index-aligned: same query per position
        oka, _ = run_assemble_compose_fri(ti, qfa)
        assert oka, "VM assembled compose->FRI rejected a valid query"
    tbad = dict(terms[0]); tvb = list(tbad["trans_v"]); tvb[0] = (tvb[0] + 1) % P
    tbad["trans_v"] = tvb                                  # tamper a transition residual
    okab, _ = run_assemble_compose_fri(tbad, fris[0])
    assert not okab, "VM assembled compose->FRI accepted a tampered composition"
    return True, (oc, ocs, ocr, occ, oce, occ5, ocm, ocf, ocx, ocfs, ocg, ocfc)


if __name__ == "__main__":
    ok, (oc_sbox, oc_state, oc_range, oc_cons, oc_ext, oc_comp, oc_merkle, oc_fold,
         oc_xpos, oc_fs, oc_grind, oc_frichain) = self_test()
    print("HP2.1 Poseidon2 x^7 S-box constraint on the BCH-VM (cashvm tokens): %s"
          % ("OK" if ok else "FAIL"))
    print("  VM residuals == reference (50 random) ; real Poseidon2 round -> 0 ; aux tamper -> != 0 ;")
    print("  selector gate=0 neutralizes (membership_comp shape). one S-box lane op_cost = %d" % oc_sbox)
    print("HP2.2 Poseidon2 linear-layer state-update residual (12x12 MDS / diag+sum): OK")
    print("  VM == reference (20 random) ; full round (M_EXT.y) + partial round (int(y)) -> 0 ;")
    print("  next-state tamper -> != 0. one state lane op_cost = %d" % oc_state)
    print("HP2.4 range (Num2Bits poly-form: booleanity+acc-recomp+value-const+acc==value): OK")
    print("  VM == reference (20 random) ; real range block -> 0 ; bit tamper -> != 0. op_cost = %d" % oc_range)
    print("HP2.4b conservation (vh_in == vh_o0+vh_o1+vh_fee, A1 wrap-safe): OK")
    print("  VM == reference (20 random) ; balanced -> 0 ; tamper -> != 0. op_cost = %d" % oc_cons)
    print("GF(p^2) Karatsuba ext-mul on the BCH-VM (u^2-%d, for the FRI fold HP3.5): OK" % EXT_W)
    print("  VM == native_gf_p2.mul (30 random) ; u*u == W. op_cost = %d" % oc_ext)
    print("HP2.5 full per-query CT-AIR composition (GF(p^2) comp == verify comp_x): OK")
    print("  VM comp == native_ct_air_stark.verify comp_x (real queries) ; residual tamper -> change ;")
    print("  reproduced proof verifies (comp_x == FRI layer-0). op_cost = %d" % oc_comp)
    print("HP2.3 selector commitment (pinned SHA256-Merkle root) + opening on the BCH-VM: OK")
    print("  valid open accepts ; tampered selector leaf / wrong root rejected (fail-closed) ;")
    print("  committed leaf == public layout. Merkle-path op_cost = %d (reused: trace/FRI opens)" % oc_merkle)
    print("HP3.5 GF(p^2) FRI fold step on the BCH-VM (hint-validated inverses): OK")
    print("  VM fold == native_gf_p2 reference (20 random) ; tampered inv2 hint rejected. op_cost = %d" % oc_fold)
    print("HP3.6 runtime modexp + xpos (verifier derives x = offset*omega^k itself): OK")
    print("  VM modexp == pow (15 random) ; xpos == Dd[k] from the real STARK setup. op_cost = %d" % oc_xpos)
    print("HP3.12 Fiat-Shamir transcript recomputation on the BCH-VM (Frozen-Heart-safe): OK")
    print("  VM transcript state + challenges + query index == native stark.FS (real proof). op_cost = %d" % oc_fs)
    print("HP3.9 grinding (proof-of-work) check on the BCH-VM: OK")
    print("  real PoW nonce accepts + advances transcript ; PoW-failing nonce rejected. op_cost = %d" % oc_grind)
    print("HP3.5b/3.5c full per-query FRI fold chain on the BCH-VM: OK")
    print("  valid query accepts (opens + folds + comp<->FRI binding + final) ; tampered FRI value /")
    print("  composition value rejected (fail-closed). full-chain op_cost = %d" % oc_frichain)
