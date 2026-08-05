"""Config parametrized DEEP-ALI verifier transaction builder.

An importable, config parametrized, self tested builder that wires the imported programs from native_ct_shard into a
multi input P2SH32 transaction (DRY, it builds nothing new). Topology: one committed blob (input 0), then nq copies of
{shardA, tail, final}, the aggregated FRI inputs (QPI=3 queries per input), the comp(z) split parts, and the openers
(trace@k / sel@k / comp@k). The builder is parametrized over (nq, blowup, grind_b, fold_step, opener_depth); for a real
deploy opener_depth = log2(T * blowup).

Two build modes. The demo builder reproduces components that accept independently, and self_test() checks 27/27 accept
at blowup=8. The sound builder single sources every prover chosen value from the committed blob (opener sourced values,
cross input carries, blob committed OOD and alphas, FS derived indices and betas) and pins every covenant to its
committed P2SH32 locking, so no input can be omitted or swapped for a bare filler; sound_full_selftest() checks that
the full sound transaction accepts and rejects the forged covenant attacks. Proving time at blowup=8 is a few seconds;
the real security parameters (blowup 8192 and up) take hours and belong to a dedicated offline proving run.
"""
import sys, os
_APPS = os.path.dirname(os.path.abspath(__file__))     # this file's dir (apps/)
sys.path.insert(0, _APPS)
sys.path.insert(0, os.path.dirname(_APPS))             # package root (cashvm, stark, structures_*)
import native_ct_shard as S, native_gf_p2 as F, native_shard_deploy_check as D
import native_ct_air_stark as STK, native_ct_air_prover as CT
from native_ct_shard import (P, _field_prelude, _deep_dual_zsplit, _acc_preimage, enc8, split_cells_prog,
                             deep_sum_part_counter_dual_deploy_prog, deep_dual_slice_read_prog, split_cells_loop,
                             _DEEP_MAC_LAZY_FID, _deep_mac_lazy_body, _deep_strided_mac_loop, ext_add_stack_prog,
                             run_deep_final_combine, deep_final_combine_qbound_prog, _fri_loop_chain_redeem,
                             _fri_loop_chain_unlock, fri_loop_defines)
from cashvm import N as NUM, P as PUSH, OP, DEFINE
from structures_fri import NORM_TAIL

QPI = 3                                                          # queries per aggregated-FRI input (STATE §LOOP#9)
_SELSPEC = ("is_full", "is_partial", "is_block_start", "is_reabsorb", "is_range", "is_range_first",
            "is_range_step", "is_range_last")


def _ci_top_bind():
    """DEEP-Chain carry_in-on-TOP self-bind (proto_chain_nq._ci_top_bind): binds the tail's total against the
    predecessor shardA carry read cross-input. Config-independent (net-zero PICK choreography)."""
    prog = []; sp = [6]
    ADD = [OP("ADD")] + NORM_TAIL

    def pk(pos):
        prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1
    prog += list(split_cells_prog(4, prefix=0)); sp[0] += 3
    pk(1); pk(5); prog += ADD; sp[0] -= 1
    pk(2); pk(6); prog += ADD; sp[0] -= 1
    pk(3); pk(7); prog += ADD; sp[0] -= 1
    pk(4); pk(8); prog += ADD; sp[0] -= 1
    pk(0); prog += list(split_cells_prog(4, prefix=0)); sp[0] += 3
    pk(12); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2
    pk(11); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2
    pk(10); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2
    pk(9); prog.append(OP("NUMEQUALVERIFY")); sp[0] -= 2
    prog += [OP("DROP")] * sp[0] + [NUM(1)]
    return prog


def _ci_top_add():
    """tail/final-fusion (HP11): the total-ONLY variant of _ci_top_bind. Entry stack (fused tail input): the unlock base
    [q_pre@0, invz0@1, invz1@2, invzg0@3, invzg1@4] with the tail sum T @5..8 (Sz0,Sz1,Szg0,Szg1) and the shardA carry A
    (32B blob) on top @9. Adds A to T limb-wise (mod P) and leaves the TOTAL Sum_z||Sum_zg as 4 limbs @5..8, WITHOUT
    _ci_top_bind's carry_out exposure / self-bind: the total flows IN-PLACE to deep_final_combine_qbound(from_stack=True)
    in the SAME redeem (no cross-input exposure -> no free witness -> the total IS the direct computation, soundness
    preserved). Net: A@9 (split) + T@5..8 consumed, TOTAL@5..8 left. Config-independent."""
    prog = []; sp = [10]
    ADD = [OP("ADD")] + NORM_TAIL
    def pk(pos): prog.extend([NUM(sp[0] - 1 - pos), OP("PICK")]); sp[0] += 1
    prog += list(split_cells_prog(4, prefix=0)); sp[0] += 3         # A@9 -> A0@9,A1@10,A2@11,A3@12 (Sz0,Sz1,Szg0,Szg1)
    pk(5); pk(9); prog += ADD; sp[0] -= 1                            # TOTAL_Sz0 = T0 + A0
    pk(6); pk(10); prog += ADD; sp[0] -= 1                           # TOTAL_Sz1
    pk(7); pk(11); prog += ADD; sp[0] -= 1                           # TOTAL_Szg0
    pk(8); pk(12); prog += ADD; sp[0] -= 1                           # TOTAL_Szg1 -> 4 TOTALs @13..16
    prog += [OP("TOALT")] * 4 + [OP("DROP")] * 8 + [OP("FROMALT")] * 4   # drop T@5..8 + A@9..12; TOTAL restored @5..8
    return prog


def _tail_standalone(N, n_sel):
    """DEEP-Chain tail shard (proto_chain_nq._tail_standalone): the [104:138] MAC tail. Config-independent."""
    rw_rel = n_sel; comp_rel = n_sel + 1
    prog = [NUM(16 * N), OP("SPLIT")]
    prog += list(split_cells_loop(2 * N, prefix=0))
    prog += [NUM(2 * N), OP("ROLL")] + list(split_cells_loop(2 * N, prefix=0))
    prog += [PUSH(_DEEP_MAC_LAZY_FID), DEFINE(_deep_mac_lazy_body())]
    prog += _deep_strided_mac_loop(N, 0, 1, n_sel, extra=0, ba=2 * N, bv=0, bo=4 * N)
    prog += _deep_strided_mac_loop(N, comp_rel, 1, 1, extra=2, ba=2 * N, bv=0, bo=4 * N)
    prog += ext_add_stack_prog()
    prog += _deep_strided_mac_loop(N, rw_rel, 1, 1, extra=2, ba=2 * N, bv=0, bo=4 * N)
    prog += ([OP("TOALT"), OP("TOALT"), OP("TOALT"), OP("TOALT")] + [OP("DROP")] * (6 * N)
             + [OP("FROMALT"), OP("FROMALT"), OP("FROMALT"), OP("FROMALT")])
    return prog


def _idx_op(n):
    """Absolute cross-input index token (proto_chain_nq.idx_op)."""
    return "OP_%d" % n if n <= 16 else "<0x%s>" % S.encode_num(n).hex()


def _read_blob_field(field_off, length):
    """HP3 cross-input read: leave `length` bytes at blob-content offset `field_off` of the sound blob@0 on top.
    Input-0 scriptSig = PUSH(nonce8) ++ PUSH(blob) ++ PUSH(redeem); the blob content starts at byte 12 (9B nonce push
    OP_DATA_8 + 8, then the 3B OP_PUSHDATA2 prefix), a DETERMINISTIC layout pinned by the fixed 8-byte nonce
    (native_ct_shard:4036-4040 -- no push-encoding malleability can shift the offset). Reused by every HP3 consumer."""
    skip = 12 + field_off
    return ("OP_0 OP_INPUTBYTECODE <0x%s> OP_SPLIT OP_NIP <0x%s> OP_SPLIT OP_DROP "
            % (S.encode_num(skip).hex(), S.encode_num(length).hex()))


def _covenant_bind_asm(idx, redeem_hash32):
    """HP8 count-anchor: one stack-neutral, fail-closed presence+content bind that blob@0 (input 0, un-omittable --
    every consumer reads it via OP_0 OP_INPUTBYTECODE) runs over input `idx`, binding it to the EXECUTED covenant via
    OP_UTXOBYTECODE: it reads input `idx`'s spent-UTXO LOCKING bytecode -- which under P2SH32 consensus PINS the redeem
    that actually executes (the revealed redeem must hash256 to it) -- and EQUALVERIFYs it against the committed P2SH32
    locking `OP_HASH256 <hash256(redeem_bin)> OP_EQUAL` (35B). Fail-closed: an omitted input shifts the list so a baked
    index is out of range OR a filler/substituted input has a different locking -> reject. So spending blob@0 forces
    every bound input present + spending a P2SH32 output committed to EXACTLY the deployed covenant.

    CRITICAL FIX #1 (audit 2026-07-20, d10e370): the earlier form hashed the trailing bytes of the input's UNLOCKING
    bytecode (OP_INPUTBYTECODE). That authenticates the scriptSig BYTES, not the code that RUNS: a self-funded BARE
    output (locking `OP_DROP OP_1`) spent with `scriptSig = PUSH(redeem_bin)` has the committed bytes as trailing data
    yet DROPS them and executes a trivial script -> the input's end-check is skipped -> forged accept. OP_UTXOBYTECODE
    binds the P2SH32 LOCKING, which the consensus rules tie to the executed redeem, so a bare (or any non-committed)
    locking is rejected.

    CRITICAL FIX #2 (audit 2026-07-20 HP12 soundness audit): the d10e370 fix bound ONLY the TERMINAL inputs (agg-FRI +
    comp_final, read by no other input), on the assumption non-terminals were "presence-bound by the cross-input read
    DAG". That assumption conflates byte-presence with covenant-EXECUTION: a non-terminal is read via OP_INPUTBYTECODE
    (its scriptSig BYTES), which does NOT force its redeem's self-bind to run. A bare-output non-terminal (opener /
    shardA / tailfinal / comp_trans) supplies the exact bytes its consumer reads (e.g. a free q_pre* to the agg-FRI)
    while its `q==q_pre` / carry / merkle-root self-bind never executes -> the trace<->comp<->FRI chain is severed ->
    forged accept. So build_sound_verifier_inputs now binds EVERY non-blob covenant with this asm, not just terminals.
    (blob@0's own execution is the single irreducible external anchor -- a within-tx self-bind is circular; the
    verifier pins input 0's outpoint = the committed fs-covenant.) Net stack effect: 0 (the UTXOBYTECODE push is
    consumed by EQUALVERIFY)."""
    locking = bytes([0xaa, 0x20]) + redeem_hash32 + bytes([0x87])    # P2SH32: OP_HASH256 <32B hash256(redeem)> OP_EQUAL
    return "%s OP_UTXOBYTECODE <0x%s> OP_EQUALVERIFY " % (_idx_op(idx), locking.hex())


def _build_sound_blob(pf, fold_step=3):
    """HP6.1 — build the HP2.4 FS-covenant blob@0 + its `fs_input_prog` covenant, faithfully replicating the
    already-tested reference (`native_ct_shard.self_test:9358-9424`). deep=True blob layout:
    [root(8) | nf(8) | cm_out(8*nod) | tp_root(32) | fri_roots(32*nrd) | comp_root(32) | z*g(16) |
    masks(16*ntd) | fs_out(8*M)]. All values come from the SAME `pf` the builder already computes (DRY, nothing
    invented — imports fs_transcript_prog/fs_input_prog from native_ct_shard). The covenant recompute-binds every
    FS challenge (alphas, betas, idx) against the committed fs_out and pins SIZE==8*M (front-pad Frozen-Heart, FS-2).
    Returns (nonce, blob, cov_tokens, offs)."""
    sd = pf["stmt"]; nod = len(sd["cm_out"])
    meta_d, T_d = STK.ct_build_layout(sd["depth"])
    Nd, oTd = STK._setup(T_d, pf["blowup"])[:2]
    ned = STK.ct_num_transition_residuals() + len(STK.ct_boundary_constraints(meta_d, sd))
    tpd = bytes.fromhex(pf["tp_root"]); nonced = bytes.fromhex(pf["nonce"])
    frid = [bytes.fromhex(r) for r in pf["fri_roots"]]; nrd = len(frid); nqd = pf["nq"]
    crd = bytes.fromhex(pf["comp_root"])
    masksd = []
    for _c in STK.FLAT_COLS:
        masksd.append((pf["Pcz"][_c][0], pf["Pcz"][_c][1])); masksd.append((pf["Pczg"][_c][0], pf["Pczg"][_c][1]))
    for _m in pf["sel_z"]:
        masksd.append((_m[0], _m[1]))
    masksd.append((pf["rw_zg"][0], pf["rw_zg"][1])); masksd.append((pf["comp_z"][0], pf["comp_z"][1]))
    ntd = len(masksd)
    vmt = S.VM(); vmt.run(S.fs_transcript_prog(tpd, sd["root"], sd["nf"], sd["cm_out"], frid, nonced, Nd, ned, nqd,
                                              fold_step=fold_step, deep=True, comp_root=crd, masks=masksd))
    Md = 2 * ned + (2 + 2 * ntd) + 2 * S._folds_to_final(Nd) + nqd
    outd = [S.decode_num(vmt.s[i]) % P for i in range(Md)]
    prefd = enc8(sd["root"] % P) + enc8(sd["nf"] % P)
    for cm in sd["cm_out"]:
        prefd += enc8(cm % P)
    prefd += tpd
    for fr in frid:
        prefd += fr
    prefd += crd + enc8(pf["zg"][0]) + enc8(pf["zg"][1])
    for _m0, _m1 in masksd:
        prefd += enc8(_m0) + enc8(_m1)
    blob = prefd + b"".join(enc8(v) for v in outd)
    cov = S.fs_input_prog(Nd, ned, nqd, nod, nrd, fold_step, pf["grind_b"], deep=True, n_terms=ntd, oT=oTd)
    folds = S._folds_to_final(Nd)
    crd = 48 + 8 * nod + 32 * nrd
    # HP3 cross-input read offsets INTO the blob content (config-invariant; consumers add the +12 input-0 push prefix):
    #   fs_out layout = [alphas(2*ned) | z(2) | deep_alphas(2*ntd) | betas(2*folds) | idx(nqd)], 8 bytes each.
    offs = {"crd": crd, "prefd_len": len(prefd), "Nd": Nd, "ned": ned, "ntd": ntd, "nqd": nqd, "nod": nod,
            "nrd": nrd, "M": Md, "folds": folds, "tp_off": 16 + 8 * nod, "comp_off": crd,
            "ood_off": crd + 48, "alpha_off": len(prefd) + 8 * (2 * ned + 2),
            "zg_off": crd + 32, "z_off": len(prefd) + 8 * (2 * ned),
            "idx0_off": len(prefd) + 8 * (2 * ned + 2 + 2 * ntd + 2 * folds)}
    return nonced, blob, cov, offs


def build_verifier_inputs(nq=6, blowup=8, grind_b=2, fold_step=3, opener_depth=8, seed=0xF54A, sound=False):
    """Build the full DEEP-ALI verifier-tx input list, config-parametrized. Returns (inputs, roles, meta).
    inputs = [{"redeem": asm, "unlock": asm}, ...] = blob@0 + nq·{shardA,tail,final} + agg-FRI + comp-parts + openers.
    DEMO-equivalent to proto_chain_nq (components accept INDEPENDENT; soundness cross-wiring = HP3-8). opener_depth:
    HP1.4 couples it to blowup (log2(T·blowup)) for real deploy; the demo self-test uses a small depth for build speed.
    sound=False (default) = byte-identical demo (blob@0 = OP_DROP OP_1 data-carrier). sound=True (HP6.1+) = blob@0 is
    the `fs_input_prog` FS-covenant over the HP2.4 layout (recompute-bind); the consumer wiring is layered in HP3-8."""
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    mt, T = STK.ct_build_layout(pf["stmt"]["depth"])
    N0, oT, oN, of, Hd, Dd, ls = STK._setup(T, pf["blowup"])
    ly = STK.ct_public_layout(mt, T); sv = STK._selector_vectors(ly, T, N0, oT, oN, of)
    z = tuple(pf["z"]); zg = tuple(pf["zg"]); pz = STK._ood_pub_at(ly, T, oT, z)
    da = [tuple(a) for a in pf["deep_alphas"]]
    nf = len(STK.FLAT_COLS)

    def build_terms(qi):
        q = pf["queries"][qi]; k = q["k"]; tm = []
        for c in STK.FLAT_COLS:
            cke = F.from_base(q["ck"][c]); tm.append((da[len(tm)], cke, tuple(pf["Pcz"][c])))
            tm.append((da[len(tm)], cke, tuple(pf["Pczg"][c])))
        sel = [(sv[kk], pz[kk]) for kk in _SELSPEC] + [(sv["rc"][i], pz["rc"][i]) for i in range(S.WIDTH)] \
            + [(sv["chain_minv"][j], pz["chain_minv"][j]) for j in range(S.WIDTH)]
        ns = len(sel)
        for dv, m in sel:
            tm.append((da[len(tm)], F.from_base(dv[k]), m))
        tm.append((da[len(tm)], F.from_base(sv["range_weight"][k]), tuple(pf["rw_zg"])))
        tm.append((da[len(tm)], tuple(q["cc"]), tuple(pf["comp_z"])))
        return tm, ns, k, q

    # global blob (ood/alpha are query-independent)
    _tm0, ns0, _, _ = build_terms(0)
    nt = len(_tm0); ao = [(t[0], t[2]) for t in _tm0]
    blob = S._deep_blob_bytes(z, zg, ao)
    ziA, zgiA = _deep_dual_zsplit(0, 104, nf, ns0)

    def build_query_inputs(qi, base):
        tm, ns, k, q = build_terms(qi)
        val = [t[1] for t in tm]; ood = [t[2] for t in tm]; alp = [t[0] for t in tm]
        (SzA, SzgA), _ = S.run_deep_sum_part_dual(0, 104, nf, ns, F.ZERO, F.ZERO, val[:104], ood[:104], alp[:104])
        (SzT, SzgT), _ = S.run_deep_sum_part_dual(104, 138, nf, ns, SzA, SzgA, val[104:], ood[104:], alp[104:])
        xk = F.from_base(Dd[k]); invz = F.inv(F.sub(xk, z)); invzg = F.inv(F.sub(xk, zg))
        qref, _ = run_deep_final_combine(SzT, SzgT, invz, invzg, dual_carry=True)
        qf = STK.query_fri_terms_fold8(pf); rounds = qf[qi]["rounds"]; final = pf["final"]
        frl = bytes.fromhex(pf["fri_roots"][-1])
        ins = []
        redA = ("OP_DROP OP_0 OP_INPUTBYTECODE OP_3 OP_SPLIT OP_NIP "
                + S.tokens_to_asm(deep_dual_slice_read_prog(0, 104, nt)) + " "
                + S.tokens_to_asm(_field_prelude()
                                  + deep_sum_part_counter_dual_deploy_prog(104, len(ziA), len(zgiA), carry_bound=True)))
        uA = [PUSH(_acc_preimage(SzA) + _acc_preimage(SzgA)), PUSH(_acc_preimage(F.ZERO) + _acc_preimage(F.ZERO))]
        for i in range(0, 104):
            uA += [NUM(val[i][0] % P), NUM(val[i][1] % P)]
        uA += [PUSH(b"\x00" * 1157)]
        ins.append({"redeem": redA, "unlock": S.tokens_to_asm(uA)})
        zit, zgit = _deep_dual_zsplit(104, 138, nf, ns)
        read_ci = "%s OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x20> OP_SPLIT OP_DROP " % _idx_op(base)
        redT = ("OP_DROP OP_0 OP_INPUTBYTECODE OP_3 OP_SPLIT OP_NIP "
                + S.tokens_to_asm(deep_dual_slice_read_prog(104, 138, nt)) + " "
                + S.tokens_to_asm(_field_prelude() + _tail_standalone(34, ns)) + " " + read_ci
                + S.tokens_to_asm(_ci_top_bind()))
        uT = [PUSH(_acc_preimage(SzT) + _acc_preimage(SzgT))]
        for i in range(104, 138):
            uT += [NUM(val[i][0] % P), NUM(val[i][1] % P)]
        uT += [PUSH(b"\x00" * 1)]
        ins.append({"redeem": redT, "unlock": S.tokens_to_asm(uT)})
        read_total = "%s OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x20> OP_SPLIT OP_DROP " % _idx_op(base + 1)
        redF = ("OP_DROP " + read_total + S.tokens_to_asm(_field_prelude() + deep_final_combine_qbound_prog()))
        uF = [PUSH(enc8(qref[0] % P) + enc8(qref[1] % P)), NUM(invz[0] % P), NUM(invz[1] % P),
              NUM(invzg[0] % P), NUM(invzg[1] % P), PUSH(b"\x00" * 1)]
        ins.append({"redeem": redF, "unlock": S.tokens_to_asm(uF)})
        return ins, (rounds, k, final, frl, base + 2)

    def build_agg_fri(group):
        red = "OP_DROP " + S.tokens_to_asm(_field_prelude() + fri_loop_defines(oN, of)) + " "
        for (rounds, k, fin, _frl, fidx) in group:
            read_q = "%s OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x10> OP_SPLIT OP_DROP " % _idx_op(fidx)
            red += read_q + S.tokens_to_asm(split_cells_prog(2, prefix=0)) + " "
            red += S.tokens_to_asm(_fri_loop_chain_redeem(rounds, k, fin, oN, of, _frl, defines_installed=True)[:-1]) + " "
        red += "OP_1"
        unl = []
        for (rounds, k, fin, _frl, fidx) in reversed(group):
            unl += _fri_loop_chain_unlock(rounds, (0, 0), _frl)[:-2]
        unl += [PUSH(b"\x00" * 1)]
        return {"redeem": red, "unlock": S.tokens_to_asm(unl)}

    if sound:                                                          # HP6.1: FS-covenant blob@0 (recompute-bind)
        _nonce, _sblob, _scov, _ = _build_sound_blob(pf, fold_step)
        inputs = [{"redeem": S.tokens_to_asm(_scov), "unlock": S.tokens_to_asm([PUSH(_nonce), PUSH(_sblob)])}]
    else:
        inputs = [{"redeem": "OP_DROP OP_1", "unlock": "<0x%s>" % blob.hex()}]
    fri_all = []
    for qi in range(nq):
        ins, frid = build_query_inputs(qi, 1 + 3 * qi)
        inputs += ins
        fri_all.append(frid)
    for g0 in range(0, nq, QPI):
        inputs.append(build_agg_fri(fri_all[g0:g0 + QPI]))
    n_deep = len(inputs); n_qin = 3 * nq

    # ---- comp(z) split-parts (real deploy tokens, carry_bound+comp_bound) ----
    import random
    import native_poseidon2 as P2
    rng = random.Random(0x5B0C); _ev = lambda: (rng.randrange(0, P), rng.randrange(0, P))
    _tf, _st = CT.build_ct_trace(CT._demo_witness(depth=2)); _fc, _T, _meta = CT.build_full_flat_trace(_tf)
    _rspec = [(CT.HELD_COLS.index("vh_" + rm["vname"]), rm["src"] is not None) for rm in _meta["range"]]
    _cons = CT.ct_boundary_constraints_ext(_meta, _st); _minvcap = [CT.M_EXT_INV[k2] for k2 in range(P2.RATE, P2.WIDTH)]
    _nt_c = CT.ct_num_transition_residuals(); _nb_c = len(_cons)
    curZ = {}
    for kk in range(P2.WIDTH):
        curZ["s%d" % kk] = _ev(); curZ["u2_%d" % kk] = _ev(); curZ["u4_%d" % kk] = _ev(); curZ["u6_%d" % kk] = _ev()
    for hc in CT.HELD_COLS:
        curZ[hc] = _ev()
    nxtZ = {"s%d" % kk: _ev() for kk in range(P2.WIDTH)}
    for hc in CT.HELD_COLS:
        nxtZ[hc] = _ev()
    pubZ = {"is_full": _ev(), "is_partial": _ev(), "is_block_start": _ev(), "is_reabsorb": _ev(), "is_range": _ev(),
            "is_range_first": _ev(), "is_range_step": _ev(), "is_range_last": _ev(),
            "rc": [_ev() for _ in range(P2.WIDTH)], "chain_minv": [_ev() for _ in range(P2.WIDTH)]}
    wnZ = _ev(); zZ = _ev(); lastZ = rng.randrange(0, P); zhZ = _ev()
    aTZ = [_ev() for _ in range(_nt_c)]; aBZ = [_ev() for _ in range(_nb_c)]
    HdZ = {row: (row * 7 + 3) % P for (row, _fn) in _cons}
    qfZ = F.mul(F.sub(zZ, F.from_base(lastZ)), zhZ)
    bixZ = [F.inv(F.sub(zZ, F.from_base(HdZ[row]))) for (row, _fn) in _cons]
    _split = S.comp_split_default_parts(_minvcap)
    _cs, _stats = S.run_comp_split(_split, CT.M_EXT, P2.MAT_DIAG12, _minvcap, CT.M_EXT_INV[0], CT.N_OUT, _rspec,
                                   _st["root"], _st["nf"], _st["cm_out"], curZ, nxtZ, pubZ, wnZ, aTZ, qfZ, bixZ, aBZ,
                                   CT.HELD_COLS, sbox_looped=True, state_looped=True, carry_bound=True, comp_bound=True)
    _nb_comp = S._n_boundary_residuals(CT.N_OUT, _rspec)
    _acc = (0, 0); _off = 0; n_comp0 = len(inputs)
    for _grp in _split:
        _pnr = sum(S._job_nres(_j, _minvcap) for _j in _grp)
        _pr0 = S.comp_split_trans_part_prog(_grp, _pnr, CT.M_EXT, P2.MAT_DIAG12, _minvcap, sbox_looped=True,
                                            state_looped=True)
        _u0 = S.comp_split_trans_part_unlock(_grp, _acc, aTZ[_off:_off + _pnr], curZ, nxtZ, pubZ, wnZ, CT.HELD_COLS)
        _vm = S.VM(); _vm.run(S._field_prelude() + _u0 + _pr0); _ao = (S.decode_num(_vm.s[-2]), S.decode_num(_vm.s[-1]))
        _bpr = S.comp_split_trans_part_prog(_grp, _pnr, CT.M_EXT, P2.MAT_DIAG12, _minvcap, sbox_looped=True,
                                            state_looped=True, carry_bound=True)
        _bu = S.comp_split_trans_part_unlock(_grp, _acc, aTZ[_off:_off + _pnr], curZ, nxtZ, pubZ, wnZ, CT.HELD_COLS,
                                             carry_bound=True, acc_out=_ao)
        inputs.append({"redeem": "OP_DROP " + S.tokens_to_asm(S._field_prelude() + _bpr),
                       "unlock": S.tokens_to_asm(_bu + [PUSH(b"\x00" * 200)])})
        _acc = _ao; _off += _pnr
    _fpr = S.comp_split_final_part_prog(CT.M_EXT_INV[0], CT.N_OUT, _rspec, _st["root"], _st["nf"], _st["cm_out"],
                                        _nb_comp, carry_bound=True, comp_bound=True)
    _fu = S.comp_split_final_part_unlock(_acc, qfZ, bixZ, aBZ, curZ, CT.HELD_COLS, _nb_comp, carry_bound=True,
                                         comp_bound=True, comp=_cs)
    inputs.append({"redeem": "OP_DROP " + S.tokens_to_asm(S._field_prelude() + _fpr),
                   "unlock": S.tokens_to_asm(_fu + [PUSH(b"\x00" * 200)])})
    n_comp1 = len(inputs)

    # ---- openers (real merkle at opener_depth: HP1.4 couples to blowup for deploy; small depth = build speed) ----
    from stark import Hf as _Hf, merkle as _merkle, m_root as _mroot, m_path as _mpath
    n_open0 = len(inputs)
    for leaf_lbl, n_cells, prefix in [("trace@k", 52, 16), ("sel@k", 33, 0), ("comp@k", 2, 16)]:
        _n = 1 << opener_depth
        _salt = b"\x00" * prefix if prefix else b""
        _pre = [b"\x07" * (prefix + 8 * n_cells) for _ in range(_n)]
        _od = []
        for _qo in range(nq):
            _k = (_qo * 41 + 5) % _n
            _cells = [(i * 3 + 1 + _qo) % P for i in range(n_cells)]
            _pre[_k] = _salt + b"".join(S.enc8(c % P) for c in _cells)
            _od.append((_cells, _k))
        _tree = _merkle([_Hf(p) for p in _pre]); _root = _mroot(_tree)
        _opens = [(_root, _mpath(_tree, _k), _salt, _cells, _k) for (_cells, _k) in _od]
        red_op = "OP_DROP " + S.tokens_to_asm(S.looped_opener_from_blob_prog(opener_depth, n_cells, nq, prefix))
        unl_op = S.looped_opener_from_blob_unlock(_opens) + [PUSH(b"\x00" * 800)]
        inputs.append({"redeem": red_op, "unlock": S.tokens_to_asm(unl_op)})
    n_open1 = len(inputs)

    roles = ["blob"]
    for i in range(1, n_qin + 1):
        roles.append(["shardA", "tail", "final"][(i - 1) % 3])
    for i in range(n_qin + 1, n_deep):
        roles.append("aggFRI")
    for i in range(n_deep, n_comp1):
        roles.append("comp")
    for i in range(n_comp1, n_open1):
        roles.append("opener")
    assert len(roles) == len(inputs), (len(roles), len(inputs))
    meta = {"nq": nq, "blowup": blowup, "grind_b": grind_b, "fold_step": fold_step, "opener_depth": opener_depth,
            "n_inputs": len(inputs), "n_deep": n_deep, "n_qin": n_qin, "n_comp0": n_comp0, "n_comp1": n_comp1,
            "n_open0": n_open0, "n_open1": n_open1}
    return inputs, roles, meta


def build_and_evaluate(nq=6, blowup=8, grind_b=2, fold_step=3, opener_depth=8, seed=0xF54A, sound=False):
    """Build the tx and evaluate ALL non-blob inputs on the real BCH-2026 libauth VM. Returns (inputs, roles, meta, res)."""
    inputs, roles, meta = build_verifier_inputs(nq, blowup, grind_b, fold_step, opener_depth, seed, sound)
    res = D._p2sh_multi(inputs, evaluate=list(range(1, len(inputs))))
    return inputs, roles, meta, res


def self_test():
    """HP2.2: all_accept self-test at the DEMO config (blowup=8, opener_depth=8 for build speed) == proto_chain_nq
    (27/27 accept). Real libauth VM, no mocks (TEST_RULES). Fails LOUD on any non-accept."""
    inputs, roles, meta, res = build_and_evaluate(nq=6, blowup=8, grind_b=2, fold_step=3, opener_depth=8)
    rs = {x["idx"]: x for x in res.get("results", [])}
    n_eval = len(inputs) - 1
    n_ok = sum(1 for i in range(1, len(inputs)) if rs.get(i, {}).get("ok"))
    fails = [(i, roles[i], str(rs.get(i, {}).get("error"))[:100]) for i in range(1, len(inputs))
             if not rs.get(i, {}).get("ok")]
    for i, role, err in fails:
        print("  [FAIL] input %d (%s): %s" % (i, role, err))
    assert n_ok == n_eval and n_ok == 27, \
        "HP2 builder: %d/%d accept (expected 27/27 == proto_chain_nq demo)" % (n_ok, n_eval)
    print("HP2 native_ct_verifier_tx durable builder: %d/%d accept at demo config == proto_chain_nq (blob + %d query "
          "+ %d aggFRI + comp + openers), txBytes=%d: OK"
          % (n_ok, n_eval, meta["n_qin"], meta["n_deep"] - 1 - meta["n_qin"], res.get("txBytes", -1)))
    return True


def sound_blob_selftest(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """HP6.1 — validate the FS-covenant blob@0 (sound=True) STANDALONE on the real BCH-2026 VM (no mocks, TEST_RULES):
    honest [nonce, blob] accepts; forged comp_root / z*g / mask / committed-z / committed-deep_alpha / committed-alpha
    + back-pad / truncation / front-pad (Frozen-Heart, size pin) ALL reject; and the blob@0 {redeem,unlock} accepts as
    input 0 in the real _p2sh_multi harness. Mirrors the tested reference native_ct_shard.self_test:9397-9421."""
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    assert pf.get("deep") and STK.verify(pf)[0], "HP6.1: sound-blob proof did not verify"
    nonced, blob, cov, offs = _build_sound_blob(pf, fold_step)

    def _run(nb, bb):
        vm = S.VM()
        try:
            vm.run([PUSH(nb), PUSH(bb)] + cov)
        except (S.VMError, IndexError):
            return False
        return len(vm.s) == 1 and vm.s[-1] not in (b"", b"\x00")

    def _flip(base, off):
        bb = bytearray(base); bb[off] ^= 0x01; return bytes(bb)

    assert _run(nonced, blob), "HP6.1: honest [nonce, blob] REJECTED"
    crd_off = offs["crd"]; zgd_off = crd_off + 32; maskd_off = zgd_off + 16
    fsd_off = offs["prefd_len"]; ned = offs["ned"]; fs_len = len(blob) - fsd_off
    assert not _run(nonced, _flip(blob, crd_off)), "HP6.1: forged comp_root accepted"
    assert not _run(nonced, _flip(blob, zgd_off)), "HP6.1: forged z*g accepted"
    assert not _run(nonced, _flip(blob, zgd_off + 8)), "HP6.1: forged z*g[1] accepted"
    assert not _run(nonced, _flip(blob, maskd_off)), "HP6.1: forged mask accepted"
    assert not _run(nonced, _flip(blob, fsd_off + 8 * (2 * ned))), "HP6.1: forged committed z accepted"
    assert not _run(nonced, _flip(blob, fsd_off + 8 * (2 * ned + 2))), "HP6.1: forged committed deep_alpha accepted"
    assert not _run(nonced, _flip(blob, fsd_off)), "HP6.1: forged committed alpha accepted"
    assert not _run(nonced, blob + b"\x00" * 8), "HP6.1: back-padded fs_out accepted (size pin broken)"
    assert not _run(nonced, blob[:-8]), "HP6.1: truncated fs_out accepted (size pin broken)"
    assert not _run(nonced, blob[:fsd_off] + b"\x00" * fs_len + blob[fsd_off:]), \
        "HP6.1: FRONT-padded fs_out accepted (Frozen-Heart; size pin must reject)"
    inputs, _roles, _meta = build_verifier_inputs(nq=nq, blowup=blowup, grind_b=grind_b, fold_step=fold_step,
                                                  opener_depth=8, seed=seed, sound=True)
    res = D._p2sh_multi(inputs, evaluate=[0])
    r0 = {x["idx"]: x for x in res.get("results", [])}.get(0, {})
    assert r0.get("ok"), "HP6.1: sound blob@0 covenant REJECTED in _p2sh_multi: %s" % str(r0.get("error"))[:140]
    print("HP6.1 FS-covenant blob@0 (sound=True): OK -- honest accept; forged comp_root/z*g/mask/committed-z/deep_alpha/"
          "alpha + back-pad/truncate/front-pad all REJECT; _p2sh_multi[0] accept. n_terms=%d M=%d blobBytes=%d"
          % (offs["ntd"], offs["M"], len(blob)))
    return True


def _sound_looped_opener(pf, offs, nq, n_cells, root_off, cells_of, salt_of, path_of, pad=3000):
    """LEVER-1 (opener-aggregation) -- verify ALL nq same-(depth,n_cells) leaf openings in ONE pinned-count
    OP_BEGIN/UNTIL loop instead of nq separate per-query opener inputs (the deploy-dominant byte lever: at deploy depth
    ~24 the per-query opener redeem is large; the loop reveals it ONCE for the whole query set, mirrors deploy_check-c3b
    from-blob looped opener). SOUNDNESS IDENTICAL to the per-query _sound_{trace,comp}_opener_one, merely amortized:
    iteration i (== qi=i; the loop consumes the stack top, and the unlock stacks block_0 on top) derives preimage =
    salt++cells from the witness blob, binds committed-k == the FS-derived index read cross-input from blob@0 at offset
    idx0_off+8*i (per-iteration offset carried as the loop's alt accumulator -> HP3.6 positions-grinding stays closed,
    no baked/witness k), climbs the path @k and EQUALVERIFYs the root against the blob@0 root (root_off, HP3.3/6.4-class
    single-source). The cells stay in each block's scriptSig; the per-query consumer reads them cross-input at the
    block's build-time offset (lever-1b). cells_of/salt_of/path_of(q) extract the leaf cells / hiding salt / Merkle path
    (trace: FLAT_COLS/sk/pk ; comp: [cc0,cc1]/16B-zero/cp). Unlock: nq blocks in REVERSE processing order (block_0 on
    top) then an op-budget pad; each block bottom->top = [sib_{d-1}..sib_0, salt, blob=enc8(cells)||enc8(k)]."""
    d = len(path_of(pf["queries"][0]))
    base_off = 12 + offs["idx0_off"]                                  # blob@0: sblob starts at byte 12 of input-0 code
    end_off = base_off + 8 * nq                                       # loop exit when the alt offset reaches here
    padtok = [PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM")]                # unsigned 8-byte LE slice -> minimal number
    # ---- loop body (alt carries the current FS-idx byte-offset = base_off + 8*i) ----
    #   pre: [.., sib_{d-1}..sib_0, salt, blob] ; split blob -> cells_bytes + k, DUP k (FS-bind copy + climb copy)
    body_split = S.tokens_to_asm([NUM(n_cells * 8), OP("SPLIT")] + padtok + [OP("DUP")])  # [.., salt, cells_bytes, k, k]
    #   FS-k bind: committed k == blob@0[offset:offset+8] (offset from alt); leaves [.., salt, cells_bytes, k]
    body_fsk = ("OP_0 OP_INPUTBYTECODE "
                + S.tokens_to_asm([OP("FROMALT"), OP("DUP"), OP("TOALT"), OP("SPLIT"), OP("NIP"),
                                   NUM(8), OP("SPLIT"), OP("DROP")] + padtok + [OP("NUMEQUALVERIFY")]))
    #   preimage = salt ++ cells_bytes ; climb @k -> H (root supplied separately, so drop the baked EQUALVERIFY)
    body_climb = S.tokens_to_asm([OP("TOALT"), OP("CAT"), OP("FROMALT")] + S.merkle_verify_stack_prog(d)[:-1])
    #   H == root (blob@0 single-source: tp_root for trace, comp_root for comp)
    body_root = _read_blob_field(root_off, 32) + S.tokens_to_asm([OP("EQUALVERIFY")])
    body = " ".join([body_split, body_fsk.strip(), body_climb, body_root.strip()])
    loop = (S.tokens_to_asm([NUM(base_off), OP("TOALT"), OP("BEGIN")]) + " " + body + " "
            + S.tokens_to_asm([OP("FROMALT"), NUM(8), OP("ADD"), OP("DUP"), OP("TOALT"),
                               NUM(end_off), OP("NUMEQUAL"), OP("UNTIL"), OP("FROMALT"), OP("DROP"), NUM(1)]))
    red = "OP_DROP " + loop
    blocks = []
    for qi in range(nq - 1, -1, -1):                                  # block_{nq-1} at the bottom, block_0 on top
        q = pf["queries"][qi]; k = q["k"]
        blob = b"".join(enc8(c % P) for c in cells_of(q)) + enc8(k)
        sibsasm = " ".join("<0x%s>" % s.hex() for s, _ in reversed([(bytes.fromhex(s), b) for s, b in path_of(q)]))
        blocks.append("%s <0x%s> <0x%s>" % (sibsasm, salt_of(q).hex(), blob.hex()))
    unl = " ".join(blocks) + " <0x%s>" % (b"\x00" * pad).hex()
    return {"redeem": red, "unlock": unl}


def _sound_looped_trace_opener(pf, offs, nq, pad=256):
    """LEVER-1 -- aggregated trace-opener: all nq trace leaves (nf FLAT_COLS cells, per-query salt sk, path pk) opened
    against tp_root in one loop. Replaces nq * _sound_trace_opener_one. pad = op-budget cushion above the nq-block
    unlock (empirically the blocks already fund the op-cost; pad=256 is a lean cushion, bump at HP9/HP11 for the deploy
    op-cost if the offline run needs it). See _sound_looped_opener."""
    nf = len(STK.FLAT_COLS)
    return _sound_looped_opener(pf, offs, nq, nf, root_off=offs["tp_off"],
                                cells_of=lambda q: [q["ck"][c] for c in STK.FLAT_COLS],
                                salt_of=lambda q: bytes.fromhex(q["sk"]),
                                path_of=lambda q: q["pk"], pad=pad)


def _sound_looped_comp_opener(pf, offs, nq, pad=256):
    """LEVER-1 -- aggregated comp-opener: all nq comp leaves ([cc0,cc1], 16B-zero salt, path cp) opened against
    comp_root in one loop. Replaces nq * _sound_comp_opener_one; the tail reads cc cross-input from each block's
    scriptSig (lever-1b). pad = op-budget cushion (see _sound_looped_trace_opener). See _sound_looped_opener."""
    return _sound_looped_opener(pf, offs, nq, 2, root_off=offs["comp_off"],
                                cells_of=lambda q: [q["cc"][0], q["cc"][1]],
                                salt_of=lambda q: b"\x00" * 16,
                                path_of=lambda q: q["cp"], pad=pad)


def _looped_opener_blob_off(pf, nq, qi, n_cells, salt_of, path_of):
    """LEVER-1b -- byte offset of block_qi's blob (enc8(cells)||enc8(k)) DATA within the aggregated opener's scriptSig,
    for the per-query consumer's cross-input read (shardA reads trace cells, tail reads comp cc). _sound_looped_opener
    stacks blocks in bytecode order block_{nq-1}..block_0 (then pad), each = per-level sib pushes ++ salt push ++ blob
    push, and OP_INPUTBYTECODE returns the scriptSig which begins with the unlock -- so this offset (from scriptSig byte
    0) locates blob_qi's cells. Computed from the ACTUAL pushed byte lengths (robust to sib width / salt size), so it is
    consistent with _sound_looped_opener's layout by construction (a wrong offset -> the consumer reads wrong cells ->
    dedup/carry mismatch -> REJECT, caught by the real-libauth selftest)."""
    def psz(L):                                                      # minimal-push encoded size of an L-byte item
        return L + (1 if L <= 75 else 2 if L <= 255 else 3)
    def dpfx(L):                                                     # push opcode/prefix size (data starts after it)
        return 1 if L <= 75 else 2 if L <= 255 else 3
    blob_len = (n_cells + 1) * 8
    off = 0
    for qq in range(nq - 1, qi, -1):                                 # whole blocks before block_qi (bytecode order)
        q = pf["queries"][qq]
        off += sum(psz(len(bytes.fromhex(s))) for s, _ in path_of(q)) + psz(len(salt_of(q))) + psz(blob_len)
    q = pf["queries"][qi]                                            # sibs + salt precede the blob within block_qi
    off += sum(psz(len(bytes.fromhex(s))) for s, _ in path_of(q)) + psz(len(salt_of(q))) + dpfx(blob_len)
    return off


def sound_looped_opener_selftest(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """LEVER-1 -- validate the aggregated sound trace-opener AND comp-opener on real BCH-2026 libauth (no mocks):
    [blob@0, looped_trace_opener] and [blob@0, looped_comp_opener] each accept (all nq leaves opened @k, each k ==
    FS-idx from blob@0, each root == tp_root/comp_root from blob@0, cells Merkle-bound); a forged cell REJECTS (wrong
    preimage -> climb != root), a forged committed-k that != FS-idx REJECTS (the per-iteration FS-k bind)."""
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    assert pf.get("deep") and STK.verify(pf)[0], "LEVER-1: proof did not verify"
    nonced, sblob, scov, offs = _build_sound_blob(pf, fold_step)
    blob0 = {"redeem": S.tokens_to_asm(scov), "unlock": S.tokens_to_asm([PUSH(nonced), PUSH(sblob)])}

    def _run(inputs, idx):
        res = D._p2sh_multi(inputs, evaluate=[idx])
        return {x["idx"]: x for x in res.get("results", [])}.get(idx, {})

    def _check(label, build, cells_of, salt_of, path_of, pad):
        looped = build(pf, offs, nq)
        r = _run([blob0, looped], 1)
        assert r.get("ok"), "LEVER-1 %s: honest looped opener REJECTED: %s" % (label, str(r.get("error"))[:200])

        def _rebuild(mutate):
            blocks = []
            for qi in range(nq - 1, -1, -1):
                q = pf["queries"][qi]; k = q["k"]
                blob = b"".join(enc8(c % P) for c in mutate(qi, list(cells_of(q)), k))
                sibsasm = " ".join("<0x%s>" % s.hex() for s, _ in reversed([(bytes.fromhex(s), b) for s, b in path_of(q)]))
                blocks.append("%s <0x%s> <0x%s>" % (sibsasm, salt_of(q).hex(), blob.hex()))
            return {"redeem": looped["redeem"], "unlock": " ".join(blocks) + " <0x%s>" % (b"\x00" * pad).hex()}

        bad_cell = _rebuild(lambda qi, cells, k: ([cells[0] ^ 0x01] + cells[1:] + [k]) if qi == 0 else cells + [k])
        assert not _run([blob0, bad_cell], 1).get("ok"), "LEVER-1 %s: forged cell accepted (merkle broken)" % label
        bad_k = _rebuild(lambda qi, cells, k: cells + [(k ^ 0x01)] if qi == 0 else cells + [k])
        assert not _run([blob0, bad_k], 1).get("ok"), "LEVER-1 %s: forged committed-k accepted (FS-k bind broken)" % label

    _check("trace", _sound_looped_trace_opener, lambda q: [q["ck"][c] for c in STK.FLAT_COLS],
           lambda q: bytes.fromhex(q["sk"]), lambda q: q["pk"], 256)
    _check("comp", _sound_looped_comp_opener, lambda q: [q["cc"][0], q["cc"][1]],
           lambda q: b"\x00" * 16, lambda q: q["cp"], 256)
    print("LEVER-1 aggregated sound openers (trace nf-cell + comp 2-cell, %d openings each in ONE pinned-count loop, "
          "root+FS-k single-source from blob@0, cells merkle-bound): OK -- honest accept; forged-cell + forged-k(!=FS) "
          "REJECT for both." % nq)
    return True


def _read_sound_slice(offs, lo, hi):
    """HP3/HP7 -- read the ood[lo:hi]||alpha[lo:hi] slice (the deep_sum_part_dual unlock slice) cross-input from the
    sound blob@0's masks (ood) + deep_alphas (alpha) sections and CAT them. Config-invariant offsets (never witness).
    Mirrors deep_dual_slice_read_prog but for the HP2.4 sound layout where ood/alpha are non-contiguous sections."""
    L = 16 * (hi - lo)
    return (_read_blob_field(offs["ood_off"] + 16 * lo, L)        # ood[lo:hi] on top
            + _read_blob_field(offs["alpha_off"] + 16 * lo, L)    # alpha[lo:hi] on top (ood 2nd)
            + "OP_CAT ")                                          # -> ood[lo:hi]||alpha[lo:hi]


def _sound_shardA_carry(pf, qi):
    """Reference Sum_z/Sum_zg over the 104 pure-trace terms [0:104] via run_deep_sum_part_dedup (== eager) -> the
    32-byte carry_out preimage the sound shardA self-binds (and the tail reads cross-input). value = the 52 base
    trace cells (opener-sourced on-chain); alpha = deep_alphas[0:104]; ood = the Pcz/Pczg masks[0:104] -- the SAME
    values the shard reads from the sound blob@0 (deep_alphas + masks sections)."""
    nf = len(STK.FLAT_COLS); q = pf["queries"][qi]
    cells_base = [q["ck"][c] for c in STK.FLAT_COLS]
    da = [tuple(a) for a in pf["deep_alphas"]]; alpha_ref = da[:2 * nf]
    ood_ref = []
    for c in range(nf):
        ood_ref.append((pf["Pcz"][STK.FLAT_COLS[c]][0], pf["Pcz"][STK.FLAT_COLS[c]][1]))
        ood_ref.append((pf["Pczg"][STK.FLAT_COLS[c]][0], pf["Pczg"][STK.FLAT_COLS[c]][1]))
    (Sz, Szg), _oc = S.run_deep_sum_part_dedup(nf, cells_base, alpha_ref, ood_ref)
    return S._acc_preimage(Sz) + S._acc_preimage(Szg)


def _sound_shardA_one(pf, qi, offs, opener_idx, nq, pad=3400):
    """HP3.1/3.2 + HP7.3 (coupled by stack order) -- the sound value-single-source shardA for ONE query. Reads the 52
    base trace cells cross-input from the AGGREGATED trace-opener (input opener_idx, LEVER-1) at block_qi's build-time
    byte offset (_looped_opener_blob_off) as the VALUE (R4-B1 fix: value is no longer a free witness), the
    deep_alphas[0:104] and Pcz/Pczg masks[0:104] cross-input from the sound blob@0 (alpha_off / ood_off sections), then
    runs deep_sum_part_dedup_prog(52) (== eager) and _counter_carry_bind_prog (self-binds Sum == carry_out_pre; the
    tail reads that carry_out cross-input). The read order value->alpha->ood lands the operands exactly as dedup expects
    ([value(52)@0, alpha(208)@52, ood(208)@260]). Returns {redeem, unlock}."""
    nf = len(STK.FLAT_COLS)
    carry_out_pre = _sound_shardA_carry(pf, qi)
    carry_in_pre = S._acc_preimage((0, 0)) + S._acc_preimage((0, 0))    # first shard: carry_in = 0
    L = 16 * 2 * nf                                                     # ood/alpha slice length = 16*104 = 1664 B
    boff = _looped_opener_blob_off(pf, nq, qi, nf, lambda q: bytes.fromhex(q["sk"]), lambda q: q["pk"])
    # split_cells_LOOP (not unrolled prog): ~23B each vs ~1.7KB unrolled -> the 3 on-chain splits fit the 10000B
    # redeem (native_ct_shard.split_cells_loop docstring: the decisive lever for the DEEP per-query blob consumer).
    read_val = ("%s OP_INPUTBYTECODE <0x%s> OP_SPLIT OP_NIP <0x%s> OP_SPLIT OP_DROP "
                % (_idx_op(opener_idx), S.encode_num(boff).hex(), S.encode_num(8 * (nf + 1)).hex()))  # 424B [52 cells|k]
    read_val += S.tokens_to_asm(list(S.split_cells_loop(nf + 1, prefix=0)) + [OP("DROP")])       # -> 52 cells (drop k)
    read_alpha = _read_blob_field(offs["alpha_off"], L) + S.tokens_to_asm(list(S.split_cells_loop(4 * nf, prefix=0)))
    read_ood = _read_blob_field(offs["ood_off"], L) + S.tokens_to_asm(list(S.split_cells_loop(4 * nf, prefix=0)))
    core = S._field_prelude() + S.deep_sum_part_dedup_prog(nf) + S._counter_carry_bind_prog()
    red = "OP_DROP " + " ".join([read_val.strip(), read_alpha.strip(), read_ood.strip(), S.tokens_to_asm(core)])
    unl = S.tokens_to_asm([PUSH(carry_out_pre), PUSH(carry_in_pre), PUSH(b"\x00" * pad)])
    return {"redeem": red, "unlock": unl}


def sound_shardA_selftest(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """HP3 (unit C) -- validate the sound value-single-source shardA against the real blob@0 + trace-opener on real
    BCH-2026 libauth (no mocks): [blob@0, trace_opener, shardA] -> shardA accepts (52 cells read cross-input from the
    opener, deep_alphas+masks from blob@0, dedup == eager, Sum self-bound to carry_out_pre); forged carry_out_pre ->
    REJECT fail-closed (the self-bind). This is the R4-B1 fix: the trace value is opener-merkle-bound, not witness."""
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    assert pf.get("deep") and STK.verify(pf)[0], "HP3-C: shardA proof did not verify"
    nonced, sblob, scov, offs = _build_sound_blob(pf, fold_step)
    blob0 = {"redeem": S.tokens_to_asm(scov), "unlock": S.tokens_to_asm([PUSH(nonced), PUSH(sblob)])}
    qi = 0
    trace_op = _sound_looped_trace_opener(pf, offs, nq)                # LEVER-1: aggregated trace-opener is input 1
    shardA = _sound_shardA_one(pf, qi, offs, opener_idx=1, nq=nq)      # reads block_qi's cells cross-input at its offset

    def _run(inputs, idx):
        res = D._p2sh_multi(inputs, evaluate=[idx])
        return {x["idx"]: x for x in res.get("results", [])}.get(idx, {})

    r = _run([blob0, trace_op, shardA], 2)                             # shardA is input 2
    assert r.get("ok"), "HP3-C: honest sound shardA REJECTED: %s" % str(r.get("error"))[:180]
    bad_carry = bytearray(_sound_shardA_carry(pf, qi)); bad_carry[0] ^= 0x01
    carry_in_pre = S._acc_preimage((0, 0)) + S._acc_preimage((0, 0))
    bad_unl = S.tokens_to_asm([PUSH(bytes(bad_carry)), PUSH(carry_in_pre), PUSH(b"\x00" * 3400)])
    rb = _run([blob0, trace_op, {"redeem": shardA["redeem"], "unlock": bad_unl}], 2)
    assert not rb.get("ok"), "HP3-C: forged carry_out_pre accepted (self-bind broken)"
    print("HP3-C sound value-single-source shardA (52 cells opener-sourced, deep_alphas+masks from blob@0, dedup==eager, "
          "carry self-bound): OK -- honest accept; forged carry_out_pre REJECT. R4-B1 closed.")
    return True


def _sound_tail_terms(pf, qi, sblob, offs):
    """Reference data for the sound tail [104:138]: the 34 term values (sel[k]/rw[k] PUBLIC + comp cc), the ood/alpha
    slices (extracted from the sound blob@0 so they == what the tail reads on-chain), the SEL count ns, and the
    segment-A carry (Sz/Szg over [0:104]). Returns (val_sel, cc, ood_T, alp_T, ns, SzA, SzgA)."""
    nf = len(STK.FLAT_COLS); q = pf["queries"][qi]; k = q["k"]
    mt, T = STK.ct_build_layout(pf["stmt"]["depth"])
    N0, oT, oN, of, Hd, Dd, ls = STK._setup(T, pf["blowup"])
    ly = STK.ct_public_layout(mt, T); sv = STK._selector_vectors(ly, T, N0, oT, oN, of)
    val_sel = [(sv[kk][k], 0) for kk in _SELSPEC]                     # 8 selspec
    val_sel += [(sv["rc"][i][k], 0) for i in range(S.WIDTH)]          # WIDTH range-check
    val_sel += [(sv["chain_minv"][j][k], 0) for j in range(S.WIDTH)]  # WIDTH chain-minv
    ns = len(val_sel)                                                 # SEL count (rw/comp separate)
    val_sel.append((sv["range_weight"][k], 0))                        # rw@ns

    def _cell(off):
        return int.from_bytes(sblob[off:off + 8], "little")
    ood_T = [(_cell(offs["ood_off"] + 16 * (104 + i)), _cell(offs["ood_off"] + 16 * (104 + i) + 8)) for i in range(34)]
    alp_T = [(_cell(offs["alpha_off"] + 16 * (104 + i)), _cell(offs["alpha_off"] + 16 * (104 + i) + 8)) for i in range(34)]
    cells_base = [q["ck"][c] for c in STK.FLAT_COLS]
    da = [tuple(a) for a in pf["deep_alphas"]]
    ood_A = [(_cell(offs["ood_off"] + 16 * i), _cell(offs["ood_off"] + 16 * i + 8)) for i in range(104)]
    (SzA, SzgA), _oc = S.run_deep_sum_part_dedup(nf, cells_base, da[:2 * nf], ood_A)
    return val_sel, tuple(q["cc"]), ood_T, alp_T, ns, SzA, SzgA


def _sound_tailfinal_one(pf, qi, offs, sblob, shardA_idx, comp_opener_idx, nq, pad=1400):
    """HP11 tail/final-fusion -- ONE input per query that does BOTH the sound tail [104:138] AND the final-combine q,
    eliding the separate final input + the tail's carry_out exposure + the tail->final cross-input read (structural
    simplification + byte saving; the tail-total flows in-place to q). Redeem (top of unlock consumed first): drop pad;
    ONE shared _field_prelude; hint-validate invz/invzg (HP5.1 GF(p^2) inv-check, leaves [q_pre, invz]); the tail terms
    (sel/rw PUBLIC-baked, comp cc from the comp-opener, ood/alpha from blob@0) run _tail_standalone -> tail sum T;
    read the shardA carry A cross-input; _ci_top_add -> TOTAL Sum_z||Sum_zg on the stack (no exposure/self-bind);
    deep_final_combine_qbound(from_stack=True) computes q = invz*Sum_z + invzg*Sum_zg from the stack total and self-binds
    q == q_pre (the value the agg-FRI reads as its layer-0 value). Soundness == the tail+final pair: the total is the
    direct in-redeem computation (no free witness); shardA's carry is still cross-input read (shardA self-binds it);
    invz/invzg still hint-validated vs x_k + z/z*g from blob@0. Returns {redeem, unlock, qref}."""
    nf = len(STK.FLAT_COLS); q = pf["queries"][qi]; k = q["k"]
    mt, T = STK.ct_build_layout(pf["stmt"]["depth"]); Dd = STK._setup(T, pf["blowup"])[5]
    xk = F.from_base(Dd[k]); z = tuple(pf["z"]); zg = tuple(pf["zg"])
    invz = F.inv(F.sub(xk, z)); invzg = F.inv(F.sub(xk, zg))
    val_sel, cc, ood_T, alp_T, ns, SzA, SzgA = _sound_tail_terms(pf, qi, sblob, offs)
    val_T = val_sel + [(cc[0], cc[1])]
    (SzT, SzgT), _oc = S.run_deep_sum_part_dual(104, 138, nf, ns, SzA, SzgA, val_T, ood_T, alp_T)   # TOTAL A+T
    qref, _oc2 = run_deep_final_combine(SzT, SzgT, invz, invzg, dual_carry=True)
    q_pre = enc8(qref[0] % P) + enc8(qref[1] % P)
    baked = S.tokens_to_asm([tok for pair in val_sel for tok in (NUM(pair[0] % P), NUM(pair[1] % P))])  # sel/rw PUBLIC
    coff = _looped_opener_blob_off(pf, nq, qi, 2, lambda q: b"\x00" * 16, lambda q: q["cp"])
    cc_read = ("%s OP_INPUTBYTECODE <0x%s> OP_SPLIT OP_NIP <0x18> OP_SPLIT OP_DROP "
               % (_idx_op(comp_opener_idx), S.encode_num(coff).hex())
               + S.tokens_to_asm(list(S.split_cells_loop(3, prefix=0)) + [OP("DROP")]))   # cc0, cc1 (drop k)
    slice_read = _read_sound_slice(offs, 104, 138)
    carry_read = "%s OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x20> OP_SPLIT OP_DROP " % _idx_op(shardA_idx)
    xk_push = S.tokens_to_asm([NUM(xk[0] % P), NUM(xk[1] % P)])
    read_z = _read_blob_field(offs["z_off"], 16) + S.tokens_to_asm(list(S.split_cells_loop(2, prefix=0)))
    read_zg = _read_blob_field(offs["zg_off"], 16) + S.tokens_to_asm(list(S.split_cells_loop(2, prefix=0)))
    inv_chk = S.tokens_to_asm(S.ext_sub_stack_prog() + S.ext_inv_check_prog())
    hint_invz = " ".join([S.tokens_to_asm([NUM(3), OP("PICK"), NUM(3), OP("PICK")]), xk_push, read_z.strip(), inv_chk])
    hint_invzg = " ".join([S.tokens_to_asm([NUM(1), OP("PICK"), NUM(1), OP("PICK")]), xk_push, read_zg.strip(), inv_chk])
    red = " ".join(["OP_DROP", S.tokens_to_asm(S._field_prelude()).strip(), hint_invz, hint_invzg,
                    baked.strip(), cc_read.strip(), slice_read.strip(),
                    S.tokens_to_asm(_tail_standalone(34, ns)).strip(),
                    carry_read.strip(), S.tokens_to_asm(_ci_top_add()).strip(),
                    S.tokens_to_asm(S.deep_final_combine_qbound_prog(from_stack=True)).strip()])
    unl = S.tokens_to_asm([PUSH(q_pre), NUM(invz[0] % P), NUM(invz[1] % P), NUM(invzg[0] % P), NUM(invzg[1] % P),
                           PUSH(b"\x00" * pad)])
    return {"redeem": red, "unlock": unl, "qref": qref, "invz": invz, "invzg": invzg}


def sound_tailfinal_selftest(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """HP11 tail/final-fusion -- validate the fused tail+final input on real BCH-2026 libauth (no mocks):
    [blob@0, trace_opener, shardA, comp_opener, tailfinal] -> tailfinal accepts (q from the in-place tail total, bound to
    q_pre; invz/invzg hint-validated; == the separate tail+final pair's q); forged q_pre REJECT."""
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    assert pf.get("deep") and STK.verify(pf)[0], "HP11-fusion: proof did not verify"
    nonced, sblob, scov, offs = _build_sound_blob(pf, fold_step)
    blob0 = {"redeem": S.tokens_to_asm(scov), "unlock": S.tokens_to_asm([PUSH(nonced), PUSH(sblob)])}
    qi = 0
    trace_op = _sound_looped_trace_opener(pf, offs, nq)               # input 1
    comp_op = _sound_looped_comp_opener(pf, offs, nq)                 # input 2
    shardA = _sound_shardA_one(pf, qi, offs, opener_idx=1, nq=nq)     # input 3
    tf = _sound_tailfinal_one(pf, qi, offs, sblob, shardA_idx=3, comp_opener_idx=2, nq=nq)   # input 4 (fused)
    base = [blob0, trace_op, comp_op, shardA]

    def _run(ins, idx):
        res = D._p2sh_multi(ins, evaluate=[idx])
        return {x["idx"]: x for x in res.get("results", [])}.get(idx, {})

    r = _run(base + [tf], 4)
    assert r.get("ok"), "HP11-fusion: honest fused tailfinal REJECTED: %s" % str(r.get("error"))[:200]
    q_pre = S.enc8(tf["qref"][0] % P) + S.enc8(tf["qref"][1] % P)
    # forged q_pre -> the q-bind (deep_final_combine self-bind q == q_pre) REJECTS
    bad_q = bytearray(q_pre); bad_q[0] ^= 0x01
    bad_unl_q = S.tokens_to_asm([PUSH(bytes(bad_q)), NUM(tf["invz"][0] % P), NUM(tf["invz"][1] % P),
                                 NUM(tf["invzg"][0] % P), NUM(tf["invzg"][1] % P), PUSH(b"\x00" * 1400)])
    assert not _run(base + [{"redeem": tf["redeem"], "unlock": bad_unl_q}], 4).get("ok"), \
        "HP11-fusion: forged q_pre accepted (q-bind broken)"
    # forged invz -> the GF(p^2) hint-check invz*(x_k - z) == 1 REJECTS (HP5.1 coverage, runs before the q compute)
    bad_unl_iz = S.tokens_to_asm([PUSH(q_pre), NUM((tf["invz"][0] + 1) % P), NUM(tf["invz"][1] % P),
                                  NUM(tf["invzg"][0] % P), NUM(tf["invzg"][1] % P), PUSH(b"\x00" * 1400)])
    assert not _run(base + [{"redeem": tf["redeem"], "unlock": bad_unl_iz}], 4).get("ok"), \
        "HP11-fusion: forged invz accepted (GF(p^2) hint-check broken)"
    print("HP11 tail/final-fusion (1 input does tail+final; total flows in-place, no cross-read; q bound to q_pre; "
          "invz/invzg hint-validated): OK -- honest accept; forged q_pre + forged invz REJECT.")
    return True


def _build_sound_query_inputs(pf, offs, sblob, nq):
    """LEVER-1 (opener-aggregation) + HP11 (tail/final-fusion) -- build the sound DEEP chains with AGGREGATED openers: 2
    shared looped openers (trace-opener@1, comp-opener@2, each verifying ALL nq openings in one pinned-count loop) then 2
    inputs/query in a fixed order so cross-input indices are deterministic: base=3+2*qi -> shardA@base (reads its trace
    cells from the aggregated trace-opener@1 at block_qi's build-time offset), tailfinal@base+1 (the FUSED tail+final:
    reads shardA@base carry + comp cc from the aggregated comp-opener@2, runs the tail, adds the carry in-place, computes
    q and exposes q_pre for the agg-FRI). Returns the input list (2 aggregated openers + shardA+tailfinal for all nq
    queries), to append after blob@0."""
    ins = [_sound_looped_trace_opener(pf, offs, nq), _sound_looped_comp_opener(pf, offs, nq)]   # inputs 1, 2
    for qi in range(nq):
        base = 3 + 2 * qi
        ins.append(_sound_shardA_one(pf, qi, offs, opener_idx=1, nq=nq))
        ins.append(_sound_tailfinal_one(pf, qi, offs, sblob, shardA_idx=base, comp_opener_idx=2, nq=nq))
    return ins


def _sound_comp_inputs(pf, sblob, offs):
    """HP6.2/HP7 value-foundation -- the REAL AIR-an-z composition inputs (== what verify():475 uses, so
    run_comp_split produces comp == comp_z == comp_root, not the demo's _ev() random). OOD from the proof (cur=Pcz,
    nxt=Pczg, pub=sel_z, w=rw_zg -- all committed in the blob masks); AIR alphas alpha_T/alpha_B FS-derived and
    EXTRACTED FROM THE SOUND BLOB fs_out (HP7.2 -- proves blob-single-source, must == the FS transcript draw); the
    z-normalizers qf=(z-last)*ZHz_inv and bound_invX=[1/(z-Hd[row])] derived from z (HP5.2 hint-checked on-chain).
    Returns a dict of every input run_comp_split / the on-chain comp-parts consume."""
    stmt = pf["stmt"]; meta, T = STK.ct_build_layout(stmt["depth"])
    N, oT, oN, of, Hd, Dd, last = STK._setup(T, pf["blowup"])
    fs = STK.FS(); fs.absorb(bytes.fromhex(pf["tp_root"])); fs.absorb_int(stmt["root"]); fs.absorb_int(stmt["nf"])
    for cm in stmt["cm_out"]:
        fs.absorb_int(cm)
    n_T = STK.ct_num_transition_residuals(); bcons = STK.ct_boundary_constraints(meta, stmt); n_b = len(bcons)
    alphas_T = [STK._ext_challenge(fs) for _ in range(n_T)]
    alphas_B = [STK._ext_challenge(fs) for _ in range(n_b)]

    def _bx(o):
        return (int.from_bytes(sblob[o:o + 8], "little"), int.from_bytes(sblob[o + 8:o + 16], "little"))
    a0 = offs["prefd_len"]                                            # fs_out alphas section start
    aT_blob = [_bx(a0 + 16 * i) for i in range(n_T)]
    aB_blob = [_bx(a0 + 16 * (n_T + j)) for j in range(n_b)]
    assert aT_blob == alphas_T and aB_blob == alphas_B, "HP7.2: blob fs_out alphas != FS-derived AIR alphas"
    import native_poseidon2 as P2
    z = tuple(pf["z"]); ZHz_inv = F.inv(F.sub(F.power(z, T), F.ONE))
    _SELSPEC2 = ("is_full", "is_partial", "is_block_start", "is_reabsorb", "is_range", "is_range_first",
                 "is_range_step", "is_range_last")
    sel_z = pf["sel_z"]; W = P2.WIDTH
    pubZ = {nm: tuple(sel_z[i]) for i, nm in enumerate(_SELSPEC2)}
    pubZ["rc"] = [tuple(sel_z[8 + i]) for i in range(W)]
    pubZ["chain_minv"] = [tuple(sel_z[8 + W + j]) for j in range(W)]
    curZ = {c: tuple(pf["Pcz"][c]) for c in pf["Pcz"]}; nxtZ = {c: tuple(pf["Pczg"][c]) for c in pf["Pczg"]}
    qfZ = F.mul(F.sub(z, F.from_base(last)), ZHz_inv)
    _tf, _st = CT.build_ct_trace(CT._demo_witness(depth=2)); _fc, _T, _meta = CT.build_full_flat_trace(_tf)
    _cons = CT.ct_boundary_constraints_ext(_meta, _st)
    bixZ = [F.inv(F.sub(z, F.from_base(Hd[row]))) for (row, _fn) in _cons]
    return {"cur": curZ, "nxt": nxtZ, "pub": pubZ, "w": tuple(pf["rw_zg"]), "aT": alphas_T, "aB": alphas_B,
            "qf": qfZ, "bix": bixZ, "n_T": n_T, "n_b": n_b, "cons": _cons, "st": _st, "meta": _meta}


def sound_comp_reference_selftest(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """HP6.2/HP7 value-foundation -- validate (pure reference, no VM) that the REAL AIR-an-z inputs (OOD from the
    proof + AIR alphas extracted from the sound blob fs_out + z-normalizers) run_comp_split to comp == comp_z ==
    comp_root. This is the value the on-chain sound comp-parts must reproduce and bind to comp_root (HP6.2)."""
    import native_poseidon2 as P2
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    assert pf.get("deep") and STK.verify(pf)[0], "HP-comp-ref: proof did not verify"
    nonced, sblob, scov, offs = _build_sound_blob(pf, fold_step)
    ci = _sound_comp_inputs(pf, sblob, offs)
    _st, _meta = ci["st"], ci["meta"]
    _rspec = [(CT.HELD_COLS.index("vh_" + rm["vname"]), rm["src"] is not None) for rm in _meta["range"]]
    _minvcap = [CT.M_EXT_INV[k2] for k2 in range(P2.RATE, P2.WIDTH)]
    _split = S.comp_split_default_parts(_minvcap)
    comp, _stats = S.run_comp_split(_split, CT.M_EXT, P2.MAT_DIAG12, _minvcap, CT.M_EXT_INV[0], CT.N_OUT, _rspec,
                                    _st["root"], _st["nf"], _st["cm_out"], ci["cur"], ci["nxt"], ci["pub"], ci["w"],
                                    ci["aT"], ci["qf"], ci["bix"], ci["aB"], CT.HELD_COLS, sbox_looped=True,
                                    state_looped=True)
    assert comp == tuple(pf["comp_z"]), "HP-comp-ref: run_comp_split(real) %s != comp_z %s" % (comp, tuple(pf["comp_z"]))
    print("HP6.2/HP7 comp value-foundation: OK -- run_comp_split(real OOD from proof + AIR alphas from blob fs_out + "
          "z-normalizers) == comp_z == comp_root (n_T=%d, n_b=%d). blob alphas == FS-derived verified." % (ci["n_T"], ci["n_b"]))
    return True


_COMP_SEL_IDX = {"isf": 0, "isp": 1, "isbs": 2, "isra": 3, "is_range": 4, "is_range_first": 5,
                 "is_range_step": 6, "is_range_last": 7}
for _k in range(S.WIDTH):
    _COMP_SEL_IDX["rc%d" % _k] = 8 + _k
    _COMP_SEL_IDX["cm%d" % _k] = 20 + _k


def _comp_mask_idx(name):
    """HP7.1 -- the ext-index of a _TRANS_ASM_OPS OOD cell within the sound blob masks section (138 ext at ood_off).
    VERIFIED against the real blob (all 101 _TRANS_ASM_OPS cells, 0 mismatches): cur s/u2/u4/u6 -> Pcz mask 2c ; cur
    held vh -> Pcz 2c ; nxt ns/nvh -> Pczg mask 2c+1 ; selectors -> 104+sel_idx ; w_next -> 136 (c = FLAT_COLS.index)."""
    FC = STK.FLAT_COLS; HC = CT.HELD_COLS
    if name in _COMP_SEL_IDX:
        return 104 + _COMP_SEL_IDX[name]
    if name == "w_next":
        return 136
    if name.startswith("nvh"):
        return 2 * FC.index(HC[int(name[3:])]) + 1
    if name.startswith("ns"):
        return 2 * FC.index("s%d" % int(name[2:])) + 1
    if name.startswith("vh"):
        return 2 * FC.index(HC[int(name[2:])])
    return 2 * FC.index(name)


def _sound_comp_trans_part(offs, ci, jobs, res_off, acc_in, minvcap, carry_idx=None, pad=2000):
    """HP4/HP7.1/HP7.2 -- one SOUND transition comp-part. Sources the inputs of the UNCHANGED
    comp_split_trans_part_prog(carry_bound=True) from the blob/cross-input instead of witness literals: the OOD base_ops
    cells from the blob masks (HP7.1, via an alt-stack reorder -- read the whole masks section once, PICK the part's
    base_ops to the alt stack in reverse order, drop the masks, then FROMALT them back in base_ops order), the alpha_T
    slice from blob fs_out (HP7.2), and carry_in cross-input from the predecessor part's exposed carry_out (HP4, input
    carry_idx; baked (0,0) for the first part). The redeem builds exactly the [carry_out_pre@0, carry_in_pre@1, alpha,
    OOD] layout the prog PICKs from, so the prog runs verbatim -- it splits carry_in_pre into acc_in, MACs the trans_v,
    and binds the computed acc_out == carry_out_pre (this part's exposed output, in the unlock). Returns
    ({redeem, unlock}, acc_out) -- acc_out is the next part's carry_in."""
    import native_poseidon2 as P2
    part_n_res = sum(S._job_nres(j, minvcap) for j in jobs)
    base_ops = S._trans_part_base_ops(jobs)
    alpha_slice = ci["aT"][res_off:res_off + part_n_res]
    # reference acc_out: run the NON-carry_bound prog once to get the carry this part exposes
    u0 = S.comp_split_trans_part_unlock(jobs, acc_in, alpha_slice, ci["cur"], ci["nxt"], ci["pub"], ci["w"], CT.HELD_COLS)
    pr0 = S.comp_split_trans_part_prog(jobs, part_n_res, CT.M_EXT, P2.MAT_DIAG12, minvcap,
                                       sbox_looped=True, state_looped=True)
    vm = S.VM(); vm.run(S._field_prelude() + u0 + pr0)
    acc_out = (S.decode_num(vm.s[-2]), S.decode_num(vm.s[-1]))
    carry_out_pre = S._acc_preimage(acc_out)
    NM = 138                                                          # masks ext count (blob masks section)
    read_masks = _read_blob_field(offs["ood_off"], 16 * NM) + S.tokens_to_asm(list(S.split_cells_loop(2 * NM, prefix=0)))
    reorder = []                                                     # main: [carry_out_pre(0), 276 masks(1..276)] = 277
    for nm in reversed(base_ops):                                    # reverse + (l1 then l0) so FROMALT restores forward
        m = _comp_mask_idx(nm)
        reorder += [NUM(276 - (2 + 2 * m)), OP("PICK"), OP("TOALT")]  # l1 -> alt
        reorder += [NUM(276 - (1 + 2 * m)), OP("PICK"), OP("TOALT")]  # l0 -> alt (alt top)
    drop_masks = [OP("DROP")] * (2 * NM)                             # clear the 276 mask limbs (carry_out_pre remains)
    if carry_idx is None:
        carry_read = S.tokens_to_asm([PUSH(S._acc_preimage((0, 0)))])                   # first part: carry_in = 0 (baked)
    else:
        carry_read = "%s OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x10> OP_SPLIT OP_DROP " % _idx_op(carry_idx)
    a0 = offs["prefd_len"] + 16 * res_off                           # alpha_T slice in fs_out
    read_alpha = _read_blob_field(a0, 16 * part_n_res) + S.tokens_to_asm(list(S.split_cells_loop(2 * part_n_res, prefix=0)))
    from_ood = S.tokens_to_asm([OP("FROMALT")] * (2 * len(base_ops)))
    prog = S.comp_split_trans_part_prog(jobs, part_n_res, CT.M_EXT, P2.MAT_DIAG12, minvcap,
                                        sbox_looped=True, state_looped=True, carry_bound=True)
    red = " ".join(["OP_DROP", read_masks.strip(), S.tokens_to_asm(reorder + drop_masks).strip(),
                    carry_read.strip(), read_alpha.strip(), from_ood.strip(),
                    S.tokens_to_asm(S._field_prelude() + prog).strip()])
    unl = S.tokens_to_asm([PUSH(carry_out_pre), PUSH(b"\x00" * pad)])
    return {"redeem": red, "unlock": unl}, acc_out


def sound_comp_trans_selftest(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """HP4/HP7.1/HP7.2 -- validate the FIRST sound transition comp-part (sbox, 12 lanes) on real BCH-2026 libauth (no
    mocks): [blob@0, sbox_part] -> the part accepts (base_ops OOD read from blob masks via the alt-stack reorder,
    alpha_T from blob fs_out, carry_in=(0,0), acc_out bound to the exposed carry_out_pre); a forged carry_out_pre
    REJECTS (the _comp_producer_bind acc_out==carry_out_pre@0)."""
    import native_poseidon2 as P2
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    assert pf.get("deep") and STK.verify(pf)[0], "HP4/7: proof did not verify"
    nonced, sblob, scov, offs = _build_sound_blob(pf, fold_step)
    blob0 = {"redeem": S.tokens_to_asm(scov), "unlock": S.tokens_to_asm([PUSH(nonced), PUSH(sblob)])}
    ci = _sound_comp_inputs(pf, sblob, offs)
    minvcap = [CT.M_EXT_INV[k2] for k2 in range(P2.RATE, P2.WIDTH)]
    split = S.comp_split_default_parts(minvcap)
    part, acc_out = _sound_comp_trans_part(offs, ci, split[0], 0, (0, 0), minvcap, carry_idx=None)

    def _run(inputs, idx):
        res = D._p2sh_multi(inputs, evaluate=[idx])
        return {x["idx"]: x for x in res.get("results", [])}.get(idx, {})

    r = _run([blob0, part], 1)
    assert r.get("ok"), "HP4/7: honest sound sbox comp-part REJECTED: %s" % str(r.get("error"))[:200]
    bad = bytearray(S._acc_preimage(acc_out)); bad[0] ^= 0x01
    bad_part = {"redeem": part["redeem"], "unlock": S.tokens_to_asm([PUSH(bytes(bad)), PUSH(b"\x00" * 1500)])}
    assert not _run([blob0, bad_part], 1).get("ok"), "HP4/7: forged carry_out_pre accepted (producer-bind broken)"
    print("HP4/HP7.1/HP7.2 sound sbox comp-part (OOD from blob masks via alt-reorder, alpha_T from blob fs_out, "
          "acc_out bound to carry_out_pre): OK -- honest accept; forged carry_out_pre REJECT.")
    return True


def _build_sound_comp_trans_parts(offs, ci, minvcap, base_idx):
    """LEVER-2/HP4 -- build the 3 sound transition comp-parts (sbox | state | chain+hold+range) as a carry chain: part
    0 bakes carry_in=(0,0); each later part i reads its carry_in cross-input from the predecessor's exposed carry_out
    (input base_idx+i-1). Returns (inputs, acc_T) where acc_T = the full transition accumulator the final part reads."""
    split = S.comp_split_default_parts(minvcap)
    ins = []; acc = (0, 0); res_off = 0
    for i, jobs in enumerate(split):
        cidx = None if i == 0 else base_idx + i - 1
        inp, acc = _sound_comp_trans_part(offs, ci, jobs, res_off, acc, minvcap, carry_idx=cidx)
        ins.append(inp)
        res_off += sum(S._job_nres(j, minvcap) for j in jobs)
    return ins, acc


def sound_comp_trans_chain_selftest(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """LEVER-2/HP4 -- validate the full sound transition comp-part carry chain on real BCH-2026 libauth (no mocks):
    [blob@0, sbox_part, state_part, chain+hold+range_part] -> all 3 accept (each OOD from blob masks, alpha_T from blob
    fs_out, carry_in cross-input from the predecessor's carry_out); a forged part-0 carry_out REJECTS both part 0
    itself (producer self-bind) and part 1 (the cross-input consumer bind), single-sourcing the carry (R8-B1/HP4)."""
    import native_poseidon2 as P2
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    assert pf.get("deep") and STK.verify(pf)[0], "HP4-chain: proof did not verify"
    nonced, sblob, scov, offs = _build_sound_blob(pf, fold_step)
    blob0 = {"redeem": S.tokens_to_asm(scov), "unlock": S.tokens_to_asm([PUSH(nonced), PUSH(sblob)])}
    ci = _sound_comp_inputs(pf, sblob, offs)
    minvcap = [CT.M_EXT_INV[k2] for k2 in range(P2.RATE, P2.WIDTH)]
    parts, acc_T = _build_sound_comp_trans_parts(offs, ci, minvcap, base_idx=1)
    res = D._p2sh_multi([blob0] + parts, evaluate=[1, 2, 3])
    rs = {x["idx"]: x for x in res.get("results", [])}
    for i in (1, 2, 3):
        if not rs.get(i, {}).get("ok"):
            print("  [FAIL] comp trans-part %d: %s" % (i, str(rs.get(i, {}).get("error"))[:120]))
    assert all(rs.get(i, {}).get("ok") for i in (1, 2, 3)), "HP4-chain: not all trans parts accept"
    p0acc = _sound_comp_trans_part(offs, ci, S.comp_split_default_parts(minvcap)[0], 0, (0, 0), minvcap)[1]
    badpre = bytearray(S._acc_preimage(p0acc)); badpre[0] ^= 0x01
    bad_p0 = {"redeem": parts[0]["redeem"], "unlock": S.tokens_to_asm([PUSH(bytes(badpre)), PUSH(b"\x00" * 2000)])}
    rb = D._p2sh_multi([blob0, bad_p0, parts[1], parts[2]], evaluate=[1, 2])
    rbs = {x["idx"]: x for x in rb.get("results", [])}
    assert not rbs.get(1, {}).get("ok"), "HP4-chain: part 0 accepted a forged carry_out (producer self-bind broken)"
    assert not rbs.get(2, {}).get("ok"), "HP4-chain: part 1 accepted a forged predecessor carry_out (cross-input bind broken)"
    print("LEVER-2/HP4 sound comp trans-part carry chain: 3/3 accept (sbox|state|chain+hold+range, OOD from masks, "
          "carry cross-input); forged part-0 carry_out REJECTS producer + consumer.")
    return True


def _sound_comp_final_part(pf, offs, ci, minvcap, carry_idx, pad=3600, qf_override=None):
    """HP6.2/HP5.2/HP7 -- the SOUND final boundary comp-part (comp_split_final_part_prog carry_bound+comp_bound), all
    inputs from the blob/cross-input: comp_preimage@0 = _acc_preimage(comp_z) bound == blob comp_z (mask 137, HP6.2 ->
    the computed comp is forced to the FS-committed comp_z); carry_in = acc_T cross-input from the last trans part
    (HP4); qf/bound_invX witness + on-chain z-eval hint-check vs z from blob (HP5.2, ext_zeval_hint_check_prog on
    PICK-copies of the SAME layout qf/bix, so the forced-unique values are the ones the prog uses); alpha_B from blob
    fs_out (HP7.2); s0..s{W-1}+vh0..3 from blob masks (HP7.1 reorder). Then the UNCHANGED prog binds computed comp ==
    comp_preimage. Layout [comp_preimage@0, carry_in@1, qf, bound_invX, alpha_B, s, vh] = 2*TU items. qf_override
    forges qf for the HP5.2-reject test."""
    W = S.WIDTH
    meta, T = STK.ct_build_layout(pf["stmt"]["depth"])
    N, oT, oN, of, Hd, Dd, last = STK._setup(T, pf["blowup"])
    log2T = T.bit_length() - 1
    n_b = len(ci["aB"]); n_T = ci["n_T"]
    rspec = [(CT.HELD_COLS.index("vh_" + rm["vname"]), rm["src"] is not None) for rm in ci["meta"]["range"]]
    assert S._n_boundary_residuals(CT.N_OUT, rspec) == n_b, "final part n_b mismatch"
    st = ci["st"]; qf = qf_override or ci["qf"]; bix = ci["bix"]
    comp_pre = S._acc_preimage(tuple(pf["comp_z"]))
    hd_vals = [Hd[row] for (row, _fn) in ci["cons"]]
    TU = 2 + 2 * n_b + W + 4
    base_ops = ["s%d" % k for k in range(W)] + ["vh%d" % i for i in range(4)]
    NM = 138
    hp62 = "OP_DUP " + _read_blob_field(offs["ood_off"] + 16 * 137, 16) + "OP_EQUALVERIFY "   # comp_preimage == blob comp_z
    carry_read = "%s OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x10> OP_SPLIT OP_DROP " % _idx_op(carry_idx)
    push_qf = S.tokens_to_asm([NUM(qf[0] % P), NUM(qf[1] % P)])
    push_bix = S.tokens_to_asm([tok for b in bix for tok in (NUM(b[0] % P), NUM(b[1] % P))])
    read_aB = (_read_blob_field(offs["prefd_len"] + 16 * n_T, 16 * n_b)
               + S.tokens_to_asm(list(S.split_cells_loop(2 * n_b, prefix=0))))
    read_masks = _read_blob_field(offs["ood_off"], 16 * NM) + S.tokens_to_asm(list(S.split_cells_loop(2 * NM, prefix=0)))
    reorder = []
    for nm in reversed(base_ops):
        m = _comp_mask_idx(nm)
        reorder += [NUM(276 - (2 + 2 * m)), OP("PICK"), OP("TOALT")]
        reorder += [NUM(276 - (1 + 2 * m)), OP("PICK"), OP("TOALT")]
    tail_layout = S.tokens_to_asm(reorder + [OP("DROP")] * (2 * NM)) + " " + S.tokens_to_asm([OP("FROMALT")] * (2 * len(base_ops)))
    read_z = _read_blob_field(offs["z_off"], 16) + S.tokens_to_asm(list(S.split_cells_prog(2, prefix=0)))
    copies = S.tokens_to_asm([tok for _ in range(2 + 2 * n_b) for tok in (NUM(2 * TU - 1), OP("PICK"))])
    hint = S.tokens_to_asm(S.ext_zeval_hint_check_prog(log2T, last, hd_vals))
    drop_hint = S.tokens_to_asm([OP("DROP")] * (4 + 2 * n_b))                    # z + qf-copy + bix-copy
    prog = S.comp_split_final_part_prog(CT.M_EXT_INV[0], CT.N_OUT, rspec, st["root"], st["nf"], st["cm_out"], n_b,
                                        carry_bound=True, comp_bound=True)
    red = " ".join(["OP_DROP", hp62.strip(), carry_read.strip(), push_qf.strip(), push_bix.strip(),
                    read_aB.strip(), read_masks.strip(), tail_layout.strip(),
                    S.tokens_to_asm(S._field_prelude()).strip(), read_z.strip(), copies.strip(), hint.strip(),
                    drop_hint.strip(), S.tokens_to_asm(prog).strip()])
    unl = S.tokens_to_asm([PUSH(comp_pre), PUSH(b"\x00" * pad)])
    return {"redeem": red, "unlock": unl}


def _build_sound_comp_parts(pf, offs, ci, minvcap, base_idx):
    """HP4/HP5.2/HP6.2/HP7 -- the full sound comp(z) split: 3 transition parts (carry chain) + the final boundary part
    (reads acc_T from the last trans part, binds comp == blob comp_z). base_idx = the first part's input index."""
    trans, _acc_T = _build_sound_comp_trans_parts(offs, ci, minvcap, base_idx)
    final = _sound_comp_final_part(pf, offs, ci, minvcap, carry_idx=base_idx + len(trans) - 1)
    return trans + [final]


def sound_comp_parts_selftest(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """HP4/HP5.2/HP6.2/HP7 -- validate the FULL sound comp(z) split (3 trans parts + final) on real BCH-2026 libauth
    (no mocks): [blob@0, sbox, state, chain+hold+range, final] -> all accept (OOD/alpha from blob, carry chain, comp
    bound == blob comp_z); a forged comp_preimage (!= blob comp_z) REJECTS (HP6.2); a forged qf REJECTS (HP5.2)."""
    import native_poseidon2 as P2
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    assert pf.get("deep") and STK.verify(pf)[0], "comp-parts: proof did not verify"
    nonced, sblob, scov, offs = _build_sound_blob(pf, fold_step)
    blob0 = {"redeem": S.tokens_to_asm(scov), "unlock": S.tokens_to_asm([PUSH(nonced), PUSH(sblob)])}
    ci = _sound_comp_inputs(pf, sblob, offs)
    minvcap = [CT.M_EXT_INV[k2] for k2 in range(P2.RATE, P2.WIDTH)]
    parts = _build_sound_comp_parts(pf, offs, ci, minvcap, base_idx=1)
    res = D._p2sh_multi([blob0] + parts, evaluate=[1, 2, 3, 4])
    rs = {x["idx"]: x for x in res.get("results", [])}
    for i in (1, 2, 3, 4):
        if not rs.get(i, {}).get("ok"):
            print("  [FAIL] comp-part %d: %s" % (i, str(rs.get(i, {}).get("error"))[:140]))
    assert all(rs.get(i, {}).get("ok") for i in (1, 2, 3, 4)), "comp-parts: not all parts accept"
    # forged comp_preimage (!= blob comp_z) -> HP6.2 reject (same pad as honest, so the ONLY change is the forged value)
    fin = parts[3]; badc = bytearray(S._acc_preimage(tuple(pf["comp_z"]))); badc[0] ^= 0x01
    bad_fin = {"redeem": fin["redeem"], "unlock": S.tokens_to_asm([PUSH(bytes(badc)), PUSH(b"\x00" * 3600)])}
    rb = D._p2sh_multi([blob0, parts[0], parts[1], parts[2], bad_fin], evaluate=[4])
    assert not {x["idx"]: x for x in rb.get("results", [])}.get(4, {}).get("ok"), "HP6.2: forged comp_preimage accepted"
    # forged qf (!= (z-last)*ZHz_inv) -> HP5.2 z-eval hint-check reject
    bad_qf = ((ci["qf"][0] + 1) % P, ci["qf"][1])
    fin_bq = _sound_comp_final_part(pf, offs, ci, minvcap, carry_idx=4, qf_override=bad_qf)
    rq = D._p2sh_multi([blob0, parts[0], parts[1], parts[2], fin_bq], evaluate=[4])
    assert not {x["idx"]: x for x in rq.get("results", [])}.get(4, {}).get("ok"), "HP5.2: forged qf accepted (hint-check broken)"
    print("HP4/HP5.2/HP6.2/HP7 FULL sound comp(z) split: 4/4 accept (3 trans + final, OOD/alpha from blob, carry chain, "
          "comp bound == blob comp_z, qf/bix z-eval hint-checked); forged comp_preimage (HP6.2) + forged qf (HP5.2) "
          "REJECT. comp-parts txBytes=%d" % res.get("txBytes", -1))
    return True


def build_sound_verifier_inputs(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """Assemble the COMPLETE sound verifier tx from the per-unit-validated helpers, with cross-input indices that line
    up: blob@0 FS-covenant | agg_trace_opener@1 | agg_comp_opener@2 | nq*{shardA,tailfinal}@3.. (base=3+2*qi, HP11
    tail/final-fusion) | ceil(nq/2) agg-FRI (HP6.4/6.4b, gq=2) reading each query's fused tailfinal@4+2*qi | 4 comp-parts
    (HP4/5.2/6.2/7) as a carry chain from comp0. Every soundness value is single-sourced from blob@0. HP8 (audit
    2026-07-20 CRITICAL FIX #2): blob@0 binds EVERY non-blob covenant's LOCKING to its committed P2SH32 redeem hash
    (_covenant_bind_asm, OP_UTXOBYTECODE) -- not just the read-by-nobody terminals -- so a prover cannot omit/substitute
    OR bare-fill ANY input to skip its self-bind (a cross-input OP_INPUTBYTECODE read authenticates bytes, not executed
    code). blob@0's own execution is the single irreducible external anchor (verifier pins input 0's outpoint). Returns
    (inputs, roles, meta). Byte reduction (<100000B) is the follow-up."""
    import native_poseidon2 as P2
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    assert pf.get("deep") and STK.verify(pf)[0], "sound-full: proof did not verify"
    nonced, sblob, scov, offs = _build_sound_blob(pf, fold_step)
    N0, oT, oN, of = STK._setup(STK.ct_build_layout(pf["stmt"]["depth"])[1], pf["blowup"])[:4]
    ci = _sound_comp_inputs(pf, sblob, offs)
    minvcap = [CT.M_EXT_INV[k2] for k2 in range(P2.RATE, P2.WIDTH)]
    query_inputs = _build_sound_query_inputs(pf, offs, sblob, nq)       # openers@1,2 + nq*{shardA,tailfinal} (HP11)
    fri0 = 1 + len(query_inputs)                                        # blob@0 occupies index 0
    groups = [list(range(g, min(g + 2, nq))) for g in range(0, nq, 2)]  # gq=2 so HP6.4/6.4b root+beta binds fit
    aggfri_inputs = [_build_sound_agg_fri(pf, offs, sblob, g, oN, of, pad=500) for g in groups]
    comp0 = fri0 + len(aggfri_inputs)
    comp_inputs = _build_sound_comp_parts(pf, offs, ci, minvcap, base_idx=comp0)
    # HP8 count-anchor (audit 2026-07-20, CRITICAL FIX #2): blob@0 binds EVERY non-blob covenant's LOCKING via
    # OP_UTXOBYTECODE (_covenant_bind_asm) to its committed P2SH32 redeem hash -- NOT just the read-by-nobody terminals.
    # The cross-input reads are OP_INPUTBYTECODE (scriptSig BYTES), which do NOT force a producer's redeem to execute;
    # a bare-output non-terminal (opener/shardA/tailfinal/comp_trans) supplies the exact bytes its consumer reads while
    # skipping its self-bind (q==q_pre / carry / merkle-root) -> severs the trace<->comp<->FRI chain -> forged accept.
    # Binding every covenant forces each to actually spend its committed P2SH32 output (i.e. to execute). blob@0 itself
    # is the single irreducible external anchor (a within-tx self-bind is circular): the verifier pins input 0's
    # outpoint = the committed fs-covenant. Two-pass: all non-blob inputs are built above (their redeems hashed via the
    # real libauth toolchain, D.redeem_p2sh32), then their binds prepend blob@0's covenant.
    bound = list(enumerate(query_inputs + aggfri_inputs + comp_inputs, start=1))    # (idx, input) for indices 1..n-1
    bind = ""
    for bidx, binp in bound:
        bind += _covenant_bind_asm(bidx, D.redeem_p2sh32(binp["redeem"]))
    blob0 = {"redeem": bind + S.tokens_to_asm(scov), "unlock": S.tokens_to_asm([PUSH(nonced), PUSH(sblob)])}
    inputs = [blob0] + query_inputs + aggfri_inputs + comp_inputs
    terminals = [fri0 + i for i in range(len(aggfri_inputs))] + [len(inputs) - 1]   # read-by-nobody (for reference)
    roles = (["blob", "agg_trace_opener", "agg_comp_opener"]
             + [["shardA", "tailfinal"][i % 2] for i in range(2 * nq)]
             + ["aggFRI"] * len(groups) + ["comp_trans", "comp_trans", "comp_trans", "comp_final"])
    assert len(roles) == len(inputs), (len(roles), len(inputs))
    return inputs, roles, {"nq": nq, "fri0": fri0, "comp0": comp0, "n_inputs": len(inputs),
                           "terminals": terminals, "bound": [b[0] for b in bound]}


def sound_full_selftest(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """FULL sound verifier -- validate the COMPLETE assembled sound tx on real BCH-2026 libauth (no mocks): EVERY
    input INCLUDING blob@0 accepts (blob@0 now runs the HP8 terminal-presence binds), i.e. every soundness value is
    single-sourced from blob@0 and cross-bound AND every terminal input is presence+content bound. Then proves HP8
    fail-closed: omitting a terminal (comp_final or an agg-FRI) OR substituting a wrong covenant at a terminal index
    makes blob@0 REJECT. Reports txBytes (byte reduction to <100000B is the follow-up)."""
    inputs, roles, meta = build_sound_verifier_inputs(nq, blowup, grind_b, fold_step, seed)
    res = D._p2sh_multi(inputs, evaluate=list(range(len(inputs))))   # HP8: blob@0 (index 0) is now evaluated too
    rs = {x["idx"]: x for x in res.get("results", [])}
    fails = [(i, roles[i], str(rs.get(i, {}).get("error"))[:90]) for i in range(len(inputs))
             if not rs.get(i, {}).get("ok")]
    for i, role, err in fails:
        print("  [FAIL] input %d (%s): %s" % (i, role, err))
    n_ok = sum(1 for i in range(len(inputs)) if rs.get(i, {}).get("ok"))
    assert n_ok == len(inputs), "sound-full: %d/%d inputs accept" % (n_ok, len(inputs))
    # HP8 fail-closed: blob@0 (index 0) must REJECT when a terminal is omitted or content-substituted (no mocks --
    # real libauth on the modified input sets). omit_final: drop comp_final -> its baked index n-1 is out of range.
    # omit_fri: drop one agg-FRI -> comp_final shifts off n-1 -> blob@0's n-1 read errors. subst_final: a WRONG
    # (comp_trans) covenant at n-1 -> its revealed redeem hashes != comp_final's committed P2SH32 hash.
    def _blob_rejects(mod_inputs):
        r = D._p2sh_multi(mod_inputs, evaluate=[0])
        return not {x["idx"]: x for x in r.get("results", [])}.get(0, {}).get("ok")

    def _sub(i, j):                                                  # a WRONG (but honest P2SH32) covenant at index i
        m = list(inputs); m[i] = inputs[j]; return m

    def _bare_filler(idx):                                           # audit 2026-07-20 exploit: a self-funded BARE output
        m = list(inputs)                                            # (locking OP_DROP OP_1 = 7551) whose scriptSig CONTAINS
        m[idx] = {"redeem": inputs[idx]["redeem"], "unlock": "",    # the committed redeem bytes (would pass a scriptSig-byte
                  "lockingHex": "7551"}                             # hash) but DROPS them and executes trivially -> the
        return m                                                    # terminal's end-check is skipped unless the LOCKING is bound
    fri0, comp0 = meta["fri0"], meta["comp0"]
    checks = [("omit_final", _blob_rejects(inputs[:-1])),           # comp_final gone -> baked idx n-1 out of range
              ("omit_fri", _blob_rejects(inputs[:fri0] + inputs[fri0 + 1:])),   # agg-FRI gone -> comp_final off n-1
              ("subst_final", _blob_rejects(_sub(len(inputs) - 1, comp0))),     # wrong covenant @ n-1 -> wrong P2SH32 locking
              ("bare_filler_final", _blob_rejects(_bare_filler(len(inputs) - 1))),   # THE audit exploit @ comp_final
              ("bare_filler_fri", _blob_rejects(_bare_filler(fri0))),          # THE audit exploit @ an agg-FRI terminal
              # audit 2026-07-20 CRITICAL FIX #2: the exploit at every NON-terminal producer -- a bare-output opener /
              # shardA / tailfinal / comp_trans would (pre-fix) supply the bytes its consumer reads while skipping its
              # own self-bind (free q_pre / carry / cells) -> forged accept. blob@0 now binds them all -> must REJECT.
              ("bare_filler_opener", _blob_rejects(_bare_filler(1))),          # aggregated trace-opener (read by shardA)
              ("bare_filler_shardA", _blob_rejects(_bare_filler(3))),          # shardA@base (carry read by tailfinal)
              ("bare_filler_tailfinal", _blob_rejects(_bare_filler(4))),       # fused tailfinal (q_pre read by agg-FRI)
              ("bare_filler_comp_trans", _blob_rejects(_bare_filler(comp0)))]  # comp_trans (acc_T feeds comp_final)
    if comp0 - fri0 >= 2:
        checks.append(("subst_fri", _blob_rejects(_sub(fri0, fri0 + 1))))       # wrong agg-FRI @ fri0 -> wrong locking
    bad = [n for n, ok in checks if not ok]
    assert not bad, "HP8 NOT fail-closed: %s did not reject blob@0" % bad
    tb = res.get("txBytes", -1)
    print("FULL sound verifier: %d/%d inputs accept (blob@0[HP8] + 2 agg-openers + %d*{shardA,tailfinal[HP11]} + %d "
          "agg-FRI[HP6.4/6.4b] + 4 comp-parts[HP4/5.2/6.2/7]) -- ALL soundness single-sourced + EVERY covenant bound. "
          "HP8 fail-closed: all %d forged-covenant attacks (%s) reject blob@0. txBytes=%d (<100000:%s; "
          "byte-reduction = follow-up)"
          % (n_ok, len(inputs), nq, (nq + 1) // 2, len(checks), "/".join(n for n, _ in checks), tb, 0 < tb < 100000))
    return True


def _build_sound_agg_fri(pf, offs, sblob, qis, oN, of, pad=200, k_override=None, final_override=None, frl_override=None,
                         bad_root=False, bad_beta=False):
    """HP3.7 + HP6.4 -- the sound aggregated-FRI input for a group of query indices. Reads each query's layer-0 value q
    cross-input from its fused tailfinal (fidx=4+2*qi, HP11), BINDS the FRI's initial index k to the FS-derived query index from
    blob@0 (HP3.7, closes R5-B positions-grinding), and (HP6.4) single-sources the FRI commitment roots: the FINAL root
    fri_root_last == blob fri_roots[-1] (@comp_off-32, one net-0 frl-bind on the bottom-most block's frl -> transitively
    all queries' frl==blob, since each self-binds merkle(final)==its frl and shares the baked `final`), AND every
    per-round fold root == blob fri_roots[r] (the round-witness roots are read cross-input: the fri_roots[0:3] section is
    read once, split, and each query's each round's witness root is PICK-compared to blob fri_roots[round] -- closes the
    per-query/per-round layer-root divergence). FRI betas remain witness here (HP6.4b is the follow-up). The bracket
    binds run before the folds (a wrong root rejects fail-closed at the bind). Returns {redeem, unlock}."""
    qf = STK.query_fri_terms_fold8(pf)
    final = final_override or pf["final"]
    frl = frl_override or bytes.fromhex(pf["fri_roots"][-1])
    frl_off = offs["comp_off"] - 32                                  # fri_roots[-1] sits right before comp_root
    fri_roots_start = offs["tp_off"] + 32                            # fri_roots[0..nrd-1] section (round roots then final)
    betas_start = offs["prefd_len"] + 8 * (2 * offs["ned"] + 2 + 2 * offs["ntd"])   # fs_out FRI-fold-betas section
    nb = offs["folds"]                                               # total FS-derived betas (== 3 per round * n_rounds)
    assert sblob[frl_off:frl_off + 32] == bytes.fromhex(pf["fri_roots"][-1]), "HP6.4: blob fri_roots[-1] offset mismatch"
    _pad = [PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM")]
    unl = []; root_pos = []; beta_pos = []                          # positions of the round roots + betas in the unlock
    for qi in reversed(qis):
        blk = _fri_loop_chain_unlock(qf[qi]["rounds"], (0, 0), frl)[:-2]
        s3 = [r for r in qf[qi]["rounds"] if r["s"] == 3]
        p = len(unl) + 1                                             # +1: frl at the block bottom; rounds are reversed
        for r in reversed(s3):
            rw = len(S.fri_loop_round_witness(r["stride"], 1 << r["li0"], r["betas"], r["base"], r["coset"],
                                              r["path"], bytes.fromhex(r["root"]), r["i2x"]))
            ridx = s3.index(r)
            root_pos.append((p + 16, ridx))                        # root at within-round index 16
            for i in range(3):                                     # betas at within-round indices 2..7 (l0,l1 per beta)
                beta_pos.append((p + 2 + 2 * i, p + 2 + 2 * i + 1, 3 * ridx + i))
            p += rw
        unl += blk
    N = len(unl)                                                    # after OP_DROP(pad); roots+betas are within the blocks
    for (rp, ridx) in root_pos:                                    # sanity: the tracked pos really holds fri_roots[ridx]
        assert unl[rp] == PUSH(bytes.fromhex(pf["fri_roots"][ridx])), "HP6.4: round-root position %d mismatch" % rp
    _flat_betas = [b for r in qf[qis[0]]["rounds"] if r["s"] == 3 for b in r["betas"]]   # 9 betas, shared across queries
    for (l0, l1, bidx) in beta_pos:                                # sanity: tracked beta pos holds beta[bidx]'s 2 limbs
        assert unl[l0] == NUM(_flat_betas[bidx][0] % P) and unl[l1] == NUM(_flat_betas[bidx][1] % P), \
            "HP6.4b: beta position (%d,%d) mismatch" % (l0, l1)
    if bad_root:                                                   # forge: flip the first round root -> per-round bind reject
        rp0 = root_pos[0][0]; bad = bytearray(bytes.fromhex(pf["fri_roots"][root_pos[0][1]])); bad[0] ^= 0x01
        unl[rp0] = PUSH(bytes(bad))
    if bad_beta:                                                   # forge: flip the first beta limb -> beta bind reject
        unl[beta_pos[0][0]] = NUM((_flat_betas[beta_pos[0][2]][0] + 1) % P)
    unl += [PUSH(b"\x00" * pad)]
    frl_bind = _read_blob_field(frl_off, 32) + S.tokens_to_asm([NUM(N), OP("PICK"), OP("EQUALVERIFY")])   # HP6.4 final root
    # HP6.4 per-round roots: read fri_roots[0:3] once (-> root0,root1,root2 on top), PICK-compare each witness round root
    read_rr = _read_blob_field(fri_roots_start, 96) + S.tokens_to_asm([NUM(32), OP("SPLIT"), NUM(32), OP("SPLIT")])
    S3 = N + 3                                                     # stack during the round-root binds (3 blob roots on top)
    rr_binds = []
    for (rp, ridx) in root_pos:                                   # witness root @rp == blob root @ (N+ridx)
        rr_binds += [NUM(S3 - 1 - rp), OP("PICK"), NUM(S3 - (N + ridx)), OP("PICK"), OP("EQUALVERIFY")]
    rr_binds += [OP("DROP")] * 3                                  # drop the 3 blob roots -> stack N (folds see the blocks)
    root_bind = read_rr + " " + S.tokens_to_asm(rr_binds)
    # HP6.4b: read the FS-derived betas section once (-> 2*nb limbs on top), PICK-compare each witness beta limb, drop
    read_bb = _read_blob_field(betas_start, 16 * nb) + S.tokens_to_asm(list(S.split_cells_loop(2 * nb, prefix=0)))
    Sb = N + 2 * nb                                               # stack during the beta binds (2*nb blob beta limbs on top)
    bb_binds = []
    for (l0, l1, bidx) in beta_pos:                              # witness beta limbs @l0/l1 == blob beta[bidx] @ N+2*bidx (+1)
        bb_binds += [NUM(Sb - 1 - l0), OP("PICK"), NUM(Sb - (N + 2 * bidx)), OP("PICK"), OP("NUMEQUALVERIFY")]
        bb_binds += [NUM(Sb - 1 - l1), OP("PICK"), NUM(Sb - (N + 2 * bidx + 1)), OP("PICK"), OP("NUMEQUALVERIFY")]
    bb_binds += [OP("DROP")] * (2 * nb)                          # drop the blob beta limbs -> stack N
    beta_bind = read_bb + " " + S.tokens_to_asm(bb_binds)
    red = ("OP_DROP " + S.tokens_to_asm(S._field_prelude() + S.fri_loop_defines(oN, of)) + " "
           + frl_bind + " " + root_bind + " " + beta_bind + " ")
    for qi in qis:
        rounds = qf[qi]["rounds"]; k = pf["queries"][qi]["k"]; fidx = 4 + 2 * qi   # HP11: fused tailfinal@base+1
        bk = (k_override or {}).get(qi, k)
        verify_k = _read_blob_field(offs["idx0_off"] + 8 * qi, 8) + S.tokens_to_asm(_pad + [NUM(bk % P),
                                                                                            OP("NUMEQUALVERIFY")])
        read_q = ("%s OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x10> OP_SPLIT OP_DROP " % _idx_op(fidx)
                  + S.tokens_to_asm(S.split_cells_prog(2, prefix=0)))
        fold = S.tokens_to_asm(_fri_loop_chain_redeem(rounds, k, final, oN, of, frl, defines_installed=True)[:-1])
        red += " ".join([verify_k.strip(), read_q.strip(), fold]) + " "
    red += "OP_1"
    return {"redeem": red.strip(), "unlock": S.tokens_to_asm(unl)}


def sound_aggfri_selftest(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """HP3.7 -- validate the sound aggregated-FRI on real BCH-2026 libauth (no mocks): the full sound tx
    [blob@0, 2 agg openers, nq*{shardA + fused tailfinal}, ceil(nq/gq) agg-FRI] -> every agg-FRI input accepts (reads
    each query's q from its fused tailfinal, folds the real FRI, binds k == FS-derived index); forged baked verify-k REJECTS."""
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    assert pf.get("deep") and STK.verify(pf)[0], "HP3.7: proof did not verify"
    nonced, sblob, scov, offs = _build_sound_blob(pf, fold_step)
    blob0 = {"redeem": S.tokens_to_asm(scov), "unlock": S.tokens_to_asm([PUSH(nonced), PUSH(sblob)])}
    mt, T = STK.ct_build_layout(pf["stmt"]["depth"])
    N0, oT, oN, of = STK._setup(T, pf["blowup"])[:4]
    inputs = [blob0] + _build_sound_query_inputs(pf, offs, sblob, nq)
    fri0 = len(inputs)
    gq = 2                                                          # HP6.4b: 2 queries/group so root+beta binds fit <10000B
    groups = [list(range(g, min(g + gq, nq))) for g in range(0, nq, gq)]
    for g in groups:
        inputs.append(_build_sound_agg_fri(pf, offs, sblob, g, oN, of, pad=500))
    fri_idx = list(range(fri0, len(inputs)))

    def _run(ins, idxs):
        res = D._p2sh_multi(ins, evaluate=idxs)
        rs = {x["idx"]: x for x in res.get("results", [])}
        return rs, res

    rs, res = _run(inputs, fri_idx)
    fails = [(i, str(rs.get(i, {}).get("error"))[:90]) for i in fri_idx if not rs.get(i, {}).get("ok")]
    for i, err in fails:
        print("  [FAIL] agg-FRI input %d: %s" % (i, err))
    assert all(rs.get(i, {}).get("ok") for i in fri_idx), "HP3.7: not all agg-FRI inputs accept"
    # HP3.7: forged baked verify-k on the first group's first query -> reject
    bad_inputs = list(inputs)
    bad_inputs[fri0] = _build_sound_agg_fri(pf, offs, sblob, groups[0], oN, of, pad=500, k_override={groups[0][0]:
                                                                                     (pf["queries"][groups[0][0]]["k"] + 1) % (1 << 20)})
    rb, _ = _run(bad_inputs, [fri0])
    assert not rb.get(fri0, {}).get("ok"), "HP3.7: forged baked verify-k accepted (FS-k bind broken)"
    # HP6.4: a prover-chosen final' with a self-consistent witness root frl'=merkle(final') -> the frl-bind (frl'!=blob
    # fri_roots[-1]) REJECTS before the folds (closes R6: a non-low-degree final' decoupling the FRI low-degree test).
    from stark import Hf as _Hf, merkle as _mk, m_root as _mr

    def _frl_of(fin):
        return _mr(_mk([_Hf(b"\x00" * 16 + enc8(f[0] % P) + enc8(f[1] % P)) for f in fin]))
    assert _frl_of(pf["final"]) == bytes.fromhex(pf["fri_roots"][-1]), "HP6.4 test: merkle(final) != fri_roots[-1]"
    _fin2 = list(pf["final"]); _fin2[-1] = ((_fin2[-1][0] + 1) % P, _fin2[-1][1])
    bad2 = list(inputs)
    bad2[fri0] = _build_sound_agg_fri(pf, offs, sblob, groups[0], oN, of, pad=500, final_override=_fin2, frl_override=_frl_of(_fin2))
    rf, _ = _run(bad2, [fri0])
    assert not rf.get(fri0, {}).get("ok"), "HP6.4: prover-chosen final'+frl'=merkle(final') accepted (frl not single-sourced)"
    # HP6.4 per-round: a forged per-round fold root (!= blob fri_roots[r]) -> the round-root bind REJECTS (before folds)
    bad3 = list(inputs)
    bad3[fri0] = _build_sound_agg_fri(pf, offs, sblob, groups[0], oN, of, pad=500, bad_root=True)
    rr, _ = _run(bad3, [fri0])
    assert not rr.get(fri0, {}).get("ok"), "HP6.4: forged per-round fold root accepted (round-root bind broken)"
    # HP6.4b: a forged FS-derived beta (!= blob betas) -> the per-round beta bind REJECTS (before folds, R8 closed)
    bad4 = list(inputs)
    bad4[fri0] = _build_sound_agg_fri(pf, offs, sblob, groups[0], oN, of, pad=500, bad_beta=True)
    rbe, _ = _run(bad4, [fri0])
    assert not rbe.get(fri0, {}).get("ok"), "HP6.4b: forged FS-derived beta accepted (beta bind broken)"
    print("HP3.7+HP6.4+HP6.4b sound agg-FRI (q from sound finals, k==FS-k, final+per-round roots == blob fri_roots, "
          "FS-derived betas == blob betas; gq=2): OK -- %d/%d accept; forged verify-k + final'/frl' + per-round root + "
          "beta all REJECT. txBytes=%d (<100000:%s)"
          % (len(fri_idx), len(fri_idx), res.get("txBytes", -1), 0 < res.get("txBytes", -1) < 100000))
    return True


def sound_query_chains_selftest(nq=6, blowup=8, grind_b=2, fold_step=3, seed=0xF54A):
    """LEVER-1 -- validate ALL nq sound DEEP chains with AGGREGATED openers on real BCH-2026 libauth (no mocks):
    [blob@0, agg_trace_opener, agg_comp_opener, nq*{shardA, tail, final}] -> every non-blob input accepts (2+3*nq
    inputs). The 2 aggregated openers verify all nq trace/comp leaves @ their FS-derived k in one loop each; each
    query's shardA/tail read their cells cross-input from the aggregated openers at block_qi's offset. Fails LOUD on
    any non-accept."""
    pf = STK.prove(CT._demo_witness(depth=2), blowup=blowup, grind_b=grind_b, n_queries=nq, fold_step=fold_step,
                   deep=True, seed=seed)
    assert pf.get("deep") and STK.verify(pf)[0], "LEVER-1: proof did not verify"
    nonced, sblob, scov, offs = _build_sound_blob(pf, fold_step)
    blob0 = {"redeem": S.tokens_to_asm(scov), "unlock": S.tokens_to_asm([PUSH(nonced), PUSH(sblob)])}
    inputs = [blob0] + _build_sound_query_inputs(pf, offs, sblob, nq)
    n_q = 2 + 2 * nq                                                # HP11: 2 inputs/query (shardA + fused tailfinal)
    res = D._p2sh_multi(inputs, evaluate=list(range(1, 1 + n_q)))
    rs = {x["idx"]: x for x in res.get("results", [])}

    def _role(i):
        return ["agg_trace_opener", "agg_comp_opener"][i - 1] if i <= 2 else ["shardA", "tailfinal"][(i - 3) % 2]
    fails = [(i, _role(i), str(rs.get(i, {}).get("error"))[:90]) for i in range(1, 1 + n_q)
             if not rs.get(i, {}).get("ok")]
    for i, role, err in fails:
        print("  [FAIL] input %d (%s): %s" % (i, role, err))
    n_ok = sum(1 for i in range(1, 1 + n_q) if rs.get(i, {}).get("ok"))
    assert n_ok == n_q, "LEVER-1: %d/%d sound query-chain inputs accept" % (n_ok, n_q)
    print("LEVER-1+HP11 sound DEEP chains (aggregated openers + tail/final-fusion): %d/%d accept (2 agg openers + nq=%d "
          "x {shardA,tailfinal}), txBytes=%d (<100000:%s): OK"
          % (n_ok, n_q, nq, res.get("txBytes", -1), 0 < res.get("txBytes", -1) < 100000))
    return True


def export_covenants(path, nq=6, blowup=8, grind_b=2, fold_step=3, opener_depth=8, seed=0xF54A):
    """HP2.3: single-source JSON covenant export for deploy_fulltx.mjs (replaces proto_chain_nq's export tail)."""
    import json
    inputs, roles, meta, res = build_and_evaluate(nq, blowup, grind_b, fold_step, opener_depth, seed)
    rs = {x["idx"]: x for x in res.get("results", [])}
    all_ok = all(rs.get(i, {}).get("ok") for i in range(1, len(inputs)))
    n_ok = sum(1 for i in range(1, len(inputs)) if rs.get(i, {}).get("ok"))
    exp = {**meta, "all_accept": bool(all_ok), "n_accept": int(n_ok), "n_eval": len(inputs) - 1,
           "tx_bytes_harness": int(res.get("txBytes", -1)),
           "note": "demo (grind_b=%d, components independent); soundness cross-wiring = HP3-8" % grind_b,
           "roles": roles, "inputs": inputs}
    with open(path, "w") as f:
        json.dump(exp, f)
    print("EXPORT: %d covenants -> %s (all_accept=%s)" % (len(inputs), path, all_ok))
    return exp


if __name__ == "__main__":
    self_test()
