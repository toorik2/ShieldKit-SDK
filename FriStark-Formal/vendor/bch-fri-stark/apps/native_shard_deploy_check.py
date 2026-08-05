"""native_shard_deploy_check.py -- HP3.10/HP4 proof that the DEPLOYABLE Merkle opener
(merkle_verify_stack_prog: witness in the push-only unlock, direction bits derived from the
FS index) is correct, fail-closed and fits a standard input on the REAL libauth BCH-2026 VM.

Verifies on a real SHA256 Merkle tree (stark.merkle) at the FRI layer-0 depth (N=2^13):
  - the deployable opener reproduces merkle_path_prog's accept (same root),
  - it is fail-closed: a wrong sibling OR a wrong index k rejects (the bits are derived from k,
    so a forged direction fails) -- the soundness reason k must be verifier-derived, not witness,
  - in proper P2SH form (witness in unlock, logic in redeem) it ACCEPTs on the real VM, the
    per-input scriptSig (redeem + unlock) is <=1650B, and the hash-digest iterations + operation
    cost stay within the CHIP-2021-05 maxima ((41+unlock)/2 and (41+unlock)*800).
No mock, no fake data: real tree, real VM, exact assertions (TEST_RULES).
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
_HARNESS = os.path.join("native_shard", "deploy_measure.mjs")
# P2SH32-ACCURATE harness (redeem revealed in the scriptSig -> density control length = 41 + witness +
# PUSH(redeem) = the TRUE CHIP-2021-05 op-cost/hash budget). deploy_measure passes the redeem as a bare
# locking bytecode -> density = witness-only, an UNDERESTIMATE that spuriously fails an op-cost-tight input
# (the fold-8 FRI-fold loop); p2sh_measure is the correct budget for such inputs (see check (4e)).
_P2SH_HARNESS = os.path.join("native_shard", "p2sh_measure.mjs")
_LINK_HARNESS = os.path.join("native_shard", "linked_input.mjs")
_MULTI_HARNESS = os.path.join("native_shard", "multi_input.mjs")
_P2SH_MULTI_HARNESS = os.path.join("native_shard", "p2sh_multi_input.mjs")
_COMPILE_HASH_HARNESS = os.path.join("native_shard", "compile_hash.mjs")

import native_ct_shard as S
import native_ct_air_prover as CT
from cashvm import N as NUM, OP
from stark import Hf, merkle as smerkle, m_root as sm_root, m_path as sm_path

_DEPTH = 13
_K = 5039


def _build_tree(depth):
    n = 1 << depth
    preimages = [b"\x00" * 16 + i.to_bytes(8, "little") + (2 * i).to_bytes(8, "little")
                 for i in range(n)]
    tree = smerkle([Hf(p) for p in preimages])
    return preimages, tree, sm_root(tree)


def _libauth(redeem_tokens, unlock_tokens, harness=_HARNESS):
    paths = []
    try:
        for toks in (redeem_tokens, unlock_tokens):
            fd, p = tempfile.mkstemp(suffix=".asm")
            os.close(fd)
            with open(p, "w") as f:
                f.write(S.tokens_to_asm(toks))
            paths.append(p)
        out = subprocess.run(["node", harness, paths[0], paths[1]],
                             cwd=_CASH, capture_output=True, text=True)
    finally:
        for p in paths:
            os.remove(p)
    lines = [ln for ln in out.stdout.splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError("no JSON from harness; stderr=" + out.stderr[:400])
    return json.loads(lines[-1])


def _linked(redeem1_asm, unlock1_asm, unlock0_asm, redeem0_asm):
    """Run the 2-input linked-tx harness (input 1 reads input 0's value via OP_INPUTBYTECODE)."""
    paths = []
    try:
        for s in (redeem1_asm, unlock1_asm, unlock0_asm, redeem0_asm):
            fd, p = tempfile.mkstemp(suffix=".asm")
            os.close(fd)
            with open(p, "w") as f:
                f.write(s)
            paths.append(p)
        out = subprocess.run(["node", _LINK_HARNESS] + paths, cwd=_CASH, capture_output=True, text=True)
    finally:
        for p in paths:
            os.remove(p)
    lines = [ln for ln in out.stdout.splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError("no JSON from linked harness; stderr=" + out.stderr[:400])
    return json.loads(lines[-1])


def _multi(inputs, evaluate=None):
    """Run the generic N-input harness (multi_input.mjs): inputs = [{"redeem": asm, "unlock": asm}, ...] on the
    real BCH-2026 VM; evaluate = the input indices to check (default all). A consumer at index i reads any producer
    input j via OP_j OP_INPUTBYTECODE. Returns {results:[{idx,ok,error,redeemBytes}], nInputs}."""
    spec = {"inputs": inputs}
    if evaluate is not None:
        spec["evaluate"] = evaluate
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        with open(p, "w") as f:
            json.dump(spec, f)
        out = subprocess.run(["node", _MULTI_HARNESS, p], cwd=_CASH, capture_output=True, text=True)
    finally:
        os.remove(p)
    lines = [ln for ln in out.stdout.splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError("no JSON from multi harness; stderr=" + out.stderr[:400])
    return json.loads(lines[-1])


def _p2sh_multi(inputs, outputs=None, evaluate=None):
    """Run the N-input P2SH32 whole-tx harness (p2sh_multi_input.mjs) on the real BCH-2026 VM. The DEPLOY-correct
    model (bch-p2s/readme.md: a >201B verifier locking output is non-standard, so the redeem is P2SH32-hashed and
    REVEALED at spend -> per-input scriptSig = unlock ++ PUSH(redeem), and the redeem counts toward both the per-input
    <=10000B scriptSig cap and the whole-tx <100000B budget). inputs = [{"redeem": asm, "unlock": asm}, ...]. Returns
    {results:[{idx,ok,error,redeemBytes,scriptSigBytes}], nInputs, txBytes, underStandardLimit} -- txBytes is the exact
    serialized tx size, the MEASURED (not modelled) whole-tx byte budget."""
    spec = {"inputs": inputs}
    if outputs is not None:
        spec["outputs"] = outputs
    if evaluate is not None:
        spec["evaluate"] = evaluate
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        with open(p, "w") as f:
            json.dump(spec, f)
        out = subprocess.run(["node", _P2SH_MULTI_HARNESS, p], cwd=_CASH, capture_output=True, text=True)
    finally:
        os.remove(p)
    lines = [ln for ln in out.stdout.splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError("no JSON from p2sh multi harness; stderr=" + out.stderr[:400])
    return json.loads(lines[-1])


def redeem_p2sh32(redeem_asm):
    """HP8: compile a redeem CashAssembly string to its P2SH32 commitment hash256(redeem_bin) via the real libauth
    toolchain (compile_hash.mjs), matching EXACTLY what p2sh_multi_input.mjs bakes into the sourceOutput locking
    (hash256(cashAssemblyToBin(redeem))). The blob@0 count-anchor binds every terminal input's spent-UTXO locking
    (OP_UTXOBYTECODE) to `OP_HASH256 <this hash> OP_EQUAL`. File-based (the redeem is multi-KB, past the OS arg
    limit). Returns hash32_bytes."""
    fd, p = tempfile.mkstemp(suffix=".asm")
    os.close(fd)
    try:
        with open(p, "w") as f:
            f.write(redeem_asm)
        out = subprocess.run(["node", _COMPILE_HASH_HARNESS, p], cwd=_CASH, capture_output=True, text=True)
    finally:
        os.remove(p)
    lines = [ln for ln in out.stdout.splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError("no JSON from compile_hash harness; stderr=" + out.stderr[:400])
    d = json.loads(lines[-1])
    return bytes.fromhex(d["hex"])


def run():
    preimages, tree, root = _build_tree(_DEPTH)
    pre = preimages[_K]
    path = sm_path(tree, _K)
    ok_all = True

    # (1) correctness + fail-closed on cashvm (vs the baked merkle_path_prog)
    base_ok, _ = S.run_merkle_path(pre, path, root)
    dep_ok, _ = S.run_merkle_verify_stack(pre, path, root, _K)
    bad_sib = [(bytes(32) if i == 0 else s, b) for i, (s, b) in enumerate(path)]
    sib_rej, _ = S.run_merkle_verify_stack(pre, bad_sib, root, _K)
    k_rej, _ = S.run_merkle_verify_stack(pre, path, root, _K ^ 1)
    c1 = base_ok and dep_ok and not sib_rej and not k_rej
    ok_all = ok_all and c1
    print("cashvm: baked accepts=%s | deployable accepts=%s | wrong-sib reject=%s | wrong-k reject=%s  [%s]"
          % (base_ok, dep_ok, not sib_rej, not k_rej, "OK" if c1 else "FAIL"))

    # (2) deployable per-input on the real BCH-2026 VM: witness in unlock, logic in redeem
    redeem = S.merkle_verify_stack_prog(_DEPTH) + [NUM(1)]
    unlock = S.merkle_verify_stack_unlock(pre, path, root, _K)
    r = _libauth(redeem, unlock)
    m = r.get("metrics", {})
    total = r["totalScriptSig"]
    hashes = m.get("hashDigestIterations")
    max_hashes = m.get("maximumHashDigestIterations")
    ops = m.get("operationCost")
    max_ops = m.get("maximumOperationCost")
    c2 = (r["accept"] and r["error"] is None and total <= 1650
          and hashes is not None and hashes <= max_hashes
          and ops is not None and ops <= max_ops)
    ok_all = ok_all and c2
    print("libauth deployable (depth=%d): redeem=%dB unlock=%dB total=%dB (<=1650:%s) accept=%s"
          % (_DEPTH, r["redeemBytes"], r["unlockBytes"], total, total <= 1650, r["accept"]))
    print("  hash iters %s/%s  op-cost %s/%s  [%s]"
          % (hashes, max_hashes, ops, max_ops, "OK" if c2 else "FAIL"))

    # (3) logic amortization + count binding: one pinned-count OP_BEGIN/UNTIL loop body verifies
    # N openings, so the redeem stays ~constant while only the witness grows; supplying != N
    # blocks rejects (the count is pinned, not a witness flag).
    def _open(j):
        idx = 100 + 37 * j
        return (preimages[idx], sm_path(tree, idx), root, idx)
    sizes = {}
    for n in (1, 5, 20):
        rr = _libauth(S.merkle_verify_loop_prog(_DEPTH, n) + [NUM(1)],
                      S.merkle_verify_loop_unlock([_open(j) for j in range(n)]))
        sizes[n] = (rr["redeemBytes"], rr["accept"])
    amortized = abs(sizes[20][0] - sizes[1][0]) <= 5 and all(a for _, a in sizes.values())
    short = _libauth(S.merkle_verify_loop_prog(_DEPTH, 20) + [NUM(1)],
                     S.merkle_verify_loop_unlock([_open(j) for j in range(19)]))
    extra = _libauth(S.merkle_verify_loop_prog(_DEPTH, 20) + [NUM(1)],
                     S.merkle_verify_loop_unlock([_open(j) for j in range(21)]))
    bound = (not short["accept"]) and (not extra["accept"])
    c3 = amortized and bound
    ok_all = ok_all and c3
    print("looped opener: redeem N=1/5/20 = %dB/%dB/%dB (amortized:%s) ; count-bind 19/21 reject=%s/%s  [%s]"
          % (sizes[1][0], sizes[5][0], sizes[20][0], amortized,
             not short["accept"], not extra["accept"], "OK" if c3 else "FAIL"))

    # (3b) HP16 openers lever: the FROM-BLOB looped opener on the REAL BCH-2026 VM. N same-leaf openings run in ONE
    # pinned-count loop; each derives its preimage from the exposed blob (preimage = salt ++ blob[:-8]) and merkle-binds
    # the cells to the pinned root -- no duplicated preimage push, no separate commit-check (merkle IS the binding). The
    # opener redeem is revealed ONCE per query set (amortized) and is smaller than the commit form (saves ~n_cells*8 B
    # per opening) -- the ~11+KB whole-tx lever (18 per-leaf opener inputs -> 3 looped: trace/sel/comp). Uses the
    # (2-cell, prefix=16) comp-leaf tree; count PINNED (a wrong block count rejects), a forged cell rejects fail-closed.
    def _opc(j):
        idx = 100 + 37 * j
        return (root, sm_path(tree, idx), preimages[idx][:16], [idx, 2 * idx], idx)   # (root, path, salt(16), cells, k)
    _osz = {}
    for n in (1, 5, 10):
        r = _libauth(S.looped_opener_from_blob_prog(_DEPTH, 2, n, 16),
                     S.looped_opener_from_blob_unlock([_opc(j) for j in range(n)]))
        _osz[n] = (r["redeemBytes"], r["accept"])
    o_amort = abs(_osz[10][0] - _osz[1][0]) <= 5 and all(a for _, a in _osz.values())
    o_forge = _libauth(S.looped_opener_from_blob_prog(_DEPTH, 2, 1, 16),
                       S.looped_opener_from_blob_unlock([(root, sm_path(tree, 100), preimages[100][:16], [101, 200], 100)]))
    o_short = _libauth(S.looped_opener_from_blob_prog(_DEPTH, 2, 10, 16),
                       S.looped_opener_from_blob_unlock([_opc(j) for j in range(9)]))
    o_extra = _libauth(S.looped_opener_from_blob_prog(_DEPTH, 2, 10, 16),
                       S.looped_opener_from_blob_unlock([_opc(j) for j in range(11)]))
    c3b = o_amort and (not o_forge["accept"]) and (not o_short["accept"]) and (not o_extra["accept"])
    ok_all = ok_all and c3b
    print("from-blob looped opener (real libauth, HP16 openers lever): redeem N=1/5/10 = %dB/%dB/%dB (amortized:%s) ; "
          "forged-cell reject=%s ; count-bind 9/11 reject=%s/%s  [%s]"
          % (_osz[1][0], _osz[5][0], _osz[10][0], o_amort, not o_forge["accept"],
             not o_short["accept"], not o_extra["accept"], "OK" if c3b else "FAIL"))

    # (4) HP3.10 thin-shard linking: the compute input (1) reads the data input's (0) carried
    # value via OP_INPUTBYTECODE and verifies it -- fail-closed (a wrong value rejects), so a
    # fold-chain intermediate can be passed between inputs at ~6 bytes of redeem overhead.
    v = "ab" * 32
    vbad = "cd" * 32
    redeem0 = "OP_DROP OP_1"                     # data input: drop the carried value, accept
    unlock0 = "<0x%s>" % v                       # data input carries v in its push-only unlock
    link = "OP_0 OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x%s> OP_EQUAL"  # read in0 unlock, strip push prefix, verify
    good = _linked(link % v, "", unlock0, redeem0)
    bad = _linked(link % vbad, "", unlock0, redeem0)
    c4 = good["accept"] and not bad["accept"] and good["error"] is None
    ok_all = ok_all and c4
    print("linked-input (OP_INPUTBYTECODE 2-input): correct link accept=%s ; wrong-value reject=%s ; redeem=%dB  [%s]"
          % (good["accept"], not bad["accept"], good["redeem1Bytes"], "OK" if c4 else "FAIL"))

    # (4b) HP3.5b-iii-3 cross-input carry of a COMPUTED value with PRODUCER BINDING: input 0 BINDS its
    # carried value H to its own computation (H == SHA256(preimage)) so the carry is NOT free witness;
    # input 1 reads H from input 0's unlock via OP_INPUTBYTECODE (multi-push extraction: strip the 1-byte
    # push prefix, then take 32 bytes) and verifies it. BOTH inputs must accept. This is the thin-shard's
    # comp-carry soundness -- the compose-input's comp is passed to the FRI rest-input; a producer cannot
    # forge the carried intermediate (a wrong value rejects at the producer, not just the consumer).
    import hashlib as _hl
    _pre = b"bch-fri-stark-cross-input-carry"
    _H = _hl.sha256(_pre).hexdigest(); _Hbad = _hl.sha256(b"WRONG").hexdigest(); _prex = _pre.hex()
    _u0 = "<0x%s> <0x%s>" % (_H, _prex)                       # producer unlock: [H, preimage]
    _r0 = "OP_SHA256 OP_EQUAL"                                # producer redeem: binds H == SHA256(preimage)
    _rc = lambda exp: ("OP_0 OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x20> OP_SPLIT OP_DROP <0x%s> OP_EQUAL"
                       % exp)                                 # consumer: extract H (32B) from in0 unlock, verify
    _cok = _linked(_rc(_H), "", _u0, _r0)                     # correct: both inputs accept
    _cprod = _linked(_rc(_Hbad), "", "<0x%s> <0x%s>" % (_Hbad, _prex), _r0)   # producer tamper: input0 rejects
    _ccons = _linked(_rc(_Hbad), "", _u0, _r0)               # consumer tamper: input1 rejects
    c4b = (_cok["accept0"] and _cok["accept"] and not _cprod["accept0"] and not _ccons["accept"]
           and _cok["error"] is None)
    ok_all = ok_all and c4b
    print("cross-input carry-of-computed-value (producer binding + OP_INPUTBYTECODE read): both accept=%s ; "
          "producer-tamper reject=%s ; consumer-tamper reject=%s  [%s]"
          % (_cok["accept0"] and _cok["accept"], not _cprod["accept0"], not _ccons["accept"],
             "OK" if c4b else "FAIL"))

    # (4c) HP3.5b-iii-3 the FULL 2-input FRI link (real BCH-2026 libauth): the FRI fold chain (witness >1650B)
    # is byte-split into contiguous layer-subset inputs. Input 0 (PRODUCER) runs the embeddable partial-FRI [0,c)
    # and BINDS its computed carry-out (folded0,folded1,ii) to the 24-byte carry_preimage in its unlock. Input 1
    # (CONSUMER) reads that carry_preimage from input 0 via OP_INPUTBYTECODE (strip the 1-byte push prefix, take
    # 24B), OP_EQUALVERIFYs its baked carry-in, then runs partial-FRI [c,L) with that (now-authenticated) carry.
    # BOTH must accept; a consumer that bakes a WRONG carry rejects (the read != baked). Real VM, no mock.
    import native_ct_air_stark as _STK4c
    # HP6.1: the deploy chain is PAIR-LEAF (fold-2 coset committed as ONE Merkle leaf -> ~half the FRI witness
    # bytes; the deployable openers auto-adapt via the "p" flag). This is the real-libauth confirmation.
    _pf4c = _STK4c.prove(CT._demo_witness(depth=2), seed=2026, pairleaf=True)
    _q4c = _STK4c.query_fri_terms(_pf4c)[0]
    _lay = _q4c["layers"]; _kq = _q4c["k"]; _fin = _pf4c["final"]; _comp = _STK4c.query_terms(_pf4c)[0]["comp_x"]
    _Lq = len(_lay); _cq = _Lq // 2
    _cy, _ = S.run_fri_partial_witness(_lay, 0, _cq, _comp, _kq, _fin)     # honest carry-out (folded0,folded1,ii)
    _f0, _f1, _iiq = _cy
    _cpre = S.fri_carry_preimage(_f0, _f1, _iiq)
    _u0fri = S.tokens_to_asm(S.fri_partial_producer_unlock(_cpre, _lay, 0, _cq))
    _r0fri = S.tokens_to_asm(S.fri_partial_producer_redeem(_lay, 0, _cq, _comp, _kq))
    _u1fri = S.tokens_to_asm(S._fri_partial_witness_unlock(_lay, _cq, _Lq))
    def _confri(pre_hex):                                        # consumer: read in0's carry_preimage (24B) == baked, then partial[c,L)
        return ("OP_0 OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x18> OP_SPLIT OP_DROP <0x%s> OP_EQUALVERIFY " % pre_hex
                + S.tokens_to_asm(S.fri_partial_witness_redeem(_lay, _cq, _Lq, (_f0, _f1), _iiq, _fin, wbase=0)))
    _lok = _linked(_confri(_cpre.hex()), _u1fri, _u0fri, _r0fri)
    _lbad = _linked(_confri(S.fri_carry_preimage((_f0 + 1) % S.P, _f1, _iiq).hex()), _u1fri, _u0fri, _r0fri)
    c4c = (_lok.get("accept0") and _lok.get("accept") and not _lok.get("error") and not _lbad.get("accept"))
    ok_all = ok_all and c4c
    print("2-input FRI link (iii-3, layers [0,%d)+[%d,%d)): producer accept=%s consumer accept=%s ; forged-carry "
          "consumer reject=%s ; consumer-redeem=%dB  [%s]  (exact per-input scriptSig bytes = iii-4)"
          % (_cq, _cq, _Lq, _lok.get("accept0"), _lok.get("accept"), not _lbad.get("accept"),
             _lok.get("redeem1Bytes", -1), "OK" if c4c else "FAIL"))

    # (4d) HP3.5b-iii-3 the compose->FRI cross-input LINK with SPLIT-AND-USE (Option C, real BCH-2026 libauth):
    # the whole pair-leaf FRI (<=10000B witness) is ONE terminal input [0,L) that CONSUMES the compose-input's
    # comp. Input 0 carries the 24-byte comp_preimage = fri_carry_preimage(comp0,comp1,k) as its first unlock push
    # (exactly what compose_producer_full binds on-chain; that binding comp_preimage==computed comp+k is validated
    # on cashvm). Input 1 (the FRI consumer) READS that 24B preimage via OP_INPUTBYTECODE (strip the 1-byte push
    # prefix, take 24B) and runs fri_partial_witness_redeem(carry_split=True): split_cells(3) -> (comp0,comp1,k)
    # FIELD values USED as carry_val/carry_idx -- NOT byte-compared against a baked value (that would let a prover
    # fold an unrelated poly Q while a byte-check still passes; OBS-2/FS-2 soundness fix). BOTH accept honest; a
    # forged comp-limb OR k-limb in input 0's pushed preimage -> the FRI rejects (the read value IS folded /
    # indexes the opens). Real VM, no mock. (The full compose_producer_full redeem as input 0 is measured in iii-4.)
    _c0d, _c1d = _comp[0] % S.P, _comp[1] % S.P
    _N0d = 2 * _lay[0]["half"]
    _readd = "OP_0 OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x18> OP_SPLIT OP_DROP "
    _rc1d = _readd + S.tokens_to_asm(S.fri_partial_witness_redeem(_lay, 0, _Lq, None, None, _fin, carry_split=True))
    _u1d = S.tokens_to_asm(S._fri_partial_witness_unlock(_lay, 0, _Lq))
    _r0d = "OP_DROP OP_1"                                        # producer: push the 24B comp_preimage, accept
    _lokd = _linked(_rc1d, _u1d, "<0x%s>" % S.fri_carry_preimage(_c0d, _c1d, _kq).hex(), _r0d)
    _lbd0 = _linked(_rc1d, _u1d, "<0x%s>" % S.fri_carry_preimage((_c0d + 1) % S.P, _c1d, _kq).hex(), _r0d)   # forged comp
    _lbdk = _linked(_rc1d, _u1d, "<0x%s>" % S.fri_carry_preimage(_c0d, _c1d, (_kq + 1) % _N0d).hex(), _r0d)  # forged k
    c4d = (_lokd.get("accept0") and _lokd.get("accept") and not _lokd.get("error")
           and not _lbd0.get("accept") and not _lbdk.get("accept"))
    ok_all = ok_all and c4d
    print("compose->FRI split-and-use link (iii-3, terminal [0,%d)): producer accept=%s consumer accept=%s ; "
          "forged comp / forged k reject=%s/%s ; consumer-redeem=%dB  [%s]"
          % (_Lq, _lokd.get("accept0"), _lokd.get("accept"), not _lbd0.get("accept"), not _lbdk.get("accept"),
             _lokd.get("redeem1Bytes", -1), "OK" if c4d else "FAIL"))

    # (4e) HP3.10/HP11 fold-8 loop-chain FRI-fold DEPLOY input on the REAL BCH-2026 VM (P2SH32-accurate density):
    # the CANONICAL fold-8 deploy FRI-fold input that the fold-8 deploy_proof (fold_step=3, 7698d5c) is verified
    # by -- _fri_loop_chain_redeem (the DEPTH-INVARIANT P2SH redeem: the ~2.3KB s=3 loop body DEFINE'd once +
    # carried-build + n INVOKE + juggle + fri_final_bind + HP11 F3 final-ROOT-bind) with the round openings in the
    # scriptSig (_fri_loop_chain_unlock, fri_root_last at the bottom). Consumes query_fri_terms_fold8 -- the
    # deploy-path verifier now runs the fold-8 chain (the fold-2 pair-leaf checks 4c/4d stay as the current-default
    # regression oracle). Measured with p2sh_measure (P2SH32-accurate: redeem revealed in scriptSig -> density =
    # 41 + witness + PUSH(redeem)) NOT deploy_measure (redeem as bare locking bytecode -> witness-only density
    # UNDERESTIMATE, which spuriously fails this op-cost-tight loop). Each query: honest ACCEPT + scriptSig <=10000B
    # (consensus) + op-cost/hash within the CHIP-2021-05 budget ; fail-closed on a tampered comp / coset / final /
    # fri_root_last. Same real fold-8 proof the self_test uses on cashvm (blowup=8/N=2^12=8^4, no s<3 tail); this
    # adds the committed REAL-VM + byte + op-cost coverage (the self_test exercises cashvm only). No mock.
    import native_ct_air_stark as _STK4e
    _pf4e = _STK4e.prove(CT._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=3, fold_step=3, seed=0x310)
    assert _STK4e.verify(_pf4e)[0], "fold-8 deploy proof must verify"
    _T4e = CT.ct_build_layout(_pf4e["stmt"]["depth"])[1]
    _oN4e, _off4e = _STK4e._setup(_T4e, _pf4e["blowup"])[2:4]
    _fin4e = _pf4e["final"]; _frl4e = bytes.fromhex(_pf4e["fri_roots"][-1])

    def _rdm4e(rounds, k, final, frl):                          # P2SH redeem = field prelude + the fold-8 loop chain
        return S._field_prelude() + S._fri_loop_chain_redeem(rounds, k, final, _oN4e, _off4e, frl)

    _nq4e = 0; _worst4e = 0; _honest4e = True; _rej4e = True
    for _qt4e in _STK4e.query_fri_terms_fold8(_pf4e):
        _k4e = _qt4e["k"]; _cx4e = _qt4e["comp_x"]; _rn4e = _qt4e["rounds"]
        _hh4e = _libauth(_rdm4e(_rn4e, _k4e, _fin4e, _frl4e),
                         S._fri_loop_chain_unlock(_rn4e, _cx4e, _frl4e), harness=_P2SH_HARNESS)
        _mm4e = _hh4e.get("metrics", {}); _ss4e = _hh4e["scriptSigBytes"]
        _ops4e = _mm4e.get("operationCost"); _mops4e = _mm4e.get("maximumOperationCost")
        _hs4e = _mm4e.get("hashDigestIterations"); _mhs4e = _mm4e.get("maximumHashDigestIterations")
        _honest4e = _honest4e and (_hh4e["accept"] and _hh4e["error"] is None and _ss4e <= 10000
                                   and _ops4e is not None and _ops4e <= _mops4e
                                   and _hs4e is not None and _hs4e <= _mhs4e)
        _worst4e = max(_worst4e, _ss4e)
        if _nq4e == 0:                                          # full fail-closed tamper matrix on the real VM
            _rc4e = _libauth(_rdm4e(_rn4e, _k4e, _fin4e, _frl4e),
                             S._fri_loop_chain_unlock(_rn4e, ((_cx4e[0] + 1) % S.P, _cx4e[1]), _frl4e), harness=_P2SH_HARNESS)
            _si4e = max(_i for _i, _r in enumerate(_rn4e) if _r["s"] == 3)
            _tr4e = [dict(_r) for _r in _rn4e]
            _tr4e[_si4e]["coset"] = [((_c[0] + 1) % S.P, _c[1]) if _j == 0 else _c
                                     for _j, _c in enumerate(_rn4e[_si4e]["coset"])]
            _rx4e = _libauth(_rdm4e(_tr4e, _k4e, _fin4e, _frl4e),
                             S._fri_loop_chain_unlock(_tr4e, _cx4e, _frl4e), harness=_P2SH_HARNESS)
            _tf4e = [((_f[0] + 1) % S.P, _f[1]) for _f in _fin4e]
            _rf4e = _libauth(_rdm4e(_rn4e, _k4e, _tf4e, _frl4e),
                             S._fri_loop_chain_unlock(_rn4e, _cx4e, _frl4e), harness=_P2SH_HARNESS)
            _wr4e = bytearray(_frl4e); _wr4e[0] ^= 1
            _rr4e = _libauth(_rdm4e(_rn4e, _k4e, _fin4e, bytes(_wr4e)),
                             S._fri_loop_chain_unlock(_rn4e, _cx4e, bytes(_wr4e)), harness=_P2SH_HARNESS)
            _rej4e = not (_rc4e["accept"] or _rx4e["accept"] or _rf4e["accept"] or _rr4e["accept"])
        _nq4e += 1
    c4e = _honest4e and _rej4e and _nq4e > 0
    ok_all = ok_all and c4e
    print("fold-8 loop-chain FRI-fold deploy input (real P2SH32 libauth, %d queries): honest accept + scriptSig<=10000B "
          "(worst=%dB) + op-cost/hash within CHIP-2021-05 budget ; tamper-reject comp/coset/final/fri_root_last  [%s]"
          % (_nq4e, _worst4e, "OK" if c4e else "FAIL"))

    # (4e-agg) HP16 FRI AGGREGATION on the REAL P2SH32 VM: verify ALL fold-8 queries in ONE input (fri_loop_defines
    # hoisted once) -- the <100KB FRI lever (6 separate FRI inputs -> ~2 aggregated at ~3 queries/input under the
    # 10000B scriptSig cap + the CHIP-2021-05 op-cost budget). A tampered comp in any query rejects fail-closed
    # (below-invariant stacking; each query's F3 root-bind still binds to the shared fri_root_last, HP7.4c). Measured
    # scriptSig + the redeem amortization vs the per-query 4e form.
    _qs4a = list(_STK4e.query_fri_terms_fold8(_pf4e))
    _redA = (S._field_prelude()
             + S.fri_loop_chain_multi_redeem([(_q["rounds"], _q["k"]) for _q in _qs4a], _oN4e, _off4e, _fin4e, _frl4e))
    _unlA = S.fri_loop_chain_multi_unlock([(_q["rounds"], _q["comp_x"]) for _q in _qs4a], _frl4e)
    _rA = _libauth(_redA, _unlA, harness=_P2SH_HARNESS)
    _mA = _rA.get("metrics", {}); _ssA = _rA.get("scriptSigBytes", 1 << 30)
    _qbA = [dict(_q) for _q in _qs4a]; _cA = _qbA[0]["comp_x"]; _qbA[0]["comp_x"] = ((_cA[0] + 1) % S.P, _cA[1])
    _rbA = _libauth(_redA, S.fri_loop_chain_multi_unlock([(_q["rounds"], _q["comp_x"]) for _q in _qbA], _frl4e), harness=_P2SH_HARNESS)
    c4a = (_rA.get("accept") and not _rA.get("error") and isinstance(_ssA, int) and _ssA <= 10000
           and _mA.get("operationCost") is not None and _mA["operationCost"] <= _mA["maximumOperationCost"]
           and not _rbA.get("accept"))
    ok_all = ok_all and c4a
    print("HP16 FRI aggregation (real P2SH32 libauth, %d fold-8 queries in ONE input, fri_loop_defines hoisted once): "
          "accept=%s ; scriptSig=%dB (<=10000:%s) ; op-cost=%s/%s within budget ; tampered comp reject=%s  [%s]"
          % (len(_qs4a), _rA.get("accept"), _ssA, isinstance(_ssA, int) and _ssA <= 10000,
             _mA.get("operationCost"), _mA.get("maximumOperationCost"), not _rbA.get("accept"), "OK" if c4a else "FAIL"))

    # (4f) HP12 DEEP final-combine CROSS-INPUT link (real BCH-2026 libauth): the DEEP quotient shards into thin
    # SUM-parts (Sum_z/Sum_zg) + a final combine. Input 0 (PRODUCER) is the real deep_sum_part(carry_bound) for
    # Sum_z -- it self-binds computed acc_out == the 16-byte carry_out preimage it exposes as its FIRST unlock
    # push (HP9.8). Input 1 (deep_final_combine carry_split CONSUMER) READS that preimage via OP_INPUTBYTECODE
    # (strip the 1-byte push prefix, take 16B), split_cells(2)s it into Sum_z and USES it in q = invz*Sum_z +
    # invzg*Sum_zg (split-and-USE, not a byte-compare -> a forged Sum_z yields the wrong q, OBS-2). BOTH accept
    # honest; a forged producer acc_out rejects AT the producer (self-bind); a forged Sum_z preimage -> wrong q at
    # the consumer. Real VM, no mock. (Sum_zg + the two hint-validated inverses are the consumer's local witness
    # here; the full 3-input final reading BOTH Sum_z and Sum_zg cross-input is the deploy assembly. The term
    # decomposition mirrors the native_ct_shard self_test reference / _deep_replay.q_at.)
    import native_ct_air_stark as _STK4f
    import native_gf_p2 as _F4f
    _pf4f = _STK4f.prove(CT._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=3, fold_step=3, deep=True, seed=0xF54A)
    assert _pf4f.get("deep") and _STK4f.verify(_pf4f)[0], "4f deep proof must verify"
    _mt4f, _T4f = _STK4f.ct_build_layout(_pf4f["stmt"]["depth"])
    _N4f, _oT4f, _oN4f, _of4f, _Hd4f, _Dd4f, _ls4f = _STK4f._setup(_T4f, _pf4f["blowup"])
    _ly4f = _STK4f.ct_public_layout(_mt4f, _T4f); _sv4f = _STK4f._selector_vectors(_ly4f, _T4f, _N4f, _oT4f, _oN4f, _of4f)
    _z4f = tuple(_pf4f["z"]); _zg4f = tuple(_pf4f["zg"]); _pz4f = _STK4f._ood_pub_at(_ly4f, _T4f, _oT4f, _z4f)
    _da4f = [tuple(_a) for _a in _pf4f["deep_alphas"]]
    _sel4f = [(_sv4f[_kk], _pz4f[_kk]) for _kk in ("is_full", "is_partial", "is_block_start", "is_reabsorb",
              "is_range", "is_range_first", "is_range_step", "is_range_last")] \
             + [(_sv4f["rc"][_i], _pz4f["rc"][_i]) for _i in range(S.WIDTH)] \
             + [(_sv4f["chain_minv"][_j], _pz4f["chain_minv"][_j]) for _j in range(S.WIDTH)]
    _nf4f = len(_STK4f.FLAT_COLS); _ns4f = len(_sel4f)
    _q4f = _pf4f["queries"][0]; _k4f = _q4f["k"]; _tm4f = []
    for _c in _STK4f.FLAT_COLS:
        _cke4f = _F4f.from_base(_q4f["ck"][_c])
        _tm4f.append((_da4f[len(_tm4f)], _cke4f, tuple(_pf4f["Pcz"][_c])))
        _tm4f.append((_da4f[len(_tm4f)], _cke4f, tuple(_pf4f["Pczg"][_c])))
    for _dv4f, _m4f in _sel4f:
        _tm4f.append((_da4f[len(_tm4f)], _F4f.from_base(_dv4f[_k4f]), _m4f))
    _tm4f.append((_da4f[len(_tm4f)], _F4f.from_base(_sv4f["range_weight"][_k4f]), tuple(_pf4f["rw_zg"])))
    _tm4f.append((_da4f[len(_tm4f)], tuple(_q4f["cc"]), tuple(_pf4f["comp_z"])))
    _zt4f = [2 * _c for _c in range(_nf4f)] + [2 * _nf4f + _s for _s in range(_ns4f)] + [2 * _nf4f + _ns4f + 1]
    _zgt4f = [2 * _c + 1 for _c in range(_nf4f)] + [2 * _nf4f + _ns4f]
    _zo4f = [_tm4f[_i] for _i in _zt4f]; _zgo4f = [_tm4f[_i] for _i in _zgt4f]
    _Sz4f, _ = S.run_deep_sum_part(_zo4f, _F4f.ZERO); _Szg4f, _ = S.run_deep_sum_part(_zgo4f, _F4f.ZERO)
    _x4f = _Dd4f[_k4f]
    _ivz4f = _F4f.inv(_F4f.sub(_F4f.from_base(_x4f), _z4f)); _ivzg4f = _F4f.inv(_F4f.sub(_F4f.from_base(_x4f), _zg4f))
    _eq4f = tuple(_STK4f.query_terms(_pf4f)[0]["comp_x"])
    _rd16 = "OP_0 OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x10> OP_SPLIT OP_DROP "   # read input0's first push (16B carry)
    _chk4f = [NUM(_eq4f[1] % S.P), OP("NUMEQUALVERIFY"), NUM(_eq4f[0] % S.P), OP("NUMEQUAL")]   # q == expected (split-and-use)
    _cred4f = S.tokens_to_asm(S._field_prelude()) + " " + _rd16 + S.tokens_to_asm(S.deep_final_combine_prog(carry_split=True) + _chk4f)
    _cunl4f = S.tokens_to_asm([NUM(_Szg4f[0] % S.P), NUM(_Szg4f[1] % S.P), NUM(_ivz4f[0] % S.P), NUM(_ivz4f[1] % S.P),
                               NUM(_ivzg4f[0] % S.P), NUM(_ivzg4f[1] % S.P)])
    _pred4f = S.tokens_to_asm(S._field_prelude() + S.deep_sum_part_prog(len(_zo4f), carry_bound=True))
    _punl4f = S.tokens_to_asm(S.deep_sum_part_unlock(_zo4f, _F4f.ZERO, carry_bound=True, acc_out=_Sz4f))
    _pforge4f = S.tokens_to_asm(S.deep_sum_part_unlock(_zo4f, _F4f.ZERO, carry_bound=True, acc_out=((_Sz4f[0] + 1) % S.P, _Sz4f[1])))
    _ok4f = _linked(_cred4f, _cunl4f, _punl4f, _pred4f)
    _bad_sz4f = _linked(_cred4f, _cunl4f, "<0x%s>" % S._acc_preimage(((_Sz4f[0] + 1) % S.P, _Sz4f[1])).hex(), "OP_DROP OP_1")
    _bad_pr4f = _linked(_cred4f, _cunl4f, _pforge4f, _pred4f)
    c4f = (_ok4f.get("accept0") and _ok4f.get("accept") and not _ok4f.get("error")
           and not _bad_sz4f.get("accept") and not _bad_pr4f.get("accept0"))
    ok_all = ok_all and c4f
    print("DEEP final-combine cross-input link (4f, Sum_z read via OP_INPUTBYTECODE + split-and-use): producer "
          "accept=%s consumer accept=%s ; forged Sum_z reject=%s / forged producer reject=%s ; consumer-redeem=%dB  [%s]"
          % (_ok4f.get("accept0"), _ok4f.get("accept"), not _bad_sz4f.get("accept"), not _bad_pr4f.get("accept0"),
             _ok4f.get("redeem1Bytes", -1), "OK" if c4f else "FAIL"))

    # (4k) HP16.1 3-input DEEP final-combine (Sum_z AND Sum_zg BOTH cross-input, real BCH-2026 libauth multi_input):
    # the FULL deploy final combine -- input 0 = the real Sum_z sum-part (deep_sum_part carry_bound, exposes Sum_z as
    # its first push), input 1 = the real Sum_zg sum-part (exposes Sum_zg), input 2 = the consumer that reads BOTH
    # carry_outs cross-input (OP_0 / OP_1 INPUTBYTECODE) and split-and-uses them in q = invz*Sum_z + invzg*Sum_zg
    # (deep_final_combine dual mode). Closes the Sum_zg single-source gap that 4f/carry_split left in the per-input
    # witness (a forged Sum_z OR Sum_zg -> wrong q -> reject). Reuses 4f's terms/sums/inverses/expected-q.
    _rd16z = "OP_0 OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x10> OP_SPLIT OP_DROP "     # Sum_z  = input 0 first push (16B)
    _rd16zg = "OP_1 OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x10> OP_SPLIT OP_DROP "    # Sum_zg = input 1 first push (16B)
    _chk4k = [NUM(_eq4f[1] % S.P), OP("NUMEQUALVERIFY"), NUM(_eq4f[0] % S.P), OP("NUMEQUAL")]   # q == expected (split-and-use)
    _cred4k = ("OP_DROP " + S.tokens_to_asm(S._field_prelude()) + " " + _rd16z + _rd16zg
               + S.tokens_to_asm(S.deep_final_combine_prog(dual=True) + _chk4k))   # drop the op-budget witness first
    _cunl4k = S.tokens_to_asm([NUM(_ivz4f[0] % S.P), NUM(_ivz4f[1] % S.P), NUM(_ivzg4f[0] % S.P), NUM(_ivzg4f[1] % S.P),
                               S.PUSH(b"\x00" * 40)])   # +40B op-budget witness ((41+unlock)*800); in the full deploy the
                                                        # invz/invzg ext_inv_check hint-operands (HP13.1) carry this budget
    _predz4k = S.tokens_to_asm(S._field_prelude() + S.deep_sum_part_prog(len(_zo4f), carry_bound=True))
    _predzg4k = S.tokens_to_asm(S._field_prelude() + S.deep_sum_part_prog(len(_zgo4f), carry_bound=True))
    _punlz4k = S.tokens_to_asm(S.deep_sum_part_unlock(_zo4f, _F4f.ZERO, carry_bound=True, acc_out=_Sz4f))
    _punlzg4k = S.tokens_to_asm(S.deep_sum_part_unlock(_zgo4f, _F4f.ZERO, carry_bound=True, acc_out=_Szg4f))

    def _mk4k(u0, u1):                                                                # 3-input spec [Sz producer, Szg producer, dual consumer]
        return _multi([{"redeem": _predz4k, "unlock": u0}, {"redeem": _predzg4k, "unlock": u1},
                       {"redeem": _cred4k, "unlock": _cunl4k}], evaluate=[0, 1, 2])

    def _acc4k(res, idx):
        return next((r.get("ok") for r in res.get("results", []) if r.get("idx") == idx), None)
    _ok4k = _mk4k(_punlz4k, _punlzg4k)
    _bz4k = _multi([{"redeem": "OP_DROP OP_1", "unlock": "<0x%s>" % S._acc_preimage(((_Sz4f[0] + 1) % S.P, _Sz4f[1])).hex()},
                    {"redeem": _predzg4k, "unlock": _punlzg4k}, {"redeem": _cred4k, "unlock": _cunl4k}], evaluate=[2])   # forged Sum_z
    _bzg4k = _multi([{"redeem": _predz4k, "unlock": _punlz4k},
                     {"redeem": "OP_DROP OP_1", "unlock": "<0x%s>" % S._acc_preimage((_Szg4f[0], (_Szg4f[1] + 1) % S.P)).hex()},
                     {"redeem": _cred4k, "unlock": _cunl4k}], evaluate=[2])                                             # forged Sum_zg
    _bpz4k = _mk4k(S.tokens_to_asm(S.deep_sum_part_unlock(_zo4f, _F4f.ZERO, carry_bound=True,
                   acc_out=((_Sz4f[0] + 1) % S.P, _Sz4f[1]))), _punlzg4k)                                              # forged Sum_z producer
    _bpzg4k = _mk4k(_punlz4k, S.tokens_to_asm(S.deep_sum_part_unlock(_zgo4f, _F4f.ZERO, carry_bound=True,
                    acc_out=(_Szg4f[0], (_Szg4f[1] + 1) % S.P))))                                                      # forged Sum_zg producer
    _cbytes4k = next((r.get("redeemBytes", -1) for r in _ok4k.get("results", []) if r.get("idx") == 2), -1)
    c4k = (_acc4k(_ok4k, 0) and _acc4k(_ok4k, 1) and _acc4k(_ok4k, 2)
           and not _acc4k(_bz4k, 2) and not _acc4k(_bzg4k, 2)
           and not _acc4k(_bpz4k, 0) and not _acc4k(_bpzg4k, 1))
    ok_all = ok_all and c4k
    print("HP16.1 3-input DEEP final-combine (4k, Sum_z@in0 + Sum_zg@in1 BOTH cross-input, dual split-and-use): "
          "producers+consumer accept=%s/%s/%s ; forged Sum_z/Sum_zg reject=%s/%s ; forged producer reject=%s/%s ; "
          "consumer-redeem=%dB  [%s]"
          % (_acc4k(_ok4k, 0), _acc4k(_ok4k, 1), _acc4k(_ok4k, 2), not _acc4k(_bz4k, 2), not _acc4k(_bzg4k, 2),
             not _acc4k(_bpz4k, 0), not _acc4k(_bpzg4k, 1), _cbytes4k, "OK" if c4k else "FAIL"))

    # (4l) HP16/HP15.2 Design A PARTIAL dual shard on the real BCH-2026 libauth -- the DEPLOY op-cost form (the
    # reverted full-range 4m was op-OVER; this is the correct partial shard). The contiguous dual shard reads ONLY its
    # ood[lo:hi]+alpha[lo:hi] slice from the ONE FS blob CROSS-INPUT (input 0 pushes z||z*g||ood||alpha; input 1 reads
    # it via OP_0 INPUTBYTECODE, strips the OP_PUSHDATA2 3-byte prefix, and deep_dual_slice_read_prog reconstructs the
    # slice via two byte-range extracts + CAT), so op-cost scales with the shard (hi-lo), not the transcript. The shard
    # then runs deep_sum_part_dual_prog(carry_bound=True), self-binding (acc_z,acc_zg) to its 32-byte carry_out
    # (R4-B1: alpha/ood single-source from the blob, BAKED window -> no re-route). The op-budget (41+unlock1)*800 (bare
    # P2S: only unlock1 counts) is bought by a dead push OP_DROP'd first, padded so op-cost <= max AND unlock1 <=10000B.
    # Real VM, no mock: honest accept + op-cost<=max + unlock1<=10000B + forged acc_z/acc_zg carry_out reject.
    _nt4l = len(_tm4f)                                                    # 2*nf+ns+2 (real 138)
    _ao4l = [(_t[0], _t[2]) for _t in _tm4f]                              # (alpha, ood) per term (blob order)
    _val4l = [_t[1] for _t in _tm4f]; _ood4l = [_t[2] for _t in _tm4f]; _alp4l = [_t[0] for _t in _tm4f]
    _blob4l = S._deep_blob_bytes(_z4f, _zg4f, _ao4l)
    _wins4l = [(0, 70), (70, _nt4l)]                                      # the 2 dual-shards/query partition (make-or-break topology)
    _pad4l = 4000                                                         # bought op-budget; tuned so op-cost<=max AND unlock1<=10000B

    def _shard4l(lo, hi):
        _paz, _pazg = S.run_deep_sum_part_dual(lo, hi, _nf4f, _ns4f, _F4f.ZERO, _F4f.ZERO,
                                               _val4l[lo:hi], _ood4l[lo:hi], _alp4l[lo:hi])[0]
        _redt = (S._field_prelude() + S.deep_dual_slice_read_prog(lo, hi, _nt4l)
                 + S.deep_sum_part_dual_prog(lo, hi, _nf4f, _ns4f, carry_bound=True))
        _red = "OP_DROP OP_0 OP_INPUTBYTECODE OP_3 OP_SPLIT OP_NIP " + S.tokens_to_asm(_redt)  # drop pad; read blob (strip 3B prefix)

        def _unl(cz, czg):
            _u = [S.PUSH(S._acc_preimage(cz) + S._acc_preimage(czg)),                    # carry_out preimage @0
                  S.PUSH(S._acc_preimage(_F4f.ZERO) + S._acc_preimage(_F4f.ZERO))]       # carry_in preimage @1 (fresh)
            for _t in range(lo, hi):
                _u += [NUM(_val4l[_t][0] % S.P), NUM(_val4l[_t][1] % S.P)]
            return S.tokens_to_asm(_u + [S.PUSH(b"\x00" * _pad4l)])                       # op-budget padding on top
        return _paz, _pazg, _red, _unl
    _rows4l = []; c4l = True
    for _lo4l, _hi4l in _wins4l:
        _paz4l, _pazg4l, _red4l, _unl4l = _shard4l(_lo4l, _hi4l)
        _ok4l = _linked(_red4l, _unl4l(_paz4l, _pazg4l), "<0x%s>" % _blob4l.hex(), "OP_DROP OP_1")
        _m4l = _ok4l.get("metrics1", {}) or {}
        _oc4l = _m4l.get("operationCost"); _moc4l = _m4l.get("maximumOperationCost"); _u1b4l = _ok4l.get("unlock1Bytes", -1)
        _win_ok = (_ok4l.get("accept0") and _ok4l.get("accept") and not _ok4l.get("error")
                   and _oc4l is not None and _moc4l is not None and _oc4l <= _moc4l and 0 < _u1b4l <= 10000)
        _frej = None
        if _lo4l == 0:                                                    # forged carry_out -> reject (self-bind, fail-closed) on one window
            _bz4l = _linked(_red4l, _unl4l(((_paz4l[0] + 1) % S.P, _paz4l[1]), _pazg4l), "<0x%s>" % _blob4l.hex(), "OP_DROP OP_1")
            _bzg4l = _linked(_red4l, _unl4l(_paz4l, (_pazg4l[0], (_pazg4l[1] + 1) % S.P)), "<0x%s>" % _blob4l.hex(), "OP_DROP OP_1")
            _frej = (not _bz4l.get("accept")) and (not _bzg4l.get("accept"))
            _win_ok = _win_ok and _frej
        _rows4l.append((_lo4l, _hi4l, _ok4l.get("accept"), _oc4l, _moc4l, _u1b4l, _ok4l.get("redeem1Bytes", -1), _frej))
        c4l = c4l and _win_ok
    ok_all = ok_all and c4l
    for _lo4l, _hi4l, _acc4l, _oc4l, _moc4l, _u1b4l, _rb4l, _frej in _rows4l:
        print("HP16 Design A partial dual shard on real libauth (4l, window[%d:%d] slice-read cross-input): "
              "accept=%s ; op-cost=%s/%s ; unlock1=%dB (<=10000:%s) ; redeem1=%dB%s"
              % (_lo4l, _hi4l, _acc4l, _oc4l, _moc4l, _u1b4l, (isinstance(_u1b4l, int) and 0 < _u1b4l <= 10000), _rb4l,
                 "" if _frej is None else (" ; forged acc_z/acc_zg reject=%s" % _frej)))
    print("  -> both dual-shards of the 2-shards/query partition fit <=10000B unlock with op-cost<=budget "
          "(make-or-break topology, forged carry fail-closed)  [%s]" % ("OK" if c4l else "FAIL"))

    # (4m) HP16.1 whole-tx DOMINANT portion on the real BCH-2026 P2SH32 VM (the DEPLOY-correct byte model, per
    # bch-p2s/readme.md: a >201B verifier locking is non-standard -> P2SH32, per-input scriptSig = unlock ++
    # PUSH(redeem), redeem counts toward both the <=10000B scriptSig cap AND the <100000B whole-tx). The 1 shared
    # FS-blob data input + nq*2 DEEP slice-shards (the 2-shards/query partition, all reading the ONE blob cross-input)
    # are assembled as ONE P2SH32 tx and the EXACT serialized txBytes measured -- the largest single chunk of the
    # whole-tx, so the make-or-break <100000B is a MEASURED number for this portion (the loop#5 75KB bare-P2S estimate
    # was invalid). Each shard is a standalone producer (carry_in=ZERO); byte-identical to the carry-chained form. The
    # remaining inputs (AIR-an-z split parts, openers 4g/h/i/j, final 4f/4k, FRI) are the HP16.1 follow-up additions.
    _NQ4m = 6                                                            # nq=6 deploy config (HP16.5, 100-bit)
    _pad4m = 750                                                         # op-budget pad; under P2SH32 the redeem fills most of the budget
    _in4m = [{"redeem": "OP_DROP OP_1", "unlock": "<0x%s>" % _blob4l.hex()}]   # input0 = the ONE shared FS blob
    for _qi4m in range(_NQ4m):
        for _lo4m, _hi4m in _wins4l:
            _pz4m, _pzg4m = S.run_deep_sum_part_dual(_lo4m, _hi4m, _nf4f, _ns4f, _F4f.ZERO, _F4f.ZERO,
                                                     _val4l[_lo4m:_hi4m], _ood4l[_lo4m:_hi4m], _alp4l[_lo4m:_hi4m])[0]
            _rt4m = (S._field_prelude() + S.deep_dual_slice_read_prog(_lo4m, _hi4m, _nt4l)
                     + S.deep_sum_part_dual_prog(_lo4m, _hi4m, _nf4f, _ns4f, carry_bound=True))
            _rd4m = "OP_DROP OP_0 OP_INPUTBYTECODE OP_3 OP_SPLIT OP_NIP " + S.tokens_to_asm(_rt4m)
            _u4m = [S.PUSH(S._acc_preimage(_pz4m) + S._acc_preimage(_pzg4m)),
                    S.PUSH(S._acc_preimage(_F4f.ZERO) + S._acc_preimage(_F4f.ZERO))]
            for _t4m in range(_lo4m, _hi4m):
                _u4m += [NUM(_val4l[_t4m][0] % S.P), NUM(_val4l[_t4m][1] % S.P)]
            _in4m.append({"redeem": _rd4m, "unlock": S.tokens_to_asm(_u4m + [S.PUSH(b"\x00" * _pad4m)])})
    _r4m = _p2sh_multi(_in4m, evaluate=list(range(1, len(_in4m))))
    _sss4m = [_x.get("scriptSigBytes", -1) for _x in _r4m.get("results", [])]
    _acc4m = [_x.get("ok") for _x in _r4m.get("results", [])]
    _tx4m = _r4m.get("txBytes", -1)
    c4m = (all(_acc4m) and len(_acc4m) == _NQ4m * 2 and _sss4m and max(_sss4m) <= 10000 and 0 < _tx4m < 100000)
    ok_all = ok_all and c4m
    print("HP16.1 whole-tx DOMINANT portion P2SH32 (4m, 1 FS-blob + %d DEEP shards, nq=%d): all shards accept=%s "
          "(%d/%d) ; per-shard scriptSig %d-%dB (<=10000:%s) ; MEASURED txBytes=%d (<100000:%s)  [%s]"
          % (_NQ4m * 2, _NQ4m, all(_acc4m), sum(1 for _a in _acc4m if _a), len(_acc4m),
             (min(_sss4m) if _sss4m else -1), (max(_sss4m) if _sss4m else -1),
             (bool(_sss4m) and max(_sss4m) <= 10000), _tx4m, (0 < _tx4m < 100000), "OK" if c4m else "FAIL"))

    # (4g) opener-input CROSS-INPUT (real BCH-2026 libauth): a per-query DEEP sum-part CONSUMER single-sources an
    # opened cell (the comp cc = the value of the DEEP comp-term) cross-input via OP_INPUTBYTECODE from the opener's
    # exposed [cell_0|cell_1|k] blob, split_cells(3)s it and USES it (split-and-use: forged cell -> wrong value).
    # The stub producer here exposes the 24-byte blob as its first unlock push; the REAL producer = opener_commit_prog
    # (Merkle-binds cells == the opened leaf @k against the pinned root) + the opener_input_prog deploy wiring (root
    # single-sourced from the FS blob, k from the FS input) is the follow-up. Honest accept + forged cc/k reject.
    import native_ct_air_stark as _STK4g
    _pf4g = _STK4g.prove(CT._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=3, fold_step=3, deep=True, seed=0xF54A)
    _q4g = _pf4g["queries"][0]; _k4g = _q4g["k"]; _cc4g = tuple(_q4g["cc"])
    _blob4g = S.enc8(_cc4g[0] % S.P) + S.enc8(_cc4g[1] % S.P) + S.enc8(_k4g)   # opened comp cell + FS index k (24B)
    _read4g = "OP_0 OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x18> OP_SPLIT OP_DROP "   # read input0's first push (24B)
    _chk4g = S.split_cells_prog(3, prefix=0) + [NUM(_k4g), OP("NUMEQUALVERIFY"),      # split -> cc0,cc1,k ; use them
                                                NUM(_cc4g[1] % S.P), OP("NUMEQUALVERIFY"), NUM(_cc4g[0] % S.P), OP("NUMEQUAL")]
    _cred4g = _read4g + S.tokens_to_asm(_chk4g)
    _g4g = _linked(_cred4g, "", "<0x%s>" % _blob4g.hex(), "OP_DROP OP_1")
    _b4g = _linked(_cred4g, "", "<0x%s>" % (S.enc8((_cc4g[0] + 1) % S.P) + S.enc8(_cc4g[1] % S.P) + S.enc8(_k4g)).hex(), "OP_DROP OP_1")
    _bk4g = _linked(_cred4g, "", "<0x%s>" % (S.enc8(_cc4g[0] % S.P) + S.enc8(_cc4g[1] % S.P) + S.enc8((_k4g + 1) % (1 << 20))).hex(), "OP_DROP OP_1")
    c4g = (_g4g.get("accept0") and _g4g.get("accept") and not _g4g.get("error")
           and not _b4g.get("accept") and not _bk4g.get("accept"))
    ok_all = ok_all and c4g
    print("opener-input cross-input consumer (4g, opened comp cell read via OP_INPUTBYTECODE + split-and-use): "
          "producer accept=%s consumer accept=%s ; forged cc / forged k reject=%s/%s ; consumer-redeem=%dB  [%s]"
          % (_g4g.get("accept0"), _g4g.get("accept"), not _b4g.get("accept"), not _bk4g.get("accept"),
             _g4g.get("redeem1Bytes", -1), "OK" if c4g else "FAIL"))

    # (4h) opener-input CROSS-INPUT for the TRACE leaf (52 cells / 424B blob) -- the main sum-part value source.
    # Same as 4g but the opened [52 cells|k] blob is >255 bytes, so its unlock push uses OP_PUSHDATA2 (a 3-byte
    # prefix, NOT the 1-byte OP_PUSHBYTES): the consumer strips 3 bytes. It reads the 424B blob cross-input,
    # split_cells(53)s it and verifies ALL 52 cells + k (split-and-use, fail-closed on any forged cell). The
    # consumer carries a witness (op-budget = (41+unlock_len)*800; here 40 dummy bytes, in the deploy the real
    # sum-part consumer's invz/invzg hints + operands provide the budget). Real libauth, no mock.
    import native_ct_air_stark as _STK4h
    _pf4h = _STK4h.prove(CT._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=3, fold_step=3, deep=True, seed=0xF54A)
    _q4h = _pf4h["queries"][0]; _k4h = _q4h["k"]; _ck4h = _q4h["ck"]
    _cells4h = [_ck4h[_c] for _c in _STK4h.FLAT_COLS]                          # 52 trace cells (FLAT_COLS order)
    _blob4h = b"".join(S.enc8(_c % S.P) for _c in _cells4h) + S.enc8(_k4h)     # [52 cells|k] = 424 bytes
    _read4h = "OP_0 OP_INPUTBYTECODE OP_3 OP_SPLIT OP_NIP <0x%s> OP_SPLIT OP_DROP " % S.encode_num(424).hex()   # strip 3B PUSHDATA2 prefix, take 424B
    _chk4h = S.split_cells_prog(53, prefix=0) + [NUM(_k4h), OP("NUMEQUALVERIFY")]   # split -> [c0..c51, k]; verify k
    _rc4h = list(reversed(_cells4h))                                          # c51..c0
    for _c in _rc4h[:-1]:
        _chk4h += [NUM(_c % S.P), OP("NUMEQUALVERIFY")]                       # verify c51..c1
    _chk4h += [NUM(_rc4h[-1] % S.P), OP("NUMEQUAL")]                          # verify c0 -> [1]
    _cred4h = "OP_DROP " + _read4h + S.tokens_to_asm(_chk4h)                  # drop the op-budget witness, then read+verify
    _cunl4h = "<0x%s>" % (b"\x00" * 40).hex()
    _g4h = _linked(_cred4h, _cunl4h, "<0x%s>" % _blob4h.hex(), "OP_DROP OP_1")
    _forge4h = b"".join(S.enc8((_cells4h[0] + 1) % S.P if _i == 0 else _c % S.P) for _i, _c in enumerate(_cells4h)) + S.enc8(_k4h)
    _b4h = _linked(_cred4h, _cunl4h, "<0x%s>" % _forge4h.hex(), "OP_DROP OP_1")   # forged cell 0
    c4h = (_g4h.get("accept0") and _g4h.get("accept") and not _g4h.get("error") and not _b4h.get("accept"))
    ok_all = ok_all and c4h
    print("opener-input cross-input TRACE leaf (4h, 52 cells / 424B blob, OP_PUSHDATA2 3-byte prefix read + "
          "split_cells(53) + verify-all-52): consumer accept=%s ; forged cell reject=%s ; consumer-redeem=%dB  [%s]"
          % (_g4h.get("accept"), not _b4h.get("accept"), _g4h.get("redeem1Bytes", -1), "OK" if c4h else "FAIL"))

    # (4i) opener_input_prog ROOT single-source (HP9.2, real libauth): the deploy opener must NOT bake / free-witness
    # the Merkle root -- it reads the FS-committed root cross-input. The CLIMB (merkle_verify_stack_prog minus its
    # final root EQUALVERIFY) computes H = the leaf's Merkle root from [sibs, preimage, k] WITHOUT a root; the opener
    # then reads the FS root cross-input via OP_INPUTBYTECODE and EQUALVERIFYs H == read_root. A prover cannot
    # substitute a favourable tree (H must equal the root the FS covenant committed). This sidesteps the stack
    # reorder (root arrives on top from the read, but the climb needs no bottom root). Honest accept + forged-root
    # / tampered-leaf reject. Real libauth, no mock. (Stub FS producer exposes the root as its first push; the real
    # producer is the FS-input covenant whose blob carries tp_root/sel_root/comp_root at fixed offsets.)
    import native_ct_air_stark as _STK4i
    _pf4i = _STK4i.prove(CT._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=3, fold_step=3, deep=True, seed=0xF54A)
    _q4i = _pf4i["queries"][0]; _k4i = _q4i["k"]; _cc4i = tuple(_q4i["cc"])
    _path4i = [(bytes.fromhex(_s), _b) for _s, _b in _q4i["cp"]]
    _pre4i = b"\x00" * 16 + S.enc8(_cc4i[0] % S.P) + S.enc8(_cc4i[1] % S.P)       # comp leaf preimage
    _cr4i = bytes.fromhex(_pf4i["comp_root"]); _d4i = len(_path4i)
    _unl4i = S.tokens_to_asm(S.bound_open_unlock(_pre4i, _path4i, _k4i))          # [sibs, preimage, k] -- ROOTLESS
    _read4i = "OP_0 OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x20> OP_SPLIT OP_DROP "   # read input0's first push (32B root)
    _red4i = S.tokens_to_asm(S.merkle_verify_stack_prog(_d4i)[:-1]) + " " + _read4i + S.tokens_to_asm([OP("EQUALVERIFY"), NUM(1)])
    _g4i = _linked(_red4i, _unl4i, "<0x%s>" % _cr4i.hex(), "OP_DROP OP_1")
    _wr4i = bytearray(_cr4i); _wr4i[0] ^= 0x01
    _br4i = _linked(_red4i, _unl4i, "<0x%s>" % bytes(_wr4i).hex(), "OP_DROP OP_1")   # forged root
    _bp4i = bytearray(_pre4i); _bp4i[16] ^= 0x01
    _bl4i = _linked(_red4i, S.tokens_to_asm(S.bound_open_unlock(bytes(_bp4i), _path4i, _k4i)),
                    "<0x%s>" % _cr4i.hex(), "OP_DROP OP_1")                       # tampered leaf
    c4i = (_g4i.get("accept0") and _g4i.get("accept") and not _g4i.get("error")
           and not _br4i.get("accept") and not _bl4i.get("accept"))
    ok_all = ok_all and c4i
    print("opener_input_prog root single-source (4i, HP9.2: opener climbs to H + reads the FS-committed root "
          "cross-input + EQUALVERIFY): opener accept=%s ; forged root reject=%s ; tampered leaf reject=%s ; "
          "opener-redeem=%dB  [%s]"
          % (_g4i.get("accept"), not _br4i.get("accept"), not _bl4i.get("accept"),
             _g4i.get("redeem1Bytes", -1), "OK" if c4i else "FAIL"))

    # (4j) opener_input_prog FULL ASSEMBLY (HP16.1, real BCH-2026 libauth): the complete deploy opener input.
    # It single-sources BOTH the Merkle root AND the FS query index k cross-input from the FS covenant (input 0
    # exposes comp_root || enc8(k) as its 40-byte first push), opens the leaf @k (climb -> H via
    # merkle_verify_stack_prog[:-1], then EQUALVERIFY H == read_root, HP9.2/4i), BINDS the committed blob's k ==
    # read_k (NUMEQUALVERIFY -- the NEW soundness step beyond opener_commit_prog, which opened at the prover-chosen
    # blob-k; now k is the FS-derived index, so a prover cannot choose a favourable slot), and commits [cells|k]
    # Merkle-bound (cells == opened, LIFO) as its own first unlock push for the downstream sum-part (4g/4h). Reuses
    # the validated merkle_verify_stack climb + split_cells + the opener_commit blob-split/bind; only the two
    # OP_INPUTBYTECODE reads are node-only. comp leaf (2 cells); honest accept + forged root/k/leaf/cell reject.
    import native_ct_air_stark as _STK4j
    _pf4j = _STK4j.prove(CT._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=3, fold_step=3, deep=True, seed=0xF54A)
    assert _pf4j.get("deep") and _STK4j.verify(_pf4j)[0], "4j deep proof must verify"
    _q4j = _pf4j["queries"][0]; _k4j = _q4j["k"]; _cc4j = tuple(_q4j["cc"])
    _path4j = [(bytes.fromhex(_s), _b) for _s, _b in _q4j["cp"]]
    _pre4j = b"\x00" * 16 + S.enc8(_cc4j[0] % S.P) + S.enc8(_cc4j[1] % S.P)              # comp leaf preimage
    _cr4j = bytes.fromhex(_pf4j["comp_root"]); _d4j = len(_path4j)
    _blob4j = S.enc8(_cc4j[0] % S.P) + S.enc8(_cc4j[1] % S.P) + S.enc8(_k4j)              # committed [cc0|cc1|k] (24B)
    _bad_blob4j = S.enc8((_cc4j[0] + 1) % S.P) + S.enc8(_cc4j[1] % S.P) + S.enc8(_k4j)    # forged committed cc0
    _fs4j = _cr4j + S.enc8(_k4j)                                                          # input0 first push: root||k (40B)
    _bad_root4j = bytearray(_cr4j); _bad_root4j[0] ^= 0x01
    _bad_pre4j = bytearray(_pre4j); _bad_pre4j[16] ^= 0x01
    _sibsasm4j = " ".join("<0x%s>" % _s.hex() for _s in reversed([_s for _s, _ in _path4j]))
    def _unl4j(blob, pre): return "<0x%s> %s <0x%s>" % (blob.hex(), _sibsasm4j, pre.hex())
    _pad4j = [S.PUSH(b"\x00"), OP("CAT"), OP("BIN2NUM")]
    _rd_k4j = "OP_0 OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x20> OP_SPLIT OP_NIP " + S.tokens_to_asm(_pad4j)  # -> k as a number
    _rd_root4j = "OP_0 OP_INPUTBYTECODE OP_1 OP_SPLIT OP_NIP <0x20> OP_SPLIT OP_DROP "   # -> first 32B = root
    _rA4j = ([NUM(_d4j + 1), OP("ROLL"), S.PUSH(S.encode_num(16)), OP("SPLIT")] + _pad4j + [OP("SWAP")]
             + [S.PUSH(S.encode_num(8)), OP("SPLIT"), OP("SWAP")] + _pad4j + [OP("TOALT")]      # cc0 -> alt
             + _pad4j + [OP("TOALT"), OP("DUP")])                                               # cc1 -> alt ; DUP k for the bind
    _rC4j = [OP("OVER"), OP("TOALT")] + S.merkle_verify_stack_prog(_d4j)[:-1]                   # stash preimage, climb -> H
    _rD4j = S.split_cells_prog(2, prefix=16) + [OP("FROMALT"), OP("NUMEQUALVERIFY"), OP("FROMALT"), OP("NUMEQUALVERIFY"), NUM(1)]
    _red4j = (S.tokens_to_asm(_rA4j) + " " + _rd_k4j + " " + S.tokens_to_asm([OP("NUMEQUALVERIFY")]) + " "
              + S.tokens_to_asm(_rC4j) + " " + _rd_root4j + S.tokens_to_asm([OP("EQUALVERIFY"), OP("FROMALT")]) + " "
              + S.tokens_to_asm(_rD4j))
    _g4j = _linked(_red4j, _unl4j(_blob4j, _pre4j), "<0x%s>" % _fs4j.hex(), "OP_DROP OP_1")
    _br4j = _linked(_red4j, _unl4j(_blob4j, _pre4j), "<0x%s>" % (bytes(_bad_root4j) + S.enc8(_k4j)).hex(), "OP_DROP OP_1")
    _bk4j = _linked(_red4j, _unl4j(_blob4j, _pre4j), "<0x%s>" % (_cr4j + S.enc8((_k4j + 1) % (1 << 20))).hex(), "OP_DROP OP_1")
    _bl4j = _linked(_red4j, _unl4j(_blob4j, bytes(_bad_pre4j)), "<0x%s>" % _fs4j.hex(), "OP_DROP OP_1")
    _bc4j = _linked(_red4j, _unl4j(_bad_blob4j, _pre4j), "<0x%s>" % _fs4j.hex(), "OP_DROP OP_1")
    c4j = (_g4j.get("accept0") and _g4j.get("accept") and not _g4j.get("error")
           and not _br4j.get("accept") and not _bk4j.get("accept")
           and not _bl4j.get("accept") and not _bc4j.get("accept"))
    ok_all = ok_all and c4j
    print("opener_input_prog FULL assembly (4j, root+k single-source cross-input + open@k + commit[cells|k]): "
          "opener accept=%s ; forged root/k/leaf/cell reject=%s/%s/%s/%s ; opener-redeem=%dB  [%s]"
          % (_g4j.get("accept"), not _br4j.get("accept"), not _bk4j.get("accept"),
             not _bl4j.get("accept"), not _bc4j.get("accept"), _g4j.get("redeem1Bytes", -1), "OK" if c4j else "FAIL"))

    # (5) deployable witness-reading GF(p^2) FRI fold: reads its 9 operands from the unlock and
    # reproduces ext_fold exactly (PICK instead of NUM-literals); fail-closed on a bad inverse
    # hint; a self-checking program (results compared to the cashvm reference) accepts on real VM.
    import random as _rnd
    rng = _rnd.Random(7)
    fold_ok = True
    args = None
    for _ in range(6):
        v = [rng.randrange(S.P) for _ in range(6)]
        x = rng.randrange(1, S.P)
        inv2 = pow(2, S.P - 2, S.P); twox = (2 * x) % S.P; i2x = pow(twox, S.P - 2, S.P)
        args = (v[0], v[1], v[2], v[3], v[4], v[5], inv2, i2x, twox)
        fold_ok = fold_ok and S.run_ext_fold_stack(*args)[0] == S.run_ext_fold(*args)[0]
    try:
        S.run_ext_fold_stack(*(args[:7] + ((args[7] + 1) % S.P,) + args[8:])); fold_rej = False
    except Exception:
        fold_rej = True
    (e0, e1), _ = S.run_ext_fold(*args)
    chk = [NUM(e1), OP("NUMEQUALVERIFY"), NUM(e0), OP("NUMEQUALVERIFY"), OP("FROMALT"), OP("DROP"), NUM(1)]
    rf = _libauth(S._field_prelude() + S.ext_fold_stack_prog() + chk, S.ext_fold_stack_unlock(*args))
    c5 = fold_ok and fold_rej and rf["accept"]
    ok_all = ok_all and c5
    print("deployable fold: reproduces ext_fold=%s ; bad-hint reject=%s ; redeem=%dB witness=%dB accept=%s  [%s]"
          % (fold_ok, fold_rej, rf["redeemBytes"], rf["unlockBytes"], rf["accept"], "OK" if c5 else "FAIL"))

    # (6) deployable FRI fold CHAIN: n sequential folds, the running value flowing on one stack
    # (fv on top). Reproduces the sequential single-fold reference, fail-closed on a corrupted
    # layer hint, and self-checks against the reference + accepts on the real VM.
    inv2c = pow(2, S.P - 2, S.P)
    rng2 = _rnd.Random(11)
    layers = []
    for _ in range(8):
        x = rng2.randrange(1, S.P); twox = (2 * x) % S.P; i2x = pow(twox, S.P - 2, S.P)
        layers.append((rng2.randrange(S.P), rng2.randrange(S.P), rng2.randrange(S.P), rng2.randrange(S.P), inv2c, i2x, twox))
    ifv0, ifv1 = rng2.randrange(S.P), rng2.randrange(S.P)
    rfv = (ifv0, ifv1)
    for layer in layers:
        rfv, _ = S.run_ext_fold(rfv[0], rfv[1], *layer)
    cfv, _ = S.run_ext_fold_chain(layers, ifv0, ifv1)
    chain_ok = cfv == rfv
    bad = [list(layer) for layer in layers]; bad[3][5] = (bad[3][5] + 1) % S.P   # corrupt i2x in layer 3
    try:
        S.run_ext_fold_chain([tuple(layer) for layer in bad], ifv0, ifv1); chain_rej = False
    except Exception:
        chain_rej = True
    chkc = [NUM(rfv[1]), OP("NUMEQUALVERIFY"), NUM(rfv[0]), OP("NUMEQUALVERIFY"), OP("FROMALT"), OP("DROP"), NUM(1)]
    rc = _libauth(S.ext_fold_chain_prog(8) + chkc, S.ext_fold_chain_unlock(layers, ifv0, ifv1))
    c6 = chain_ok and chain_rej and rc["accept"]
    ok_all = ok_all and c6
    print("deployable fold-chain (8 layers): VM==reference=%s ; bad-hint reject=%s ; redeem=%dB witness=%dB accept=%s  [%s]"
          % (chain_ok, chain_rej, rc["redeemBytes"], rc["unlockBytes"], rc["accept"], "OK" if c6 else "FAIL"))

    # (7) SOUNDNESS capstone: the opener's query index is DERIVED from the FS transcript (never a
    # free witness), so a prover cannot pick the position; the opening verifies against the pinned
    # root at the derived index. Exercises OP_BIN2NUM (libauth requires minimal encoding for the
    # FS arithmetic -- the cashvm-only 0x00-pad alone is rejected by the deployable VM).
    import hashlib
    N = 1 << _DEPTH
    s = hashlib.sha256(b"STARK-v0" + root).digest()
    kfs = int.from_bytes(hashlib.sha256(s + b"idx").digest()[:8], "little") % N
    fs_ok, _ = S.run_fs_bound_open(N, _DEPTH, root, preimages[kfs], sm_path(tree, kfs))
    kbad = (kfs + 1) % N
    fs_wrong, _ = S.run_fs_bound_open(N, _DEPTH, root, preimages[kbad], sm_path(tree, kbad))
    rfs = _libauth(S.fs_bound_open_prog(N, _DEPTH, root), S.fs_bound_open_unlock(preimages[kfs], sm_path(tree, kfs)))
    c7 = fs_ok and (not fs_wrong) and rfs["accept"] and rfs["totalScriptSig"] <= 1650
    ok_all = ok_all and c7
    print("FS-bound opener (derived index, k=%d): accept=%s ; wrong-position reject=%s ; libauth accept=%s total=%dB  [%s]"
          % (kfs, fs_ok, not fs_wrong, rfs["accept"], rfs["totalScriptSig"], "OK" if c7 else "FAIL"))

    # (8) deployable witness-reading CT-AIR composition: reads residuals/alphas/qf from the unlock
    # and reproduces run_compose exactly (the GF(p^2) value the FRI layer-0 opening must match).
    rng3 = _rnd.Random(5)
    nt, nb = 3, 2
    tv = [rng3.randrange(S.P) for _ in range(nt)]
    ta = [(rng3.randrange(S.P), rng3.randrange(S.P)) for _ in range(nt)]
    qf = rng3.randrange(S.P)
    bv = [rng3.randrange(S.P) for _ in range(nb)]
    bix = [rng3.randrange(S.P) for _ in range(nb)]
    ba = [(rng3.randrange(S.P), rng3.randrange(S.P)) for _ in range(nb)]
    exp = S.run_compose(tv, ta, qf, bv, bix, ba)[0]
    got = S.run_compose_stack(tv, ta, qf, bv, bix, ba)[0]
    chkc2 = [NUM(exp[1]), OP("NUMEQUALVERIFY"), NUM(exp[0]), OP("NUMEQUALVERIFY"), OP("FROMALT"), OP("DROP"), NUM(1)]
    rcm = _libauth(S._field_prelude() + S.compose_stack_prog(nt, nb) + chkc2, S.compose_stack_unlock(tv, ta, qf, bv, bix, ba))
    c8 = (got == exp) and rcm["accept"]
    ok_all = ok_all and c8
    print("deployable compose (n_t=%d n_b=%d): VM==run_compose=%s ; redeem=%dB witness=%dB accept=%s  [%s]"
          % (nt, nb, got == exp, rcm["redeemBytes"], rcm["unlockBytes"], rcm["accept"], "OK" if c8 else "FAIL"))

    # (9) deployable Poseidon2 S-box-lane residual: reads s/rc/u2/u4/u6/gate from the unlock and
    # reproduces run_sbox_lane exactly -- the AIR residual computed on-chain from the trace cells
    # that feeds the composition (so the composed value is bound to the opened trace, not witness).
    rng4 = _rnd.Random(9)
    sb_args = tuple(rng4.randrange(S.P) for _ in range(6))
    sbref, _ = S.run_sbox_lane(*sb_args)
    sbdep, _ = S.run_sbox_lane_stack(*sb_args)
    chks = []
    for r in reversed(sbref):
        chks += [NUM(r), OP("NUMEQUALVERIFY")]
    chks += [OP("FROMALT"), OP("DROP"), NUM(1)]
    rsb = _libauth(S._field_prelude() + S.sbox_lane_stack_prog() + chks, S.sbox_lane_stack_unlock(*sb_args))
    c9 = (sbdep == sbref) and rsb["accept"]
    ok_all = ok_all and c9
    print("deployable S-box lane: VM==run_sbox_lane=%s ; redeem=%dB witness=%dB accept=%s  [%s]"
          % (sbdep == sbref, rsb["redeemBytes"], rsb["unlockBytes"], rsb["accept"], "OK" if c9 else "FAIL"))

    # (10) deployable Poseidon2 state residual reading a PRECOMPUTED ef_j (state_lane_from_ef): given
    # ef_j = sum_k M_row[k]*y_full[k] (the external MDS image produced on-chain by matmul_external, see 10b)
    # plus y_part/diag/sj/isf/isp from the unlock, reproduces run_state_lane's v_j exactly -- the c_st
    # constraint computed on-chain from the opened trace cells.
    rng5 = _rnd.Random(10)
    W = S.WIDTH
    M_row = [rng5.randrange(S.P) for _ in range(W)]
    y_full = [rng5.randrange(S.P) for _ in range(W)]
    y_part = [rng5.randrange(S.P) for _ in range(W)]
    diag_j = rng5.randrange(S.P); jlane = rng5.randrange(W)
    sj = rng5.randrange(S.P); isf = rng5.randrange(S.P); isp = rng5.randrange(S.P)
    ef_j = sum(M_row[k] * y_full[k] for k in range(W)) % S.P     # the ef matmul_external produces for lane j
    stref, _ = S.run_state_lane(M_row, y_full, y_part, diag_j, jlane, sj, isf, isp)
    stdep, _ = S.run_state_lane_from_ef(ef_j, y_part, diag_j, jlane, sj, isf, isp)
    chkst = [NUM(stref), OP("NUMEQUALVERIFY"), OP("FROMALT"), OP("DROP"), NUM(1)]
    rst = _libauth(S._field_prelude() + S.state_lane_from_ef_stack_prog(jlane) + chkst,
                   S.state_lane_from_ef_stack_unlock(ef_j, y_part, diag_j, sj, isf, isp))
    c10 = (stdep == stref) and rst["accept"]
    ok_all = ok_all and c10
    print("deployable state lane (from_ef, j=%d): VM==run_state_lane=%s ; redeem=%dB witness=%dB accept=%s  [%s]"
          % (jlane, stdep == stref, rst["redeemBytes"], rst["unlockBytes"], rst["accept"], "OK" if c10 else "FAIL"))
    # NOTE: matmul_external (the structured external MDS producing ef for all lanes at once, feeding every
    # state lane above) is a SUB-ROUTINE of the transition assembly, never a standalone P2SH input. Its
    # correctness is validated on cashvm (native_ct_shard self_test: 21 vectors == CT._ext_apply, and inside
    # the full deployable shard_verify) and its real-VM op-density (measured standalone ~124003 op) is
    # validated in its deployment context by the per-query/shard libauth measurement (HP3.5b-iii-4), where
    # it runs under the query's large witness budget -- a standalone libauth accept is op-density-infeasible.

    # (11) deployable Num2Bits range residuals: reads the 11 inputs from the unlock and reproduces
    # run_range's five residuals exactly -- the booleanity + recomposition constraints on-chain.
    rng6 = _rnd.Random(11)
    rg_args = tuple(rng6.randrange(S.P) for _ in range(11))
    rgref, _ = S.run_range(*rg_args)
    rgdep, _ = S.run_range_stack(*rg_args)
    chkrg = []
    for r in reversed(rgref):
        chkrg += [NUM(r), OP("NUMEQUALVERIFY")]
    chkrg += [OP("FROMALT"), OP("DROP"), NUM(1)]
    rrg = _libauth(S._field_prelude() + S.range_residual_stack_prog() + chkrg,
                   S.range_residual_stack_unlock(*rg_args))
    c11 = (rgdep == rgref) and rrg["accept"]
    ok_all = ok_all and c11
    print("deployable range residuals: VM==run_range=%s ; redeem=%dB witness=%dB accept=%s  [%s]"
          % (rgdep == rgref, rrg["redeemBytes"], rrg["unlockBytes"], rrg["accept"], "OK" if c11 else "FAIL"))

    # (12) deployable additive conservation residual: reads vh_in/vh_o0/vh_o1/vh_fee from the unlock
    # and reproduces run_conservation exactly -- the value-conservation constraint on-chain.
    rng7 = _rnd.Random(12)
    cs_args = tuple(rng7.randrange(S.P) for _ in range(4))
    csref, _ = S.run_conservation(*cs_args)
    csdep, _ = S.run_conservation_stack(*cs_args)
    chkcs = [NUM(csref), OP("NUMEQUALVERIFY"), OP("FROMALT"), OP("DROP"), NUM(1)]
    rcs = _libauth(S._field_prelude() + S.conservation_stack_prog() + chkcs,
                   S.conservation_stack_unlock(*cs_args))
    c12 = (csdep == csref) and rcs["accept"]
    ok_all = ok_all and c12
    print("deployable conservation: VM==run_conservation=%s ; redeem=%dB witness=%dB accept=%s  [%s]"
          % (csdep == csref, rcs["redeemBytes"], rcs["unlockBytes"], rcs["accept"], "OK" if c12 else "FAIL"))

    # (13) HP1 assembled compose->FRI seam on a REAL query: compose computes the composition on the
    # stack, the FRI chain binds it to the opened layer-0 value and folds. Correctness is validated on
    # the reference VM (cashvm, op_cost-accounted). The BAKED seam inlines all FRI data, so it exceeds
    # MAX_SCRIPT_SIZE (10000B) and cannot run as one libauth script -- that oversize is exactly why the
    # deployable witness-split + thin-shard (HP2/HP4, <=1650B/input) exist; the baked byte count is the
    # informative measurement here, not a shippable form.
    import native_ct_air_stark as STK
    pfa = STK.prove(CT._demo_witness(depth=2), seed=2026)
    ta = STK.query_terms(pfa)[0]; fa = STK.query_fri_terms(pfa)[0]
    okasm, ocasm = S.run_assemble_compose_fri(ta, fa)
    rasm = _libauth(S.assemble_compose_fri_prog(ta, fa), [])
    c13 = okasm
    ok_all = ok_all and c13
    print("HP1 assembled compose->FRI seam (real query): cashvm accept=%s op_cost=%d ; baked redeem=%dB "
          "(>10000B MAX_SCRIPT_SIZE -> needs HP2 witness-split) libauth-run=%s  [%s]"
          % (okasm, ocasm, rasm["redeemBytes"], rasm["accept"], "OK" if c13 else "FAIL"))

    # --- 3.4b: param-drift protection -- the deployed shard's soundness params MUST trace to the ONE
    #     canonical native_ct_air_config (round-5 R2-L3: a shard with fewer queries or a lower blowup
    #     collapses the >=100-bit margin -> the shard's hardcoded params MUST be checked against config).
    #     Build the PINNED-config proof (blowup/grind/queries FROM config, not the TEST values) and assert
    #     its params == config, the derived shard params (N/T/depth/shift) are self-consistent, and config
    #     reaches the security target. A param-consistency guard, not a full-shard run (byte-infeasible at
    #     Q=21 unrolled -> HP3.5b loop). ---
    import native_ct_air_config as CFG
    assert CFG.SECURITY_BITS >= CFG.SECURITY_TARGET_BITS, "config below the security target"
    pfp = STK.prove(CT._demo_witness(depth=2), blowup=CFG.BLOWUP, grind_b=CFG.GRIND_BITS,
                    n_queries=CFG.QUERIES, seed=2026)
    okp = STK.verify(pfp)[0]
    _meta, _T = CT.ct_build_layout(pfp["stmt"]["depth"])
    _N = STK._setup(_T, pfp["blowup"])[0]
    _depth = _N.bit_length() - 1; _shift = _N // _T
    drift_ok = (pfp["blowup"] == CFG.BLOWUP and pfp["grind_b"] == CFG.GRIND_BITS
                and pfp["nq"] == CFG.QUERIES and _shift == CFG.BLOWUP and _N == _T * CFG.BLOWUP
                and (1 << _depth) == _N and okp)
    ok_all = ok_all and drift_ok
    print("3.4b param-drift (shard params vs native_ct_air_config): config %.0f-bit "
          "(Q=%d blowup=%d grind=%d fold=%d) ; pinned proof blowup=%d grind=%d nq=%d -> derived N=2^%d "
          "T=2^%d shift=%d(==blowup) verify=%s  [%s]"
          % (CFG.SECURITY_BITS, CFG.QUERIES, CFG.BLOWUP, CFG.GRIND_BITS, CFG.FOLD,
             pfp["blowup"], pfp["grind_b"], pfp["nq"], _depth, _T.bit_length() - 1, _shift, okp,
             "OK" if drift_ok else "FAIL"))
    return ok_all


if __name__ == "__main__":
    success = run()
    print("DEPLOYABLE MERKLE OPENER (real libauth BCH-2026):", "ALL OK" if success else "FAIL")
    sys.exit(0 if success else 1)
