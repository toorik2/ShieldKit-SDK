"""
standard_tx_sweep.py -- ANALYSIS ONLY (read-only research; no app code touched).

QUESTION: is there a >=100-bit config where the native CT-AIR hash-STARK
verifier fits a STANDARD single tx? Deploy structure GROUNDED 2026-07-02 vs the official libauth
bch-2026-consensus.js + bch-2023-instruction-set.js verify() (the VM the harness runs):
  - P2SH32 mandatory (maximumStandardLockingBytecodeLength=201 -> a bare >201B verifier locking
    output is non-standard). The redeem is REVEALED in the spending scriptSig, so per input
    scriptSig = witness(unlock) + PUSH(redeem), and BOTH count toward the limits.
  - per-input scriptSig <= 10000B (maximumStandardUnlockingBytecodeLength=10000, BCH_2026 override;
    the old ConsensusCommon 1650 is removed) -- so unlock room per input = 10000 - redeem.
  - whole spending tx <= 100000B (maximumStandardTransactionSize) over sum(unlock)+sum(redeem)+ovh.

This sweeps the soundness lever (blowup, grind -> queries q) against the REAL VM-measured op-cost
(cost_report_native) and the REAL byte model (proof_size_native), models the P2SH redeem coupling,
and reports the whole-tx bytes + feasibility for the LOOP (deploy form) and UNROLLED (sensitivity)
redeem sizes.

NOT a build. It bounds the search: it tells us whether the whole tx (data + sharded redeem) clears
100KB. Exact per-input bytes are measured on the real VM in the iii-4 build (deploy_measure.mjs).

Reuses (single source of truth, no duplicated math):
  cost_report_native.measure_config   (REAL per-query op, re-measured per blowup)
  proof_size_native.native_proof_bytes (REAL proof byte model)
  cost_report.max_op_cost/std/cons     (the (41+L)*800 etc. budgets)
"""
import math
import cost_report_native as CN
import proof_size_native as PSN
from cost_report import max_op_cost, max_std_iters, max_cons_iters

# BCH limits GROUNDED vs official libauth bch-2026-consensus.js (ConsensusBch2026). The BCH_2026
# standard per-input scriptSig cap = maximumStandardUnlockingBytecodeLength = 10000 (the old
# ConsensusCommon 1650 is overridden/removed; matches plan 3.1). scriptSig is also <=10000 at
# consensus (maximumBytecodeLength) -> STD and CONS share the per-input cap; they differ in tx size.
STD_TX, CONS_TX = 100_000, 1_000_000            # maximumStandard / maximum TransactionSize
STD_UNLOCK, CONS_UNLOCK = 10_000, 10_000        # per-input scriptSig cap (unlock+redeem, P2SH)
PER_INPUT_OVERHEAD = 42        # outpoint 36 + sequence 4 + scriptlen varint ~2 (non-script)
TX_SKELETON = 250             # version + counts + pool-out + change-out + locktime (approx)

# per-input redeem-bytecode estimate. P2SH: the redeem is revealed in the scriptSig, so it BOTH
# eats the per-input unlock budget (10000 - redeem room for witness) AND counts toward the 100KB tx.
# LOOP = the deploy form (plan 2.41: an OP_BEGIN/UNTIL loop-opener redeem is ~200B, constant in the
# witness volume it processes). UNROLLED = pessimistic sensitivity (measured FRI redeems 1009-1892B,
# plan iii-4). Exact per-input-type loop redeems (compose/FRI/selector) are measured in the build.
REDEEM_LOOP, REDEEM_UNROLLED = 200, 1500

# per-input budgets at the full-scriptSig cap
OP_STD  = max_op_cost(STD_UNLOCK)       # (41+10000)*800 = 8,032,800
OP_CONS = max_op_cost(CONS_UNLOCK)      # (41+10000)*800 = 8,032,800
HSTD    = max_std_iters(STD_UNLOCK)     # (41+10000)/2 standard hash-iter budget/input
HCONS   = max_cons_iters(CONS_UNLOCK)   # (41+10000)*7/2 consensus hash-iter budget/input

SEC_TARGET = 100
D = 20                                   # native trace 2^10 (smallest config)


def q_for(blowup, grind):
    """conjectured (Starkware) regime: per-query bits = log2(blowup); q*log2(bl)+grind>=100."""
    per_q = math.log2(blowup)
    return max(1, math.ceil((SEC_TARGET - grind) / per_q))


def measure_perquery(blowup):
    """REAL VM re-measure of per-query op + once-per-proof op at this blowup (N=2^10*bl)."""
    CN.BLOWUP = blowup
    c = CN.measure_config(D)
    return c["oc_q"], c["oc_fs"] + c["oc_selhash"], c["tr"]["m"]


def plan_config(blowup, grind, oc_q, once, log_trace, redeem):
    q = q_for(blowup, grind)
    op_total = q * oc_q + once
    data_bytes, sec, parts = PSN.native_proof_bytes(
        log_trace, blowup=blowup, queries=q, grind=grind)
    # WITNESS floor: min total unlock bytes over all inputs -- must buy the op budget (op_total/800)
    # AND carry the proof data. The redeem is separate (P2SH, added to the tx below).
    floor = max(op_total / 800.0, data_bytes)

    # P2SH thin-sharding: each input's scriptSig = witness(unlock) + PUSH(redeem) <= unlock cap, so the
    # witness room per input = cap - redeem. n inputs must carry all the proof data as witness AND the
    # op budget. Whole tx = sum(unlock) + sum(redeem) + n*overhead + skeleton = data + n*(redeem+ovh) + skel.
    def shard(cap, op_cap, tx_cap):
        room = cap - redeem                              # witness bytes per input under P2SH
        n = math.ceil(max(op_total / op_cap, data_bytes / room))
        tx = data_bytes + n * (redeem + PER_INPUT_OVERHEAD) + TX_SKELETON
        return n, tx, tx_cap - tx
    n_std, tx_std, head_std = shard(STD_UNLOCK, OP_STD, STD_TX)
    n_cons, tx_cons, head_cons = shard(CONS_UNLOCK, OP_CONS, CONS_TX)

    # per-query opening bytes (does one query's data fit one input's witness room, <10000?)
    perq_open = parts["trace_open"] // q + parts["fri_query"] // q if q else 0

    return dict(blowup=blowup, grind=grind, q=q, sec=sec, op_total=op_total, redeem=redeem,
                data_bytes=data_bytes, floor=floor,
                n_std=n_std, tx_std=tx_std, head_std=head_std,
                n_cons=n_cons, tx_cons=tx_cons, perq_open=perq_open)


def main():
    print("=" * 96)
    print("PFAD C -- STANDARD single-tx feasibility SWEEP (real-VM op + real byte model, P2SH BCH-2026)")
    print("=" * 96)
    print(f"limits (libauth BCH_2026): STD_TX={STD_TX:,} CONS_TX={CONS_TX:,} | per-input scriptSig cap "
          f"STD={STD_UNLOCK:,} CONS={CONS_UNLOCK:,} (unlock+redeem, P2SH)")
    print(f"per-input op budget: (41+{STD_UNLOCK})*800 = {OP_STD:,}")
    print(f"target security >= {SEC_TARGET} bit (conjectured: q*log2(blowup)+grind)")
    print(f"native trace D={D} -> 2^{CN.trace_rows(D)['m']}; P2SH tx = data + sum(redeem+overhead) + skeleton")
    print()

    # measure per-query op once per blowup (REAL VM)
    blowups = [16, 32, 64, 128, 256]
    perq = {}
    for bl in blowups:
        oc_q, once, lt = measure_perquery(bl)
        perq[bl] = (oc_q, once, lt)
        print(f"  [measured] blowup={bl:>3}: per-query op={oc_q:>12,}  once/proof={once:,}  N=2^{lt+int(math.log2(bl))}")
    print()

    grinds = [16, 24, 32, 40]
    for redeem in (REDEEM_LOOP, REDEEM_UNROLLED):
        form = "LOOP = deploy form (~const redeem)" if redeem == REDEEM_LOOP else "UNROLLED = pessimistic sensitivity"
        print(f"### per-input redeem = {redeem}B  [{form}]  (P2SH: scriptSig = unlock + redeem <= {STD_UNLOCK})")
        print(f"{'blowup':>6} {'grind':>5} {'q':>3} {'sec':>4} | {'op_total':>12} {'floor B':>9} "
              f"{'1q open':>8} | {'STD n':>5} {'tx_std':>8} {'head':>8} | {'CONS n':>6} {'tx_cons':>9}")
        print("-" * 96)
        best = None
        for bl in blowups:
            oc_q, once, lt = perq[bl]
            for g in grinds:
                r = plan_config(bl, g, oc_q, once, lt, redeem)
                std_ok = r["tx_std"] < STD_TX
                flag = " STD-OK" if std_ok else ""
                print(f"{bl:>6} {g:>5} {r['q']:>3} {r['sec']:>4.0f} | {r['op_total']:>12,} "
                      f"{r['floor']:>9,.0f} {r['perq_open']:>8,} | {r['n_std']:>5} {r['tx_std']:>8,.0f} "
                      f"{r['head_std']:>8,.0f} | {r['n_cons']:>6} {r['tx_cons']:>9,.0f}{flag}")
                if std_ok and (best is None or r["tx_std"] < best["tx_std"]):
                    best = r
        if best:
            print(f"  CHEAPEST STD @redeem={redeem}B: blowup={best['blowup']} grind={best['grind']} q={best['q']} "
                  f"sec~{best['sec']:.0f} -> {best['n_std']} inputs, tx_std~{best['tx_std']:,.0f}B "
                  f"(headroom ~{best['head_std']:,.0f}B < {STD_TX:,}). STANDARD FEASIBLE.")
        else:
            print(f"  NO config clears 100KB @redeem={redeem}B.")
        print()

    print("READING:")
    print("  floor B = min total WITNESS bytes (op-budget op/800 OR proof-data, whichever binds).")
    print("  1q open = ONE query's opening bytes; <10000 => one query fits one input's witness room.")
    print("  tx_std  = data + n*(redeem+overhead) + skeleton -- P2SH: the redeem IS in the scriptSig,")
    print("            counted toward 100KB (not free headroom). STD-OK = tx_std < 100KB.")
    print()
    print("CAVEATS (honest): (0) FOLD / PAIR-LEAF (HP6.1, RESOLVED 2026-07-02): the deployed FRI folds BY 2; the")
    print("  deployed opener now commits each fold-2 coset (v@i, w@i+half) as ONE 'pair-leaf' Merkle leaf -> 1 path/")
    print("  layer instead of 2. LIBAUTH-MEASURED (scratchpad pairleaf_bytes.py, real BCH-2026): per-query full FRI")
    print("  chain unlock 2108B vs 4488B 2-leaf (2.13x fewer paths), both accept -> the real deployed FRI witness is")
    print("  ~HALF the fold-2/2-leaf value. data_bytes below (proof_size_native fold-8) is a rough proxy; the GROUNDED")
    print("  pair-leaf feasibility is scratchpad hp61_fold_bytes.py (calibrated to 4488B, libauth-confirmed): ~69-96KB.")
    print("  (1) per-query op = this blowup's REAL cashvm measurement (deployed structured")
    print("  matmul_external MDS, iii-0c); real libauth OP_MUL size^2 (CHIP-2021-05:89, +122op/MUL measured)")
    print("  makes this a conservative UPPER bound. (2) conjectured soundness regime; provable/unique-decoding")
    print("  = 2x queries (the grind column is the safety proxy). (3) redeem: LOOP 200B = the deploy form")
    print("  (2.41 loop-opener, constant); exact per-input-type loop redeems (compose/FRI/selector) are measured")
    print("  in the iii-4 build; UNROLLED 1500B brackets the pessimistic per-input redeem. Both clear 100KB.")


if __name__ == "__main__":
    main()
