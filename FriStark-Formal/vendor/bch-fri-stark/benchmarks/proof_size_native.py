"""
proof_size_native.py -- byte accounting for the NATIVE CT-AIR zk-STARK proof,
to check the <=90KB budget (E2) of PATHC_PHASE0_HASHSTARK_FEASIBILITY (AUFGABE A).

WHY THIS FILE EXISTS (HP4.1 / E2):
  proof_size.py books the proof bytes for a GENERIC trace (2^10..2^16) but with
  TWO settings that do NOT match the native CT-AIR + the plan's E2 hint:
    * it counts only ONE trace opening per query; the real verifier opens TWO
      (current row k + next-row kn=(k+shift)%N, membership_stark.verify:268-271 /
      stark.verify:222-225) -> trace_open bytes are ~doubled (E2 HINT in the plan).
    * its n_cols is the membership width (12), not the native committed trace
      width (Poseidon2 state t=12 + the x^7-decomposition aux cells).
  This file REUSES proof_size.proof_bytes (the validated FRI byte model -- NO
  duplicated byte math) and:
    (i)  adds the SECOND trace opening (E2 HINT correction),
    (ii) uses the NATIVE per-config trace 2^10 (D=20) / 2^11 (D=26,32) and the
         native committed column count,
    (iii) uses EXACTLY the FRI structure the op-cost model uses
          (cost_report_native: blowup=16, q=21, fold=8, layer-depth step -3),
         so BYTE model and OP-COST model are CONSISTENT (HP6.1 consistency).
  Result: proof KB per config (D=20/26/32) + the <=90KB verdict, with the
  fri_roots / trace_open / fri_query / final / grind breakdown the task asks for.

CONSISTENCY (single source of truth -- imported, not re-hardcoded):
    proof_size.proof_bytes          (FRI/Merkle byte model + soundness accounting)
    cost_report_native.trace_rows   (native trace size 2^m per config D)
    cost_report_native.BLOWUP/Q/FOLD (FRI params identical to the op-cost report)
  The ONLY native-specific additions are: +1 trace opening, native n_cols.

NATIVE COMMITTED TRACE WIDTH (n_cols):
  round-per-row Poseidon2 (HP2-ERGEBNIS / GOLDILOCKS_NATIVE_HASH.md): each trace
  row = the t=12 state lanes + the x^7 S-box decomposition aux (u2,u4,u6) for the
  active lane(s). Committed width = 12 state + 3 aux = 15 field elements/row.
  (The membership PoC commits the analogous 6 = st+u2+u4+u6+nu+inj. 15 is the
  native-state generalization; flagged as the layout assumption below.)
  Single-row Poseidon2 (all 30 rounds in one ~600-col row) is the alternative
  layout: far fewer ROWS (smaller Merkle paths) but ~600 cols/leaf -> larger
  trace_open per query; net proof size is similar (paths shrink, columns grow).
  We measure round-per-row and flag the alternative (same caveat as HP3.2).
"""
import math

# REUSE the validated byte model + soundness accounting (no duplicated math).
# (proof_size.py runs its own merkle/hiding self-tests + a banner table at import;
#  that is the existing module's self-test output and is left intact.)
from proof_size import proof_bytes, HASH, FELT, EXT
# REUSE the native trace size + FRI params (single source of truth).
import cost_report_native as CN

# native committed trace width: Poseidon2 state t=12 + x^7 aux (u2,u4,u6)
N_COLS_NATIVE = CN.T_STATE + 3            # 15

# FRI / soundness config -- identical to the native OP-COST report
BLOWUP   = CN.BLOWUP                       # 16
QUERIES  = CN.Q                            # 21
FOLD     = CN.FOLD                         # 8
GRIND    = 16                              # proof_size headline grind bits
FINAL_DEG = 8                              # proof_size default final-layer degree


def native_proof_bytes(log_trace, n_cols=N_COLS_NATIVE,
                       blowup=BLOWUP, queries=QUERIES, grind=GRIND, fold=FOLD,
                       trace_opens=2):
    """Native proof bytes = proof_size.proof_bytes (1 trace open counted) PLUS
    the (trace_opens-1) EXTRA trace opening(s) the plan's E2 HINT requires.

    proof_size.proof_bytes counts trace_open = queries*(n_cols*FELT + logN*HASH)
    for ONE opening. The real verifier opens `trace_opens` rows per query (k + kn),
    so we add (trace_opens-1) more identical openings and fold them into the
    breakdown -- reusing the SAME per-opening formula, no new byte math."""
    size, sec, parts = proof_bytes(log_trace, blowup, queries, grind, fold,
                                   n_cols, final_deg=FINAL_DEG)
    N = (1 << log_trace) * blowup
    logN = int(math.log2(N))
    one_open = queries * (n_cols * FELT + logN * HASH)   # identical to proof_size:22
    extra = (trace_opens - 1) * one_open
    parts = dict(parts)
    parts["trace_open"] += extra                          # now counts BOTH rows
    size += extra
    return size, sec, parts


def main():
    print("=" * 78)
    print("AUFGABE A -- NATIVE CT-AIR proof size vs <=90KB (E2)")
    print("=" * 78)
    print(f"REUSED byte model: proof_size.proof_bytes  (HASH={HASH} FELT={FELT} EXT={EXT})")
    print(f"native n_cols = {N_COLS_NATIVE} (Poseidon2 state t={CN.T_STATE} + x^7 aux u2,u4,u6)")
    print(f"FRI (= op-cost report): blowup={BLOWUP} queries q={QUERIES} fold={FOLD} "
          f"grind={GRIND}  EXT={EXT}")
    print(f"trace openings/query = 2 (current k + next-row kn)  [E2 HINT correction]")
    print()

    # native trace per config, EXACTLY as the op-cost report computes it
    cfg_log = {}
    for D in (20, 26, 32):
        tr = CN.trace_rows(D)
        cfg_log[D] = tr["m"]            # log2(trace)

    print("-" * 78)
    print(f"{'D':>3} {'log2(tr)':>8} {'N=tr*bl':>9} {'~security':>10} "
          f"{'proof KB':>9} {'<=90KB':>7}")
    results = {}
    for D in (20, 26, 32):
        lt = cfg_log[D]
        size, sec, parts = native_proof_bytes(lt)
        results[D] = (lt, size, sec, parts)
        N = (1 << lt) * BLOWUP
        ok = "OK" if size <= 90_000 else "OVER"
        print(f"{D:>3} {lt:>8} 2^{int(math.log2(N)):<7} {sec:>9.0f}b "
              f"{size/1000:>8.1f}K {ok:>7}")
    print()

    # full breakdown per config (the task asks for fri_roots/trace_open/fri_query/
    # final/grind aufschluesselung)
    for D in (20, 26, 32):
        lt, size, sec, parts = results[D]
        print(f"### D={D}  (trace 2^{lt}, FRI domain 2^{int(math.log2((1<<lt)*BLOWUP))})  "
              f"security ~{sec:.0f} bit")
        for k in ("fri_roots", "trace_open", "fri_query", "final_poly", "grind+misc"):
            print(f"     {k:<12} {parts[k]/1000:7.2f} KB")
        print(f"     {'TOTAL':<12} {size/1000:7.2f} KB   "
              f"({'<=90KB OK' if size <= 90_000 else 'OVER 90KB'})")
        print()

    # cross-check: the dominant term is fri_query (per-query FRI openings). Trace
    # opening doubling (E2 HINT) is the native correction over proof_size headline.
    lt20 = cfg_log[20]
    s1, _, p1 = proof_bytes(lt20, BLOWUP, QUERIES, GRIND, FOLD, N_COLS_NATIVE, final_deg=FINAL_DEG)
    s2, _, p2 = native_proof_bytes(lt20)
    print("-" * 78)
    print("E2 HINT cross-check (D=20, trace 2^%d):" % lt20)
    print(f"  trace_open with 1 opening (proof_size baseline) = {p1['trace_open']/1000:.2f} KB")
    print(f"  trace_open with 2 openings (native, k + kn)     = {p2['trace_open']/1000:.2f} KB")
    print(f"  total 1-open = {s1/1000:.2f} KB  ->  2-open = {s2/1000:.2f} KB "
          f"(+{(s2-s1)/1000:.2f} KB)")
    print()
    print("VERDICT (E2 <=90KB):")
    worst = max(results.values(), key=lambda r: r[1])
    print(f"  worst config = {worst[1]/1000:.1f} KB "
          f"({'<=90KB -> E2 SATISFIED' if worst[1] <= 90_000 else 'OVER 90KB -> E2 FAIL'})")
    print()
    print("ASSUMPTIONS / OPEN:")
    print("  * n_cols=15 = round-per-row committed width (state 12 + x^7 aux 3);")
    print("    single-row Poseidon2 (~600 cols, far fewer rows) is the alternative")
    print("    layout -> paths shrink, columns grow, net size ~similar (HP3.2 OPEN).")
    print("  * fold=8 + layer-depth step -3 = IDENTICAL to cost_report_native op-cost")
    print("    model (HP6.1 fold consistency held: NOT the stark.py fold-2 path which")
    print("    proof_size.py warns blows to ~135KB).")
    print("  * EXT=16 booked for FRI folded values/challenges (extension field), same")
    print("    as proof_size.py; base-vs-ext final decision = HP6.1 (OPEN).")
    print("  * grind bits do NOT affect size (8-byte nonce); security accounting is")
    print("    q*log2(blowup)+grind = conjectured bits (proof_size model).")


if __name__ == "__main__":
    main()
