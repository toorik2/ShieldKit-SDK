"""
Measured VM-Limits op-cost + hashing for the tested verifier, vs CHIP-2021-05 limits.
"""
import os
from cashvm import VM, P, N, OP, DEFINE
from structures_merkle import build_tree, proof, merkle_body, MERKLE_FID

# exact CHIP formulas
def max_std_iters(unlock_len):  return (41 + unlock_len) // 2
def max_cons_iters(unlock_len): return ((41 + unlock_len) * 7) // 2
def max_op_cost(unlock_len):    return (41 + unlock_len) * 800

def measure_one_query(depth):
    n = 1 << depth
    leaves = [os.urandom(40) for _ in range(n)]   # 40B = 32 salt + 8 value (hiding leaf)
    layers = build_tree(leaves); root = layers[-1][0]; idx = n // 3
    pth = proof(layers, idx)
    prog = [P(root), N(len(pth)), P(leaves[idx])]
    for (sib, d) in reversed(pth):
        prog += [P(sib), OP("TOALT"), N(d), OP("TOALT")]
    prog += [P(MERKLE_FID), DEFINE(merkle_body), P(MERKLE_FID), OP("INVOKE")]
    vm = VM(); vm.hash_cost = 192  # standard
    vm.run(prog)
    return vm.hash_iters, vm.op_cost

print("Per-merkle-opening measured cost (one query):")
print(f"{'depth':>6} {'digest_iters':>13} {'op_cost':>12}")
costs = {}
for d in (10, 16, 18, 20):
    it, oc = measure_one_query(d)
    costs[d] = (it, oc)
    print(f"{d:>6} {it:>13} {oc:>12}")

# Full zk-STARK verifier estimate (trace 2^14, blowup 16 -> N=2^18, q=21 queries, fold 8)
# components per query: trace open (depth 18) + 6 FRI layers (depths 18,15,12,9,6,3)
d_trace = 18
fri_depths = [18, 15, 12, 9, 6, 3]
q = 21
it_trace, oc_trace = costs[18]
# approximate a FRI-layer opening by reusing merkle opening at that depth
def layer_cost(depth):
    # smaller domains: synthesize via measure at nearest available; measure directly
    it, oc = measure_one_query(depth) if depth in (10,16,18,20) else (None,None)
    return it, oc
# measure the needed depths
need = sorted(set(fri_depths + [d_trace]))
for d in need:
    if d not in costs:
        costs[d] = measure_one_query(d)
it_q = costs[d_trace][0] + sum(costs[d][0] for d in fri_depths)
oc_q = costs[d_trace][1] + sum(costs[d][1] for d in fri_depths)
total_iters = q * it_q
total_opcost = q * oc_q
print(f"\nFull verifier estimate: {q} queries x (1 trace + {len(fri_depths)} FRI layers)")
print(f"  total digest iterations ~ {total_iters}")
print(f"  total operation cost    ~ {total_opcost:,}")

print("\nBudget vs scriptSig length (single input):")
print(f"{'scriptSig B':>11} {'std iters':>10} {'cons iters':>11} {'op budget':>14}")
for L in (1650, 10000):
    print(f"{L:>11} {max_std_iters(L):>10} {max_cons_iters(L):>11} {max_op_cost(L):>14,}")

print("\nVerdict (single input):")
for L in (1650, 10000):
    fits_std  = total_iters <= max_std_iters(L) and total_opcost <= max_op_cost(L)
    fits_cons = total_iters <= max_cons_iters(L) and total_opcost <= max_op_cost(L)
    print(f"  scriptSig={L}B  standard:{'FITS' if fits_std else 'NO':<5} consensus:{'FITS' if fits_cons else 'NO'}")

# how many inputs needed (each input gets its own budget AND carries ~10KB of proof)
import math
need_std  = math.ceil(total_iters / max_std_iters(10000))
need_cons = math.ceil(total_iters / max_cons_iters(10000))
print(f"\nMulti-input sharding (10KB scriptSig each):")
print(f"  inputs needed for hashing budget  standard: {need_std}   consensus: {need_cons}")
print("  (each input also carries ~10KB of the proof, so sharding solves BOTH the")
print("   90KB data-doesnt-fit-10KB problem AND the hashing-budget problem at once)")
