// FULL economic model: SOUND batched-FS SZ-witness on the baked-G2+prepVK chunked Miller.
// Ground truth measured: per-mul Horner (A2 chained) = 94,569 op; FS incremental hash; tower per-mul.
// VM constants (libauth bch-2025/2026, source-pinned):
const DCL_BASE = 41;            // densityControlBaseLength
const OP_PER_BYTE = 800;        // operationCostBudgetPerByte
const HASH_ITER_PER_BYTE_STD = 0.5;
const HASH_ITER_PER_BYTE_NONSTD = 3.5;
const HASH_COST_STD = 192;      // op-cost per hash iter (standard)
const HASH_COST_NONSTD = 64;    // consensus
const MAX_STD_UNLOCK = 1650;    // standard unlocking bytecode cap (P2SH path larger via redeem, but item caps apply)

// Per HASH256 of L input bytes: iters = 2 + ceil((L+8)/64).  (R-bch-vm)
const hashIters = (L) => 2 + Math.ceil((L + 8) / 64);

// ===== current baked-G2+prepVK Miller (MEASURED) =====
const MILLER_OP = 146_140_316;
const MILLER_CHUNKS = 20;
const MILLER_LOCK = 109_227;          // total locking bytes
const MILLER_UNLOCK_BYTES = 182_688;  // = opcost/800 padding
const MILLER_BYTES = 291_915;
const N_MULS = 330;                   // 264 line + 65 fp12Sqr + 1 fp12Mul
const OPS_PER_CHUNK = 17;

// ===== MEASURED SZ costs =====
const PERMUL_SZ = 94_569;             // chained per-mul Horner block (2 Horners + product + 2 RLC), real-VM
const PERMUL_SZ_PUSH_BYTES = 12 * 33; // R limbs witnessed per mul (~33B/limb pushed)
// FS hash per mul: commit R (12 limbs * 40B = 480B). Incremental, packed k=8/hash.
// From sz-fs-incremental: 156 limbs (13 muls), k=8 => 82,300 op for the hashing.
// => per-mul FS hash op ~ 82300/13 = 6,331 op.  Per-mul hash iters?
const FS_HASH_OP_PER_MUL = Math.round(82_300 / 13);
// limbs per mul = 12 (R). Packed k=8 => ceil(12/8)=2 hashes/mul, each ~ 32+8*40=352B input.
// iters/hash(352B) = 2+ceil(360/64)=2+6=8. So ~2 hashes => but spans; approximate per-mul hash iters:
const FS_ITERS_PER_MUL = hashIters(32 + 8 * 40) + hashIters(32 + 4 * 40); // 2 packed hashes covering 12 limbs

console.log('=== VM budget formulas (source-pinned) ===');
console.log('densityControlLength = 41 + unlockingBytes');
console.log('op-budget = 800 * dcl ; hash-iter-budget = 0.5*dcl (std) / 3.5*dcl (nonstd)');
console.log('hash-cost = 192/iter (std) / 64/iter (consensus)');
console.log();

// ===== Per-mul total SZ on-chain cost =====
const perMulTotalSZ = PERMUL_SZ + FS_HASH_OP_PER_MUL;
console.log('=== Per-mul cost comparison ===');
console.log('tower per-mul (line+pp+sqr avg) =', Math.round(MILLER_OP / N_MULS).toLocaleString(), 'op');
console.log('SZ per-mul: Horner', PERMUL_SZ.toLocaleString(), '+ FS-hash', FS_HASH_OP_PER_MUL.toLocaleString(), '=', perMulTotalSZ.toLocaleString(), 'op');
console.log('  ratio =', (perMulTotalSZ / (MILLER_OP / N_MULS)).toFixed(3) + '×');
console.log();

// ===== amortized batch overhead (once per Miller, or once per chunk) =====
// big_Q (deg ~ 11*N or aggregated to 11 limbs after reduction): one M(z) eval + one final equality.
// This is negligible vs N muls. Q per-mul is NOT witnessed in the batched design (only aggregated big_Q).
// BUT: the RLC requires each mul's R committed AND each mul's (A,B) bound. In a CHAINED Miller,
// A_i = R_{i-1} (already committed), B_i = the sparse line/op operand (committed coeffs, or VK-baked).

// ===== HASH DENSITY CONSTRAINT (the load-bearing limit) =====
// Per chunk: hash budget = 0.5 * (41 + unlockBytes) iters (standard).
// To commit M muls' R (12 limbs * 40B each), incremental hash needs ~ M * FS_ITERS_PER_MUL iters.
// unlockBytes must be LARGE enough to buy that hash budget. But unlockBytes is bounded by witness mass.
console.log('=== Hash density: how many muls can ONE chunk commit? (standard relay) ===');
console.log('FS iters per mul (12 limbs, packed) ~', FS_ITERS_PER_MUL);
for (const unlockKB of [1.65, 10, 50, 100]) {
  const ub = unlockKB * 1000;
  const hashBudgetStd = Math.floor(HASH_ITER_PER_BYTE_STD * (DCL_BASE + ub));
  const hashBudgetNonstd = Math.floor(HASH_ITER_PER_BYTE_NONSTD * (DCL_BASE + ub));
  const opBudget = OP_PER_BYTE * (DCL_BASE + ub);
  const mulsByHashStd = Math.floor(hashBudgetStd / FS_ITERS_PER_MUL);
  const mulsByHashNonstd = Math.floor(hashBudgetNonstd / FS_ITERS_PER_MUL);
  const mulsByOp = Math.floor(opBudget / perMulTotalSZ);
  console.log(`  unlock=${unlockKB}KB: op-budget=${(opBudget/1e6).toFixed(1)}M hash-budget std=${hashBudgetStd}/nonstd=${hashBudgetNonstd} iters`);
  console.log(`     => muls/chunk: by-op=${mulsByOp}, by-hash(std)=${mulsByHashStd}, by-hash(nonstd)=${mulsByHashNonstd}`);
}
console.log();

// ===== witness mass reality check =====
// Each committed R = 12 limbs. Whole Miller = 330 muls => 330*12 = 3960 limbs witnessed.
// at 33B/limb pushed (in unlocking) = 130,680 bytes of WITNESS across the whole Miller.
// This unlocking mass also BUYS budget. But standard unlocking cap = 1650B/input!
const totalWitnessBytes = N_MULS * 12 * 33;
console.log('=== Witness mass ===');
console.log('whole-Miller R witness =', totalWitnessBytes.toLocaleString(), 'bytes (330 muls * 12 limbs * 33B)');
console.log('standard unlocking cap = 1650B/input => witness must be split OR use nonstandard (1MB tx, miner-direct)');
console.log();

// ===== NET byte projection =====
// Two regimes:
// (1) op-cost-bound (cheaper ops => fewer chunks => less padding+locking): the WIN.
// (2) hash-bound or witness-bound (FS hash + witness mass become the new bottleneck): the TAX.
console.log('=== NET projection ===');
// New per-chunk op-cost with SZ: OPS_PER_CHUNK can rise since per-mul is cheaper.
// But chunk is bounded by min(op-budget, hash-budget). Compute muls/chunk under standard unlock budget.
// Realistic: keep unlocking modest. Need witness for R (12 limbs/mul committed) in unlocking.
// muls/chunk limited by witness that fits + hash budget it buys.
for (const regime of ['standard-1.65KB', 'nonstandard-large']) {
  let ub, hashPerByte, hashCost;
  if (regime === 'standard-1.65KB') { ub = 1650; hashPerByte = HASH_ITER_PER_BYTE_STD; hashCost = HASH_COST_STD; }
  else { ub = 100_000; hashPerByte = HASH_ITER_PER_BYTE_NONSTD; hashCost = HASH_COST_NONSTD; }
  const hashBudget = Math.floor(hashPerByte * (DCL_BASE + ub));
  const opBudget = OP_PER_BYTE * (DCL_BASE + ub);
  // witness mass: each mul needs 12 limbs in unlocking. limbs that fit in ub:
  const mulsByWitness = Math.floor(ub / (12 * 33));
  const mulsByHash = Math.floor(hashBudget / FS_ITERS_PER_MUL);
  const mulsByOp = Math.floor(opBudget / perMulTotalSZ);
  const mulsPerChunk = Math.min(mulsByWitness, mulsByHash, mulsByOp);
  const nChunks = Math.max(1, Math.ceil(N_MULS / Math.max(1, mulsPerChunk)));
  const bind = mulsPerChunk === mulsByWitness ? 'WITNESS' : mulsPerChunk === mulsByHash ? 'HASH' : 'OP';
  console.log(`  [${regime}] muls/chunk=${mulsPerChunk} (bound by ${bind}; op=${mulsByOp},hash=${mulsByHash},wit=${mulsByWitness}) => ${nChunks} chunks`);
}
