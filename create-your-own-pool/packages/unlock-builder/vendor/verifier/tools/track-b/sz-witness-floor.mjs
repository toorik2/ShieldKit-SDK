// WITNESS-MASS FLOOR analysis. When SZ cuts op-cost 4.5x, chunks flip from op-bound to WITNESS-bound.
// What is witnessed?
//  - Each intermediate Fp12 f_i (12 limbs) along the chain: needed so z=hash(transcript) binds it,
//    AND so the Horner eval f_i(z) has its coefficients on stack.
//  - The sparse op operand B_i: line coeffs (6 Fp limbs) for variable pair; BAKED pairs => literals in LOCKING (free witness).
//  - big_Q (aggregated): 11 limbs, ONCE per Miller (negligible).
// In the baked Miller, of 330 muls: pair-0 (variable A,B) lines need witnessed coeffs;
//  pairs 2,3 (baked γ,δ) line coeffs are LITERALS (already in locking). fp12Sqr has no operand.
// f_i intermediates: 330 of them, 12 limbs each = the dominant witness mass.

const N_MULS = 330;
const LIMB_PUSH = 33; // ~32B value + 1 push opcode/len byte
// f intermediates: every mul outputs a new f_i that must be committed. 330 * 12 limbs.
const fWitness = N_MULS * 12 * LIMB_PUSH;
// BUT: consecutive f_i share — f_i is the INPUT to mul i and OUTPUT of mul i-1. The transcript
// commits each DISTINCT f value once. There are N_MULS+1 distinct f values (f_0..f_N). ~ same.
// Optimization: do we need to push f_i AND eval its 12 coeffs? The eval needs the 12 coeffs on stack.
// They come from witness. No way around pushing 12 limbs/intermediate IF each is an independent witness.

// CAN WE AVOID witnessing every f_i?  Alternative: only witness chunk-BOUNDARY f's (already in NFT),
// and RECOMPUTE intermediate f_i(z) on-chain from f_{i-1}(z) and op_i? That requires the Fp12 PRODUCT
// at z: f_i(z) = f_{i-1}(z) * op_i(z) (since eval is a ring hom!). So f_i(z) is DERIVED, not witnessed —
// but then we are NOT proving f_i = f_{i-1}*op_i, we are ASSUMING it (evaluating the claimed product).
// The SZ check is: prove the WITNESSED f_i equals f_{i-1}*op_i. If we derive f_i(z) we skip the witness
// but ALSO skip the check -> we'd just be computing the Miller at z, which does NOT verify the real f.
//
// RESOLUTION: the SZ batch proves  Σ w^i (f_{i-1}(z)*op_i(z) - f_i(z)) == big_Q(z)*M(z).
//   - f_{i-1}(z), f_i(z): evals of WITNESSED intermediates (must be committed -> witnessed).
//   - op_i(z): eval of the operand (line coeffs / sqr is f_{i-1} itself).
// So every intermediate f_i IS witnessed. The mass is real.
console.log('f-intermediate witness (330 * 12 limbs * 33B) =', fWitness.toLocaleString(), 'B');

// line-coeff witness for variable pair (pair 0): per double/add line, 6 Fp limbs (c0,c1,c2 in Fp2).
// pair0 ops ~ 1/3 of line ops ~ 88 lines * 6 * 33:
const lineCoeffWitness = 88 * 6 * LIMB_PUSH;
console.log('variable-pair line-coeff witness ~', lineCoeffWitness.toLocaleString(), 'B (baked pairs are literals=free)');

const totalWitness = fWitness + lineCoeffWitness;
console.log('TOTAL SZ witness mass ~', totalWitness.toLocaleString(), 'B');
console.log();

// This witness mass is the Miller byte FLOOR (it must appear in unlocking across all chunks).
// Compare to the op-padding floor it replaces.
const SZ_MILLER_OP = 32_193_810;
const padFloor = SZ_MILLER_OP / 800;
console.log('op-padding floor (SZ op/800) =', Math.round(padFloor).toLocaleString(), 'B');
console.log('witness floor =', totalWitness.toLocaleString(), 'B => witness DOMINATES, sets the real floor');
console.log();

// Real Miller bytes = max(padding, witness) [both are unlocking; witness counts toward padding budget]
//   + locking. Since witness > padding, unlocking = witness (the chunk is witness-bound, op-budget slack).
// chunks: each chunk's unlock = its witness share; op-budget = 800*(41+unlock) must still >= chunk op-cost.
//   chunk witness ~ enough to cover its muls. op-cost/chunk = muls*97557. Check op-budget vs op-cost:
//   unlock(witness) per chunk for M muls = M*(12*33) [f] + (M/3.75)*6*33 [coeffs] ~ M*412 B.
//   op-budget = 800*(41+M*412) = 800*M*412 ~ 329,600*M >> op-cost 97,557*M. So op-budget has 3.4x SLACK.
//   => chunks are WITNESS-bound; op-cost is NOT the constraint anymore. Hash budget = 0.5*(41+M*412)=206*M
//      iters; demand = M*14 iters. 206 >> 14, hash fine.
const witnessPerMul = 12 * LIMB_PUSH + (6 * LIMB_PUSH) / 3.75;
console.log('witness/mul ~', Math.round(witnessPerMul), 'B; op-budget/mul = 800*that =', Math.round(800*witnessPerMul).toLocaleString(), 'vs op-cost/mul 97,557 (', (800*witnessPerMul/97557).toFixed(1)+'x slack)');
console.log();

// So a chunk can hold as many muls as fit in the standard tx-size / unlocking limits, NOT op-budget.
// Per-input unlocking is the constraint. Standard cap 1650B/input is TINY. But the EXISTING baked Miller
// already pushes ~9.6KB unlock/chunk -> so the deployment is NOT standard-1650-capped (P2SH32 redeem path
// or consensus relay). Match the existing regime: unlock can be ~10KB/chunk (as baked Miller).
const UNLOCK_PER_CHUNK = 9625; // matches baked Miller op-bound unlock
const mulsPerChunk = Math.floor(UNLOCK_PER_CHUNK / witnessPerMul);
const nChunks = Math.ceil(N_MULS / mulsPerChunk);
console.log('at', UNLOCK_PER_CHUNK, 'B unlock/chunk: muls/chunk =', mulsPerChunk, '=> chunks =', nChunks);
const lockPerChunk = 109227/20; // ~5461B (likely LESS for SZ: drops fp6Mul/fp12Mul tower fns, keeps Horner)
const totBytes = totalWitness + nChunks*lockPerChunk;
console.log('Miller bytes ~ witness', totalWitness.toLocaleString(), '+ locking', Math.round(nChunks*lockPerChunk).toLocaleString(), '=', Math.round(totBytes).toLocaleString());
console.log('  vs baked Miller 291,915 =>', ((totBytes-291915)/291915*100).toFixed(1)+'%');
const verifier = 594496 - (291915 - totBytes);
console.log('VERIFIER baked-only 594,496 => with SZ Miller ~', Math.round(verifier).toLocaleString());
