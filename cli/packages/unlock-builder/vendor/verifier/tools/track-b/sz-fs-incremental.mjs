// Correct INCREMENTAL FS hash: state(32B) = HASH256(state(32) || limb(40)) per limb.
// Never builds a huge stack item -> push cost stays O(72B/step), hash iters bounded.
// This is the real on-chain transcript-binding cost.
import { push, measure, O, asm } from './asm-measure.mjs';

// Each step: state(32) limb(40) CAT (->72B) HASH256 (->32B). Repeat N times.
// We start from a 32-byte seed already on stack.
function incrementalFS(numLimbs) {
  const parts = [[0x20, ...new Uint8Array(32).fill(0xab)]]; // seed state 32B
  for (let i = 0; i < numLimbs; i++) {
    parts.push([0x28, ...new Uint8Array(40).fill((i * 7) & 0xff)]); // limb 40B
    parts.push(O.OP_CAT);      // state||limb = 72B
    parts.push(O.OP_HASH256);  // -> 32B
  }
  // consume final
  parts.push(O.OP_SIZE); parts.push([0x01, 0x20]); parts.push(O.OP_NUMEQUALVERIFY); parts.push(O.OP_DROP); parts.push(O.OP_1);
  const lk = asm(...parts);
  const res = measure(lk);
  return { numLimbs, opCost: res.opCost, push: res.push, instr: res.instr, accepted: res.accepted, error: res.error ? String(res.error).slice(0, 60) : null };
}
console.log('INCREMENTAL FS (state||limb per HASH256, 32B state):');
for (const nm of [12, 156, 192, 480, 3960, 3971]) console.log('  ', JSON.stringify(incrementalFS(nm)));

// Alternative: pack 2 limbs per hash (state 32 || limb 40 || limb 40 = 112B, 2 iters/hash anyway).
// Or batch: since HASH256 of L bytes = (2+ceil((L+8)/64)) iters, hashing 32+40=72B = 2+ceil(80/64)=2+2=4 iters.
// Packing more limbs per hash amortizes the fixed +2: 32 + k*40 bytes.
function packedFS(numLimbs, perHash) {
  const parts = [];
  let i = 0;
  parts.push([0x20, ...new Uint8Array(32).fill(0xab)]); // seed
  while (i < numLimbs) {
    const k = Math.min(perHash, numLimbs - i);
    for (let j = 0; j < k; j++) { parts.push([0x28, ...new Uint8Array(40).fill(((i + j) * 7) & 0xff)]); parts.push(O.OP_CAT); }
    parts.push(O.OP_HASH256);
    i += k;
  }
  parts.push(O.OP_SIZE); parts.push([0x01, 0x20]); parts.push(O.OP_NUMEQUALVERIFY); parts.push(O.OP_DROP); parts.push(O.OP_1);
  const lk = asm(...parts);
  const res = measure(lk);
  return { numLimbs, perHash, opCost: res.opCost, push: res.push, instr: res.instr, accepted: res.accepted, error: res.error ? String(res.error).slice(0, 70) : null };
}
console.log('\nPACKED FS (k limbs per HASH256), 156 limbs (~13 muls):');
for (const k of [1, 2, 4, 8, 12]) console.log('  ', JSON.stringify(packedFS(156, k)));
console.log('\nPACKED FS, 3960 limbs (whole Miller, 330 muls):');
for (const k of [4, 8, 16]) console.log('  ', JSON.stringify(packedFS(3960, k)));
