import { commitBin, pairsFor, vec, millerBatchOps } from './_millermath.mjs';
import { inState, outState, states } from './gen_miller_residue.mjs';
import { residueWitness, millerFusedOps, fp12limbsOf } from './_residuemath.mjs';
import { binToHex } from '@bitauth/libauth';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x)=>((BigInt(x)%P)+P)%P;
// V3 miller final covOut (reduced, as covOut emits: name % Pmod)
const millerFinalRaw = outState(states.length-1).map(BigInt);
const millerFinalReduced = millerFinalRaw.map(red);
const millerCovOut = binToHex(commitBin(millerFinalReduced));
// Regenerated generic tail covIn: commitBin([fF,c,cInv] reduced) from the same residue witness
const pairs = pairsFor(vec.publicInputs.map(BigInt));
const { boundary: fRaw } = millerBatchOps(pairs);
const { c, cInv } = residueWitness(fRaw);
const fused = millerFusedOps(pairs, c, cInv);
const tailState36 = [...fp12limbsOf(fused.boundary), ...fp12limbsOf(c), ...fp12limbsOf(cInv)].map(red);
const tailCovIn = binToHex(commitBin(tailState36));
console.log('V3 miller FINAL covOut (reduced)  =', millerCovOut);
console.log('generic TAIL covIn (regenerated)  =', tailCovIn);
console.log('endSeam binds (generic)?          =', millerCovOut === tailCovIn);
console.log('');
console.log('values identical limb-by-limb?    =', millerFinalReduced.every((v,i)=>v===tailState36[i]), '(nlimbs',millerFinalReduced.length,'vs',tailState36.length,')');
