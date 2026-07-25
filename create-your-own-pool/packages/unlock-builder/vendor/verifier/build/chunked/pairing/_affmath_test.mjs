import { pairsFor, vec, singlePairMiller, millerBatchOps } from './_millermath.mjs';
import { millerBatchOpsAffine, millerFusedOpsAffine } from './_affmath.mjs';
import { residueWitness, SIX_X_PLUS_2, eq12, ROOT27, frob } from './_residuemath.mjs';
import { bn254 } from './_millermath.mjs';
const { Fp12 } = bn254.fields;
const pairs = pairsFor(vec.publicInputs.map(BigInt));
// 1. affine all-4-pairs boundary -> residue witness -> tail relation must hold
const { boundary: fRawAff } = millerBatchOpsAffine(pairs);
const { boundary: fRawJac } = millerBatchOps(pairs);
console.log('affine fRaw differs from jacobian (Fp* scaling expected):', !eq12(fRawAff, fRawJac));
// scaling factor s0 = fRawAff/fRawJac must be in Fp* (dies in finalExp) -> pairing equal
const finalExp = (x) => Fp12.finalExponentiate(x);
console.log('finalExp(fRawAff) == finalExp(fRawJac):', eq12(finalExp(fRawAff), finalExp(fRawJac)));
// 2. residue witness from affine boundary + fused affine build + tail
const { c, cInv, w } = residueWitness(fRawAff);
const fused = millerFusedOpsAffine(pairs, c, cInv, singlePairMiller);
const fF = fused.boundary;
const tail = eq12(mul(mul(fF, w), frob(c, 2)), mul(frob(c, 1), frob(c, 3)));
function mul(a,b){return Fp12.mul(a,b);}
console.log('AFFINE TAIL fF*w*c^q2 == c^q*c^q3:', tail);
console.log('num affine fused ops:', fused.ops.length, '(baseline', millerBatchOps(pairs).ops.length, 'unfused)');
// count pair0 point ops needing lambda
let nDl=0,nAl=0,nPp=0;
for(const o of fused.ops){ if(o.j===0){ if(o.t==='dl')nDl++; else if(o.t==='al')nAl++; else if(o.t==='pp')nPp++; } }
console.log('pair0 affine ops: dl',nDl,'al',nAl,'pp',nPp,'-> total lambdas =', nDl+nAl+2*nPp);
