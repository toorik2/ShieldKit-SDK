// Terminal-selector residue representatives for the PF6 projected route.
//
// ROOT27 / v^2 and ROOT27^2 / v are cubes in Fp12. Replacing the historical
// 27th-root representatives by {1, v^2, v} therefore preserves the three
// cubic cosets while making the terminal multiplication a pure Fp6 rotation.
import { bn254, Fp, Fp2, Fp6, Fp12 } from '../../../../build/chunked/pairing/_millermath.mjs';
import { COSET27, LAMBDA, fp12limbsOf, residueWitness as legacyResidueWitness } from '../../../../build/chunked/pairing/_residuemath.mjs';

const P12 = Fp.ORDER ** 12n - 1n;
const FR = bn254.fields.Fr.ORDER;
const zero6 = [0n, 0n, 0n, 0n, 0n, 0n];
const fp6 = (limbs) => Fp6.create({
  c0: Fp2.fromBigTuple([limbs[0], limbs[1]]),
  c1: Fp2.fromBigTuple([limbs[2], limbs[3]]),
  c2: Fp2.fromBigTuple([limbs[4], limbs[5]]),
});
const fp12lo = (limbs) => Fp12.create({ c0: fp6(limbs), c1: fp6(zero6) });
const V = fp12lo([0n, 0n, 1n, 0n, 0n, 0n]);
const V2 = fp12lo([0n, 0n, 0n, 0n, 1n, 0n]);
const eq12 = (a, b) => {
  const aa = fp12limbsOf(a);
  const bb = fp12limbsOf(b);
  return aa.every((x, i) => x === bb[i]);
};
const pow = (a, exponent) => Fp12.pow(a, exponent);
const inverseMod = (value, modulus) => {
  let [oldR, r] = [((value % modulus) + modulus) % modulus, modulus];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return ((oldS % modulus) + modulus) % modulus;
};

const U = P12 / 27n;
const cubeCorrection = U % 3n === 2n ? 1n : 2n;
const cubeExponent = (cubeCorrection * U + 1n) / 3n;
const cubeRoot = (value) => {
  const classElement = pow(value, U);
  let classIndex = -1;
  for (let i = 0; i < 9; i += 1) {
    if (eq12(COSET27[(3 * i) % 27], classElement)) {
      classIndex = i;
      break;
    }
  }
  if (classIndex < 0) throw new Error('selector residue representative is not a cube');
  const correction = ((-(cubeCorrection * BigInt(classIndex))) % 27n + 27n) % 27n;
  return Fp12.mul(pow(value, cubeExponent), COSET27[Number(correction)]);
};

/**
 * Keep `w` in the historical COSET27 encoding for L17 statement serialization,
 * while `terminalW` is the equivalent sparse representative used by the tail.
 */
export function residueWitnessForTerminal(fRaw) {
  if (process.env.TERMINAL_W_SELECTOR !== '1') {
    const legacy = legacyResidueWitness(fRaw);
    return { ...legacy, terminalW: legacy.w };
  }
  const candidates = [Fp12.ONE, V2, V];
  for (const [selector, terminalW] of candidates.entries()) {
    const scaled = Fp12.mul(fRaw, terminalW);
    if (!eq12(pow(scaled, P12 / 3n), Fp12.ONE)) continue;
    const rootInput = pow(scaled, inverseMod(FR, P12 / FR));
    const c = cubeRoot(pow(rootInput, inverseMod(LAMBDA / (3n * FR), P12)));
    return {
      c,
      cInv: Fp12.inv(c),
      // `_szmath.wselOf` remains the transcript authority for selector bytes.
      w: COSET27[selector],
      terminalW,
      selector,
    };
  }
  throw new Error('no selector residue representative makes the Miller boundary cubic');
}
