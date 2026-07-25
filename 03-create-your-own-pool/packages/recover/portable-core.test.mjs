import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
// The independently pinned reference implementation lives in the sibling core
// package. It is deliberately test-only: the browser-safe recovery runtime
// does not depend on circomlibjs.
import { buildBabyjub } from '../profile/node_modules/circomlibjs/main.js';
import {
  BABYJUB_BASE8, BABYJUB_SUBGROUP_ORDER, FR_MODULUS,
  babyJubAdd, babyJubInSubgroup, babyJubMul, packBabyJubPoint,
  unpackBabyJubPoint,
} from './portable-core.mjs';

const equalPoint = (left, right) => left[0] === right[0] && left[1] === right[1];
const fromReference = (reference, point) => Object.freeze([
  reference.F.toObject(point[0]), reference.F.toObject(point[1]),
]);
const scalar = (index) => {
  const digest = createHash('sha256').update(`shield.cash/projective-babyjub-differential/v1/${index}`).digest('hex');
  return (BigInt(`0x${digest}`) % (BABYJUB_SUBGROUP_ORDER - 1n)) + 1n;
};

test('projective BabyJubJub arithmetic agrees with independent circomlib affine vectors', async () => {
  // circomlibjs BabyJub uses affine divisions in addPoint/mulPointEscalar;
  // it is intentionally independent of portable-core's projective formulas.
  const reference = await buildBabyjub();
  const scalars = [0n, 1n, 2n, 3n, 7n, 42n, 255n, 65_537n, BABYJUB_SUBGROUP_ORDER - 1n, ...Array.from({ length: 64 }, (_, index) => scalar(index))];
  for (const value of scalars) {
    const actual = babyJubMul(BABYJUB_BASE8, value);
    const expected = fromReference(reference, reference.mulPointEscalar(reference.Base8, value));
    assert.ok(equalPoint(actual, expected), `scalar multiplication differs for ${value}`);
    if (value !== 0n) assert.equal(babyJubInSubgroup(actual), true, `nonzero multiple leaves subgroup for ${value}`);
  }
  for (let index = 0; index < scalars.length - 1; index += 1) {
    const leftScalar = scalars[index]; const rightScalar = scalars[index + 1];
    const left = babyJubMul(BABYJUB_BASE8, leftScalar); const right = babyJubMul(BABYJUB_BASE8, rightScalar);
    const actual = babyJubAdd(left, right);
    const expected = fromReference(reference, reference.addPoint(reference.mulPointEscalar(reference.Base8, leftScalar), reference.mulPointEscalar(reference.Base8, rightScalar)));
    assert.ok(equalPoint(actual, expected), `addition differs for scalar pair ${leftScalar}/${rightScalar}`);
  }
});

test('projective implementation preserves strict canonical point and subgroup rejection', () => {
  assert.equal(babyJubInSubgroup([0n, 1n]), false, 'identity is not an allowed public subgroup point');
  assert.throws(() => packBabyJubPoint([0n, 1n]), /nonidentity prime-subgroup/);
  assert.throws(() => unpackBabyJubPoint(new Uint8Array(32).fill(0xff)), /noncanonical/);
  const noncanonicalY = new Uint8Array(32);
  let field = FR_MODULUS;
  for (let index = 0; index < 32; index += 1) { noncanonicalY[index] = Number(field & 0xffn); field >>= 8n; }
  assert.throws(() => unpackBabyJubPoint(noncanonicalY), /noncanonical/);
  assert.throws(() => babyJubMul(BABYJUB_BASE8, -1n), /invalid BabyJubJub multiplication input/);
});
