// Self-test for the intratx-aware tamper helpers. The important invariant:
// a mutated unlocking bytecode must be visible through every sibling step's
// `intraTx.inputs`, because evaluatePair builds the real transaction from that
// shared input list.
import { tamperRunStepProof, tamperStepProof } from './tamper.js';
import type { Step } from './types.js';

const bytes = (...xs: number[]) => Uint8Array.from(xs);
const push = (...xs: number[]) => Uint8Array.from([xs.length, ...xs]);
const eq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);

let pass = 0;
let fail = 0;
const check = (name: string, cond: boolean, extra = '') => {
  if (cond) {
    pass += 1;
    console.log('  ok   ', name);
  } else {
    fail += 1;
    console.log('  FAIL ', name, extra);
  }
};

const locking = bytes(0x51);
const unlocks = [push(1, 2, 3, 4), push(5, 6, 7, 8), push(9, 10, 11, 12)];
const inputs = unlocks.map((unlockingBytecode) => ({ lockingBytecode: locking, unlockingBytecode }));
const run: Step[] = inputs.map((input, index) => ({
  label: `i${index}`,
  lockingBytecode: input.lockingBytecode,
  unlockingBytecode: input.unlockingBytecode,
  intraTx: { index, inputs },
}));

const forged = tamperRunStepProof(run, 1);
const patchedInputs = forged[0]!.intraTx!.inputs;

check('target outer unlocking changed', !eq(forged[1]!.unlockingBytecode, run[1]!.unlockingBytecode));
check('honest run was not mutated', eq(run[1]!.unlockingBytecode, unlocks[1]!));
check('shared intratx input list patched', eq(patchedInputs[1]!.unlockingBytecode, forged[1]!.unlockingBytecode));
check('all forged siblings share the patched input list', forged.every((step) => step.intraTx!.inputs === patchedInputs));
check('non-target intratx inputs preserved', eq(patchedInputs[0]!.unlockingBytecode, unlocks[0]!) && eq(patchedInputs[2]!.unlockingBytecode, unlocks[2]!));
check('only target outer step changed', eq(forged[0]!.unlockingBytecode, unlocks[0]!) && eq(forged[2]!.unlockingBytecode, unlocks[2]!));

const plain: Step = { label: 'plain', lockingBytecode: locking, unlockingBytecode: push(10, 11, 12, 13) };
const plainForged = tamperStepProof(plain);
check('plain-step tamper still changes outer unlocking', !eq(plainForged.unlockingBytecode, plain.unlockingBytecode));
check('plain-step tamper does not add intratx context', plainForged.intraTx === undefined);

console.log(`\ntamper helper self-test: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
