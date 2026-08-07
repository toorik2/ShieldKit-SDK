// Derive invalid proofs from a valid (push-only) unlocking script by flipping one
// bit inside a data push. Used to produce REJECT test vectors for verifiers whose
// unlocking is just pushed proof/witness data.
import type { Step } from './types.js';

/** [start,end) byte ranges of each data-push payload in a push-only script. */
const dataPushRanges = (script: Uint8Array): Array<[number, number]> => {
  const ranges: Array<[number, number]> = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i]!;
    i += 1;
    let len = -1;
    if (op >= 0x01 && op <= 0x4b) len = op;
    else if (op === 0x4c) { len = script[i]!; i += 1; }
    else if (op === 0x4d) { len = script[i]! | (script[i + 1]! << 8); i += 2; }
    else if (op === 0x4e) { len = script[i]! | (script[i + 1]! << 8) | (script[i + 2]! << 16) | (script[i + 3]! << 24); i += 4; }
    else continue; // OP_0 / OP_1..OP_16 / OP_1NEGATE: no payload
    if (len > 0) ranges.push([i, i + len]);
    i += len;
  }
  return ranges;
};

/** Flip one bit inside the nth-largest data push (0 = largest). */
export const tamperProof = (script: Uint8Array, nthLargest = 0): Uint8Array => {
  const ranges = dataPushRanges(script).sort((a, b) => b[1] - b[0] - (a[1] - a[0]));
  const target = ranges[nthLargest];
  if (target === undefined) throw new Error('no data push to tamper');
  const [start, end] = target;
  const copy = script.slice();
  const at = start + Math.floor((end - start) / 2);
  copy[at]! ^= 0x01;
  return copy;
};

/**
 * Replace one step's unlocking bytecode while preserving the context the BCH VM
 * will actually see. Intra-tx steps are evaluated from `intraTx.inputs`, so the
 * sibling input list must be patched too; changing only `step.unlockingBytecode`
 * creates a no-op tamper.
 */
export const patchRunStepUnlocking = (
  run: readonly Step[],
  targetRunIndex: number,
  unlockingBytecode: Uint8Array,
): Step[] => {
  const target = run[targetRunIndex];
  if (target === undefined) throw new Error(`step ${targetRunIndex} is outside the run`);

  if (target.intraTx === undefined) {
    return run.map((step, index) => (index === targetRunIndex ? { ...step, unlockingBytecode } : step));
  }

  const targetInputIndex = target.intraTx.index;
  if (target.intraTx.inputs[targetInputIndex] === undefined) {
    throw new Error(`intraTx input ${targetInputIndex} is outside the shared input list`);
  }

  const inputs = target.intraTx.inputs.map((input, index) =>
    index === targetInputIndex ? { ...input, unlockingBytecode } : input,
  );

  return run.map((step, index) => {
    if (step.intraTx === undefined) {
      return index === targetRunIndex ? { ...step, unlockingBytecode } : step;
    }
    const isTargetInput = step.intraTx.index === targetInputIndex;
    return {
      ...step,
      unlockingBytecode: isTargetInput ? unlockingBytecode : step.unlockingBytecode,
      intraTx: { ...step.intraTx, inputs },
    };
  });
};

export const patchStepUnlocking = (step: Step, unlockingBytecode: Uint8Array): Step =>
  patchRunStepUnlocking([step], 0, unlockingBytecode)[0]!;

export const tamperRunStepProof = (run: readonly Step[], targetRunIndex: number, nthLargest = 0): Step[] =>
  patchRunStepUnlocking(run, targetRunIndex, tamperProof(run[targetRunIndex]!.unlockingBytecode, nthLargest));

export const tamperStepProof = (step: Step, nthLargest = 0): Step =>
  patchStepUnlocking(step, tamperProof(step.unlockingBytecode, nthLargest));
