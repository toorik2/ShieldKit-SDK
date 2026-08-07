// The uniform five-window x/slope plan. Every fixed double in the deployed
// [1,64) Miller interval is represented by its two Fp2 slopes; each executor
// has one two-pair x seed. Fixed additions retain the normalized slope form.
//
// This module is shared by the offline S-Z rebuild and the table emitter so a
// mismatch in the selected algebraic quotient cannot silently enter a build.
// Stock K=13 research windows (legacy fixed-G2 striping).
export const XONLY_WINDOWS_K13 = Object.freeze([[1, 14], [14, 27], [27, 40], [40, 53], [53, 64]]);
// PairFold-7 mixed pure-pair ranges (must match MIXED_EXECUTOR_RANGES_7).
export const XONLY_WINDOWS_PF7 = Object.freeze([[1, 14], [14, 26], [26, 38], [38, 50], [50, 64]]);
// PairFold-6 pure-pair ranges (must match MIXED_EXECUTOR_RANGES_6).
export const XONLY_WINDOWS_PF6 = Object.freeze([[2, 16], [16, 32], [32, 48], [48, 64]]);
export const XONLY_WINDOWS_PF6_DENSE = Object.freeze([[1, 16], [16, 32], [32, 48], [48, 64]]);
// Select topology windows when composed PairFold is active.
const _xonlyTopo = process.env.C7_PAIRFOLD_TOPOLOGY ?? '7';
export const XONLY_WINDOWS = Object.freeze(
  (process.env.C7_COMPOSED_P2SH === '1' && _xonlyTopo === '7')
    ? [...XONLY_WINDOWS_PF7]
    : (process.env.C7_COMPOSED_P2SH === '1' && _xonlyTopo === '6')
      ? (process.env.C7_SCALAR_ENDPOINT === '1' ? [...XONLY_WINDOWS_PF6_DENSE] : [...XONLY_WINDOWS_PF6])
      : [...XONLY_WINDOWS_K13],
);
export const XONLY_SEED_BYTES = 128;
export const XONLY_RECORD_BYTES = 128;

export const isXOnlyFixedDoubleStep = (step) => Number.isInteger(step) && step >= 1 && step < 64;

export const xOnlyWindowFor = (lo, hi) => {
  if (!XONLY_WINDOWS.some(([start, end]) => start === lo && end === hi)) {
    throw new Error(`x/slope plan has no window [${lo}, ${hi}) among ${JSON.stringify(XONLY_WINDOWS)}`);
  }
  return { lo, hi };
};

// A role starts from a local seed. An x update after its final step is dead;
// the next role authenticates its own seed rather than consuming forwarded x.
// Block indices are end+1 of each window (1-based Miller step after last event).
const xOnlySeedHandoffBlkidx = () => XONLY_WINDOWS.map(([, end]) => end + 1);
export const xOnlyCarriesPastBlockIndex = (blkidx) => !xOnlySeedHandoffBlkidx().includes(blkidx);
