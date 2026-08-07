// PairFold's mixed singleton/two-step transcript is a complete S-Z
// construction, not a pair of substituted challenges. Re-export the
// normalized arithmetic surface while replacing its transcript authority and
// domain separators as one unit for the generated genesis and terminal code.
import {
  mixedGenesisTrajectory,
  TAG_GAMMA_MIXED_V2,
  TAG_GAMMA_FIN_MIXED_V2,
  TAG_Z_MIXED_V2,
  TAG_GAMMA_MIXED_GEN64,
  TAG_GAMMA_FIN_MIXED_GEN64,
  TAG_Z_MIXED_GEN64,
} from './composed-window-szmath.mjs';

export * from './normalized-szmath.mjs';

// Mirror absorb variants so on-chain tag literals match the frozen trajectory.
const GEN_ABSORB_HEAD4 = new Set([
  'gen6-4exec',
  '6in-gen2-8877',
  '7in-gen2-flat',
]);
const useGen64 = process.env.C7_FORCE_IDEAL_WINDOWS !== '0'
  && GEN_ABSORB_HEAD4.has(process.env.C7_IDEAL_VARIANT || '');

export const TAG_GAMMA = useGen64 ? TAG_GAMMA_MIXED_GEN64 : TAG_GAMMA_MIXED_V2;
export const TAG_GAMMA_FIN = useGen64 ? TAG_GAMMA_FIN_MIXED_GEN64 : TAG_GAMMA_FIN_MIXED_V2;
export const TAG_Z = useGen64 ? TAG_Z_MIXED_GEN64 : TAG_Z_MIXED_V2;

export const trajectory = () => mixedGenesisTrajectory();
