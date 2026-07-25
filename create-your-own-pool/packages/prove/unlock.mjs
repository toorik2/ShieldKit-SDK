/**
 * Unlock product surface (consume / measure).
 * Compile unlocks: `@shieldkit/unlock-builder` → `buildVerifierUnlocks`.
 */
export {
  measurePf7FixedPointCandidate,
  verifyPf7FixedPointCandidate,
  enumeratePf7FixedPointCandidates,
  Pf7FixedPointError,
  PF7_UNLOCKING_BYTE_LIMIT,
  COMPLETE_SETTLEMENT_WIRE_LIMIT,
} from './fixed-point.mjs';
export { parsePf7CarrierAuthority } from './authority.mjs';
