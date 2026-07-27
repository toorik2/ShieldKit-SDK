/**
 * @shieldkit/unlock-builder — Node-only verifier unlock factory (live densFuel pin).
 *
 * Phase 1: resolves C7 toolchain via SHIELDKIT_UNLOCK_ROOT or .worktrees escape hatch.
 * Phase 2: vendors under ./vendor (blank-machine default).
 */

export {
  PIN_LENS,
  ROLE_NAMES,
  LIVE_UNLOCK_FLAGS,
  buildLiveUnlockEnv,
  assertPinLens,
} from './env.mjs';

export {
  resolveUnlockRoot,
  resolveLeanRoot,
  resolveTsxBin,
  PKG_ROOT,
  REPO_ROOT,
} from './resolve.mjs';

export {
  buildVerifierUnlocks,
  UnlockBuilderError,
} from './build.mjs';

export {
  PIN_ECIP_MAX_TRY,
  measureEcipPinBudget,
  assertEcipWithinPinBudget,
} from './ecip-pin-gate.mjs';
