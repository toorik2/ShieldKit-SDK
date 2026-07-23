// Browser-safe wallet facade. This entrypoint deliberately imports only the
// portable recovery implementation: profiles, proving artifacts, chain access,
// and transaction broadcast remain application-owned and local.
import {
  constructRecipientOutput,
  deriveRecipientAddress,
  recoverRecipientOutput,
} from '../recovery/recovery.mjs';
import { recoverAuthenticatedChainHistory, serializeChainHistoryActions } from '../recovery/chain-history.mjs';

const HEX_32 = /^[0-9a-f]{64}$/;
const HASH_ID = /^sha256:[0-9a-f]{64}$/;

export class WalletSdkError extends Error {
  constructor(code, message) { super(message); this.name = 'WalletSdkError'; this.code = code; }
}
const fail = (code, message) => { throw new WalletSdkError(code, message); };
const exactKeys = (value, label, expected) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail('INVALID_OBJECT', `${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail('UNKNOWN_PROPERTY', `${label} has missing or unknown properties`);
};

/** Validate immutable coordinates obtained from an authenticated profile bundle. */
export function createProfileCoordinates(value) {
  exactKeys(value, 'profile coordinates', ['instanceId', 'network', 'profileId']);
  if (value.network !== 'chipnet') fail('UNSUPPORTED_NETWORK', 'only Chipnet is authorized by this SDK');
  if (!HASH_ID.test(value.profileId) || !HASH_ID.test(value.instanceId)) fail('PROFILE_IDENTITY', 'profileId and instanceId must be lowercase sha256 identifiers');
  return Object.freeze({ network: value.network, profileId: value.profileId, instanceId: value.instanceId });
}

function recoveryIdentity(profile) {
  return Object.freeze({ profileId: profile.profileId.slice('sha256:'.length), instanceId: profile.instanceId.slice('sha256:'.length) });
}

/**
 * Construct a portable wallet view. It neither stores a seed nor discovers
 * chain data; callers provide one serialized chain output at a time.
 */
export function createBrowserWalletSdk(value) {
  exactKeys(value, 'browser wallet SDK input', ['profile']);
  const profile = createProfileCoordinates(value.profile); const identity = recoveryIdentity(profile);
  return Object.freeze({
    schema: 'shield.cash/browser-wallet-sdk/v1',
    profile,
    qualification: 'portable recovery binding only; no browser proving, chain synchronization, transaction broadcast, or device qualification claim',
    async deriveRecipientAddress(seed) { return deriveRecipientAddress({ seed, ...identity }); },
    async constructRecipientOutput(request) {
      const hasRng = request !== null && typeof request === 'object' && Object.hasOwn(request, 'rng');
      exactKeys(request, 'recipient-output request', ['address', 'kind', 'slot', ...(hasRng ? ['rng'] : [])]);
      const { address, kind, slot, rng } = request;
      if (address?.profileId !== identity.profileId || address?.instanceId !== identity.instanceId) fail('PROFILE_MISMATCH', 'recipient address is not for this profile and instance');
      return constructRecipientOutput({ address, kind, slot, ...(rng === undefined ? {} : { rng }) });
    },
    async recoverChainOutput(request) {
      exactKeys(request, 'serialized chain output', ['kind', 'outputCommitment', 'record', 'seed', 'slot']);
      const { seed, kind, slot, outputCommitment, record } = request;
      if (!HEX_32.test(outputCommitment)) fail('MALFORMED_CHAIN_OUTPUT', 'output commitment must be 32 lowercase hexadecimal bytes');
      return recoverRecipientOutput({ seed, kind, slot, outputCommitment, record, ...identity });
    },
    async recoverAuthenticatedHistory(request) {
      exactKeys(request, 'authenticated packet history', ['accountSeed', 'history']);
      return recoverAuthenticatedChainHistory({ accountSeed: request.accountSeed, history: request.history, ...identity });
    },
    serializeHistoryActions: serializeChainHistoryActions,
  });
}

/** Require an explicit local-only proving capability before any proof workflow. */
export function requireLocalProverCapability(value) {
  exactKeys(value, 'local prover capability', ['mode', 'prove', 'schema']);
  if (value.schema !== 'shield.cash/local-prover-capability/v1' || value.mode !== 'local-only' || typeof value.prove !== 'function') {
    fail('LOCAL_PROVER_REQUIRED', 'a local-only prover capability with prove(request) is required');
  }
  return Object.freeze(value);
}
