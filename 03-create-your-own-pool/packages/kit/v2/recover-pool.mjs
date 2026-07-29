import {
  createV2CanonicalHistorySynchronizer,
} from './canonical-history-sync.mjs';
import {
  assertV2ProductionChainClientCapability,
} from './chain-client.mjs';

export class V2RecoverPoolError extends Error {
  constructor(message, { cause = undefined } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2RecoverPoolError';
  }
}

const fail = (message, options) => {
  throw new V2RecoverPoolError(message, options);
};

function exactOptions(value) {
  const expected = [
    'binding',
    'chainClient',
    'fundingWallets',
    'genesis',
    'recoverOwnedNote',
    'recoveryScanner',
    'store',
  ].sort();
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('V2 recoverPool options must be a plain object');
  }
  const actual = Object.keys(value).sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail('V2 recoverPool options have missing or unknown fields');
  }
  return value;
}

function priorCanonicalTip(store) {
  if (
    store === null
    || typeof store !== 'object'
    || typeof store.canonicalState !== 'function'
  ) {
    fail('store must expose canonicalState');
  }
  const value = store.canonicalState();
  if (
    value === null
    || typeof value !== 'object'
    || !(value.state instanceof Uint8Array)
    || !(value.outpoint?.txid instanceof Uint8Array)
    || !(value.blockHash instanceof Uint8Array)
  ) {
    fail('store returned an invalid durable canonical tip');
  }
  return Object.freeze({
    state: Buffer.from(value.state).toString('hex'),
    txid: Buffer.from(value.outpoint.txid).toString('hex'),
    vout: value.outpoint.vout,
    actionSequence: value.actionSequence,
    height: value.height,
    blockHash: Buffer.from(value.blockHash).toString('hex'),
  });
}

/**
 * Rebuild and atomically install canonical V2 state from the descriptor genesis
 * and the active best chain. This API accepts no snapshots, history records,
 * executable paths, hashes, or terminal-authentication callback.
 */
export async function recoverPool(value) {
  const options = exactOptions(value);
  try {
    assertV2ProductionChainClientCapability(options.chainClient);
  } catch (error) {
    fail(
      'recoverPool requires the production pinned-TLS V2 chain-client capability',
      { cause: error },
    );
  }
  const synchronizeCanonicalTip =
    createV2CanonicalHistorySynchronizer(options);
  const canonical = await synchronizeCanonicalTip({
    operationId: null,
    phase: 'recoverPool',
    priorCanonicalTip: priorCanonicalTip(options.store),
  });
  return Object.freeze({ canonical });
}
