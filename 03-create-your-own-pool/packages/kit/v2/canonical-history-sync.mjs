import { createHash } from 'node:crypto';

import {
  decodeActionPacket,
} from '../../action/v2/packet.mjs';
import {
  encodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import {
  canonicalizeJcs,
} from '../../profile/v2/profile-core.mjs';
import {
  deriveV2RecoveryScannerExecutionPin,
} from '../../profile/v2/instance-descriptor.mjs';
import {
  scanNativeRecoveryStream,
} from '../../pool/v2/recovery-native.mjs';
import {
  assertV2ProductionChainClientCapability,
  V2_CANONICAL_HISTORY_MAX_ACTIONS,
} from './chain-client.mjs';
import {
  parseV2RawTransaction,
} from './transaction-policy.mjs';

export const V2_CANONICAL_HISTORY_SYNCHRONIZER_SCHEMA =
  'shieldkit-v2-canonical-history-synchronizer-v1';

const HASH = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U32 = 0xffff_ffff;
const MAX_ACTION_SEQUENCE = 0x1_ffff_ffff;

export class V2CanonicalHistorySyncError extends Error {
  constructor(code, message, { cause = undefined, recoverable = false } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2CanonicalHistorySyncError';
    this.code = code;
    this.recoverable = recoverable;
  }
}

const fail = (code, message, options) => {
  throw new V2CanonicalHistorySyncError(code, message, options);
};

function plain(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('CANONICAL_HISTORY_INVALID', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      `${label} has missing or unknown fields`,
    );
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      `${label} must be lowercase 32-byte hex`,
    );
  }
  return value;
}

function stateHex(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{256}$/.test(value)) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      `${label} must be lowercase 128-byte hex`,
    );
  }
  return value;
}

function decimal(value, maximum, label) {
  if (
    typeof value !== 'string'
    || !DECIMAL.test(value)
    || BigInt(value) > BigInt(maximum)
  ) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      `${label} must be a bounded canonical decimal`,
    );
  }
  return value;
}

function integer(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      `${label} is outside its supported integer range`,
    );
  }
  return value;
}

function requireStore(value) {
  const methods = [
    'applyConfirmed',
    'canonicalState',
    'installAuthenticatedSnapshotStream',
    'operation',
  ];
  if (
    value === null
    || typeof value !== 'object'
    || methods.some((method) => typeof value[method] !== 'function')
  ) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      'store does not expose the required authenticated synchronization API',
    );
  }
  return value;
}

function requireChainClient(value) {
  const methods = [
    'fetchAuthenticatedPoolTip',
    'fetchCanonicalHistoryPage',
    'fetchTransaction',
    'queryWalletUtxos',
  ];
  if (
    value === null
    || typeof value !== 'object'
    || methods.some((method) => typeof value[method] !== 'function')
  ) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      'chainClient does not expose the required typed read API',
    );
  }
  return value;
}

function normalizeLocalTip(value) {
  exact(
    value,
    ['actionSequence', 'blockHash', 'height', 'outpoint', 'state'],
    'durable canonical tip',
  );
  exact(value.outpoint, ['txid', 'vout'], 'durable canonical outpoint');
  if (
    !(value.state instanceof Uint8Array)
    || value.state.length !== 128
    || !(value.outpoint.txid instanceof Uint8Array)
    || value.outpoint.txid.length !== 32
    || !(value.blockHash instanceof Uint8Array)
    || value.blockHash.length !== 32
  ) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      'durable canonical tip byte fields have invalid lengths',
    );
  }
  return Object.freeze({
    state: Buffer.from(value.state),
    outpoint: Object.freeze({
      txid: Buffer.from(value.outpoint.txid),
      vout: integer(value.outpoint.vout, 0, MAX_U32, 'canonical vout'),
    }),
    actionSequence: integer(
      value.actionSequence,
      0,
      MAX_ACTION_SEQUENCE,
      'canonical actionSequence',
    ),
    height: integer(value.height, 0, MAX_U32, 'canonical height'),
    blockHash: Buffer.from(value.blockHash),
  });
}

function normalizePriorTip(value) {
  exact(
    value,
    ['actionSequence', 'blockHash', 'height', 'state', 'txid', 'vout'],
    'prior canonical tip',
  );
  return Object.freeze({
    state: stateHex(value.state, 'prior canonical tip.state'),
    txid: hash(value.txid, 'prior canonical tip.txid'),
    vout: integer(value.vout, 0, MAX_U32, 'prior canonical tip.vout'),
    actionSequence: integer(
      value.actionSequence,
      0,
      MAX_ACTION_SEQUENCE,
      'prior canonical tip.actionSequence',
    ),
    height: integer(
      value.height,
      0,
      MAX_U32,
      'prior canonical tip.height',
    ),
    blockHash: hash(
      value.blockHash,
      'prior canonical tip.blockHash',
    ),
  });
}

function normalizeRemoteTip(value, instanceId) {
  exact(
    value,
    [
      'actionSequence',
      'blockHash',
      'confirmations',
      'height',
      'state',
      'txid',
      'vout',
    ],
    'remote canonical tip',
  );
  return Object.freeze({
    state: stateHex(value.state, 'remote canonical tip.state'),
    txid: hash(value.txid, 'remote canonical tip.txid'),
    vout: integer(value.vout, 0, MAX_U32, 'remote canonical tip.vout'),
    actionSequence: integer(
      value.actionSequence,
      0,
      MAX_ACTION_SEQUENCE,
      'remote canonical tip.actionSequence',
    ),
    height: integer(value.height, 0, MAX_U32, 'remote canonical tip.height'),
    blockHash: hash(value.blockHash, 'remote canonical tip.blockHash'),
    confirmations: integer(
      value.confirmations,
      1,
      Number.MAX_SAFE_INTEGER,
      'remote canonical tip.confirmations',
    ),
    instanceId,
  });
}

function sameTip(local, remote) {
  return (
    local.state.toString('hex') === remote.state
    && local.outpoint.txid.toString('hex') === remote.txid
    && local.outpoint.vout === remote.vout
    && local.actionSequence === remote.actionSequence
    && local.height === remote.height
    && local.blockHash.toString('hex') === remote.blockHash
  );
}

function sameRemoteTip(left, right) {
  return (
    left.state === right.state
    && left.txid === right.txid
    && left.vout === right.vout
    && left.actionSequence === right.actionSequence
    && left.height === right.height
    && left.blockHash === right.blockHash
    && left.confirmations === right.confirmations
  );
}

function pageIdentity(page) {
  return canonicalizeJcs({
    schema: page.schema,
    instanceId: page.instanceId,
    snapshotId: page.snapshotId,
    genesis: page.genesis,
    tip: {
      transactionId: page.tip.transactionId,
      outputIndex: page.tip.outputIndex,
      stateHex: page.tip.stateHex,
      actionSequence: page.tip.actionSequence,
      height: page.tip.height,
      blockHash: page.tip.blockHash,
    },
    actionCount: page.actionCount,
    historySha256: page.historySha256,
  });
}

function pageTip(page, instanceId) {
  return normalizeRemoteTip({
    state: page.tip.stateHex,
    txid: page.tip.transactionId,
    vout: page.tip.outputIndex,
    actionSequence: Number(decimal(
      page.tip.actionSequence,
      MAX_ACTION_SEQUENCE,
      'history tip actionSequence',
    )),
    height: page.tip.height,
    blockHash: page.tip.blockHash,
    confirmations: page.tip.confirmations,
  }, instanceId);
}

function operationOrNull(store, operationId) {
  if (operationId === null) return null;
  try {
    return store.operation(operationId);
  } catch (error) {
    if (
      error instanceof Error
      && error.message === 'operation does not exist'
    ) {
      return null;
    }
    throw error;
  }
}

function publicRecordId(transactionId, outputNoteLeaf) {
  return `v2r:${createHash('sha256').update(Buffer.concat([
    Buffer.from('ShieldKit/V2Direct/LocalRecordId/v1\0', 'utf8'),
    transactionId,
    outputNoteLeaf,
  ])).digest('hex')}`;
}

function confirmationUndo(remote) {
  return Buffer.from(canonicalizeJcs({
    schema: 'shieldkit-v2-confirmation-anchor-v1',
    transactionId: remote.txid,
    outputIndex: remote.vout,
    stateHex: remote.state,
    actionSequence: String(remote.actionSequence),
    height: remote.height,
    blockHash: remote.blockHash,
    confirmations: remote.confirmations,
  }), 'utf8');
}

async function applyOwnConfirmedOperation({
  chainClient,
  denominationSats,
  operation,
  recoverOwnedNote,
  remote,
  store,
}) {
  if (
    !['broadcast', 'mempool'].includes(operation.journalState)
    || operation.packet === null
    || operation.signedTx === null
  ) {
    return null;
  }
  const signed = parseV2RawTransaction(operation.signedTx.toString('hex'));
  if (signed.txid !== remote.txid || remote.vout !== 0) return null;
  const observedRaw = await chainClient.fetchTransaction({
    transactionId: remote.txid,
  });
  if (observedRaw !== signed.rawTransactionHex) {
    fail(
      'CANONICAL_HISTORY_DIVERGENT_TRANSACTION',
      'confirmed pool tip transaction bytes differ from the durable signed operation',
    );
  }
  const packet = decodeActionPacket(operation.packet, {
    denominationSats,
  });
  const postState = encodeStateNftCommitment(packet.postState, {
    denominationSats,
  });
  if (
    postState.toString('hex') !== remote.state
    || Number(packet.postState.actionSequence) !== remote.actionSequence
    || remote.actionSequence !== operation.expectedActionSequence + 1
  ) {
    fail(
      'CANONICAL_HISTORY_DIVERGENT_TRANSACTION',
      'confirmed durable transaction does not produce the observed canonical state',
    );
  }
  const outputActive = operation.kind !== 'withdrawal';
  const transactionId = Buffer.from(remote.txid, 'hex');
  const outputNoteLeaf = outputActive
    ? Buffer.from(packet.outputNoteLeaf, 'hex')
    : null;
  let owned = null;
  let recordId = null;
  if (outputActive) {
    recordId = publicRecordId(transactionId, outputNoteLeaf);
    owned = recoverOwnedNote(Object.freeze({
      noteIndex: Number(packet.preState.noteCount),
      outputNoteLeaf,
      encryptedRecord: Buffer.from(packet.encryptedRecord),
      actionSequence: remote.actionSequence,
      transactionId,
    }));
    if (owned !== null && owned.recordId !== recordId) {
      fail(
        'CANONICAL_HISTORY_OWNED_NOTE_INVALID',
        'recovered owned note record identity differs from the canonical output',
      );
    }
  }
  const change = signed.outputs.at(-1);
  if (change === undefined) {
    fail(
      'CANONICAL_HISTORY_DIVERGENT_TRANSACTION',
      'confirmed operation omitted its funding-wallet change output',
    );
  }
  return store.applyConfirmed({
    operationId: operation.operationId,
    expected: {
      state: operation.expectedState,
      outpoint: operation.expectedOutpoint,
      actionSequence: operation.expectedActionSequence,
    },
    next: {
      state: postState,
      outpoint: { txid: transactionId, vout: 0 },
      actionSequence: remote.actionSequence,
      height: remote.height,
      blockHash: Buffer.from(remote.blockHash, 'hex'),
    },
    records: outputActive
      ? [{ recordId, record: Buffer.from(packet.encryptedRecord) }]
      : [],
    notes: {
      insert: owned === null
        ? []
        : [{
            noteId: owned.noteId,
            recordId: owned.recordId,
            noteIndex: Number(packet.preState.noteCount),
            nullifier: owned.nullifier,
          }],
      spend: operation.kind === 'deposit'
        ? []
        : [operation.intent.selectedNoteId],
    },
    funding: {
      spend: {
        txid: operation.intent.funding.txid,
        vout: operation.intent.funding.vout,
      },
      change: [{
        txid: transactionId,
        vout: change.index,
        valueSats: change.valueSatoshis.toString(),
      }],
    },
    undo: confirmationUndo(remote),
    crashAt: null,
  });
}

function validateOptions(value) {
  exact(
    value,
    [
      'binaryPath',
      'binarySha256',
      'binding',
      'chainClient',
      'fundingWallets',
      'genesis',
      'recoverOwnedNote',
      'scanRecoveryStream',
      'store',
    ],
    'canonical history synchronizer options',
  );
  exact(
    value.binding,
    [
      'carrierCount',
      'denominationSats',
      'instanceId',
      'networkId',
      'profileId',
      'runtimeMaterialsSha256',
    ],
    'canonical history synchronizer binding',
  );
  if (
    !Array.isArray(value.fundingWallets)
    || value.fundingWallets.length === 0
    || value.fundingWallets.length > 100_000
  ) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      'canonical history synchronizer fundingWallets must be a nonempty bounded array',
    );
  }
  const fundingWallets = [];
  const seenFundingAddresses = new Set();
  const seenFundingLocks = new Set();
  for (let index = 0; index < value.fundingWallets.length; index += 1) {
    const wallet = value.fundingWallets[index];
    exact(
      wallet,
      ['cashAddress', 'lockingBytecodeHex'],
      `canonical history synchronizer fundingWallets[${index}]`,
    );
    if (
      typeof wallet.cashAddress !== 'string'
      || !wallet.cashAddress.startsWith('bchtest:')
      || typeof wallet.lockingBytecodeHex !== 'string'
      || !/^76a914[0-9a-f]{40}88ac$/.test(wallet.lockingBytecodeHex)
      || seenFundingAddresses.has(wallet.cashAddress)
      || seenFundingLocks.has(wallet.lockingBytecodeHex)
    ) {
      fail(
        'CANONICAL_HISTORY_INVALID',
        'canonical history synchronizer funding wallets must be unique canonical Chipnet P2PKH addresses',
      );
    }
    seenFundingAddresses.add(wallet.cashAddress);
    seenFundingLocks.add(wallet.lockingBytecodeHex);
    fundingWallets.push(Object.freeze({
      cashAddress: wallet.cashAddress,
      lockingBytecodeHex: wallet.lockingBytecodeHex,
    }));
  }
  exact(
    value.genesis,
    [
      'initialStateHex',
      'outputIndex',
      'transactionId',
    ],
    'canonical history synchronizer genesis',
  );
  if (
    typeof value.binaryPath !== 'string'
    || !value.binaryPath.startsWith('/')
    || typeof value.binarySha256 !== 'string'
    || !HASH.test(value.binarySha256)
    || typeof value.recoverOwnedNote !== 'function'
    || typeof value.scanRecoveryStream !== 'function'
  ) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      'canonical synchronizer binary, scanner, or note recovery options are invalid',
    );
  }
  const binding = Object.freeze({
    profileId: hash(value.binding.profileId, 'binding.profileId'),
    instanceId: hash(value.binding.instanceId, 'binding.instanceId'),
    networkId: integer(value.binding.networkId, 1, 2, 'binding.networkId'),
    denominationSats: decimal(
      value.binding.denominationSats,
      2_100_000_000_000_000n,
      'binding.denominationSats',
    ),
    carrierCount: integer(
      value.binding.carrierCount,
      1,
      255,
      'binding.carrierCount',
    ),
    runtimeMaterialsSha256: hash(
      value.binding.runtimeMaterialsSha256,
      'binding.runtimeMaterialsSha256',
    ),
  });
  const genesis = Object.freeze({
    transactionId: hash(
      value.genesis.transactionId,
      'genesis.transactionId',
    ),
    outputIndex: integer(
      value.genesis.outputIndex,
      0,
      MAX_U32,
      'genesis.outputIndex',
    ),
    initialStateHex: stateHex(
      value.genesis.initialStateHex,
      'genesis.initialStateHex',
    ),
  });
  return Object.freeze({
    binaryPath: value.binaryPath,
    binarySha256: value.binarySha256,
    binding,
    chainClient: requireChainClient(value.chainClient),
    fundingWallets: Object.freeze(fundingWallets),
    genesis,
    recoverOwnedNote: value.recoverOwnedNote,
    scanRecoveryStream: value.scanRecoveryStream,
    store: requireStore(value.store),
  });
}

async function fetchFundingInventory(options, expectedRemote) {
  const observations = [];
  for (const wallet of options.fundingWallets) {
    const observation = await options.chainClient.queryWalletUtxos({
      cashAddress: wallet.cashAddress,
      instanceId: options.binding.instanceId,
      lockingBytecodeHex: wallet.lockingBytecodeHex,
    });
    const observedTip = normalizeRemoteTip(
      observation.canonicalTip,
      options.binding.instanceId,
    );
    if (!sameRemoteTip(expectedRemote, observedTip)) {
      fail(
        'CANONICAL_FUNDING_INVENTORY_RACE',
        'funding inventory was not observed at the exact canonical pool tip',
        { recoverable: true },
      );
    }
    observations.push(observation);
  }
  return Object.freeze(observations);
}

function storeFundingInventory(observations) {
  const seen = new Set();
  const inventory = [];
  for (const observation of observations) {
    for (const entry of observation.utxos) {
      const key = `${entry.txid}:${entry.vout}`;
      if (seen.has(key)) {
        fail(
          'CANONICAL_FUNDING_INVENTORY_INVALID',
          'funding inventory repeats one outpoint across wallet addresses',
        );
      }
      seen.add(key);
      inventory.push(Object.freeze({
        txid: Buffer.from(entry.txid, 'hex'),
        vout: entry.vout,
        valueSats: entry.valueSats,
      }));
    }
  }
  return Object.freeze(inventory);
}

async function fetchFirstPage(options) {
  const page = await options.chainClient.fetchCanonicalHistoryPage({
    instanceId: options.binding.instanceId,
    genesisTransactionId: options.genesis.transactionId,
    cursor: null,
    maxActions: V2_CANONICAL_HISTORY_MAX_ACTIONS,
  });
  if (
    page.pageStartIndex !== '0'
    || page.genesis.transactionId !== options.genesis.transactionId
    || page.genesis.outputIndex !== options.genesis.outputIndex
    || page.genesis.initialStateHex !== options.genesis.initialStateHex
  ) {
    fail(
      'CANONICAL_HISTORY_GENESIS_MISMATCH',
      'canonical history did not begin at the descriptor-bound genesis',
    );
  }
  return page;
}

function historySteps(options, firstPage) {
  const identity = pageIdentity(firstPage);
  const seenCursors = new Set();
  return (async function* steps() {
    let page = firstPage;
    let expectedIndex = 0;
    while (true) {
      if (
        pageIdentity(page) !== identity
        || Number(page.pageStartIndex) !== expectedIndex
      ) {
        fail(
          'CANONICAL_HISTORY_PAGE_DRIFT',
          'canonical history page identity or contiguous range changed during streaming',
          { recoverable: true },
        );
      }
      for (const entry of page.actions) {
        if (Number(entry.index) !== expectedIndex) {
          fail(
            'CANONICAL_HISTORY_PAGE_DRIFT',
            'canonical history action index is not globally contiguous',
          );
        }
        expectedIndex += 1;
        yield Object.freeze({
          action: entry.action,
          fundingPrevout: entry.fundingPrevout,
        });
      }
      if (page.nextCursor === null) {
        if (expectedIndex !== Number(page.actionCount)) {
          fail(
            'CANONICAL_HISTORY_PAGE_DRIFT',
            'terminal canonical history page ended before actionCount',
          );
        }
        return;
      }
      if (seenCursors.has(page.nextCursor)) {
        fail(
          'CANONICAL_HISTORY_CURSOR_CYCLE',
          'canonical history cursor repeated before the terminal page',
        );
      }
      seenCursors.add(page.nextCursor);
      page = await options.chainClient.fetchCanonicalHistoryPage({
        instanceId: options.binding.instanceId,
        genesisTransactionId: options.genesis.transactionId,
        cursor: page.nextCursor,
        maxActions: V2_CANONICAL_HISTORY_MAX_ACTIONS,
      });
    }
  })();
}

async function installRemoteHistory(options, initialRemote) {
  const initialFunding = await fetchFundingInventory(
    options,
    initialRemote,
  );
  const fundingIdentity = canonicalizeJcs(initialFunding);
  const firstPage = await fetchFirstPage(options);
  const pageRemote = pageTip(firstPage, options.binding.instanceId);
  if (!sameRemoteTip(initialRemote, pageRemote)) {
    fail(
      'CANONICAL_HISTORY_RACE',
      'pool tip changed between terminal observation and history pagination',
      { recoverable: true },
    );
  }
  const actionCount = Number(decimal(
    firstPage.actionCount,
    MAX_ACTION_SEQUENCE,
    'canonical history actionCount',
  ));
  const requestHeader = Object.freeze({
    networkId: options.binding.networkId,
    profileId: options.binding.profileId,
    instanceId: options.binding.instanceId,
    denominationSats: options.binding.denominationSats,
    carrierCount: options.binding.carrierCount,
    runtimeMaterialsSha256: options.binding.runtimeMaterialsSha256,
    genesis: {
      transactionId: firstPage.genesis.transactionId,
      rawTransaction: firstPage.genesis.rawTransaction,
      height: firstPage.genesis.height,
      blockHash: firstPage.genesis.blockHash,
    },
    genesisOutpoint: {
      transactionId: firstPage.genesis.transactionId,
      outputIndex: firstPage.genesis.outputIndex,
    },
    initialStateHex: firstPage.genesis.initialStateHex,
    expectedTip: {
      transactionId: firstPage.tip.transactionId,
      outputIndex: firstPage.tip.outputIndex,
      height: firstPage.tip.height,
      blockHash: firstPage.tip.blockHash,
    },
  });
  const installed = await options.store.installAuthenticatedSnapshotStream({
    authenticateTerminal: async ({ snapshot, canonical }) => {
      if (
        snapshot.actionCount !== firstPage.actionCount
        || snapshot.historySha256 !== firstPage.historySha256
        || snapshot.genesis.transactionId
          !== firstPage.genesis.transactionId
        || snapshot.genesis.outputIndex !== firstPage.genesis.outputIndex
        || snapshot.genesis.stateHex !== firstPage.genesis.initialStateHex
        || snapshot.tip.transactionId !== firstPage.tip.transactionId
        || snapshot.tip.outputIndex !== firstPage.tip.outputIndex
        || snapshot.tip.stateHex !== firstPage.tip.stateHex
        || canonical.state.toString('hex') !== firstPage.tip.stateHex
        || canonical.outpoint.txid.toString('hex')
          !== firstPage.tip.transactionId
        || canonical.outpoint.vout !== firstPage.tip.outputIndex
        || canonical.actionSequence !== actionCount
        || canonical.height !== firstPage.tip.height
        || canonical.blockHash.toString('hex') !== firstPage.tip.blockHash
      ) {
        fail(
          'CANONICAL_HISTORY_SCANNER_DIVERGENCE',
          'native scanner terminal material differs from the canonical history identity',
        );
      }
      const finalRemote = normalizeRemoteTip(
        await options.chainClient.fetchAuthenticatedPoolTip({
          instanceId: options.binding.instanceId,
        }),
        options.binding.instanceId,
      );
      if (!sameRemoteTip(initialRemote, finalRemote)) {
        fail(
          'CANONICAL_HISTORY_RACE',
          'pool tip changed before atomic canonical history installation',
          { recoverable: true },
        );
      }
      const finalFunding = await fetchFundingInventory(
        options,
        finalRemote,
      );
      if (canonicalizeJcs(finalFunding) !== fundingIdentity) {
        fail(
          'CANONICAL_FUNDING_INVENTORY_RACE',
          'funding inventory changed before atomic canonical history installation',
          { recoverable: true },
        );
      }
      return true;
    },
    frames: options.scanRecoveryStream({
      binaryPath: options.binaryPath,
      binarySha256: options.binarySha256,
      requestHeader,
      actionCount,
      steps: historySteps(options, firstPage),
    }),
    fundingInventory: storeFundingInventory(initialFunding),
    recoverOwnedNote: options.recoverOwnedNote,
    crashAt: null,
  });
  return normalizeLocalTip(installed.canonical);
}

function createSynchronizerFromValidatedOptions(options) {
  return async function synchronizeCanonicalTip(request = {}) {
    exact(
      request,
      ['operationId', 'phase', 'priorCanonicalTip'],
      'canonical synchronization request',
    );
    if (
      typeof request.phase !== 'string'
      || request.phase.length === 0
      || (
        request.operationId !== null
        && typeof request.operationId !== 'string'
      )
    ) {
      fail(
        'CANONICAL_HISTORY_INVALID',
        'canonical synchronization phase or operationId is invalid',
      );
    }
    const local = normalizeLocalTip(options.store.canonicalState());
    const prior = normalizePriorTip(request.priorCanonicalTip);
    if (!sameTip(local, prior)) {
      fail(
        'CANONICAL_LOCAL_RACE',
        'caller prior canonical tip differs from the durable store tip',
        { recoverable: true },
      );
    }
    const remote = normalizeRemoteTip(
      await options.chainClient.fetchAuthenticatedPoolTip({
        instanceId: options.binding.instanceId,
      }),
      options.binding.instanceId,
    );
    if (sameTip(local, remote)) return local;

    const operation = operationOrNull(options.store, request.operationId);
    if (operation !== null) {
      if (
        request.phase === 'confirm'
        && ['broadcast', 'mempool', 'confirmed', 'settled'].includes(
          operation.journalState,
        )
      ) {
        const applied = await applyOwnConfirmedOperation({
          chainClient: options.chainClient,
          denominationSats: options.binding.denominationSats,
          operation,
          recoverOwnedNote: options.recoverOwnedNote,
          remote,
          store: options.store,
        });
        if (applied !== null) return normalizeLocalTip(applied);
        // The remote tip may be a later successor of our transaction or a
        // competing branch. Only a complete descriptor-genesis-bound scan can
        // distinguish those cases. The atomic stream install reconciles the
        // durable operation against the exact canonical transaction IDs.
        return await installRemoteHistory(options, remote);
      }
      fail(
        'CANONICAL_TIP_CHANGED',
        'canonical pool tip changed while an operation was pending; the operation must enter conflict recovery before history synchronization',
        { recoverable: true },
      );
    }
    return await installRemoteHistory(options, remote);
  };
}

/**
 * Create the authenticated chain-to-store boundary used by every lifecycle
 * phase. Pinned TLS delegates active-best-chain assertions to the configured
 * provider; raw transaction lineage, roots, packets, and terminal state are
 * independently reconstructed by the descriptor-pinned native scanner before
 * commit. Caller-provided executable paths, hashes, and scanner functions are
 * intentionally absent from this production API.
 */
export function createV2CanonicalHistorySynchronizer(value) {
  exact(
    value,
    [
      'binding',
      'chainClient',
      'fundingWallets',
      'genesis',
      'recoverOwnedNote',
      'recoveryScanner',
      'store',
    ],
    'production canonical history synchronizer options',
  );
  let executionPin;
  try {
    executionPin = deriveV2RecoveryScannerExecutionPin(
      value.recoveryScanner,
    );
  } catch (error) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      'production recovery scanner must be derived from the validated signed instance descriptor',
      { cause: error },
    );
  }
  try {
    assertV2ProductionChainClientCapability(value.chainClient);
  } catch (error) {
    fail(
      'CANONICAL_HISTORY_INVALID',
      'production synchronization requires the pinned-TLS V2 Chipnet chain-client capability',
      { cause: error },
    );
  }
  return createSynchronizerFromValidatedOptions(validateOptions({
    binaryPath: executionPin.binaryPath,
    binarySha256: executionPin.binarySha256,
    binding: value.binding,
    chainClient: value.chainClient,
    fundingWallets: value.fundingWallets,
    genesis: value.genesis,
    recoverOwnedNote: value.recoverOwnedNote,
    scanRecoveryStream: scanNativeRecoveryStream,
    store: value.store,
  }));
}

/**
 * Explicit unit-only orchestration seam. Qualification and production callers
 * must use `createV2CanonicalHistorySynchronizer`; this constructor exists so
 * deterministic tests can exercise provider/store races without executing a
 * native binary.
 */
export function createV2FixtureOnlyCanonicalHistorySynchronizer(value) {
  exact(
    value,
    [
      'binding',
      'chainClient',
      'fixtureScanner',
      'fundingWallets',
      'genesis',
      'recoverOwnedNote',
      'scanRecoveryStream',
      'store',
    ],
    'fixture-only canonical history synchronizer options',
  );
  exact(
    value.fixtureScanner,
    ['binaryPath', 'binarySha256'],
    'fixture-only recovery scanner',
  );
  return createSynchronizerFromValidatedOptions(validateOptions({
    binaryPath: value.fixtureScanner.binaryPath,
    binarySha256: value.fixtureScanner.binarySha256,
    binding: value.binding,
    chainClient: value.chainClient,
    fundingWallets: value.fundingWallets,
    genesis: value.genesis,
    recoverOwnedNote: value.recoverOwnedNote,
    scanRecoveryStream: value.scanRecoveryStream,
    store: value.store,
  }));
}
