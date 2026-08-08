import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { encodeActionPacket } from '../../action/v2/packet.mjs';
import { encodeStateNftCommitment } from '../../action/v2/state.mjs';
import {
  applyDirectV2Transition,
  createDirectV2PoolModel,
} from '../../action/v2/transition.mjs';
import { openV2DirectStore } from '../../pool/v2/store.mjs';
import { parseV2RawTransaction } from './transaction-policy.mjs';
import {
  createV2CanonicalHistorySynchronizer,
  createV2FixtureOnlyCanonicalHistorySynchronizer,
  V2CanonicalHistorySyncError,
} from './canonical-history-sync.mjs';

// Unit-only orchestration fixtures. They deliberately exercise the strict
// chain/scanner boundary without representing a proof, a BCH acceptance test,
// or release evidence. The first test additionally uses a real V2DirectStore
// to cover the no-scan fast path against its durable canonical state.
const PROFILE_ID = '11'.repeat(32);
const INSTANCE_ID = '22'.repeat(32);
const RUNTIME = '33'.repeat(32);
const GENESIS_TXID = '44'.repeat(32);
const GENESIS_BLOCK = '55'.repeat(32);
const DENOMINATION_SATS = '10000000';
const FUNDING_ADDRESS =
  'bchtest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdpn3jdgd';
const FUNDING_LOCK = `76a914${'00'.repeat(20)}88ac`;
const SECOND_FUNDING_ADDRESS =
  'bchtest:qqqszqgpqyqszqgpqyqszqgpqyqszqgpqy8kvl0kqa';
const SECOND_FUNDING_LOCK = `76a914${'01'.repeat(20)}88ac`;
const FUNDING_WALLET = Object.freeze({
  cashAddress: FUNDING_ADDRESS,
  lockingBytecodeHex: FUNDING_LOCK,
});
const SECOND_FUNDING_WALLET = Object.freeze({
  cashAddress: SECOND_FUNDING_ADDRESS,
  lockingBytecodeHex: SECOND_FUNDING_LOCK,
});
const DEFAULT_FUNDING_WALLETS = Object.freeze([FUNDING_WALLET]);
const BINDING = Object.freeze({
  profileId: PROFILE_ID,
  instanceId: INSTANCE_ID,
  networkId: 2,
  denominationSats: DENOMINATION_SATS,
  carrierCount: 7,
  runtimeMaterialsSha256: RUNTIME,
});

const hash = (byte) => byte.repeat(64);
const stateContext = Object.freeze({ denominationSats: DENOMINATION_SATS });
const initialModel = () => createDirectV2PoolModel({
  profileId: PROFILE_ID,
  maximumLiveNotes: '32',
  denominationSats: DENOMINATION_SATS,
});
const initialState = () => encodeStateNftCommitment(
  initialModel().state,
  stateContext,
);
const asLocal = ({
  state = initialState(),
  txid = GENESIS_TXID,
  vout = 0,
  actionSequence = 0,
  height = 100,
  blockHash = GENESIS_BLOCK,
} = {}) => Object.freeze({
  state: Buffer.from(state),
  outpoint: Object.freeze({ txid: Buffer.from(txid, 'hex'), vout }),
  actionSequence,
  height,
  blockHash: Buffer.from(blockHash, 'hex'),
});
const cloneLocal = (value) => Object.freeze({
  state: Buffer.from(value.state),
  outpoint: Object.freeze({
    txid: Buffer.from(value.outpoint.txid),
    vout: value.outpoint.vout,
  }),
  actionSequence: value.actionSequence,
  height: value.height,
  blockHash: Buffer.from(value.blockHash),
});
const asRemote = (local, confirmations = 6) => Object.freeze({
  state: local.state.toString('hex'),
  txid: local.outpoint.txid.toString('hex'),
  vout: local.outpoint.vout,
  actionSequence: local.actionSequence,
  height: local.height,
  blockHash: local.blockHash.toString('hex'),
  confirmations,
});
const priorTip = (local) => Object.freeze({
  state: local.state.toString('hex'),
  txid: local.outpoint.txid.toString('hex'),
  vout: local.outpoint.vout,
  actionSequence: local.actionSequence,
  height: local.height,
  blockHash: local.blockHash.toString('hex'),
});
const request = (
  operationId = null,
  phase = 'prepare',
  local = asLocal(),
) => ({
  operationId,
  phase,
  priorCanonicalTip: priorTip(local),
});
const genesis = () => Object.freeze({
  transactionId: GENESIS_TXID,
  outputIndex: 0,
  initialStateHex: initialState().toString('hex'),
});

function baseOptions({
  chainClient,
  fundingWallets = DEFAULT_FUNDING_WALLETS,
  recoverOwnedNote = () => null,
  scanRecoveryStream,
  store,
}) {
  return {
    binding: BINDING,
    chainClient,
    fixtureScanner: Object.freeze({
      binaryPath: '/unit-only/recovery-scanner',
      binarySha256: hash('a'),
    }),
    fundingWallets,
    genesis: genesis(),
    recoverOwnedNote,
    scanRecoveryStream,
    store,
  };
}

function page({
  actions,
  actionCount,
  pageStartIndex,
  nextCursor,
  remote,
  snapshotId = hash('b'),
  historySha256 = hash('c'),
}) {
  return Object.freeze({
    schema: 'shieldkit-v2-canonical-history-page-v1',
    instanceId: INSTANCE_ID,
    snapshotId,
    genesis: Object.freeze({
      transactionId: GENESIS_TXID,
      outputIndex: 0,
      initialStateHex: initialState().toString('hex'),
      rawTransaction: '00',
      height: 100,
      blockHash: GENESIS_BLOCK,
    }),
    tip: Object.freeze({
      transactionId: remote.txid,
      outputIndex: remote.vout,
      stateHex: remote.state,
      actionSequence: String(remote.actionSequence),
      height: remote.height,
      blockHash: remote.blockHash,
      confirmations: remote.confirmations,
    }),
    actionCount: String(actionCount),
    historySha256,
    pageStartIndex: String(pageStartIndex),
    actions: Object.freeze(actions.map((value, index) => Object.freeze({
      index: String(pageStartIndex + index),
      action: Object.freeze({ rawTransaction: value.action }),
      fundingPrevout: Object.freeze({ rawTransaction: value.funding }),
    }))),
    nextCursor,
  });
}

function recordingStore(local, { operations = new Map(), scannerTerminal = null } = {}) {
  let canonical = cloneLocal(local);
  const calls = [];
  const store = {
    canonicalState() { return canonical; },
    operation(operationId) {
      if (!operations.has(operationId)) throw new Error('operation does not exist');
      return operations.get(operationId);
    },
    async installAuthenticatedSnapshotStream(input) {
      calls.push(['install', input.fundingInventory]);
      for await (const _frame of input.frames) calls.push(['frame']);
      const terminal = scannerTerminal ?? canonical;
      const authenticated = await input.authenticateTerminal(Object.freeze({
        snapshot: Object.freeze({
          actionCount: String(terminal.actionSequence),
          historySha256: hash('c'),
          genesis: Object.freeze({
            transactionId: GENESIS_TXID,
            outputIndex: 0,
            stateHex: initialState().toString('hex'),
          }),
          tip: Object.freeze({
            transactionId: terminal.outpoint.txid.toString('hex'),
            outputIndex: terminal.outpoint.vout,
            stateHex: terminal.state.toString('hex'),
          }),
        }),
        canonical: terminal,
      }));
      assert.equal(authenticated, true);
      canonical = cloneLocal(terminal);
      return Object.freeze({ canonical });
    },
    applyConfirmed(input) {
      calls.push(['apply', input]);
      canonical = asLocal({
        state: input.next.state,
        txid: input.next.outpoint.txid.toString('hex'),
        vout: input.next.outpoint.vout,
        actionSequence: input.next.actionSequence,
        height: input.next.height,
        blockHash: input.next.blockHash.toString('hex'),
      });
      return canonical;
    },
  };
  return { calls, store, canonical: () => canonical };
}

function chain({
  fundingObservations = [],
  pages = [],
  tips,
  rawByTxid = new Map(),
}) {
  let tipIndex = 0;
  let pageIndex = 0;
  let fundingIndex = 0;
  const calls = [];
  return {
    calls,
    async fetchAuthenticatedPoolTip() {
      calls.push(['tip', tipIndex]);
      return tips[Math.min(tipIndex++, tips.length - 1)];
    },
    async fetchCanonicalHistoryPage(input) {
      calls.push(['page', input.cursor]);
      const next = pages[pageIndex++];
      assert.ok(next, 'unexpected canonical-history page request');
      return next;
    },
    async fetchTransaction({ transactionId }) {
      calls.push(['tx', transactionId]);
      return rawByTxid.get(transactionId);
    },
    async queryWalletUtxos(input) {
      calls.push(['funding', fundingIndex, input]);
      const selectedIndex = fundingIndex++;
      const supplied = fundingObservations[Math.min(
        selectedIndex,
        fundingObservations.length - 1,
      )];
      if (supplied !== undefined) return supplied;
      const canonicalTip = tips[Math.min(selectedIndex, tips.length - 1)];
      return Object.freeze({
        canonicalTip,
        cashAddress: FUNDING_ADDRESS,
        lockingBytecodeHex: FUNDING_LOCK,
        utxos: Object.freeze([]),
      });
    },
  };
}

function fundingObservation(remote, utxos = [], wallet = FUNDING_WALLET) {
  return Object.freeze({
    canonicalTip: remote,
    cashAddress: wallet.cashAddress,
    lockingBytecodeHex: wallet.lockingBytecodeHex,
    utxos: Object.freeze(utxos.map((entry) => Object.freeze(entry))),
  });
}

async function* scannerFrames({ steps, capture }) {
  for await (const step of steps) capture.push(step);
  yield Object.freeze({ type: 'unit-only-frame' });
}

function depositPacketAndTransaction() {
  const model = initialModel();
  const outputNoteLeaf = `${'0'.repeat(63)}1`;
  const transition = applyDirectV2Transition({
    kind: 'deposit',
    networkId: 2,
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    denominationSats: DENOMINATION_SATS,
    preState: model.state,
    noteTree: model.noteTree,
    nullifierTree: model.nullifierTree,
    transactionContextHash: hash('d'),
    output: { outputNoteLeaf, encryptedRecord: Buffer.alloc(128, 0x42) },
  });
  const packet = encodeActionPacket({
    kind: 'deposit',
    networkId: 2,
    instanceId: INSTANCE_ID,
    preState: model.state,
    postState: transition.state,
    publicNullifier: '0'.repeat(64),
    outputNoteLeaf,
    encryptedRecord: Buffer.alloc(128, 0x42),
    withdrawalLockingBytecodeHash: '0'.repeat(64),
    transactionContextHash: hash('d'),
  }, stateContext);
  const raw = Buffer.from(
    `0200000001${'00'.repeat(32)}0000000000ffffffff` +
    '012202000000000000015100000000',
    'hex',
  );
  const parsed = parseV2RawTransaction(raw.toString('hex'));
  return { packet, raw, parsed, transition };
}

test('[unit-only] production synchronizer rejects caller-created scanner capabilities', () => {
  const local = asLocal();
  const fixtureOptions = baseOptions({
    store: recordingStore(local).store,
    chainClient: chain({ tips: [asRemote(local)] }),
    scanRecoveryStream: async function* () {},
  });
  const {
    fixtureScanner,
    scanRecoveryStream,
    ...productionOptions
  } = fixtureOptions;
  assert.throws(
    () => createV2CanonicalHistorySynchronizer({
      ...productionOptions,
      recoveryScanner: {
        binaryPath: fixtureScanner.binaryPath,
        binarySha256: fixtureScanner.binarySha256,
      },
    }),
    (error) =>
      error instanceof V2CanonicalHistorySyncError
      && error.code === 'CANONICAL_HISTORY_INVALID'
      && /validated signed instance descriptor/.test(error.message),
  );
  assert.throws(
    () => createV2CanonicalHistorySynchronizer({
      ...productionOptions,
      binaryPath: fixtureScanner.binaryPath,
      binarySha256: fixtureScanner.binarySha256,
      scanRecoveryStream,
    }),
    (error) =>
      error instanceof V2CanonicalHistorySyncError
      && error.code === 'CANONICAL_HISTORY_INVALID',
  );
});

test('[unit-only] identical authenticated remote tip uses real V2DirectStore and never scans', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-v2-canonical-sync-'));
  t.after(async () => { await rm(directory, { recursive: true, force: true }); });
  const initial = asLocal();
  const store = openV2DirectStore({
    path: path.join(directory, 'private', 'pool.sqlite'),
    profileId: Buffer.from(PROFILE_ID, 'hex'),
    instanceId: Buffer.from(INSTANCE_ID, 'hex'),
    networkId: 2,
    denominationSats: DENOMINATION_SATS,
    carrierCount: 7,
    runtimeMaterialsSha256: Buffer.from(RUNTIME, 'hex'),
    state: initial.state,
    outpoint: initial.outpoint,
    actionSequence: initial.actionSequence,
    height: initial.height,
    blockHash: initial.blockHash,
  });
  t.after(() => store.close());
  const client = chain({ tips: [asRemote(initial)] });
  let scans = 0;
  const synchronize = createV2FixtureOnlyCanonicalHistorySynchronizer(baseOptions({
    store,
    chainClient: client,
    scanRecoveryStream: async function* () { scans += 1; },
  }));

  const result = await synchronize(request());
  assert.deepEqual(result, initial);
  assert.equal(scans, 0);
  assert.deepEqual(client.calls, [['tip', 0]]);
});

test('[unit-only] stale caller tip fails before any provider read or scan', async () => {
  const local = asLocal();
  const target = recordingStore(local);
  const client = chain({ tips: [asRemote(local)] });
  let scans = 0;
  const synchronize = createV2FixtureOnlyCanonicalHistorySynchronizer(baseOptions({
    store: target.store,
    chainClient: client,
    scanRecoveryStream: async function* () { scans += 1; },
  }));
  const stale = asLocal({
    txid: hash('9'),
    height: local.height + 1,
    blockHash: hash('8'),
  });
  await assert.rejects(
    synchronize(request(null, 'prepare', stale)),
    (error) =>
      error instanceof V2CanonicalHistorySyncError
      && error.code === 'CANONICAL_LOCAL_RACE'
      && error.recoverable === true,
  );
  assert.equal(scans, 0);
  assert.deepEqual(client.calls, []);
  assert.deepEqual(target.canonical(), local);
});

test('[unit-only] contiguous multi-page scan rechecks the terminal tip before one atomic install', async () => {
  const local = asLocal();
  const terminal = asLocal({
    state: Buffer.alloc(128, 0x66), txid: hash('6'), actionSequence: 2,
    height: 102, blockHash: hash('7'),
  });
  const remote = asRemote(terminal);
  const pages = [
    page({
      remote, actionCount: 2, pageStartIndex: 0, nextCursor: 'next',
      actions: [{ action: 'action-0', funding: 'funding-0' }],
    }),
    page({
      remote, actionCount: 2, pageStartIndex: 1, nextCursor: null,
      actions: [{ action: 'action-1', funding: 'funding-1' }],
    }),
  ];
  const observed = [];
  const target = recordingStore(local, { scannerTerminal: terminal });
  const client = chain({ pages, tips: [remote, remote] });
  const synchronize = createV2FixtureOnlyCanonicalHistorySynchronizer(baseOptions({
    store: target.store,
    chainClient: client,
    scanRecoveryStream: (value) => scannerFrames({ steps: value.steps, capture: observed }),
  }));

  assert.deepEqual(await synchronize(request()), terminal);
  assert.deepEqual(observed, [
    { action: { rawTransaction: 'action-0' }, fundingPrevout: { rawTransaction: 'funding-0' } },
    { action: { rawTransaction: 'action-1' }, fundingPrevout: { rawTransaction: 'funding-1' } },
  ]);
  assert.deepEqual(target.calls.map(([name]) => name), ['install', 'frame']);
  assert.deepEqual(
    client.calls.map(([name]) => name),
    ['tip', 'funding', 'page', 'page', 'tip', 'funding'],
  );
});

test('[unit-only] two funding wallets aggregate their exact-tip inventories', async () => {
  const local = asLocal();
  const terminal = asLocal({
    state: Buffer.alloc(128, 0x66),
    txid: hash('6'),
    actionSequence: 1,
    height: 101,
    blockHash: hash('7'),
  });
  const remote = asRemote(terminal);
  const wallets = Object.freeze([FUNDING_WALLET, SECOND_FUNDING_WALLET]);
  const firstUtxo = Object.freeze({
    txid: hash('a'),
    vout: 0,
    valueSats: '1000',
    lockingBytecodeHex: FUNDING_LOCK,
    token: null,
  });
  const secondUtxo = Object.freeze({
    txid: hash('b'),
    vout: 1,
    valueSats: '2000',
    lockingBytecodeHex: SECOND_FUNDING_LOCK,
    token: null,
  });
  const target = recordingStore(local, { scannerTerminal: terminal });
  const client = chain({
    pages: [page({
      remote,
      actionCount: 1,
      pageStartIndex: 0,
      nextCursor: null,
      actions: [{ action: 'action-0', funding: 'funding-0' }],
    })],
    tips: [remote, remote],
    fundingObservations: [
      fundingObservation(remote, [firstUtxo], FUNDING_WALLET),
      fundingObservation(remote, [secondUtxo], SECOND_FUNDING_WALLET),
      fundingObservation(remote, [firstUtxo], FUNDING_WALLET),
      fundingObservation(remote, [secondUtxo], SECOND_FUNDING_WALLET),
    ],
  });
  const synchronize = createV2FixtureOnlyCanonicalHistorySynchronizer(baseOptions({
    store: target.store,
    chainClient: client,
    fundingWallets: wallets,
    scanRecoveryStream: (value) => scannerFrames({ steps: value.steps, capture: [] }),
  }));

  assert.deepEqual(await synchronize(request()), terminal);
  assert.deepEqual(target.calls[0], ['install', [
    { txid: Buffer.from(firstUtxo.txid, 'hex'), vout: 0, valueSats: '1000' },
    { txid: Buffer.from(secondUtxo.txid, 'hex'), vout: 1, valueSats: '2000' },
  ]]);
  assert.deepEqual(
    client.calls.filter(([name]) => name === 'funding').map(([, , input]) => input),
    [
      { cashAddress: FUNDING_ADDRESS, instanceId: INSTANCE_ID, lockingBytecodeHex: FUNDING_LOCK },
      { cashAddress: SECOND_FUNDING_ADDRESS, instanceId: INSTANCE_ID, lockingBytecodeHex: SECOND_FUNDING_LOCK },
      { cashAddress: FUNDING_ADDRESS, instanceId: INSTANCE_ID, lockingBytecodeHex: FUNDING_LOCK },
      { cashAddress: SECOND_FUNDING_ADDRESS, instanceId: INSTANCE_ID, lockingBytecodeHex: SECOND_FUNDING_LOCK },
    ],
  );
});

test('[unit-only] a funding-wallet tip mismatch rejects before history pagination or install', async () => {
  const local = asLocal();
  const terminal = asLocal({
    state: Buffer.alloc(128, 0x66),
    txid: hash('6'),
    actionSequence: 1,
    height: 101,
    blockHash: hash('7'),
  });
  const remote = asRemote(terminal);
  const target = recordingStore(local, { scannerTerminal: terminal });
  const client = chain({
    tips: [remote],
    fundingObservations: [
      fundingObservation(remote, [], FUNDING_WALLET),
      fundingObservation({ ...remote, txid: hash('9') }, [], SECOND_FUNDING_WALLET),
    ],
  });
  let scans = 0;
  const synchronize = createV2FixtureOnlyCanonicalHistorySynchronizer(baseOptions({
    store: target.store,
    chainClient: client,
    fundingWallets: Object.freeze([FUNDING_WALLET, SECOND_FUNDING_WALLET]),
    scanRecoveryStream: async function* () { scans += 1; },
  }));

  await assert.rejects(
    synchronize(request()),
    (error) =>
      error instanceof V2CanonicalHistorySyncError
      && error.code === 'CANONICAL_FUNDING_INVENTORY_RACE'
      && error.recoverable === true,
  );
  assert.equal(scans, 0);
  assert.deepEqual(target.calls, []);
  assert.deepEqual(client.calls.map(([name]) => name), ['tip', 'funding', 'funding']);
  assert.deepEqual(target.canonical(), local);
});

test('[unit-only] a duplicate outpoint across funding wallets rejects before install', async () => {
  const local = asLocal();
  const terminal = asLocal({
    state: Buffer.alloc(128, 0x66),
    txid: hash('6'),
    actionSequence: 1,
    height: 101,
    blockHash: hash('7'),
  });
  const remote = asRemote(terminal);
  const duplicate = Object.freeze({
    txid: hash('a'),
    vout: 0,
    valueSats: '1000',
    lockingBytecodeHex: FUNDING_LOCK,
    token: null,
  });
  const target = recordingStore(local, { scannerTerminal: terminal });
  const client = chain({
    pages: [page({
      remote,
      actionCount: 1,
      pageStartIndex: 0,
      nextCursor: null,
      actions: [{ action: 'action-0', funding: 'funding-0' }],
    })],
    tips: [remote],
    fundingObservations: [
      fundingObservation(remote, [duplicate], FUNDING_WALLET),
      fundingObservation(remote, [duplicate], SECOND_FUNDING_WALLET),
    ],
  });
  let scans = 0;
  const synchronize = createV2FixtureOnlyCanonicalHistorySynchronizer(baseOptions({
    store: target.store,
    chainClient: client,
    fundingWallets: Object.freeze([FUNDING_WALLET, SECOND_FUNDING_WALLET]),
    scanRecoveryStream: async function* () { scans += 1; },
  }));

  await assert.rejects(
    synchronize(request()),
    (error) =>
      error instanceof V2CanonicalHistorySyncError
      && error.code === 'CANONICAL_FUNDING_INVENTORY_INVALID',
  );
  assert.equal(scans, 0);
  assert.deepEqual(target.calls, []);
  assert.deepEqual(client.calls.map(([name]) => name), ['tip', 'funding', 'funding', 'page']);
  assert.deepEqual(target.canonical(), local);
});

test('[unit-only] duplicate funding-wallet identity rejects during synchronizer construction', () => {
  const local = asLocal();
  const target = recordingStore(local);
  const client = chain({ tips: [asRemote(local)] });
  assert.throws(
    () => createV2FixtureOnlyCanonicalHistorySynchronizer(baseOptions({
      store: target.store,
      chainClient: client,
      fundingWallets: Object.freeze([FUNDING_WALLET, FUNDING_WALLET]),
      scanRecoveryStream: async function* () {},
    })),
    (error) =>
      error instanceof V2CanonicalHistorySyncError
      && error.code === 'CANONICAL_HISTORY_INVALID'
      && /unique canonical Chipnet P2PKH addresses/.test(error.message),
  );
  assert.deepEqual(client.calls, []);
  assert.deepEqual(target.canonical(), local);
});

test('[unit-only] history page identity, cursor cycles, and terminal-tip races reject before changing state', async (t) => {
  const terminal = asLocal({
    state: Buffer.alloc(128, 0x66), txid: hash('6'), actionSequence: 2,
    height: 102, blockHash: hash('7'),
  });
  const remote = asRemote(terminal);
  const cases = [
    {
      name: 'page identity drift',
      pages: [
        page({ remote, actionCount: 2, pageStartIndex: 0, nextCursor: 'next', actions: [{ action: 'a0', funding: 'f0' }] }),
        page({ remote, actionCount: 2, pageStartIndex: 1, nextCursor: null, snapshotId: hash('e'), actions: [{ action: 'a1', funding: 'f1' }] }),
      ],
      tips: [remote],
      code: 'CANONICAL_HISTORY_PAGE_DRIFT',
    },
    {
      name: 'cursor cycle',
      pages: [
        page({ remote, actionCount: 3, pageStartIndex: 0, nextCursor: 'next', actions: [{ action: 'a0', funding: 'f0' }] }),
        page({ remote, actionCount: 3, pageStartIndex: 1, nextCursor: 'next', actions: [{ action: 'a1', funding: 'f1' }] }),
      ],
      tips: [remote],
      code: 'CANONICAL_HISTORY_CURSOR_CYCLE',
    },
    {
      name: 'terminal tip race',
      pages: [
        page({
          remote, actionCount: 2, pageStartIndex: 0, nextCursor: null,
          actions: [{ action: 'a0', funding: 'f0' }, { action: 'a1', funding: 'f1' }],
        }),
      ],
      tips: [remote, { ...remote, txid: hash('9') }],
      code: 'CANONICAL_HISTORY_RACE',
    },
  ];
  for (const scenario of cases) await t.test(scenario.name, async () => {
    const local = asLocal();
    const target = recordingStore(local, { scannerTerminal: terminal });
    const client = chain({ pages: scenario.pages, tips: scenario.tips });
    const synchronize = createV2FixtureOnlyCanonicalHistorySynchronizer(baseOptions({
      store: target.store,
      chainClient: client,
      scanRecoveryStream: (value) => scannerFrames({ steps: value.steps, capture: [] }),
    }));
    await assert.rejects(
      synchronize(request()),
      (error) => error instanceof V2CanonicalHistorySyncError && error.code === scenario.code,
    );
    assert.deepEqual(target.canonical(), local);
  });
});

test('[unit-only] funding inventory drift during a history stream rejects before the atomic switch', async () => {
  const local = asLocal();
  const terminal = asLocal({
    state: Buffer.alloc(128, 0x66),
    txid: hash('6'),
    actionSequence: 1,
    height: 101,
    blockHash: hash('7'),
  });
  const remote = asRemote(terminal);
  const target = recordingStore(local, { scannerTerminal: terminal });
  const client = chain({
    pages: [page({
      remote,
      actionCount: 1,
      pageStartIndex: 0,
      nextCursor: null,
      actions: [{ action: 'action-0', funding: 'funding-0' }],
    })],
    tips: [remote, remote],
    fundingObservations: [
      fundingObservation(remote),
      fundingObservation(remote, [{
        txid: hash('a'),
        vout: 0,
        valueSats: '1000',
        lockingBytecodeHex: FUNDING_LOCK,
        token: null,
      }]),
    ],
  });
  const synchronize = createV2FixtureOnlyCanonicalHistorySynchronizer(baseOptions({
    store: target.store,
    chainClient: client,
    scanRecoveryStream: (value) =>
      scannerFrames({ steps: value.steps, capture: [] }),
  }));
  await assert.rejects(
    synchronize(request()),
    (error) =>
      error instanceof V2CanonicalHistorySyncError
      && error.code === 'CANONICAL_FUNDING_INVENTORY_RACE',
  );
  assert.deepEqual(target.canonical(), local);
});

test('[unit-only] a pending operation becomes CANONICAL_TIP_CHANGED before any scan', async () => {
  const local = asLocal();
  const changed = asRemote(asLocal({ txid: hash('8'), height: 101, blockHash: hash('9') }));
  const operations = new Map([['pending-1', Object.freeze({ journalState: 'signed' })]]);
  const target = recordingStore(local, { operations });
  const client = chain({ tips: [changed] });
  let scans = 0;
  const synchronize = createV2FixtureOnlyCanonicalHistorySynchronizer(baseOptions({
    store: target.store,
    chainClient: client,
    scanRecoveryStream: async function* () { scans += 1; },
  }));
  await assert.rejects(
    synchronize(request('pending-1')),
    (error) => error instanceof V2CanonicalHistorySyncError && error.code === 'CANONICAL_TIP_CHANGED',
  );
  assert.equal(scans, 0);
  assert.deepEqual(target.canonical(), local);
});

test('[unit-only] a confirmed own action applies only after exact raw-byte and state agreement', async (t) => {
  const local = asLocal();
  const { packet, raw, parsed, transition } = depositPacketAndTransaction();
  const postState = encodeStateNftCommitment(transition.state, stateContext);
  const remote = asRemote(asLocal({
    state: postState,
    txid: parsed.txid,
    vout: 0,
    actionSequence: 1,
    height: 101,
    blockHash: hash('8'),
  }));
  const operation = Object.freeze({
    operationId: 'own-deposit',
    journalState: 'broadcast',
    packet,
    signedTx: raw,
    kind: 'deposit',
    expectedState: local.state,
    expectedOutpoint: local.outpoint,
    expectedActionSequence: 0,
    intent: Object.freeze({
      funding: Object.freeze({ txid: hash('f'), vout: 0 }),
      selectedNoteId: null,
    }),
  });
  const scenarios = [
    { name: 'exact match', remote, raw: raw.toString('hex'), code: null, applies: 1 },
    { name: 'raw mismatch', remote, raw: '00', code: 'CANONICAL_HISTORY_DIVERGENT_TRANSACTION', applies: 0 },
    {
      name: 'state mismatch',
      remote: { ...remote, state: initialState().toString('hex') },
      raw: raw.toString('hex'),
      code: 'CANONICAL_HISTORY_DIVERGENT_TRANSACTION',
      applies: 0,
    },
  ];
  for (const scenario of scenarios) await t.test(scenario.name, async () => {
    const target = recordingStore(local, { operations: new Map([[operation.operationId, operation]]) });
    const client = chain({
      tips: [scenario.remote],
      rawByTxid: new Map([[parsed.txid, scenario.raw]]),
    });
    const synchronize = createV2FixtureOnlyCanonicalHistorySynchronizer(baseOptions({
      store: target.store,
      chainClient: client,
      scanRecoveryStream: async function* () { throw new Error('must not scan own confirmation'); },
    }));
    if (scenario.code === null) {
      assert.deepEqual(await synchronize(request(operation.operationId, 'confirm')), asLocal({
        state: postState, txid: parsed.txid, actionSequence: 1, height: 101, blockHash: hash('8'),
      }));
    } else {
      await assert.rejects(
        synchronize(request(operation.operationId, 'confirm')),
        (error) => error instanceof V2CanonicalHistorySyncError && error.code === scenario.code,
      );
      assert.deepEqual(target.canonical(), local);
    }
    assert.equal(target.calls.filter(([name]) => name === 'apply').length, scenario.applies);
  });
});
