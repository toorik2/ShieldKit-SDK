import assert from 'node:assert/strict';
import test from 'node:test';

import {
  encodeDirectV2TransactionContext,
  validateDirectV2RoleTopology,
} from './context.mjs';
import {
  DIRECT_V2_ROLLING_BUNDLE_MODEL_SCHEMA,
  DirectV2RollingBundleError,
  validateDirectV2RollingBundle,
} from './rolling-bundle.mjs';
import { encodeStateNftCommitment } from './state.mjs';

const D = 10_000_000n;
const STATE_CONTEXT = Object.freeze({ denominationSats: D.toString() });
const role = (kind, ordinal = 0) => ({ kind, ordinal: String(ordinal) });
const p2pkh = (byte) => Uint8Array.from([
  0x76, 0xa9, 0x14, ...Array(20).fill(byte), 0x88, 0xac,
]);
const fr = (value) => BigInt(value).toString(16).padStart(64, '0');

function state(kind, post) {
  const profiles = {
    deposit: [
      ['0', '0', '0', '0'],
      ['1', '0', D.toString(), '1'],
    ],
    transfer: [
      ['1', '0', D.toString(), '1'],
      ['2', '1', D.toString(), '2'],
    ],
    withdrawal: [
      ['2', '1', D.toString(), '2'],
      ['2', '2', '0', '3'],
    ],
  };
  const [noteCount, nullifierCount, reserveSats, actionSequence] =
    profiles[kind][post ? 1 : 0];
  const noteRootChanges = kind !== 'withdrawal';
  const nullifierRootChanges = kind !== 'deposit';
  return {
    profileId: '11'.repeat(32),
    noteRoot: fr(post && noteRootChanges ? 3 : 1),
    nullifierRoot: fr(post && nullifierRootChanges ? 4 : 2),
    noteCount,
    nullifierCount,
    maximumLiveNotes: '8',
    reserveSats,
    actionSequence,
  };
}

function stateToken(commitment, overrides = {}) {
  return {
    category: '22'.repeat(32),
    amount: '0',
    nft: {
      capability: 'mutable',
      commitment,
      ...overrides.nft,
    },
    ...overrides,
  };
}

function fixture(kind = 'deposit', carrierCount = 1) {
  const preState = state(kind, false);
  const postState = state(kind, true);
  const preCommitment = encodeStateNftCommitment(preState, STATE_CONTEXT);
  const postCommitment = encodeStateNftCommitment(postState, STATE_CONTEXT);
  const parent = 'aa'.repeat(32);
  const verifierCarriers = Array.from({ length: carrierCount }, (_, index) => ({
    baseValueSats: String(1_000 + index),
    lockingBytecode: Uint8Array.of(0x51, index),
  }));
  const pins = {
    previousBundleTransactionHash: parent,
    stateBaseSats: '2000',
    stateLockingBytecode: Uint8Array.of(0x52),
    bindingBaseSats: '1500',
    bindingLockingBytecode: Uint8Array.of(0x53),
    verifierCarriers,
  };
  const sequence = '4294967295';
  const inputs = [
    ...verifierCarriers.map((pin, index) => ({
      role: role('verifier', index),
      outpointTransactionHash: parent,
      outpointIndex: String(index + 1),
      sequence,
      valueSats: pin.baseValueSats,
      lockingBytecode: pin.lockingBytecode,
      token: null,
    })),
    {
      role: role('binding'),
      outpointTransactionHash: parent,
      outpointIndex: String(carrierCount + 1),
      sequence,
      valueSats: pins.bindingBaseSats,
      lockingBytecode: pins.bindingLockingBytecode,
      token: null,
    },
    {
      role: role('state'),
      outpointTransactionHash: parent,
      outpointIndex: '0',
      sequence,
      valueSats: (2_000n + BigInt(preState.reserveSats)).toString(),
      lockingBytecode: pins.stateLockingBytecode,
      token: stateToken(preCommitment),
    },
    {
      role: role('funding'),
      outpointTransactionHash: 'bb'.repeat(32),
      outpointIndex: '7',
      sequence,
      valueSats: (5_500n + (kind === 'deposit' ? D : 0n)).toString(),
      lockingBytecode: p2pkh(0x31),
      token: null,
    },
  ];
  const outputs = [
    {
      role: role('state'),
      valueSats: (2_000n + BigInt(postState.reserveSats)).toString(),
      lockingBytecode: pins.stateLockingBytecode,
      token: stateToken(postCommitment),
    },
    ...verifierCarriers.map((pin, index) => ({
      role: role('verifier', index),
      valueSats: pin.baseValueSats,
      lockingBytecode: pin.lockingBytecode,
      token: null,
    })),
    {
      role: role('binding'),
      valueSats: pins.bindingBaseSats,
      lockingBytecode: pins.bindingLockingBytecode,
      token: null,
    },
    ...(kind === 'withdrawal' ? [{
      role: role('withdrawal'),
      valueSats: D.toString(),
      lockingBytecode: p2pkh(0x32),
      token: null,
    }] : []),
    {
      role: role('change'),
      valueSats: '5000',
      lockingBytecode: p2pkh(0x33),
      token: null,
    },
  ];
  return {
    carrierCount,
    kind,
    networkId: 2,
    profileId: '11'.repeat(32),
    instanceId: '22'.repeat(32),
    denominationSats: D.toString(),
    feeSats: '500',
    transactionVersion: '2',
    locktime: '0',
    preState,
    postState,
    pins,
    inputs,
    outputs,
  };
}

function mutate(base, change) {
  const copy = structuredClone(base);
  change(copy);
  return copy;
}

test('accepts every action at frozen carrier counts N=1 and N=7', () => {
  for (const carrierCount of [1, 7]) {
    for (const kind of ['deposit', 'transfer', 'withdrawal']) {
      const model = validateDirectV2RollingBundle(fixture(kind, carrierCount));
      assert.equal(model.schema, DIRECT_V2_ROLLING_BUNDLE_MODEL_SCHEMA);
      assert.equal(model.modelOnly, true);
      assert.deepEqual(model.claims, {
        transactionQualified: false,
        covenantQualified: false,
        bchVmQualified: false,
      });
      assert.equal(model.carrierCount, carrierCount);
      assert.equal(Object.isFrozen(model), true);
      assert.equal(Object.isFrozen(model.context), true);
      assert.equal(
        validateDirectV2RoleTopology(model.context, carrierCount).kind,
        kind,
      );
      assert.ok(
        encodeDirectV2TransactionContext(
          model.context,
          { carrierCount },
        ).length > 0,
      );
      assert.equal(
        model.context.outputs.length,
        carrierCount + (kind === 'withdrawal' ? 4 : 3),
      );
    }
  }
});

test('preserves non-palindromic instance categories in token-prefix byte order', () => {
  const instanceId =
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  const value = fixture('deposit', 1);
  value.instanceId = instanceId;
  value.inputs[2].token.category = instanceId;
  value.outputs[0].token.category = instanceId;
  const model = validateDirectV2RollingBundle(value);
  for (const prefix of [
    model.context.inputs[2].tokenPrefix,
    model.context.outputs[0].tokenPrefix,
  ]) {
    assert.equal(prefix[0], 0xef);
    assert.equal(Buffer.from(prefix.subarray(1, 33)).toString('hex'), instanceId);
  }
});

test('rejects mixed/alternate rolling parents, source indices, roles, and counts', () => {
  const base = fixture('deposit', 7);
  for (const [change, pattern] of [
    [(value) => { value.inputs[3].outpointTransactionHash = 'cc'.repeat(32); }, /previous verifier/],
    [(value) => { value.inputs[0].outpointIndex = '2'; }, /previous verifier/],
    [(value) => { value.inputs[7].outpointTransactionHash = 'cc'.repeat(32); }, /previous binding/],
    [(value) => { value.inputs[7].outpointIndex = '0'; }, /previous binding/],
    [(value) => { value.inputs[8].outpointTransactionHash = 'cc'.repeat(32); }, /previous output 0/],
    [(value) => { value.inputs[8].outpointIndex = '1'; }, /previous output 0/],
    [(value) => { value.inputs[0].role = role('binding'); }, /canonical role/],
    [(value) => { value.outputs[1].role = role('change'); }, /canonical role/],
    [(value) => { value.inputs.pop(); }, /input count/],
    [(value) => { value.outputs.splice(2, 1); }, /output count/],
  ]) {
    assert.throws(
      () => validateDirectV2RollingBundle(mutate(base, change)),
      pattern,
    );
  }
});

test('rejects carrier/binding/state lock and value drift or omitted outputs', () => {
  const base = fixture('transfer', 7);
  for (const change of [
    (value) => { value.inputs[0].lockingBytecode = Uint8Array.of(0xff); },
    (value) => { value.outputs[1].lockingBytecode = Uint8Array.of(0xff); },
    (value) => { value.inputs[0].valueSats = '999'; },
    (value) => { value.outputs[1].valueSats = '999'; },
    (value) => { value.inputs[7].valueSats = '1499'; },
    (value) => { value.outputs[8].lockingBytecode = Uint8Array.of(0xff); },
    (value) => { value.inputs[8].valueSats = '10001999'; },
    (value) => { value.outputs[0].valueSats = '10001999'; },
  ]) {
    assert.throws(
      () => validateDirectV2RollingBundle(mutate(base, change)),
      /pinned|state lock/,
    );
  }
});

test('requires one exact mutable state NFT and tokenlessness everywhere else', () => {
  const base = fixture('deposit', 1);
  for (const [change, pattern] of [
    [(value) => { value.inputs[2].token.category = '33'.repeat(32); }, /unique mutable state NFT/],
    [(value) => { value.inputs[2].token.amount = '1'; }, /unique mutable state NFT/],
    [(value) => { value.outputs[0].token.nft.capability = 'minting'; }, /unique mutable state NFT/],
    [(value) => { value.outputs[0].token.nft.commitment[0] ^= 1; }, /unique mutable state NFT/],
    [(value) => { value.inputs[0].token = stateToken(value.inputs[2].token.nft.commitment); }, /tokenless/],
    [(value) => { value.outputs[2].token = stateToken(value.outputs[0].token.nft.commitment); }, /tokenless/],
    [(value) => { value.inputs[3].token = stateToken(value.inputs[2].token.nft.commitment); }, /tokenless/],
    [(value) => { value.outputs.at(-1).token = stateToken(value.outputs[0].token.nft.commitment); }, /tokenless/],
  ]) {
    assert.throws(
      () => validateDirectV2RollingBundle(mutate(base, change)),
      pattern,
    );
  }
});

test('enforces P2PKH funding/change/payout, exact action funding, and conservation', () => {
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const base = fixture(kind, 1);
    assert.throws(
      () => validateDirectV2RollingBundle(mutate(base, (value) => {
        value.inputs[3].lockingBytecode = Uint8Array.of(0x51);
      })),
      /P2PKH/,
    );
    assert.throws(
      () => validateDirectV2RollingBundle(mutate(base, (value) => {
        value.outputs.at(-1).lockingBytecode =
          value.inputs[3].lockingBytecode;
      })),
      /fresh P2PKH/,
    );
    assert.throws(
      () => validateDirectV2RollingBundle(mutate(base, (value) => {
        value.inputs[3].valueSats =
          (BigInt(value.inputs[3].valueSats) + 1n).toString();
      })),
      /exactly fund/,
    );
  }
  const withdrawal = fixture('withdrawal', 1);
  assert.throws(
    () => validateDirectV2RollingBundle(mutate(withdrawal, (value) => {
      value.outputs[3].lockingBytecode = Uint8Array.of(0x51);
    })),
    /P2PKH/,
  );
  assert.throws(
    () => validateDirectV2RollingBundle(mutate(withdrawal, (value) => {
      value.outputs[3].valueSats = (D - 1n).toString();
    })),
    /payout/,
  );
  assert.throws(
    () => validateDirectV2RollingBundle(mutate(withdrawal, (value) => {
      [value.outputs[3], value.outputs[4]] =
        [value.outputs[4], value.outputs[3]];
    })),
    /canonical role/,
  );
});

test('rejects state/action drift, malformed carrier counts, and preparation extras', () => {
  const base = fixture('deposit', 1);
  for (const [change, pattern] of [
    [(value) => { value.postState.reserveSats = '0'; }, DirectV2RollingBundleError],
    [(value) => { value.postState.actionSequence = '2'; }, DirectV2RollingBundleError],
    [(value) => { value.postState.profileId = '33'.repeat(32); }, DirectV2RollingBundleError],
    [(value) => {
      value.postState.noteCount = '2';
      value.postState.reserveSats = (2n * D).toString();
      value.postState.actionSequence = '2';
    }, /counter delta/],
    [(value) => {
      value.postState.nullifierCount = '1';
      value.postState.reserveSats = '0';
    }, /counter delta/],
    [(value) => { value.postState.maximumLiveNotes = '9'; }, /immutable maximumLiveNotes/],
    [(value) => { value.postState.nullifierRoot = fr(99); }, /nullifier root/],
  ]) {
    assert.throws(
      () => validateDirectV2RollingBundle(mutate(base, change)),
      pattern,
    );
  }
  const withdrawal = fixture('withdrawal', 1);
  assert.throws(
    () => validateDirectV2RollingBundle(mutate(withdrawal, (value) => {
      value.postState.noteRoot = fr(99);
    })),
    /note root/,
  );
  assert.throws(
    () => validateDirectV2RollingBundle(mutate(base, (value) => {
      value.inputs.at(-1).valueSats = '2100000000000001';
    })),
    /exceeds its range/,
  );
  assert.throws(
    () => validateDirectV2RollingBundle({ ...base, carrierCount: 0 }),
    /carrierCount/,
  );
  assert.throws(
    () => validateDirectV2RollingBundle({
      ...base,
      preparation: { forbidden: true },
    }),
    /missing or unknown/,
  );
});
