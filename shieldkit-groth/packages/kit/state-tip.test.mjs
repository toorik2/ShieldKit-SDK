import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeTransaction, hexToBin, binToHex, encodeTransaction } from '@bitauth/libauth';

// Internal helpers re-tested via discoverStateTip with a mock rpc.
import { discoverStateTip } from './state-tip.mjs';

function revHex(hex) {
  return Buffer.from(hex, 'hex').reverse().toString('hex');
}

/** Minimal P2SH32-like lock (not real hash — unit test only). */
const STATE_LOCK = Buffer.alloc(35, 0xaa);
STATE_LOCK[0] = 0xaa;
STATE_LOCK[1] = 0x20;
const STATE_LOCK_HEX = STATE_LOCK.toString('hex');

const CATEGORY = 'af5831853433ccd226727bc508885ca472f30c10c201b34b007ee5c069944530';
const INSTANCE = 'bb27e427a13f62aac70727492c4762b8ba4fb031296de14bebb30565dbb3ce06';

function shstCommitment(instanceId, actionSequence) {
  const buf = Buffer.alloc(80);
  buf.write('SHST', 0, 4, 'ascii');
  buf[4] = 1; // version
  buf[5] = 2; // network chipnet-ish
  Buffer.from(instanceId, 'hex').copy(buf, 8);
  // stateCommitment zeros
  // actionSequence u64 le at offset 72
  buf.writeBigUInt64LE(BigInt(actionSequence), 72);
  return buf;
}

function fakeStateTx({ txid, actionSequence, valueSatoshis, spendPrev }) {
  // Build a minimal decoded-like structure via encode/decode if possible — or hand object.
  // Hand-craft transaction object for decodeTransaction roundtrip is hard; mock getHex
  // to return raw that we build with libauth encode.
  const commitment = shstCommitment(INSTANCE, actionSequence);
  const outputs = [
    {
      lockingBytecode: STATE_LOCK,
      valueSatoshis: BigInt(valueSatoshis),
      token: {
        category: hexToBin(CATEGORY),
        amount: 0n,
        nft: { capability: 'mutable', commitment },
      },
    },
  ];
  const inputs = spendPrev
    ? [{
      outpointTransactionHash: hexToBin(revHex(spendPrev.txid)),
      outpointIndex: spendPrev.vout,
      unlockingBytecode: Uint8Array.of(0x00),
      sequenceNumber: 0xffffffff,
    }]
    : [{
      outpointTransactionHash: new Uint8Array(32),
      outpointIndex: 0,
      unlockingBytecode: Uint8Array.of(0x00),
      sequenceNumber: 0xffffffff,
    }];
  const tx = {
    version: 2,
    inputs,
    outputs,
    locktime: 0,
  };
  const encoded = encodeTransaction(tx);
  if (typeof encoded === 'string') throw new Error(encoded);
  return { txid, hex: binToHex(encoded), actionSequence, valueSatoshis };
}

test('discoverStateTip listunspent prefers higher actionSequence', async () => {
  const dep = fakeStateTx({
    txid: '11'.repeat(32),
    actionSequence: 11,
    valueSatoshis: 110001080,
  });
  const wdr = fakeStateTx({
    txid: '22'.repeat(32),
    actionSequence: 12,
    valueSatoshis: 100001080,
    spendPrev: { txid: dep.txid, vout: 0 },
  });
  const byTx = { [dep.txid]: dep.hex, [wdr.txid]: wdr.hex };

  const rpc = {
    backend: 'electrum',
    _electrumCall: async (method, params) => {
      if (method === 'blockchain.transaction.get') return byTx[params[0]];
      if (method === 'blockchain.scripthash.get_history') {
        return [
          { tx_hash: dep.txid, height: 100 },
          { tx_hash: wdr.txid, height: 100 },
        ];
      }
      throw new Error(`unexpected ${method}`);
    },
    listScriptUnspent: async () => [
      // only withdraw tip live
      { txid: wdr.txid, vout: 0, sats: wdr.valueSatoshis, height: 100 },
    ],
  };

  const tip = await discoverStateTip({
    rpc,
    stateLockingBytecode: STATE_LOCK_HEX,
    stateNftCategory: CATEGORY,
    instanceId: INSTANCE,
  });
  assert.equal(tip.stateTxid, wdr.txid);
  assert.equal(tip.actionSequence, '12');
  assert.equal(tip.source, 'listunspent');
});

test('discoverStateTip history marks spent tip and keeps successor', async () => {
  const dep = fakeStateTx({
    txid: '33'.repeat(32),
    actionSequence: 11,
    valueSatoshis: 110001080,
  });
  const wdr = fakeStateTx({
    txid: '44'.repeat(32),
    actionSequence: 12,
    valueSatoshis: 100001080,
    spendPrev: { txid: dep.txid, vout: 0 },
  });
  const byTx = { [dep.txid]: dep.hex, [wdr.txid]: wdr.hex };

  // Electrum often lists same-height txs in reverse-ish order — deposit after withdraw in array
  const rpc = {
    backend: 'electrum',
    _electrumCall: async (method, params) => {
      if (method === 'blockchain.transaction.get') return byTx[params[0]];
      if (method === 'blockchain.scripthash.get_history') {
        return [
          { tx_hash: wdr.txid, height: 200 },
          { tx_hash: dep.txid, height: 200 },
        ];
      }
      throw new Error(`unexpected ${method}`);
    },
    listScriptUnspent: async () => [], // force history path
  };

  const tip = await discoverStateTip({
    rpc,
    stateLockingBytecode: STATE_LOCK_HEX,
    stateNftCategory: CATEGORY,
    instanceId: INSTANCE,
  });
  assert.equal(tip.stateTxid, wdr.txid);
  assert.equal(tip.actionSequence, '12');
  assert.equal(tip.source, 'history');
  assert.equal(tip.unspentMatches, 1);
});

test('mempool height ranks above confirmed', async () => {
  const old = fakeStateTx({
    txid: '55'.repeat(32),
    actionSequence: 10,
    valueSatoshis: 100001080,
  });
  const neu = fakeStateTx({
    txid: '66'.repeat(32),
    actionSequence: 11,
    valueSatoshis: 110001080,
    spendPrev: { txid: old.txid, vout: 0 },
  });
  const byTx = { [old.txid]: old.hex, [neu.txid]: neu.hex };
  const rpc = {
    backend: 'electrum',
    _electrumCall: async (method, params) => {
      if (method === 'blockchain.transaction.get') return byTx[params[0]];
      if (method === 'blockchain.scripthash.get_history') {
        return [
          { tx_hash: old.txid, height: 300 },
          { tx_hash: neu.txid, height: -1 },
        ];
      }
      throw new Error(method);
    },
    listScriptUnspent: async () => [
      { txid: neu.txid, vout: 0, height: -1, sats: neu.valueSatoshis },
    ],
  };
  const tip = await discoverStateTip({
    rpc,
    stateLockingBytecode: STATE_LOCK_HEX,
    stateNftCategory: CATEGORY,
    instanceId: INSTANCE,
  });
  assert.equal(tip.stateTxid, neu.txid);
  assert.equal(tip.actionSequence, '11');
});
