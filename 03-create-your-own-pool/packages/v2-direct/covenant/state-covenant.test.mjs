import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  createVirtualMachineBch2026,
  encodeTransaction,
} from '@bitauth/libauth';
import {
  artifactPresent,
  createStateCovenant,
  STATE_ARTIFACT_PATH,
} from './state-covenant.mjs';
import { productBindingLock, packetUnlockFromSda2 } from './binding-state.mjs';
import { encodePoolStateV2 } from '../state.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';
import {
  NETWORK_CHIPNET, PLAYGROUND_MAXIMUM_LIVE_NOTES, DENOMINATION_SATS,
} from '../constants.mjs';

const N = 7;
const SOURCE = 10_000n;
const STATE_BASE = 10_000n;

describe('ShieldStateV2Direct CashScript covenant', () => {
  it('artifact is present in-repo (structural)', () => {
    assert.equal(artifactPresent(), true, STATE_ARTIFACT_PATH);
  });

  it('P2SH32 advance() accepts deposit on Libauth product topology (strict + loose)', async () => {
    const profileId = createHash('sha256').update('scov-p').digest('hex');
    const instanceId = createHash('sha256').update('scov-i').digest('hex');
    const bindingLock = productBindingLock();
    const cov = await createStateCovenant({
      bindingLock,
      profileId,
      instanceIdCategory: instanceId,
      stateBaseSats: STATE_BASE,
      carrierCount: N,
    });
    assert.equal(cov.lockingBytecode.length, 35);
    assert.equal(cov.lockingBytecode[0], 0xaa);
    assert.ok(cov.bytesize > 200 && cov.bytesize < 2000);

    const engine = createPoolEngineV2({
      profileId,
      instanceId,
      maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
      noteDepth: 8,
      nullifierDepth: 8,
    });
    const alice = createAccountKeys();
    const addr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
    });
    const note = freshOutputNote({
      profileId, instanceId, authority: addr.authority, postActionSequence: 1,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    const d = engine.deposit({
      outputNoteLeaf: note.outputNoteLeaf,
      encryptedRecord: note.encryptedRecord,
    });
    const preCm = encodePoolStateV2(d.preState);
    const postCm = encodePoolStateV2(d.postState);
    const category = Buffer.from(instanceId, 'hex');
    const packetUnlock = packetUnlockFromSda2(d.packet);
    const carrierLock = Buffer.from([0x51]);
    const fundLock = Buffer.from([0x51]);
    const parent = new Uint8Array(32).fill(0x44);
    const preStateValue = STATE_BASE + BigInt(d.preState.reserveSats);
    const postStateValue = STATE_BASE + BigInt(d.postState.reserveSats);
    const feeSats = 50_000n;
    const feeUtxoVal = DENOMINATION_SATS + feeSats + 546n;
    const change = feeUtxoVal - DENOMINATION_SATS - feeSats;

    const sourceOutputs = [
      ...Array.from({ length: N }, () => ({
        valueSatoshis: SOURCE,
        lockingBytecode: Uint8Array.from(carrierLock),
      })),
      {
        valueSatoshis: SOURCE,
        lockingBytecode: Uint8Array.from(bindingLock),
      },
      {
        valueSatoshis: preStateValue,
        lockingBytecode: Uint8Array.from(cov.lockingBytecode),
        token: {
          category: Uint8Array.from(category),
          amount: 0n,
          nft: { capability: 'mutable', commitment: Uint8Array.from(preCm) },
        },
      },
      {
        valueSatoshis: feeUtxoVal,
        lockingBytecode: Uint8Array.from(fundLock),
      },
    ];
    const outputs = [
      ...Array.from({ length: N }, () => ({
        valueSatoshis: SOURCE,
        lockingBytecode: Uint8Array.from(carrierLock),
      })),
      {
        valueSatoshis: SOURCE,
        lockingBytecode: Uint8Array.from(bindingLock),
      },
      {
        valueSatoshis: postStateValue,
        lockingBytecode: Uint8Array.from(cov.lockingBytecode),
        token: {
          category: Uint8Array.from(category),
          amount: 0n,
          nft: { capability: 'mutable', commitment: Uint8Array.from(postCm) },
        },
      },
      {
        valueSatoshis: change,
        lockingBytecode: Uint8Array.from(fundLock),
      },
    ];
    const transaction = {
      version: 2,
      locktime: 0,
      inputs: [
        ...Array.from({ length: N }, (_, i) => ({
          outpointTransactionHash: parent,
          outpointIndex: i,
          sequenceNumber: 0,
          unlockingBytecode: new Uint8Array(),
        })),
        {
          outpointTransactionHash: parent,
          outpointIndex: N,
          sequenceNumber: 0,
          unlockingBytecode: Uint8Array.from(packetUnlock),
        },
        {
          outpointTransactionHash: parent,
          outpointIndex: N + 1,
          sequenceNumber: 0xffffffff,
          unlockingBytecode: new Uint8Array(),
        },
        {
          outpointTransactionHash: new Uint8Array(32).fill(0x55),
          outpointIndex: 0,
          sequenceNumber: 0xffffffff,
          unlockingBytecode: new Uint8Array(),
        },
      ],
      outputs,
    };
    const unlock = await cov.generateAdvanceUnlock({
      transaction,
      sourceOutputs,
      inputIndex: N + 1,
    });
    transaction.inputs[N + 1].unlockingBytecode = Uint8Array.from(unlock);

    for (const strict of [false, true]) {
      const vm = createVirtualMachineBch2026(strict);
      const result = vm.verify({ sourceOutputs, transaction });
      assert.equal(result, true, `strict=${strict}: ${String(result)}`);
    }
    assert.ok(encodeTransaction(transaction).length > 500);
  });

  it('rejects forged post commitment via covenant', async () => {
    const profileId = createHash('sha256').update('fg-p').digest('hex');
    const instanceId = createHash('sha256').update('fg-i').digest('hex');
    const bindingLock = productBindingLock();
    const cov = await createStateCovenant({
      bindingLock, profileId, instanceIdCategory: instanceId, stateBaseSats: STATE_BASE,
    });
    const engine = createPoolEngineV2({
      profileId, instanceId, maximumLiveNotes: 32, noteDepth: 8, nullifierDepth: 8,
    });
    const alice = createAccountKeys();
    const addr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
    });
    const note = freshOutputNote({
      profileId, instanceId, authority: addr.authority, postActionSequence: 1,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    const d = engine.deposit({
      outputNoteLeaf: note.outputNoteLeaf, encryptedRecord: note.encryptedRecord,
    });
    const preCm = encodePoolStateV2(d.preState);
    const postCm = Buffer.from(encodePoolStateV2(d.postState));
    postCm[20] ^= 0xff; // forge
    const category = Buffer.from(instanceId, 'hex');
    const packetUnlock = packetUnlockFromSda2(d.packet);
    const carrierLock = Buffer.from([0x51]);
    const fundLock = Buffer.from([0x51]);
    const parent = new Uint8Array(32).fill(0x44);
    const feeUtxoVal = DENOMINATION_SATS + 50_000n + 546n;
    const sourceOutputs = [
      ...Array.from({ length: N }, () => ({
        valueSatoshis: SOURCE, lockingBytecode: Uint8Array.from(carrierLock),
      })),
      { valueSatoshis: SOURCE, lockingBytecode: Uint8Array.from(bindingLock) },
      {
        valueSatoshis: STATE_BASE,
        lockingBytecode: Uint8Array.from(cov.lockingBytecode),
        token: {
          category: Uint8Array.from(category), amount: 0n,
          nft: { capability: 'mutable', commitment: Uint8Array.from(preCm) },
        },
      },
      { valueSatoshis: feeUtxoVal, lockingBytecode: Uint8Array.from(fundLock) },
    ];
    const outputs = [
      ...Array.from({ length: N }, () => ({
        valueSatoshis: SOURCE, lockingBytecode: Uint8Array.from(carrierLock),
      })),
      { valueSatoshis: SOURCE, lockingBytecode: Uint8Array.from(bindingLock) },
      {
        valueSatoshis: STATE_BASE + DENOMINATION_SATS,
        lockingBytecode: Uint8Array.from(cov.lockingBytecode),
        token: {
          category: Uint8Array.from(category), amount: 0n,
          nft: { capability: 'mutable', commitment: Uint8Array.from(postCm) },
        },
      },
      { valueSatoshis: 546n, lockingBytecode: Uint8Array.from(fundLock) },
    ];
    const transaction = {
      version: 2, locktime: 0,
      inputs: [
        ...Array.from({ length: N }, (_, i) => ({
          outpointTransactionHash: parent, outpointIndex: i,
          sequenceNumber: 0, unlockingBytecode: new Uint8Array(),
        })),
        {
          outpointTransactionHash: parent, outpointIndex: N, sequenceNumber: 0,
          unlockingBytecode: Uint8Array.from(packetUnlock),
        },
        {
          outpointTransactionHash: parent, outpointIndex: N + 1,
          sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(),
        },
        {
          outpointTransactionHash: new Uint8Array(32).fill(0x55), outpointIndex: 0,
          sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(),
        },
      ],
      outputs,
    };
    const unlock = await cov.generateAdvanceUnlock({
      transaction, sourceOutputs, inputIndex: N + 1,
    });
    transaction.inputs[N + 1].unlockingBytecode = Uint8Array.from(unlock);
    const vm = createVirtualMachineBch2026(false);
    const result = vm.verify({ sourceOutputs, transaction });
    assert.notEqual(result, true, 'forged post must fail');
  });
});
