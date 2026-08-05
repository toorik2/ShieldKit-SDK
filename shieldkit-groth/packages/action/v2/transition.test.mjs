import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  constructDirectV2Output,
  deriveDirectV2Address,
  recoverDirectV2Output,
} from './notes.mjs';
import {
  applyDirectV2Transition,
  createDirectV2PoolModel,
  DIRECT_V2_DENOMINATION_SATS,
  DirectV2TransitionError,
} from './transition.mjs';

const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
const digest = (value) => createHash('sha256').update(value).digest('hex');
const profileId = digest('v2-direct-transition-profile');
const instanceId = digest('v2-direct-transition-instance');
const spendSecret = fr(3);
const incomingViewSecret = fr(4);

function rngFrom(start) {
  let next = BigInt(start);
  return {
    bytes() {
      const value = next;
      next += 1n;
      return Uint8Array.from(Buffer.from(fr(value), 'hex'));
    },
  };
}

function depositFixture(maximumLiveNotes = '4') {
  const pool = createDirectV2PoolModel({ profileId, maximumLiveNotes });
  const address = deriveDirectV2Address({
    networkId: 2,
    profileId,
    instanceId,
    spendSecret,
    incomingViewSecret,
  });
  const output = constructDirectV2Output({
    address,
    postActionSequence: '1',
    rng: rngFrom(5),
  });
  const deposit = applyDirectV2Transition({
    kind: 'deposit',
    networkId: 2,
    profileId,
    instanceId,
    denominationSats: DIRECT_V2_DENOMINATION_SATS.toString(),
    preState: pool.state,
    noteTree: pool.noteTree,
    nullifierTree: pool.nullifierTree,
    output: {
      outputNoteLeaf: output.public.outputNoteLeaf,
      encryptedRecord: output.public.encryptedRecord,
    },
    transactionContextHash: digest('deposit context'),
  });
  return { address, deposit, output, pool };
}

test('executes a deterministic deposit-transfer-withdrawal state chain', () => {
  const { address, deposit, output: firstOutput } = depositFixture();
  assert.deepEqual({
    noteCount: deposit.state.noteCount,
    nullifierCount: deposit.state.nullifierCount,
    reserveSats: deposit.state.reserveSats,
    actionSequence: deposit.state.actionSequence,
  }, {
    noteCount: '1',
    nullifierCount: '0',
    reserveSats: '10000000',
    actionSequence: '1',
  });
  const firstNote = recoverDirectV2Output({
    account: { address, spendSecret, incomingViewSecret },
    outputNoteLeaf: firstOutput.public.outputNoteLeaf,
    encryptedRecord: firstOutput.public.encryptedRecord,
  });
  const secondOutput = constructDirectV2Output({
    address,
    postActionSequence: '2',
    rng: rngFrom(8),
  });
  const transfer = applyDirectV2Transition({
    kind: 'transfer',
    networkId: 2,
    profileId,
    instanceId,
    denominationSats: DIRECT_V2_DENOMINATION_SATS.toString(),
    preState: deposit.state,
    noteTree: deposit.noteTree,
    nullifierTree: deposit.nullifierTree,
    spend: {
      inputNoteLeaf: firstOutput.public.outputNoteLeaf,
      noteIndex: '0',
      publicNullifier: firstNote.nullifier,
    },
    output: {
      outputNoteLeaf: secondOutput.public.outputNoteLeaf,
      encryptedRecord: secondOutput.public.encryptedRecord,
    },
    transactionContextHash: digest('transfer context'),
  });
  assert.deepEqual({
    noteCount: transfer.state.noteCount,
    nullifierCount: transfer.state.nullifierCount,
    reserveSats: transfer.state.reserveSats,
    actionSequence: transfer.state.actionSequence,
  }, {
    noteCount: '2',
    nullifierCount: '1',
    reserveSats: '10000000',
    actionSequence: '2',
  });
  const secondNote = recoverDirectV2Output({
    account: { address, spendSecret, incomingViewSecret },
    outputNoteLeaf: secondOutput.public.outputNoteLeaf,
    encryptedRecord: secondOutput.public.encryptedRecord,
  });
  const withdrawal = applyDirectV2Transition({
    kind: 'withdrawal',
    networkId: 2,
    profileId,
    instanceId,
    denominationSats: DIRECT_V2_DENOMINATION_SATS.toString(),
    preState: transfer.state,
    noteTree: transfer.noteTree,
    nullifierTree: transfer.nullifierTree,
    spend: {
      inputNoteLeaf: secondOutput.public.outputNoteLeaf,
      noteIndex: '1',
      publicNullifier: secondNote.nullifier,
    },
    withdrawalLockingBytecodeHash: digest('withdrawal lock'),
    transactionContextHash: digest('withdrawal context'),
  });
  assert.deepEqual({
    noteCount: withdrawal.state.noteCount,
    nullifierCount: withdrawal.state.nullifierCount,
    reserveSats: withdrawal.state.reserveSats,
    actionSequence: withdrawal.state.actionSequence,
  }, {
    noteCount: '2',
    nullifierCount: '2',
    reserveSats: '0',
    actionSequence: '3',
  });
  assert.equal(withdrawal.state.noteRoot, transfer.state.noteRoot);
  for (const result of [deposit, transfer, withdrawal]) {
    assert.equal(result.packet.length, 552);
    assert.match(result.packetDigest, /^[0-9a-f]{64}$/);
    assert.equal(result.publicInputs.length, 2);
  }
});

test('rejects capacity, duplicate nullifiers, bad membership, and exact-post drift', () => {
  const { deposit, output } = depositFixture('1');
  const secondOutput = { ...output.public, encryptedRecord: new Uint8Array(output.public.encryptedRecord) };
  assert.throws(
    () => applyDirectV2Transition({
      kind: 'deposit',
      networkId: 2,
      profileId,
      instanceId,
      denominationSats: DIRECT_V2_DENOMINATION_SATS.toString(),
      preState: deposit.state,
      noteTree: deposit.noteTree,
      nullifierTree: deposit.nullifierTree,
      output: {
        outputNoteLeaf: secondOutput.outputNoteLeaf,
        encryptedRecord: secondOutput.encryptedRecord,
      },
      transactionContextHash: digest('second deposit'),
    }),
    /maximumLiveNotes/,
  );

  const { address } = depositFixture();
  const firstNote = recoverDirectV2Output({
    account: { address, spendSecret, incomingViewSecret },
    outputNoteLeaf: output.public.outputNoteLeaf,
    encryptedRecord: output.public.encryptedRecord,
  });
  const nextOutput = constructDirectV2Output({
    address,
    postActionSequence: '2',
    rng: rngFrom(8),
  });
  const transferInput = {
    kind: 'transfer',
    networkId: 2,
    profileId,
    instanceId,
    denominationSats: DIRECT_V2_DENOMINATION_SATS.toString(),
    preState: deposit.state,
    noteTree: deposit.noteTree,
    nullifierTree: deposit.nullifierTree,
    spend: {
      inputNoteLeaf: output.public.outputNoteLeaf,
      noteIndex: '0',
      publicNullifier: firstNote.nullifier,
    },
    output: {
      outputNoteLeaf: nextOutput.public.outputNoteLeaf,
      encryptedRecord: nextOutput.public.encryptedRecord,
    },
    transactionContextHash: digest('first transfer context'),
  };
  const transfer = applyDirectV2Transition(transferInput);
  const thirdOutput = constructDirectV2Output({
    address,
    postActionSequence: '3',
    rng: rngFrom(11),
  });
  assert.throws(
    () => applyDirectV2Transition({
      ...transferInput,
      preState: transfer.state,
      noteTree: transfer.noteTree,
      nullifierTree: transfer.nullifierTree,
      spend: {
        inputNoteLeaf: nextOutput.public.outputNoteLeaf,
        noteIndex: '1',
        publicNullifier: firstNote.nullifier,
      },
      output: {
        outputNoteLeaf: thirdOutput.public.outputNoteLeaf,
        encryptedRecord: thirdOutput.public.encryptedRecord,
      },
      transactionContextHash: digest('duplicate transfer context'),
    }),
    /already present/,
  );
  assert.throws(
    () => applyDirectV2Transition({
      ...transferInput,
      spend: { ...transferInput.spend, inputNoteLeaf: fr(99) },
    }),
    /membership leaf/,
  );
  assert.throws(
    () => applyDirectV2Transition({
      ...transferInput,
      expectedPostState: { ...transfer.state, actionSequence: '1' },
    }),
    DirectV2TransitionError,
  );
});
