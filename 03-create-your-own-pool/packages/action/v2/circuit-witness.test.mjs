import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  buildDirectV2CircuitInput,
  DirectV2CircuitWitnessError,
} from './circuit-witness.mjs';
import {
  constructDirectV2Output,
  deriveDirectV2Address,
  recoverDirectV2Output,
} from './notes.mjs';
import {
  applyDirectV2Transition,
  createDirectV2PoolModel,
} from './transition.mjs';

const digest = (value) => createHash('sha256').update(value).digest('hex');
const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
const profileId = digest('v2-circuit-witness-profile');
const instanceId = digest('v2-circuit-witness-instance');
const spendSecret = fr(3);
const incomingViewSecret = fr(4);

function rng(start) {
  let next = BigInt(start);
  return {
    bytes() {
      const value = next;
      next += 1n;
      return Buffer.from(fr(value), 'hex');
    },
  };
}

function depositFixture() {
  const pool = createDirectV2PoolModel({
    profileId,
    maximumLiveNotes: '4',
  });
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
    rng: rng(5),
  });
  const transition = applyDirectV2Transition({
    kind: 'deposit',
    networkId: 2,
    profileId,
    instanceId,
    denominationSats: '10000000',
    preState: pool.state,
    noteTree: pool.noteTree,
    nullifierTree: pool.nullifierTree,
    output: {
      outputNoteLeaf: output.public.outputNoteLeaf,
      encryptedRecord: output.public.encryptedRecord,
    },
    transactionContextHash: digest('deposit context'),
  });
  return { address, output, pool, transition };
}

test('builds exact active and fixed-inactive deposit witness fields', () => {
  const fixture = depositFixture();
  const input = buildDirectV2CircuitInput({
    denominationSats: '10000000',
    transition: fixture.transition,
    output: fixture.output,
  });
  assert.equal(input.packet.length, 552);
  assert.equal(input.noteAppendSiblings.length, 32);
  assert.equal(input.spendSk, '0');
  assert.equal(input.nullifierPredecessorType, '0');
  assert.equal(input.outputRhoBlind, '5');
  assert.equal(input.outputR, '6');
  assert.equal(input.outputEsk, '7');
  assert.ok(input.outputSpendX !== '0');
});

test('builds transfer and withdrawal inputs from recovered note material', () => {
  const first = depositFixture();
  const recoveredFirst = recoverDirectV2Output({
    account: {
      address: first.address,
      spendSecret,
      incomingViewSecret,
    },
    outputNoteLeaf: first.output.public.outputNoteLeaf,
    encryptedRecord: first.output.public.encryptedRecord,
  });
  const secondOutput = constructDirectV2Output({
    address: first.address,
    postActionSequence: '2',
    rng: rng(8),
  });
  const transfer = applyDirectV2Transition({
    kind: 'transfer',
    networkId: 2,
    profileId,
    instanceId,
    denominationSats: '10000000',
    preState: first.transition.state,
    noteTree: first.transition.noteTree,
    nullifierTree: first.transition.nullifierTree,
    spend: {
      inputNoteLeaf: first.output.public.outputNoteLeaf,
      noteIndex: '0',
      publicNullifier: recoveredFirst.nullifier,
    },
    output: {
      outputNoteLeaf: secondOutput.public.outputNoteLeaf,
      encryptedRecord: secondOutput.public.encryptedRecord,
    },
    transactionContextHash: digest('transfer context'),
  });
  const transferInput = buildDirectV2CircuitInput({
    denominationSats: '10000000',
    transition: transfer,
    spend: {
      spendSecret,
      incomingViewPublicKey: first.address.incomingViewPublicKey,
      rho: recoveredFirst.rho,
      r: recoveredFirst.r,
      encryptedRecord: recoveredFirst.encryptedRecord,
    },
    output: secondOutput,
  });
  assert.equal(transferInput.spendSk, '3');
  assert.equal(
    BigInt(transferInput.spendRecordTag).toString(16).padStart(64, '0'),
    Buffer.from(recoveredFirst.encryptedRecord).subarray(96).toString('hex'),
  );
  assert.equal(transferInput.spendNoteIndex, '0');
  assert.equal(transferInput.nullifierPredecessorType, '1');
  assert.equal(transferInput.outputRhoBlind, '8');

  const recoveredSecond = recoverDirectV2Output({
    account: {
      address: first.address,
      spendSecret,
      incomingViewSecret,
    },
    outputNoteLeaf: secondOutput.public.outputNoteLeaf,
    encryptedRecord: secondOutput.public.encryptedRecord,
  });
  const withdrawal = applyDirectV2Transition({
    kind: 'withdrawal',
    networkId: 2,
    profileId,
    instanceId,
    denominationSats: '10000000',
    preState: transfer.state,
    noteTree: transfer.noteTree,
    nullifierTree: transfer.nullifierTree,
    spend: {
      inputNoteLeaf: secondOutput.public.outputNoteLeaf,
      noteIndex: '1',
      publicNullifier: recoveredSecond.nullifier,
    },
    withdrawalLockingBytecodeHash: digest('withdrawal lock'),
    transactionContextHash: digest('withdrawal context'),
  });
  const withdrawalInput = buildDirectV2CircuitInput({
    denominationSats: '10000000',
    transition: withdrawal,
    spend: {
      spendSecret,
      incomingViewPublicKey: first.address.incomingViewPublicKey,
      rho: recoveredSecond.rho,
      r: recoveredSecond.r,
      encryptedRecord: recoveredSecond.encryptedRecord,
    },
  });
  assert.equal(withdrawalInput.outputEsk, '0');
  assert.deepEqual(withdrawalInput.noteAppendSiblings, Array(32).fill('0'));
  assert.equal(withdrawalInput.spendNoteIndex, '1');
});

test('rejects packet/public-input drift and missing branch witnesses', () => {
  const fixture = depositFixture();
  assert.throws(
    () => buildDirectV2CircuitInput({
      denominationSats: '10000000',
      transition: fixture.transition,
    }),
    DirectV2CircuitWitnessError,
  );
  assert.throws(
    () => buildDirectV2CircuitInput({
      denominationSats: '10000000',
      transition: {
        ...fixture.transition,
        publicInputs: ['0', fixture.transition.publicInputs[1]],
      },
      output: fixture.output,
    }),
    /public input 0/,
  );
  const wrongOutput = {
    ...fixture.output,
    public: {
      ...fixture.output.public,
      encryptedRecord: new Uint8Array(128),
    },
  };
  assert.throws(
    () => buildDirectV2CircuitInput({
      denominationSats: '10000000',
      transition: fixture.transition,
      output: wrongOutput,
    }),
    /does not match/,
  );
});
