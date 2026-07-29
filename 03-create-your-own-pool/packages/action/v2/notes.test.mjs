import assert from 'node:assert/strict';
import test from 'node:test';

import {
  constructDirectV2Output,
  deriveDirectV2Address,
  deriveDirectV2NoteCommitment,
  deriveDirectV2Rho,
  DirectV2NoteError,
  recoverDirectV2Output,
  validateDirectV2Address,
  validateDirectV2OutputConstruction,
} from './notes.mjs';
import { BN254_SCALAR_FIELD_MODULUS } from './domains.mjs';
import { BABYJUB_SUBGROUP_ORDER } from '../../recover/portable-core.mjs';

const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
const profileId = '11'.repeat(32);
const instanceId = '22'.repeat(32);
const spendSecret = fr(3);
const incomingViewSecret = fr(4);

function fixedRng(values = [5n, 6n, 7n]) {
  const remaining = [...values];
  return {
    bytes(length) {
      assert.equal(length, 32);
      if (remaining.length === 0) throw new Error('fixed CSPRNG exhausted');
      return Uint8Array.from(Buffer.from(fr(remaining.shift()), 'hex'));
    },
  };
}

function fixture() {
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
    rng: fixedRng(),
  });
  const account = Object.freeze({ address, spendSecret, incomingViewSecret });
  return { account, address, output };
}

function copyOutput(output) {
  return {
    public: {
      ...output.public,
      encryptedRecord: new Uint8Array(output.public.encryptedRecord),
    },
    witness: { ...output.witness },
  };
}

function expectOutputError(code, action, label) {
  assert.throws(
    action,
    (error) => error instanceof DirectV2NoteError && error.code === code,
    label,
  );
}

test('pins the complete address, ECDH record, note, leaf, and nullifier vector', () => {
  const { account, address, output } = fixture();
  assert.deepEqual(address, {
    schema: 'shieldkit-address-v2-direct',
    networkId: 2,
    profileId,
    instanceId,
    spendPublicKey: '957cfd431b63e4a96bf4f3ef71dfb4c19c31f98958f2944495ae95220e6fd621',
    incomingViewPublicKey: 'dc4f6bf477ec17e8f19442c6730e701caaa89050edc595280d3155e00beed782',
    authority: '0dc9831817e6c520d9a38d14c88e91d930a1f33179ac917b52f39bb83e125bbd',
  });
  assert.deepEqual({
    noteCommitment: output.public.noteCommitment,
    outputNoteLeaf: output.public.outputNoteLeaf,
    encryptedRecord: Buffer.from(output.public.encryptedRecord).toString('hex'),
    rho: output.witness.rho,
    rhoBlind: output.witness.rhoBlind,
    r: output.witness.r,
    ephemeralScalar: output.witness.ephemeralScalar,
  }, {
    noteCommitment: '0d0f3580dd8101f05cdc4b07f17d3ce38ef23b4cdacac540cc912a4682fc3723',
    outputNoteLeaf: '063b2fb6fc17fff7200daefe163121f26bcf2fe1e79a33a2f7a81c3743a7ee28',
    encryptedRecord: '210f9eb1f917b8d07a49ba0f326ad4a058663b2b9ac7d1126e5f26f65d67c79a1ddabf2d7cdb587f50cdff2c24d9746dca2c329969b1085b3e63e55638bc9b4604775026554dac6457dfac915f510b27c67f93be2a78e5611e5ae2a2e6793b792829b5e0ebdf1c35bf199eb27d97fec9f9eb917bb70e1b8df78e9ae906519a96',
    rho: '08b1cb9269cf911ed0bdf63ab77da6fbeb09042d8a4bfe27b78000091d514783',
    rhoBlind: fr(5),
    r: fr(6),
    ephemeralScalar: fr(7),
  });
  const recovered = recoverDirectV2Output({
    account,
    outputNoteLeaf: output.public.outputNoteLeaf,
    encryptedRecord: output.public.encryptedRecord,
  });
  assert.deepEqual({
    authority: recovered.authority,
    rho: recovered.rho,
    r: recovered.r,
    noteCommitment: recovered.noteCommitment,
    nullifier: recovered.nullifier,
    outputNoteLeaf: recovered.outputNoteLeaf,
  }, {
    authority: address.authority,
    rho: output.witness.rho,
    r: fr(6),
    noteCommitment: output.public.noteCommitment,
    nullifier: '05862a6bb1b9f827f3283df7006a3db2a0e449e27e239c13856107cfd4fe4630',
    outputNoteLeaf: output.public.outputNoteLeaf,
  });
});

test('a sender constructs an output from public address data only', () => {
  const { address } = fixture();
  assert.deepEqual(Object.keys(address).sort(), [
    'authority',
    'incomingViewPublicKey',
    'instanceId',
    'networkId',
    'profileId',
    'schema',
    'spendPublicKey',
  ]);
  const first = constructDirectV2Output({
    address,
    postActionSequence: '1',
    rng: fixedRng(),
  });
  const second = constructDirectV2Output({
    address,
    postActionSequence: '2',
    rng: fixedRng(),
  });
  assert.notEqual(first.witness.rho, second.witness.rho);
  assert.notEqual(first.public.noteCommitment, second.public.noteCommitment);
  assert.notEqual(first.public.outputNoteLeaf, second.public.outputNoteLeaf);
});

test('every encrypted-record byte is authenticated and the tag is leaf-bound', () => {
  const { account, output } = fixture();
  for (let offset = 0; offset < output.public.encryptedRecord.length; offset += 1) {
    const mutated = new Uint8Array(output.public.encryptedRecord);
    mutated[offset] ^= 1;
    assert.throws(
      () => recoverDirectV2Output({
        account,
        outputNoteLeaf: output.public.outputNoteLeaf,
        encryptedRecord: mutated,
      }),
      DirectV2NoteError,
      `record byte ${offset}`,
    );
  }
  const wrongLeaf = `${output.public.outputNoteLeaf.slice(0, -2)}ad`;
  assert.throws(
    () => recoverDirectV2Output({
      account,
      outputNoteLeaf: wrongLeaf,
      encryptedRecord: output.public.encryptedRecord,
    }),
    /outputNoteLeaf/,
  );
});

test('rejects malformed addresses, wrong accounts, noncanonical records, and zero randomness', () => {
  const { account, address, output } = fixture();
  assert.throws(
    () => validateDirectV2Address({ ...address, authority: fr(9) }),
    /authority/,
  );
  assert.throws(
    () => validateDirectV2Address({ ...address, extra: true }),
    /unknown properties/,
  );
  assert.throws(
    () => recoverDirectV2Output({
      account: { ...account, incomingViewSecret: fr(8) },
      outputNoteLeaf: output.public.outputNoteLeaf,
      encryptedRecord: output.public.encryptedRecord,
    }),
    /secrets do not match/,
  );
  const noncanonical = new Uint8Array(output.public.encryptedRecord);
  noncanonical.fill(0xff, 32, 64);
  assert.throws(
    () => recoverDirectV2Output({
      account,
      outputNoteLeaf: output.public.outputNoteLeaf,
      encryptedRecord: noncanonical,
    }),
    /noncanonical/,
  );
  assert.throws(
    () => deriveDirectV2Rho({
      profileId,
      instanceId,
      postActionSequence: '1',
      rhoBlind: fr(0),
    }),
    /nonzero/,
  );
  assert.throws(
    () => deriveDirectV2NoteCommitment({
      profileId,
      instanceId,
      authority: address.authority,
      rho: output.witness.rho,
      r: fr(0),
    }),
    /nonzero/,
  );
  assert.throws(
    () => constructDirectV2Output({
      address,
      postActionSequence: '1',
      rng: { bytes: () => new Uint8Array(31) },
    }),
    /invalid byte string/,
  );
});

test('Q-05 rejects valid-looking foreign output recovery (Faerie-style recipient resistance)', () => {
  const { account, address } = fixture();
  const foreignAddress = deriveDirectV2Address({
    networkId: 2,
    profileId,
    instanceId,
    spendSecret: fr(9),
    incomingViewSecret: fr(10),
  });
  const foreignOutput = constructDirectV2Output({
    address: foreignAddress,
    postActionSequence: '1',
    rng: fixedRng(),
  });
  assert.throws(
    () => recoverDirectV2Output({
      account,
      outputNoteLeaf: foreignOutput.public.outputNoteLeaf,
      encryptedRecord: foreignOutput.public.encryptedRecord,
    }),
    /authentication/,
  );
  const repeated = constructDirectV2Output({
    address,
    postActionSequence: '1',
    rng: fixedRng(),
  });
  const first = constructDirectV2Output({
    address,
    postActionSequence: '1',
    rng: fixedRng(),
  });
  assert.equal(repeated.public.noteCommitment, first.public.noteCommitment);
  assert.equal(repeated.public.outputNoteLeaf, first.public.outputNoteLeaf);
  assert.deepEqual(repeated.public.encryptedRecord, first.public.encryptedRecord);
});

test('validates a complete V2 output construction round trip for its exact successor', () => {
  const { address, output } = fixture();
  const validated = validateDirectV2OutputConstruction({
    address,
    postActionSequence: '1',
    output,
  });
  assert.deepEqual(validated, output);
  assert.notEqual(validated.public.encryptedRecord, output.public.encryptedRecord);
});

test('rejects recipient, sequence, witness, commitment, record, and leaf mutations before proof', () => {
  const { address, output } = fixture();
  const validate = (candidate, sequence = '1') => validateDirectV2OutputConstruction({
    address,
    postActionSequence: sequence,
    output: candidate,
  });
  const foreignAddress = deriveDirectV2Address({
    networkId: 2,
    profileId,
    instanceId,
    spendSecret: fr(9),
    incomingViewSecret: fr(10),
  });

  for (const field of ['authority', 'spendPublicKey', 'incomingViewPublicKey']) {
    const mutated = copyOutput(output);
    mutated.witness[field] = foreignAddress[field];
    expectOutputError('OUTPUT_RECIPIENT_MISMATCH', () => validate(mutated), field);
  }

  // A construct made for sequence 1 cannot enter a proof path for sequence 2.
  expectOutputError('OUTPUT_SEQUENCE_MISMATCH', () => validate(output, '2'), 'stale sequence');

  const rhoMutated = copyOutput(output);
  rhoMutated.witness.rho = deriveDirectV2Rho({
    profileId,
    instanceId,
    postActionSequence: '2',
    rhoBlind: output.witness.rhoBlind,
  }).toString(16).padStart(64, '0');
  expectOutputError('OUTPUT_SEQUENCE_MISMATCH', () => validate(rhoMutated), 'rho');

  const rhoBlindMutated = copyOutput(output);
  rhoBlindMutated.witness.rhoBlind = fr(8);
  expectOutputError('OUTPUT_SEQUENCE_MISMATCH', () => validate(rhoBlindMutated), 'rhoBlind');

  const rMutated = copyOutput(output);
  rMutated.witness.r = fr(8);
  expectOutputError('OUTPUT_COMMITMENT_MISMATCH', () => validate(rMutated), 'r');

  const ephemeralScalarMutated = copyOutput(output);
  ephemeralScalarMutated.witness.ephemeralScalar = fr(8);
  expectOutputError('OUTPUT_RECORD_MISMATCH', () => validate(ephemeralScalarMutated), 'ephemeral scalar');

  const commitmentMutated = copyOutput(output);
  commitmentMutated.public.noteCommitment = fr(1);
  expectOutputError('OUTPUT_COMMITMENT_MISMATCH', () => validate(commitmentMutated), 'note commitment');

  for (let segment = 0; segment < 4; segment += 1) {
    for (let byte = 0; byte < 32; byte += 1) {
      const recordMutated = copyOutput(output);
      recordMutated.public.encryptedRecord[(segment * 32) + byte] ^= 1;
      expectOutputError(
        'OUTPUT_RECORD_MISMATCH',
        () => validate(recordMutated),
        `encrypted record segment ${segment}, byte ${byte}`,
      );
    }
  }

  const leafMutated = copyOutput(output);
  leafMutated.public.outputNoteLeaf = fr(1);
  expectOutputError('OUTPUT_LEAF_MISMATCH', () => validate(leafMutated), 'output leaf');
});

test('rejects missing or unknown output fields plus noncanonical and non-subgroup values', () => {
  const { address, output } = fixture();
  const validate = (candidate, candidateAddress = address) => validateDirectV2OutputConstruction({
    address: candidateAddress,
    postActionSequence: '1',
    output: candidate,
  });

  for (const [label, candidate] of [
    ['unknown top-level field', { ...copyOutput(output), extra: true }],
    ['missing public field', { witness: { ...output.witness } }],
    ['unknown public field', {
      ...copyOutput(output),
      public: { ...output.public, extra: true },
    }],
    ['missing witness field', {
      ...copyOutput(output),
      witness: (({ r, ...witness }) => witness)(output.witness),
    }],
  ]) {
    expectOutputError('UNKNOWN_PROPERTY', () => validate(candidate), label);
  }

  const noncanonicalRhoBlind = copyOutput(output);
  noncanonicalRhoBlind.witness.rhoBlind = fr(BN254_SCALAR_FIELD_MODULUS);
  assert.throws(() => validate(noncanonicalRhoBlind), /canonical/);

  const nonSubgroupEphemeralScalar = copyOutput(output);
  nonSubgroupEphemeralScalar.witness.ephemeralScalar = fr(BABYJUB_SUBGROUP_ORDER);
  expectOutputError(
    'INVALID_SCALAR',
    () => validate(nonSubgroupEphemeralScalar),
    'non-subgroup ephemeral scalar',
  );

  for (const [label, spendPublicKey] of [
    ['non-subgroup recipient public key', '00'.repeat(32)],
    ['noncanonical recipient public key', Buffer.from(
      fr(BN254_SCALAR_FIELD_MODULUS),
      'hex',
    ).reverse().toString('hex')],
  ]) {
    expectOutputError(
      'INVALID_POINT',
      () => validate(output, { ...address, spendPublicKey }),
      label,
    );
  }
});
