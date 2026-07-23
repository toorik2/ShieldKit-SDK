import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  createVirtualMachineBch2026,
  disassembleBytecodeBch,
  encodeTransaction,
  encodeTokenPrefix,
} from '@bitauth/libauth';
import {
  buildLoopScctLock,
  buildPacketOnlyBindingLock,
  buildStateContinuityLock,
  buildStateSettlementHelper,
  buildStateTrampolineLock,
  buildStateTrampolineUnlock,
} from './compressed-covenants.mjs';
import { deriveInstanceId } from '../../packages/core/verifier-profile.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const pf7 = JSON.parse(readFileSync(
  new URL('./pf7-seam-v0-locks.json', import.meta.url),
));
const profileId = sha256(Buffer.from('g2-loop-profile'));
const stateCategory = sha256(Buffer.from('g2-loop-state-category'));
const stateCarrierBase = 1_000n;
const denomination = 10_000_000n;
const maximumReserve = 30_000_000n;
const genesis = {
  categoryInputOutpoint: { txid: stateCategory.toString('hex'), vout: '0' },
  instanceId: '',
  network: 'chipnet',
  profileId: `sha256:${profileId.toString('hex')}`,
  reserveCapSatoshis: maximumReserve.toString(),
  stateNftCategory: stateCategory.toString('hex'),
};
genesis.instanceId = deriveInstanceId(genesis);
const instanceId = Buffer.from(genesis.instanceId.slice('sha256:'.length), 'hex');
const feePubkey = Buffer.concat([Buffer.of(0x02), Buffer.alloc(32, 0x19)]);
const hash160 = (bytes) => createHash('ripemd160').update(sha256(bytes)).digest();
const p2pkh = Buffer.concat([
  Buffer.from('76a914', 'hex'),
  hash160(feePubkey),
  Buffer.from('88ac', 'hex'),
]);
const feeUnlock = Buffer.concat([
  Buffer.of(0x41),
  Buffer.alloc(64, 0x23),
  Buffer.of(0x41, 0x21),
  feePubkey,
]);
assert.equal(feeUnlock.length, 100);
const noTokenHash = sha256(Buffer.alloc(0));
const kindCode = Object.freeze({ deposit: 1, transfer: 2, withdrawal: 3 });

const accepts = (result) => (
  result.error === undefined
  && result.stack.length === 1
  && result.stack[0].some((byte) => byte !== 0)
);
const u16le = (value) => {
  const out = Buffer.alloc(2);
  out.writeUInt16LE(value);
  return out;
};
const u32le = (value) => {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value);
  return out;
};
const u64le = (value) => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(value);
  return out;
};
const tokenHash = (token) => sha256(encodeTokenPrefix(token));
const stateToken = (commitment) => ({
  category: Uint8Array.from(stateCategory),
  amount: 0n,
  nft: {
    capability: 'mutable',
    commitment: Uint8Array.from(commitment),
  },
});

function stateCommitment(label) {
  return sha256(Buffer.from(label));
}

function nftCommitment(state, sequence) {
  return Buffer.concat([
    Buffer.from('SHST'),
    Buffer.of(1, 2, 0, 0),
    profileId,
    state,
    u64le(sequence),
  ]);
}

function packetFor(kind, contextDigest) {
  const code = kindCode[kind];
  const preReserve = kind === 'deposit' ? 0n : denomination;
  const postReserve = kind === 'withdrawal' ? 0n : denomination;
  const preSequence = kind === 'deposit' ? 0n : 1n;
  const postSequence = preSequence + 1n;
  const preStateCommitment = stateCommitment(`${kind}-pre`);
  const postStateCommitment = stateCommitment(`${kind}-post`);
  const packet = Buffer.alloc(752);
  Buffer.from('SCAR').copy(packet);
  packet.set([1, 2, code, 0], 4);
  profileId.copy(packet, 8);
  instanceId.copy(packet, 40);
  u64le(preSequence).copy(packet, 140);
  u64le(preReserve).copy(packet, 152);
  u64le(maximumReserve).copy(packet, 160);
  preStateCommitment.copy(packet, 168);
  profileId.copy(packet, 200);
  instanceId.copy(packet, 232);
  u64le(postSequence).copy(packet, 332);
  u64le(postReserve).copy(packet, 344);
  u64le(maximumReserve).copy(packet, 352);
  postStateCommitment.copy(packet, 360);
  u64le(kind === 'transfer' ? 0n : denomination).copy(packet, 680);
  if (kind === 'withdrawal') sha256(Buffer.of(0x51)).copy(packet, 688);
  if (contextDigest !== undefined) Buffer.from(contextDigest).copy(packet, 720);
  return {
    packet,
    preReserve,
    postReserve,
    preToken: stateToken(nftCommitment(preStateCommitment, preSequence)),
    postToken: stateToken(nftCommitment(postStateCommitment, postSequence)),
  };
}

function encodeScct(kind, transaction, sourceOutputs) {
  const roles = kind === 'withdrawal' ? [0, 2, 1] : [0, 1];
  const fields = [
    Buffer.from('SCCT'),
    Buffer.of(1, 2, kindCode[kind], 0),
    profileId,
    instanceId,
    u16le(10),
    u16le(transaction.outputs.length),
  ];
  for (let index = 0; index < 10; index += 1) {
    const input = transaction.inputs[index];
    const source = sourceOutputs[index];
    fields.push(
      Buffer.of(index),
      Buffer.from(input.outpointTransactionHash).reverse(),
      u32le(input.outpointIndex),
      u32le(input.sequenceNumber),
      u64le(source.valueSatoshis),
      sha256(source.lockingBytecode),
      tokenHash(source.token),
    );
  }
  for (let index = 0; index < transaction.outputs.length; index += 1) {
    const output = transaction.outputs[index];
    fields.push(
      Buffer.of(roles[index]),
      u64le(output.valueSatoshis),
      sha256(output.lockingBytecode),
      tokenHash(output.token),
    );
  }
  return Buffer.concat(fields);
}

function programFor(kind, bindingLock, stateLock, digest = undefined) {
  const initial = packetFor(kind);
  const sourceOutputs = Array.from({ length: 10 }, (_, index) => ({
    valueSatoshis: 2_000n + BigInt(index),
    lockingBytecode: index < 7
      ? Buffer.from(pf7.locks[index], 'hex')
      : index === 7
        ? bindingLock
        : index === 8
          ? stateLock
          : p2pkh,
    ...(index === 8 ? { token: initial.preToken } : {}),
  }));
  sourceOutputs[8].valueSatoshis = stateCarrierBase + initial.preReserve;
  sourceOutputs[7].valueSatoshis = stateCarrierBase
    + (kind === 'deposit' ? denomination : 0n);
  sourceOutputs[9].valueSatoshis = 100_000n;
  const outputs = [{
    valueSatoshis: stateCarrierBase + initial.postReserve,
    lockingBytecode: stateLock,
    token: initial.postToken,
  }];
  if (kind === 'withdrawal') {
    outputs.push(
      { valueSatoshis: denomination, lockingBytecode: Buffer.of(0x51) },
      { valueSatoshis: 50_000n, lockingBytecode: p2pkh },
    );
  } else {
    outputs.push({ valueSatoshis: 50_000n, lockingBytecode: p2pkh });
  }
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: Array.from({ length: 10 }, (_, index) => ({
      // Non-palindromic hashes make display-vs-wire reversal observable.
      outpointTransactionHash: Uint8Array.from(
        Buffer.from(Array.from({ length: 32 }, (_, byte) => (
          (index * 37 + byte * 11 + 1) & 0xff
        ))),
      ),
      outpointIndex: index * 17,
      sequenceNumber: 0,
      unlockingBytecode: index === 9 ? feeUnlock : Buffer.alloc(0),
    })),
    outputs,
  };
  transaction.inputs[7].outpointTransactionHash = Uint8Array.from(
    transaction.inputs[9].outpointTransactionHash,
  );
  transaction.inputs[7].outpointIndex = 0;
  transaction.inputs[9].outpointIndex = 1;
  const preimage = encodeScct(kind, transaction, sourceOutputs);
  const contextDigest = digest ?? sha256(preimage);
  const packet = packetFor(kind, contextDigest).packet;
  transaction.inputs[7].unlockingBytecode = Buffer.concat([
    Buffer.of(0x4d, 0xf0, 0x02),
    packet,
  ]);
  return { contextDigest, packet, preimage, sourceOutputs, transaction };
}

function refreshContextDigest(kind, program) {
  const preimage = encodeScct(kind, program.transaction, program.sourceOutputs);
  sha256(preimage).copy(program.transaction.inputs[7].unlockingBytecode, 3 + 720);
  program.preimage = preimage;
}

// Use the authentic state category in every negative case. This ensures a
// token cannot be smuggled into another role merely by reusing the state
// category with a different CashToken form.
function nonStateToken(form, discriminator) {
  switch (form) {
    case 'fungible':
      return { category: Uint8Array.from(stateCategory), amount: 1n };
    case 'immutable-nft':
      return {
        category: Uint8Array.from(stateCategory),
        amount: 0n,
        nft: { capability: 'none', commitment: Uint8Array.of(discriminator) },
      };
    case 'mutable-nft':
      return {
        category: Uint8Array.from(stateCategory),
        amount: 0n,
        nft: {
          capability: 'mutable',
          commitment: Uint8Array.from({ length: 80 }, (_, index) => (
            (discriminator + index) & 0xff
          )),
        },
      };
    case 'minting-nft':
      return {
        category: Uint8Array.from(stateCategory),
        amount: 0n,
        nft: { capability: 'minting', commitment: Uint8Array.of(discriminator) },
      };
    default:
      throw new Error(`unknown non-state token form: ${form}`);
  }
}

function evaluate(lock, program, inputIndex, standard) {
  return createVirtualMachineBch2026(standard).evaluate({
    inputIndex,
    sourceOutputs: program.sourceOutputs,
    transaction: program.transaction,
  });
}

test('full helper rejects every CashToken form at every non-state input and output with refreshed SCCT', () => {
  const bindingLock = buildPacketOnlyBindingLock();
  const helper = buildStateSettlementHelper({
    bindingLock,
    pf7Locks: pf7.locks.map((value) => Buffer.from(value, 'hex')),
    profileId,
    instanceId,
    stateCategory,
    bindingCarrierBaseSatoshis: Number(stateCarrierBase),
  });
  const stateLock = buildStateTrampolineLock({ helper, bindingLock });
  const stateUnlock = buildStateTrampolineUnlock(helper);
  const forms = ['fungible', 'immutable-nft', 'mutable-nft', 'minting-nft'];
  const actionLayouts = {
    deposit: [1],
    transfer: [1],
    withdrawal: [1, 2],
  };
  const counts = { inputCases: 0, outputCases: 0, evaluations: 0 };

  for (const [kind, nonStateOutputIndexes] of Object.entries(actionLayouts)) {
    const baseline = programFor(kind, bindingLock, stateLock);
    baseline.transaction.inputs[8].unlockingBytecode = stateUnlock;
    for (const standard of [false, true]) {
      assert.equal(
        accepts(evaluate(stateLock, baseline, 8, standard)),
        true,
        `${kind} baseline standard=${standard}`,
      );
    }

    for (const inputIndex of [0, 1, 2, 3, 4, 5, 6, 7, 9]) {
      for (const form of forms) {
        const program = structuredClone(baseline);
        program.sourceOutputs[inputIndex].token = nonStateToken(
          form,
          0x10 + inputIndex,
        );
        refreshContextDigest(kind, program);
        for (const standard of [false, true]) {
          assert.equal(
            accepts(evaluate(stateLock, program, 8, standard)),
            false,
            `${kind} input ${inputIndex} ${form} standard=${standard}`,
          );
          counts.evaluations += 1;
        }
        counts.inputCases += 1;
      }
    }

    for (const outputIndex of nonStateOutputIndexes) {
      for (const form of forms) {
        const program = structuredClone(baseline);
        program.transaction.outputs[outputIndex].token = nonStateToken(
          form,
          0x80 + outputIndex,
        );
        refreshContextDigest(kind, program);
        for (const standard of [false, true]) {
          assert.equal(
            accepts(evaluate(stateLock, program, 8, standard)),
            false,
            `${kind} output ${outputIndex} ${form} standard=${standard}`,
          );
          counts.evaluations += 1;
        }
        counts.outputCases += 1;
      }
    }
  }

  assert.deepEqual(counts, {
    inputCases: 108,
    outputCases: 16,
    evaluations: 248,
  });
  console.log(JSON.stringify({
    tokenExclusionMatrix: {
      actions: Object.keys(actionLayouts),
      nonStateInputsPerAction: 9,
      tokenForms: forms,
      inputCases: counts.inputCases,
      outputCases: counts.outputCases,
      refreshedContextDigest: true,
      normalAndStandardEvaluations: counts.evaluations,
      includesFeeInput9: true,
      includesWithdrawalOutput2: true,
    },
    helperBytes: helper.length,
    stateTrampolineBytes: stateLock.length,
    stateHelperUnlockBytes: stateUnlock.length,
  }, null, 2));
});

test('loop reconstruction byte-matches exact SCCT for all actions and asymmetric wire-order outpoints', () => {
  const rawLock = buildLoopScctLock({ raw: true, tokenFunction: true });
  const bindingLock = buildLoopScctLock({ tokenFunction: true });
  const stateLock = buildStateContinuityLock({ bindingLock });
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const program = programFor(kind, rawLock, stateLock);
    const result = evaluate(rawLock, program, 7, false);
    assert.equal(result.error, undefined, `${kind}: ${result.error}`);
    assert.deepEqual(Buffer.from(result.stack[0]), program.preimage, kind);
    const firstOutpointOffset = 77;
    assert.deepEqual(
      Buffer.from(result.stack[0]).subarray(firstOutpointOffset, firstOutpointOffset + 32),
      Buffer.from(program.transaction.inputs[0].outpointTransactionHash).reverse(),
    );
    assert.notDeepEqual(
      Buffer.from(result.stack[0]).subarray(firstOutpointOffset, firstOutpointOffset + 32),
      Buffer.from(program.transaction.inputs[0].outpointTransactionHash),
    );
  }
});

test('loop SCCT lock executes in normal and standard BCH-2026 VMs and rejects every field family', () => {
  const simpleLoopLock = buildLoopScctLock();
  const lock = buildLoopScctLock({ tokenFunction: true });
  const coupledLock = buildLoopScctLock({
    tokenFunction: true,
    delegateTransactionShape: true,
  });
  const stateLock = buildStateContinuityLock({ bindingLock: lock });
  const baseline = programFor('deposit', lock, stateLock);
  let accepted;
  for (const standard of [false, true]) {
    const result = evaluate(lock, baseline, 7, standard);
    assert.equal(accepts(result), true, `standard=${standard}: ${result.error}`);
    if (standard) accepted = result;
  }
  const coupledProgram = programFor(
    'deposit',
    coupledLock,
    buildStateContinuityLock({ bindingLock: coupledLock }),
  );
  assert.equal(accepts(evaluate(coupledLock, coupledProgram, 7, true)), true);
  const mutations = [
    ['wire-outpoint-first', (p) => { p.transaction.inputs[0].outpointTransactionHash[31] ^= 1; }],
    ['wire-outpoint-last', (p) => { p.transaction.inputs[0].outpointTransactionHash[0] ^= 1; }],
    ['outpoint-index', (p) => { p.transaction.inputs[1].outpointIndex += 1; }],
    ['sequence', (p) => { p.transaction.inputs[2].sequenceNumber = 1; }],
    ['source-value', (p) => { p.sourceOutputs[3].valueSatoshis += 1n; }],
    ['source-lock', (p) => { p.sourceOutputs[4].lockingBytecode = Buffer.of(0x51); }],
    ['binding-lock', (p) => { p.sourceOutputs[7].lockingBytecode = Buffer.of(0x51); }],
    ['state-category', (p) => { p.sourceOutputs[8].token.category[0] ^= 1; }],
    ['state-capability', (p) => { p.sourceOutputs[8].token.nft.capability = 'minting'; }],
    ['state-commitment', (p) => { p.sourceOutputs[8].token.nft.commitment[0] ^= 1; }],
    ['state-amount', (p) => { p.sourceOutputs[8].token.amount = 1n; }],
    ['non-state-input-token', (p) => { p.sourceOutputs[9].token = p.sourceOutputs[8].token; }],
    ['output-value', (p) => { p.transaction.outputs[0].valueSatoshis += 1n; }],
    ['output-lock', (p) => { p.transaction.outputs[1].lockingBytecode = Buffer.of(0x51); }],
    ['output-state-token', (p) => { p.transaction.outputs[0].token.nft.commitment[0] ^= 1; }],
    ['non-state-output-token', (p) => { p.transaction.outputs[1].token = p.sourceOutputs[8].token; }],
    ['version', (p) => { p.transaction.version = 1; }],
    ['locktime', (p) => { p.transaction.locktime = 1; }],
    ['input-count', (p) => { p.transaction.inputs.pop(); p.sourceOutputs.pop(); }],
    ['output-count', (p) => { p.transaction.outputs.push({ valueSatoshis: 1n, lockingBytecode: Buffer.of(0x51) }); }],
    ['packet-context', (p) => { p.transaction.inputs[7].unlockingBytecode[3 + 720] ^= 1; }],
    ['noncanonical-packet-push', (p) => {
      p.transaction.inputs[7].unlockingBytecode = Buffer.concat([
        Buffer.of(0x4e, 0xf0, 0x02, 0, 0),
        p.packet,
      ]);
    }],
  ];
  for (const [name, mutate] of mutations) {
    const program = structuredClone(baseline);
    mutate(program);
    const result = evaluate(lock, program, 7, true);
    assert.equal(accepts(result), false, name);
  }
  console.log(JSON.stringify({
    simpleLoopScctLockingBytes: simpleLoopLock.length,
    standaloneFunctionLoopScctLockingBytes: lock.length,
    coupledFunctionLoopScctLockingBytes: coupledLock.length,
    projectP2sLimitBytes: 190,
    standaloneExcessBytes: lock.length - 190,
    coupledRemainingBytes: 190 - coupledLock.length,
    unlockingBytes: baseline.transaction.inputs[7].unlockingBytecode.length,
    operationCost: accepted.metrics.operationCost,
    allBytesContribution: lock.length + baseline.transaction.inputs[7].unlockingBytecode.length,
    asmSha256: sha256(Buffer.from(disassembleBytecodeBch(lock))).toString('hex'),
  }, null, 2));
});

test('minimal state continuity lock is <=190, executes in both VMs, and rejects state-edge mutations', () => {
  const bindingLock = buildLoopScctLock({
    tokenFunction: true,
    delegateTransactionShape: true,
  });
  const stateLock = buildStateContinuityLock({ bindingLock });
  assert.ok(stateLock.length <= 190, `state lock is ${stateLock.length} bytes`);
  const measurements = {};
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const program = programFor(kind, bindingLock, stateLock);
    for (const standard of [false, true]) {
      const bindingResult = evaluate(bindingLock, program, 7, standard);
      assert.equal(
        accepts(bindingResult),
        true,
        `${kind} binding, standard=${standard}: ${bindingResult.error}`,
      );
      const stateResult = evaluate(stateLock, program, 8, standard);
      assert.equal(
        accepts(stateResult),
        true,
        `${kind} state, standard=${standard}: ${stateResult.error}`,
      );
      if (standard) measurements[kind] = stateResult.metrics.operationCost;
    }
  }
  const baseline = programFor('deposit', bindingLock, stateLock);
  const mutations = [
    ['active-index', (p) => {
      p.program.sourceOutputs[7].lockingBytecode = stateLock;
      p.inputIndex = 7;
    }],
    ['successor-lock', (p) => { p.program.transaction.outputs[0].lockingBytecode = Buffer.of(0x51); }],
    ['binding-lock', (p) => { p.program.sourceOutputs[7].lockingBytecode = Buffer.of(0x51); }],
    ['input-category', (p) => { p.program.sourceOutputs[8].token.category[0] ^= 1; }],
    ['output-category', (p) => { p.program.transaction.outputs[0].token.category[0] ^= 1; }],
    ['input-capability', (p) => { p.program.sourceOutputs[8].token.nft.capability = 'minting'; }],
    ['output-capability', (p) => { p.program.transaction.outputs[0].token.nft.capability = 'minting'; }],
    ['input-amount', (p) => { p.program.sourceOutputs[8].token.amount = 1n; }],
    ['output-amount', (p) => { p.program.transaction.outputs[0].token.amount = 1n; }],
    ['input-commitment', (p) => { p.program.sourceOutputs[8].token.nft.commitment[40] ^= 1; }],
    ['output-commitment', (p) => { p.program.transaction.outputs[0].token.nft.commitment[40] ^= 1; }],
    ['packet-pre-state', (p) => { p.program.transaction.inputs[7].unlockingBytecode[3 + 168] ^= 1; }],
    ['packet-post-state', (p) => { p.program.transaction.inputs[7].unlockingBytecode[3 + 360] ^= 1; }],
    ['input-value', (p) => { p.program.sourceOutputs[8].valueSatoshis += 1n; }],
    ['output-value', (p) => { p.program.transaction.outputs[0].valueSatoshis += 1n; }],
    ['unsupported-kind', (p) => { p.program.transaction.inputs[7].unlockingBytecode[3 + 6] = 4; }],
  ];
  for (const [name, mutate] of mutations) {
    const holder = { program: structuredClone(baseline), inputIndex: 8 };
    mutate(holder);
    const result = evaluate(stateLock, holder.program, holder.inputIndex, true);
    assert.equal(accepts(result), false, name);
  }
  console.log(JSON.stringify({
    stateLockingBytes: stateLock.length,
    projectP2sLimitBytes: 190,
    remainingBytes: 190 - stateLock.length,
    unlockingBytes: 0,
    standardOperationCost: measurements,
    asmSha256: sha256(Buffer.from(disassembleBytecodeBch(stateLock))).toString('hex'),
  }, null, 2));
});

test('state helper construction fails closed unless its cap, profile, instance, and state category agree with canonical genesis', () => {
  const bindingLock = buildPacketOnlyBindingLock();
  const input = {
    bindingLock,
    pf7Locks: pf7.locks.map((value) => Buffer.from(value, 'hex')),
    profileId,
    instanceId,
    stateCategory,
    maximumReserveSatoshis: maximumReserve.toString(),
    genesis,
    bindingCarrierBaseSatoshis: Number(stateCarrierBase),
  };
  assert.doesNotThrow(() => buildStateSettlementHelper(input));
  assert.throws(
    () => buildStateSettlementHelper({ ...input, maximumReserveSatoshis: '20000000' }),
    /genesis reserve cap does not match helper maximumReserveSatoshis/,
  );
  assert.throws(
    () => buildStateSettlementHelper({
      ...input,
      genesis: { ...genesis, reserveCapSatoshis: '20000000' },
      maximumReserveSatoshis: '20000000',
    }),
    /genesis instanceId derivation mismatch/,
  );
  assert.throws(
    () => buildStateSettlementHelper({
      ...input,
      genesis: {
        ...genesis,
        categoryInputOutpoint: { ...genesis.categoryInputOutpoint, txid: '11'.repeat(32) },
      },
    }),
    /genesis state category does not match helper stateCategory/,
  );
});

test('hash-authenticated state trampoline executes the full helper and rejects helper, PF7, state, and category substitutions', () => {
  const bindingLock = buildPacketOnlyBindingLock();
  const helper = buildStateSettlementHelper({
    bindingLock,
    pf7Locks: pf7.locks.map((value) => Buffer.from(value, 'hex')),
    profileId,
    instanceId,
    stateCategory,
    maximumReserveSatoshis: maximumReserve.toString(),
    genesis,
    bindingCarrierBaseSatoshis: Number(stateCarrierBase),
  });
  const stateLock = buildStateTrampolineLock({ helper, bindingLock });
  const stateUnlock = buildStateTrampolineUnlock(helper);
  assert.ok(stateLock.length <= 190);
  assert.ok(stateUnlock.length <= 10_000);
  const operationCost = {};
  const bindingOperationCost = {};
  const fixtureWireBytes = {};
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const program = programFor(kind, bindingLock, stateLock);
    program.transaction.inputs[8].unlockingBytecode = stateUnlock;
    for (const standard of [false, true]) {
      const bindingResult = evaluate(bindingLock, program, 7, standard);
      assert.equal(
        accepts(bindingResult),
        true,
        `${kind} binding, standard=${standard}: ${bindingResult.error}`,
      );
      const stateResult = evaluate(stateLock, program, 8, standard);
      assert.equal(
        accepts(stateResult),
        true,
        `${kind} state, standard=${standard}: ${stateResult.error}`,
      );
      if (standard) operationCost[kind] = stateResult.metrics.operationCost;
      if (standard) bindingOperationCost[kind] = bindingResult.metrics.operationCost;
    }
    fixtureWireBytes[kind] = encodeTransaction(program.transaction).length;
  }

  const baseline = programFor('deposit', bindingLock, stateLock);
  baseline.transaction.inputs[8].unlockingBytecode = stateUnlock;
  const mutations = [
    ['helper-byte', (p) => { p.transaction.inputs[8].unlockingBytecode[3] ^= 1; }],
    ['extra-helper-push', (p) => {
      p.transaction.inputs[8].unlockingBytecode = Buffer.concat([
        Buffer.of(0),
        p.transaction.inputs[8].unlockingBytecode,
      ]);
    }],
    ['binding-lock', (p) => { p.sourceOutputs[7].lockingBytecode = Buffer.of(0x51); }],
    ['wrong-preparation-parent-with-refreshed-context', (p) => {
      p.transaction.inputs[9].outpointTransactionHash[0] ^= 1;
      refreshContextDigest('deposit', p);
    }],
    ['wrong-binding-vout-with-refreshed-context', (p) => {
      p.transaction.inputs[7].outpointIndex = 2;
      refreshContextDigest('deposit', p);
    }],
    ['wrong-fee-vout-with-refreshed-context', (p) => {
      p.transaction.inputs[9].outpointIndex = 2;
      refreshContextDigest('deposit', p);
    }],
    ['wrong-fee-sighash', (p) => {
      p.transaction.inputs[9].unlockingBytecode[65] = 0x40;
    }],
    ['wrong-fee-lock-with-refreshed-context', (p) => {
      p.sourceOutputs[9].lockingBytecode = Buffer.of(0x51);
      refreshContextDigest('deposit', p);
    }],
    ['wrong-change-key-with-refreshed-context', (p) => {
      p.transaction.outputs.at(-1).lockingBytecode = Buffer.from(
        '76a914222222222222222222222222222222222222222288ac',
        'hex',
      );
      refreshContextDigest('deposit', p);
    }],
    ['pf7-lock-with-refreshed-context', (p) => {
      p.sourceOutputs[0].lockingBytecode = Buffer.of(0x51);
      refreshContextDigest('deposit', p);
    }],
    ['state-input-commitment-with-refreshed-context', (p) => {
      p.sourceOutputs[8].token.nft.commitment[40] ^= 1;
      refreshContextDigest('deposit', p);
    }],
    ['state-output-value-with-refreshed-context', (p) => {
      p.transaction.outputs[0].valueSatoshis += 1n;
      refreshContextDigest('deposit', p);
    }],
    ['pre-state-cap-with-refreshed-context', (p) => {
      p.transaction.inputs[7].unlockingBytecode[3 + 160] ^= 1;
      refreshContextDigest('deposit', p);
    }],
    ['post-state-cap-with-refreshed-context', (p) => {
      p.transaction.inputs[7].unlockingBytecode[3 + 352] ^= 1;
      refreshContextDigest('deposit', p);
    }],
    ['same-category-fungible-input-with-refreshed-context', (p) => {
      p.sourceOutputs[0].token = {
        category: Uint8Array.from(stateCategory),
        amount: 1n,
      };
      refreshContextDigest('deposit', p);
    }],
    ['same-category-immutable-input-with-refreshed-context', (p) => {
      p.sourceOutputs[1].token = {
        category: Uint8Array.from(stateCategory),
        amount: 0n,
        nft: { capability: 'none', commitment: Uint8Array.of(1) },
      };
      refreshContextDigest('deposit', p);
    }],
    ['same-category-minting-input-with-refreshed-context', (p) => {
      p.sourceOutputs[2].token = {
        category: Uint8Array.from(stateCategory),
        amount: 0n,
        nft: { capability: 'minting', commitment: Uint8Array.of(2) },
      };
      refreshContextDigest('deposit', p);
    }],
    ['same-category-mutable-output-with-refreshed-context', (p) => {
      p.transaction.outputs[1].token = {
        category: Uint8Array.from(stateCategory),
        amount: 0n,
        nft: { capability: 'mutable', commitment: new Uint8Array(80) },
      };
      refreshContextDigest('deposit', p);
    }],
  ];
  for (const [name, mutate] of mutations) {
    const program = structuredClone(baseline);
    mutate(program);
    const result = evaluate(stateLock, program, 8, true);
    assert.equal(accepts(result), false, name);
  }

  const withdrawal = programFor('withdrawal', bindingLock, stateLock);
  withdrawal.transaction.inputs[8].unlockingBytecode = stateUnlock;
  withdrawal.transaction.outputs[1].lockingBytecode = Buffer.of(0x52);
  refreshContextDigest('withdrawal', withdrawal);
  assert.equal(accepts(evaluate(stateLock, withdrawal, 8, true)), false);

  const measuredPf7StructuralWire = {
    deposit: 55_311,
    transfer: 55_376,
    withdrawal: 55_247,
  };
  // The supervisor's original fixed-envelope calculation used a 57-byte
  // wrapper and 307 other fixed bytes. This exact recalculation replaces the
  // wrapper with the measured 88-byte script; it is not a complete-transaction
  // execution result.
  const correctedFixedEnvelopeBytes = 307 + (stateLock.length - 57);
  const envelopeRecalculation = Object.fromEntries(
    Object.entries(measuredPf7StructuralWire).map(([kind, wireBytes]) => [
      kind,
      {
        helperUnlockCapBytes:
          59_000 - wireBytes - correctedFixedEnvelopeBytes,
        recalculatedWireBytes:
          wireBytes + correctedFixedEnvelopeBytes + stateUnlock.length,
        remainingTo59000:
          59_000 - wireBytes - correctedFixedEnvelopeBytes - stateUnlock.length,
      },
    ]),
  );
  assert.equal(
    Math.min(...Object.values(envelopeRecalculation)
      .map((value) => value.helperUnlockCapBytes)),
    3_286,
  );

  console.log(JSON.stringify({
    packetOnlyBindingLockingBytes: bindingLock.length,
    packetInputUnlockingBytes: 755,
    stateTrampolineLockingBytes: stateLock.length,
    stateHelperBytes: helper.length,
    stateHelperUnlockingBytes: stateUnlock.length,
    combinedBindingStateLockUnlockBytes:
      bindingLock.length + 755 + stateLock.length + stateUnlock.length,
    feeP2pkhLockingBytes: p2pkh.length,
    feeP2pkhUnlockingBytes: feeUnlock.length,
    combinedBindingStateFeeLockUnlockBytes:
      bindingLock.length + 755 + stateLock.length + stateUnlock.length
      + p2pkh.length + feeUnlock.length,
    stateHelperStandardOperationCost: operationCost,
    packetBindingStandardOperationCost: bindingOperationCost,
    isolatedTenInputFixtureWireBytes: fixtureWireBytes,
    structuralEnvelopeRecalculationNotCompleteMeasurement: {
      correctedFixedEnvelopeBytes,
      ...envelopeRecalculation,
    },
    helperSha256: sha256(helper).toString('hex'),
    stateLockAsmSha256:
      sha256(Buffer.from(disassembleBytecodeBch(stateLock))).toString('hex'),
  }, null, 2));
});
