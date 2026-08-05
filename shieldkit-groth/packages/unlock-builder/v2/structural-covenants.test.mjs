import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  createVirtualMachineBch2026,
  encodeDataPush,
  encodeTokenPrefix,
  hash256,
} from '@bitauth/libauth';

import {
  encodeDirectV2TransactionContext,
  hashDirectV2TransactionContext,
} from '../../action/v2/context.mjs';
import {
  encodeActionPacket,
} from '../../action/v2/packet.mjs';
import {
  encodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
  directV2VerifierTopologyById,
} from '../../action/v2/topology.mjs';
import {
  buildDirectV2BindingLock,
  buildDirectV2BindingRedeem,
  buildDirectV2BindingUnlock,
  buildDirectV2StateHelper,
  buildDirectV2StateTrampolineLock,
  buildDirectV2StateTrampolineUnlock,
  structuralCovenantInternals,
} from './structural-covenants.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const hash160 = (bytes) => (
  createHash('ripemd160').update(sha256(bytes)).digest()
);
const accepts = (result) => (
  result.error === undefined
  && result.stack.length === 1
  && result.stack[0].some((byte) => byte !== 0)
);
const role = (kind, ordinal = 0) => ({ kind, ordinal: String(ordinal) });
const noToken = new Uint8Array();
const networkId = 2;
const denominationSats = 10_000_000n;
const profileId = sha256(Buffer.from('shieldkit-v2-structural-profile')).toString('hex');
// This is protocol/token-prefix byte order, deliberately non-palindromic.
const stateCategory = Buffer.from(
  '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f',
  'hex',
);
// Libauth's transaction model stores the category in display order.
const libauthCategory = Uint8Array.from(stateCategory).reverse();
const stateContext = Object.freeze({
  denominationSats: denominationSats.toString(),
});
const verifierLocks = Object.freeze(Array.from(
  { length: 11 },
  (_, index) => Uint8Array.from([0x61, 0x50 + ((index % 16) + 1)]),
));
const verifierValues = Object.freeze(Array(11).fill(1_000n));
const pf11Topology = directV2VerifierTopologyById(
  DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
);
const pf10Topology = directV2VerifierTopologyById(
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
);
const bindingValue = 1_000n;
const stateBaseValue = 1_000n;
const minimumChange = 546n;
const fundingPublicKey = Buffer.concat([
  Buffer.of(0x02),
  sha256(Buffer.from('shieldkit-v2-funding-pubkey')),
]);
const fundingLock = Buffer.concat([
  Buffer.from('76a914', 'hex'),
  hash160(fundingPublicKey),
  Buffer.from('88ac', 'hex'),
]);
const fundingUnlock = Buffer.concat([
  Buffer.of(0x41),
  Buffer.alloc(64, 0x23),
  Buffer.of(0x61, 0x21),
  fundingPublicKey,
]);
assert.equal(fundingUnlock.length, 100);
const changeLock = Buffer.concat([
  Buffer.from('76a914', 'hex'),
  hash160(Buffer.concat([Buffer.of(0x03), Buffer.alloc(32, 0x42)])),
  Buffer.from('88ac', 'hex'),
]);
const withdrawalLock = Buffer.concat([
  Buffer.from('76a914', 'hex'),
  hash160(Buffer.concat([Buffer.of(0x02), Buffer.alloc(32, 0x77)])),
  Buffer.from('88ac', 'hex'),
]);

const stateToken = (commitment) => ({
  category: libauthCategory,
  amount: 0n,
  nft: {
    capability: 'mutable',
    commitment: Uint8Array.from(commitment),
  },
});

const makeState = ({
  noteCount,
  nullifierCount,
  reserveSats,
  actionSequence,
  noteRootByte,
  nullifierRootByte,
}) => ({
  profileId,
  noteRoot: noteRootByte.repeat(32),
  nullifierRoot: nullifierRootByte.repeat(32),
  noteCount: String(noteCount),
  nullifierCount: String(nullifierCount),
  maximumLiveNotes: '32',
  reserveSats: String(reserveSats),
  actionSequence: String(actionSequence),
});

const statesFor = (kind) => {
  if (kind === 'deposit') {
    return {
      preState: makeState({
        noteCount: 0,
        nullifierCount: 0,
        reserveSats: 0,
        actionSequence: 0,
        noteRootByte: '00',
        nullifierRootByte: '00',
      }),
      postState: makeState({
        noteCount: 1,
        nullifierCount: 0,
        reserveSats: denominationSats,
        actionSequence: 1,
        noteRootByte: '01',
        nullifierRootByte: '00',
      }),
    };
  }
  if (kind === 'transfer') {
    return {
      preState: makeState({
        noteCount: 1,
        nullifierCount: 0,
        reserveSats: denominationSats,
        actionSequence: 1,
        noteRootByte: '01',
        nullifierRootByte: '00',
      }),
      postState: makeState({
        noteCount: 2,
        nullifierCount: 1,
        reserveSats: denominationSats,
        actionSequence: 2,
        noteRootByte: '02',
        nullifierRootByte: '03',
      }),
    };
  }
  return {
    preState: makeState({
      noteCount: 1,
      nullifierCount: 0,
      reserveSats: denominationSats,
      actionSequence: 1,
      noteRootByte: '01',
      nullifierRootByte: '00',
    }),
    postState: makeState({
      noteCount: 1,
      nullifierCount: 1,
      reserveSats: 0,
      actionSequence: 2,
      noteRootByte: '01',
      nullifierRootByte: '03',
    }),
  };
};

function tokenPrefix(token) {
  return token === undefined
    ? noToken
    : Uint8Array.from(encodeTokenPrefix(token));
}

function contextFor(
  kind,
  transaction,
  sourceOutputs,
  preState,
  postState,
  topology = pf11Topology,
) {
  const inputs = transaction.inputs.map((input, index) => ({
    role: index < topology.carrierCount
      ? role('verifier', index)
      : index === topology.bindingInputIndex
        ? role('binding')
        : index === topology.stateInputIndex
          ? role('state')
          : role('funding'),
    // BCH wire order, matching OP_OUTPOINTTXHASH.
    outpointTransactionHash: Buffer.from(input.outpointTransactionHash)
      .reverse()
      .toString('hex'),
    outpointIndex: String(input.outpointIndex),
    sequence: String(input.sequenceNumber),
    valueSats: String(sourceOutputs[index].valueSatoshis),
    lockingBytecode: Uint8Array.from(sourceOutputs[index].lockingBytecode),
    tokenPrefix: tokenPrefix(sourceOutputs[index].token),
  }));
  const outputs = transaction.outputs.map((output, index) => ({
    role: index === 0
      ? role('state')
      : index <= topology.carrierCount
        ? role('verifier', index - 1)
        : index === topology.bindingOutputIndex
          ? role('binding')
          : kind === 'withdrawal'
              && index === topology.withdrawalOutputIndex
            ? role('withdrawal')
            : role('change'),
    valueSats: String(output.valueSatoshis),
    lockingBytecode: Uint8Array.from(output.lockingBytecode),
    tokenPrefix: tokenPrefix(output.token),
  }));
  return {
    networkId,
    kind,
    profileId,
    instanceId: stateCategory.toString('hex'),
    transactionVersion: String(transaction.version),
    locktime: String(transaction.locktime),
    preActionSequence: preState.actionSequence,
    postActionSequence: postState.actionSequence,
    inputs,
    outputs,
  };
}

function fixture(
  kind,
  {
    contextProbe = false,
    topology = pf11Topology,
  } = {},
) {
  const { preState, postState } = statesFor(kind);
  const preCommitment = encodeStateNftCommitment(preState, stateContext);
  const postCommitment = encodeStateNftCommitment(postState, stateContext);
  const bindingOptions = {
    networkId,
    profileId,
    stateCategory: stateCategory.toString('hex'),
    denominationSats,
    topologyId: topology.id,
    verifierRoles: topology.verifierRoles,
  };
  const bindingRedeem = contextProbe
    ? structuralCovenantInternals.buildBindingContextProbe(bindingOptions)
    : buildDirectV2BindingRedeem(bindingOptions);
  const bindingLock = contextProbe
    ? structuralCovenantInternals.buildP2sh32Lock(bindingRedeem)
    : buildDirectV2BindingLock(bindingOptions);
  const selectedVerifierLocks = topology.carrierCount === verifierLocks.length
    ? verifierLocks
    : Object.freeze(Array.from(
      { length: topology.carrierCount },
      (_, index) => Uint8Array.from([0x61, 0x50 + ((index % 16) + 1)]),
    ));
  const selectedVerifierValues =
    topology.carrierCount === verifierValues.length
      ? verifierValues
      : Object.freeze(Array(topology.carrierCount).fill(1_000n));
  const helper = buildDirectV2StateHelper({
    bindingLock,
    verifierLocks: selectedVerifierLocks,
    verifierBaseValues: selectedVerifierValues,
    bindingBaseValueSats: bindingValue,
    stateBaseValueSats: stateBaseValue,
    denominationSats,
    stateCategory: stateCategory.toString('hex'),
    minimumChangeSats: minimumChange,
    topologyId: topology.id,
    verifierRoles: topology.verifierRoles,
  });
  const stateLock = buildDirectV2StateTrampolineLock({
    helper,
    bindingLock,
    topologyId: topology.id,
    verifierRoles: topology.verifierRoles,
  });
  const stateUnlock = buildDirectV2StateTrampolineUnlock(helper);
  const parent = sha256(Buffer.from(`${kind}-parent`));
  const fundingParent = sha256(Buffer.from(`${kind}-funding-parent`));
  const sourceOutputs = [
    ...selectedVerifierLocks.map((lockingBytecode, index) => ({
      lockingBytecode,
      valueSatoshis: selectedVerifierValues[index],
    })),
    { lockingBytecode: bindingLock, valueSatoshis: bindingValue },
    {
      lockingBytecode: stateLock,
      valueSatoshis: stateBaseValue + BigInt(preState.reserveSats),
      token: stateToken(preCommitment),
    },
    {
      lockingBytecode: fundingLock,
      valueSatoshis: (
        (kind === 'deposit' ? denominationSats : 0n) + 11_000n
      ),
    },
  ];
  const outputs = [
    {
      lockingBytecode: stateLock,
      valueSatoshis: stateBaseValue + BigInt(postState.reserveSats),
      token: stateToken(postCommitment),
    },
    ...selectedVerifierLocks.map((lockingBytecode, index) => ({
      lockingBytecode,
      valueSatoshis: selectedVerifierValues[index],
    })),
    { lockingBytecode: bindingLock, valueSatoshis: bindingValue },
    ...(kind === 'withdrawal'
      ? [{ lockingBytecode: withdrawalLock, valueSatoshis: denominationSats }]
      : []),
    { lockingBytecode: changeLock, valueSatoshis: 10_000n },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: Array.from({ length: topology.inputCount }, (_, index) => ({
      outpointTransactionHash: Uint8Array.from(
        index <= topology.stateInputIndex ? parent : fundingParent,
      ),
      outpointIndex: index <= topology.bindingInputIndex
        ? index + 1
        : index === topology.stateInputIndex
          ? 0
          : 7,
      sequenceNumber: 0xffff_ffff,
      unlockingBytecode: index === topology.stateInputIndex
        ? stateUnlock
        : index === topology.fundingInputIndex
          ? fundingUnlock
          : new Uint8Array(),
    })),
    outputs,
  };
  const context = contextFor(
    kind,
    transaction,
    sourceOutputs,
    preState,
    postState,
    topology,
  );
  const transactionContextHash = hashDirectV2TransactionContext(
    context,
    { carrierCount: topology.carrierCount },
  );
  const packet = encodeActionPacket({
    kind,
    networkId,
    instanceId: stateCategory.toString('hex'),
    preState,
    postState,
    publicNullifier: kind === 'deposit' ? '00'.repeat(32) : '04'.repeat(32),
    outputNoteLeaf: kind === 'withdrawal' ? '00'.repeat(32) : '05'.repeat(32),
    encryptedRecord: kind === 'withdrawal'
      ? Buffer.alloc(128)
      : Buffer.alloc(128, 0x06),
    withdrawalLockingBytecodeHash: kind === 'withdrawal'
      ? sha256(withdrawalLock).toString('hex')
      : '00'.repeat(32),
    transactionContextHash: transactionContextHash.toString('hex'),
  }, stateContext);
  transaction.inputs[topology.bindingInputIndex].unlockingBytecode =
    buildDirectV2BindingUnlock({
    packet,
    redeem: bindingRedeem,
  });
  const projection = Buffer.alloc(480);
  sha256(packet).copy(projection, 448);
  transaction.inputs[topology.digestCarrierIndex].unlockingBytecode =
    Buffer.concat([
    Buffer.from('4de001', 'hex'),
    projection,
  ]);
  return {
    bindingLock,
    bindingRedeem,
    context,
    helper,
    packet,
    sourceOutputs,
    stateLock,
    stateUnlock,
    topology,
    transaction,
  };
}

function evaluate(program, inputIndex, standard = false) {
  return createVirtualMachineBch2026(standard).evaluate({
    inputIndex,
    sourceOutputs: program.sourceOutputs,
    transaction: program.transaction,
  });
}

function debugFailure(program, inputIndex) {
  const trace = createVirtualMachineBch2026(false).debug({
    inputIndex,
    sourceOutputs: program.sourceOutputs,
    transaction: program.transaction,
  });
  const state = trace.at(-1);
  return {
    error: state.error,
    ip: state.ip,
    opcode: state.instructions[state.ip - 1]?.opcode,
    previousOpcodes: state.instructions
      .slice(Math.max(0, state.ip - 8), state.ip + 2)
      .map((instruction) => instruction.opcode),
    stackDepth: state.stack.length,
    stack: state.stack.map((item) => Buffer.from(item).toString('hex').slice(0, 80)),
  };
}

test('binding and state covenants execute all three exact PF11 structural layouts', () => {
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const program = fixture(kind);
    for (const standard of [false, true]) {
      const bindingResult = evaluate(program, 11, standard);
      const stateResult = evaluate(program, 12, standard);
      if (!accepts(bindingResult)) console.log(debugFailure(program, 11));
      if (!accepts(stateResult)) console.log(debugFailure(program, 12));
      assert.equal(
        accepts(bindingResult),
        true,
        `${kind} binding standard=${standard}: ${bindingResult.error}`,
      );
      assert.equal(
        accepts(stateResult),
        true,
        `${kind} state standard=${standard}: ${stateResult.error}`,
      );
    }
    assert.equal(program.bindingLock.length, 35);
    assert.equal(program.bindingRedeem.length <= 10_000, true);
    assert.equal(program.stateUnlock.length <= 10_000, true);
    assert.equal(
      program.transaction.inputs[11].unlockingBytecode.length,
      555 + encodeDataPush(program.bindingRedeem).length,
    );
    assert.equal(
      program.transaction.inputs[11].unlockingBytecode.length <= 10_000,
      true,
    );
    assert.equal(program.transaction.inputs.length, 14);
    assert.equal(
      program.transaction.outputs.length,
      kind === 'withdrawal' ? 15 : 14,
    );
  }
});

test('binding and state covenants execute all three exact PF10 structural layouts', () => {
  assert.deepEqual(
    pf10Topology.verifierRoles,
    DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  );
  assert.deepEqual(
    pf11Topology.verifierRoles,
    DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
  );
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const program = fixture(kind, { topology: pf10Topology });
    for (const standard of [false, true]) {
      const bindingResult = evaluate(
        program,
        pf10Topology.bindingInputIndex,
        standard,
      );
      const stateResult = evaluate(
        program,
        pf10Topology.stateInputIndex,
        standard,
      );
      assert.equal(
        accepts(bindingResult),
        true,
        `${kind} PF10 binding standard=${standard}: ${bindingResult.error}`,
      );
      assert.equal(
        accepts(stateResult),
        true,
        `${kind} PF10 state standard=${standard}: ${stateResult.error}`,
      );
    }
    assert.equal(program.transaction.inputs.length, 13);
    assert.equal(
      program.transaction.outputs.length,
      kind === 'withdrawal' ? 14 : 13,
    );
    assert.equal(
      program.transaction.inputs[
        pf10Topology.bindingInputIndex
      ].unlockingBytecode.length <= 10_000,
      true,
    );
    assert.equal(program.stateUnlock.length <= 10_000, true);
  }
});

test('binding covenant reconstructs the byte-identical SDC2 preimage', () => {
  const program = fixture('deposit', { contextProbe: true });
  const result = evaluate(program, 11);
  assert.equal(result.error, undefined);
  assert.equal(result.stack.length, 1);
  const actual = Buffer.from(result.stack[0]);
  const expected = encodeDirectV2TransactionContext(
    program.context,
    { carrierCount: 11 },
  );
  if (!actual.equals(expected)) {
    const firstDifference = actual.findIndex((byte, index) => byte !== expected[index]);
    console.log({
      actualBytes: actual.length,
      expectedBytes: expected.length,
      firstDifference,
      actual: actual.subarray(firstDifference, firstDifference + 64).toString('hex'),
      expected: expected.subarray(firstDifference, firstDifference + 64).toString('hex'),
    });
  }
  assert.deepEqual(actual, expected);
});

test('packet, context, category, parent, bundle, state, token, and funding mutations reject', () => {
  const mutations = [
    ['packet', (program) => {
      program.transaction.inputs[11].unlockingBytecode[40] ^= 1;
    }, 11],
    ['binding redeem', (program) => {
      program.transaction.inputs[11].unlockingBytecode[
        program.transaction.inputs[11].unlockingBytecode.length - 1
      ] ^= 1;
    }, 11],
    ['context output value', (program) => {
      program.transaction.outputs[13].valueSatoshis += 1n;
    }, 11],
    ['state category', (program) => {
      program.sourceOutputs[12].token.category[0] ^= 1;
    }, 12],
    ['mixed parent', (program) => {
      program.transaction.inputs[5].outpointTransactionHash[0] ^= 1;
    }, 12],
    ['carrier lock', (program) => {
      program.sourceOutputs[5].lockingBytecode = Uint8Array.of(0x51);
    }, 12],
    ['omitted successor', (program) => {
      program.transaction.outputs[6].lockingBytecode = Uint8Array.of(0x51);
    }, 12],
    ['duplicate token', (program) => {
      program.sourceOutputs[3].token = structuredClone(program.sourceOutputs[12].token);
    }, 12],
    ['minting state', (program) => {
      program.sourceOutputs[12].token.nft.capability = 'minting';
    }, 12],
    ['reserve theft', (program) => {
      program.transaction.outputs[0].valueSatoshis -= 1n;
    }, 12],
    ['bad sighash mode', (program) => {
      program.transaction.inputs[13].unlockingBytecode[65] = 0x41;
    }, 12],
  ];
  for (const [label, mutate, inputIndex] of mutations) {
    const program = structuredClone(fixture('deposit'));
    mutate(program);
    assert.equal(
      accepts(evaluate(program, inputIndex)),
      false,
      label,
    );
  }
});

test('PF10 state covenant rejects Q-03 bundle attacks and every late-carrier role swap', () => {
  const rejectAtState = (label, mutate, inputIndex = pf10Topology.stateInputIndex) => {
    const program = structuredClone(fixture('deposit', { topology: pf10Topology }));
    mutate(program);
    assert.equal(
      accepts(evaluate(program, inputIndex)),
      false,
      label,
    );
  };

  rejectAtState('standalone carrier burn', (program) => {
    program.transaction.outputs[6].valueSatoshis = 0n;
  });
  rejectAtState('partial carrier bundle', (program) => {
    program.sourceOutputs.splice(0, 1);
    program.transaction.inputs.splice(0, 1);
    program.transaction.outputs.splice(1, 1);
  }, pf10Topology.stateInputIndex - 1);
  rejectAtState('mixed common parent', (program) => {
    program.transaction.inputs[7].outpointTransactionHash[0] ^= 1;
  });
  rejectAtState('fake state category', (program) => {
    program.sourceOutputs[pf10Topology.stateInputIndex].token.category[0] ^= 1;
  });
  rejectAtState('duplicate state NFT', (program) => {
    program.sourceOutputs[4].token = structuredClone(
      program.sourceOutputs[pf10Topology.stateInputIndex].token,
    );
  });
  rejectAtState('minting state NFT authority', (program) => {
    program.sourceOutputs[pf10Topology.stateInputIndex].token
      .nft.capability = 'minting';
  });
  rejectAtState('omitted PF10 carrier successor', (program) => {
    program.transaction.outputs[9].lockingBytecode = Uint8Array.of(0x51);
  });

  const lateCarrierIndices = [5, 6, 7, 8, 9];
  for (let left = 0; left < lateCarrierIndices.length; left += 1) {
    for (let right = left + 1; right < lateCarrierIndices.length; right += 1) {
      const first = lateCarrierIndices[left];
      const second = lateCarrierIndices[right];
      const firstRole = pf10Topology.verifierRoles[first];
      const secondRole = pf10Topology.verifierRoles[second];
      rejectAtState(`PF10 role swap ${firstRole} <-> ${secondRole}`, (program) => {
        [
          program.sourceOutputs[first],
          program.sourceOutputs[second],
        ] = [
          program.sourceOutputs[second],
          program.sourceOutputs[first],
        ];
        [
          program.transaction.outputs[first + 1],
          program.transaction.outputs[second + 1],
        ] = [
          program.transaction.outputs[second + 1],
          program.transaction.outputs[first + 1],
        ];
      });
    }
  }
});

test('fixed locks and helper have deterministic hashes and fit the full BCH limits', () => {
  const program = fixture('deposit');
  const repeated = fixture('deposit');
  assert.deepEqual(program.bindingLock, repeated.bindingLock);
  assert.deepEqual(program.bindingRedeem, repeated.bindingRedeem);
  assert.deepEqual(program.stateLock, repeated.stateLock);
  assert.deepEqual(program.stateUnlock, repeated.stateUnlock);
  assert.equal(program.bindingLock.length, 35);
  assert.equal(program.bindingRedeem.length, 2_280);
  assert.equal(program.helper.length, 2_793);
  assert.equal(program.stateLock.length, 88);
  assert.equal(program.stateUnlock.length, 2_796);
  assert.equal(hash256(program.bindingLock).length, 32);
});
