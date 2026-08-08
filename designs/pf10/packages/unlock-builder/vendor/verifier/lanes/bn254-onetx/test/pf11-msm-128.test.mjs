import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import {
  binToHex,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
  hexToBin,
  bigIntToVmNumber,
} from '@bitauth/libauth';

import {
  BN254_BASE_FIELD,
  computeDirectV2ExactMsm,
  encodeDirectV2MsmState,
  parseDirectV2VerificationKeyJson,
} from '../../../../../v2/exact-msm.mjs';
import {
  renderDirectV2ExactMsmRole,
} from '../../../../../v2/exact-msm-cashscript.mjs';
import {
  buildDirectV2BindingLock,
  buildDirectV2BindingRedeem,
  buildDirectV2BindingUnlock,
} from '../../../../../v2/structural-covenants.mjs';
import {
  compileBytecodeRaw,
} from '../../../build/chunked/pairing/_millermath.mjs';
import {
  createLoosenedVm,
  createRealVm,
  evaluatePair,
  realOpCostBudget,
} from '../../../harness/src/harness/vm.ts';

const verifierRoot = path.resolve(import.meta.dirname, '../../..');
const fixturePath = path.resolve(
  verifierRoot,
  '../../../prove/test-fixtures/two-public/verification_key.json',
);
const verificationKey = parseDirectV2VerificationKeyJson(
  readFileSync(fixturePath),
);
const PACKET = Buffer.alloc(552);
PACKET.write('SDA2', 0, 'ascii');
for (let index = 4; index < PACKET.length; index += 1) {
  PACKET[index] = (index * 73 + 19) & 0xff;
}
const digest = createHash('sha256').update(PACKET).digest();
const input0 = BigInt(`0x${digest.subarray(0, 16).toString('hex')}`);
const input1 = BigInt(`0x${digest.subarray(16).toString('hex')}`);
const trace = computeDirectV2ExactMsm(verificationKey, input0, input1);
const projection = Buffer.alloc(480);
const qx = trace.output.x.toString(16).padStart(64, '0');
const qy = trace.output.y.toString(16).padStart(64, '0');
Buffer.from(qx, 'hex').reverse().copy(projection, 128);
Buffer.from(qy, 'hex').reverse().copy(projection, 160);
digest.copy(projection, 448);

const pushInt = (value) => encodeDataPush(bigIntToVmNumber(BigInt(value)));
const opTrueRedeem = Uint8Array.from([0x51]);
const opTrueLock = encodeLockingBytecodeP2sh32(hash256(opTrueRedeem));
const opTrueUnlock = encodeDataPush(opTrueRedeem);
const stateCategory = Uint8Array.from(
  Buffer.from('00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f', 'hex'),
);
const bindingOptions = {
  networkId: 2,
  profileId: '11'.repeat(32),
  stateCategory: binToHex(Uint8Array.from(stateCategory).reverse()),
  denominationSats: 10_000_000n,
};
const bindingRedeem = buildDirectV2BindingRedeem(bindingOptions);
const bindingLock = buildDirectV2BindingLock(bindingOptions);
const stateCommitment = Uint8Array.from(Buffer.alloc(128));
stateCommitment.set(Buffer.from('SKS2', 'ascii'));
const TARGET_UNLOCK_BYTES = Object.freeze([10_000, 10_000, 10_000, 5_000]);

const compileRole = ({
  windowIndex,
  successorLock,
  successorStatePayloadOffset,
}) => {
  let paddingBytes = 8_000;
  let redeem;
  let source;
  let unlock;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    source = renderDirectV2ExactMsmRole({
      verificationKey,
      windowIndex,
      inputIndex: 5 + windowIndex,
      successorInputIndex: 6 + windowIndex,
      successorLockingBytecodeHex: binToHex(successorLock),
      successorStatePayloadOffset,
      stateCategoryHex: binToHex(Uint8Array.from(stateCategory).reverse()),
      packetLockingBytecodeHex: binToHex(bindingLock),
      expectedInputCount: 14,
      packetInputIndex: 11,
      zeroPaddingBytes: paddingBytes,
    });
    redeem = compileBytecodeRaw(source);
    const state = encodeDirectV2MsmState(trace.states[windowIndex]);
    const pieces = [
      ...(windowIndex === 3 ? [encodeDataPush(projection)] : []),
      encodeDataPush(state),
      pushInt(windowIndex === 3 ? trace.output.zInverse : 0n),
      encodeDataPush(Buffer.alloc(paddingBytes)),
      encodeDataPush(redeem),
    ];
    unlock = Buffer.concat(pieces);
    const adjustment = TARGET_UNLOCK_BYTES[windowIndex] - unlock.length;
    if (adjustment === 0) break;
    paddingBytes += adjustment;
  }
  assert.equal(unlock.length, TARGET_UNLOCK_BYTES[windowIndex]);
  return Object.freeze({
    source,
    redeem,
    lock: encodeLockingBytecodeP2sh32(hash256(redeem)),
    unlock: Uint8Array.from(unlock),
    paddingBytes,
  });
};

const role3 = compileRole({
  windowIndex: 3,
  successorLock: opTrueLock,
  successorStatePayloadOffset: 0,
});
const role2 = compileRole({
  windowIndex: 2,
  successorLock: role3.lock,
  successorStatePayloadOffset: 483 + 2,
});
const role1 = compileRole({
  windowIndex: 1,
  successorLock: role2.lock,
  successorStatePayloadOffset: 2,
});
const role0 = compileRole({
  windowIndex: 0,
  successorLock: role1.lock,
  successorStatePayloadOffset: 2,
});
const roles = [role0, role1, role2, role3];

const packetUnlock = buildDirectV2BindingUnlock({
  packet: PACKET,
  redeem: bindingRedeem,
});
const dummyLock = opTrueLock;
const dummyUnlock = opTrueUnlock;
const parent = new Uint8Array(32).fill(0x5a);
const baseInputs = [
  ...Array.from({ length: 5 }, () => ({
    lockingBytecode: dummyLock,
    unlockingBytecode: dummyUnlock,
    outpointTransactionHash: parent,
  })),
  ...roles.map((role) => ({
    lockingBytecode: role.lock,
    unlockingBytecode: role.unlock,
    outpointTransactionHash: parent,
  })),
  {
    lockingBytecode: opTrueLock,
    unlockingBytecode: opTrueUnlock,
    outpointTransactionHash: parent,
  },
  {
    lockingBytecode: opTrueLock,
    unlockingBytecode: opTrueUnlock,
    outpointTransactionHash: parent,
  },
  {
    lockingBytecode: bindingLock,
    unlockingBytecode: packetUnlock,
    outpointTransactionHash: parent,
  },
  {
    lockingBytecode: dummyLock,
    unlockingBytecode: dummyUnlock,
    outpointTransactionHash: parent,
    token: {
      category: stateCategory,
      capability: 'mutable',
      commitment: stateCommitment,
    },
  },
  {
    lockingBytecode: dummyLock,
    unlockingBytecode: dummyUnlock,
    outpointTransactionHash: new Uint8Array(32).fill(0x20),
  },
].map((input, index) => ({
  ...input,
  outpointIndex: index <= 11 ? index + 1 : index === 12 ? 0 : 7,
}));

const evaluateRole = (index, inputs = baseInputs, vm = createRealVm()) =>
  evaluatePair(
    vm,
    inputs[index].lockingBytecode,
    inputs[index].unlockingBytecode,
    undefined,
    { index, inputs },
  );

const replaceRoleStatePushIn = (
  sourceInputs,
  inputIndex,
  state,
  push = encodeDataPush(state),
) => {
  const inputs = structuredClone(sourceInputs);
  const original = Buffer.from(inputs[inputIndex].unlockingBytecode);
  const prefixBytes = inputIndex === 8 ? 483 : 0;
  const oldStateEnd = prefixBytes + 2 + 128;
  inputs[inputIndex].unlockingBytecode = Uint8Array.from(Buffer.concat([
    original.subarray(0, prefixBytes),
    Buffer.from(push),
    original.subarray(oldStateEnd),
  ]));
  return inputs;
};

const replaceRoleStatePush = (inputIndex, state, push = encodeDataPush(state)) =>
  replaceRoleStatePushIn(baseInputs, inputIndex, state, push);

const writeBe = (target, offset, width, value) => {
  const encoded = Buffer.from(BigInt(value).toString(16).padStart(width * 2, '0'), 'hex');
  encoded.copy(target, offset);
};

test('four fixed exact-MSM roles accept under the full BCH hard ceilings', () => {
  const results = roles.map((_, offset) => evaluateRole(5 + offset));
  console.log(JSON.stringify({
    pf11ExactMsm: roles.map((role, index) => ({
      role: 5 + index,
      redeemBytes: role.redeem.length,
      unlockBytes: role.unlock.length,
      zeroPaddingBytes: role.paddingBytes,
      operationCost: results[index].operationCost,
      operationBudget: realOpCostBudget(role.unlock.length),
      instructionCount: results[index].instructionCount,
      arithmeticCost: results[index].arithmeticCost,
      stackPushedBytes: results[index].stackPushedBytes,
    })),
  }));
  for (const [index, result] of results.entries()) {
    assert.equal(
      result.accepted,
      true,
      `role ${index} rejected: ${result.error ?? 'unknown'}`,
    );
    assert.equal(roles[index].unlock.length <= 10_000, true);
    assert.equal(
      result.operationCost <= realOpCostBudget(roles[index].unlock.length),
      true,
    );
  }
});

test('state token, topology, successor, Q, packet, inverse, and role mutations reject', () => {
  for (const [roleIndex, successorIndex, byteIndex] of [
    [5, 6, 2],
    [6, 7, 2 + 63],
    [7, 8, 483 + 2 + 127],
  ]) {
    const inputs = structuredClone(baseInputs);
    inputs[successorIndex].unlockingBytecode[byteIndex] ^= 1;
    assert.equal(evaluateRole(roleIndex, inputs).accepted, false);
  }

  {
    const inputs = structuredClone(baseInputs);
    inputs[8].unlockingBytecode[3 + 128] ^= 1;
    assert.equal(evaluateRole(8, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    inputs[11].unlockingBytecode[3 + 551] ^= 1;
    assert.equal(evaluateRole(8, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    const stateEnd = 483 + 2 + 128;
    inputs[8].unlockingBytecode[stateEnd] ^= 1;
    assert.equal(evaluateRole(8, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    inputs[7].lockingBytecode = opTrueLock;
    assert.equal(evaluateRole(6, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    [inputs[5], inputs[6]] = [inputs[6], inputs[5]];
    assert.equal(evaluateRole(5, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    inputs[12].token.category[0] ^= 1;
    assert.equal(evaluateRole(5, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    inputs[12].token.capability = 'none';
    assert.equal(evaluateRole(5, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    inputs[12].token.commitment = inputs[12].token.commitment.subarray(1);
    assert.equal(evaluateRole(5, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    inputs[12].token.amount = 1n;
    assert.equal(evaluateRole(5, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    inputs[12].outpointTransactionHash = new Uint8Array(32).fill(0x5b);
    assert.equal(evaluateRole(5, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    inputs[11].outpointTransactionHash = new Uint8Array(32).fill(0x5b);
    assert.equal(evaluateRole(5, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    inputs[5].outpointIndex = 5;
    assert.equal(evaluateRole(5, inputs).accepted, false);
  }
  {
    const inputs = structuredClone(baseInputs);
    inputs[11].lockingBytecode = encodeLockingBytecodeP2sh32(
      hash256(Uint8Array.from([0x52])),
    );
    assert.equal(evaluateRole(5, inputs).accepted, false);
  }
});

test('compiled frame codec rejects aliases, alternate pushes, and invalid lengths', () => {
  assert.equal(input0 >= (1n << 127n), true);
  const maximum = (1n << 128n) - 1n;
  const alternating = BigInt(`0x${'aa'.repeat(16)}`);
  const highBitMetrics = [];
  for (const [high0, high1] of [
    [1n << 127n, maximum],
    [maximum, maximum],
    [maximum, 0n],
    [0n, maximum],
    [alternating, maximum ^ alternating],
  ]) {
    const highTrace = computeDirectV2ExactMsm(
      verificationKey,
      high0,
      high1,
    );
    for (let windowIndex = 0; windowIndex < 3; windowIndex += 1) {
      const roleIndex = 5 + windowIndex;
      let highInputs = replaceRoleStatePushIn(
        baseInputs,
        roleIndex,
        encodeDirectV2MsmState(highTrace.states[windowIndex]),
      );
      highInputs = replaceRoleStatePushIn(
        highInputs,
        roleIndex + 1,
        encodeDirectV2MsmState(highTrace.states[windowIndex + 1]),
      );
      const highOutcome = evaluateRole(roleIndex, highInputs);
      const highLoosenedOutcome = evaluateRole(
        roleIndex,
        highInputs,
        createLoosenedVm(),
      );
      highBitMetrics.push({
        role: roleIndex,
        input0: `0x${high0.toString(16).padStart(32, '0')}`,
        input1: `0x${high1.toString(16).padStart(32, '0')}`,
        operationCost: highLoosenedOutcome.operationCost,
      });
      assert.equal(
        highOutcome.accepted,
        true,
        `high-bit role ${roleIndex} frame ${high0.toString(16)}/${high1.toString(16)} rejected: ${JSON.stringify({
          real: highOutcome,
          loosened: highLoosenedOutcome,
        })}`,
      );
    }
  }
  console.log(JSON.stringify({ highBitMsm0: highBitMetrics }));

  const valid = Buffer.from(encodeDirectV2MsmState(trace.states[1]));
  const noncanonicalIdentity = Buffer.from(valid);
  writeBe(noncanonicalIdentity, 0, 32, 7n);
  writeBe(noncanonicalIdentity, 32, 32, 9n);
  writeBe(noncanonicalIdentity, 64, 32, 0n);
  assert.equal(evaluateRole(6, replaceRoleStatePush(6, noncanonicalIdentity)).accepted, false);

  const identityAlias = Buffer.from(valid);
  writeBe(identityAlias, 0, 32, 0n);
  writeBe(identityAlias, 32, 32, 1n);
  writeBe(identityAlias, 64, 32, 1n);
  assert.equal(evaluateRole(6, replaceRoleStatePush(6, identityAlias)).accepted, false);

  const fieldAlias = Buffer.from(valid);
  writeBe(fieldAlias, 0, 32, BN254_BASE_FIELD);
  assert.equal(evaluateRole(6, replaceRoleStatePush(6, fieldAlias)).accepted, false);

  assert.equal(
    evaluateRole(6, replaceRoleStatePush(6, valid.subarray(0, 127))).accepted,
    false,
  );
  assert.equal(
    evaluateRole(6, replaceRoleStatePush(6, Buffer.concat([valid, Buffer.from([0])]))).accepted,
    false,
  );

  const nonminimalPush = Buffer.concat([
    Buffer.from([0x4d, 0x80, 0x00]),
    valid,
  ]);
  assert.equal(
    evaluateRole(6, replaceRoleStatePush(6, valid, nonminimalPush)).accepted,
    false,
  );
});
