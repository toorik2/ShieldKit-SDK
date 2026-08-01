import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  bigIntToCompactUint,
  encodeTransactionOutput,
} from '@bitauth/libauth';

import {
  parseV2RawTransaction,
} from './network-gate.mjs';
import {
  assertV2VmResourceMetrics,
  canonicalizeV2Evidence,
  evaluateV2RawTransactionInputs,
  inspectV2LocalVmEvidence,
  projectV2LocalVmEvidenceTelemetry,
} from './vm-evidence.mjs';
import {
  createV2InputRoleLayout,
  transactionId,
} from './transaction-policy.mjs';
import {
  buildRawTransaction,
  createFixtureEvidence,
  fixtureOutpoints,
  fixtureSourceTransactions,
  pushOnlyUnlockAtSize,
  rawTransactionAtSize,
  sourceOutputBytes,
} from './v2-test-fixtures.mjs';

const hasCode = (code) => (error) => error?.code === code;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const hash = (value) => createHash('sha256').update(value).digest('hex');

function recommit(value) {
  const { evidenceHash: ignored, ...core } = value;
  return Buffer.from(
    canonicalizeV2Evidence({
      ...core,
      evidenceHash: createHash('sha256')
        .update(canonicalizeV2Evidence(core))
        .digest('hex'),
    }),
    'utf8',
  );
}

function mutateEvidence(bytes, mutate) {
  const value = JSON.parse(Buffer.from(bytes).toString('utf8'));
  mutate(value);
  return recommit(value);
}

const u32 = (value) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
};

function genericSourceTransaction({
  index,
  lockingBytecode = Buffer.from([0x51]),
  valueSatoshis = 100_000n,
}) {
  return Buffer.concat([
    u32(2),
    bigIntToCompactUint(1n),
    Buffer.alloc(32, index + 1),
    u32(index),
    bigIntToCompactUint(0n),
    u32(0xffff_ffff),
    bigIntToCompactUint(1n),
    Buffer.from(encodeTransactionOutput({
      valueSatoshis,
      lockingBytecode,
    })),
    u32(index + 1),
  ]).toString('hex');
}

function genericResolvedTransaction({
  lockingBytecodes,
  unlockingBytecodes = lockingBytecodes.map(() => Buffer.alloc(0)),
  outputLockingBytecode = Buffer.alloc(50, 0x51),
  outputValueSatoshis =
    BigInt(lockingBytecodes.length * 100_000) - 1_000n,
  duplicateOutpoint = false,
  vouts = lockingBytecodes.map(() => 0),
} = {}) {
  const sourceTransactionHexes = lockingBytecodes.map(
    (lockingBytecode, index) =>
      genericSourceTransaction({ index, lockingBytecode }),
  );
  const pieces = [
    u32(2),
    bigIntToCompactUint(BigInt(lockingBytecodes.length)),
  ];
  for (let index = 0; index < lockingBytecodes.length; index += 1) {
    const sourceIndex = duplicateOutpoint && index === 1 ? 0 : index;
    pieces.push(
      Buffer.from(
        transactionId(
          Buffer.from(sourceTransactionHexes[sourceIndex], 'hex'),
        ),
        'hex',
      ).reverse(),
      u32(vouts[index]),
      bigIntToCompactUint(BigInt(unlockingBytecodes[index].length)),
      Buffer.from(unlockingBytecodes[index]),
      u32(0xffff_ffff),
    );
  }
  pieces.push(
    bigIntToCompactUint(1n),
    Buffer.from(encodeTransactionOutput({
      valueSatoshis: outputValueSatoshis,
      lockingBytecode: outputLockingBytecode,
    })),
    u32(0),
  );
  return Object.freeze({
    rawTransactionHex: Buffer.concat(pieces).toString('hex'),
    sourceTransactionHexes: Object.freeze(
      duplicateOutpoint
        ? [
            sourceTransactionHexes[0],
            sourceTransactionHexes[0],
            ...sourceTransactionHexes.slice(2),
          ]
        : sourceTransactionHexes,
    ),
  });
}

function genericResolvedTransactionAtSize(sizeBytes) {
  for (
    let lockingBytes = Math.max(0, sizeBytes - 100);
    lockingBytes <= sizeBytes;
    lockingBytes += 1
  ) {
    const value = genericResolvedTransaction({
      lockingBytecodes: [Buffer.from([0x51])],
      outputLockingBytecode: Buffer.alloc(lockingBytes, 0x61),
    });
    if (value.rawTransactionHex.length / 2 === sizeBytes) return value;
  }
  throw new Error(`could not construct generic transaction at ${sizeBytes} bytes`);
}

test('fresh raw evaluator accepts arbitrary input counts without assigning roles', () => {
  for (const inputCount of [1, 2, 4, 11]) {
    const closure = genericResolvedTransaction({
      lockingBytecodes: Array.from(
        { length: inputCount },
        () => Buffer.from([0x51]),
      ),
    });
    const result = evaluateV2RawTransactionInputs(closure);
    assert.deepEqual(
      Object.keys(result).sort(),
      [
        'allInputsAccepted',
        'inputs',
        'rawTransactionSha256',
        'sourceTransactionSha256s',
        'transactionId',
      ],
    );
    assert.equal(result.allInputsAccepted, true);
    assert.equal(result.inputs.length, inputCount);
    assert.deepEqual(
      result.inputs.map((input) => input.index),
      Array.from({ length: inputCount }, (_, index) => index),
    );
    for (const input of result.inputs) {
      assert.deepEqual(
        Object.keys(input).sort(),
        [
          'accepted',
          'error',
          'index',
          'metrics',
          'sourceOutputSha256',
          'unlockingBytecodeSha256',
        ],
      );
      assert.equal(input.accepted, true);
      assert.equal(input.error, null);
      assert.equal(Object.hasOwn(input, 'role'), false);
      assert.equal(Object.hasOwn(input, 'q07Qualified'), false);
    }
    assert.equal(
      result.rawTransactionSha256,
      hash(Buffer.from(closure.rawTransactionHex, 'hex')),
    );
    assert.deepEqual(
      result.sourceTransactionSha256s,
      closure.sourceTransactionHexes.map((raw) =>
        hash(Buffer.from(raw, 'hex'))),
    );
    assert.equal(
      result.transactionId,
      transactionId(Buffer.from(closure.rawTransactionHex, 'hex')),
    );
    assert.ok(Object.isFrozen(result));
    assert.ok(Object.isFrozen(result.inputs));
    assert.ok(Object.isFrozen(result.sourceTransactionSha256s));
    assert.ok(result.inputs.every((input) =>
      Object.isFrozen(input) && Object.isFrozen(input.metrics)));
  }
  const closure = genericResolvedTransaction({
    lockingBytecodes: [Buffer.from([0x51])],
  });
  assert.throws(
    () => evaluateV2RawTransactionInputs({
      ...closure,
      carrierCount: 1,
    }),
    hasCode('INVALID_VM_EVIDENCE'),
  );
});

test('fresh raw evaluator attributes ordinary script rejection and still evaluates every input', () => {
  const closure = genericResolvedTransaction({
    lockingBytecodes: [
      Buffer.from([0x51]),
      Buffer.from([0x00]),
      Buffer.from([0x51]),
    ],
  });
  const result = evaluateV2RawTransactionInputs(closure);
  assert.equal(result.allInputsAccepted, false);
  assert.deepEqual(
    result.inputs.map((input) => input.accepted),
    [true, false, true],
  );
  assert.equal(result.inputs[0].error, null);
  assert.equal(typeof result.inputs[1].error, 'string');
  assert.notEqual(result.inputs[1].error.length, 0);
  assert.equal(result.inputs[2].error, null);
  for (const input of result.inputs) {
    assert.match(input.metrics.operationCost, DECIMAL);
    assert.match(input.metrics.maximumOperationCost, DECIMAL);
    assert.match(input.sourceOutputSha256, /^[0-9a-f]{64}$/);
    assert.match(input.unlockingBytecodeSha256, /^[0-9a-f]{64}$/);
  }

  const wholeTransactionReject = evaluateV2RawTransactionInputs(
    genericResolvedTransaction({
      lockingBytecodes: [Buffer.from([0x51])],
      outputValueSatoshis: 100_001n,
    }),
  );
  assert.equal(
    wholeTransactionReject.inputs[0].accepted,
    true,
    'the input script is independently accepted',
  );
  assert.equal(
    wholeTransactionReject.allInputsAccepted,
    false,
    'vm.verify rejection participates in allInputsAccepted',
  );
});

test('fresh raw evaluator requires the complete ordered source-transaction closure', () => {
  const closure = genericResolvedTransaction({
    lockingBytecodes: [
      Buffer.from([0x51]),
      Buffer.from([0x51]),
      Buffer.from([0x51]),
    ],
  });
  for (const sourceTransactionHexes of [
    closure.sourceTransactionHexes.slice(0, -1),
    [...closure.sourceTransactionHexes, closure.sourceTransactionHexes[0]],
    Object.assign(new Array(3), {
      0: closure.sourceTransactionHexes[0],
      2: closure.sourceTransactionHexes[2],
    }),
  ]) {
    assert.throws(
      () => evaluateV2RawTransactionInputs({
        rawTransactionHex: closure.rawTransactionHex,
        sourceTransactionHexes,
      }),
      hasCode('SOURCE_TRANSACTION_CLOSURE_REQUIRED'),
    );
  }
});

test('fresh raw evaluator rejects duplicate spending outpoints before execution', () => {
  const closure = genericResolvedTransaction({
    lockingBytecodes: [
      Buffer.from([0x51]),
      Buffer.from([0x51]),
    ],
    duplicateOutpoint: true,
  });
  assert.throws(
    () => evaluateV2RawTransactionInputs(closure),
    hasCode('DUPLICATE_INPUT_OUTPOINT'),
  );
});

test('fresh raw evaluator enforces exact generic transaction and unlocking hard limits', () => {
  const exactTransaction = genericResolvedTransactionAtSize(100_000);
  const exactResult = evaluateV2RawTransactionInputs(exactTransaction);
  assert.equal(exactResult.inputs.length, 1);
  assert.throws(
    () => evaluateV2RawTransactionInputs(
      genericResolvedTransactionAtSize(100_001),
    ),
    hasCode('TRANSACTION_SIZE_LIMIT'),
  );

  const exactUnlock = genericResolvedTransaction({
    lockingBytecodes: [Buffer.from([0x51])],
    unlockingBytecodes: [Buffer.alloc(10_000, 0x61)],
  });
  const exactUnlockResult =
    evaluateV2RawTransactionInputs(exactUnlock);
  assert.equal(exactUnlockResult.inputs.length, 1);
  assert.throws(
    () => evaluateV2RawTransactionInputs(
      genericResolvedTransaction({
        lockingBytecodes: [Buffer.from([0x51])],
        unlockingBytecodes: [Buffer.alloc(10_001, 0x61)],
      }),
    ),
    hasCode('UNLOCKING_BYTECODE_LIMIT'),
  );
});

test('fresh raw evaluator authenticates each source txid and vout', () => {
  const closure = genericResolvedTransaction({
    lockingBytecodes: [
      Buffer.from([0x51]),
      Buffer.from([0x51]),
    ],
  });
  assert.throws(
    () => evaluateV2RawTransactionInputs({
      rawTransactionHex: closure.rawTransactionHex,
      sourceTransactionHexes: [
        closure.sourceTransactionHexes[1],
        closure.sourceTransactionHexes[0],
      ],
    }),
    hasCode('SOURCE_TRANSACTION_MISMATCH'),
  );
  const badVout = genericResolvedTransaction({
    lockingBytecodes: [
      Buffer.from([0x51]),
      Buffer.from([0x51]),
    ],
    vouts: [1, 0],
  });
  assert.throws(
    () => evaluateV2RawTransactionInputs(badVout),
    hasCode('SOURCE_OUTPOINT_MISMATCH'),
  );
});

// These validate the serialized evidence boundary only. The fixture records do
// not claim execution by a live BCH node or independently qualify a VM result.
test('canonical VM evidence supports exact N=7/10 and N=10/13 rolling role layouts', () => {
  for (const carrierCount of [7, 10]) {
    const rawTransactionHex = buildRawTransaction({ carrierCount });
    const evidence = createFixtureEvidence({
      rawTransactionHex,
      carrierCount,
    });
    const inspected = inspectV2LocalVmEvidence(evidence);
    const layout = createV2InputRoleLayout(carrierCount);
    assert.equal(inspected.carrierCount, carrierCount);
    assert.equal(inspected.inputs.length, carrierCount + 3);
    assert.deepEqual(inspected.inputRoleLayout, layout);
    assert.deepEqual(
      inspected.inputs.map((input) => input.role),
      layout,
    );
    assert.ok(inspected.inputs.every((input) => input.accepted));
    assert.equal(
      inspected.inputs[carrierCount + 1].sourceOutput.token.nft
        .capability,
      'mutable',
    );
    assert.equal(
      inspected.inputs[carrierCount + 1].sourceOutput.token.nft
        .commitmentHex.length,
      256,
    );
    assert.equal(
      inspected.inputs[carrierCount + 2].sourceOutput.token,
      null,
    );
    assert.match(
      inspected.inputs[carrierCount + 2].sourceOutput.lockingBytecodeHex,
      /^76a914[0-9a-f]{40}88ac$/,
    );
  }
});

test('state category uses frozen token-prefix byte order and carries all 128 state bytes', () => {
  const instanceId =
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  const carrierCount = 7;
  const sourceOutputs = sourceOutputBytes({ carrierCount, instanceId });
  const sourceTransactionHexes = fixtureSourceTransactions({
    carrierCount,
    sourceOutputs,
  });
  const rawTransactionHex = buildRawTransaction({
    carrierCount,
    outpoints: fixtureOutpoints({
      carrierCount,
      sourceTransactionHexes,
    }),
  });
  const inspected = inspectV2LocalVmEvidence(createFixtureEvidence({
    rawTransactionHex,
    carrierCount,
    instanceId,
    sourceTransactionHexes,
  }));
  const token =
    inspected.inputs[carrierCount + 1].sourceOutput.token;
  assert.equal(token.categoryWire, instanceId);
  assert.equal(token.nft.commitmentHex.length, 256);
});

test('public VM telemetry projects every exact verdict and metric without source bytes', () => {
  const bytes = createFixtureEvidence({ rawTransactionHex: buildRawTransaction() });
  const telemetry = projectV2LocalVmEvidenceTelemetry(bytes);
  assert.equal(telemetry.schema, 'shieldkit-v2-local-vm-telemetry-v1');
  assert.equal(telemetry.allInputsAccepted, true);
  assert.ok(telemetry.inputs.length > 0);
  for (const input of telemetry.inputs) {
    assert.deepEqual(Object.keys(input).sort(), ['accepted', 'index', 'metrics']);
    assert.equal(input.accepted, true);
    assert.match(input.metrics.operationCost, DECIMAL);
    assert.equal(Object.hasOwn(input, 'sourceTransaction'), false);
    assert.equal(Object.hasOwn(input, 'unlockingBytecode'), false);
  }
});

test('VM evidence is canonical and fails closed on forged hash or partial acceptance', () => {
  const evidence = createFixtureEvidence({
    rawTransactionHex: buildRawTransaction(),
  });
  const forged = Buffer.from(evidence);
  forged[forged.length - 2] =
    forged[forged.length - 2] === 0x30 ? 0x31 : 0x30;
  assert.throws(
    () => inspectV2LocalVmEvidence(forged),
    (error) =>
      ['VM_EVIDENCE_HASH_MISMATCH', 'INVALID_VM_EVIDENCE'].includes(
        error?.code,
      ),
  );
  const partial = mutateEvidence(evidence, (value) => {
    value.allInputsAccepted = false;
  });
  assert.throws(
    () => inspectV2LocalVmEvidence(partial),
    hasCode('PARTIAL_VM_ACCEPTANCE'),
  );
  const noncanonical = Buffer.from(` ${evidence.toString('utf8')}`, 'utf8');
  assert.throws(
    () => inspectV2LocalVmEvidence(noncanonical),
    hasCode('NON_CANONICAL_VM_EVIDENCE'),
  );
});

test('VM evidence rejects missing, duplicate, reordered, ordinal, and carrier-count role-layout mutations', () => {
  const evidence = createFixtureEvidence({
    rawTransactionHex: buildRawTransaction(),
  });
  const mutations = [
    (value) => {
      value.inputRoleLayout.pop();
    },
    (value) => {
      value.inputRoleLayout[1] = {
        ...value.inputRoleLayout[0],
      };
    },
    (value) => {
      [
        value.inputRoleLayout[0],
        value.inputRoleLayout[1],
      ] = [
        value.inputRoleLayout[1],
        value.inputRoleLayout[0],
      ];
    },
    (value) => {
      value.inputRoleLayout[3].ordinal = 2;
    },
    (value) => {
      value.carrierCount = 10;
    },
  ];
  for (const mutate of mutations) {
    assert.throws(
      () => inspectV2LocalVmEvidence(mutateEvidence(evidence, mutate)),
      hasCode('INPUT_ROLE_LAYOUT_MISMATCH'),
    );
  }
  const sourceTransactions = fixtureSourceTransactions();
  const outpoints = fixtureOutpoints({
    sourceTransactionHexes: sourceTransactions,
  });
  outpoints[1] = { ...outpoints[0] };
  assert.throws(
    () => parseV2RawTransaction(buildRawTransaction({ outpoints })),
    hasCode('DUPLICATE_INPUT_OUTPOINT'),
  );
});

test('VM evidence rejects role, outpoint, source-fact, and state-token substitutions even with a recomputed self-hash', () => {
  const rawTransactionHex = buildRawTransaction();
  const evidence = createFixtureEvidence({ rawTransactionHex });
  const role = mutateEvidence(evidence, (value) => {
    value.inputs[7].role = {
      index: 7,
      kind: 'state',
      ordinal: null,
    };
  });
  assert.throws(
    () => inspectV2LocalVmEvidence(role),
    hasCode('INPUT_ROLE_LAYOUT_MISMATCH'),
  );
  const outpoint = mutateEvidence(evidence, (value) => {
    value.inputs[4].outpoint.txid = 'ab'.repeat(32);
  });
  assert.throws(
    () => inspectV2LocalVmEvidence(outpoint),
    hasCode('SOURCE_OUTPOINT_MISMATCH'),
  );
  const tokenFacts = mutateEvidence(evidence, (value) => {
    value.inputs[8].sourceOutput.token.categoryWire = 'cd'.repeat(32);
  });
  assert.throws(
    () => inspectV2LocalVmEvidence(tokenFacts),
    hasCode('SOURCE_OUTPUT_FACT_MISMATCH'),
  );
  const substitutedSources = sourceOutputBytes({
    stateCategoryWire: 'ef'.repeat(32),
  });
  const substitutedSourceTransactions = fixtureSourceTransactions({
    sourceOutputs: substitutedSources,
  });
  const substitutedRawTransaction = buildRawTransaction({
    outpoints: fixtureOutpoints({
      sourceTransactionHexes: substitutedSourceTransactions,
    }),
  });
  assert.throws(
    () =>
      createFixtureEvidence({
        rawTransactionHex: substitutedRawTransaction,
        sourceTransactionHexes: substitutedSourceTransactions,
      }),
    hasCode('STATE_TOKEN_MISMATCH'),
  );
});

test('standard transaction and unlocking-bytecode ceilings accept equality and reject one byte over', () => {
  assert.equal(
    parseV2RawTransaction(rawTransactionAtSize(100_000)).sizeBytes,
    100_000,
  );
  assert.throws(
    () => parseV2RawTransaction(rawTransactionAtSize(100_001)),
    hasCode('TRANSACTION_SIZE_LIMIT'),
  );
  const exactSourceOutputs = sourceOutputBytes();
  exactSourceOutputs[0] = Buffer.from(
    encodeTransactionOutput({
      valueSatoshis: 100_000n,
      lockingBytecode: Buffer.from([0x75, 0x51]),
    }),
  );
  const exactSourceTransactions = fixtureSourceTransactions({
    sourceOutputs: exactSourceOutputs,
  });
  const exactUnlock = buildRawTransaction({
    unlockingBytecodes: [
      pushOnlyUnlockAtSize(10_000),
      ...Array.from({ length: 9 }, () => Buffer.alloc(0)),
    ],
    outpoints: fixtureOutpoints({
      sourceTransactionHexes: exactSourceTransactions,
    }),
  });
  assert.equal(
    parseV2RawTransaction(exactUnlock).inputs[0].unlockingBytecodeBytes,
    10_000,
  );
  assert.equal(
    inspectV2LocalVmEvidence(
      createFixtureEvidence({
        rawTransactionHex: exactUnlock,
        sourceTransactionHexes: exactSourceTransactions,
      }),
    ).inputs[0].unlockingBytecodeBytes,
    10_000,
  );
  const overUnlock = buildRawTransaction({
    unlockingBytecodes: [
      Buffer.alloc(10_001, 0x51),
      ...Array.from({ length: 9 }, () => Buffer.alloc(0)),
    ],
  });
  assert.throws(
    () => parseV2RawTransaction(overUnlock),
    hasCode('UNLOCKING_BYTECODE_LIMIT'),
  );
});

test('VM execution is rerun exactly; resource ceilings accept equality and reject any overage or forged maximum', () => {
  const rawTransactionHex = buildRawTransaction();
  const evidence = createFixtureEvidence({ rawTransactionHex });
  const evaluated = inspectV2LocalVmEvidence(evidence);
  const metrics = evaluated.inputs[0].metrics;
  const equalityArithmeticCost =
    BigInt(metrics.maximumOperationCost) -
    100n -
    BigInt(metrics.maximumHashDigestIterations) * 192n -
    BigInt(metrics.maximumSignatureCheckCount) * 26_000n;
  const equality = assertV2VmResourceMetrics(
    {
      ...metrics,
      arithmeticCost: equalityArithmeticCost.toString(),
      evaluatedInstructionCount: '1',
      operationCost: metrics.maximumOperationCost,
      hashDigestIterations: metrics.maximumHashDigestIterations,
      signatureCheckCount: metrics.maximumSignatureCheckCount,
      stackPushedBytes: '0',
    },
    { inputIndex: 0, unlockingBytecodeBytes: 0 },
  );
  assert.equal(
    equality.operationCost,
    equality.maximumOperationCost,
  );
  for (const [field, maximum] of [
    ['operationCost', 'maximumOperationCost'],
    ['hashDigestIterations', 'maximumHashDigestIterations'],
    ['signatureCheckCount', 'maximumSignatureCheckCount'],
  ]) {
    assert.throws(
      () =>
        assertV2VmResourceMetrics(
          {
            ...metrics,
            [field]: String(BigInt(metrics[maximum]) + 1n),
          },
          { inputIndex: 0, unlockingBytecodeBytes: 0 },
        ),
      hasCode('VM_RESOURCE_LIMIT'),
      `${field} must fail above 100%`,
    );
  }
  assert.throws(
    () =>
      assertV2VmResourceMetrics(
        {
          ...metrics,
          maximumOperationCost: String(
            BigInt(metrics.maximumOperationCost) + 1n,
          ),
        },
        { inputIndex: 0, unlockingBytecodeBytes: 0 },
      ),
    hasCode('VM_RESOURCE_PROFILE_MISMATCH'),
  );
  assert.throws(
    () =>
      assertV2VmResourceMetrics(
        {
          ...metrics,
          arithmeticCost: String(
            BigInt(metrics.arithmeticCost) + 1n,
          ),
        },
        { inputIndex: 0, unlockingBytecodeBytes: 0 },
      ),
    hasCode('VM_RESOURCE_ACCOUNTING_MISMATCH'),
  );
  const selfConsistentForgery = mutateEvidence(evidence, (value) => {
    value.inputs[0].metrics.arithmeticCost = String(
      BigInt(value.inputs[0].metrics.arithmeticCost) + 1n,
    );
    value.inputs[0].metrics.operationCost = String(
      BigInt(value.inputs[0].metrics.operationCost) + 1n,
    );
  });
  assert.throws(
    () => inspectV2LocalVmEvidence(selfConsistentForgery),
    hasCode('VM_METRICS_MISMATCH'),
  );
});
