import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { encodeTransactionOutput } from '@bitauth/libauth';

import {
  parseV2RawTransaction,
} from './network-gate.mjs';
import {
  assertV2VmResourceMetrics,
  canonicalizeV2Evidence,
  inspectV2LocalVmEvidence,
} from './vm-evidence.mjs';
import {
  createV2InputRoleLayout,
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
