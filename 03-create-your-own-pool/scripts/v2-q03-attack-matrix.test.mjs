/* TEST-ONLY, nonqualifying matrix/delta parser coverage. */
import assert from 'node:assert/strict';
import test from 'node:test';

import { encodeTransactionOutput } from '@bitauth/libauth';

import {
  parseSerializedSourceOutput,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  buildV2Q03AttackMatrix,
  digestV2Q03AttackMatrix,
  validateV2Q03AttackMatrixDelta,
  v2Q03AttackMatrixSha256,
  V2Q03AttackMatrixError,
} from './v2-q03-attack-matrix.mjs';

const roles = Object.freeze([
  'exec0',
  'exec1',
  'exec2',
  'exec3',
  'exec4',
  'msm5',
  'msm6',
  'msm7',
  'fused-q-genesis8',
  'terminal9',
  'binding',
  'state',
  'funding',
]);
const stateNft = Object.freeze({
  amount: '1',
  categoryWire: 'a'.repeat(64),
  nft: Object.freeze({
    capability: 'mutable',
    commitmentHex: '11',
  }),
});

function encodeToken(token) {
  return token === null
    ? undefined
    : {
        amount: BigInt(token.amount),
        category: Buffer.from(token.categoryWire, 'hex'),
        nft: token.nft === null
          ? undefined
          : {
              capability: token.nft.capability,
              commitment: Buffer.from(token.nft.commitmentHex, 'hex'),
            },
      };
}

function output(
  valueSatoshis = '1',
  lockingBytecodeHex = '51',
  token = null,
) {
  const serializedHex = Buffer.from(encodeTransactionOutput({
    lockingBytecode: Buffer.from(lockingBytecodeHex, 'hex'),
    token: encodeToken(token),
    valueSatoshis: BigInt(valueSatoshis),
  })).toString('hex');
  const parsed = parseSerializedSourceOutput(serializedHex);
  return {
    lockingBytecodeHex: parsed.lockingBytecodeHex,
    serializedHex: parsed.serializedHex,
    sha256: parsed.sha256,
    token: parsed.token,
    tokenPrefixHex: parsed.tokenPrefixHex,
    valueSatoshis: parsed.valueSatoshis.toString(),
  };
}

function source(index, token = null) {
  const normalized = output('1', '51', token);
  return {
    output: normalized,
    serializedOutputHex: normalized.serializedHex,
    sourceTransaction: `source-${index}`,
  };
}

function replaceSourceOutput(value, index, token) {
  const normalized = output('1', '51', token);
  value.sources[index].output = normalized;
  value.sources[index].serializedOutputHex = normalized.serializedHex;
}

function baseline() {
  const inputs = roles.map((_, index) => ({
    outpoint: {
      txid: index.toString(16).padStart(2, '0').repeat(32),
      vout: 0,
    },
    sequence: 0,
    unlockingBytecodeHex:
      index === 8 ? `4de001${'01'.repeat(480)}51` : '51',
  }));
  const sources = roles.map((_, index) => ({
    ...source(index, index === 11 ? stateNft : null),
    sourceTransaction:
      index <= 11 ? 'rolling-parent-base' : 'funding-parent',
  }));
  return {
    sources,
    transaction: {
      inputs,
      outputs: Array.from(
        { length: 13 },
        (_, index) =>
          output('1', `51${index.toString(16).padStart(2, '0')}`),
      ),
    },
  };
}

function moveRollingParent(value) {
  for (let index = 0; index <= 11; index += 1) {
    value.transaction.inputs[index].outpoint.txid = 'f'.repeat(64);
    value.sources[index].sourceTransaction = 'rolling-parent-mutant';
  }
}

function mutateSourceCategory(
  value,
  index,
  categoryWire = 'b'.repeat(64),
) {
  moveRollingParent(value);
  replaceSourceOutput(value, index, {
    ...(value.sources[index].output.token ?? stateNft),
    categoryWire,
  });
}

function validate(caseId, mutant) {
  return validateV2Q03AttackMatrixDelta({
    action: 'deposit',
    baseline: baseline(),
    caseId,
    mutant,
  });
}

function expectReject(caseId, mutate) {
  const value = baseline();
  mutate(value);
  assert.throws(
    () => validate(caseId, value),
    V2Q03AttackMatrixError,
  );
}

test('TEST-ONLY matrix has exact deterministic 73/action and 219 total ordering/digest', () => {
  const matrix = buildV2Q03AttackMatrix();
  assert.equal(matrix.length, 219);
  assert.equal(
    matrix.filter((entry) => entry.action === 'deposit').length,
    73,
  );
  assert.equal(
    matrix.filter((entry) => entry.action === 'transfer').length,
    73,
  );
  assert.equal(
    matrix.filter((entry) => entry.action === 'withdrawal').length,
    73,
  );
  assert.equal(matrix[0].caseId, 'deposit:standalone-burn:exec0');
  assert.equal(
    matrix[72].caseId,
    'deposit:identity-branch-substitution:input8',
  );
  assert.equal(
    digestV2Q03AttackMatrix(matrix),
    v2Q03AttackMatrixSha256,
  );
});

test('TEST-ONLY matrix has all ten late affine pairs and no identity swaps', () => {
  const swaps = buildV2Q03AttackMatrix().filter(
    (entry) =>
      entry.action === 'deposit' && entry.family === 'role-swap',
  );
  assert.equal(swaps.length, 10);
  assert.deepEqual(
    swaps.map((entry) => `${entry.leftRole}/${entry.rightRole}`),
    [
      'msm5/msm6',
      'msm5/msm7',
      'msm5/fused-q-genesis8',
      'msm5/terminal9',
      'msm6/msm7',
      'msm6/fused-q-genesis8',
      'msm6/terminal9',
      'msm7/fused-q-genesis8',
      'msm7/terminal9',
      'fused-q-genesis8/terminal9',
    ],
  );
  assert.ok(swaps.every((entry) => entry.branch === 'affine'));
});

test('TEST-ONLY representative typed deltas cover every matrix family', () => {
  let value = baseline();
  value.transaction.outputs[1] = output(
    '0',
    value.transaction.outputs[1].lockingBytecodeHex,
  );
  assert.equal(
    validate('deposit:standalone-burn:exec0', value).nonqualifying,
    true,
  );

  value = baseline();
  value.transaction.inputs.splice(0, 1);
  value.sources.splice(0, 1);
  value.transaction.outputs.splice(1, 1);
  validate('deposit:partial-bundle:exec0', value);

  value = baseline();
  value.transaction.inputs[0].outpoint.txid = 'f'.repeat(64);
  value.sources[0].sourceTransaction = 'other-parent';
  validate('deposit:mixed-parent:exec0', value);

  value = baseline();
  mutateSourceCategory(value, 11);
  validate('deposit:fake-category:state', value);

  value = baseline();
  moveRollingParent(value);
  replaceSourceOutput(value, 0, stateNft);
  validate('deposit:duplicate-state-nft:exec0', value);

  value = baseline();
  value.transaction.inputs[12].outpoint.txid = 'f'.repeat(64);
  value.sources[12].sourceTransaction = 'funding-parent-mutant';
  replaceSourceOutput(value, 12, stateNft);
  validate('deposit:duplicate-state-nft:funding', value);

  value = baseline();
  moveRollingParent(value);
  replaceSourceOutput(value, 11, {
    ...stateNft,
    nft: { ...stateNft.nft, capability: 'minting' },
  });
  validate('deposit:minting-authority:state', value);

  value = baseline();
  value.transaction.outputs[1] = output('1', '6a');
  validate('deposit:omitted-successor:exec0', value);

  value = baseline();
  value.transaction.inputs.splice(10, 1);
  value.sources.splice(10, 1);
  value.transaction.outputs.splice(11, 1);
  validate('deposit:altered-role-count:binding:missing', value);

  value = baseline();
  value.transaction.inputs.push({
    outpoint: { txid: 'e'.repeat(64), vout: 0 },
    sequence: 0,
    unlockingBytecodeHex: '51',
  });
  value.sources.push(source(99));
  validate('deposit:altered-role-count:funding:extra-input', value);

  value = baseline();
  value.transaction.outputs.push(output('0', '6a'));
  validate('deposit:altered-role-count:funding:extra-output', value);

  value = baseline();
  [value.transaction.inputs[5], value.transaction.inputs[6]] = [
    value.transaction.inputs[6],
    value.transaction.inputs[5],
  ];
  [value.sources[5], value.sources[6]] = [
    value.sources[6],
    value.sources[5],
  ];
  [value.transaction.outputs[6], value.transaction.outputs[7]] = [
    value.transaction.outputs[7],
    value.transaction.outputs[6],
  ];
  validate('deposit:role-swap:msm5:msm6:affine', value);

  value = baseline();
  const bytes = Buffer.from(
    value.transaction.inputs[8].unlockingBytecodeHex,
    'hex',
  );
  bytes.fill(0, 131, 195);
  value.transaction.inputs[8].unlockingBytecodeHex =
    bytes.toString('hex');
  validate('deposit:identity-branch-substitution:input8', value);
});

test('TEST-ONLY typed delta rejects undeclared closure drift and wrong identity offsets', () => {
  expectReject('deposit:standalone-burn:exec0', (value) => {
    value.transaction.outputs[1] = output(
      '0',
      value.transaction.outputs[1].lockingBytecodeHex,
    );
    value.transaction.outputs[2] = output(
      '0',
      value.transaction.outputs[2].lockingBytecodeHex,
    );
  });
  expectReject('deposit:mixed-parent:exec0', (value) => {
    value.transaction.inputs[0].outpoint.txid = 'f'.repeat(64);
    value.sources[0].sourceTransaction = 'other';
    value.sources[0].serializedOutputHex = 'drift';
  });
  expectReject('deposit:fake-category:state', (value) =>
    mutateSourceCategory(value, 0));
  expectReject('deposit:fake-category:state', (value) => {
    moveRollingParent(value);
    value.sources[11].output.token = {
      ...value.sources[11].output.token,
      categoryWire: 'b'.repeat(64),
    };
  });
  expectReject('deposit:role-swap:msm5:msm6:affine', (value) => {
    [value.transaction.inputs[5], value.transaction.inputs[6]] = [
      value.transaction.inputs[6],
      value.transaction.inputs[5],
    ];
  });
  expectReject(
    'deposit:identity-branch-substitution:input8',
    (value) => {
      const bytes = Buffer.from(
        value.transaction.inputs[8].unlockingBytecodeHex,
        'hex',
      );
      bytes.fill(0, 130, 194);
      value.transaction.inputs[8].unlockingBytecodeHex =
        bytes.toString('hex');
    },
  );

  const value = baseline();
  value.transaction.outputs[1] = output(
    '0',
    value.transaction.outputs[1].lockingBytecodeHex,
  );
  assert.throws(
    () => validateV2Q03AttackMatrixDelta({
      action: 'transfer',
      baseline: baseline(),
      caseId: 'deposit:standalone-burn:exec0',
      mutant: value,
    }),
    V2Q03AttackMatrixError,
  );
});
