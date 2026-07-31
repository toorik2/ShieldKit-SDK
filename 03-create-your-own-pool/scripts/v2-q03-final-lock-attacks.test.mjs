/* TEST-ONLY structural policy coverage. No fixture grants qualification. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  buildV2Q03AttackMatrix,
  v2Q03AttackMatrixSha256,
} from './v2-q03-attack-matrix.mjs';
import {
  parseV2Q03Arguments,
  revalidateV2Q03FinalLockAttacks,
  validateV2Q03BchnRejectionForTestOnly,
  validateV2Q03LocalAttributionForTestOnly,
  verifyV2Q03FinalLockAttacks,
  V2_Q03_RESULT_SCHEMA,
  V2Q03FinalLockAttacksError,
} from './v2-q03-final-lock-attacks.mjs';

const hash = (value) =>
  createHash('sha256').update(value).digest('hex');
const sha1 = (value) =>
  createHash('sha1').update(value).digest('hex');
const canonical = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');
const h = (label) => hash(Buffer.from(label));

const identity = Object.freeze({
  descriptorSha256: h('descriptor'),
  finalLocksSha256: h('locks'),
  instanceId: h('instance'),
  manifestSha256: h('manifest'),
  profileId: h('profile-id'),
  profileSha256: h('profile'),
  releaseBootstrapSha256: h('release-bootstrap'),
  releaseRootId: 'shieldkit-v2-final-r1',
  runtimeMaterialSha256: h('runtime'),
  sourceCommit: sha1('commit'),
  sourceTree: sha1('tree'),
  topologyId: 'pf10-fused-q-genesis-v1',
});

const roots = Object.freeze({
  authorityArtifactSha256: h('authority'),
  b02ResultSha256: h('b02'),
  corpusInventorySha256: h('corpus-inventory'),
  corpusSha256: h('corpus'),
  identity,
  laneInventorySha256: h('lane-inventory'),
  matrixSha256: v2Q03AttackMatrixSha256,
  transactionsManifestSha256: h('transactions-manifest'),
});

function expectedShape(entry) {
  if (entry.family === 'partial-bundle') {
    return {
      finalInputIndexes: Array.from(
        { length: 11 },
        (_, index) => index,
      ),
      mutantInputCount: 12,
    };
  }
  if (
    entry.family === 'altered-role-count'
    && entry.mode === 'missing'
  ) {
    const finalCount = entry.role === 'funding' ? 12 : 11;
    return {
      finalInputIndexes: Array.from(
        { length: finalCount },
        (_, index) => index,
      ),
      mutantInputCount: 12,
    };
  }
  return {
    finalInputIndexes: Array.from(
      { length: 12 },
      (_, index) => index,
    ),
    mutantInputCount:
      entry.family === 'altered-role-count'
      && entry.mode === 'extra-input'
        ? 14
        : 13,
  };
}

function resultFixture() {
  const matrix = buildV2Q03AttackMatrix();
  let runOrdinal = 0;
  const cases = matrix.map((entry, matrixOrdinal) => {
    const shape = expectedShape(entry);
    const mutantInputAcceptance = Array.from(
      { length: shape.mutantInputCount },
      () => true,
    );
    mutantInputAcceptance[0] = false;
    const lanes = [
      'maintainer',
      'bchn-mempool',
      'leanbch',
    ].map((role) => {
      const ordinal = runOrdinal;
      runOrdinal += 2;
      return {
        authorityId: `${role.replaceAll('-', '.')}.authority`,
        baselineEnvelopeSha256:
          h(`${entry.caseId}-${role}-baseline-envelope`),
        baselineRunId: h(`run-${ordinal}`),
        commandSha256: h(`${role}-command`),
        machineManifestSha256: h(`${role}-machine`),
        mutantEnvelopeSha256:
          h(`${entry.caseId}-${role}-mutant-envelope`),
        mutantRunId: h(`run-${ordinal + 1}`),
        pairWindowMilliseconds: 1000,
        role,
        toolSha256: h(`${role}-tool`),
      };
    });
    return {
      action: entry.action,
      baselineRawTransactionSha256:
        h(`${entry.action}-baseline-raw`),
      baselineTransactionId: h(`${entry.action}-baseline-txid`),
      caseId: entry.caseId,
      lanes,
      local: {
        baselineEvaluationSha256:
          h(`${entry.caseId}-baseline-evaluation`),
        baselineInputCount: 13,
        finalInputIndexes: shape.finalInputIndexes,
        finalRejectedInputIndexes: [0],
        mutantEvaluationSha256:
          h(`${entry.caseId}-mutant-evaluation`),
        mutantInputAcceptance,
        mutantInputCount: shape.mutantInputCount,
        nonFinalRejectedInputIndexes: [],
      },
      matrixOrdinal,
      mutantRawTransactionSha256: h(`${entry.caseId}-mutant-raw`),
      mutantTransactionId: h(`${entry.caseId}-mutant-txid`),
      sourceClosureSha256: h(`${entry.caseId}-source-closure`),
    };
  });
  return {
    schema: V2_Q03_RESULT_SCHEMA,
    status:
      'q03-qualified-final-lock-attacks-not-production-or-release',
    q03Qualified: true,
    production: false,
    releaseQualified: false,
    identity,
    authorityArtifactSha256: roots.authorityArtifactSha256,
    b02ResultSha256: roots.b02ResultSha256,
    corpusInventorySha256: roots.corpusInventorySha256,
    corpusSha256: roots.corpusSha256,
    laneInventorySha256: roots.laneInventorySha256,
    matrixSha256: roots.matrixSha256,
    transactionsManifestSha256:
      roots.transactionsManifestSha256,
    caseCount: cases.length,
    lanePairCount: cases.length * 3,
    laneRunCount: cases.length * 3 * 2,
    cases,
    attackSetSha256: hash(canonical(cases)),
  };
}

function metricRecord(overrides = {}) {
  return {
    arithmeticCost: '0',
    definedFunctions: '0',
    densityControlLength: '100',
    evaluatedInstructionCount: '1',
    hashDigestIterations: '0',
    maximumHashDigestIterations: '50',
    maximumOperationCost: '100',
    maximumSignatureCheckCount: '1',
    operationCost: '1',
    signatureCheckCount: '0',
    stackPushedBytes: '0',
    ...overrides,
  };
}

function localFixture() {
  const finalLock = '51';
  const fundingLock = '76a914' + '11'.repeat(20) + '88ac';
  const source = (lockingBytecodeHex) => ({
    output: { lockingBytecodeHex },
  });
  const inputs = Array.from({ length: 13 }, () => ({}));
  const baseline = {
    normalized: {
      sources: [
        ...Array.from({ length: 12 }, () => source(finalLock)),
        source(fundingLock),
      ],
    },
    transaction: { inputs },
  };
  const mutant = structuredClone(baseline);
  const baselineEvaluation = {
    allInputsAccepted: true,
    inputs: inputs.map((_, index) => ({
      accepted: true,
      error: null,
      index,
      metrics: metricRecord(),
    })),
  };
  const mutantEvaluation = structuredClone(baselineEvaluation);
  mutantEvaluation.allInputsAccepted = false;
  mutantEvaluation.inputs[0].accepted = false;
  mutantEvaluation.inputs[0].error =
    'mandatory-script-verify-flag-failed';
  return {
    baseline,
    baselineEvaluation,
    mutant,
    mutantEvaluation,
    settlementPins: {
      bindingLockingBytecode: Buffer.from(finalLock, 'hex'),
      stateLockingBytecode: Buffer.from('52', 'hex'),
      verifierCarriers: Array.from(
        { length: 10 },
        () => ({ lockingBytecode: Buffer.from(finalLock, 'hex') }),
      ),
    },
  };
}

test('Q-03 result replay requires independent roots and exact 219/657/1314 closure', () => {
  const result = resultFixture();
  const replay = revalidateV2Q03FinalLockAttacks(result, roots);
  assert.equal(replay.q03Qualified, true);
  assert.equal(replay.production, false);
  assert.equal(replay.releaseQualified, false);
  assert.equal(replay.caseCount, 219);
  assert.equal(replay.laneRunCount, 1314);
  assert.equal(replay.resultSha256, hash(canonical(result)));

  assert.throws(
    () => revalidateV2Q03FinalLockAttacks(result),
    V2Q03FinalLockAttacksError,
  );
  for (const key of [
    'authorityArtifactSha256',
    'b02ResultSha256',
    'corpusInventorySha256',
    'corpusSha256',
    'laneInventorySha256',
    'matrixSha256',
    'transactionsManifestSha256',
  ]) {
    assert.throws(
      () => revalidateV2Q03FinalLockAttacks(
        result,
        { ...roots, [key]: h(`wrong-${key}`) },
      ),
      V2Q03FinalLockAttacksError,
    );
  }
});

test('Q-03 result replay rejects reorder, relabel, topology, run, and hash drift', () => {
  const mutations = [
    (result) => {
      [result.cases[0], result.cases[1]] =
        [result.cases[1], result.cases[0]];
    },
    (result) => {
      result.cases[0].matrixOrdinal = 1;
    },
    (result) => {
      result.cases[0].local.mutantInputCount = 12;
      result.cases[0].local.mutantInputAcceptance.pop();
    },
    (result) => {
      result.cases[0].local.nonFinalRejectedInputIndexes = [12];
      result.cases[0].local.mutantInputAcceptance[12] = false;
    },
    (result) => {
      result.cases[0].lanes[0].mutantRunId =
        result.cases[0].lanes[0].baselineRunId;
    },
    (result) => {
      result.cases[1].lanes[0].baselineRunId =
        result.cases[0].lanes[0].baselineRunId;
    },
    (result) => {
      result.cases[0].lanes.pop();
    },
  ];
  for (const mutate of mutations) {
    const result = resultFixture();
    mutate(result);
    result.attackSetSha256 = hash(canonical(result.cases));
    assert.throws(
      () => revalidateV2Q03FinalLockAttacks(result, roots),
      V2Q03FinalLockAttacksError,
    );
  }
  const result = resultFixture();
  result.attackSetSha256 = h('invented-attack-set');
  assert.throws(
    () => revalidateV2Q03FinalLockAttacks(result, roots),
    V2Q03FinalLockAttacksError,
  );
});

test('Q-03 local attribution requires final-lock rejection and accepts every funding/extra input', () => {
  const fixture = localFixture();
  const result = validateV2Q03LocalAttributionForTestOnly(fixture);
  assert.deepEqual(result.finalRejectedInputIndexes, [0]);
  assert.deepEqual(result.nonFinalRejectedInputIndexes, []);

  let changed = localFixture();
  changed.mutantEvaluation.inputs[12].accepted = false;
  changed.mutantEvaluation.inputs[12].error = 'false';
  assert.throws(
    () => validateV2Q03LocalAttributionForTestOnly(changed),
    V2Q03FinalLockAttacksError,
  );

  changed = localFixture();
  changed.mutantEvaluation.inputs[0].accepted = true;
  changed.mutantEvaluation.inputs[0].error = null;
  assert.throws(
    () => validateV2Q03LocalAttributionForTestOnly(changed),
    V2Q03FinalLockAttacksError,
  );

  changed = localFixture();
  changed.mutantEvaluation.inputs[0].error =
    'maximum operation cost exceeded';
  assert.throws(
    () => validateV2Q03LocalAttributionForTestOnly(changed),
    V2Q03FinalLockAttacksError,
  );

  changed = localFixture();
  changed.mutantEvaluation.inputs[0].metrics.operationCost = '101';
  assert.throws(
    () => validateV2Q03LocalAttributionForTestOnly(changed),
    V2Q03FinalLockAttacksError,
  );
});

test('Q-03 BCHN policy accepts only explicit script/CashToken rejection classes', () => {
  const stdout = (reason, details = '') => ({
    result: [{
      allowed: false,
      ...(details === '' ? {} : { 'reject-details': details }),
      'reject-reason': reason,
      txid: h(reason),
    }],
  });
  for (const reason of [
    'mandatory-script-verify-flag-failed',
    'non-mandatory-script-verify-flag',
    'bad-txns-token-invalid-category',
  ]) {
    assert.equal(
      validateV2Q03BchnRejectionForTestOnly(stdout(reason)),
      true,
    );
  }
  for (const reason of [
    'bad-txns-inputs-missingorspent',
    'txn-mempool-conflict',
    'min relay fee not met',
    'dust',
    'nonstandard-scriptpubkey',
    'bad-txns-vout-negative',
  ]) {
    assert.throws(
      () => validateV2Q03BchnRejectionForTestOnly(stdout(reason)),
      V2Q03FinalLockAttacksError,
    );
  }
});

test('Q-03 CLI requires all final-root, B-02, corpus, lane, Git, and output arguments', () => {
  const argv = [
    '--profile-core', '/tmp/profile.json',
    '--descriptor', '/tmp/descriptor.json',
    '--final-manifest', '/tmp/manifest.json',
    '--release-root', 'shieldkit-v2-final-r1',
    '--b02-result', '/tmp/b02.json',
    '--attack-corpus', '/tmp/corpus/corpus.json',
    '--lane-evidence-dir', '/tmp/lanes',
    '--expected-commit', sha1('commit'),
    '--expected-tree', sha1('tree'),
    '--output-dir', '/tmp/output',
  ];
  const parsed = parseV2Q03Arguments(argv);
  assert.equal(parsed.b02ResultPath, '/tmp/b02.json');
  assert.equal(parsed.attackCorpusPath, '/tmp/corpus/corpus.json');
  assert.equal(parsed.laneEvidenceDirectory, '/tmp/lanes');
  assert.throws(
    () => parseV2Q03Arguments(argv.slice(0, -2)),
    V2Q03FinalLockAttacksError,
  );
  const duplicate = [...argv];
  duplicate[0] = '--descriptor';
  assert.throws(
    () => parseV2Q03Arguments(duplicate),
    V2Q03FinalLockAttacksError,
  );
});

test('Q-03 production verifier rejects dependency injection before any external I/O', async () => {
  await assert.rejects(
    verifyV2Q03FinalLockAttacks({}, { fake: true }),
    V2Q03FinalLockAttacksError,
  );
});
