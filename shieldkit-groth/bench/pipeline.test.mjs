import assert from 'node:assert/strict';
import test from 'node:test';

import {
  PIPELINE_SCHEMA,
  buildPipelineReport,
  extractPipelineTimings,
  formatPipelineTable,
  pipelineSourceFromCliResult,
} from './pipeline.mjs';

test('extractPipelineTimings and format drive real helpers', () => {
  const source = {
    actionTimingsMs: {
      stateRead: 438.4,
      fundingRead: 440.9,
      treeAndPreparation: 16.2,
      witnessCalculation: 665.1,
      proofGeneration: 2544.0,
      proofVerification: 200.2,
      proofTotal: 3666.3,
      witnessAssembly: 777.9,
      signingAndVm: 234.0,
      localVm: 222.4,
      admission: 3200,
      commit: 80,
      total: 9800,
    },
    cliTimingsMs: { sessionOpen: 50, commandTotal: 9900 },
  };
  const extracted = extractPipelineTimings(source);
  assert.equal(extracted.steps.proofGeneration, 2544);
  assert.equal(extracted.commandTotal, 9900);

  const report = buildPipelineReport({
    design: 't',
    kind: 'deposit',
    transactionId: 'ab'.repeat(32),
    source,
  });
  assert.equal(report.schema, PIPELINE_SCHEMA);
  assert.equal(report.rows[4].short, 'proofGen');
  assert.ok(report.sums.localWorkMs > 5000);
  assert.equal(report.sums.admissionMs, 3200);

  const table = formatPipelineTable(report);
  assert.match(table, /Look up tip on network/);
  assert.match(table, /Make ZK proof/);
  assert.match(table, /Broadcast \+ mempool/);
  assert.match(table, /local work done/);
  assert.match(table, /total ~/);
  assert.match(table, /ShieldKit-Groth/);
  assert.match(table, /verifier=DIRECT_V2_PF10/);
  assert.equal(report.subject.product, 'ShieldKit-Groth');
  assert.equal(report.subject.verifier, 'DIRECT_V2_PF10');
  assert.ok(typeof report.subject.version === 'string' && report.subject.version.length > 0);
});

test('pipelineSourceFromCliResult reads product envelope', () => {
  const envelope = {
    ok: true,
    result: {
      command: 'deposit',
      transactionId: 'cd'.repeat(32),
      timingsMs: { sessionOpen: 12, action: 9000, commandTotal: 9100 },
      action: {
        kind: 'deposit',
        operationId: 'deposit.1',
        transactionId: 'cd'.repeat(32),
        timingsMs: {
          stateRead: 100,
          fundingRead: 100,
          treeAndPreparation: 10,
          witnessCalculation: 50,
          proofGeneration: 2000,
          proofVerification: 100,
          proofTotal: 2200,
          witnessAssembly: 100,
          signingAndVm: 50,
          localVm: 40,
          admission: 500,
          commit: 20,
          total: 3000,
        },
      },
    },
  };
  const src = pipelineSourceFromCliResult(envelope);
  assert.equal(src.kind, 'deposit');
  assert.equal(src.transactionId, 'cd'.repeat(32));
  const report = buildPipelineReport({ source: src, kind: src.kind });
  assert.equal(report.sums.proofGenerationMs, 2000);
  assert.equal(report.sums.admissionMs, 500);
  assert.equal(report.sums.commandTotalMs, 9100);
});
