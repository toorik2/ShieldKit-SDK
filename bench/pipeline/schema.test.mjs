import assert from 'node:assert/strict';
import test from 'node:test';

import {
  RUN_SCHEMA,
  CAMPAIGN_SUMMARY_SCHEMA,
  buildRunRecord,
  validateRunRecord,
  buildCampaignSummary,
  formatCampaignReport,
} from './schema.mjs';
import { SpanRecorder } from './span-recorder.mjs';
import { buildOutcome } from './outcomes.mjs';

const COMMIT = 'a'.repeat(40);

function sampleSpans() {
  const rec = new SpanRecorder({ design: 'pf10' });
  const c = rec.start('command');
  const i = rec.start('intent', { parentId: c });
  const p = rec.start('proof', { parentId: i, attempt: 1 });
  rec.end(p, { status: 'executed' });
  rec.end(i, { status: 'executed' });
  rec.end(c, { status: 'executed' });
  return rec.finalize();
}

test('buildRunRecord + validateRunRecord enforce schema identity and gates', () => {
  const spans = sampleSpans();
  const accepted = buildRunRecord({
    runId: 'run-1',
    campaignId: 'camp-1',
    design: 'pf10',
    profile: 'DIRECT_V2_PF10',
    commit: COMMIT,
    action: 'deposit',
    cacheMode: 'warm-resident',
    spans,
    outcome: buildOutcome({
      class: 'accepted',
      intentToAcceptedMs: 1000,
      commandToAcceptedMs: 1100,
      localPreparationMs: 900,
      admissionMs: 100,
      commandCompletionMs: 1150,
    }),
    acceptance: {
      accepted: true,
      acceptanceMethod: 'mempool_membership',
      txid: 'cd'.repeat(32),
      mempoolObserved: true,
      observeMethod: 'getmempoolentry',
      tmaIsAcceptance: false,
      readback: { match: true, transactionId: 'cd'.repeat(32), rawTransactionHex: '00' },
    },
    metrics: { txBytes: 90000, maxUnlockBytes: 9999, feeSats: 90001 },
    firstTry: true,
  });
  assert.equal(accepted.schema, RUN_SCHEMA);
  assert.equal(accepted.commit.length, 40);
  assert.equal(accepted.acceptance.txid.length, 64);
  assert.equal(accepted.acceptance.tmaIsAcceptance, false);
  assert.ok(accepted.criticalPath.criticalPathMs >= 0);
  assert.match(accepted.provenance.recordSha256, /^[0-9a-f]{64}$/);

  // Reject TMA-as-acceptance
  assert.throws(
    () => validateRunRecord({
      ...accepted,
      acceptance: { ...accepted.acceptance, tmaIsAcceptance: true },
      provenance: { ...accepted.provenance, recordSha256: accepted.provenance.recordSha256 },
    }),
    /tmaIsAcceptance/,
  );

  // Reject estimated sizes
  assert.throws(
    () => buildRunRecord({
      runId: 'x',
      campaignId: 'y',
      design: 'pf6',
      profile: 'p',
      commit: COMMIT,
      action: 'transfer',
      spans,
      outcome: buildOutcome({ class: 'design_failure', reason: 'x' }),
      acceptance: {
        accepted: false,
        acceptanceMethod: null,
        txid: null,
        mempoolObserved: false,
        tmaIsAcceptance: false,
        readback: null,
      },
      metrics: { estimated: true, txBytes: 1 },
    }),
    /estimated/,
  );
});

test('campaign summary has reliability + Pareto and no global winner', () => {
  const spans = sampleSpans();
  const mk = (design, action, outcomeClass, ms) => buildRunRecord({
    runId: `${design}-${action}-${outcomeClass}`,
    campaignId: 'camp',
    design,
    profile: design,
    commit: COMMIT,
    action,
    cacheMode: 'warm-resident',
    spans,
    outcome: outcomeClass === 'accepted'
      ? buildOutcome({
        class: 'accepted',
        intentToAcceptedMs: ms,
        commandToAcceptedMs: ms,
        localPreparationMs: ms,
        commandCompletionMs: ms,
      })
      : buildOutcome({ class: outcomeClass, reason: 'unit' }),
    acceptance: outcomeClass === 'accepted'
      ? {
        accepted: true,
        acceptanceMethod: 'mempool_membership',
        txid: 'ee'.repeat(32),
        mempoolObserved: true,
        tmaIsAcceptance: false,
        readback: { match: true, transactionId: 'ee'.repeat(32) },
      }
      : {
        accepted: false,
        acceptanceMethod: null,
        txid: null,
        mempoolObserved: false,
        tmaIsAcceptance: false,
        readback: null,
      },
    metrics: {
      txBytes: outcomeClass === 'accepted' ? 50000 : null,
      maxUnlockBytes: outcomeClass === 'accepted' ? 8000 : null,
      feeSats: outcomeClass === 'accepted' ? 50001 : null,
      cpuSeconds: 1.5,
      peakRssBytes: 1e9,
    },
    firstTry: true,
  });

  const runs = [
    mk('pf10', 'deposit', 'accepted', 1000),
    mk('pf10', 'deposit', 'design_failure', null),
    mk('pf6', 'deposit', 'infrastructure_invalid', null),
    mk('fri', 'withdrawal', 'accepted', 5000),
  ];
  // cold panel separate
  const cold = buildRunRecord({
    ...mk('pf10', 'deposit', 'accepted', 2000),
    runId: 'cold-1',
    // rebuild properly
  });
  // rebuild cold with correct cacheMode
  const coldRun = buildRunRecord({
    runId: 'cold-1',
    campaignId: 'camp',
    design: 'pf10',
    profile: 'pf10',
    commit: COMMIT,
    action: 'deposit',
    cacheMode: 'cold-installed',
    spans,
    outcome: buildOutcome({
      class: 'accepted',
      intentToAcceptedMs: 2000,
      commandToAcceptedMs: 2000,
      localPreparationMs: 2000,
      commandCompletionMs: 2000,
    }),
    acceptance: {
      accepted: true,
      acceptanceMethod: 'mempool_membership',
      txid: 'ff'.repeat(32),
      mempoolObserved: true,
      tmaIsAcceptance: false,
      readback: { match: true, transactionId: 'ff'.repeat(32) },
    },
    metrics: { txBytes: 50000, maxUnlockBytes: 8000, feeSats: 50001 },
    firstTry: true,
  });

  const summary = buildCampaignSummary({
    campaignId: 'camp',
    runs: [...runs, coldRun],
  });
  assert.equal(summary.schema, CAMPAIGN_SUMMARY_SCHEMA);
  assert.equal(summary.globalWinner, null);
  assert.equal(summary.ranking, 'none');
  assert.ok(summary.pareto.length >= 1);
  assert.ok(summary.panels.warm.length >= 1);
  assert.ok(summary.panels.cold.length >= 1);
  const text = formatCampaignReport(summary);
  assert.match(text, /globalWinner=none/);
  assert.match(text, /Pareto/);
  assert.doesNotMatch(text, /winner:\s*pf10/i);
});
