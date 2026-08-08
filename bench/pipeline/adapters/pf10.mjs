/**
 * PF10 real-action adapter: drives product CLI pool deposit|transfer|withdraw
 * and emits shieldkit-action-benchmark-run/v2.
 */

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { buildOutcome } from '../outcomes.mjs';
import { spansFromProductTimings, SpanRecorder } from '../span-recorder.mjs';
import { buildRunRecord } from '../schema.mjs';
import {
  SDK_ROOT,
  resolveGitCommit,
  captureEnvironment,
  newRunIds,
  buildFailClosedRun,
  normalizeAction,
  productActionCliKind,
} from './common.mjs';

export const PF10_DESIGN = 'pf10';
export const PF10_PROFILE = 'DIRECT_V2_PF10';

const CLI = path.join(SDK_ROOT, 'designs/pf10/scripts/shieldkit.mjs');

/**
 * Run one PF10 action against a product data-home.
 * @param {{ action: string, dataHome: string, to?: string, note?: string, campaignId?: string, cacheMode?: string }} opts
 */
export function runPf10Action(opts) {
  const action = normalizeAction(opts.action);
  const dataHome = opts.dataHome;
  const campaignId = opts.campaignId;
  const cacheMode = opts.cacheMode || 'warm-resident';
  const commit = resolveGitCommit();
  const env = captureEnvironment({ designRoot: path.join(SDK_ROOT, 'designs/pf10') });

  if (typeof dataHome !== 'string' || !path.isAbsolute(dataHome)) {
    return buildFailClosedRun({
      design: PF10_DESIGN,
      profile: PF10_PROFILE,
      action,
      commit,
      campaignId,
      outcomeClass: 'infrastructure_invalid',
      reason: 'PF10 requires absolute --data-home with session.json',
      cacheMode,
      environment: env,
      notes: 'blocker: missing data-home',
    });
  }

  const sessionCandidates = [
    path.join(dataHome, 'session.json'),
    path.join(dataHome, 'shieldkit', 'v2-beta-product', 'session.json'),
  ];
  if (!sessionCandidates.some((p) => existsSync(p))) {
    return buildFailClosedRun({
      design: PF10_DESIGN,
      profile: PF10_PROFILE,
      action,
      commit,
      campaignId,
      outcomeClass: 'infrastructure_invalid',
      reason: `no session.json under data-home ${dataHome}`,
      cacheMode,
      environment: env,
      notes: 'blocker: PF10 pool session not provisioned',
    });
  }

  if (!existsSync(CLI)) {
    return buildFailClosedRun({
      design: PF10_DESIGN,
      profile: PF10_PROFILE,
      action,
      commit,
      campaignId,
      outcomeClass: 'infrastructure_invalid',
      reason: 'shieldkit.mjs CLI missing',
      cacheMode,
      environment: env,
    });
  }

  const kind = productActionCliKind(action);
  const cliArgs = ['pool', kind, '--data-home', dataHome, '--json'];
  if (kind === 'withdraw') {
    if (!opts.to) {
      return buildFailClosedRun({
        design: PF10_DESIGN,
        profile: PF10_PROFILE,
        action,
        commit,
        campaignId,
        outcomeClass: 'infrastructure_invalid',
        reason: 'withdrawal requires --to payout address',
        cacheMode,
        environment: env,
      });
    }
    cliArgs.push('--to', opts.to);
  }
  if ((kind === 'transfer' || kind === 'withdraw') && opts.note) {
    cliArgs.push('--note', opts.note);
  }
  if (kind === 'transfer' && !opts.note) {
    return buildFailClosedRun({
      design: PF10_DESIGN,
      profile: PF10_PROFILE,
      action,
      commit,
      campaignId,
      outcomeClass: 'infrastructure_invalid',
      reason: 'transfer requires --note',
      cacheMode,
      environment: env,
    });
  }

  const rec = new SpanRecorder({ design: PF10_DESIGN, profile: PF10_PROFILE });
  const commandStartWall = Date.now();
  const commandId = rec.start('command');
  const intentId = rec.start('intent', { parentId: commandId });
  const t0 = performance.now();

  const result = spawnSync(process.execPath, [CLI, ...cliArgs], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env },
  });

  const wallMs = performance.now() - t0;
  let envelope = null;
  try {
    envelope = JSON.parse(result.stdout || '{}');
  } catch {
    envelope = null;
  }

  if (!envelope || envelope.ok !== true) {
    const reason = envelope?.error?.message
      || result.stderr?.slice(0, 500)
      || `CLI exit ${result.status}`;
    const code = envelope?.error?.code || '';
    rec.end(intentId, { status: 'failed', reason });
    rec.end(commandId, { status: 'failed', reason });
    const spans = rec.snapshot();
    const infra = /RPC|ECONN|ENOENT|data-home|session|fund|UTXO|wallet|SSH|network/i.test(reason)
      || /RPC|INFRA|NETWORK|SESSION/i.test(code);
    return buildRunRecord({
      ...newRunIds(campaignId),
      design: PF10_DESIGN,
      profile: PF10_PROFILE,
      commit,
      action,
      cacheMode,
      boundary: 'intent',
      spans,
      outcome: buildOutcome({
        class: infra ? 'infrastructure_invalid' : 'design_failure',
        reason: `${code}: ${reason}`.slice(0, 800),
        commandCompletionMs: wallMs,
      }),
      acceptance: {
        accepted: false,
        acceptanceMethod: null,
        txid: null,
        mempoolObserved: false,
        tmaIsAcceptance: false,
        readback: null,
      },
      metrics: { txBytes: null, maxUnlockBytes: null, feeSats: null },
      environment: env,
      firstTry: true,
      notes: 'PF10 product CLI first-try fail-closed',
      wallStartedAt: new Date(commandStartWall).toISOString(),
      wallEndedAt: new Date().toISOString(),
    });
  }

  const actionResult = envelope.result?.action ?? envelope.result ?? envelope;
  const timings = actionResult.timingsMs ?? envelope.result?.timingsMs ?? {};
  const txid = actionResult.transactionId
    ?? actionResult.acceptedTxid
    ?? envelope.result?.transactionId
    ?? null;
  const txHex = actionResult.transactionHex
    ?? actionResult.rawTransactionHex
    ?? null;
  const txBytes = typeof txHex === 'string' ? txHex.length / 2
    : (typeof actionResult.txBytes === 'number' ? actionResult.txBytes : null);
  const maxUnlock = actionResult.maxUnlockBytes
    ?? actionResult.metrics?.maxUnlockBytes
    ?? null;
  const feeSats = actionResult.feeSats ?? actionResult.fee ?? null;

  // Close live intent/command envelopes; attach product stage spans as children via timings
  rec.end(intentId, { status: 'executed' });
  rec.end(commandId, { status: 'executed' });
  // Prefer detailed product timings when present
  let spans;
  if (timings && Object.keys(timings).length > 0) {
    spans = spansFromProductTimings({
      timingsMs: { ...timings, total: timings.total ?? wallMs },
      commandStartOffsetMs: 0,
      intentStartOffsetMs: 0,
      design: PF10_DESIGN,
      profile: PF10_PROFILE,
    });
  } else {
    spans = rec.snapshot();
  }

  const mempoolOk = Boolean(
    txid
    && /^[0-9a-f]{64}$/.test(txid)
    && (actionResult.admission?.allowed === true
      || actionResult.accepted === true
      || actionResult.state === 'accepted_zero_conf'
      || envelope.result?.accepted === true
      || timings.admission != null),
  );

  // Product path already admitted via transaction-coordinator (send + readback).
  // We require full txid and product success; mark mempool acceptance evidence.
  const readbackMatch = Boolean(
    actionResult.readback?.rawTransactionHex
    || actionResult.readbackMatch === true
    || (txHex && txid),
  );

  if (!mempoolOk || !txid) {
    return buildRunRecord({
      ...newRunIds(campaignId),
      design: PF10_DESIGN,
      profile: PF10_PROFILE,
      commit,
      action,
      cacheMode,
      boundary: 'intent',
      spans,
      outcome: buildOutcome({
        class: 'design_failure',
        reason: 'CLI ok but missing exact mempool acceptance evidence / txid',
        commandCompletionMs: wallMs,
        localPreparationMs: timings.total ?? null,
      }),
      acceptance: {
        accepted: false,
        acceptanceMethod: null,
        txid: txid && /^[0-9a-f]{64}$/.test(txid) ? txid : null,
        mempoolObserved: false,
        tmaIsAcceptance: false,
        readback: null,
      },
      metrics: {
        txBytes: Number.isFinite(txBytes) ? txBytes : null,
        maxUnlockBytes: maxUnlock,
        feeSats,
      },
      environment: env,
      firstTry: true,
      notes: 'incomplete acceptance evidence from product envelope',
      wallStartedAt: new Date(commandStartWall).toISOString(),
      wallEndedAt: new Date().toISOString(),
    });
  }

  const intentMs = typeof timings.total === 'number' ? timings.total : wallMs;
  const admissionMs = typeof timings.admission === 'number' ? timings.admission : null;
  const localPrep = admissionMs !== null && intentMs !== null
    ? Math.max(0, intentMs - admissionMs)
    : intentMs;

  return buildRunRecord({
    ...newRunIds(campaignId),
    design: PF10_DESIGN,
    profile: PF10_PROFILE,
    commit,
    action,
    cacheMode,
    boundary: 'intent',
    spans,
    outcome: buildOutcome({
      class: 'accepted',
      intentToAcceptedMs: intentMs,
      commandToAcceptedMs: wallMs,
      localPreparationMs: localPrep,
      admissionMs,
      acceptedToReadyMs: typeof timings.commit === 'number' ? timings.commit : null,
      commandCompletionMs: wallMs,
    }),
    acceptance: {
      accepted: true,
      acceptanceMethod: 'mempool_membership',
      txid,
      mempoolObserved: true,
      observeMethod: 'product_transaction_coordinator',
      tmaIsAcceptance: false,
      readback: {
        match: readbackMatch,
        transactionId: txid,
        rawTransactionHex: typeof txHex === 'string' ? txHex : null,
      },
    },
    metrics: {
      txBytes: Number.isFinite(txBytes) ? Math.trunc(txBytes) : null,
      maxUnlockBytes: typeof maxUnlock === 'number' ? maxUnlock : null,
      feeSats: typeof feeSats === 'number' ? feeSats : null,
      operationId: actionResult.operationId ?? null,
    },
    environment: env,
    workload: { kind: action, design: PF10_DESIGN },
    firstTry: true,
    notes: 'PF10 real product path via shieldkit.mjs',
    wallStartedAt: new Date(commandStartWall).toISOString(),
    wallEndedAt: new Date().toISOString(),
  });
}
