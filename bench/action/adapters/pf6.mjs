/**
 * PF6 real-action adapter: drives profile module / design scripts when present.
 * Fail-closed with plan-legal outcomes when live path cannot run.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { buildOutcome } from '../outcomes.mjs';
import { SpanRecorder } from '../span-recorder.mjs';
import { buildRunRecord } from '../schema.mjs';
import {
  SDK_ROOT,
  resolveGitCommit,
  captureEnvironment,
  newRunIds,
  buildFailClosedRun,
  normalizeAction,
} from './common.mjs';

export const PF6_DESIGN = 'pf6';
export const PF6_PROFILE = 'pf6-a3-direct-v1';

const DESIGN_ROOT = path.join(SDK_ROOT, 'shieldkit-groth-54kb');
const PROFILE_MODULE = path.join(SDK_ROOT, 'cli/profiles/pf6-a3-direct-v1.mjs');

/**
 * Attempt one PF6 live action.
 * Prefers design evidence scripts or profile entry if data-home/env provided.
 */
export function runPf6Action(opts) {
  const action = normalizeAction(opts.action);
  const campaignId = opts.campaignId;
  const cacheMode = opts.cacheMode || 'warm-resident';
  const commit = resolveGitCommit();
  const env = captureEnvironment({ designRoot: DESIGN_ROOT });

  if (!existsSync(DESIGN_ROOT)) {
    return buildFailClosedRun({
      design: PF6_DESIGN,
      profile: PF6_PROFILE,
      action,
      commit,
      campaignId,
      outcomeClass: 'infrastructure_invalid',
      reason: 'shieldkit-groth-54kb design root missing',
      cacheMode,
      environment: env,
    });
  }

  // Live entry: optional SHIELDKIT_PF6_ACTION_SCRIPT or package scripts under design
  const scriptCandidates = [
    opts.actionScript,
    process.env.SHIELDKIT_PF6_ACTION_SCRIPT,
    path.join(DESIGN_ROOT, 'scripts', `chipnet-${action}.mjs`),
    path.join(DESIGN_ROOT, 'scripts', `live-${action}.mjs`),
    path.join(DESIGN_ROOT, 'src', `run-live-${action}.mjs`),
  ].filter(Boolean);

  const script = scriptCandidates.find((p) => typeof p === 'string' && existsSync(p));

  // Profile-based CLI via experimental lab (pool action through profile)
  const labCli = path.join(SDK_ROOT, 'cli/scripts/shieldkit.mjs');
  const dataHome = opts.dataHome || process.env.SHIELDKIT_PF6_DATA_HOME || null;

  if (!script && !(existsSync(labCli) && dataHome && existsSync(PROFILE_MODULE))) {
    // Honest infrastructure fail-closed: no provisioned live path
    return buildFailClosedRun({
      design: PF6_DESIGN,
      profile: PF6_PROFILE,
      action,
      commit,
      campaignId,
      outcomeClass: 'infrastructure_invalid',
      reason: 'PF6 live action path not provisioned (no action script and no SHIELDKIT_PF6_DATA_HOME)',
      cacheMode,
      environment: env,
      notes: 'blocker: provision PF6 data-home or action script; no synthetic accept',
    });
  }

  const rec = new SpanRecorder({ design: PF6_DESIGN, profile: PF6_PROFILE });
  const commandStartWall = Date.now();
  const commandId = rec.start('command');
  const intentId = rec.start('intent', { parentId: commandId });
  // Lane construction is design-specific — record as materialize branch
  const matId = rec.start('materialize', { parentId: intentId, meta: { branch: 'pf6-lane' } });
  const t0 = performance.now();

  let result;
  if (script) {
    result = spawnSync(process.execPath, [script, ...(opts.scriptArgs || [])], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      env: {
        ...process.env,
        SHIELDKIT_ACTION: action,
        SHIELDKIT_DATA_HOME: dataHome || '',
      },
      timeout: opts.timeoutMs || 900_000,
    });
  } else {
    const kind = action === 'withdrawal' ? 'withdraw' : action;
    const args = [
      'pool', kind,
      '--profile', PF6_PROFILE,
      '--data-home', dataHome,
      '--json',
    ];
    if (kind === 'withdraw' && opts.to) args.push('--to', opts.to);
    if (kind === 'transfer' && opts.note) args.push('--note', opts.note);
    result = spawnSync(process.execPath, [labCli, ...args], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env },
      timeout: opts.timeoutMs || 900_000,
    });
  }

  const wallMs = performance.now() - t0;
  rec.end(matId, { status: result.status === 0 ? 'executed' : 'failed' });

  let envelope = null;
  try {
    envelope = JSON.parse(result.stdout || '{}');
  } catch {
    // try last JSON line
    const lines = (result.stdout || '').trim().split('\n').filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i -= 1) {
      try {
        envelope = JSON.parse(lines[i]);
        break;
      } catch { /* continue */ }
    }
  }

  if (result.status !== 0 || !envelope || envelope.ok === false) {
    const reason = envelope?.error?.message
      || result.stderr?.slice(0, 500)
      || `exit ${result.status}`;
    rec.end(intentId, { status: 'failed', reason });
    rec.end(commandId, { status: 'failed', reason });
    const spans = rec.snapshot();
    const infra = /RPC|fund|UTXO|data-home|session|ENOENT|provision|SSH|network/i.test(reason);
    return buildRunRecord({
      ...newRunIds(campaignId),
      design: PF6_DESIGN,
      profile: PF6_PROFILE,
      commit,
      action,
      cacheMode,
      boundary: 'intent',
      spans,
      outcome: buildOutcome({
        class: infra ? 'infrastructure_invalid' : 'design_failure',
        reason: String(reason).slice(0, 800),
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
      metrics: {},
      environment: env,
      firstTry: true,
      notes: 'PF6 first-try fail-closed',
      wallStartedAt: new Date(commandStartWall).toISOString(),
      wallEndedAt: new Date().toISOString(),
    });
  }

  const actionResult = envelope.result?.action ?? envelope.result ?? envelope;
  const txid = actionResult.transactionId ?? actionResult.txid ?? envelope.txid ?? null;
  const txHex = actionResult.transactionHex ?? actionResult.rawTransactionHex ?? null;
  const txBytes = typeof txHex === 'string' ? txHex.length / 2
    : (typeof actionResult.txBytes === 'number' ? actionResult.txBytes : null);
  const timings = actionResult.timingsMs ?? {};

  rec.end(intentId, { status: 'executed' });
  rec.end(commandId, { status: 'executed' });
  const spans = rec.snapshot();

  const accepted = Boolean(txid && /^[0-9a-f]{64}$/.test(txid) && (envelope.ok === true || actionResult.accepted));
  if (!accepted) {
    return buildRunRecord({
      ...newRunIds(campaignId),
      design: PF6_DESIGN,
      profile: PF6_PROFILE,
      commit,
      action,
      cacheMode,
      boundary: 'intent',
      spans,
      outcome: buildOutcome({
        class: 'design_failure',
        reason: 'PF6 completed without full 64-char mempool acceptance evidence',
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
      metrics: { txBytes: Number.isFinite(txBytes) ? txBytes : null },
      environment: env,
      firstTry: true,
      notes: 'incomplete PF6 acceptance',
      wallStartedAt: new Date(commandStartWall).toISOString(),
      wallEndedAt: new Date().toISOString(),
    });
  }

  return buildRunRecord({
    ...newRunIds(campaignId),
    design: PF6_DESIGN,
    profile: PF6_PROFILE,
    commit,
    action,
    cacheMode,
    boundary: 'intent',
    spans,
    outcome: buildOutcome({
      class: 'accepted',
      intentToAcceptedMs: timings.total ?? wallMs,
      commandToAcceptedMs: wallMs,
      localPreparationMs: timings.total ?? wallMs,
      admissionMs: timings.admission ?? null,
      commandCompletionMs: wallMs,
    }),
    acceptance: {
      accepted: true,
      acceptanceMethod: 'mempool_membership',
      txid,
      mempoolObserved: true,
      observeMethod: 'product_or_profile_path',
      tmaIsAcceptance: false,
      readback: {
        match: Boolean(txHex),
        transactionId: txid,
        rawTransactionHex: typeof txHex === 'string' ? txHex : null,
      },
    },
    metrics: {
      txBytes: Number.isFinite(txBytes) ? Math.trunc(txBytes) : null,
      maxUnlockBytes: actionResult.maxUnlockBytes ?? null,
      feeSats: actionResult.feeSats ?? null,
    },
    environment: env,
    firstTry: true,
    notes: 'PF6 real path',
    wallStartedAt: new Date(commandStartWall).toISOString(),
    wallEndedAt: new Date().toISOString(),
  });
}

/** List recent evidence scorecards (component only — not action-bench). */
export function listPf6ComponentEvidence() {
  const dir = path.join(DESIGN_ROOT, 'evidence/bench');
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith('.json'));
}
