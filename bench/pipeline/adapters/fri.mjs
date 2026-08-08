/**
 * FRI-STARK real-action adapter: drives the FRI design's Chipnet stories.
 * Records proof/materialization attempts visibly; product path remains first-try.
 */

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
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

export const FRI_DESIGN = 'fri';
export const FRI_PROFILE = 'fri-stark-96kb';

const DESIGN_ROOT = path.join(SDK_ROOT, 'designs/fri');

/**
 * Map action → story script that can exercise a single kind when possible.
 * Lifecycle scripts may run multiple kinds; we still record one action focus.
 */
function resolveFriScript(action, opts) {
  if (opts.actionScript && existsSync(opts.actionScript)) return opts.actionScript;
  if (process.env.SHIELDKIT_FRI_ACTION_SCRIPT && existsSync(process.env.SHIELDKIT_FRI_ACTION_SCRIPT)) {
    return process.env.SHIELDKIT_FRI_ACTION_SCRIPT;
  }
  const candidates = {
    deposit: [
      path.join(DESIGN_ROOT, 'scripts/chipnet-deposit-withdraw-story.mjs'),
      path.join(DESIGN_ROOT, 'scripts/chipnet-one-tip-lifecycle.mjs'),
    ],
    transfer: [
      path.join(DESIGN_ROOT, 'scripts/chipnet-one-tip-lifecycle.mjs'),
      path.join(DESIGN_ROOT, 'scripts/chipnet-wallet-lifecycle.mjs'),
    ],
    withdrawal: [
      path.join(DESIGN_ROOT, 'scripts/chipnet-deposit-withdraw-story.mjs'),
      path.join(DESIGN_ROOT, 'scripts/chipnet-one-tip-lifecycle.mjs'),
    ],
  };
  return (candidates[action] || []).find((p) => existsSync(p)) || null;
}

export function runFriAction(opts) {
  const action = normalizeAction(opts.action);
  const campaignId = opts.campaignId;
  const cacheMode = opts.cacheMode || 'warm-resident';
  const commit = resolveGitCommit();
  const env = captureEnvironment({
    designRoot: DESIGN_ROOT,
    friDepth: process.env.VC_FRI_DEPTH || '20',
  });

  if (!existsSync(DESIGN_ROOT)) {
    return buildFailClosedRun({
      design: FRI_DESIGN,
      profile: FRI_PROFILE,
      action,
      commit,
      campaignId,
      outcomeClass: 'infrastructure_invalid',
      reason: 'FRI design root missing',
      cacheMode,
      environment: env,
    });
  }

  const script = resolveFriScript(action, opts);
  if (!script) {
    return buildFailClosedRun({
      design: FRI_DESIGN,
      profile: FRI_PROFILE,
      action,
      commit,
      campaignId,
      outcomeClass: 'infrastructure_invalid',
      reason: 'no FRI chipnet action script found',
      cacheMode,
      environment: env,
      notes: 'blocker: FRI story scripts missing',
    });
  }

  // Require explicit opt-in for live FRI (multi-GB prove) unless data/env ready
  const liveEnabled = opts.live === true
    || process.env.SHIELDKIT_FRI_BENCH_LIVE === '1'
    || process.env.SHIELDKIT_ACTION_BENCH_LIVE === '1';

  if (!liveEnabled) {
    return buildFailClosedRun({
      design: FRI_DESIGN,
      profile: FRI_PROFILE,
      action,
      commit,
      campaignId,
      outcomeClass: 'infrastructure_invalid',
      reason: 'FRI live bench requires SHIELDKIT_FRI_BENCH_LIVE=1 (multi-GB prove; Chipnet funds)',
      cacheMode,
      environment: env,
      notes: `script=${path.relative(SDK_ROOT, script)}; set SHIELDKIT_FRI_BENCH_LIVE=1 to run`,
    });
  }

  const rec = new SpanRecorder({ design: FRI_DESIGN, profile: FRI_PROFILE });
  const commandStartWall = Date.now();
  const commandId = rec.start('command');
  const intentId = rec.start('intent', { parentId: commandId });
  // Proof + materialize as siblings under intent (parallel branches preserved if overlapping)
  const proofId = rec.start('proof', { parentId: intentId, attempt: 1, meta: { depth: env.friDepth } });
  const matId = rec.start('materialize', { parentId: intentId, attempt: 1 });

  const t0 = performance.now();
  const result = spawnSync(process.execPath, [script, ...(opts.scriptArgs || [])], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    cwd: DESIGN_ROOT,
    env: {
      ...process.env,
      SHIELDKIT_ACTION: action,
      // Profile depth — never silent depth-32 default when product pin differs
      VC_FRI_DEPTH: process.env.VC_FRI_DEPTH || '20',
    },
    timeout: opts.timeoutMs || 3_600_000,
  });
  const wallMs = performance.now() - t0;

  rec.end(proofId, {
    status: result.status === 0 ? 'executed' : 'failed',
    reason: result.status === 0 ? null : `exit ${result.status}`,
  });
  rec.end(matId, {
    status: result.status === 0 ? 'executed' : 'failed',
  });

  let envelope = null;
  try {
    envelope = JSON.parse(result.stdout || '{}');
  } catch {
    const lines = (result.stdout || '').trim().split('\n').filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i -= 1) {
      try {
        envelope = JSON.parse(lines[i]);
        break;
      } catch { /* */ }
    }
  }

  // Extract per-kind result if lifecycle
  const kindKey = action === 'withdrawal' ? 'withdrawal' : action;
  const actionResult = envelope?.[kindKey]
    ?? envelope?.result?.[kindKey]
    ?? envelope?.result
    ?? envelope
    ?? {};

  const txid = actionResult.transactionId
    ?? actionResult.txid
    ?? envelope?.txid
    ?? null;
  const txHex = actionResult.transactionHex ?? actionResult.rawTransactionHex ?? null;
  const txBytes = typeof txHex === 'string'
    ? txHex.length / 2
    : (typeof actionResult.txBytes === 'number' ? actionResult.txBytes : null);

  if (result.status !== 0 || !txid || !/^[0-9a-f]{64}$/.test(String(txid))) {
    const reason = (result.stderr || result.stdout || '').slice(0, 800)
      || `FRI script exit ${result.status}`;
    rec.end(intentId, { status: 'failed', reason: reason.slice(0, 200) });
    rec.end(commandId, { status: 'failed', reason: reason.slice(0, 200) });
    const spans = rec.snapshot();
    const infra = /RPC|fund|UTXO|OOM|ENOMEM|SSH|wallet|provision|mempool/i.test(reason)
      || result.status === 137;
    return buildRunRecord({
      ...newRunIds(campaignId),
      design: FRI_DESIGN,
      profile: FRI_PROFILE,
      commit,
      action,
      cacheMode,
      boundary: 'intent',
      spans,
      outcome: buildOutcome({
        class: infra ? 'infrastructure_invalid' : 'design_failure',
        reason: reason.slice(0, 800),
        commandCompletionMs: wallMs,
      }),
      acceptance: {
        accepted: false,
        acceptanceMethod: null,
        txid: txid && /^[0-9a-f]{64}$/.test(String(txid)) ? String(txid) : null,
        mempoolObserved: false,
        tmaIsAcceptance: false,
        readback: null,
      },
      metrics: { txBytes: Number.isFinite(txBytes) ? txBytes : null },
      environment: env,
      firstTry: true,
      notes: `FRI script ${path.basename(script)} first-try`,
      wallStartedAt: new Date(commandStartWall).toISOString(),
      wallEndedAt: new Date().toISOString(),
    });
  }

  rec.end(intentId, { status: 'executed' });
  rec.end(commandId, { status: 'executed' });
  const spans = rec.snapshot();

  return buildRunRecord({
    ...newRunIds(campaignId),
    design: FRI_DESIGN,
    profile: FRI_PROFILE,
    commit,
    action,
    cacheMode,
    boundary: 'intent',
    spans,
    outcome: buildOutcome({
      class: 'accepted',
      intentToAcceptedMs: wallMs,
      commandToAcceptedMs: wallMs,
      localPreparationMs: wallMs,
      commandCompletionMs: wallMs,
    }),
    acceptance: {
      accepted: true,
      acceptanceMethod: 'mempool_membership',
      txid: String(txid),
      mempoolObserved: true,
      observeMethod: 'fri_chipnet_story',
      tmaIsAcceptance: false,
      readback: {
        match: Boolean(txHex),
        transactionId: String(txid),
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
    notes: `FRI real path via ${path.basename(script)}`,
    wallStartedAt: new Date(commandStartWall).toISOString(),
    wallEndedAt: new Date().toISOString(),
  });
}
