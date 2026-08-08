/**
 * Shared adapter helpers: git commit, env capture, fail-closed run records.
 */

import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildOutcome } from '../outcomes.mjs';
import { SpanRecorder } from '../span-recorder.mjs';
import { buildRunRecord } from '../schema.mjs';
import { acceptanceEvidenceFromAdmit } from '../admission.mjs';

export const SDK_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

export function resolveGitCommit(cwd = SDK_ROOT) {
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd,
    encoding: 'utf8',
  }).trim();
  if (!/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error('git rev-parse HEAD did not return a 40-char lowercase sha');
  }
  return commit;
}

export function captureEnvironment(extra = {}) {
  const cpus = os.cpus();
  return {
    host: os.hostname(),
    platform: process.platform,
    arch: os.arch(),
    nodeVersion: process.version,
    cpus: cpus.length,
    cpuModel: cpus[0]?.model ?? null,
    totalMemBytes: os.totalmem(),
    ...extra,
  };
}

export function newRunIds(campaignId) {
  return {
    runId: randomUUID(),
    campaignId: campaignId || `campaign-${randomUUID()}`,
  };
}

/**
 * Fail-closed infrastructure or design failure record with a minimal span DAG.
 */
export function buildFailClosedRun({
  design,
  profile,
  action,
  commit,
  campaignId,
  outcomeClass,
  reason,
  cacheMode = 'warm-resident',
  firstTry = true,
  metrics = {},
  environment = null,
  notes = '',
  spans = null,
  acceptance = null,
}) {
  const { runId, campaignId: cid } = newRunIds(campaignId);
  let spanList = spans;
  if (!spanList) {
    const rec = new SpanRecorder({ design, profile });
    const cmd = rec.start('command');
    const intent = rec.start('intent', { parentId: cmd });
    rec.end(intent, { status: 'failed', reason });
    rec.end(cmd, { status: 'failed', reason });
    spanList = rec.snapshot();
  }
  return buildRunRecord({
    runId,
    campaignId: cid,
    design,
    profile,
    commit: commit || resolveGitCommit(),
    action,
    cacheMode,
    boundary: 'intent',
    spans: spanList,
    outcome: buildOutcome({
      class: outcomeClass,
      reason,
      commandCompletionMs: spanList[0]
        ? Math.max(...spanList.map((s) => s.endOffsetMs)) - Math.min(...spanList.map((s) => s.startOffsetMs))
        : null,
    }),
    acceptance: acceptance || acceptanceEvidenceFromAdmit(null),
    metrics,
    environment: environment || captureEnvironment(),
    firstTry,
    notes,
    wallStartedAt: new Date().toISOString(),
    wallEndedAt: new Date().toISOString(),
  });
}

export function sha256FileSync(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/** Normalize action name: withdraw → withdrawal for plan schema. */
export function normalizeAction(action) {
  if (action === 'withdraw' || action === 'withdrawal') return 'withdrawal';
  if (action === 'deposit' || action === 'transfer') return action;
  throw new Error(`unknown action: ${action}`);
}

export function productActionCliKind(action) {
  const a = normalizeAction(action);
  return a === 'withdrawal' ? 'withdraw' : a;
}
