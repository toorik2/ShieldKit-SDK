import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../packages/profile/load.mjs';
import { runQ07StoreWorker } from './v2-q07-store-worker.mjs';
import {
  V2Q07IndexedMicrobenchmarkError,
  parseQ07IndexedMicrobenchmarkArguments,
  runQ07IndexedMicrobenchmark,
  verifyQ07IndexedMicrobenchmarkBundle,
} from './v2-q07-indexed-microbenchmark.mjs';

const counts = { baseline: 3, prefix: 5, full: 6, warmSamples: 2 };
const contained = Object.freeze({
  backend: 'test-only-cgroup-seam',
  containment: { cgroup: '/test/q07', memoryMax: '4294967296', memorySwapMax: '0', memoryPeak: '1024', memoryEvents: { oom: 0, oomKill: 0 } },
  termination: { exitCode: 0, signal: null, memoryPeak: '1024', memoryEvents: { oom: 0, oomKill: 0 } },
});

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'q07-indexed-')); chmodSync(root, 0o700);
  const q04 = join(root, 'q04-evidence.json'); writeFileSync(q04, `${canonicalJson({ schema: 'test-q04-v3' })}\n`, { mode: 0o600 }); chmodSync(q04, 0o600);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, q04 };
}
const runner = async ({ config }) => { runQ07StoreWorker(config); return structuredClone(contained); };
const verifyQ04 = async () => ({ status: 'verified', q04GatePass: true, q04Verdict: 'pass-bounded-100000-and-depth4-shared-kernel' });

async function run(t) {
  const subject = fixture(t);
  const result = await runQ07IndexedMicrobenchmark({ outputParent: subject.root, q04Verification: subject.q04, testOnlyCounts: counts, runner, verifyQ04, testOnlySkipGit: true });
  return { ...subject, result };
}

test('Q07 indexed auxiliary bundle uses tiny stores only through the explicit test seam', async (t) => {
  const subject = await run(t);
  assert.equal(subject.result.q07Qualified, false);
  assert.equal(subject.result.status, 'indexed-nullifier-store-microbenchmark-only');
  const evidence = JSON.parse(readFileSync(subject.result.evidence.path, 'utf8'));
  assert.equal(evidence.qualificationBoundary, 'indexed-nullifier-store-microbenchmark-only');
  assert.equal(evidence.warm.sampleCount, 2);
  assert.equal(evidence.dataset.mainCount, 6);
  assert.ok(evidence.references.length > 10);
});

test('Q07 indexed bundle verifier rejects tampering, missing samples, fake cgroup, Q04 drift, relabeling, and source drift', async (t) => {
  const mutate = async (name, change, pattern) => {
    const subject = await run(t); const evidence = JSON.parse(readFileSync(subject.result.evidence.path, 'utf8'));
    change(subject, evidence);
    writeFileSync(subject.result.evidence.path, `${canonicalJson(evidence)}\n`, { mode: 0o600 }); chmodSync(subject.result.evidence.path, 0o600);
    await assert.rejects(() => verifyQ07IndexedMicrobenchmarkBundle(subject.result.evidence.path, { testOnlyCounts: counts, testOnlySkipGit: true }), pattern, name);
  };
  await mutate('missing', (_subject, evidence) => { evidence.references.pop(); }, /sample count|artifact binding/u);
  await mutate('relabel', (_subject, evidence) => { evidence.q07Qualified = true; }, /claim a Q07 V2 phase/u);
  await mutate('source', (_subject, evidence) => { evidence.sourceSetSha256 = '0'.repeat(64); }, /sourceSet|source drift/u);
  await mutate('q04', (subject, evidence) => { const q04 = join(subject.result.bundle, 'q04', 'evidence.json'); writeFileSync(q04, 'x', { mode: 0o600 }); chmodSync(q04, 0o600); }, /byte count drifted|SHA-256 drifted/u);
  await mutate('cgroup', (subject, evidence) => { const ref = evidence.references.find((entry) => entry.id.endsWith('.cgroup.json')); const path = join(subject.result.bundle, ref.path); const value = JSON.parse(readFileSync(path, 'utf8')); value.termination.exitCode = 1; writeFileSync(path, `${canonicalJson(value)}\n`, { mode: 0o600 }); chmodSync(path, 0o600); const bytes = readFileSync(path); ref.bytes = bytes.length; ref.sha256 = createHash('sha256').update(bytes).digest('hex'); }, /termination/u);
});

test('Q07 indexed CLI parser has no reduced-count or quick surface', () => {
  assert.throws(() => parseQ07IndexedMicrobenchmarkArguments(['--output-parent', '/tmp']), V2Q07IndexedMicrobenchmarkError);
  assert.throws(() => parseQ07IndexedMicrobenchmarkArguments(['--output-parent', '/tmp', '--q04-verification', '/tmp/x', '--quick']), V2Q07IndexedMicrobenchmarkError);
});
