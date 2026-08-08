#!/usr/bin/env node
/** P1 — Security + one-tx reality */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, existsSync, readFileSync, readdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ROOT, writeJson } from './lib/evidence.mjs';
import {
  productionFriParams,
  assertProductionFloor,
  friParamId,
  securityBits,
} from '../packages/prove/fri-params.mjs';
import { buildSignedSettlement } from '../packages/settlement/settlement.mjs';
import { runVmGate } from '../packages/vm/corpus.mjs';
import { encodeState, genesisState, STATE_BYTES } from '../packages/core/codecs/state.mjs';
import { encodePacket, statementDigest, PACKET_BYTES, KIND } from '../packages/core/codecs/packet.mjs';
import { applyTransition } from '../packages/core/codecs/transition.mjs';
import { NoteTree } from '../packages/core/trees/note-tree.mjs';
import { digest4ToHex, h4 } from '../packages/core/crypto/h4.mjs';

const outDir = path.join(ROOT, 'evidence/p1');
mkdirSync(outDir, { recursive: true });
const checks = [];
const threads = String(Math.max(1, os.cpus().length - 2));

const params = productionFriParams();
try {
  assertProductionFloor(params);
  checks.push({
    id: 'fri-floor',
    ok: true,
    params,
    bits: securityBits(params),
    friParamId: friParamId(params),
  });
} catch (e) {
  checks.push({ id: 'fri-floor', ok: false, error: String(e.message || e) });
}

let weakRejected = false;
try {
  assertProductionFloor({ ...params, blowup: 8, queries: 1, grindBits: 2, maskDeg: 4, securityTargetBits: 100, field: 'goldilocks', scheme: 'deep-ali-fri-stark', fold: 8, merkleHashBytes: 32, extNonres: 7 });
} catch {
  weakRejected = true;
}
checks.push({ id: 'reject-weak-params', ok: weakRejected });

const profileId = createHash('sha256').update('p1-profile').digest('hex');
const instanceId = createHash('sha256').update('p1-instance').digest('hex');
const pre = genesisState({ profileId });
const tree = new NoteTree();
const leaf = digest4ToHex(h4('NOTE_LEAF', [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]));
const { root } = tree.append(leaf);
const post = applyTransition(pre, {
  kind: KIND.DEPOSIT,
  nextNoteRoot: root,
  nextNullifierRoot: pre.nullifierRoot,
});
const packet = {
  networkId: 2,
  kind: KIND.DEPOSIT,
  instanceId,
  preState: pre,
  postState: post,
  publicNullifier: '0'.repeat(64),
  outputNoteLeaf: leaf,
  withdrawalLockingBytecodeHash: '0'.repeat(64),
  transactionContextHash: createHash('sha256').update('p1-ctx').digest('hex'),
};
const sfs1 = encodeState(pre);
const sfp1 = encodePacket(packet);
checks.push({
  id: 'wire-128-424',
  ok: sfs1.length === 128 && sfp1.length === 424,
  sfs1: sfs1.length,
  sfp1: sfp1.length,
  statementDigest: statementDigest(sfp1).toString('hex'),
});

const py = path.join(ROOT, 'packages/prove/python/pool_prove.py');
const selftest = spawnSync('python3', [py, 'selftest'], {
  encoding: 'utf8',
  cwd: ROOT,
  env: { ...process.env, OMP_NUM_THREADS: threads },
  timeout: 180_000,
});
let selftestBody = null;
let selftestOk = false;
if (selftest.status === 0) {
  try {
    selftestBody = JSON.parse(selftest.stdout);
    selftestOk = selftestBody.verifyOk === true && /^[0-9a-f]{64}$/.test(selftestBody.proofBlobSha256);
  } catch {
    selftestOk = false;
  }
}
checks.push({
  id: 'native-stark-selftest',
  ok: selftestOk,
  status: selftest.status,
  stderr: (selftest.stderr || '').slice(0, 500),
  proofBlobSha256: selftestBody?.proofBlobSha256,
  proveSeconds: selftestBody?.proveSeconds,
});
if (selftestBody) writeJson(path.join(outDir, 'selftest-proof-meta.json'), selftestBody);

const prodResults = [];
for (const kind of ['deposit', 'transfer', 'withdrawal']) {
  const out = path.join(outDir, `proof-${kind}.json`);
  if (existsSync(out)) {
    try {
      const meta = JSON.parse(readFileSync(out, 'utf8'));
      if (meta.verifyOk && meta.friParams?.blowup >= 2048 && meta.depth === 20) {  // AMENDED 2026-08-06 (product config depth 20)
        prodResults.push({
          kind,
          ok: true,
          cached: true,
          proofBlobSha256: meta.proofBlobSha256,
          proveSeconds: meta.proveSeconds,
          friParams: meta.friParams,
        });
        continue;
      }
    } catch {
      /* prove fresh */
    }
  }
  // AMENDED 2026-08-06: product config depth=20
  console.error(`[P1] production prove ${kind} (depth=20, production FRI, multi-core)...`);
  const r = spawnSync(
    'python3',
    [
      py,
      'prove',
      '--kind',
      kind,
      '--depth',
      '32',
      '--eligibility',
      'final',
      '--omit-proof-body',
      '--out',
      out,
      '--seed',
      '1',
    ],
    {
      encoding: 'utf8',
      cwd: ROOT,
      env: { ...process.env, OMP_NUM_THREADS: threads },
      timeout: 14_400_000,
    },
  );
  let meta = null;
  if (r.status === 0 && existsSync(out)) meta = JSON.parse(readFileSync(out, 'utf8'));
  prodResults.push({
    kind,
    ok: r.status === 0 && meta?.verifyOk === true && meta?.friParams?.blowup >= 2048,
    status: r.status,
    error: r.status !== 0 ? (r.stderr || r.stdout || '').slice(0, 1500) : null,
    proofBlobSha256: meta?.proofBlobSha256,
    proveSeconds: meta?.proveSeconds,
    friParams: meta?.friParams,
  });
}
checks.push({
  id: 'production-prove-three-kinds',
  ok: prodResults.length === 3 && prodResults.every((x) => x.ok),
  results: prodResults,
});

const settle = buildSignedSettlement({
  statement: { kind: 'deposit', statementDigest: statementDigest(sfp1).toString('hex') },
  // Product path: real materialized sound assembly (Rust-worker proven); the
  // pure-JS depth-20 assemble is not the product path and would hang.
  assemblyArtifact: path.join(ROOT, 'evidence/production/assemble-state0/assemble-deposit-d20-b2048-n7-g30-base1.materialized.json'),
});
const vm = runVmGate();
// Topology / size measurements still recorded, but product path fails closed on placeholders.
checks.push({
  id: 'signed-settlement-18in',
  ok: settle.fullySigned && settle.roleLayout.inputCount === 18 && settle.sizes.maxUnlockBytes <= 10_000,
  sizes: settle.sizes,
});
checks.push({
  id: 'production-fri-verifiers',
  ok: settle.productionVerifiers === true && settle.placeholder !== true,
  productionVerifiers: settle.productionVerifiers,
  placeholder: settle.placeholder,
  placeholderKind: settle.placeholderKind,
  error:
    settle.placeholder || !settle.productionVerifiers
      ? 'PLACEHOLDER_SETTLEMENT: tag-hash preimage redeems are not production FRI 17-role locks'
      : null,
});
checks.push({ id: 'vm-honest-and-corpus', ok: vm.ok, corpusCount: vm.corpus.count });

// Plan P1 SLA: p95 <= 60s per action — the honest bar comes from the P5 campaign
// (evidence/sla/proof-{kind}-*.json: 3 warmups + 32 measured proofs/action).
const slaDir = path.join(ROOT, 'evidence/sla');
const proveTimes = [];
if (existsSync(slaDir)) {
  for (const f of readdirSync(slaDir)) {
    if (!/^proof-(deposit|transfer|withdrawal)-\d{2}\.json$/.test(f)) continue;
    try {
      const d = JSON.parse(readFileSync(path.join(slaDir, f), 'utf8'));
      if (typeof d.proveSeconds === 'number') proveTimes.push(d.proveSeconds);
    } catch {
      /* ignore */
    }
  }
}
const p95 = proveTimes.length
  ? [...proveTimes].sort((a, b) => a - b)[Math.min(proveTimes.length - 1, Math.ceil(proveTimes.length * 0.95) - 1)]
  : null;
const SLA_P95 = 60;
checks.push({
  id: 'prover-sla-p95',
  ok: p95 != null && p95 <= SLA_P95,
  p95Seconds: p95,
  barSeconds: SLA_P95,
  samples: proveTimes,
  error:
    p95 == null
      ? 'no measured proveSeconds'
      : p95 > SLA_P95
        ? `PROVER_SLA_EXCEEDED: p95=${p95}s > ${SLA_P95}s (pure-Python depth-20/blowup-2048)`
        : null,
});

writeJson(path.join(outDir, 'settlement.json'), settle);
writeJson(path.join(outDir, 'vm.json'), vm);
if (p95 != null && p95 > SLA_P95) {
  writeJson(path.join(outDir, 'PROVER_SLA_EXCEEDED.json'), {
    schema: 'shieldkit-fri-stark-prover-sla-exceeded-v1',
    p95Seconds: p95,
    barSeconds: SLA_P95,
    samples: prodResults,
    timestamp: new Date().toISOString(),
  });
}

const ok = checks.every((c) => c.ok);
const report = {
  gate: 'P1',
  name: 'security-one-tx-reality',
  ok,
  checks,
  command: 'npm run qualify:security',
  timestamp: new Date().toISOString(),
};
writeJson(path.join(outDir, 'P1_REPORT.json'), report);
console.log(JSON.stringify(report, null, 2));
process.exit(ok ? 0 : 1);
