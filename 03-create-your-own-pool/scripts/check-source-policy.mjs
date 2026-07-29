#!/usr/bin/env node
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const projectRoot = path.join(repositoryRoot, '03-create-your-own-pool');
const tracked = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
  cwd: repositoryRoot,
  encoding: 'utf8',
}).split('\0').filter((filename) => (
  filename && existsSync(path.join(repositoryRoot, filename))
));
const sourceFiles = tracked.filter((filename) => (
  filename.startsWith('03-create-your-own-pool/')
  && filename.endsWith('.mjs')
  && !filename.includes('/vendor/')
));
const policyFiles = sourceFiles.filter((filename) => (
  !filename.endsWith('.test.mjs')
  && filename !== '03-create-your-own-pool/scripts/check-source-policy.mjs'
));

if (sourceFiles.length === 0) throw new Error('no tracked first-party modules found');

const failures = [];
for (const filename of sourceFiles) {
  const check = spawnSync(process.execPath, ['--check', filename], {
    cwd: repositoryRoot,
    encoding: 'utf8',
  });
  if (check.status !== 0) {
    failures.push(`${filename}: syntax check failed: ${check.stderr || check.stdout}`);
  }
}

const allowedRawSenders = new Set([
  '03-create-your-own-pool/packages/kit/chipnet-rpc.mjs',
  '03-create-your-own-pool/packages/kit/transaction-coordinator.mjs',
  // V2 Direct product path uses its own network gate (not V1 coordinator).
  '03-create-your-own-pool/packages/v2-direct/network-gate.mjs',
  '03-create-your-own-pool/packages/v2-direct/operator/chipnet-rpc.mjs',
]);
for (const filename of policyFiles) {
  const source = readFileSync(path.join(repositoryRoot, filename), 'utf8');
  if (/\.sendrawtransaction\s*\(/.test(source) && !allowedRawSenders.has(filename)) {
    failures.push(`${filename}: direct sendrawtransaction bypasses the coordinator`);
  }
  if (/rejectUnauthorized\s*:\s*false/.test(source)) {
    failures.push(`${filename}: TLS certificate verification is disabled`);
  }
  if (/cat\s*>\s*\/tmp\/sk-|\/tmp\/sk-[A-Za-z0-9._-]*\.hex/.test(source)) {
    failures.push(`${filename}: fixed shared /tmp transaction file is forbidden`);
  }
  if (/spawn(?:Sync)?\s*\(\s*['"]ssh['"]/.test(source)
    && filename !== '03-create-your-own-pool/packages/kit/chipnet-rpc.mjs') {
    failures.push(`${filename}: SSH must use the validated unified RPC adapter`);
  }
}

const unsupportedLocks = tracked.filter((filename) => (
  /^03-create-your-own-pool\/packages\/[^/]+\/package-lock\.json$/.test(filename)
));
if (unsupportedLocks.length > 0) {
  failures.push(`package-local lockfiles are forbidden: ${unsupportedLocks.join(', ')}`);
}

if (failures.length > 0) {
  process.stderr.write(`${failures.join('\n')}\n`);
  process.exit(1);
}

console.log(JSON.stringify({
  ok: true,
  syntaxChecked: sourceFiles.length,
  rawSenders: [...allowedRawSenders],
  lockfile: 'package-lock.json',
}, null, 2));
