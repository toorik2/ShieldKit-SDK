#!/usr/bin/env node
/**
 * Fail-closed first-party source policy scan for the ShieldKit-Groth-54KB
 * (pf6) contained tree.
 *
 * Equivalent of shieldkit-groth-94kb/scripts/check-source-policy.mjs for this
 * product tree: syntax-check every first-party module, forbid direct raw
 * senders outside the coordinator, forbid TLS verification disablement,
 * forbid fixed shared /tmp transaction scratch files (product patterns),
 * forbid SSH spawning outside the unified RPC adapter, forbid network calls
 * in first-party modules, forbid package-local lockfiles. Fixed /tmp scratch
 * usage outside the product patterns and absolute file:// imports are
 * reported as non-blocking telemetry only.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** First-party module roots (never vendor/). */
const MODULE_ROOTS = ['src', 'scripts'];
/** Modules permitted to call sendrawtransaction directly (none today). */
const ALLOWED_RAW_SENDERS = new Set([]);
/** Modules permitted to spawn ssh / perform network calls (unified RPC adapter; none today). */
const ALLOWED_NETWORK_MODULES = new Set([]);

const FORBIDDEN_IMPORT_SOURCES = new Set([
  'node:http', 'node:https', 'node:net', 'node:dgram', 'node:tls', 'node:tls',
  'undici', 'axios', 'ws', 'node-fetch', '@electrum-cash/network', 'node:worker_threads',
]);
const NETWORK_CALL_PATTERNS = [
  /\bfetch\s*\(/,
  /\bhttps?\s*\.\s*request\s*\(/,
  /\bnet\s*\.\s*connect\s*\(/,
  /\bWebSocket\s*\(/,
  /\baxios\b/,
];
const RAW_SENDER_PATTERN = /\.sendrawtransaction\s*\(/;
const TLS_DISABLE_PATTERN = /rejectUnauthorized\s*:\s*false/;
const TMP_SHARED_PATTERN = /cat\s*>\s*\/tmp\/sk-|\/tmp\/sk-[A-Za-z0-9._-]*\.hex/;
const SSH_SPAWN_PATTERN = /spawn(?:Sync)?\s*\(\s*['"]ssh['"]/;
const TMP_SCRATCH_PATTERN = /\/tmp\/[A-Za-z0-9._-]+/g;
const FILE_IMPORT_PATTERN = /from\s+['"]file:\/\/[^'"]+['"]/g;
const CHILD_PROCESS_PATTERN = /(?:spawn|exec|execFile|fork)\w*\s*\(/g;

function fail(message) {
  process.stderr.write(`check:source-policy-54kb FAILED: ${message}\n`);
  process.exit(1);
}

function listModules() {
  const out = [];
  for (const root of MODULE_ROOTS) {
    const dir = path.join(repositoryRoot, root);
    if (!existsSync(dir)) continue;
    const walk = (d) => {
      for (const entry of readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, entry.name);
        if (entry.isDirectory()) {
          if (['node_modules', '.git', '.tmp', '.cache'].includes(entry.name)) continue;
          walk(full);
        } else if (entry.name.endsWith('.mjs')) {
          out.push(path.relative(repositoryRoot, full));
        }
      }
    };
    walk(dir);
  }
  return out.sort();
}

function findPackageLocalLockfiles() {
  const out = [];
  const walk = (d) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      const rel = path.relative(repositoryRoot, full);
      if (entry.isDirectory()) {
        if (['vendor', 'node_modules', '.git'].includes(entry.name)) continue;
        walk(full);
      } else if (entry.name === 'package-lock.json') {
        out.push(rel);
      }
    }
  };
  walk(repositoryRoot);
  return out;
}

export function runSourcePolicyScan() {
  const modules = listModules();
  if (modules.length === 0) fail('no first-party modules found');
  const failures = [];
  const telemetry = [];

  // Syntax check every first-party module.
  for (const rel of modules) {
    const check = spawnSync(process.execPath, ['--check', path.join(repositoryRoot, rel)], { encoding: 'utf8' });
    if (check.status !== 0) {
      failures.push(`${rel}: syntax check failed: ${check.stderr || check.stdout}`);
    }
  }

  const policyTargets = modules.filter((rel) => rel !== 'scripts/check-source-policy-54kb.mjs');
  for (const rel of policyTargets) {
    const source = readFileSync(path.join(repositoryRoot, rel), 'utf8');
    if (RAW_SENDER_PATTERN.test(source) && !ALLOWED_RAW_SENDERS.has(rel)) {
      failures.push(`${rel}: direct sendrawtransaction bypasses the coordinator`);
    }
    if (TLS_DISABLE_PATTERN.test(source)) {
      failures.push(`${rel}: TLS certificate verification is disabled`);
    }
    if (TMP_SHARED_PATTERN.test(source)) {
      failures.push(`${rel}: fixed shared /tmp transaction file is forbidden`);
    }
    if (SSH_SPAWN_PATTERN.test(source) && !ALLOWED_NETWORK_MODULES.has(rel)) {
      failures.push(`${rel}: SSH must use the validated unified RPC adapter`);
    }
    for (const pattern of NETWORK_CALL_PATTERNS) {
      if (pattern.test(source) && !ALLOWED_NETWORK_MODULES.has(rel)) {
        failures.push(`${rel}: network call in first-party module (${pattern})`);
        break;
      }
    }
    const imports = [...source.matchAll(/import\s+[^;]+?from\s+['"]([^'"]+)['"]/g)].map((m) => m[1]);
    for (const spec of imports) {
      if (FORBIDDEN_IMPORT_SOURCES.has(spec)) {
        failures.push(`${rel}: forbidden network import "${spec}"`);
      }
    }
    // Non-blocking telemetry: fixed /tmp scratch, absolute file:// imports,
    // local child-process invocations.
    const tmpScratch = [...new Set(source.match(TMP_SCRATCH_PATTERN) ?? [])];
    const fileImports = [...new Set(source.match(FILE_IMPORT_PATTERN) ?? [])];
    const childProcess = [...new Set(source.match(CHILD_PROCESS_PATTERN) ?? [])];
    if (tmpScratch.length || fileImports.length || childProcess.length) {
      telemetry.push({
        file: rel,
        tmpScratchPaths: tmpScratch.slice(0, 12),
        absoluteFileImports: fileImports.slice(0, 4),
        childProcessCalls: childProcess.slice(0, 8),
      });
    }
  }

  const lockfiles = findPackageLocalLockfiles();
  if (lockfiles.length > 0) {
    failures.push(`package-local lockfiles are forbidden: ${lockfiles.join(', ')}`);
  }

  if (failures.length > 0) {
    process.stderr.write(`${failures.join('\n')}\n`);
    process.exit(1);
  }

  return {
    ok: true,
    schema: 'shieldkit-54kb/release-scan/source-policy/v1',
    root: repositoryRoot,
    syntaxChecked: modules.length,
    policyChecked: policyTargets.length,
    allowedRawSenders: [...ALLOWED_RAW_SENDERS],
    allowedNetworkModules: [...ALLOWED_NETWORK_MODULES],
    lockfile: 'none (no package-local lockfiles)',
    nonBlockingTelemetry: telemetry,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.stdout.write(`${JSON.stringify(runSourcePolicyScan(), null, 2)}\n`);
}
