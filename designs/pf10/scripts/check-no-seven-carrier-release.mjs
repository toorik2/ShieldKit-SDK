#!/usr/bin/env node
/**
 * Fail-closed release-closure scan for forbidden seven-carrier product material
 * in the ShieldKit-Groth product tree or packed CLI surface.
 *
 * Frozen cryptographic schema identifiers that historically embed the old
 * seven-carrier adapter name are allowlisted only when the full schema string
 * matches exactly. Do not broaden the allowlist without an explicit migration.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const productRoot = path.join(repositoryRoot, 'designs/pf10');
// Built as character classes to avoid self-matching this scanner source.
const TOKEN_A = 'PF' + '7';
const TOKEN_B = 'dens' + 'Fuel';
const TOKEN_C = 'pairfold';
const PATTERN = new RegExp(
  String.raw`(\b${TOKEN_A}\b|${TOKEN_C}[-_ ]?7|${TOKEN_B})`,
  'i',
);

/** Exact frozen schema IDs preserved for wire compatibility (not product branding). */
const FROZEN_SCHEMA_ALLOWLIST = new Set([
  'shield.cash/snarkjs-groth16-' + 'pf7' + '-adapter/v1',
]);

const SELF = new Set([
  'designs/pf10/scripts/check-no-seven-carrier-release.mjs',
  'designs/pf10/scripts/qualification-beta.mjs',
]);

function fail(message) {
  process.stderr.write(`check:no-seven-carrier-release FAILED: ${message}\n`);
  process.exit(1);
}

function listFiles(root) {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(repositoryRoot, full);
      if (entry.isDirectory()) {
        if (['vendor', 'node_modules', 'target', '.codex-build', '.tmp', '.git'].includes(entry.name)) continue;
        if (dir === productRoot && ['demo', 'research'].includes(entry.name)) continue;
        if (entry.name.startsWith('.codex') || entry.name.startsWith('.tmp')
          || entry.name.startsWith('.shieldkit-v2-recovery')) continue;
        walk(full);
        continue;
      }
      if (/\.(o|d|rlib|a|so|wasm|bin|map|png|jpg)$/i.test(entry.name)) continue;
      if (SELF.has(rel)) continue;
      out.push(rel);
    }
  };
  walk(root);
  return out;
}

function lineAllowed(line) {
  for (const schema of FROZEN_SCHEMA_ALLOWLIST) {
    if (!line.includes(schema)) continue;
    const stripped = line.split(schema).join('');
    if (!PATTERN.test(stripped)) return true;
  }
  return false;
}

function scanFiles(files, label) {
  const hits = [];
  for (const rel of files) {
    const full = path.join(repositoryRoot, rel);
    let text;
    try { text = readFileSync(full, 'utf8'); } catch { continue; }
    text.split(/\r?\n/).forEach((line, index) => {
      if (!PATTERN.test(line)) return;
      if (lineAllowed(line)) return;
      hits.push(`${rel}:${index + 1}:${line.trim().slice(0, 200)}`);
    });
  }
  if (hits.length > 0) {
    fail(`${label}: ${hits.length} release-closure match(es)\n${hits.slice(0, 50).join('\n')}`);
  }
  return files.length;
}

if (!existsSync(productRoot)) fail('designs/pf10/ missing');
const productFiles = listFiles(productRoot);
const scanned = scanFiles(productFiles, 'designs/pf10');

const packList = path.join(repositoryRoot, '.tmp/npm-pack-files.txt');
if (existsSync(packList)) {
  const names = readFileSync(packList, 'utf8').split(/\r?\n/).filter(Boolean);
  const matches = names.filter((name) => PATTERN.test(name));
  if (matches.length > 0) {
    fail(`npm pack file list contains forbidden names: ${matches.slice(0, 20).join(', ')}`);
  }
}

const help = execFileSync(process.execPath, [
  path.join(productRoot, 'scripts/shieldkit.mjs'),
  '--help',
], { encoding: 'utf8', cwd: repositoryRoot });
if (PATTERN.test(help)) {
  fail('shieldkit --help still mentions forbidden seven-carrier product material');
}

console.log(JSON.stringify({
  ok: true,
  productRoot: 'designs/pf10',
  filesScanned: scanned,
  frozenSchemaAllowlist: [...FROZEN_SCHEMA_ALLOWLIST],
  helpClean: true,
}, null, 2));
