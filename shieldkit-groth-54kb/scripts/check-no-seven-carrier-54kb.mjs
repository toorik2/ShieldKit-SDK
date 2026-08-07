#!/usr/bin/env node
/**
 * Fail-closed release-closure scan for forbidden seven-carrier product material
 * in the ShieldKit-Groth-54KB (pf6) contained tree.
 *
 * Equivalent of shieldkit-groth-94kb/scripts/check-no-seven-carrier-release.mjs for
 * this product tree: the pf6 tree must be free of PF7/densFuel/pairfold-7
 * PRODUCT material except the frozen wire schema allowlist. Provenance
 * references to the pf7-sub62 worktree are permitted ONLY in record/evidence
 * surfaces and only
 * when the line contains no other forbidden token after stripping the exact
 * allowlisted provenance markers. Do not broaden the allowlists without an
 * explicit migration.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Built as character classes to avoid self-matching this scanner source.
const TOKEN_A = 'PF' + '7';
const TOKEN_B = 'dens' + 'Fuel';
const TOKEN_C = 'pair' + 'fold';
export const FORBIDDEN_PATTERN = new RegExp(
  String.raw`(\b${TOKEN_A}\b|${TOKEN_C}[-_ ]?7|${TOKEN_B})`,
  'i',
);

/** Exact frozen schema IDs preserved for wire compatibility (not product branding). */
export const FROZEN_SCHEMA_ALLOWLIST = new Set([
  'shield.cash/snarkjs-groth16-' + 'pf7' + '-adapter/v1',
]);

/**
 * Exact provenance markers permitted ONLY under record/evidence surfaces
 * (evidence/, design/, README.md). These are reconciliation records, not product
 * material. A line is allowed iff after stripping every marker the line no
 * longer matches FORBIDDEN_PATTERN.
 */
export const PROVENANCE_MARKERS = new Set([
  'verifier-pf7-sub62',
  'pf7-sub62',
  'pf7-54326',
  'densFuel-DROP',
  // Exact gate-description / quoted-commit-subject phrases in the plan docs
  // (policy statements about this very scan, not product material).
  'PF7/densFuel/pairfold-7',
  'PF7 shield packet digest',
]);

/** Scanner sources (themselves describing the scan) are exempt, mirroring the
 *  product scanner's SELF set. */
const SELF = new Set(['scripts/check-no-seven-carrier-54kb.mjs']);

const DOCUMENTATION_SURFACES = new Set(['evidence', 'design']);
const DOCUMENTATION_FILES = new Set(['README.md']);
const SKIP_DIRS = new Set(['vendor', 'node_modules', '.git', '.tmp', '.cache']);
const BINARY_EXT = /\.(o|d|rlib|a|so|wasm|bin|map|png|jpg|jpeg|gif|wtns|proof|gz|tgz|zip|tar)$/i;

function fail(message) {
  process.stderr.write(`check:no-seven-carrier-54kb FAILED: ${message}\n`);
  process.exit(1);
}

export function isBinary(filename) {
  return BINARY_EXT.test(filename);
}

export function listFiles(root) {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(root, full);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.codex')) continue;
        walk(full);
        continue;
      }
      out.push(rel);
    }
  };
  walk(root);
  return out.sort();
}

function isDocumentationSurface(rel) {
  const parts = rel.split('/');
  if (DOCUMENTATION_FILES.has(parts[parts.length - 1])) return true;
  if (DOCUMENTATION_SURFACES.has(parts[0])) return true;
  return false;
}

export function lineAllowed(line, rel) {
  // Frozen wire schema allowlist: exact full-schema string may be present;
  // any forbidden token elsewhere on the line still fails.
  for (const schema of FROZEN_SCHEMA_ALLOWLIST) {
    if (!line.includes(schema)) continue;
    const stripped = line.split(schema).join('');
    if (!FORBIDDEN_PATTERN.test(stripped)) return true;
  }
  // Provenance markers only on documentation/evidence surfaces.
  if (!isDocumentationSurface(rel)) return false;
  let stripped = line;
  for (const marker of PROVENANCE_MARKERS) stripped = stripped.split(marker).join('');
  return !FORBIDDEN_PATTERN.test(stripped);
}

export function scanTree(root, label = 'shieldkit-groth-54kb', relStrip = '') {
  const files = listFiles(root);
  const stripPrefix = (rel) => {
    if (!relStrip || !rel.startsWith(`${relStrip}/`)) return rel;
    const rest = rel.slice(relStrip.length + 1);
    for (const section of ['product', 'vendorPins']) {
      if (rest.startsWith(`${section}/`)) return rest.slice(section.length + 1);
    }
    return rest;
  };
  const hits = [];
  const binarySkipped = [];
  let provenanceLinesAllowed = 0;
  let frozenSchemaLinesAllowed = 0;
  for (const rel0 of files) {
    const rel = stripPrefix(rel0);
    if (SELF.has(rel)) continue;
    const full = path.join(root, rel0);
    let stat;
    try { stat = statSync(full); } catch { continue; }
    if (!stat.isFile()) continue;
    if (isBinary(rel)) { binarySkipped.push(rel); continue; }
    let text;
    try { text = readFileSync(full, 'utf8'); } catch { binarySkipped.push(rel); continue; }
    text.split(/\r?\n/).forEach((line, index) => {
      if (!FORBIDDEN_PATTERN.test(line)) return;
      if (lineAllowed(line, rel)) {
        for (const schema of FROZEN_SCHEMA_ALLOWLIST) {
          if (line.includes(schema)) { frozenSchemaLinesAllowed += 1; return; }
        }
        provenanceLinesAllowed += 1;
        return;
      }
      hits.push(`${rel}:${index + 1}:${line.trim().slice(0, 200)}`);
    });
  }
  return { files, hits, binarySkipped, provenanceLinesAllowed, frozenSchemaLinesAllowed };
}

export function runScan({ root = repositoryRoot, label = 'shieldkit-groth-54kb' } = {}) {
  const { files, hits, binarySkipped, provenanceLinesAllowed, frozenSchemaLinesAllowed } = scanTree(root, label);
  if (hits.length > 0) {
    fail(`${label}: ${hits.length} release-closure match(es)\n${hits.slice(0, 50).join('\n')}`);
  }
  return {
    ok: true,
    schema: 'shieldkit-54kb/release-scan/no-seven-carrier/v1',
    root: root,
    label,
    filesScanned: files.length,
    binarySkipped: binarySkipped.length,
    provenanceLinesAllowed,
    frozenSchemaLinesAllowed,
    frozenSchemaAllowlist: [...FROZEN_SCHEMA_ALLOWLIST],
    provenanceMarkers: [...PROVENANCE_MARKERS],
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.stdout.write(`${JSON.stringify(runScan(), null, 2)}\n`);
}
