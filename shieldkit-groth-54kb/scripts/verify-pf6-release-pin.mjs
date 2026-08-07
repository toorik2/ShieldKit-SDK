#!/usr/bin/env node
/**
 * Independently verify the ShieldKit-Groth-54KB (pf6) offline release pin:
 *  1. read pins/pf6-release.pin.json (trust root: releaseManifestSha256)
 *  2. extract pins/<releaseId>.tar.gz into a temp dir
 *  3. hash the extracted manifest.json and compare to releaseManifestSha256
 *  4. hash every artifact in the manifest and compare (path/bytes/sha256)
 *  5. re-run the fail-closed no-seven-carrier scan on the extracted tree
 * 6. confirm every artifact exists exactly once and no extras are present
 * Exit 0 only if all checks pass. No writes outside the temp dir.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import { repositoryRoot, scanTree } from './check-no-seven-carrier-54kb.mjs';

function fail(message) { throw new Error(`PF6_RELEASE_PIN_VERIFY_FAILED: ${message}`); }
function sha256File(p) { return createHash('sha256').update(readFileSync(p)).digest('hex'); }

export function verifyPf6ReleasePin({ pinPath = path.join(repositoryRoot, 'pins/pf6-release.pin.json') } = {}) {
  if (!existsSync(pinPath)) fail(`pin missing: ${pinPath}`);
  const pin = JSON.parse(readFileSync(pinPath, 'utf8'));
  const { releaseId, releaseManifestSha256 } = pin;
  if (!releaseId || !/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(releaseId)) fail('pin releaseId invalid');
  if (!releaseManifestSha256 || !/^[0-9a-f]{64}$/.test(releaseManifestSha256)) fail('pin releaseManifestSha256 invalid');

  const tarPath = path.join(path.dirname(pinPath), `${releaseId}.tar.gz`);
  if (!existsSync(tarPath)) fail(`bundle tar missing: ${tarPath}`);
  const tarBytes = statSync(tarPath).size;
  const tarSha256 = sha256File(tarPath);

  const verifyRoot = mkdtempSync(path.join(os.tmpdir(), 'pf6-release-verify-'));
  try {
    const r = spawnSync('tar', ['-xzf', tarPath, '-C', verifyRoot], { encoding: 'utf8' });
    if (r.status !== 0) fail(`tar extract failed: ${r.stderr || r.stdout}`);

    const bundleRoot = path.join(verifyRoot, releaseId);
    if (!existsSync(bundleRoot)) fail(`bundle root missing in tar: ${releaseId}`);

    const manifestPath = path.join(bundleRoot, 'manifest.json');
    const manifestBytes = readFileSync(manifestPath);
    const manifestSha = createHash('sha256').update(manifestBytes).digest('hex');
    if (manifestSha !== releaseManifestSha256) {
      fail(`manifest sha256 mismatch: pin ${releaseManifestSha256} vs tar ${manifestSha}`);
    }
    const manifest = JSON.parse(manifestBytes.toString('utf8'));
    if (manifest.releaseId !== releaseId) fail('manifest releaseId mismatch');

    const expected = new Map();
    let totalBytes = 0;
    for (const [section, artifacts] of Object.entries(manifest.artifacts)) {
      for (const a of artifacts) {
        const rel = path.join(section, a.path);
        if (expected.has(rel)) fail(`duplicate artifact path: ${rel}`);
        expected.set(rel, a);
        totalBytes += a.bytes;
      }
    }

    const seen = new Set();
    const walk = (dir, prefix) => {
      const entries = [];
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
        if (entry.isDirectory()) entries.push(...walk(full, rel));
        else if (entry.isFile()) entries.push(rel);
        else fail(`unexpected non-file entry in tar: ${rel}`);
      }
      return entries;
    };
    for (const rel of walk(bundleRoot, '')) {
      if (rel === 'manifest.json') continue;
      const meta = expected.get(rel);
      if (!meta) fail(`unexpected file in tar: ${rel}`);
      seen.add(rel);
      const full = path.join(bundleRoot, rel);
      const bytes = statSync(full).size;
      const sha = sha256File(full);
      if (bytes !== meta.bytes) fail(`${rel}: byte count ${bytes} != manifest ${meta.bytes}`);
      if (sha !== meta.sha256) fail(`${rel}: sha256 mismatch`);
    }
    for (const rel of expected.keys()) {
      if (!seen.has(rel)) fail(`missing artifact in tar: ${rel}`);
    }

    const scan = scanTree(verifyRoot, 'shieldkit-groth-54kb-offline-bundle-verify', releaseId);
    if (scan.hits.length > 0) fail(`extracted bundle scan hits:\n${scan.hits.slice(0, 30).join('\n')}`);

    return {
      ok: true,
      schema: 'shieldkit-54kb/evidence/release-pin-verify/v1',
      releaseId,
      releaseManifestSha256,
      bundleTar: path.relative(repositoryRoot, tarPath),
      bundleBytes: tarBytes,
      bundleSha256: tarSha256,
      artifactCount: expected.size,
      totalUnpackedBytes: totalBytes,
      scan: {
        filesScanned: scan.files.length,
        binarySkipped: scan.binarySkipped.length,
        provenanceLinesAllowed: scan.provenanceLinesAllowed,
        frozenSchemaLinesAllowed: scan.frozenSchemaLinesAllowed,
      },
    };
  } finally {
    rmSync(verifyRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.stdout.write(`${JSON.stringify(verifyPf6ReleasePin(), null, 2)}\n`);
}
