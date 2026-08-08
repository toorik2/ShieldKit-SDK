#!/usr/bin/env node
/**
 * Build the local-only, hash-pinned offline release bundle + release pin for
 * the ShieldKit-Groth-54KB (pf6) product, mirroring the
 * shieldkit-groth-94kb `v2-beta-product-offline-r3.pin.json` pattern: exact
 * release ID + manifest SHA-256 as trust root, no remote publication.
 *
 * Bundle layout (staged then deterministically tarred):
 *   <releaseId>/manifest.json      canonical JSON inventory (path/bytes/sha256)
 *   <releaseId>/product/…          README.md design/ src/ scripts/ evidence/
 *   <releaseId>/vendorPins/…       vendor-pin.json SHA256SUMS pf6-lane/
 *                                  verifier-pin/ product-vk/ chipnet-txs/
 *
 * The staged bundle is scanned with the same fail-closed no-seven-carrier
 * rule as the source tree; the packed tar is re-extracted and re-verified
 * (manifest sha + scan) before the pin is written.
 *
 * Outputs:
 *   pins/<releaseId>.tar.gz
 *   pins/pf6-release.manifest.json
 *   pins/pf6-release.pin.json
 *   evidence/08-release/offline-bundle.json  (receipt)
 *   evidence/08-release/release-pin.json     (receipt)
 */
import { createHash, randomUUID } from 'node:crypto';
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  rmSync, statSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import { repositoryRoot, scanTree, FORBIDDEN_PATTERN } from './check-no-seven-carrier-54kb.mjs';

const RELEASE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const FALSE_CLAIMS = Object.freeze({ productionQualified: false, releaseQualified: false });

const BUNDLE_SCHEMA = 'shieldkit-54kb-pf6-offline-release-bundle-v1';
const PIN_SCHEMA = 'shieldkit-54kb-pf6-release-pin-v1';
const MANIFEST_SCHEMA = 'shieldkit-54kb-pf6-offline-release-manifest-v1';

/**
 * Meta-records describing the release bundle/pin itself (receipts and the
 * final-state scan). Excluded from the bundle so the bundle content is stable
 * under meta updates (no self-referential circularity).
 */
const META_EVIDENCE = new Set([
  'evidence/08-release/offline-bundle.json',
  'evidence/08-release/release-pin.json',
  'evidence/08-release/release-pin-verify.json',
  'evidence/08-release/final-state-scan.json',
]);

const SECTIONS = Object.freeze({
  product: Object.freeze({
    files: ['README.md'],
    dirs: ['design', 'src', 'scripts', 'evidence'],
  }),
  vendorPins: Object.freeze({
    files: ['vendor/vendor-pin.json', 'vendor/SHA256SUMS'],
    dirs: ['vendor/pf6-lane', 'vendor/verifier-pin', 'vendor/product-vk', 'vendor/chipnet-txs'],
  }),
});

function fail(message) { throw new Error(`PF6_OFFLINE_PACK_FAILED: ${message}`); }

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function collectFiles(sectionDef, base) {
  const out = [];
  for (const f of sectionDef.files) {
    const p = path.join(base, f);
    if (!existsSync(p)) fail(`missing section file ${f}`);
    if (!statSync(p).isFile()) fail(`section file is not a regular file: ${f}`);
    out.push(f);
  }
  for (const d of sectionDef.dirs) {
    const root = path.join(base, d);
    if (!existsSync(root)) fail(`missing section dir ${d}`);
    const walk = (dir, prefix) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
        if (entry.isDirectory()) {
          if (['node_modules', '.git'].includes(entry.name)) continue;
          walk(full, rel);
        } else {
          if (META_EVIDENCE.has(rel)) continue;
          out.push(rel);
        }
      }
    };
    walk(root, d);
  }
  return out.sort();
}

function copyTree(sourceRoot, destRoot, rels) {
  for (const rel of rels) {
    const from = path.join(sourceRoot, rel);
    const to = path.join(destRoot, rel);
    mkdirSync(path.dirname(to), { recursive: true });
    copyFileSync(from, to);
  }
}

function inventory(destRoot, rels) {
  return rels.map((rel) => {
    const p = path.join(destRoot, rel);
    const st = statSync(p);
    return Object.freeze({ path: rel, bytes: st.size, sha256: sha256Bytes(readFileSync(p)) });
  });
}

function runTar(args, cwd) {
  const r = spawnSync('tar', args, { cwd, encoding: 'utf8' });
  if (r.status !== 0) fail(`tar failed: ${r.stderr || r.stdout}`);
}

function defaultReleaseId(now = new Date()) {
  const ymd = now.toISOString().slice(0, 10).replace(/-/g, '');
  return `shieldkit-54kb-pf6-${ymd}-r1`;
}

export function packPf6OfflineBundle({ releaseId = defaultReleaseId(), outDir = path.join(repositoryRoot, 'pins') } = {}) {
  if (typeof releaseId !== 'string' || !RELEASE_ID.test(releaseId)) fail('invalid releaseId');
  mkdirSync(outDir, { recursive: true });

  const sourceRels = Object.fromEntries(Object.entries(SECTIONS).map(([name, def]) => [name, collectFiles(def, repositoryRoot)]));

  // Stage the bundle.
  const stageRoot = mkdtempSync(path.join(outDir, '.bundle-stage-'));
  const bundleRoot = path.join(stageRoot, releaseId);
  try {
    for (const [name, rels] of Object.entries(sourceRels)) {
      copyTree(repositoryRoot, path.join(bundleRoot, name), rels);
    }
    // Fail-closed scan of the staged bundle (rel paths stripped of <releaseId>/).
    const scan = scanTree(stageRoot, 'shieldkit-groth-54kb-offline-bundle', releaseId);
    if (scan.hits.length > 0) {
      fail(`bundle scan hits:\n${scan.hits.slice(0, 50).join('\n')}`);
    }

    const manifest = {
      schema: MANIFEST_SCHEMA,
      status: 'offline-beta-unqualified',
      claims: FALSE_CLAIMS,
      releaseId,
      generated: new Date().toISOString(),
      artifacts: Object.fromEntries(
        Object.entries(sourceRels).map(([name, rels]) => [name, inventory(path.join(bundleRoot, name), rels)]),
      ),
    };
    const manifestBytes = Buffer.from(canonicalize(manifest), 'utf8');
    writeFileSync(path.join(bundleRoot, 'manifest.json'), manifestBytes);
    const releaseManifestSha256 = sha256Bytes(manifestBytes);

    // Deterministic tar: fixed ordering, mtime, ownership.
    const tarPath = path.join(outDir, `${releaseId}.tar.gz`);
    runTar(['--sort=name', '--mtime=@0', '--owner=0', '--group=0', '--numeric-owner',
      '--format=gnu', '-czf', tarPath, '-C', stageRoot, releaseId], repositoryRoot);

    // Verify: extract the tar, re-hash the manifest, re-scan the tree.
    const verifyRoot = mkdtempSync(path.join(outDir, '.bundle-verify-'));
    try {
      runTar(['-xzf', tarPath, '-C', verifyRoot], repositoryRoot);
      const extractedManifest = readFileSync(path.join(verifyRoot, releaseId, 'manifest.json'));
      if (sha256Bytes(extractedManifest) !== releaseManifestSha256) {
        fail('extracted manifest sha256 mismatch');
      }
      const verifyScan = scanTree(verifyRoot, 'shieldkit-groth-54kb-offline-bundle-verify', releaseId);
      if (verifyScan.hits.length > 0) fail('extracted bundle scan hits');
      if (JSON.parse(extractedManifest.toString('utf8')).releaseId !== releaseId) fail('manifest releaseId mismatch');
    } finally {
      rmSync(verifyRoot, { recursive: true, force: true });
    }

    // Pin (mirrors v2-beta-product-offline-r3.pin.json shape).
    const pin = {
      bundleSchema: BUNDLE_SCHEMA,
      claims: FALSE_CLAIMS,
      releaseId,
      releaseManifestSha256,
      schema: PIN_SCHEMA,
      status: 'pinned-beta-unqualified',
    };
    // Byte-identical to the tar-embedded manifest: no trailing newline, so the
    // on-disk copy hashes to releaseManifestSha256.
    writeFileSync(path.join(outDir, 'pf6-release.manifest.json'), canonicalize(manifest));
    writeFileSync(path.join(outDir, 'pf6-release.pin.json'), `${JSON.stringify(pin)}\n`);

    return {
      ok: true,
      releaseId,
      bundleTar: path.relative(repositoryRoot, tarPath),
      bundleBytes: statSync(tarPath).size,
      bundleSha256: sha256Bytes(readFileSync(tarPath)),
      releaseManifestSha256,
      stagedFiles: Object.fromEntries(Object.entries(sourceRels).map(([name, rels]) => [name, rels.length])),
      pinPath: 'pins/pf6-release.pin.json',
      bundleScan: {
        filesScanned: scan.files.length,
        binarySkipped: scan.binarySkipped.length,
        provenanceLinesAllowed: scan.provenanceLinesAllowed,
        frozenSchemaLinesAllowed: scan.frozenSchemaLinesAllowed,
      },
    };
  } finally {
    rmSync(stageRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const releaseId = args.includes('--release-id') ? args[args.indexOf('--release-id') + 1] : undefined;
  const outDir = args.includes('--out-dir') ? args[args.indexOf('--out-dir') + 1] : undefined;
  const result = packPf6OfflineBundle(releaseId || outDir ? { releaseId, outDir } : {});
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
