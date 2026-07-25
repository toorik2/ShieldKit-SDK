#!/usr/bin/env node
/**
 * Install pin artifacts for create-pool / prove (UX U-01).
 *
 * Sources (first hit):
 *   --from <path|url>          explicit
 *   SHIELDKIT_PIN_TAR          env
 *   .cache/pins/shieldkit-pin-artifacts-v1.tar.gz
 *   If none: try pack from existing .cache/profile-build-live/artifacts
 *
 * Dest (default): .cache/profile-build-live/artifacts
 *
 * Usage:
 *   npm run fetch-pin-artifacts
 *   npm run fetch-pin-artifacts -- --from /path/to/pin.tar.gz
 *   npm run fetch-pin-artifacts -- --from https://…/pin.tar.gz
 */
import { createHash } from 'node:crypto';
import {
  createWriteStream, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const REQUIRED = [
  'final.zkey', 'g1_relation.r1cs', 'g1_relation.wasm', 'verification_key.json',
  'verifier-set.bin', 'public-input-abi.json', 'relation.json', 'setup-metadata.json',
  'circom2-cli.js', 'snarkjs-cli.cjs',
];

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}

function sha256File(p) {
  return `sha256:${createHash('sha256').update(readFileSync(p)).digest('hex')}`;
}

async function download(url, dest) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download ${url} → HTTP ${res.status}`);
  await pipeline(Readable.fromWeb(res.body), createWriteStream(dest));
}

function completeDest(dest) {
  return REQUIRED.every((f) => existsSync(path.join(dest, f)));
}

async function main() {
  const dest = path.resolve(arg('dest', path.join(ROOT, '.cache/profile-build-live/artifacts')));
  const force = process.argv.includes('--force');
  if (completeDest(dest) && !force) {
    console.log(JSON.stringify({
      ok: true,
      skipped: true,
      reason: 'dest already complete (pass --force to overwrite)',
      dest,
    }, null, 2));
    return;
  }

  let from = arg('from', process.env.SHIELDKIT_PIN_TAR || '');
  const defaultTar = path.join(ROOT, '.cache/pins/shieldkit-pin-artifacts-v1.tar.gz');
  if (!from && existsSync(defaultTar)) from = defaultTar;

  if (!from) {
    // try pack from live source if present
    const live = path.join(ROOT, '.cache/profile-build-live/artifacts');
    if (completeDest(live)) {
      console.error(JSON.stringify({ phase: 'pack-local', source: live }));
      const pack = spawnSync(process.execPath, [
        path.join(ROOT, '03-create-your-own-pool/scripts/pack-pin-artifacts.mjs'),
        '--source', live,
      ], { encoding: 'utf8' });
      if (pack.status !== 0) throw new Error(pack.stderr || pack.stdout);
      from = defaultTar;
    }
  }

  if (!from) {
    throw new Error(
      'no pin tarball. Provide --from <path|url>, set SHIELDKIT_PIN_TAR, '
      + 'or place .cache/pins/shieldkit-pin-artifacts-v1.tar.gz, '
      + 'or keep a full .cache/profile-build-live/artifacts and re-run.',
    );
  }

  mkdirSync(path.dirname(dest), { recursive: true });
  mkdirSync(dest, { recursive: true });

  let tarPath = from;
  if (/^https?:\/\//i.test(from)) {
    const tmp = path.join(ROOT, '.cache/pins', `download-${Date.now()}.tar.gz`);
    mkdirSync(path.dirname(tmp), { recursive: true });
    console.error(JSON.stringify({ phase: 'download', url: from, tmp }));
    await download(from, tmp);
    tarPath = tmp;
  } else {
    tarPath = path.resolve(from);
    if (!existsSync(tarPath)) throw new Error(`tar not found: ${tarPath}`);
  }

  console.error(JSON.stringify({ phase: 'extract', tar: tarPath, dest }));
  // clear partial dest files if force
  if (force) {
    for (const f of REQUIRED) {
      const p = path.join(dest, f);
      if (existsSync(p)) rmSync(p);
    }
  }
  const r = spawnSync('tar', ['-xzf', tarPath, '-C', dest], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`extract failed: ${r.stderr || r.stdout}`);

  const missing = REQUIRED.filter((f) => !existsSync(path.join(dest, f)));
  if (missing.length) throw new Error(`extract incomplete, missing: ${missing.join(', ')}`);

  const files = Object.fromEntries(REQUIRED.map((name) => {
    const p = path.join(dest, name);
    return [name, { bytes: statSync(p).size, sha256: sha256File(p) }];
  }));

  const installMeta = {
    schema: 'shieldkit/pin-artifacts-install/v1',
    installedAt: new Date().toISOString(),
    tar: tarPath,
    tarSha256: sha256File(tarPath),
    dest,
    files,
  };
  writeFileSync(path.join(dest, 'PIN_INSTALL.json'), JSON.stringify(installMeta, null, 2));
  // also ensure profile-bundle sibling exists if missing: operator may scaffold from dest
  console.log(JSON.stringify({
    ok: true,
    dest,
    tar: tarPath,
    files: Object.keys(files).length,
    totalBytes: Object.values(files).reduce((s, f) => s + f.bytes, 0),
    next: [
      'npm run create-pool -- --out ./my-pool',
      'npm run create-pool -- --out ./new --with-genesis --fund-txid … --broadcast',
    ],
  }, null, 2));
}

main().catch((e) => {
  console.error('FAIL', e.message || e);
  process.exit(1);
});
