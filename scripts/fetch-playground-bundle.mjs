#!/usr/bin/env node
/**
 * Fetch + verify the Chipnet playground profile bundle (release asset).
 * Development-only example — not production privacy.
 *
 * Usage:
 *   node scripts/fetch-playground-bundle.mjs
 *   node scripts/fetch-playground-bundle.mjs --out chipnet-playground-live-pool/bundle
 *   SHIELDKIT_PLAYGROUND_BUNDLE=... is set by printing export line on success
 */
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const instancePath = path.join(root, 'chipnet-playground-live-pool/instance.json');

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}

async function sha256File(file) {
  const h = createHash('sha256');
  const { createReadStream } = await import('node:fs');
  await new Promise((resolve, reject) => {
    const s = createReadStream(file);
    s.on('data', (c) => h.update(c));
    s.on('error', reject);
    s.on('end', resolve);
  });
  return `sha256:${h.digest('hex')}`;
}

async function main() {
  const instance = JSON.parse(await readFile(instancePath, 'utf8'));
  const release = instance.profileBundle?.release;
  if (!release?.url || !release?.sha256) {
    console.error('instance.json missing profileBundle.release.url/sha256');
    process.exit(1);
  }

  const outDir = path.resolve(arg('out', path.join(root, 'chipnet-playground-live-pool/bundle')));
  const cacheDir = path.join(root, '.cache/playground-download');
  await mkdir(cacheDir, { recursive: true });
  const tarPath = path.join(cacheDir, 'chipnet-playground-profile-bundle.tar.gz');

  console.error('Downloading', release.url);
  const res = await fetch(release.url);
  if (!res.ok) {
    console.error(`download failed: HTTP ${res.status}`);
    process.exit(1);
  }
  await pipeline(res.body, createWriteStream(tarPath));
  const got = await sha256File(tarPath);
  if (got !== release.sha256) {
    console.error(`tarball hash mismatch:\n  expected ${release.sha256}\n  got      ${got}`);
    process.exit(1);
  }
  console.error('Tarball verified', got);

  await rm(outDir, { recursive: true, force: true });
  await mkdir(path.dirname(outDir), { recursive: true });
  // extract: tarball contains top-level profile-bundle/
  await execFileAsync('tar', ['-xzf', tarPath, '-C', cacheDir]);
  const extracted = path.join(cacheDir, 'profile-bundle');
  await rename(extracted, outDir);

  // verify manifest present
  await stat(path.join(outDir, 'manifest.json'));
  // optional: verify proving key hash if listed
  const pk = instance.profileBundle?.provingKeySha256;
  if (pk) {
    const pkPath = path.join(outDir, 'artifacts/final.zkey');
    const pkHash = await sha256File(pkPath);
    if (pkHash !== pk) {
      console.error(`proving key hash mismatch:\n  expected ${pk}\n  got ${pkHash}`);
      process.exit(1);
    }
    console.error('Proving key verified');
  }

  console.log(outDir);
  console.error(`\nexport SHIELDKIT_PLAYGROUND_BUNDLE="${outDir}"`);
  console.error('node scripts/shieldkit.mjs playground doctor');
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
