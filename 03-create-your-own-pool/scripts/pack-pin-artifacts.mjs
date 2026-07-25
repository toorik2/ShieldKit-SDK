#!/usr/bin/env node
/**
 * Pack pin circuit/profile artifacts for distribution (closes UX U-01).
 *
 * Source (default): .cache/profile-build-live/artifacts
 * Output (default): .cache/pins/shieldkit-pin-artifacts-v1.tar.gz + manifest.json
 *
 * Usage:
 *   node 03-create-your-own-pool/scripts/pack-pin-artifacts.mjs
 *   node 03-create-your-own-pool/scripts/pack-pin-artifacts.mjs --source … --out …
 */
import { createHash } from 'node:crypto';
import {
  createWriteStream, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const REQUIRED = [
  'final.zkey',
  'g1_relation.r1cs',
  'g1_relation.wasm',
  'verification_key.json',
  'verifier-set.bin',
  'public-input-abi.json',
  'relation.json',
  'setup-metadata.json',
  'circom2-cli.js',
  'snarkjs-cli.cjs',
];

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}

function sha256File(p) {
  return `sha256:${createHash('sha256').update(readFileSync(p)).digest('hex')}`;
}

function main() {
  const source = path.resolve(arg('source', path.join(ROOT, '.cache/profile-build-live/artifacts')));
  const outDir = path.resolve(arg('out-dir', path.join(ROOT, '.cache/pins')));
  const tag = arg('tag', 'v1');
  const tarName = `shieldkit-pin-artifacts-${tag}.tar.gz`;
  const tarPath = path.join(outDir, tarName);

  if (!existsSync(source)) {
    throw new Error(`pin source missing: ${source}`);
  }
  const missing = REQUIRED.filter((f) => !existsSync(path.join(source, f)));
  if (missing.length) throw new Error(`missing pin files: ${missing.join(', ')}`);

  mkdirSync(outDir, { recursive: true });
  const files = {};
  let total = 0;
  for (const name of REQUIRED) {
    const p = path.join(source, name);
    const st = statSync(p);
    total += st.size;
    files[name] = { bytes: st.size, sha256: sha256File(p) };
  }

  // portable tar of just required files
  const r = spawnSync('tar', ['-czf', tarPath, '-C', source, ...REQUIRED], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`tar failed: ${r.stderr || r.stdout}`);

  const manifest = {
    schema: 'shieldkit/pin-artifacts-manifest/v1',
    tag,
    createdAt: new Date().toISOString(),
    tar: {
      path: tarPath,
      fileName: tarName,
      bytes: statSync(tarPath).size,
      sha256: sha256File(tarPath),
    },
    files,
    totalUnpackedBytes: total,
    install: {
      destDefault: '.cache/profile-build-live/artifacts',
      command: `npm run fetch-pin-artifacts -- --from ${tarPath}`,
    },
  };
  const manPath = path.join(outDir, `shieldkit-pin-artifacts-${tag}.manifest.json`);
  writeFileSync(manPath, JSON.stringify(manifest, null, 2));
  console.log(JSON.stringify({
    ok: true,
    tar: tarPath,
    tarBytes: manifest.tar.bytes,
    tarSha256: manifest.tar.sha256,
    manifest: manPath,
    totalUnpackedBytes: total,
  }, null, 2));
}

main();
