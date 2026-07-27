#!/usr/bin/env node
/**
 * Install the verifier pin only after validating a repository-tracked trust manifest.
 *
 * The default manifest pins the release URL, compressed archive hash, exact member set,
 * unpacked sizes, and unpacked hashes. `--from` changes transport only; it never changes
 * the expected identity.
 */
import { createHash } from 'node:crypto';
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
} from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { atomicWriteJson, PRIVATE_FILE_MODE } from '../packages/kit/secure-files.mjs';
import { assertSafeReplaceDirectory } from '../packages/kit/safe-paths.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const DEFAULT_MANIFEST = path.join(
  ROOT,
  '03-create-your-own-pool/pins/shieldkit-pin-artifacts-v1.manifest.json',
);
const HASH = /^sha256:[0-9a-f]{64}$/;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}

function sha256File(file) {
  const hash = createHash('sha256');
  hash.update(readFileSync(file));
  return `sha256:${hash.digest('hex')}`;
}

function readTrustManifest(manifestPath) {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  if (manifest?.schema !== 'shieldkit/pin-artifacts-manifest/v2') {
    throw new Error('trusted pin manifest must use shieldkit/pin-artifacts-manifest/v2');
  }
  if (!manifest.source || typeof manifest.source.url !== 'string'
    || !/^https:\/\//.test(manifest.source.url)) {
    throw new Error('trusted pin manifest requires an HTTPS source URL');
  }
  if (!manifest.tar || !SAFE_NAME.test(manifest.tar.fileName)
    || !Number.isSafeInteger(manifest.tar.bytes) || manifest.tar.bytes <= 0
    || !HASH.test(manifest.tar.sha256)) {
    throw new Error('trusted pin manifest tar identity is invalid');
  }
  const names = Object.keys(manifest.files || {}).sort();
  if (names.length === 0 || names.some((name) => !SAFE_NAME.test(name))) {
    throw new Error('trusted pin manifest file set is invalid');
  }
  for (const name of names) {
    const expected = manifest.files[name];
    if (!Number.isSafeInteger(expected?.bytes) || expected.bytes <= 0 || !HASH.test(expected.sha256)) {
      throw new Error(`trusted pin manifest identity is invalid for ${name}`);
    }
  }
  return { manifest, names };
}

async function download(url, destination) {
  const response = await fetch(url, {
    redirect: 'follow',
    signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok) throw new Error(`download ${url} returned HTTP ${response.status}`);
  await pipeline(
    Readable.fromWeb(response.body),
    createWriteStream(destination, { flags: 'wx', mode: PRIVATE_FILE_MODE }),
  );
}

function verifyArchiveMembers(tarPath, expectedNames) {
  const listed = spawnSync('tar', ['-tzf', tarPath], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
  if (listed.status !== 0) throw new Error(`cannot list pin archive: ${listed.stderr || listed.stdout}`);
  const actual = listed.stdout.split('\n').filter(Boolean).sort();
  if (actual.length !== expectedNames.length
    || actual.some((name, index) => name !== expectedNames[index])) {
    throw new Error(
      `pin archive member set mismatch: expected ${JSON.stringify(expectedNames)}, `
      + `got ${JSON.stringify(actual)}`,
    );
  }
}

function verifyExtracted(staging, manifest, names) {
  for (const name of names) {
    const file = path.join(staging, name);
    const stats = lstatSync(file);
    if (!stats.isFile() || stats.isSymbolicLink()) throw new Error(`${name} is not a regular file`);
    const expected = manifest.files[name];
    if (stats.size !== expected.bytes) {
      throw new Error(`${name} size mismatch: expected ${expected.bytes}, got ${stats.size}`);
    }
    const actualHash = sha256File(file);
    if (actualHash !== expected.sha256) {
      throw new Error(`${name} hash mismatch: expected ${expected.sha256}, got ${actualHash}`);
    }
  }
}

function installedMatches(destination, manifest, manifestSha256) {
  const marker = path.join(destination, 'PIN_INSTALL.json');
  if (!existsSync(marker)) return false;
  try {
    const installed = JSON.parse(readFileSync(marker, 'utf8'));
    if (installed.manifestSha256 !== manifestSha256
      || installed.tarSha256 !== manifest.tar.sha256) return false;
    return Object.entries(manifest.files).every(([name, expected]) => {
      const file = path.join(destination, name);
      return existsSync(file) && statSync(file).size === expected.bytes && sha256File(file) === expected.sha256;
    });
  } catch {
    return false;
  }
}

async function main() {
  const manifestPath = path.resolve(arg('manifest', DEFAULT_MANIFEST));
  const { manifest, names } = readTrustManifest(manifestPath);
  const manifestSha256 = sha256File(manifestPath);
  const destination = assertSafeReplaceDirectory(
    arg('dest', path.join(ROOT, '.cache/profile-build-live/artifacts')),
    { repositoryRoot: ROOT },
  );
  const force = process.argv.includes('--force');
  if (!force && installedMatches(destination, manifest, manifestSha256)) {
    console.log(JSON.stringify({
      ok: true,
      skipped: true,
      reason: 'installed pin exactly matches trusted manifest',
      destination,
      manifest: manifestPath,
      manifestSha256,
    }, null, 2));
    return;
  }

  const cacheDirectory = path.join(ROOT, '.cache/pins');
  mkdirSync(cacheDirectory, { recursive: true, mode: 0o700 });
  let source = arg('from', process.env.SHIELDKIT_PIN_TAR || '');
  const cached = path.join(cacheDirectory, manifest.tar.fileName);
  if (!source && existsSync(cached)) source = cached;
  if (!source) source = manifest.source.url;

  let tarPath;
  let downloaded = false;
  if (/^https:\/\//.test(source)) {
    tarPath = path.join(cacheDirectory, `.download-${process.pid}-${Date.now()}.tar.gz`);
    console.error(JSON.stringify({ phase: 'download', source }));
    await download(source, tarPath);
    downloaded = true;
  } else {
    if (/^[a-z]+:\/\//i.test(source)) throw new Error('pin source must be HTTPS or a local path');
    tarPath = path.resolve(source);
    if (!existsSync(tarPath)) throw new Error(`pin archive not found: ${tarPath}`);
  }

  const actualTarBytes = statSync(tarPath).size;
  const actualTarHash = sha256File(tarPath);
  if (actualTarBytes !== manifest.tar.bytes || actualTarHash !== manifest.tar.sha256) {
    if (downloaded) rmSync(tarPath, { force: true });
    throw new Error(
      `pin archive identity mismatch: expected ${manifest.tar.bytes} bytes ${manifest.tar.sha256}, `
      + `got ${actualTarBytes} bytes ${actualTarHash}`,
    );
  }
  verifyArchiveMembers(tarPath, names);

  const staging = `${destination}.staging-${process.pid}-${Date.now()}`;
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true, mode: 0o700 });
  try {
    const extracted = spawnSync('tar', ['-xzf', tarPath, '-C', staging, '--no-same-owner', '--no-same-permissions'], {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    });
    if (extracted.status !== 0) throw new Error(`pin extraction failed: ${extracted.stderr || extracted.stdout}`);
    verifyExtracted(staging, manifest, names);
    atomicWriteJson(path.join(staging, 'PIN_INSTALL.json'), {
      schema: 'shieldkit/pin-artifacts-install/v2',
      installedAt: new Date().toISOString(),
      source: /^https:\/\//.test(source) ? source : 'local-file',
      manifest: path.relative(ROOT, manifestPath),
      manifestSha256,
      tarSha256: actualTarHash,
      files: manifest.files,
    });
    rmSync(destination, { recursive: true, force: true });
    mkdirSync(path.dirname(destination), { recursive: true });
    renameSync(staging, destination);
  } catch (error) {
    rmSync(staging, { recursive: true, force: true });
    throw error;
  } finally {
    if (downloaded && existsSync(tarPath)) rmSync(tarPath, { force: true });
  }

  console.log(JSON.stringify({
    ok: true,
    destination,
    manifest: manifestPath,
    manifestSha256,
    tarSha256: actualTarHash,
    files: names.length,
    totalBytes: Object.values(manifest.files).reduce((sum, file) => sum + file.bytes, 0),
  }, null, 2));
}

main().catch((error) => {
  console.error('FAIL', error.message || error);
  process.exit(1);
});
