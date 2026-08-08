#!/usr/bin/env node
/**
 * Fetch + verify the Chipnet playground profile bundle (release asset).
 * Development-only demo — not production privacy.
 *
 * Download strategy:
 *   1) unauthenticated HTTPS (public assets)
 *   2) if 404/403 and `gh` is available: `gh release download` (private repos)
 *
 * Usage:
 *   node designs/pf10/scripts/fetch-playground-bundle.mjs
 *   node designs/pf10/scripts/fetch-playground-bundle.mjs --out designs/pf10/demo/chipnet/bundle
 */
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import {
  lstat, mkdir, readFile, readdir, realpath, rename, rm, stat,
} from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { assertSafeReplaceDirectory } from '../packages/kit/safe-paths.mjs';

const execFileAsync = promisify(execFile);
const monorepoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const instancePath = path.join(monorepoRoot, 'designs/pf10/demo/chipnet/instance.json');

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

async function downloadHttps(url, tarPath) {
  const res = await fetch(url);
  if (!res.ok) {
    const err = new Error(`HTTPS download failed: HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  await pipeline(res.body, createWriteStream(tarPath));
}

async function downloadViaGh(tag, assetName, tarPath) {
  // gh writes into -D directory with original asset name
  const dir = path.dirname(tarPath);
  const tmpName = path.basename(tarPath);
  await execFileAsync('gh', [
    'release', 'download', tag,
    '-R', 'toorik2/ShieldKit-SDK',
    '-p', assetName,
    '-D', dir,
    '--clobber',
  ], { maxBuffer: 8 * 1024 * 1024 });
  const downloaded = path.join(dir, assetName);
  if (downloaded !== tarPath) {
    await rename(downloaded, tarPath);
  }
  void tmpName;
}

async function verifySafeArchive(tarPath) {
  const { stdout } = await execFileAsync('tar', ['-tzf', tarPath], {
    maxBuffer: 8 * 1024 * 1024,
  });
  const members = stdout.split('\n').filter(Boolean);
  const unique = new Set(members);
  if (members.length === 0 || unique.size !== members.length) {
    throw new Error('playground archive must have a nonempty unique member set');
  }
  for (const member of members) {
    const parts = member.replace(/\/$/, '').split('/');
    if (!member.startsWith('profile-bundle/')
      || member.startsWith('/')
      || member.includes('\\')
      || parts.some((part) => !part || part === '.' || part === '..')) {
      throw new Error(`unsafe playground archive member: ${member}`);
    }
  }
  const verbose = await execFileAsync('tar', ['-tvzf', tarPath], {
    maxBuffer: 8 * 1024 * 1024,
  });
  if (verbose.stdout.split('\n').some((line) => /^[lh]/.test(line))) {
    throw new Error('playground archive links are forbidden');
  }
}

async function verifyExtractedTree(root) {
  const rootReal = await realpath(root);
  const visit = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const filename = path.join(directory, entry.name);
      const stats = await lstat(filename);
      if (stats.isSymbolicLink()) throw new Error(`extracted symlink is forbidden: ${entry.name}`);
      const resolved = await realpath(filename);
      if (resolved !== rootReal && !resolved.startsWith(`${rootReal}${path.sep}`)) {
        throw new Error(`extracted member escaped staging: ${entry.name}`);
      }
      if (stats.isDirectory()) await visit(filename);
      else if (!stats.isFile()) throw new Error(`unsupported extracted file type: ${entry.name}`);
    }
  };
  await visit(root);
}

async function main() {
  const instance = JSON.parse(await readFile(instancePath, 'utf8'));
  const release = instance.profileBundle?.release;
  if (!release?.url || !release?.sha256 || !release?.tag) {
    console.error('instance.json missing profileBundle.release.url/sha256/tag');
    process.exit(1);
  }

  const outDir = assertSafeReplaceDirectory(
    arg('out', path.join(monorepoRoot, 'designs/pf10/demo/chipnet/bundle')),
    { repositoryRoot: monorepoRoot },
  );
  const cacheDir = path.join(monorepoRoot, '.cache/playground-download');
  await mkdir(cacheDir, { recursive: true });
  const assetName = path.basename(new URL(release.url).pathname);
  const tarPath = path.join(cacheDir, assetName);

  console.error('Downloading', release.url);
  try {
    await downloadHttps(release.url, tarPath);
    console.error('Downloaded via HTTPS');
  } catch (e) {
    if (e.status === 404 || e.status === 403) {
      console.error(
        `Unauthenticated download failed (HTTP ${e.status}). `
          + 'Repo/asset may be private — trying authenticated `gh release download`…',
      );
      try {
        await downloadViaGh(release.tag, assetName, tarPath);
        console.error('Downloaded via gh (authenticated)');
      } catch (ghErr) {
        console.error(
          'Both HTTPS and gh download failed.\n'
            + `  HTTPS: ${e.message}\n`
            + `  gh: ${ghErr.message || ghErr}\n`
            + 'Fix: make the release asset public, or install/login `gh` with repo read access.\n'
            + `Manual: gh release download ${release.tag} -p ${assetName}`,
        );
        process.exit(1);
      }
    } else {
      console.error(e.message || e);
      process.exit(1);
    }
  }

  const got = await sha256File(tarPath);
  if (got !== release.sha256) {
    console.error(`tarball hash mismatch:\n  expected ${release.sha256}\n  got      ${got}`);
    process.exit(1);
  }
  console.error('Tarball verified', got);
  await verifySafeArchive(tarPath);

  await rm(outDir, { recursive: true, force: true });
  await mkdir(path.dirname(outDir), { recursive: true });
  // extract into cache then move profile-bundle/ → outDir
  const extractRoot = path.join(cacheDir, 'extract');
  await rm(extractRoot, { recursive: true, force: true });
  await mkdir(extractRoot, { recursive: true });
  await execFileAsync('tar', ['-xzf', tarPath, '-C', extractRoot]);
  const extracted = path.join(extractRoot, 'profile-bundle');
  await verifyExtractedTree(extracted);
  await rename(extracted, outDir);

  await stat(path.join(outDir, 'manifest.json'));
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
  console.error('node designs/pf10/scripts/shieldkit.mjs playground doctor');
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
