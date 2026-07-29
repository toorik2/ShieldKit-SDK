import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  realpath,
  rm,
} from 'node:fs/promises';
import { promisify } from 'node:util';
import { build } from 'esbuild';
import test from 'node:test';

const execFileAsync = promisify(execFile);
const root = new URL('./', import.meta.url);
const bundle = new URL('./.browser-test-bundle.mjs', import.meta.url);

async function createPrivateChromiumProfile() {
  // Chromium derives Unix-domain Singleton paths below this directory. This
  // test deliberately targets Linux Chromium at /usr/bin/chromium, so use a
  // short, explicit Linux root rather than the potentially long TMPDIR.
  const directory = await mkdtemp('/tmp/shieldkit-browser-');
  try {
    await chmod(directory, 0o700);
    const [canonical, metadata] = await Promise.all([
      realpath(directory),
      lstat(directory),
    ]);
    if (canonical !== directory || !metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error('Chromium profile must be a canonical non-symlink directory');
    }
    if (
      typeof process.getuid === 'function'
      && metadata.uid !== process.getuid()
    ) {
      throw new Error('Chromium profile must be owned by the current user');
    }
    if ((metadata.mode & 0o777) !== 0o700) {
      throw new Error('Chromium profile must have mode 0700');
    }
    return directory;
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

test('Chromium module worker runs the bundled SDK browser entrypoint without Node built-ins', async () => {
  await build({ entryPoints: [new URL('./browser.mjs', import.meta.url).pathname], outfile: bundle.pathname, bundle: true, format: 'esm', platform: 'browser', target: 'es2022', legalComments: 'none' });
  const bytes = (await readFile(bundle)).length;
  assert.ok(bytes > 0 && bytes < 1_000_000, 'browser SDK bundle must be a bounded local asset');
  const server = createServer(async (request, response) => {
    if (request.url === '/') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><body>pending<script type="module">const w=new Worker("/browser-worker.fixture.mjs",{type:"module"});w.onmessage=e=>document.body.textContent=JSON.stringify(e.data);w.onerror=e=>document.body.textContent="error:"+e.message;</script>');
      return;
    }
    try {
      const pathname = new URL(request.url, 'http://localhost').pathname;
      if (!/^\/[a-zA-Z0-9._-]+\.mjs$/.test(pathname)) throw new Error('invalid path');
      response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' }); response.end(await readFile(new URL(`.${pathname}`, root)));
    } catch { response.writeHead(404); response.end(); }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let chromiumProfile = null;
  try {
    chromiumProfile = await createPrivateChromiumProfile();
    const { port } = server.address();
    const { stdout } = await execFileAsync('/usr/bin/chromium', [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--virtual-time-budget=10000',
      '--dump-dom',
      `--user-data-dir=${chromiumProfile}`,
      `http://127.0.0.1:${port}/`,
    ], {
      env: { ...process.env, TMPDIR: chromiumProfile },
      maxBuffer: 1024 * 1024,
    });
    assert.match(stdout, /\{"recovered":true,"recordBytes":192\}/);
  } finally {
    try {
      if (chromiumProfile !== null) {
        await rm(chromiumProfile, { recursive: true, force: true });
      }
    } finally {
      try {
        await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      } finally {
        await rm(bundle, { force: true });
      }
    }
  }
});
