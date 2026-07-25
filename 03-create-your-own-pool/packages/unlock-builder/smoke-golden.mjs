#!/usr/bin/env node
/**
 * Golden smoke: rebuild unlocks for a known live-battery adapter+packet.
 * Usage (from repo root):
 *   node 03-create-your-own-pool/packages/unlock-builder/smoke-golden.mjs \
 *     [--adapter path] [--packet path] [--out path]
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildVerifierUnlocks, PIN_LENS } from './index.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../../..');

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  return fallback;
}

const adapterPath = path.resolve(arg(
  'adapter',
  path.join(REPO, '.cache/live-battery/run-20260724/cycles/18/deposit-adapter.json'),
));
const packetPath = path.resolve(arg(
  'packet',
  path.join(REPO, '.cache/live-battery/run-20260724/cycles/18/deposit.packet'),
));
const outDir = path.resolve(arg(
  'out',
  path.join(REPO, '.cache/unlock-builder-smoke'),
));

const t0 = Date.now();
try {
  const out = buildVerifierUnlocks({ adapterPath, packetPath, outDir });
  console.log(JSON.stringify({
    ok: true,
    ms: Date.now() - t0,
    lens: out.lens,
    pinLens: PIN_LENS,
    wire: out.wire,
    unlockRoot: out.unlockRoot,
    roles: out.roles.map((r) => ({ name: r.name, unlockLen: r.unlockLen, lock: r.lockHex.slice(0, 16) })),
  }, null, 2));
} catch (err) {
  console.error(JSON.stringify({
    ok: false,
    ms: Date.now() - t0,
    code: err.code || 'ERROR',
    message: err.message,
    logTail: err.logTail?.slice?.(-1500),
  }, null, 2));
  process.exit(1);
}
