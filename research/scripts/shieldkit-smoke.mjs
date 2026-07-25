#!/usr/bin/env node
/**
 * Golden-path live smoke: one deposit→transfer→withdrawal (or resume kinds)
 * via the battery runner with injectible config (network gates via app-kit).
 *
 * Example:
 *   SHIELDKIT_WALLETS=... node scripts/shieldkit-smoke.mjs --cycle 17 --kinds transfer,withdrawal
 */
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertBroadcastAllowed, resolveNetwork } from '../../packages/kit/network.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}
function flag(name) {
  return process.argv.includes(`--${name}`);
}

const network = arg('network', 'chipnet');
resolveNetwork(network);
assertBroadcastAllowed({
  network,
  setupMode: arg('setup-mode', 'development-only'),
  mainnetAcknowledged: flag('i-understand-mainnet'),
  allowDevelopmentOnMainnet: flag('allow-development-on-mainnet'),
});

const cycle = arg('cycle', '18');
const kinds = arg('kinds', 'deposit,transfer,withdrawal');
const runDir = path.resolve(arg('run-dir', path.join(ROOT, '.cache/live-battery/run-20260724')));
const wallets = path.resolve(arg('wallets', process.env.SHIELDKIT_WALLETS || ''));
const bundle = path.resolve(arg('bundle', process.env.SHIELDKIT_BUNDLE || path.join(ROOT, '.cache/profile-build-live/profile-bundle')));

if (!wallets || wallets === path.resolve('')) {
  console.error(JSON.stringify({ ok: false, error: 'required --wallets or SHIELDKIT_WALLETS' }));
  process.exit(1);
}

const script = path.join(ROOT, 'scripts/golden-path-cycle.mjs');
const args = [
  script,
  '--run-dir', runDir,
  '--cycle', cycle,
  '--kinds', kinds,
  '--wallets', wallets,
  '--bundle', bundle,
];
console.log(JSON.stringify({
  smoke: true, network, cycle, kinds, runDir, wallets: path.basename(wallets), bundle: path.basename(bundle),
}));
const r = spawnSync(process.execPath, args, {
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
  env: { ...process.env, SHIELDKIT_WALLETS: wallets, SHIELDKIT_BUNDLE: bundle },
  cwd: ROOT,
});
process.stdout.write(r.stdout || '');
process.stderr.write(r.stderr || '');
process.exit(r.status === null ? 1 : r.status);
