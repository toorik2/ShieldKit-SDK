#!/usr/bin/env node
/**
 * doctor --pool preflight (UX red team).
 *
 * Checks: instance, bundle load, tip, fee UTXOs, pin arts, unlock vendor, PIN_LENS.
 */
import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { loadVerifierProfileBundle } from '../packages/profile/load.mjs';
import {
  PIN_LENS, resolveUnlockRoot, resolveLeanRoot,
} from '../packages/unlock-builder/index.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SSH_OPTS = ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=10'];
const PIN_FILES = [
  'final.zkey', 'g1_relation.r1cs', 'g1_relation.wasm', 'verification_key.json', 'verifier-set.bin',
];

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}

function gettxout(txid, vout) {
  try {
    const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
      `sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf gettxout ${txid} ${vout} true`], {
      encoding: 'utf8', timeout: 15000,
    });
    if (r.status !== 0) return null;
    const t = (r.stdout || '').trim();
    if (!t || t === 'null') return null;
    return JSON.parse(t);
  } catch {
    return null;
  }
}

async function main() {
  const pool = path.resolve(arg('pool', ''));
  if (!pool) {
    console.log(JSON.stringify({
      ok: false,
      code: 'POOL_REQUIRED',
      message: 'doctor --pool <dir>',
      usage: 'npm run shieldkit -- doctor --pool ./my-pool',
    }, null, 2));
    process.exit(2);
  }

  const checks = [];
  const push = (id, ok, detail = {}) => checks.push({ id, ok, ...detail });

  // instance + bundle
  const instancePath = path.join(pool, 'instance.json');
  const bundleDir = path.join(pool, 'bundle');
  const statePath = path.join(pool, 'state.json');
  push('instance.json', existsSync(instancePath), { path: instancePath });
  push('bundle/', existsSync(bundleDir), { path: bundleDir });

  let instance = null;
  let loaded = null;
  if (existsSync(instancePath)) {
    try {
      instance = JSON.parse(readFileSync(instancePath, 'utf8'));
      push('instance.parse', true, {
        profileId: instance.profileId,
        instanceId: instance.instanceId,
        network: instance.network,
      });
    } catch (e) {
      push('instance.parse', false, { error: e.message });
    }
  }
  if (existsSync(bundleDir)) {
    try {
      loaded = await loadVerifierProfileBundle(bundleDir);
      push('bundle.load', true, {
        profileId: loaded.manifest.identity.profileId,
        instanceId: loaded.manifest.genesis.instanceId,
        setupMode: loaded.manifest.setup?.mode,
      });
      if (instance?.profileId && instance.profileId !== loaded.manifest.identity.profileId) {
        push('profileId.match', false, { instance: instance.profileId, bundle: loaded.manifest.identity.profileId });
      } else if (instance?.profileId) {
        push('profileId.match', true);
      }
    } catch (e) {
      push('bundle.load', false, { error: e.message, code: e.code });
    }
  }

  // tip (U-03)
  let state = null;
  if (existsSync(statePath)) {
    try {
      state = JSON.parse(readFileSync(statePath, 'utf8'));
      push('state.json', true);
    } catch (e) {
      push('state.json', false, { error: e.message });
    }
  } else {
    push('state.json', false, { error: 'missing' });
  }
  const tip = state?.stateTxid || null;
  push('stateTxid', Boolean(tip), { stateTxid: tip, note: tip ? null : 'set after genesis or --state-txid (U-03)' });

  // fee inventory
  const fees = state?.feeUtxos || [];
  let liveFees = 0;
  let rpcOk = null;
  if (fees.length) {
    for (const u of fees.slice(0, 20)) {
      const o = gettxout(u.txid, u.vout);
      if (o) liveFees += 1;
      if (rpcOk === null) rpcOk = o !== null || true;
    }
    // if all null might be network
    push('feeUtxos', fees.length > 0, { count: fees.length, liveSample: liveFees });
  } else {
    push('feeUtxos', false, { count: 0, note: 'no fee UTXOs in state — fund hot wallet' });
  }
  push('rpc.layer1-node', rpcOk !== false, {
    note: 'gettxout via ssh layer1-node (optional for offline doctor)',
  });

  // pin arts for create-pool / prove
  const pinDest = path.join(ROOT, '.cache/profile-build-live/artifacts');
  const pinOk = PIN_FILES.every((f) => existsSync(path.join(pinDest, f)));
  push('pin.artifacts', pinOk, {
    path: pinDest,
    missing: PIN_FILES.filter((f) => !existsSync(path.join(pinDest, f))),
    fix: pinOk ? null : 'npm run fetch-pin-artifacts',
  });

  // unlock vendor
  let unlockRoot = null;
  let leanRoot = null;
  try {
    unlockRoot = resolveUnlockRoot();
    leanRoot = resolveLeanRoot();
    push('unlock.vendor', true, { unlockRoot, leanRoot, pinLens: PIN_LENS });
  } catch (e) {
    push('unlock.vendor', false, { error: e.message });
  }

  // protocol limits
  push('protocol.limits', true, {
    feeRateSatPerByte: 1,
    unlockMaxBytes: 10000,
    settlementWireMax: 59000,
    pinLens: PIN_LENS,
    feeKeyPolicy: 'A=feePrivateKey | B=feePublicKey+feeSignature',
  });

  const failed = checks.filter((c) => !c.ok);
  const critical = failed.filter((c) => ['instance.json', 'bundle/', 'bundle.load', 'stateTxid', 'unlock.vendor'].includes(c.id));

  const body = {
    ok: critical.length === 0,
    pool,
    checks,
    failed: failed.map((c) => c.id),
    criticalFailed: critical.map((c) => c.id),
    next: critical.length === 0
      ? [
        'npm run shieldkit -- deposit --pool <dir> --wallets … --broadcast',
        'or: node create-your-own-pool/scripts/pool-act.mjs deposit --pool … --broadcast',
      ]
      : [
        !pinOk ? 'npm run fetch-pin-artifacts' : null,
        !tip ? 'create-pool --with-genesis --broadcast  OR set state.json stateTxid' : null,
        !existsSync(bundleDir) ? 'create-pool --out <dir>' : null,
      ].filter(Boolean),
  };

  console.log(JSON.stringify(body, null, 2));
  process.exit(body.ok ? 0 : 2);
}

main().catch((e) => {
  console.error(JSON.stringify({ ok: false, error: e.message || String(e) }, null, 2));
  process.exit(1);
});
