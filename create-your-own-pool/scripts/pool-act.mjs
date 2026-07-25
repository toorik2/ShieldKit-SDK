#!/usr/bin/env node
/**
 * Full act against a pool directory: deposit | transfer | withdraw.
 * Uses completeAction + optional BCHN broadcast (layer1-node).
 *
 * Usage:
 *   node create-your-own-pool/scripts/pool-act.mjs deposit --pool ./my-pool \
 *     --wallets .cache/e2e-full-20260725/local-wallets.json [--broadcast]
 *
 * Funding: --funding-txid/--funding-vout or first eligible state.feeUtxos entry.
 */
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadVerifierProfileBundle } from '../packages/profile/load.mjs';
import { completeAction, PIN_LENS } from '../packages/kit/complete-action.mjs';
import { resolveUnlockRoot } from '../packages/unlock-builder/index.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SSH_OPTS = ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=20'];

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}
function hasFlag(name) {
  return process.argv.includes(`--${name}`);
}

function bchnSendHex(hex) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `cat > /tmp/sk-pool-act.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf sendrawtransaction "$(cat /tmp/sk-pool-act.hex)" true`], {
    encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`sendraw: ${r.stderr || r.stdout}`);
  return (r.stdout || '').trim();
}

function bchnTestMempool(hex) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `cat > /tmp/sk-pool-act.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf testmempoolaccept "[\\"$(cat /tmp/sk-pool-act.hex)\\"]"`], {
    encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`testmempool: ${r.stderr || r.stdout}`);
  return JSON.parse(r.stdout);
}

function gettxout(txid, vout) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf gettxout ${txid} ${vout} true`], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  const t = (r.stdout || '').trim();
  if (!t || t === 'null') return null;
  try { return JSON.parse(t); } catch { return null; }
}

function minSats(kind) {
  return kind === 'deposit' ? 11_500_000 : 1_500_000;
}

function loadStab(kind) {
  const p = path.join(ROOT, `.cache/stabilize-pf7-${kind}/build/inputs_dump.json`);
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, 'utf8'));
}

async function main() {
  const verb = process.argv[2];
  const kind = verb === 'withdraw' ? 'withdrawal' : verb;
  if (!['deposit', 'transfer', 'withdrawal'].includes(kind)) {
    throw new Error('usage: pool-act.mjs deposit|transfer|withdraw --pool <dir> …');
  }

  const pool = path.resolve(arg('pool', ''));
  if (!pool || !existsSync(pool)) throw new Error('--pool <dir> required');
  const walletsPath = path.resolve(arg('wallets', path.join(ROOT, '.cache/e2e-full-20260725/local-wallets.json')));
  if (!existsSync(walletsPath)) throw new Error(`wallets missing: ${walletsPath}`);

  const instancePath = path.join(pool, 'instance.json');
  const statePath = path.join(pool, 'state.json');
  const bundleDir = path.join(pool, 'bundle');
  if (!existsSync(instancePath) || !existsSync(bundleDir)) {
    throw new Error('pool must contain instance.json and bundle/');
  }

  const instance = JSON.parse(readFileSync(instancePath, 'utf8'));
  const state = existsSync(statePath)
    ? JSON.parse(readFileSync(statePath, 'utf8'))
    : { stateTxid: null, feeUtxos: [], history: [] };

  const stateTxid = arg('state-txid', state.stateTxid);
  if (!stateTxid) throw new Error('stateTxid missing — set state.json or --state-txid (U-03)');

  const wallets = JSON.parse(readFileSync(walletsPath, 'utf8'));
  const hot = wallets.hot;
  const feePrivateKey = Buffer.from(hot.privateKeyHex, 'hex');
  const loaded = await loadVerifierProfileBundle(bundleDir);
  const expectedProfile = {
    profileId: instance.profileId || loaded.manifest.identity.profileId,
    instanceId: instance.instanceId || loaded.manifest.genesis.instanceId,
    network: instance.network || 'chipnet',
  };

  let funding;
  const fTx = arg('funding-txid');
  if (fTx) {
    funding = {
      txid: fTx,
      vout: Number(arg('funding-vout', '0')),
      sats: Number(arg('funding-sats', '0')),
      publicKeyHex: hot.publicKeyHex,
    };
    if (!funding.sats) {
      const u = gettxout(funding.txid, funding.vout);
      if (!u) throw new Error('funding UTXO missing on chain');
      funding.sats = Math.round(u.value * 1e8);
    }
  } else {
    const need = minSats(kind);
    const sorted = [...(state.feeUtxos || [])].sort((a, b) => b.sats - a.sats);
    const pick = sorted.find((u) => u.sats >= need && gettxout(u.txid, u.vout));
    if (!pick) throw new Error(`no fee UTXO ≥ ${need} in state.json (pass --funding-txid)`);
    funding = { ...pick, publicKeyHex: hot.publicKeyHex };
    state.feeUtxos = state.feeUtxos.filter((u) => !(u.txid === pick.txid && u.vout === pick.vout));
  }

  const wsh = createHash('sha256').update(Buffer.from(hot.lockingBytecodeHex, 'hex')).digest('hex');
  const workDir = path.join(pool, 'runs', `${kind}-${Date.now()}`);
  mkdirSync(workDir, { recursive: true });

  const digests = state.resumeDigests || {
    deposit: '00'.repeat(32), transfer: '00'.repeat(32), withdrawal: '00'.repeat(32),
  };
  const witnessSeed = state.resumeSeed || randomBytes(32).toString('hex');
  const unlockRoot = resolveUnlockRoot();
  console.error(JSON.stringify({
    phase: 'pool-act-start', kind, pool, stateTxid, unlockRoot, funding: { txid: funding.txid.slice(0, 16), vout: funding.vout, sats: funding.sats },
  }));

  const result = await completeAction({
    kind,
    bundleDirectory: bundleDir,
    expectedProfile,
    stateTxid,
    feePrivateKey,
    funding,
    workDir,
    witnessSeed,
    withdrawalScriptHash: wsh,
    withdrawalLockingBytecode: Buffer.from(hot.lockingBytecodeHex, 'hex'),
    priorCycles: state.history || [],
    transferHops: 1,
    digests,
    stabilizeUnlockTemplate: loadStab(kind) || undefined,
  });

  if (JSON.stringify(result.lens) !== JSON.stringify(PIN_LENS)) {
    throw new Error(`pin lens mismatch ${JSON.stringify(result.lens)}`);
  }

  const doBroadcast = hasFlag('broadcast');
  if (doBroadcast) {
    const prepA = bchnTestMempool(result.prepHex);
    if (!prepA[0]?.allowed) throw new Error(`prep mempool reject ${JSON.stringify(prepA)}`);
    bchnSendHex(result.prepHex);
    const setA = bchnTestMempool(result.settleHex);
    if (!setA[0]?.allowed) throw new Error(`settle mempool reject ${JSON.stringify(setA)}`);
    bchnSendHex(result.settleHex);
    for (let i = 0; i < result.complete.transaction.outputs.length; i++) {
      const o = result.complete.transaction.outputs[i];
      if (Buffer.from(o.lockingBytecode).toString('hex') === hot.lockingBytecodeHex) {
        state.feeUtxos = state.feeUtxos || [];
        state.feeUtxos.push({ txid: result.settleTxid, vout: i, sats: Number(o.valueSatoshis) });
      }
    }
  }

  state.stateTxid = result.settleTxid;
  state.resumeDigests = result.digests;
  state.resumeSeed = witnessSeed;
  state.history = state.history || [];
  state.history.push({ witnessSeed, transactionContextDigests: { ...result.digests }, kind });
  writeFileSync(statePath, JSON.stringify(state, null, 2));
  appendFileSync(path.join(pool, 'ledger.jsonl'), `${JSON.stringify({
    ts: new Date().toISOString(), kind, prepTxid: result.prepTxid, settleTxid: result.settleTxid,
    wire: result.wire, unlockMs: result.unlockMs, broadcast: doBroadcast,
  })}\n`);

  console.log(JSON.stringify({
    ok: true,
    kind,
    pool,
    prepTxid: result.prepTxid,
    settleTxid: result.settleTxid,
    wire: result.wire,
    maxUnlock: result.maxUnlock,
    proveMs: result.proveMs,
    unlockMs: result.unlockMs,
    lens: result.lens,
    unlockRoot: result.unlockRoot,
    broadcast: doBroadcast,
    workDir,
  }, null, 2));
}

main().catch((e) => {
  console.error('FAIL', e.message || e);
  process.exit(1);
});
