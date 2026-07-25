#!/usr/bin/env node
/**
 * Standalone Chipnet e2e: deposit → transfer → withdrawal using only product packages.
 * Unlock builder resolves packages/unlock-builder/vendor/* (no sibling verifier.cash).
 *
 * Requires: SSH host `layer1-node` BCHN, wallets, live profile tip (or --state-txid).
 *
 * Usage (repo root):
 *   node create-your-own-pool/scripts/standalone-e2e-chipnet.mjs \
 *     [--out .cache/standalone-e2e] \
 *     [--kinds deposit,transfer,withdrawal]
 */
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hash256 } from '../packages/action/node_modules/@bitauth/libauth/build/index.js';
import { loadVerifierProfileBundle } from '../packages/profile/load.mjs';
import { completeAction, PIN_LENS } from '../packages/kit/complete-action.mjs';
import { resolveUnlockRoot, resolveLeanRoot } from '../packages/unlock-builder/index.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}

const OUT = path.resolve(arg('out', path.join(ROOT, '.cache/standalone-e2e')));
const KINDS = (arg('kinds', 'deposit,transfer,withdrawal')).split(',').map((s) => s.trim());
const BUNDLE = path.resolve(arg('bundle', path.join(ROOT, '.cache/profile-build-live/profile-bundle')));
const WALLETS = path.resolve(arg('wallets', path.join(ROOT, '.cache/e2e-full-20260725/local-wallets.json')));
const STATE_FILE = path.resolve(arg('state', path.join(ROOT, '.cache/live-battery/run-20260724/state.json')));
const STAB = {
  deposit: path.join(ROOT, '.cache/stabilize-pf7-deposit/build/inputs_dump.json'),
  transfer: path.join(ROOT, '.cache/stabilize-pf7-transfer/build/inputs_dump.json'),
  withdrawal: path.join(ROOT, '.cache/stabilize-pf7-withdrawal/build/inputs_dump.json'),
};

const SSH_OPTS = ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=20'];

function sshRetry(label, fn) {
  let last;
  for (let i = 0; i < 5; i++) {
    try { return fn(); } catch (e) {
      last = e;
      if (!/Network|Connection|unreachable|timed out/i.test(String(e.message || e))) throw e;
      spawnSync('sleep', [String(1 + i)]);
    }
  }
  throw last;
}

function bchnSendHex(hex) {
  return sshRetry('sendraw', () => {
    const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
      `cat > /tmp/sk-standalone.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf sendrawtransaction "$(cat /tmp/sk-standalone.hex)"`], {
      encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
    });
    if (r.status !== 0) throw new Error(`sendraw: ${r.stderr || r.stdout}`);
    return (r.stdout || '').trim();
  });
}

function bchnTestMempool(hex) {
  return sshRetry('testmempool', () => {
    const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
      `cat > /tmp/sk-standalone.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf testmempoolaccept "[\\"$(cat /tmp/sk-standalone.hex)\\"]"`], {
      encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
    });
    if (r.status !== 0) throw new Error(`testmempool: ${r.stderr || r.stdout}`);
    return JSON.parse(r.stdout);
  });
}

function gettxout(txid, vout) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf gettxout ${txid} ${vout}`], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  const t = (r.stdout || '').trim();
  if (!t || t === 'null') return null;
  try { return JSON.parse(t); } catch { return null; }
}

function pickFee(state, minSats) {
  const sorted = [...(state.feeUtxos || [])].sort((a, b) => b.sats - a.sats);
  for (const u of sorted) {
    if (u.sats < minSats) continue;
    if (!gettxout(u.txid, u.vout)) continue;
    state.feeUtxos = state.feeUtxos.filter((x) => !(x.txid === u.txid && x.vout === u.vout));
    return u;
  }
  throw new Error(`no fee UTXO ≥ ${minSats}`);
}

function pushFee(state, u) {
  if (!state.feeUtxos.some((x) => x.txid === u.txid && x.vout === u.vout)) {
    state.feeUtxos.push(u);
  }
}

function minSatsFor(kind) {
  if (kind === 'deposit') return 11_500_000;
  return 1_500_000;
}

function loadStab(kind) {
  const p = STAB[kind];
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, 'utf8'));
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  // Prove vendor resolution (standalone)
  const unlockRoot = resolveUnlockRoot();
  const leanRoot = resolveLeanRoot();
  if (!unlockRoot.includes(`${path.sep}unlock-builder${path.sep}vendor${path.sep}`)) {
    console.warn(JSON.stringify({ warn: 'unlock root not under vendor', unlockRoot }));
  }
  console.log(JSON.stringify({
    phase: 'start',
    unlockRoot,
    leanRoot,
    pinLens: PIN_LENS,
    bundle: BUNDLE,
    kinds: KINDS,
  }));

  const wallets = JSON.parse(readFileSync(WALLETS, 'utf8'));
  const hot = wallets.hot;
  const feePrivateKey = Buffer.from(hot.privateKeyHex, 'hex');
  const loaded = await loadVerifierProfileBundle(BUNDLE);
  const expectedProfile = {
    profileId: loaded.manifest.identity.profileId,
    instanceId: loaded.manifest.genesis.instanceId,
    network: 'chipnet',
  };

  const state = JSON.parse(readFileSync(STATE_FILE, 'utf8'));
  let stateTxid = arg('state-txid', state.stateTxid);
  if (!stateTxid) throw new Error('no stateTxid');

  // withdrawal script hash from hot p2pkh
  const wsh = createHash('sha256').update(Buffer.from(hot.lockingBytecodeHex, 'hex')).digest('hex');
  const withdrawalLockingBytecode = Buffer.from(hot.lockingBytecodeHex, 'hex');

  let digests = state.resumeDigests || {
    deposit: '00'.repeat(32),
    transfer: '00'.repeat(32),
    withdrawal: '00'.repeat(32),
  };
  const priorCycles = state.history || [];
  let witnessSeed = state.resumeSeed || randomBytes(32).toString('hex');

  const ledger = [];
  for (const kind of KINDS) {
    const fee = pickFee(state, minSatsFor(kind));
    console.log(JSON.stringify({ fee: true, kind, txid: fee.txid.slice(0, 16), vout: fee.vout, sats: fee.sats }));
    const workDir = path.join(OUT, kind);
    mkdirSync(workDir, { recursive: true });
    const template = loadStab(kind);

    const result = await completeAction({
      kind,
      bundleDirectory: BUNDLE,
      expectedProfile,
      stateTxid,
      feePrivateKey,
      funding: {
        txid: fee.txid,
        vout: fee.vout,
        sats: fee.sats,
        publicKeyHex: hot.publicKeyHex,
      },
      workDir,
      witnessSeed,
      withdrawalScriptHash: wsh,
      withdrawalLockingBytecode,
      priorCycles,
      transferHops: 1,
      digests,
      stabilizeUnlockTemplate: template || undefined,
    });

    if (JSON.stringify(result.lens) !== JSON.stringify(PIN_LENS)) {
      throw new Error(`pin lens mismatch ${JSON.stringify(result.lens)}`);
    }
    if (!String(result.unlockRoot).includes(`${path.sep}vendor${path.sep}`)) {
      throw new Error(`not standalone unlock root: ${result.unlockRoot}`);
    }

    const prepAccept = bchnTestMempool(result.prepHex);
    if (!prepAccept[0]?.allowed) {
      pushFee(state, fee);
      throw new Error(`${kind} prep mempool reject ${JSON.stringify(prepAccept)}`);
    }
    bchnSendHex(result.prepHex);
    const settleAccept = bchnTestMempool(result.settleHex);
    if (!settleAccept[0]?.allowed) {
      throw new Error(`${kind} settle mempool reject ${JSON.stringify(settleAccept)}`);
    }
    bchnSendHex(result.settleHex);

    // harvest change to hot
    for (let i = 0; i < result.complete.transaction.outputs.length; i++) {
      const o = result.complete.transaction.outputs[i];
      if (Buffer.from(o.lockingBytecode).toString('hex') === hot.lockingBytecodeHex) {
        pushFee(state, { txid: result.settleTxid, vout: i, sats: Number(o.valueSatoshis) });
      }
    }

    digests = result.digests;
    stateTxid = result.settleTxid;
    state.stateTxid = stateTxid;
    const row = {
      kind,
      prepTxid: result.prepTxid,
      settleTxid: result.settleTxid,
      wire: result.wire,
      maxUnlock: result.maxUnlock,
      proveMs: result.proveMs,
      unlockMs: result.unlockMs,
      lens: result.lens,
      unlockRoot: result.unlockRoot,
      digest: result.digest,
      standalone: true,
    };
    ledger.push(row);
    console.log(JSON.stringify(row));
    appendFileSync(path.join(OUT, 'ledger.jsonl'), `${JSON.stringify(row)}\n`);
  }

  state.history = state.history || [];
  state.history.push({ witnessSeed, transactionContextDigests: { ...digests } });
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
  writeFileSync(path.join(OUT, 'result.json'), JSON.stringify({
    ok: true,
    kinds: KINDS,
    stateTxid,
    pinLens: PIN_LENS,
    unlockRoot,
    leanRoot,
    ledger,
  }, null, 2));

  console.log(JSON.stringify({
    done: true,
    stateTxid,
    kinds: KINDS.length,
    unlockRoot,
    standalone: true,
  }));
  process.exit(0);
}

main().catch((e) => {
  console.error('FAIL', e.message || e);
  if (e.stack) console.error(e.stack.split('\n').slice(0, 8).join('\n'));
  process.exit(1);
});
