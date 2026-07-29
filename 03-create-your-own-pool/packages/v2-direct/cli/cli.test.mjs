import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { main } from './shieldkit-v2.mjs';
import { createNoteWallet } from '../wallet/notes.mjs';
import { CIRCUIT_TREE_DEPTH } from '../operator/prove-local.mjs';

const profileId = createHash('sha256').update('cli-profile-v2').digest('hex');
const instanceId = createHash('sha256').update('cli-instance-v2').digest('hex');
const testRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../.cache/v2-direct-tests');
const ARTIFACT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../.cache/v2-direct-circuit');
mkdirSync(testRoot, { recursive: true });
const tmpHome = () => mkdtempSync(path.join(testRoot, `cli-${randomBytes(4).toString('hex')}-`));

function fundWallet(home) {
  const wallet = createNoteWallet(path.join(home, 'wallet'), { profileId, instanceId });
  wallet.setUtxos([
    { outpoint: `${'aa'.repeat(32)}:0`, txid: 'aa'.repeat(32), vout: 0, value: '50000000' },
    { outpoint: `${'bb'.repeat(32)}:0`, txid: 'bb'.repeat(32), vout: 0, value: '50000000' },
    { outpoint: `${'cc'.repeat(32)}:0`, txid: 'cc'.repeat(32), vout: 0, value: '50000000' },
  ]);
  return wallet;
}

async function runCaptured(home, argv) {
  let out = '';
  let err = '';
  const olog = console.log;
  const oerr = console.error;
  console.log = (...a) => { out += a.join(' ') + '\n'; };
  console.error = (...a) => { err += a.join(' ') + '\n'; };
  let code;
  try {
    code = await main(['--home', home, ...argv]);
  } finally {
    console.log = olog;
    console.error = oerr;
  }
  let json = null;
  const blob = out + err;
  const s = blob.indexOf('{');
  const e = blob.lastIndexOf('}');
  if (s >= 0 && e > s) {
    try { json = JSON.parse(blob.slice(s, e + 1)); } catch { /* multi-json */ }
  }
  return { code, out, err, json };
}

describe('shieldkit-v2 CLI (real prove, no fake broadcast)', () => {
  it('uses CIRCUIT_TREE_DEPTH 32', () => {
    assert.equal(CIRCUIT_TREE_DEPTH, 32);
  });

  it('prints maturity / dev-keys banner and documents pool create', async () => {
    process.env.V2_QUIET_BANNER = '0';
    let err = '';
    const oerr = console.error;
    console.error = (...a) => { err += a.join(' ') + '\n'; };
    let out = '';
    const olog = console.log;
    console.log = (...a) => { out += a.join(' ') + '\n'; };
    try {
      const code = await main(['--help']);
      assert.equal(code, 0);
    } finally {
      console.error = oerr;
      console.log = olog;
      process.env.V2_QUIET_BANNER = '1';
    }
    assert.match(err + out, /DEV KEYS ONLY|not for real-money privacy/i);
    assert.match(out, /pool create/);
    assert.match(out, /funding-wallet/);
  });

  it('gates mainnet without explicit override', async () => {
    process.env.V2_QUIET_BANNER = '1';
    delete process.env.V2_ALLOW_MAINNET;
    const home = tmpHome();
    const desc = path.join(home, 'descriptor.json');
    writeFileSync(desc, JSON.stringify({
      profileId, instanceId, maximumLiveNotes: 32, networkId: 1,
    }));
    await assert.rejects(
      async () => main(['--home', home, 'pool', 'add', desc]),
      /MAINNET_GATED/,
    );
  });

  it('deposit runs real Groth16 prove; does not invent txid without broadcast', async () => {
    if (!existsSync(path.join(ARTIFACT, 'circuit_final.zkey'))) {
      console.log('SKIP: circuit artifacts missing');
      return;
    }
    const home = tmpHome();
    assert.equal((await runCaptured(home, ['wallet', 'create'])).code, 0);
    const desc = path.join(home, 'descriptor.json');
    writeFileSync(desc, JSON.stringify({
      profileId, instanceId, maximumLiveNotes: 32, networkId: 2,
    }));
    assert.equal((await runCaptured(home, ['pool', 'add', desc])).code, 0);
    fundWallet(home);

    const dep = await runCaptured(home, ['deposit']);
    assert.equal(dep.code, 0, dep.err || dep.out);
    assert.ok(dep.json, dep.out);
    assert.equal(dep.json.ok, true);
    assert.equal(dep.json.kind, 'deposit');
    assert.equal(dep.json.treeDepth, 32);
    assert.ok(dep.json.proveMs > 100);
    assert.equal(dep.json.publicSignals.length, 2);
    assert.equal(dep.json.txid, null);
    assert.equal(dep.json.broadcast, false);
    // proof artifacts on disk
    assert.ok(existsSync(path.join(home, 'prove')));
  });

  it('deposit --broadcast without V2_CHIPNET_LIVE refuses (exit 3), no fake txid', async () => {
    if (!existsSync(path.join(ARTIFACT, 'circuit_final.zkey'))) return;
    const home = tmpHome();
    await runCaptured(home, ['wallet', 'create']);
    const desc = path.join(home, 'descriptor.json');
    writeFileSync(desc, JSON.stringify({
      profileId, instanceId, maximumLiveNotes: 32, networkId: 2,
    }));
    await runCaptured(home, ['pool', 'add', desc]);
    fundWallet(home);
    const r = await runCaptured(home, ['deposit', '--broadcast']);
    assert.equal(r.code, 3);
    // Live gate or missing tip — never invents a success txid
    assert.match(r.err + r.out, /CHIPNET_LIVE|LIVE_TIP|BROADCAST_FAILED|LIVE_SETTLE/);
    assert.ok(!r.json?.txid || r.json.ok === false);
  });

  it('deposit --broadcast with V2_CHIPNET_LIVE but no liveTip refuses (no V2_SETTLE_HEX theater)', async () => {
    if (!existsSync(path.join(ARTIFACT, 'circuit_final.zkey'))) return;
    const prev = process.env.V2_CHIPNET_LIVE;
    process.env.V2_CHIPNET_LIVE = '1';
    try {
      const home = tmpHome();
      await runCaptured(home, ['wallet', 'create']);
      const desc = path.join(home, 'descriptor.json');
      writeFileSync(desc, JSON.stringify({
        profileId, instanceId, maximumLiveNotes: 32, networkId: 2,
      }));
      await runCaptured(home, ['pool', 'add', desc]);
      fundWallet(home);
      const r = await runCaptured(home, ['deposit', '--broadcast']);
      assert.equal(r.code, 3);
      assert.match(r.err + r.out, /LIVE_TIP_REQUIRED/);
      assert.ok(!r.json?.txid);
    } finally {
      if (prev === undefined) delete process.env.V2_CHIPNET_LIVE;
      else process.env.V2_CHIPNET_LIVE = prev;
    }
  });

  it('deposit / transfer / withdraw each produce real proofs (txid null offline)', async () => {
    if (!existsSync(path.join(ARTIFACT, 'circuit_final.zkey'))) return;
    const home = tmpHome();
    await runCaptured(home, ['wallet', 'create']);
    const desc = path.join(home, 'descriptor.json');
    writeFileSync(desc, JSON.stringify({
      profileId, instanceId, maximumLiveNotes: 32, networkId: 2,
    }));
    await runCaptured(home, ['pool', 'add', desc]);
    fundWallet(home);

    const dep = await runCaptured(home, ['deposit']);
    assert.equal(dep.code, 0, dep.err);
    assert.equal(dep.json.treeDepth, 32);
    const noteId = dep.json.noteId;

    const tr = await runCaptured(home, ['transfer', '--note', noteId]);
    assert.equal(tr.code, 0, tr.err + tr.out);
    assert.equal(tr.json.treeDepth, 32);
    assert.ok(tr.json.proveMs > 100);
    assert.equal(tr.json.txid, null);
    const note2 = tr.json.noteId;

    // Valid cashaddr — packet hash must be sha256(lockingBytecode), not sha256(text)
    const payoutAddr = 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';
    const w = await runCaptured(home, ['withdraw', '--note', note2, '--to', payoutAddr]);
    assert.equal(w.code, 0, w.err + w.out);
    assert.equal(w.json.treeDepth, 32);
    assert.ok(w.json.proveMs > 100);
    assert.equal(w.json.payoutSats, '10000000');
    assert.equal(w.json.txid, null);
    assert.equal(w.json.payoutSource, 'cashaddr');
    assert.ok(/^[0-9a-f]{64}$/.test(w.json.withdrawalHashHex));
    // Anti-regression: must not equal sha256(cashaddr text)
    const textHash = createHash('sha256').update(payoutAddr).digest('hex');
    assert.notEqual(w.json.withdrawalHashHex, textHash);
    // Must equal sha256 of decoded P2PKH lock
    const lockHex = '76a914233c0f9b7593aecb09dca11931965a16b90548c288ac';
    const lockHash = createHash('sha256').update(Buffer.from(lockHex, 'hex')).digest('hex');
    assert.equal(w.json.withdrawalHashHex, lockHash);

    assert.equal((await runCaptured(home, ['status'])).code, 0);
    assert.equal((await runCaptured(home, ['doctor'])).code, 0);
  });

  it('deposit fails FUNDING_UTXO_REQUIRED before prove when unfunded', async () => {
    const home = tmpHome();
    await runCaptured(home, ['wallet', 'create']);
    const desc = path.join(home, 'descriptor.json');
    writeFileSync(desc, JSON.stringify({ profileId, instanceId, maximumLiveNotes: 8 }));
    await runCaptured(home, ['pool', 'add', desc]);
    const r = await runCaptured(home, ['deposit']);
    assert.equal(r.code, 2);
    assert.match(r.err + r.out, /FUNDING_UTXO_REQUIRED/);
  });
});
