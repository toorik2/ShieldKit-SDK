#!/usr/bin/env node
/**
 * Public golden-path cycle runner (extracted from lab battery).
 * Usage: node scripts/golden-path-cycle.mjs --run-dir <dir> --cycle N --wallets <wallets.json> [--kinds deposit,transfer,withdrawal]
 * Network gates: use scripts/shieldkit-smoke.mjs which wraps this after assertBroadcastAllowed.
 */
/**
 * One full live Chipnet cycle: deposit → transfer → withdrawal (or subset via --kinds).
 * Hardened: auto cold→hot top-up when funding short; PF7 genesis-fail retry via alternate fee UTXO.
 *
 * Usage:
 *   node run-full-cycle.mjs --run-dir <dir> --cycle <n> [--kinds deposit,transfer,withdrawal]
 */
import { createHash } from 'node:crypto';
import { writeFileSync, readFileSync, mkdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdir, appendFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateSigningSerializationBch, hash256, instantiateSecp256k1,
  SigningSerializationTypeBch, encodeTransaction,
} from '@bitauth/libauth';
import { loadVerifierProfileBundle } from '../../../packages/profile/load.mjs';
import { parsePf7CarrierAuthority } from '../../../packages/prove/authority.mjs';
import {
  planCompletePreparationTransaction, finalizeCompletePreparationTransaction,
} from '../../../packages/action/prep.mjs';
import { generateFreshWitnessInputs } from '../../../packages/action/witness.mjs';
import {
  planCompleteSettlement, assembleCompleteSettlement, classifyCompleteSettlementVm,
} from '../../../packages/action/assemble.mjs';
import { adaptSnarkjsGroth16 } from '../../../packages/prove/groth16.mjs';

const require = createRequire(import.meta.url);
const snarkjs = require('../../../packages/prove/node_modules/snarkjs');
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}
const RUN = path.resolve(arg('run-dir', path.join(ROOT, 'examples/golden-path-run')));
const CYCLE = Number(arg('cycle', '1'));
const KINDS = (arg('kinds', 'deposit,transfer,withdrawal')).split(',').map((s) => s.trim()).filter(Boolean);
// 0 = deposit→withdrawal (no transfer); 1 = full. Auto from kinds if unset.
const TRANSFER_HOPS = (() => {
  const raw = arg('transfer-hops', '');
  if (raw !== '' && raw !== undefined) return Number(raw);
  if (KINDS.includes('deposit') && KINDS.includes('withdrawal') && !KINDS.includes('transfer')) return 0;
  return 1;
})();

const PROFILE_BUNDLE = path.resolve(arg('bundle', process.env.SHIELDKIT_BUNDLE || path.join(ROOT, '.cache/profile-build-live/profile-bundle')));
const VS_PATH = path.resolve(arg('verifier-set', process.env.SHIELDKIT_VERIFIER_SET || path.join(ROOT, '.cache/pf7-verifier-set-stabilize/bch-verifier-set.json')));
const VT = path.resolve(arg('pf7-worktree', process.env.SHIELDKIT_PF7_WORKTREE || path.join(ROOT, '.worktrees/verifier-pf7-sub62')));
const LEAN = path.resolve(arg('leanbch', process.env.SHIELDKIT_LEANBCH || path.join(ROOT, '.worktrees/leanbch-pf7')));
const WALLETS = path.resolve(arg('wallets', process.env.SHIELDKIT_WALLETS || path.join(ROOT, 'examples/local-wallets.json')));
const COLD_FLOOR_SATS = 95n * 100_000_000n;
const DEPOSIT_MIN_SATS = 11_500_000; // binding 10.001M + carriers + fee-funding + dust
const DEFAULT_MIN_SATS = 1_500_000;
const TOPUP_DEPOSIT_SATS = 50_000_000; // 0.5 BCH — covers ~4 deposits + fees before next top-up
const TOPUP_SMALL_SATS = 5_000_000; // 0.05 BCH for xfer/wd
const PF7_MAX_ATTEMPTS = 4;
const PIN_LENS = [8177, 6654, 7066, 7066, 8393, 7600, 9350];

const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};
const hexSha = async (p) => createHash('sha256').update(await readFile(p)).digest('hex');

const SSH_OPTS = ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=20',
  '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3'];
const SSH_RETRIES = 5;

function isTransientNet(err) {
  const s = String(err || '');
  return /Network is unreachable|Connection timed out|Connection reset|Connection refused|Broken pipe|No route to host|Connection closed|ssh: connect/i.test(s);
}

function sshRetry(label, runOnce) {
  let last;
  for (let i = 1; i <= SSH_RETRIES; i++) {
    try {
      return runOnce();
    } catch (e) {
      last = e;
      if (!isTransientNet(e.message || e) || i === SSH_RETRIES) throw e;
      const backoff = Math.min(2 ** i, 30);
      console.log(JSON.stringify({ ssh_retry: true, label, attempt: i, backoff, err: String(e.message || e).slice(0, 120) }));
      spawnSync('sleep', [String(backoff)]);
    }
  }
  throw last;
}

function bchn(args) {
  return sshRetry(`bchn ${args.slice(0, 40)}`, () => {
    const remote = `sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf ${args}`;
    const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node', remote], {
      encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    });
    if (r.status !== 0) throw new Error(`bchn ${args}: ${r.stderr || r.stdout}`);
    return r.stdout.trim();
  });
}

function bchnJsonFile(cmdWithPlaceholder, jsonPayload) {
  return sshRetry('bchn-file', () => {
    const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
      `cat > /tmp/sk-bat-arg.json && ${cmdWithPlaceholder}`], {
      encoding: 'utf8', input: typeof jsonPayload === 'string' ? jsonPayload : JSON.stringify(jsonPayload),
      maxBuffer: 64 * 1024 * 1024,
    });
    if (r.status !== 0) throw new Error(`bchn-file: ${r.stderr || r.stdout}`);
    return r.stdout.trim();
  });
}

function bchnSendHex(hex) {
  return sshRetry('sendraw', () => {
    const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
      `cat > /tmp/sk-battery.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf sendrawtransaction "$(cat /tmp/sk-battery.hex)"`], {
      encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
    });
    if (r.status !== 0) throw new Error(`sendraw: ${r.stderr || r.stdout}`);
    return r.stdout.trim();
  });
}

function bchnTestMempool(hex) {
  return sshRetry('testmempool', () => {
    const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
      `cat > /tmp/sk-battery.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf testmempoolaccept "[\\"$(cat /tmp/sk-battery.hex)\\"]"`], {
      encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
    });
    if (r.status !== 0) throw new Error(`testmempool: ${r.stderr || r.stdout}`);
    return JSON.parse(r.stdout);
  });
}

function gettxout(txid, vout) {
  try {
    const out = bchn(`gettxout ${txid} ${vout} true`);
    if (!out) return null;
    return JSON.parse(out);
  } catch {
    return null;
  }
}

/** Batch gettxout over SSH — one round-trip for many UTXOs. */
function gettxoutBatch(utxos) {
  if (!utxos.length) return [];
  // Sort largest-first and cap — prune only what pickFee needs.
  const ordered = [...utxos].sort((a, b) => (b.sats || 0) - (a.sats || 0)).slice(0, 40);
  const payload = JSON.stringify(ordered.map((u) => ({ txid: u.txid, vout: u.vout })));
  return sshRetry('gettxoutBatch', () => {
    // Do NOT use stdin heredoc for python — it eats the JSON payload.
    // Pipe payload into remote file then run checker.
    const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
      `cat > /tmp/sk-gettxout-batch.json && python3 - <<'PY'
import json,subprocess
cli=['sudo','-n','-u','bchn','/usr/local/bin/bitcoin-cli','-conf=/etc/bchn/bitcoin.conf']
items=json.load(open('/tmp/sk-gettxout-batch.json'))
out=[]
for it in items:
  try:
    raw=subprocess.check_output(cli+['gettxout',it['txid'],str(it['vout']),'true'],text=True).strip()
    out.append(json.loads(raw) if raw else None)
  except Exception:
    out.append(None)
print(json.dumps(out))
PY`], { encoding: 'utf8', input: payload, maxBuffer: 16 * 1024 * 1024 });
    if (r.status !== 0) throw new Error(`gettxoutBatch: ${r.stderr || r.stdout}`);
    const tips = JSON.parse(r.stdout.trim());
    // Map results back onto ordered slice; callers that passed full list need alignment —
    // return tips aligned to `ordered` and let pickFee re-merge by index into that slice.
    return { ordered, tips };
  });
}

function minSatsFor(kind) {
  return kind === 'deposit' ? DEPOSIT_MIN_SATS : DEFAULT_MIN_SATS;
}

async function loadState() {
  const p = path.join(RUN, 'state.json');
  try {
    return JSON.parse(await readFile(p, 'utf8'));
  } catch {
    return { stateTxid: null, history: [], feeUtxos: [], cyclesCompleted: 0 };
  }
}

async function saveState(state) {
  await writeFile(path.join(RUN, 'state.json'), JSON.stringify(state, null, 2) + '\n');
}

async function ledger(row) {
  await appendFile(path.join(RUN, 'ledger.jsonl'), JSON.stringify({ ts: new Date().toISOString(), ...row }) + '\n');
}

function pushFee(state, utxo) {
  if (!utxo || utxo.sats <= 1000) return;
  // dedupe
  if (state.feeUtxos.some((u) => u.txid === utxo.txid && u.vout === utxo.vout)) return;
  state.feeUtxos.push(utxo);
}

function scantxout(addr) {
  return sshRetry('scantxoutset', () => {
    const scanRaw = spawnSync('ssh', [
      ...SSH_OPTS, 'layer1-node',
      `sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf scantxoutset start '["addr(${addr})"]'`,
    ], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    if (scanRaw.status !== 0) throw new Error(`scantxoutset: ${scanRaw.stderr || scanRaw.stdout}`);
    return JSON.parse(scanRaw.stdout);
  });
}

/** Merge hot UTXOs from scantxoutset into fee inventory (confirmed only via gettxout). */
function refreshHotFees(state, wallets) {
  try {
    const scan = scantxout(wallets.hot.address);
    for (const u of scan.unspents || []) {
      const tip = gettxout(u.txid, u.vout);
      if (!tip) continue;
      pushFee(state, { txid: u.txid, vout: u.vout, sats: Math.round(tip.value * 1e8) });
    }
  } catch (e) {
    console.log(JSON.stringify({ refreshHotFees_err: String(e.message || e).slice(0, 120) }));
  }
}

function pickFee(state, minSats) {
  // prune spent (batch gettxout — avoid N SSH round-trips)
  try {
    const { ordered, tips } = gettxoutBatch(state.feeUtxos);
    const keptKeys = new Set();
    const kept = [];
    for (let i = 0; i < ordered.length; i++) {
      const tip = tips[i];
      if (!tip) continue;
      const u = { ...ordered[i], sats: Math.round(tip.value * 1e8) };
      kept.push(u);
      keptKeys.add(`${u.txid}:${u.vout}`);
    }
    // retain unscanned tail unpruned (optimistic) so inventory doesn't collapse to top-40 only
    for (const u of state.feeUtxos) {
      const k = `${u.txid}:${u.vout}`;
      if (keptKeys.has(k)) continue;
      // only keep if not in the scanned ordered set
      if (ordered.some((o) => o.txid === u.txid && o.vout === u.vout)) continue;
      kept.push(u);
    }
    state.feeUtxos = kept;
  } catch {
    // fallback sequential on top candidates only
    state.feeUtxos.sort((a, b) => b.sats - a.sats);
    const head = state.feeUtxos.slice(0, 20);
    const tail = state.feeUtxos.slice(20);
    const kept = head.filter((u) => {
      const tip = gettxout(u.txid, u.vout);
      if (!tip) return false;
      u.sats = Math.round(tip.value * 1e8);
      return true;
    });
    state.feeUtxos = [...kept, ...tail];
  }
  // sort largest first
  state.feeUtxos.sort((a, b) => b.sats - a.sats);
  // cap inventory growth
  if (state.feeUtxos.length > 60) state.feeUtxos = state.feeUtxos.slice(0, 60);
  for (let i = 0; i < state.feeUtxos.length; i++) {
    const u = state.feeUtxos[i];
    if (u.sats >= minSats) {
      state.feeUtxos.splice(i, 1);
      return { ...u };
    }
  }
  return null;
}

/**
 * Cold→hot top-up via BCHN signrawtransactionwithkey.
 * Tracks state.coldUtxo so zero-conf cold change (not yet in scantxoutset) stays spendable.
 */
function coldTopUp(state, wallets, amountSats) {
  const candidates = [];
  // 1) tracked zero-conf / known cold change
  if (state.coldUtxo) {
    const tip = gettxout(state.coldUtxo.txid, state.coldUtxo.vout);
    if (tip) {
      candidates.push({
        txid: state.coldUtxo.txid,
        vout: state.coldUtxo.vout,
        sats: Math.round(tip.value * 1e8),
        amount: tip.value,
        scriptPubKey: wallets.cold.lockingBytecodeHex || state.coldUtxo.scriptPubKey,
        source: 'tracked',
      });
    } else {
      delete state.coldUtxo;
    }
  }
  // 2) scantxoutset (confirmed UTXO set; may lag mempool spends — filter via gettxout)
  try {
    const scan = scantxout(wallets.cold.address);
    for (const u of scan.unspents || []) {
      const tip = gettxout(u.txid, u.vout);
      if (!tip) continue; // spent in mempool or stale scan entry
      if (candidates.some((c) => c.txid === u.txid && c.vout === u.vout)) continue;
      candidates.push({
        txid: u.txid,
        vout: u.vout,
        sats: Math.round(tip.value * 1e8),
        amount: tip.value,
        scriptPubKey: wallets.cold.lockingBytecodeHex || u.scriptPubKey,
        source: 'scan',
      });
    }
  } catch (e) {
    if (!candidates.length) throw e;
  }
  candidates.sort((a, b) => b.sats - a.sats);
  if (!candidates.length) throw new Error('cold has no spendable UTXOs (tracked+scan empty)');
  const u = candidates[0];
  const coldSats = u.sats;
  const totalCold = candidates.reduce((a, x) => a + x.sats, 0);
  if (BigInt(totalCold) - BigInt(amountSats) < COLD_FLOOR_SATS) {
    throw new Error(`cold top-up would breach 95 BCH floor (cold=${totalCold} need=${amountSats})`);
  }
  const feeSats = 500;
  const changeSats = coldSats - amountSats - feeSats;
  if (changeSats < 546) throw new Error(`cold change dust ${changeSats}`);

  const pack = {
    inputs: [{ txid: u.txid, vout: u.vout }],
    outputs: {
      [wallets.hot.address]: Number((amountSats / 1e8).toFixed(8)),
      [wallets.cold.address]: Number((changeSats / 1e8).toFixed(8)),
    },
    prev: [{
      txid: u.txid, vout: u.vout,
      scriptPubKey: u.scriptPubKey || wallets.cold.lockingBytecodeHex,
      amount: u.amount,
    }],
    keys: [wallets.cold.wif],
    expectIn: u.txid,
  };
  const packPath = path.join(RUN, 'tmp-topup-pack.json');
  writeFileSync(packPath, JSON.stringify(pack));
  const scp = sshRetry('scp-topup', () => {
    const r = spawnSync('scp', [
      ...SSH_OPTS, packPath, 'layer1-node:/tmp/sk-topup-pack.json',
    ], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`scp topup pack: ${r.stderr || r.stdout}`);
    return r;
  });
  const r = sshRetry('coldTopUp-send', () => {
    const rr = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
      `python3 - <<'PY'
import json,subprocess,sys,pathlib,hashlib
pack=json.loads(pathlib.Path('/tmp/sk-topup-pack.json').read_text())
cli=['sudo','-n','-u','bchn','/usr/local/bin/bitcoin-cli','-conf=/etc/bchn/bitcoin.conf']
IN=json.dumps(pack['inputs']); OUT=json.dumps(pack['outputs'])
PREV=json.dumps(pack['prev']); KEYS=json.dumps(pack['keys'])
raw=subprocess.check_output(cli+['createrawtransaction',IN,OUT],text=True).strip()
signed=json.loads(subprocess.check_output(cli+['signrawtransactionwithkey',raw,KEYS,PREV],text=True))
if not signed.get('complete'):
  print('SIGN_FAIL', signed, file=sys.stderr); sys.exit(2)
hex_tx=signed['hex']
h=hashlib.sha256(hashlib.sha256(bytes.fromhex(hex_tx)).digest()).digest()
local_txid=h[::-1].hex()
try:
  txid=subprocess.check_output(cli+['sendrawtransaction',hex_tx],text=True).strip()
except subprocess.CalledProcessError as e:
  err=(e.stderr or e.stdout or b'').decode() if isinstance(e.stderr, (bytes,bytearray)) else (e.stderr or str(e))
  if 'already in' in err.lower() or 'txn-already' in err.lower():
    txid=local_txid
  else:
    print('SEND_FAIL', err, file=sys.stderr); sys.exit(3)
if txid != local_txid:
  print('WARN_TXID_MISMATCH', txid, local_txid, file=sys.stderr)
print(local_txid)
print(hex_tx[:32], file=sys.stderr)
PY`], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
    if (rr.status !== 0) throw new Error(`coldTopUp: ${rr.stderr || rr.stdout}`);
    return rr;
  });
  const lines = r.stdout.trim().split('\n').filter(Boolean);
  const txid = lines[lines.length - 1];
  if (!/^[0-9a-f]{64}$/.test(txid)) throw new Error(`coldTopUp bad txid ${JSON.stringify(r.stdout)}`);
  if (txid === pack.expectIn) throw new Error(`coldTopUp returned input txid ${txid} (send did not create new tx)`);
  let tip = null;
  for (let i = 0; i < 15; i++) {
    tip = gettxout(txid, 0);
    if (tip) break;
    spawnSync('sleep', ['0.4']);
  }
  if (!tip) throw new Error(`coldTopUp not visible ${txid}:0 after retries (stderr=${(r.stderr || '').slice(0, 200)})`);
  const sats = Math.round(tip.value * 1e8);
  // track cold change (vout 1) for next zero-conf top-up
  const coldChangeTip = gettxout(txid, 1);
  if (coldChangeTip) {
    state.coldUtxo = {
      txid,
      vout: 1,
      sats: Math.round(coldChangeTip.value * 1e8),
      scriptPubKey: wallets.cold.lockingBytecodeHex,
    };
  } else {
    // still record expected change; gettxout may lag
    state.coldUtxo = {
      txid,
      vout: 1,
      sats: changeSats,
      scriptPubKey: wallets.cold.lockingBytecodeHex,
    };
  }
  console.log(JSON.stringify({
    topup: true, txid, sats, amountSats, from: u.txid.slice(0, 16),
    coldChange: state.coldUtxo.txid.slice(0, 16) + ':1',
  }));
  return { txid, vout: 0, sats };
}

function ensureFee(state, wallets, minSats) {
  let fee = pickFee(state, minSats);
  if (fee) return fee;
  // rescan hot before top-up (catches settlement/withdrawal change not yet tracked)
  refreshHotFees(state, wallets);
  fee = pickFee(state, minSats);
  if (fee) return fee;
  const amount = minSats >= DEPOSIT_MIN_SATS ? TOPUP_DEPOSIT_SATS : TOPUP_SMALL_SATS;
  const top = coldTopUp(state, wallets, amount);
  pushFee(state, top);
  fee = pickFee(state, minSats);
  if (!fee) throw new Error(`ensureFee failed after top-up min=${minSats}`);
  return fee;
}

function pf7Build(kind, adapterPath, packetPath, outDir) {
  const shaA = createHash('sha256').update(readFileSync(adapterPath)).digest('hex');
  const shaP = createHash('sha256').update(readFileSync(packetPath)).digest('hex');
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(path.join(outDir, 'build'), { recursive: true });
  mkdirSync(path.join(outDir, 'generated'), { recursive: true });
  // Unique TMPDIR per invocation — tsx IPC pipes collide on reuse (EADDRINUSE).
  const tmpDir = path.join(outDir, `tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  mkdirSync(tmpDir, { recursive: true });
  const env = {
    PATH: `${path.join(VT, 'harness/node_modules/.bin')}:/home/toorik/.local/share/mise/installs/node/20.20.2/bin:/usr/bin:/bin`,
    HOME: process.env.HOME,
    TMPDIR: tmpDir,
    CASHC_ROOT: path.join(VT, 'vendor/cashc-resched/packages/cashc'),
    LEANBCH_ROOT: LEAN,
    C7_SHIELD_ADAPTER_FILE: adapterPath,
    C7_SHIELD_ADAPTER_SHA256: shaA,
    C7_STRUCTURAL_ROLE_COUNT: '3',
    C7_SHIELD_ACTION_PACKET_FILE: packetPath,
    C7_SHIELD_ACTION_PACKET_SHA256: shaP,
    C7_TMP: path.join(outDir, 'build'),
    C7_GEN: path.join(outDir, 'generated'),
    KWIN: '13', STRIPED_FRAGS: '5', SW: '32', CDNW: '1', CDWIDTH: '34', UNW: '16', WDWIDTH: '32',
    WIDE_POS: '', FIN_PAD: '', C7_MAXTRY: '2', NITS: '1', RESCHEDULE: 'on',
    SZ_ALLAFF: '1', L17SEL: '1', SEAMNARROW: '1', KSPEC: '1', SIBLING_READ: '1', FIXED_WDAT: '1', DYN_PACK: '1',
    DERIVE_MODE: '1', DP: '1', STRIPED: '1', STRIPE_BOUNDARY: '1', DIRECT_FINALIZE_STATE: '1',
    STRICT_DEPLOYMENT: '1', PUBLIC_BENCH_CONTEXT: '1', DRIVER_PACK_DERIVED: '1', DRIVER_WINDOW_DERIVED: '1',
    C7_PROJECTED_BQ_7: '1', C7_FIXED_G2_TABLE: '1', C7_FIXED_G2_COMPACT: '1', C7_FIXED_G2_NORMALIZED_ADDS: '1',
    C7_VK_DIGEST: '1', C7_WSEL_U8: '1', C7_COMPOSED_P2SH: '1', C7_COMPOSED_DIRECT_TERMINAL: '1',
    C7_PAIRFOLD_TOPOLOGY: '7', C7_SCALAR_ENDPOINT: '1', C7_DENSFUEL_DROP: '1',
    C7_ZBITS_GB3: './normalized-gb3.mjs', C7_SZ_MODULE: './mixed-sz.mjs',
    C7_FIXED_G2_UNLOCK_TABLE: '1', C7_FIXED_G2_WITNESS_TABLE_BYTES: '0,1536,2460,2427,2304',
    C7_SELF_CARRIED_TERMINAL: '1',
    TERMINAL_FUSION9: '1', TERMINAL_REUSE_ZPOWERS: '1', TERMINAL_CANON_ZPROLOGUE: '1', TERMINAL_FULL_OPT: '1',
  };
  const t0 = Date.now();
  const r = spawnSync('tsx', ['lanes/bn254-onetx/src/c7/build.ts'], {
    cwd: VT, env, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  writeFileSync(path.join(outDir, 'build.log'), (r.stdout || '') + (r.stderr || ''));
  const ms = Date.now() - t0;
  if (r.status !== 0) {
    return { ok: false, error: `pf7 exit ${r.status}`, ms, dump: null, result: null };
  }
  const result = JSON.parse(readFileSync(path.join(outDir, 'build/result.json'), 'utf8'));
  if (!result.gateOk) {
    const gen = (result.manual || []).find((row) => row.i === 5);
    return {
      ok: false,
      error: `pf7 gateOk false genesis=${gen?.accepts} err=${(gen?.error || '').slice(0, 80)}`,
      ms, dump: null, result,
    };
  }
  const dump = JSON.parse(readFileSync(path.join(outDir, 'build/inputs_dump.json'), 'utf8'));
  const lens = dump.slice(0, 7).map((row) => row.unlock.length / 2);
  if (JSON.stringify(lens) !== JSON.stringify(PIN_LENS)) {
    return { ok: false, error: `pf7 pins ${JSON.stringify(lens)}`, ms, dump, result };
  }
  return { ok: true, dump, result, ms };
}

async function main() {
  await mkdir(RUN, { recursive: true });
  await mkdir(path.join(RUN, 'cycles', String(CYCLE)), { recursive: true });
  const cycleDir = path.join(RUN, 'cycles', String(CYCLE));
  const state = await loadState();

  const wallets = JSON.parse(await readFile(WALLETS, 'utf8'));
  const hot = wallets.hot;
  const feePrivateKey = Buffer.from(hot.privateKeyHex, 'hex');
  const secp = await instantiateSecp256k1();
  const loaded = await loadVerifierProfileBundle(PROFILE_BUNDLE);
  const expectedProfile = {
    profileId: loaded.manifest.identity.profileId,
    instanceId: loaded.manifest.genesis.instanceId,
    network: 'chipnet',
  };
  const vs = JSON.parse(await readFile(VS_PATH, 'utf8'));
  const authority = parsePf7CarrierAuthority(vs);
  const bindingBase = authority.settlementKernel.artifact.constants.bindingCarrierBaseSatoshis;
  const stateBase = authority.settlementKernel.artifact.constants.stateCarrierBaseSatoshis;
  const bindingLock = authority.settlementKernel.bindingLock.toString('hex');
  const zkey = path.join(PROFILE_BUNDLE, 'artifacts/final.zkey');
  const wasm = path.join(PROFILE_BUNDLE, 'artifacts/g1_relation.wasm');
  const vkPath = path.join(PROFILE_BUNDLE, 'artifacts/verification_key.json');
  const vk = JSON.parse(await readFile(vkPath, 'utf8'));

  const canonicalSeed = sha256(
    Buffer.from('shieldkit/live-battery/v1\\0', 'utf8'),
    Buffer.from(String(CYCLE)),
    Buffer.from('42'.repeat(32), 'hex'),
  ).toString('hex');
  // Only honor resume hooks when they match this cycle's seed (prevents stale cycle-N
  // resumeDigests/seed from colliding notes into cycle N+1).
  let witnessSeed = canonicalSeed;
  if (state.resumeSeed && state.resumeSeed === canonicalSeed) {
    witnessSeed = state.resumeSeed;
  } else if (state.resumeSeed || state.resumeDigests) {
    console.log(JSON.stringify({
      clear_stale_resume: true,
      hadSeed: Boolean(state.resumeSeed),
      hadDigests: Boolean(state.resumeDigests),
      cycle: CYCLE,
    }));
    delete state.resumeSeed;
    delete state.resumeDigests;
  }

  if (!state.history) {
    const dep = JSON.parse(await readFile(path.join(ROOT, '.cache/live-chipnet-e2e/deposit-plan.json'), 'utf8'));
    const xfer = JSON.parse(await readFile(path.join(ROOT, '.cache/live-chipnet-e2e/transfer-plan.json'), 'utf8'));
    const wd = JSON.parse(await readFile(path.join(ROOT, '.cache/live-chipnet-e2e/withdrawal-plan.json'), 'utf8'));
    state.history = [{
      witnessSeed: '42'.repeat(32),
      transactionContextDigests: { deposit: dep.digest, transfer: xfer.digest, withdrawal: wd.digest },
    }];
  }
  const priorCycles = state.history;
  const withdrawalLockingBytecode = hot.lockingBytecodeHex;
  const wsh = createHash('sha256').update(Buffer.from(withdrawalLockingBytecode, 'hex')).digest('hex');

  let digests = { deposit: '00'.repeat(32), transfer: '00'.repeat(32), withdrawal: '00'.repeat(32) };
  if (state.resumeDigests && state.resumeSeed === canonicalSeed) {
    digests = { ...digests, ...state.resumeDigests };
  }

  let stateTxid = state.stateTxid;
  console.log(JSON.stringify({
    cycle: CYCLE, kinds: KINDS, stateTxid, priorCycles: priorCycles.length, feeUtxos: state.feeUtxos.length,
  }));

  const stabDumpCache = {};
  const loadStab = async (kind) => {
    if (!stabDumpCache[kind]) {
      stabDumpCache[kind] = JSON.parse(
        await readFile(path.join(ROOT, `.cache/stabilize-pf7-${kind}/build/inputs_dump.json`), 'utf8'),
      );
    }
    return stabDumpCache[kind];
  };

  for (const kind of KINDS) {
    const t0 = Date.now();
    let lastErr = null;
    let succeeded = false;
    // Avoid re-picking the same fee UTXO after PF7 genesis fail (same prep shape).
    const rejectedFeeKeys = new Set();

    for (let attempt = 1; attempt <= PF7_MAX_ATTEMPTS; attempt++) {
      const minSats = minSatsFor(kind);
      let fee;
      try {
        // park rejected fees so ensureFee/pickFee cannot reselect them this kind
        const parked = [];
        state.feeUtxos = state.feeUtxos.filter((u) => {
          const k = `${u.txid}:${u.vout}`;
          if (rejectedFeeKeys.has(k)) {
            parked.push(u);
            return false;
          }
          return true;
        });
        fee = ensureFee(state, wallets, minSats);
        // restore parked for later kinds
        for (const u of parked) pushFee(state, u);
      } catch (e) {
        lastErr = e;
        break;
      }
      console.log(JSON.stringify({
        fee: true, kind, attempt, txid: fee.txid.slice(0, 16), vout: fee.vout, sats: fee.sats,
      }));

      try {
        const prepIn = {
          kind,
          bundleDirectory: PROFILE_BUNDLE,
          expectedProfile,
          bindingCarrierBaseValueSatoshis: bindingBase,
          bindingLockingBytecode: bindingLock,
          fundingOutpointIndex: String(fee.vout),
          fundingOutpointTransactionHashWire: Buffer.from(fee.txid, 'hex').reverse().toString('hex'),
          fundingPublicKey: hot.publicKeyHex,
          fundingSourceValueSatoshis: String(fee.sats),
          minimumFeeRateSatoshisPerByte: '1',
          settlementFeeFundingSatoshis: '100000',
        };
        const prepPlan = await planCompletePreparationTransaction(prepIn);
        const ss = generateSigningSerializationBch({
          inputIndex: 0, sourceOutputs: [prepPlan.sourceOutput], transaction: prepPlan.unsignedTransaction,
        }, {
          coveredBytecode: prepPlan.sourceOutput.lockingBytecode,
          signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputs),
        });
        const sig = secp.signMessageHashSchnorr(feePrivateKey, hash256(ss));
        if (typeof sig === 'string') throw new Error(sig);
        const prep = await finalizeCompletePreparationTransaction(prepIn, Buffer.from(sig).toString('hex'));
        const prepHex = Buffer.from(encodeTransaction(prep.transaction)).toString('hex');
        const prepTxid = Buffer.from(hash256(Buffer.from(prepHex, 'hex'))).reverse().toString('hex');

        // track prep change
        const changeSats = Number(prep.outputValues?.preparationChangeSatoshis
          ?? prep.outputValues?.fundingChangeSatoshis ?? 0);
        if (changeSats > 1000) {
          const outs = prep.transaction.outputs;
          for (let i = outs.length - 1; i >= 0; i--) {
            if (Buffer.from(outs[i].lockingBytecode).toString('hex') === hot.lockingBytecodeHex
              && Number(outs[i].valueSatoshis) === changeSats) {
              pushFee(state, { txid: prepTxid, vout: i, sats: changeSats });
              break;
            }
          }
        }

        const stabDump = await loadStab(kind);
        const planPf7 = (preparation) => preparation.settlementOutpoints.verifierCarriers.map((carrier, i) => ({
          lockingBytecode: carrier.lockingBytecode,
          unlockingBytecode: stabDump[i].unlock,
          valueSatoshis: carrier.valueSatoshis,
          outpointTransactionHashWire: carrier.outpointTransactionHashWire,
          outpointIndex: Number(carrier.outpointIndex),
        }));

        // digests for this attempt: keep prior kinds; re-zero current kind for re-plan
        const attemptDigests = { ...digests, [kind]: '00'.repeat(32) };

        if (!['deposit', 'transfer', 'withdrawal'].includes(kind)) {
          throw new Error(`unsupported kind ${kind}`);
        }
        if (TRANSFER_HOPS === 0 && kind === 'transfer') {
          throw new Error('transfer kind not allowed when transfer-hops=0');
        }
        const w0 = await generateFreshWitnessInputs({
          bundleDirectory: PROFILE_BUNDLE,
          expectedProfile,
          transactionContextDigests: attemptDigests,
          withdrawalScriptHash: wsh,
          witnessSeed,
          priorCycles,
          transferHops: TRANSFER_HOPS,
        });
        if (!w0.actions[kind]) {
          throw new Error(`witness missing action for kind=${kind} hops=${TRANSFER_HOPS}`);
        }
        const planInput0 = {
          kind, bundleDirectory: PROFILE_BUNDLE, expectedProfile,
          actionPacket: w0.actions[kind].actionPacket,
          minimumFeeRateSatoshisPerByte: 1n, feePrivateKey,
          feeSourceValueSatoshis: prep.outputValues.settlementFeeFundingSatoshis,
          bindingCarrierBaseSatoshis: BigInt(bindingBase),
          stateCarrierBaseSatoshis: BigInt(stateBase),
          preparationTransactionHashWire: prep.settlementOutpoints.binding.outpointTransactionHashWire,
          stateOutpointTransactionHashWire: Buffer.from(stateTxid, 'hex').reverse().toString('hex'),
          stateOutpointIndex: 0,
          pf7: planPf7(prep),
          ...(kind === 'withdrawal' ? { withdrawalLockingBytecode } : {}),
        };
        const plan0 = await planCompleteSettlement(planInput0);
        const digests1 = { ...attemptDigests, [kind]: plan0.context.digestHex };
        const w1 = await generateFreshWitnessInputs({
          bundleDirectory: PROFILE_BUNDLE,
          expectedProfile,
          transactionContextDigests: digests1,
          withdrawalScriptHash: wsh,
          witnessSeed,
          priorCycles,
          transferHops: TRANSFER_HOPS,
        });
        const plan1 = await planCompleteSettlement({
          ...planInput0, actionPacket: w1.actions[kind].actionPacket,
        });
        if (plan1.context.digestHex !== plan0.context.digestHex) {
          throw new Error(`${kind} SCCT digest drift`);
        }

        const packetPath = path.join(cycleDir, `${kind}.packet`);
        await writeFile(packetPath, Buffer.from(w1.actions[kind].actionPacket));
        await writeFile(path.join(cycleDir, `${kind}.circuitInput.json`), JSON.stringify(w1.actions[kind].circuitInput));
        await writeFile(path.join(cycleDir, `${kind}-plan.json`), JSON.stringify({
          digest: plan1.context.digestHex, wire: plan1.expectedWireBytes,
          fee: plan1.expectedFeeSatoshis.toString(), prepTxid, stateTxid, attempt,
        }));

        const proveT0 = Date.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          w1.actions[kind].circuitInput, wasm, zkey,
        );
        const proveMs = Date.now() - proveT0;
        if (!(await snarkjs.groth16.verify(vk, publicSignals, proof))) {
          throw new Error(`${kind} proof verify false`);
        }
        const proofPath = path.join(cycleDir, `${kind}.proof.json`);
        const pubPath = path.join(cycleDir, `${kind}.public.json`);
        await writeFile(proofPath, JSON.stringify(proof));
        await writeFile(pubPath, JSON.stringify(publicSignals));
        const adapter = await adaptSnarkjsGroth16({
          proof: { path: proofPath, sha256: await hexSha(proofPath) },
          publicSignals: { path: pubPath, sha256: await hexSha(pubPath) },
          verificationKey: { path: vkPath, sha256: await hexSha(vkPath) },
        });
        const adapterPath = path.join(cycleDir, `${kind}-adapter.json`);
        await writeFile(adapterPath, JSON.stringify(adapter));

        const pf7Out = path.join(cycleDir, `pf7-${kind}-a${attempt}`);
        const pf7 = pf7Build(kind, adapterPath, packetPath, pf7Out);
        if (!pf7.ok) {
          // Blacklist this fee for remaining attempts of this kind so retry uses
          // a different funding outpoint (changes prep/carrier outpoints + digest).
          rejectedFeeKeys.add(`${fee.txid}:${fee.vout}`);
          // do NOT pushFee back until kind finishes — avoid same-UTXO reselect
          // drop the prep-change we just added for this prepTxid (never broadcast)
          state.feeUtxos = state.feeUtxos.filter((u) => u.txid !== prepTxid);
          lastErr = new Error(pf7.error);
          await ledger({
            cycle: CYCLE, kind, attempt, error: pf7.error, errorClass: 'Pf7GenesisFail',
            feeTxid: fee.txid, feeVout: fee.vout,
          });
          console.log(JSON.stringify({
            pf7_retry: true, kind, attempt, error: pf7.error, ms: pf7.ms,
            blacklistedFee: fee.txid.slice(0, 16),
          }));
          // capture repro
          const failDir = path.join(RUN, 'failures', `c${CYCLE}-${kind}-a${attempt}`);
          mkdirSync(failDir, { recursive: true });
          writeFileSync(path.join(failDir, 'error.txt'), pf7.error);
          try {
            writeFileSync(path.join(failDir, 'result.json'), JSON.stringify(pf7.result, null, 2));
          } catch { /* ignore */ }
          continue;
        }

        const pf7Live = prep.settlementOutpoints.verifierCarriers.map((carrier, i) => ({
          lockingBytecode: carrier.lockingBytecode,
          unlockingBytecode: pf7.dump[i].unlock,
          valueSatoshis: carrier.valueSatoshis,
          outpointTransactionHashWire: carrier.outpointTransactionHashWire,
          outpointIndex: Number(carrier.outpointIndex),
        }));
        const complete = await assembleCompleteSettlement({
          kind, bundleDirectory: PROFILE_BUNDLE, expectedProfile,
          actionPacket: w1.actions[kind].actionPacket,
          minimumFeeRateSatoshisPerByte: 1n, feePrivateKey,
          feeSourceValueSatoshis: prep.outputValues.settlementFeeFundingSatoshis,
          bindingCarrierBaseSatoshis: BigInt(bindingBase),
          stateCarrierBaseSatoshis: BigInt(stateBase),
          preparationTransactionHashWire: prep.settlementOutpoints.binding.outpointTransactionHashWire,
          stateOutpointTransactionHashWire: Buffer.from(stateTxid, 'hex').reverse().toString('hex'),
          stateOutpointIndex: 0,
          pf7: pf7Live,
          ...(kind === 'withdrawal' ? { withdrawalLockingBytecode } : {}),
        });
        const verdict = classifyCompleteSettlementVm(complete, true);
        if (!verdict.accepted) {
          pushFee(state, fee);
          state.feeUtxos = state.feeUtxos.filter((u) => u.txid !== prepTxid);
          lastErr = new Error(`${kind} libauth reject ${JSON.stringify([...verdict.failedInputIndexes])}`);
          continue;
        }
        const wire = complete.measurements.wireBytes;
        const maxUnlock = complete.measurements.maximumUnlockingBytes;
        if (wire > 59000 || maxUnlock > 10000) {
          throw new Error(`${kind} size gate wire=${wire} maxUnlock=${maxUnlock}`);
        }
        const settleHex = Buffer.from(encodeTransaction(complete.transaction)).toString('hex');
        const settleTxid = Buffer.from(hash256(Buffer.from(settleHex, 'hex'))).reverse().toString('hex');

        const prepAccept = bchnTestMempool(prepHex);
        if (!prepAccept[0]?.allowed) {
          pushFee(state, fee);
          state.feeUtxos = state.feeUtxos.filter((u) => u.txid !== prepTxid);
          lastErr = new Error(`${kind} prep mempool reject ${JSON.stringify(prepAccept)}`);
          continue;
        }
        bchnSendHex(prepHex);
        const settleAccept = bchnTestMempool(settleHex);
        if (!settleAccept[0]?.allowed) {
          lastErr = new Error(`${kind} settle mempool reject ${JSON.stringify(settleAccept)}`);
          // prep already broadcast — cannot safely retry same tip without recovering carriers
          throw lastErr;
        }
        bchnSendHex(settleHex);

        for (let i = 0; i < complete.transaction.outputs.length; i++) {
          const o = complete.transaction.outputs[i];
          if (Buffer.from(o.lockingBytecode).toString('hex') === hot.lockingBytecodeHex) {
            pushFee(state, { txid: settleTxid, vout: i, sats: Number(o.valueSatoshis) });
          }
        }

        digests = digests1;
        stateTxid = settleTxid;
        state.stateTxid = settleTxid;
        state.lastCompleted = state.lastCompleted || {};
        state.lastCompleted[kind] = plan1.context.digestHex;
        delete state.resumeDigests;
        delete state.resumeSeed;

        const row = {
          cycle: CYCLE, kind, attempt, prepTxid, settleTxid, wire, maxUnlock,
          fee: complete.measurements.feeSatoshis.toString(),
          proveMs, pf7Ms: pf7.ms, totalMs: Date.now() - t0,
          vmOk: true, mempoolOk: true, digest: plan1.context.digestHex,
        };
        await ledger(row);
        console.log(JSON.stringify(row));
        await writeFile(path.join(cycleDir, `${kind}-settlement.hex`), settleHex);
        await writeFile(path.join(cycleDir, `${kind}-settlement-meta.json`), JSON.stringify(row, null, 2));
        await saveState(state);
        succeeded = true;
        break;
      } catch (e) {
        lastErr = e;
        // if fee still unspent, return it
        if (fee && gettxout(fee.txid, fee.vout)) pushFee(state, fee);
        console.log(JSON.stringify({
          attempt_fail: true, kind, attempt, error: String(e.message || e).slice(0, 200),
        }));
        if (String(e.message || e).includes('settle mempool reject')) throw e;
      }
    }

    if (!succeeded) {
      throw lastErr || new Error(`${kind} failed after ${PF7_MAX_ATTEMPTS} attempts`);
    }
    // Note: blacklisted fees for this kind stay out of inventory this cycle —
    // they remain spendable on-chain for a later cycle's refreshHotFees.
  }

  state.history = state.history || [];
  if (!state.history.some((h) => h.witnessSeed === witnessSeed)) {
    const hist = { witnessSeed, transactionContextDigests: { ...digests } };
    if (TRANSFER_HOPS === 0) hist.transferHops = 0;
    state.history.push(hist);
  }
  state.cyclesCompleted = Math.max(state.cyclesCompleted || 0, CYCLE);
  await saveState(state);
  console.log(JSON.stringify({
    done: true, cycle: CYCLE, stateTxid: state.stateTxid,
    feeUtxos: state.feeUtxos.length, history: state.history.length,
  }));
  // snarkjs/wasm workers keep the event loop alive — force clean exit.
  process.exit(0);
}

main().catch(async (e) => {
  console.error('FAIL', e.message || e);
  try {
    await appendFile(path.join(RUN, 'ledger.jsonl'), `${JSON.stringify({
      ts: new Date().toISOString(), cycle: CYCLE, error: String(e.message || e),
      errorClass: e.name || 'Error',
    })}\n`);
  } catch { /* ignore */ }
  process.exit(1);
});
