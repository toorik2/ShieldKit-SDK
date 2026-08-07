// cli/profiles/fri-stark-96kb.mjs
// ShieldKit unified CLI — verifier-pool profile: FRI-STARK 96KB
// (depth=20 blowup=2048 nq=7 grind=30 fold_step=3 DEEP-ALI, Goldilocks, 17 roles,
// 18-input actions, 100-bit security, RANDOM CSPRNG ZK masks, wallet-derived note
// secrets). Same command surface as the other profiles:
//   pool create|doctor|deposit|transfer|withdraw|recover
// Same options (--funding-wallet, --funding-utxo, --data-home, --json) and the same
// fail-closed JSON envelope family.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = process.env.SHIELDKIT_DESIGN_ROOT
  ? path.resolve(process.env.SHIELDKIT_DESIGN_ROOT)
  : path.resolve(HERE, '../../shieldkit-fri-stark-96kb');
const WORKER = path.join(ROOT, '.private/cargo-target/release/shieldkit-fri-worker');
const ASSEMBLE = path.join(ROOT, 'packages/settlement/python/assemble_sound_settlement.py');
const ASM_DIR = path.join(ROOT, 'evidence/production/assemble-state0');
const ASM = {
  deposit: path.join(ASM_DIR, 'assemble-deposit-d20-b2048-n7-g30-base1.materialized.json'),
  transfer: path.join(ASM_DIR, 'assemble-transfer-d20-b2048-n7-g30-base1.materialized.json'),
  withdrawal: path.join(ASM_DIR, 'assemble-withdrawal-d20-b2048-n7-g30-base1.materialized.json'),
};
const ASM_FOR = { deposit: ASM.deposit, transfer: ASM.transfer, withdrawal: ASM.withdrawal };

export const FRI_PROFILE_ID = 'fri-stark-96kb';
export const FRI_PROFILE_SCHEMA = 'shieldkit-v2-beta-product-cli-result-v1';
export const FRI_PROFILE_RESULT_SCHEMA = FRI_PROFILE_SCHEMA;
export const FRI_PROFILE_PIN = {
  scriptBytes: 96734, roles: 17, inputsPerAction: 18, securityBits: 100,
  depth: 20, nq: 7, blowup: 2048, grindBits: 30, foldStep: 3,
  maskSource: 'csprng(thread_rng, 128-bit)', chipnetOnly: true,
};

export class FriProfileError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'FriProfileError';
    this.code = code;
    this.exitCode = options?.exitCode ?? 2;
  }
}
const fail = (code, message, options = undefined) => { throw new FriProfileError(code, message, options); };
const okJson = (body, exitCode = 0) => { console.log(JSON.stringify(body, null, 2)); process.exitCode = exitCode; };
const failJson = (code, message, exitCode = 2, extra = undefined) => {
  console.log(JSON.stringify({ ok: false, code, error: message, ...extra }, null, 2));
  process.exitCode = exitCode;
};
const arg = (argv, name, def) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : def; };
const flag = (argv, name) => argv.includes(`--${name}`);

const WALLET_DEFAULT = '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/wallet-private.json';
const jsonReplacer = (_, v) => (typeof v === 'bigint' ? v.toString() : v);

// design-root imports (the unified CLI sets SHIELDKIT_DESIGN_ROOT)
const mod = (p) => import('file://' + p);
const poolMods = async () => {
  const [createPool, actionSpend, walletNotes, packet, fundSpend] = await Promise.all([
    mod(path.join(ROOT, 'packages/pool/create-pool.mjs')),
    mod(path.join(ROOT, 'packages/pool/action-spend.mjs')),
    mod(path.join(ROOT, 'packages/pool/wallet-notes.mjs')),
    mod(path.join(ROOT, 'packages/core/codecs/packet.mjs')),
    mod(path.join(ROOT, 'scripts/lib/chipnet-fund-spend.mjs')),
  ]);
  return { createPool, actionSpend, walletNotes, packet, fundSpend };
};

function dataHome(argv) {
  const dh = arg(argv, 'data-home');
  if (!dh) fail('DATA_HOME_REQUIRED', '--data-home <dir> is required for this profile (persistent pool state)');
  mkdirSync(dh, { recursive: true });
  return dh;
}
function walletPath(argv) {
  return arg(argv, 'funding-wallet') || process.env.CHIPNET_WALLET_PRIVATE || WALLET_DEFAULT;
}
function loadWallet(argv) {
  const p = walletPath(argv);
  if (!existsSync(p)) fail('WALLET_MISSING', `funding wallet not found: ${p}`);
  try { return JSON.parse(readFileSync(p, 'utf8')); } catch (e) { fail('WALLET_UNREADABLE', String(e?.message ?? e)); }
}
function noteMaster(wallet) {
  if (wallet.noteMasterKeyHex) return wallet.noteMasterKeyHex;
  const m = createHash('sha256').update(`note-master/${wallet.privateKeyHex}`).digest().toString('hex');
  wallet.noteMasterKeyHex = m;
  writeFileSync(walletPath({}), JSON.stringify(wallet, null, 2) + '\n', { mode: 0o600 });
  return m;
}

// ---- persistent pool state (data home) ----
function loadPool(dh) {
  const p = path.join(dh, 'pool.json');
  if (!existsSync(p)) fail('POOL_STATE_MISSING', `no pool state in ${dh}; run 'pool create' first`);
  return JSON.parse(readFileSync(p, 'utf8'));
}
function savePool(dh, pool) {
  writeFileSync(path.join(dh, 'pool.json'), JSON.stringify(pool, jsonReplacer, 2) + '\n');
}
function loadJournal(dh) {
  const p = path.join(dh, 'journal.json');
  if (!existsSync(p)) return { schema: 'shieldkit-fri-wallet-journal-v1', notes: [], steps: [] };
  return JSON.parse(readFileSync(p, 'utf8'));
}
function saveJournal(dh, j) {
  writeFileSync(path.join(dh, 'journal.json'), JSON.stringify(j, jsonReplacer, 2) + '\n');
}

// ---- RPC helpers (node-side; the layer1-node VPS hosts chipnet) ----
let _rpcMod = null;
async function rpc() {
  if (!_rpcMod) {
    const m = await mod(path.join(ROOT, 'scripts/lib/chipnet-fund-spend.mjs'));
    _rpcMod = m;
  }
  return _rpcMod;
}
async function rpcCall(method, params, timeoutMs = 60_000) {
  const { rpcStdin } = await rpc();
  return rpcStdin(method, params, timeoutMs);
}
async function sshRpc(method, params) {
  const { sshCli } = await rpc();
  return sshCli(`${method} ${(params || []).map((p) => `'${String(p).replace(/'/g, "\\'")}'`).join(' ')}`);
}

// ---- funding UTXO: explicit --funding-utxo <t:v> or auto-scan ----
async function pickFunding(argv, wallet, exclude, needDenom) {
  const explicit = arg(argv, 'funding-utxo');
  if (explicit) {
    const [txid, vout] = explicit.split(':');
    const g = await rpcCall('gettxout', [txid, Number(vout), true], 30_000);
    if (!g.parsed || g.parsed.value == null) fail('FUNDING_UTXO_INVALID', `gettxout failed for ${explicit}`);
    if (g.parsed.tokenData || g.parsed.token_data) fail('FUNDING_UTXO_TOKEN', `funding utxo ${explicit} carries tokens`);
    return { txid, vout: Number(vout), valueSats: BigInt(Math.round(Number(g.parsed.value) * 1e8)), lockingHex: g.parsed.scriptPubKey?.hex || wallet.lockingBytecodeHex };
  }
  const { scantxoutsetHot } = await rpc();
  const { scan, unspents } = scantxoutsetHot(wallet.address);
  if (!scan?.success) fail('SCAN_FAILED', 'scantxoutset failed');
  const ranked = unspents
    .map((u) => ({ txid: u.txid, vout: u.vout, amountSats: BigInt(Math.round(Number(u.amount) * 1e8)), scriptPubKey: u.scriptPubKey }))
    .filter((u) => u.amountSats >= needDenom + 200_000n && !exclude.has(`${u.txid}:${u.vout}`))
    .sort((a, b) => Number(b.amountSats - a.amountSats));
  for (const cand of ranked.slice(0, 80)) {
    const g = await rpcCall('gettxout', [cand.txid, cand.vout, true], 30_000);
    if (!g.parsed || g.parsed.value == null) continue;
    if (g.parsed.tokenData || g.parsed.token_data) continue;
    return { txid: cand.txid, vout: cand.vout, valueSats: cand.amountSats, lockingHex: cand.scriptPubKey || wallet.lockingBytecodeHex };
  }
  fail('NO_FUNDING_UTXO', `no plain funding UTXO >= ${needDenom + 200_000n} sats`);
}

// ---- worker prove + assemble (fresh random-mask proof per action) ----
function workerProve(witness, kind, tag) {
  const proofOut = path.join(process.env.SHIELDKIT_FRI_TMP || '/tmp', `fri-${kind}-${tag}.pf.json`);
  const req = { cmd: 'prove', kind, witness, depth: 20, blowup: 2048, queries: 7,
                grindBits: 30, foldStep: 3, deep: true, proofOut };
  const r = spawnSync(WORKER, [], { input: JSON.stringify(req) + '\n', encoding: 'utf8', cwd: ROOT, timeout: 600_000 });
  if (r.status !== 0) fail('PROVE_FAILED', `worker rc=${r.status}: ${(r.stderr || r.stdout || '').slice(0, 400)}`);
  const lines = (r.stdout || '').split('\n').filter((l) => l.trim().startsWith('{'));
  const doc = JSON.parse(lines[lines.length - 1]);
  if (doc.verifyOk !== true) fail('PROVE_NOT_OK', JSON.stringify(doc).slice(0, 400));
  if (doc.maskSource !== 'csprng(thread_rng, 128-bit)') {
    fail('PRODUCTION_MASK_GATE', `expected csprng mask, got ${doc.maskSource}`);
  }
  const pf = JSON.parse(readFileSync(proofOut, 'utf8'));
  pf.stmt = { ...pf.stmt, kind };
  return { doc, pf };
}

const PICKLE_PY = `import json,pickle,sys
def to_int(o, key=None, parent=None):
  if key in ("nonce", "comp_root", "tp_root", "path", "pk", "sk", "cp", "frl", "beta", "i2x"): return o
  if key == "root" and parent != "stmt": return o
  if isinstance(o, dict): return {k: to_int(v, k, key) for k, v in o.items()}
  if isinstance(o, list): return [to_int(x, key, parent) for x in o]
  if isinstance(o, str):
    try: return int(o)
    except ValueError: return o
  return o
pf = to_int(json.load(open(sys.argv[1]))); open(sys.argv[2],"wb").write(pickle.dumps(pf, protocol=4))`;

function proveAndAssemble(kind, witness, tag) {
  const { doc, pf } = workerProve(witness, kind, tag);
  const outDir = process.env.SHIELDKIT_FRI_TMP || '/tmp';
  const pfJson = path.join(outDir, `fri-${kind}-${tag}.pf.json`);
  const cache = path.join(outDir, `fri-${kind}-${tag}.pkl`);
  writeFileSync(pfJson, JSON.stringify(pf));
  const pr = spawnSync('python3', ['-c', PICKLE_PY, pfJson, cache], { encoding: 'utf8', timeout: 120 });
  if (pr.status !== 0) fail('PICKLE_FAILED', (pr.stderr || '').slice(0, 300));
  const out = path.join(outDir, `fri-${kind}-${tag}.materialized.json`);
  const env = {
    ...process.env,
    VC_PRODUCT_FIXED_LOCKS: '1', VC_ROLE_INDEX_BASE: '1', VC_BLOB_IDX: '1',
    VC_SKIP_PROOF_VERIFY: '1', VC_RUST_FRI_TERMS: '1',
    SHIELDKIT_FRI_WORKER: WORKER, VC_PROOF_CACHE: cache,
  };
  let attempts = 0;
  for (;;) {
    attempts += 1;
    const ar = spawnSync('python3', [ASSEMBLE, kind, '--depth', '20', '--nq', '7', '--blowup', '2048',
      '--grind', '30', '--fold-step', '3', '--seed', '1', '--out', out], { encoding: 'utf8', cwd: ROOT, env, timeout: 600_000 });
    if (!existsSync(out)) fail('ASSEMBLE_FAILED', (ar.stderr || ar.stdout || '').slice(-600));
    const art = JSON.parse(readFileSync(out, 'utf8'));
    const vm = art.vm || {};
    if (vm.allAccept === true && (vm.fails || []).length === 0) {
      return { artPath: out, art, doc, attempts };
    }
    if (attempts >= 12) fail('ASSEMBLE_VM_REJECT', `VM reject after 12 random-mask attempts: ${JSON.stringify(vm.fails || vm).slice(0, 400)}`);
    const { pf: pf2 } = workerProve(witness, kind, `${tag}-r${attempts}`);
    writeFileSync(pfJson, JSON.stringify(pf2));
    const pr2 = spawnSync('python3', ['-c', PICKLE_PY, pfJson, cache], { encoding: 'utf8', timeout: 120 });
    if (pr2.status !== 0) fail('PICKLE_FAILED', 're-prove pickle failed');
  }
}

// ---- build + fee fixpoint + broadcast ----
async function executeAction(argv, kind, { tip, wallet, funding, artPath }) {
  const { actionSpend, packet } = await poolMods();
  const { buildTipActionTx, withSourceOutputs, evaluateTipActionTx, signFundingInput, ROLE_DUST, kindCode } = actionSpend;
  const k = kindCode(kind);
  const needDenom = k === packet.KIND.DEPOSIT ? 10_000_000n : 0n;
  const exclude = new Set([`${tip.stateOutpoint.txid}:${tip.stateOutpoint.vout}`, ...tip.roleOutpoints.map((r) => `${r.txid}:${r.vout}`)]);
  const funding2 = funding ?? (await pickFunding(argv, wallet, exclude, needDenom));
  const mk = (fee) => {
    let built = buildTipActionTx({
      kind, categoryHex: tip.categoryHex, preState: tip.state, assemblyPath: artPath,
      stateOutpoint: tip.stateOutpoint, roleOutpoints: tip.roleOutpoints,
      funding: { txid: funding2.txid, vout: funding2.vout, valueSats: funding2.valueSats, lockingHex: funding2.lockingHex },
      payoutLockingHex: wallet.lockingBytecodeHex, feeSats: fee,
    });
    return withSourceOutputs(built, {
      stateOutpoint: tip.stateOutpoint, roleOutpoints: tip.roleOutpoints,
      funding: { txid: funding2.txid, vout: funding2.vout, valueSats: funding2.valueSats, lockingHex: funding2.lockingHex },
      categoryHex: tip.categoryHex, preCommitmentHex: tip.stateCommitmentHex, stateLockingHex: tip.stateLockingHex,
    });
  };
  let feeSats = 3000n;
  let built = mk(feeSats);
  const vmR = evaluateTipActionTx(built, { skipFunding: true });
  if (!vmR.allAccept) fail('VM_REJECT', `${kind} local VM reject: ${JSON.stringify(vmR.fails).slice(0, 800)}`);
  built = signFundingInput(built, { privateKeyHex: wallet.privateKeyHex });
  const libauth = await import('@bitauth/libauth');
  let signedHex = libauth.binToHex(libauth.encodeTransaction(built.tx));
  const buildSigned = async (fee) => {
    const b2 = mk(fee);
    const v2 = evaluateTipActionTx(b2, { skipFunding: true });
    if (!v2.allAccept) fail('VM_REJECT', `${kind} VM after re-fee reject`);
    const b3 = signFundingInput(b2, { privateKeyHex: wallet.privateKeyHex });
    return libauth.binToHex(libauth.encodeTransaction(b3.tx));
  };
  for (let it = 0; it < 10; it += 1) {
    const sizeFee = BigInt(signedHex.length / 2 + 1);
    if (sizeFee === feeSats) break;
    feeSats = sizeFee;
    signedHex = await buildSigned(feeSats);
  }
  let converged = BigInt(signedHex.length / 2 + 1) === feeSats;
  if (!converged) {
    for (let delta = -12n; delta <= 12n && !converged; delta += 1n) {
      const cand = feeSats + delta;
      if (cand <= 0n) continue;
      const h = await buildSigned(cand);
      const sz = BigInt(h.length / 2 + 1);
      if (process.env.SHIELDKIT_FRI_DEBUG) {
        console.error(`[fri96] fee search cand=${cand} size+1=${sz}`);
      }
      if (sz === cand) { feeSats = cand; signedHex = h; converged = true; }
    }
  }
  if (!converged) fail('FEE_NOT_CONVERGED', `${kind} fee = size+1 fixpoint not found (last size+1=${signedHex.length / 2 + 1})`);
  const acc = await rpcCall('testmempoolaccept', [[signedHex]], 60_000);
  const allowed = Array.isArray(acc.parsed) && acc.parsed[0]?.allowed === true;
  if (!allowed) fail('MEMPOOL_REJECT', JSON.stringify(acc.parsed || acc.text).slice(0, 1200));
  const txid = String((await rpcCall('sendrawtransaction', [signedHex], 60_000)).parsed).trim();
  if (!/^[0-9a-f]{64}$/i.test(txid)) fail('BAD_TXID', `bad txid ${txid}`);
  const raw = String((await rpcCall('getrawtransaction', [txid, false], 60_000)).parsed).trim().toLowerCase();
  if (raw !== signedHex.toLowerCase()) fail('READBACK_MISMATCH', `${kind} raw readback mismatch`);
  return {
    txid, bytes: signedHex.length / 2, feeSats: feeSats.toString(),
    postState: built.postState, postCommitmentHex: built.postCommitmentHex,
    stateValueOut: built.stateValueOut.toString(), funding: funding2,
    maskSource: 'csprng(thread_rng, 128-bit)',
  };
}

// ---- note/witness construction (wallet-driven; kind-tagged client trees) ----
function buildWitness(kind, { notes, instanceId32, master, actionSpend, walletNotes }) {
  const { deriveNoteSecrets, ownerPubkey, noteCommitment, ClientNoteTree, POOL_NOTE_VALUE, KIND_ID } = walletNotes;
  const isDeposit = kind === 'deposit';
  const spent = isDeposit ? null : notes[notes.length - 1]; // last created note is the spent one
  const newIndex = notes.length;
  const sec = deriveNoteSecrets(master, instanceId32, newIndex);
  const pk = ownerPubkey(sec.sk);
  const cm = noteCommitment(POOL_NOTE_VALUE, pk, sec.rho, sec.blind);
  const nf = walletNotes.noteNullifier(sec.sk, sec.rho);
  const tree = new ClientNoteTree(20, KIND_ID[kind]);
  const spentCm = isDeposit ? cm : spent.cm;
  const { path } = tree.append(spentCm);
  const w = isDeposit
    ? {
        sk: sec.sk.toString(), rho_in: sec.rho.toString(), blind_in: sec.blind.toString(),
        value_in: POOL_NOTE_VALUE.toString(), fee: '0',
        value_outs: [POOL_NOTE_VALUE.toString(), '0'],
        owners_out: [pk.toString(), '0'], rhos_out: [sec.rho.toString(), '0'], blinds_out: [sec.blind.toString(), '0'],
        siblings: path.map((x) => x.toString()),
      }
    : kind === 'transfer'
      ? {
          sk: spent.sk.toString(), rho_in: spent.rho.toString(), blind_in: spent.blind.toString(),
          value_in: POOL_NOTE_VALUE.toString(), fee: '0',
          value_outs: [POOL_NOTE_VALUE.toString(), '0'],
          owners_out: [pk.toString(), '0'], rhos_out: [sec.rho.toString(), '0'], blinds_out: [sec.blind.toString(), '0'],
          siblings: path.map((x) => x.toString()),
        }
      : {
          sk: spent.sk.toString(), rho_in: spent.rho.toString(), blind_in: spent.blind.toString(),
          value_in: POOL_NOTE_VALUE.toString(), fee: POOL_NOTE_VALUE.toString(),
          value_outs: ['0', '0'], owners_out: ['0', '0'], rhos_out: ['0', '0'], blinds_out: ['0', '0'],
          siblings: path.map((x) => x.toString()),
        };
  return { w, sec, pk, cm, nf, path };
}

// ---- commands ----
export async function poolDoctor(argv) {
  const checks = {
    material: ['deposit', 'transfer', 'withdrawal'].every((k) => existsSync(ASM_FOR[k])),
    worker: existsSync(WORKER),
    vendorPin: existsSync(path.join(ROOT, 'vendor/bch-fri-stark/VENDORED_COMMIT'))
      && readFileSync(path.join(ROOT, 'vendor/bch-fri-stark/VENDORED_COMMIT'), 'utf8').trim() === 'a600e828d68eb41840049cb16d0c21850ff9df57',
    wallet: existsSync(walletPath(argv)),
  };
  if (!checks.material) fail('MATERIAL_MISSING', `missing assemble artifacts in ${ASM_DIR}`);
  if (!checks.worker) fail('WORKER_MISSING', `worker not built at ${WORKER}`);
  if (!checks.wallet) fail('WALLET_MISSING', `wallet not found at ${walletPath(argv)}`);
  // worker manifest
  const m = spawnSync(WORKER, [], { input: '{"cmd":"manifest"}\n', encoding: 'utf8', cwd: ROOT, timeout: 30_000 });
  let manifest = null;
  try { manifest = JSON.parse((m.stdout || '').split('\n').filter((l) => l.trim().startsWith('{')).pop()); } catch { /* */ }
  okJson({
    ok: true, schema: FRI_PROFILE_SCHEMA, command: 'doctor', profile: FRI_PROFILE_ID,
    profilePin: FRI_PROFILE_PIN,
    checks: { ...checks, manifest: manifest?.schema ?? null, workerEngine: manifest?.engine ?? null },
    status: 'wiring-ok', network: 'chipnet',
  });
}

export async function poolCreate(argv) {
  const { createPool } = await poolMods();
  const dh = dataHome(argv);
  const wallet = loadWallet(argv);
  const { rpcStdin, scantxoutsetHot, sshCli } = await rpc();
  const chainRaw = sshCli('getblockchaininfo');
  let chainInfo = null;
  try { chainInfo = JSON.parse(chainRaw.stdout); } catch { /* */ }
  if (!chainRaw.ok || chainInfo?.chain !== 'chip') fail('NOT_CHIPNET', 'live chipnet RPC required');
  const live = await createPool.createPoolLive({
    rpcStdin, scantxoutsetHot, walletPath: walletPath(argv), outDir: path.join(dh, 'create-pool'),
    assemblyPath: ASM.transfer, requireVout0: true, requirePlain: true, minVinSats: 100_000n,
  });
  if (!live.ok || live.operatorKeySpendable || !live.genesisTxid) fail('CREATE_POOL_FAILED', JSON.stringify(live).slice(0, 600));
  const pool = {
    schema: 'shieldkit-fri-cli-pool-v1',
    profile: FRI_PROFILE_ID,
    genesisTxid: live.genesisTxid, categoryHex: live.categoryHex, instanceId32: live.instanceId32,
    profileId: live.profileId,
    stateOutpoint: { txid: live.genesisTxid, vout: 0, valueSats: '2000' },
    roleOutpoints: live.roleOutpoints.map((op, i) => {
      const [txid, vout] = op.split(':');
      return { txid, vout: Number(vout), valueSats: '1000', lockingHex: live.genesisDescriptor.roleLockingHexes[i] };
    }),
    state: live.state, stateCommitmentHex: live.stateCommitmentHex, stateLockingHex: live.stateLockingHex,
    noteCount: 0, actionSequence: 0,
  };
  savePool(dh, pool);
  const j = loadJournal(dh);
  j.steps.push({ kind: 'createPool', txid: live.genesisTxid, stateCommitmentHex: live.stateCommitmentHex, feeSats: live.feeSats, rawMatch: live.rawMatch });
  saveJournal(dh, j);
  okJson({
    ok: true, schema: FRI_PROFILE_SCHEMA, command: 'pool create', profile: FRI_PROFILE_ID,
    network: 'chipnet', dataHome: dh,
    pool: { genesisTxid: live.genesisTxid, categoryHex: live.categoryHex, instanceId32: live.instanceId32,
            stateOutpoint: pool.stateOutpoint, roleCount: pool.roleOutpoints.length,
            stateCommitmentHex: live.stateCommitmentHex, feeSats: live.feeSats, rawMatch: live.rawMatch,
            maskSource: 'csprng(thread_rng, 128-bit)' },
    notes: ['FRI-STARK 96KB fresh pool: state@0 covenant + 17 fixed role locks; note secrets derive from the wallet note-master key'],
  });
}

export async function actionCommand(argv, kind) {
  const { actionSpend, walletNotes } = await poolMods();
  const dh = dataHome(argv);
  const wallet = loadWallet(argv);
  const master = noteMaster(wallet);
  const pool = loadPool(dh);
  const j = loadJournal(dh);
  if (kind === 'deposit' && pool.noteCount >= 2) fail('NOTE_LIMIT', 'this demo profile supports up to 2 notes (deposit->transfer->withdraw chain)');
  const { w, sec, pk, cm, nf } = buildWitness(kind, {
    notes: j.notes.map((n) => ({ ...n, sk: secOf(n, master, pool.instanceId32, walletNotes).sk,
                                       rho: secOf(n, master, pool.instanceId32, walletNotes).rho,
                                       blind: secOf(n, master, pool.instanceId32, walletNotes).blind })),
    instanceId32: pool.instanceId32, master, actionSpend, walletNotes,
  });
  const tag = `${kind}-${pool.actionSequence}`;
  const { artPath } = proveAndAssemble(kind, w, tag);
  const tip = {
    stateOutpoint: pool.stateOutpoint, roleOutpoints: pool.roleOutpoints,
    state: pool.state, stateCommitmentHex: pool.stateCommitmentHex, stateLockingHex: pool.stateLockingHex,
    categoryHex: pool.categoryHex,
  };
  const res = await executeAction(argv, kind, { tip, wallet, funding: null, artPath });
  // persist the tip + the note
  pool.stateOutpoint = { txid: res.txid, vout: 0, valueSats: res.stateValueOut };
  pool.roleOutpoints = pool.roleOutpoints.map((r, i) => ({ txid: res.txid, vout: i + 1, valueSats: '1000', lockingHex: r.lockingHex }));
  pool.state = res.postState; pool.stateCommitmentHex = res.postCommitmentHex;
  pool.actionSequence += 1;
  // journal records only indices + commitments: note secrets re-derive from the
  // wallet note-master key (never stored; the master never enters the journal).
  if (kind === 'deposit') {
    j.notes.push({ index: pool.noteCount, kind, txid: res.txid, cm: cm.toString(), nf: nf.toString() });
    pool.noteCount += 1;
  } else {
    j.notes[j.notes.length - 1] = { ...j.notes[j.notes.length - 1], spent: true, spentTxid: res.txid };
    j.notes.push({ index: pool.noteCount, kind, txid: res.txid, cm: cm.toString(), nf: nf.toString() });
    pool.noteCount += 1;
  }
  j.steps.push({ kind, txid: res.txid, stateCommitmentHex: res.postCommitmentHex, feeSats: res.feeSats, bytes: res.bytes });
  savePool(dh, pool);
  saveJournal(dh, j);
  okJson({
    ok: true, schema: FRI_PROFILE_SCHEMA, command: kind, profile: FRI_PROFILE_ID,
    network: 'chipnet', dataHome: dh,
    action: { kind, txid: res.txid, bytes: res.bytes, feeSats: res.feeSats, maskSource: res.maskSource,
              stateOutpoint: pool.stateOutpoint, stateCommitmentHex: res.postCommitmentHex,
              note: { index: pool.noteCount - 1, cm: cm.toString(), nf: nf.toString() } },
    notes: ['fresh random-mask proof (csprng); no pinned caches; fee = size+1'],
  });
}

function secOf(note, master, instanceId32, walletNotes) {
  const { deriveNoteSecrets } = walletNotes;
  return deriveNoteSecrets(master, instanceId32, note.index);
}

export async function recoverCommand(argv) {
  const { walletNotes } = await poolMods();
  const dh = dataHome(argv);
  const wallet = loadWallet(argv);
  const master = noteMaster(wallet);
  const pool = loadPool(dh);
  const j = loadJournal(dh);
  const recovered = [];
  for (const note of j.notes) {
    const sec = secOf(note, master, pool.instanceId32, walletNotes);
    const pk = walletNotes.ownerPubkey(sec.sk);
    const cm = walletNotes.noteCommitment(walletNotes.POOL_NOTE_VALUE, pk, sec.rho, sec.blind);
    const nf = walletNotes.noteNullifier(sec.sk, sec.rho);
    const ok = cm.toString() === note.cm && nf.toString() === note.nf;
    recovered.push({ index: note.index, kind: note.kind, cm: cm.toString(), nf: nf.toString(), matchesJournal: ok, spent: note.spent ?? false });
    if (!ok) fail('RECOVER_MISMATCH', `note ${note.index} re-derivation mismatch`);
  }
  // chain readback of the last action
  let lastTx = null;
  if (j.steps.length > 1) {
    const last = j.steps[j.steps.length - 1];
    try {
      const g = await rpcCall('getrawtransaction', [last.txid, false], 30_000);
      lastTx = { txid: last.txid, rawOk: typeof g.parsed === 'string' && g.parsed.length > 0 };
    } catch { lastTx = { txid: last.txid, rawOk: false }; }
  }
  okJson({
    ok: true, schema: FRI_PROFILE_SCHEMA, command: 'recover', profile: FRI_PROFILE_ID,
    network: 'chipnet', dataHome: dh,
    recovery: {
      mode: 'journal+master-key', masterKeyTag: createHash('sha256').update(master).digest('hex').slice(0, 16),
      notes: recovered, recoverableCount: recovered.length,
      poolTip: { stateOutpoint: pool.stateOutpoint, stateCommitmentHex: pool.stateCommitmentHex, actionSequence: pool.actionSequence },
      lastTx,
    },
    notes: ['notes re-derived from the wallet note-master key + the journal (never a proof seed)'],
  });
}

// ---- dispatcher ----
export async function runFriProfileCommand(argv) {
  const cmd = argv[0];
  try {
    if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') { console.log(friUsage()); return; }
    if (cmd === 'pool') {
      const sub = argv[1];
      if (!sub || sub === 'help' || sub === '--help' || sub === '-h') { console.log(friUsage()); return; }
      if (sub === 'create') return await poolCreate(argv);
      if (sub === 'doctor') return await poolDoctor(argv);
      if (sub === 'deposit') return await actionCommand(argv, 'deposit');
      if (sub === 'transfer') return await actionCommand(argv, 'transfer');
      if (sub === 'withdraw') return await actionCommand(argv, 'withdrawal');
      if (sub === 'recover' || sub === 'recovery') return await recoverCommand(argv);
      fail('UNKNOWN_COMMAND', `unknown pool subcommand for profile ${FRI_PROFILE_ID}: ${sub}`);
    }
    if (cmd === 'deposit') return await actionCommand(argv, 'deposit');
    if (cmd === 'transfer') return await actionCommand(argv, 'transfer');
    if (cmd === 'withdraw') return await actionCommand(argv, 'withdrawal');
    if (cmd === 'recover' || cmd === 'recovery') return await recoverCommand(argv);
    if (cmd === 'doctor') return await poolDoctor(argv);
    fail('UNKNOWN_COMMAND', `unknown command for profile ${FRI_PROFILE_ID}: ${cmd}`);
  } catch (e) {
    if (e instanceof FriProfileError) { failJson(e.code, e.message, e.exitCode ?? 2); return; }
    failJson('FRI_PROFILE_INTERNAL', String(e?.message ?? e), 2, { stack: String(e?.stack ?? '').split('\n').slice(0, 6) });
  }
}

export function friUsage() {
  return `ShieldKit unified CLI — profile ${FRI_PROFILE_ID} (FRI-STARK d20/b2048/n7/g30, 17 roles, 18-input actions, 100-bit, random-mask)
  node shieldkit.mjs --profile fri-stark-96kb pool create   --funding-wallet <w> [--funding-utxo <t:v>] --data-home <dir> [--json]
  node shieldkit.mjs --profile fri-stark-96kb pool doctor   [--data-home <dir>] [--json]
  node shieldkit.mjs --profile fri-stark-96kb deposit       --funding-wallet <w> [--funding-utxo <t:v>] --data-home <dir> [--json]
  node shieldkit.mjs --profile fri-stark-96kb transfer      --funding-wallet <w> [--funding-utxo <t:v>] --data-home <dir> [--json]
  node shieldkit.mjs --profile fri-stark-96kb withdraw      --funding-wallet <w> [--funding-utxo <t:v>] --data-home <dir> [--json]
  node shieldkit.mjs --profile fri-stark-96kb recover       --funding-wallet <w> --data-home <dir> [--json]
`;
}
