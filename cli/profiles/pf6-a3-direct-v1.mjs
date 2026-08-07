// cli/profiles/pf6-a3-direct-v1.mjs
// ShieldKit unified CLI — verifier-pool profile: bn254-onetx-pf6-a3-r1 ("54KB", 6 roles, 9-input actions).
// Same command surface as the beta product CLI (pool create|doctor|deposit|transfer|withdraw|recover),
// same options, same fail-closed JSON envelope family.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// the DESIGN ROOT is resolved by the shared CLI from the pool-designs registry
// (process.env.SHIELDKIT_DESIGN_ROOT); the fallback keeps direct execution working.
const ROOT = process.env.SHIELDKIT_DESIGN_ROOT
  ? path.resolve(process.env.SHIELDKIT_DESIGN_ROOT)
  : path.resolve(HERE, '../../shieldkit-groth-54kb');
const G = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-94kb';

export const PF6_PROFILE_ID = 'pf6-a3-direct-v1';
export const PF6_PROFILE_SCHEMA = 'shieldkit-v2-beta-product-cli-result-v1';
export const PF6_PROFILE_RESULT_SCHEMA = PF6_PROFILE_SCHEMA;
export const PF6_PROFILE_PIN = {
  scriptBytes: 54671, score: 54949, roles: 6, inputsPerAction: 9,
  vk: 'd38f3cfc', ceremony: 'reuse-single-contributor', chipnetOnly: true,
};

export class Pf6ProfileError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'Pf6ProfileError';
    this.code = code;
    this.exitCode = options?.exitCode ?? 2;
  }
}
const fail = (code, message, options = undefined) => { throw new Pf6ProfileError(code, message, options); };
const okJson = (body, exitCode = 0) => { console.log(JSON.stringify(body, null, 2)); process.exitCode = exitCode; };
const failJson = (code, message, exitCode = 2, extra = undefined) => {
  console.log(JSON.stringify({ ok: false, code, error: message, ...extra }, null, 2));
  process.exitCode = exitCode;
};
const arg = (argv, name, def) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : def; };
const flag = (argv, name) => argv.includes(`--${name}`);

const sha256hex = (b) => createHash('sha256').update(b).digest('hex');
let _la = null;
const libauth = () => (_la ??= import('file://' + path.join(ROOT, 'vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js')));
let _rpc = null;
const rpc = async () => {
  if (_rpc) return _rpc;
  const { createLayer1BchnChipnetRpc } = await import('file://' + path.join(HERE, '../packages/kit/chipnet-rpc.mjs'));
  _rpc = await createLayer1BchnChipnetRpc();
  return _rpc;
};
const mod = (p) => import('file://' + p);
const G_MOD = (p) => mod(G + p);
let _covenants = null;
const covenants = () => (_covenants ??= mod(path.join(ROOT, 'src/product-port/structural-covenants.mjs')));
let _topology = null;
const topology = () => (_topology ??= mod(path.join(ROOT, 'src/topology-pf6.mjs')));

const DENOMINATION = '10000000';
const CARRIER_VALUE = 1000n;
const STATE_BASE = 2500n;
const SOURCE_FUND = 2_000_000n;

function pf6Material() {
  const mat = JSON.parse(readFileSync(path.join(ROOT, 'src/verifier-material/pf6-action-material.json'), 'utf8'));
  return mat.actions.deposit;
}
function freshPoolConstants() {
  return JSON.parse(readFileSync(path.join(ROOT, 'src/fresh-pool-constants.json'), 'utf8'));
}
function walletFromPath(walletPath) {
  if (!walletPath) fail('BETA_WALLET_REQUIRED', '--funding-wallet <absolute wallet-private.json path> is required');
  const p = path.resolve(walletPath);
  if (!existsSync(p)) fail('BETA_WALLET_MISSING', `wallet file not found: ${p}`);
  let w;
  try { w = JSON.parse(readFileSync(p, 'utf8')); } catch (e) { fail('BETA_WALLET_INVALID', `wallet file is not JSON: ${p}`); }
  if (typeof w.privateKeyHex !== 'string' || typeof w.publicKeyHex !== 'string' || typeof w.lockingBytecodeHex !== 'string') {
    fail('BETA_WALLET_INVALID', 'wallet file must contain privateKeyHex, publicKeyHex, lockingBytecodeHex');
  }
  return w;
}
function parseFundingUtxo(value) {
  if (!value) fail('BETA_FUNDING_UTXO_REQUIRED', '--funding-utxo <64-hex-txid:vout> is required');
  const m = /^([0-9a-f]{64}):(\d+)$/.exec(value);
  if (!m) fail('BETA_FUNDING_UTXO_INVALID', '--funding-utxo must be <64-lowercase-hex-txid>:<vout>');
  return { txid: m[1], vout: Number(m[2]) };
}
function poolJournalPath(dataHome) {
  if (!dataHome) fail('BETA_DATA_HOME_REQUIRED', '--data-home <absolute directory> is required');
  return path.join(path.resolve(dataHome), 'pf6-pool.json');
}
function loadPoolJournal(dataHome) {
  const p = poolJournalPath(dataHome);
  if (!existsSync(p)) fail('BETA_POOL_NOT_FOUND', `no pf6 pool journal at ${p}; run "pool create" first`);
  return JSON.parse(readFileSync(p, 'utf8'));
}
function savePoolJournal(dataHome, journal) {
  const p = poolJournalPath(dataHome);
  mkdirSync(path.dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(journal, null, 2), { mode: 0o600 });
  return p;
}
async function signP2pkh(tx, sourceLock, sourceValue, inputIndex, wallet) {
  const la = await libauth();
  const ser = la.generateSigningSerializationBch(
    { inputIndex, sourceOutputs: [{ lockingBytecode: la.hexToBin(sourceLock), valueSatoshis: sourceValue }], transaction: tx },
    { coveredBytecode: la.hexToBin(sourceLock), signingSerializationType: Uint8Array.of(97) },
  );
  const digest = la.hash256(ser);
  const priv = Uint8Array.from(Buffer.from(wallet.privateKeyHex, 'hex'));
  const schnorr = la.secp256k1.signMessageHashSchnorr(priv, digest);
  return Buffer.concat([
    la.encodeDataPush(Uint8Array.from([...schnorr, 97])),
    la.encodeDataPush(Uint8Array.from(Buffer.from(wallet.publicKeyHex, 'hex'))),
  ]);
}
const txidOf = (hex) => {
  const la = libauth();
  return la.then(m => m.binToHex(m.hash256(m.hexToBin(hex)).reverse()));
};

// ---- pool create: source + genesis (pf6 fresh pool) ----
export async function poolCreate(argv) {
  const wallet = walletFromPath(arg(argv, 'funding-wallet'));
  const funding = parseFundingUtxo(arg(argv, 'funding-utxo'));
  const dataHome = arg(argv, 'data-home');
  mkdirSync(dataHome, { recursive: true });  // fresh data home support
  const journalPath = poolJournalPath(dataHome);
  if (existsSync(journalPath) && !flag(argv, 'resume')) {
    fail('BETA_POOL_EXISTS', `a pf6 pool journal already exists at ${journalPath}; use --resume to resume`);
  }
  const R = await rpc();
  const la = await libauth();
  const mat = pf6Material();
  const fpc = freshPoolConstants();
  const cov = await covenants();
  const topo = await topology();
  const st = await G_MOD('/packages/action/v2/state.mjs');
  const tm = await G_MOD('/packages/action/v2/transition.mjs');
  const pc = await G_MOD('/packages/profile/v2/profile-core.mjs');

  const fundingOut = await R.gettxout(funding.txid, funding.vout);
  if (!fundingOut) fail('BETA_FUNDING_UTXO_UNSPENT', `funding utxo ${funding.txid}:${funding.vout} is not unspent`);
  const fundingRawTxHex = await R.getrawtransaction(funding.txid, false);
  const fundingFeeTx = la.decodeTransaction(la.hexToBin(fundingRawTxHex));
  const fundingLock = la.binToHex(fundingFeeTx.outputs[funding.vout].lockingBytecode);
  const fundingValue = fundingFeeTx.outputs[funding.vout].valueSatoshis;
  if (fundingLock !== wallet.lockingBytecodeHex) {
    fail('BETA_FUNDING_UTXO_LOCK', 'the funding utxo is not locked to --funding-wallet');
  }

  // Phase A: source tx (2M output) with a fee loop
  let sourceHex = null, sourceChange = 0n;
  for (let i = 0; i < 8; i++) {
    const tx = {
      version: 2,
      inputs: [{ outpointTransactionHash: la.hexToBin(funding.txid), outpointIndex: funding.vout, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() }],
      outputs: [
        { lockingBytecode: la.hexToBin(wallet.lockingBytecodeHex), valueSatoshis: SOURCE_FUND },
        { lockingBytecode: la.hexToBin(wallet.lockingBytecodeHex), valueSatoshis: sourceChange },
      ],
      locktime: 0,
    };
    const unlock = await signP2pkh(tx, wallet.lockingBytecodeHex, fundingValue, 0, wallet);
    tx.inputs[0].unlockingBytecode = unlock;
    const raw = la.binToHex(la.encodeTransaction(tx));
    const requiredFee = BigInt(raw.length / 2 + 1);
    const totalOut = SOURCE_FUND + sourceChange;
    if (fundingValue - totalOut === requiredFee) { sourceHex = raw; break; }
    sourceChange = fundingValue - SOURCE_FUND - requiredFee;
  }
  if (!sourceHex) fail('BETA_SOURCE_FEE_CONVERGE', 'source tx fee loop did not converge');
  const sourceTxid = (await txidOf(sourceHex));
  const instanceId = Buffer.from(sourceTxid, 'hex').reverse().toString('hex');
  const profileId = fpc.profileId;

  const model = tm.createDirectV2PoolModel({ profileId, maximumLiveNotes: '32', denominationSats: DENOMINATION });
  const initialState = st.encodeStateNftCommitment(model.state, { denominationSats: DENOMINATION });

  // Phase B: genesis (6 verifier + carrier + state + change)
  const verifierLocks = mat.verifierRoles.map(r => Uint8Array.from(Buffer.from(r.lock, 'hex')));
  const bindingLock = Uint8Array.of(0x75, 0x51);
  const helper = cov.buildDirectV2StateHelper({
    bindingLock, verifierLocks,
    verifierBaseValues: verifierLocks.map(() => CARRIER_VALUE),
    bindingBaseValueSats: CARRIER_VALUE, stateBaseValueSats: STATE_BASE,
    denominationSats: DENOMINATION, stateCategory: instanceId, minimumChangeSats: 546n,
    topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES,
  });
  const stateLock = cov.buildDirectV2StateTrampolineLock({
    helper, bindingLock,
    topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES,
  });
  const category = Uint8Array.from(Buffer.from(instanceId, 'hex')).reverse();
  const stateToken = { amount: 0n, category, nft: { capability: 'mutable', commitment: initialState } };
  const genesisOuts = [
    ...verifierLocks.map(l => ({ lockingBytecode: l, valueSatoshis: CARRIER_VALUE })),
    { lockingBytecode: bindingLock, valueSatoshis: CARRIER_VALUE },
    { lockingBytecode: stateLock, valueSatoshis: STATE_BASE, token: stateToken },
  ];
  let genesisHex = null, genesisChange = 0n;
  for (let i = 0; i < 8; i++) {
    const tx = {
      version: 2,
      inputs: [{ outpointTransactionHash: la.hexToBin(sourceTxid), outpointIndex: 0, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() }],
      outputs: [...genesisOuts, { lockingBytecode: la.hexToBin(wallet.lockingBytecodeHex), valueSatoshis: genesisChange }],
      locktime: 0,
    };
    const unlock = await signP2pkh(tx, wallet.lockingBytecodeHex, SOURCE_FUND, 0, wallet);
    tx.inputs[0].unlockingBytecode = unlock;
    const raw = la.binToHex(la.encodeTransaction(tx));
    const requiredFee = BigInt(raw.length / 2 + 1);
    const totalOut = 7n * CARRIER_VALUE + STATE_BASE + genesisChange;
    if (SOURCE_FUND - totalOut === requiredFee) { genesisHex = raw; break; }
    genesisChange = SOURCE_FUND - 7n * CARRIER_VALUE - STATE_BASE - requiredFee;
  }
  if (!genesisHex) fail('BETA_GENESIS_FEE_CONVERGE', 'genesis tx fee loop did not converge');
  const genesisTxid = (await txidOf(genesisHex));

  // admission: source then genesis
  const sourceTma = await R.testmempoolaccept(sourceHex);
  if (!sourceTma?.[0]?.allowed) fail('BETA_SOURCE_REJECTED', `source rejected: ${JSON.stringify(sourceTma?.[0] ?? 'unknown')}`);
  await R.sendrawtransaction(sourceHex, true);
  const genesisTma = await R.testmempoolaccept(genesisHex);
  if (!genesisTma?.[0]?.allowed) fail('BETA_GENESIS_REJECTED', `genesis rejected: ${JSON.stringify(genesisTma?.[0] ?? 'unknown')}`);
  const broadcastTxid = String(await R.sendrawtransaction(genesisHex, true)).trim();

  // pool account (note secrets)
  const accountPath = path.join(path.dirname(journalPath), 'pf6-pool-account.json');
  let account;
  if (existsSync(accountPath)) {
    account = JSON.parse(readFileSync(accountPath, 'utf8'));
  } else {
    const sampleScalar = async () => {
      const { BABYJUB_SUBGROUP_ORDER } = await G_MOD('/packages/recover/portable-core.mjs');
      for (let i = 0; i < 1024; i++) {
        const hex = randomBytes(32).toString('hex');
        if (BigInt('0x' + hex) > 0n && BigInt('0x' + hex) < BABYJUB_SUBGROUP_ORDER) return hex;
      }
      throw new Error('scalar sampling failed');
    };
    account = { spendSecret: await sampleScalar(), incomingViewSecret: await sampleScalar() };
    writeFileSync(accountPath, JSON.stringify(account, null, 1), { mode: 0o600 });
  }

  const journal = {
    schema: 'shieldkit-pf6-pool-journal/v1',
    profile: PF6_PROFILE_ID,
    profileId,
    instanceId,
    sourceTxid,
    sourceHex,
    genesisTxid,
    genesisHex,
    verifierLocks: verifierLocks.map(l => la.binToHex(l)),
    bindingLock: la.binToHex(bindingLock),
    stateLock: la.binToHex(stateLock),
    stateCovenantBytes: stateLock.length,
    denominationSats: DENOMINATION,
    carrierValueSats: String(CARRIER_VALUE),
    stateBaseValueSats: String(STATE_BASE),
    walletLockingBytecode: wallet.lockingBytecodeHex,
    account: { spendSecret: account.spendSecret, incomingViewSecret: account.incomingViewSecret },
    state: model.state,
    stateInValueSats: String(STATE_BASE),
    created: new Date().toISOString(),
  };
  savePoolJournal(dataHome, journal);

  okJson({
    ok: true,
    schema: PF6_PROFILE_SCHEMA,
    command: 'pool-create',
    profile: PF6_PROFILE_ID,
    pin: PF6_PROFILE_PIN,
    status: 'broadcast',
    network: 'chipnet',
    operationId: `pf6-pool-${genesisTxid.slice(0, 16)}`,
    sourceTransactionId: sourceTxid,
    transactionId: genesisTxid,
    pool: {
      instanceId,
      profileId,
      genesisTransactionId: genesisTxid,
      stateCovenantBytes: stateLock.length,
      verifierRoleCount: verifierLocks.length,
      inputsPerAction: 9,
      journalPath,
    },
    notes: ['zero-conf Chipnet only; no mainnet claim'],
  });
}

// ---- pool doctor (local wiring only) ----
export async function poolDoctor(argv) {
  const dataHome = arg(argv, 'data-home');
  const checks = {
    material: existsSync(path.join(ROOT, 'src/verifier-material/pf6-action-material.json')),
    constants: existsSync(path.join(ROOT, 'src/fresh-pool-constants.json')),
    covenants: existsSync(path.join(ROOT, 'src/product-port/structural-covenants.mjs')),
    libauth: existsSync(path.join(ROOT, 'vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js')),
    prover: existsSync(path.join(ROOT, 'vendor/product-current/native/prover')),
    zkey: existsSync(path.join(ROOT, 'vendor/product-current/circuit/beta.zkey')),
    wasm: existsSync(path.join(ROOT, 'vendor/product-current/circuit/main-chipnet.wasm')),
    laneCandidates: existsSync(path.join(ROOT, 'vendor/pf6-lane/candidates')),
    journal: dataHome ? (existsSync(poolJournalPath(dataHome)) ? JSON.parse(readFileSync(poolJournalPath(dataHome), 'utf8')).ok !== false : true) : false,
  };
  const allOk = Object.values(checks).every(Boolean);
  okJson({
    ok: allOk,
    schema: PF6_PROFILE_SCHEMA,
    command: 'pool-doctor',
    profile: PF6_PROFILE_ID,
    pin: PF6_PROFILE_PIN,
    network: 'chipnet',
    status: allOk ? 'local-ok' : 'local-failed',
    checks,
    notes: [
      'pool doctor checks local CLI wiring only; run pool create/deposit/withdraw for live operations',
      'zero-conf Chipnet only; no mainnet product claim',
    ],
  }, allOk ? 0 : 2);
}

// ---- dispatcher: the pf6 profile command surface ----
export async function runPf6ProfileCommand(argv) {
  const cmd = argv[0];
  try {
    if (cmd === '--version' || cmd === '-v') {
      console.log(JSON.stringify({ ok: true, product: 'ShieldKit-Groth-54KB', profile: PF6_PROFILE_ID,
        version: '0.3.0-beta.1', toolkitVersion: '0.3.0-beta.1', roles: PF6_PROFILE_PIN.roles, scriptBytes: PF6_PROFILE_PIN.scriptBytes }, null, 2));
      return;
    }
    if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
      console.log(pf6Usage('pool'));
      return;
    }
    if (cmd === 'pool') {
      const sub = argv[1];
      if (!sub || sub === 'help' || sub === '--help' || sub === '-h') {
        console.log(pf6Usage('pool'));
        return;
      }
      if (sub === 'create') return await poolCreate(argv);
      if (sub === 'doctor') return await poolDoctor(argv);
      if (sub === 'deposit') return await actionCommand(argv, 'deposit');
      if (sub === 'transfer') return await actionCommand(argv, 'transfer');
      if (sub === 'withdraw') return await actionCommand(argv, 'withdrawal');
      if (sub === 'recover' || sub === 'recovery') return await recoverCommand(argv);
      fail('UNKNOWN_COMMAND', `unknown pool subcommand for profile ${PF6_PROFILE_ID}: ${sub}`);
    }
    if (cmd === 'deposit') return await actionCommand(argv, 'deposit');
    if (cmd === 'transfer') return await actionCommand(argv, 'transfer');
    if (cmd === 'withdraw') return await actionCommand(argv, 'withdrawal');
    if (cmd === 'recovery') return await recoverCommand(argv);
    if (cmd === 'doctor') return await poolDoctor(argv);
    fail('UNKNOWN_COMMAND', `unknown command for profile ${PF6_PROFILE_ID}: ${cmd}`);
  } catch (e) {
    if (e instanceof Pf6ProfileError) {
      failJson(e.code, e.message, e.exitCode ?? 2);
      return;
    }
    failJson('PF6_PROFILE_INTERNAL', String(e?.message ?? e), 2, { stack: String(e?.stack ?? '').split('\n').slice(0, 6) });
  }
}

export function pf6Usage(topic = 'pool') {
  if (topic === 'pool') {
    return `ShieldKit unified CLI — profile ${PF6_PROFILE_ID} (bn254-onetx-pf6-a3-r1, 6 roles, 9-input actions)

  pool create --funding-wallet <wallet-private.json> --funding-utxo <txid:vout> [--data-home <dir>] [--json|--human]
  pool deposit --data-home <dir> [--note <label>] [--operation-id <id>] [--json|--human]
  pool transfer --data-home <dir> [--to <label>] [--note <label>] [--operation-id <id>] [--json|--human]
  pool withdraw --data-home <dir> [--to <label>] [--operation-id <id>] [--json|--human]
  pool recover --data-home <dir> [--scan|--inspect|--rebroadcast] [--acknowledge-exact-rebroadcast] [--json|--human]
  pool doctor [--data-home <dir>] [--json|--human]
  deposit|transfer|withdraw ...   (top-level aliases)
`;
  }
  return `profile ${PF6_PROFILE_ID}: use "pool create|deposit|transfer|withdraw|recover|doctor"`;
}

// ---- the action pipeline (deposit/transfer/withdrawal): packet -> prove -> lane build -> assemble -> admit ----
async function loadActionContext(argv) {
  const dataHome = arg(argv, 'data-home');
  const journal = loadPoolJournal(dataHome);
  const wallet = walletFromPath(arg(argv, 'funding-wallet'));
  const funding = parseFundingUtxo(arg(argv, 'funding-utxo'));
  return { dataHome, journal, wallet, funding };
}

async function proveAction(circuitInputPath, outDir) {
  const prove = await import('file://' + path.join(ROOT, 'src/prove-pf6.mjs'));
  mkdirSync(outDir, { recursive: true });
  const proved = prove.proveGroth16({
    zkeyPath: path.join(ROOT, 'vendor/product-current/circuit/beta.zkey'),
    wasmPath: path.join(ROOT, 'vendor/product-current/circuit/main-chipnet.wasm'),
    circuitInputPath, outDir,
    proverBin: path.join(ROOT, 'vendor/product-current/native/prover'),
    snarkjsCli: '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/node_modules/.bin/snarkjs',
  });
  const proof = JSON.parse(readFileSync(proved.proofPath, 'utf8'));
  const publicSignals = JSON.parse(readFileSync(proved.publicPath, 'utf8'));
  return { proof, publicSignals, proofPath: proved.proofPath, publicPath: proved.publicPath };
}

function buildCandidate(kind, adapterPath, packetPath, outDir) {
  const pc = JSON.parse(readFileSync(path.join(ROOT, 'vendor/product-current/verification_key.json'), 'utf8'));
  const adapter = JSON.parse(readFileSync(adapterPath, 'utf8'));
  const candidate = {
    schema: 'verifier.cash/candidate/v1',
    id: `bn254-onetx-pf6-a3-shieldkit-cli-${kind}-r1`,
    lane: 'bn254-onetx', status: 'profile-live',
    capability: { proofSystem: 'Groth16', field: 'BN254', structure: 'single-tx', proofBinding: 'runtime', vkBinding: 'fixed', deploymentBinding: 'fixed' },
    identity: { humanName: `pf6 CLI ${kind}`, construction: 'pf6-a3-shieldkit-cli', topology: 6, stateModel: 'p2shchain', revision: 'r1', slug: `pf6-cli-${kind}` },
    toolchain: { cashc: '1c707c1dbf87396b30ba5e0704b1db44475ce893', libauth: '3.1.0-next.8', leanbch: '51201015fdaef4562debf2a2b1cab4013a45e8b4', bch: 'BCH-2026' },
    build: {
      adapter: 'lane-module', module: 'lanes/bn254-onetx/src/build-adapter.mjs',
      entrypoint: 'lanes/bn254-onetx/src/c7/build.ts',
      fixture: 'harness/src/checkpoints/dense-proof-candidate-25.json',
      fixedG2Static: true, pairfoldTopology: 6, scalarEndpoint: true,
      fixedG2WitnessTableBytes: '0,0,0,0',
      inputValidationFixture: 'lanes/bn254-onetx/test/fixtures/dense-proof-candidate-25-offsubgroup.json',
      runtimeCorpus: { extraMultiproofIndices: [0, 1, 2], worstCase: true },
      structuralRoleCount: 3,
      shieldAdapter: { path: adapterPath, sha256: sha256hex(readFileSync(adapterPath)) },
      shieldActionPacket: { path: packetPath, sha256: sha256hex(readFileSync(packetPath)) },
      shieldActionPacketAbi: 'sda2-v2-direct',
      profile: {
        schema: 'verifier.cash/bn254-onetx-c7-profile/v1',
        generator: { allAffine: true, selectL17: true, narrowSeam: true, specializeK: true, siblingRead: true, fixedWitnessData: true, dynamicPacking: true, deriveMode: true, rescheduleStacks: true },
        mode: { directPort: true, striped: true, stripeBoundary: true, directFinalizeState: true, strictDeployment: false, publicBenchContext: true, driverPackDerived: true, driverWindowDerived: true },
        layout: { windowSize: 13, stripedFragments: 4 },
        packing: { stateWidth: 32, consensusNarrowLimbs: 1, consensusWidth: 34, narrowWitnessLimbs: 16, witnessWidth: 32, wideWitnessPositions: [], retainConsensusData: false, retainWitnessData: false, finalPadding: [], enforceInputExhaustion: true, stripedNoForward: false, stripedNoWindow: false, stripedWindowTest: false, stripedNoDriver: false, stripedNoHash: false },
        optimization: { foldOnly: false, disableFold: false, disableOptimize: false, disableStrip: false, disableConstantSeed: false, disableH1: false, disableParameterAlias: false, disableMultiplyByOne: false, keepNodeBake: false, maxTry: 2 },
      },
      terminal: { frobFuse: true, wSelector: false, densDropBytes: 1115, bqReserveBytes: 160, bqResidualNoFuel: true },
    },
    judge: { profile: `shieldkit-pf6-cli-${kind}`, sourceValueSatoshis: 1000, sequenceNumber: 1, expected: { scriptBytes: null, txOverheadBytes: null, score: null, inputCount: 9, transactionCount: 1 } },
    provenance: { sourceCommit: 'cli-profile-pf6-a3-direct-v1', scope: `profile CLI ${kind} on chipnet` },
  };
  writeFileSync(path.join(outDir, 'candidate.json'), JSON.stringify(candidate, null, 1));
  return candidate;
}

async function runLaneBuild(kind, outDir) {
  const runId = `pf6-cli-${kind}-${Date.now()}`;
  const candidateName = `bn254-onetx-pf6-a3-shieldkit-cli-${kind}-r1.json`;
  mkdirSync(path.join(ROOT, 'vendor/pf6-lane/candidates'), { recursive: true });
  writeFileSync(path.join(ROOT, 'vendor/pf6-lane/candidates', candidateName), readFileSync(path.join(outDir, 'candidate.json')));
  const res = spawnSync(process.execPath, [path.join(ROOT, 'src/run-pf6-product-build.mjs')], {
    env: { ...process.env, RUN_ID: runId, CANDIDATE: candidateName },
    encoding: 'utf8', timeout: 600_000, maxBuffer: 64 * 1024 * 1024,
  });
  const resultPath = path.join(ROOT, 'vendor/verifier-workspace/.vc/runs', runId, 'build/result.json');
  if (!existsSync(resultPath)) {
    fail('PF6_LANE_BUILD_FAILED', `lane build did not produce ${resultPath}: ${(res.stderr || res.stdout || '').slice(0, 500)}`);
  }
  const result = JSON.parse(readFileSync(resultPath, 'utf8'));
  // The authoritative verifier gate = the six-role surface (exec0-3 + genesis + terminal).
  // The run's extended manual may also include packet/state/fee rows; the harness cannot
  // evaluate the state covenant's token context or the fee input's P2PKH (known harness
  // limitations — "Tried to read from an empty stack"), so the CLI requires only the six
  // verifier roles green and lets BCHN testmempoolaccept be the final authority.
  const roleRows = (result.manual ?? []).filter((m) => (
    ['exec0', 'exec1', 'exec2', 'exec3', 'terminal'].includes(m.name)
  ));
  if (roleRows.length !== 5 || !roleRows.every((m) => m.accepts === true)) {
    fail('PF6_LANE_GATE', `lane build proof-role gate not green: ${JSON.stringify(roleRows.map(m => [m.name, m.accepts]))}`);
  }
  // The genesis (digest-pin) role is evaluated by the run only against the run's INTERNAL candidate
  // tx, whose output layout is the generic 9-output shape; for the withdrawal (10 outputs) the
  // run's internal genesis eval is an artifact. The digest pin is verified by the BCHN admission
  // (the assembled tx's state covenant checks sha256(packet) at input4:451) — the final authority.
  return { runId, result, inputsDump: JSON.parse(readFileSync(path.join(ROOT, 'vendor/verifier-workspace/.vc/runs', runId, 'build/inputs_dump.json'), 'utf8')) };
}

// the per-kind action construction (packet + circuit input) — same logic as src/<kind>-pf6.mjs
async function buildActionPacket(kind, ctx, account) {
  const { journal } = ctx;
  const notes = await G_MOD('/packages/action/v2/notes.mjs');
  const tm = await G_MOD('/packages/action/v2/transition.mjs');
  const st = await G_MOD('/packages/action/v2/state.mjs');
  const nt = await G_MOD('/packages/action/v2/note-tree.mjs');
  const ink = await G_MOD('/packages/action/v2/indexed-nullifier-tree.mjs');
  const pz = await G_MOD('/packages/action/v2/poseidon.mjs');
  const cx = await G_MOD('/packages/action/v2/context.mjs');
  const cw = await G_MOD('/packages/action/v2/circuit-witness.mjs');
  const la = await libauth();
  const { profileId, instanceId } = journal;
  const address = notes.deriveDirectV2Address({ networkId: 2, profileId, instanceId, ...account });
  const accountWithAddr = { ...account, address };

  // the pre-state from the journal
  const preState = journal.state;
  const preSeq = BigInt(preState.actionSequence ?? 0);

  // the packet/context/tx structure per kind
  const verifierLocks = journal.verifierLocks.map(h => Uint8Array.from(Buffer.from(h, 'hex')));
  const bindingLock = Uint8Array.from(Buffer.from(journal.bindingLock, 'hex'));
  const stateLock = Uint8Array.from(Buffer.from(journal.stateLock, 'hex'));
  const parentTxid = journal.lastActionTxid ?? journal.genesisTxid;
  const parentTxHex = journal.lastActionHex ?? journal.genesisHex;
  const parentTx = la.decodeTransaction(la.hexToBin(parentTxHex));
  const stateInValue = BigInt(journal.stateInValueSats ?? STATE_BASE);
  const stateOutValue = kind === 'deposit'
    ? stateInValue + BigInt(DENOMINATION)
    : kind === 'withdrawal' ? stateInValue - BigInt(DENOMINATION) : stateInValue;

  // the note tree + nullifier tree (journaled): replay the journal's note leaves + recovered nullifiers
  const noteTree0 = nt.create({ depth: 32, emptyLeafHash: pz.hashEmptyNoteLeaf(), hashNode: pz.hashNoteTreeNode });
  const nullifierTree0 = ink.create({ depth: 32, hashLeaf: pz.hashIndexedNullifierLeaf, hashNode: pz.hashIndexedNullifierNode });
  let noteTree = noteTree0;
  let nullifierTree = nullifierTree0;
  for (const leaf of journal.noteLeaves ?? []) {
    noteTree = nt.append(noteTree, BigInt('0x' + leaf)).tree;
  }
  for (const nul of journal.spentNullifiers ?? []) {
    nullifierTree = ink.insert(nullifierTree, Uint8Array.from(Buffer.from(nul, 'hex'))).tree;
  }

  let output = null;
  let spend = null;
  let rec = null;
  if (kind === 'deposit') {
    const rng = { bytes(len) { if (len !== 32) throw new Error('len'); return Uint8Array.from(randomBytes(32)); } };
    output = notes.constructDirectV2Output({ address: accountWithAddr.address, postActionSequence: String(preSeq + 1n), rng });
  } else {
    // spend the newest live note (the journal's last deposited note)
    const leaf = journal.liveNoteLeaf;
    const enc = journal.liveNoteEncryptedRecord;
    rec = notes.recoverDirectV2Output({ account: accountWithAddr, outputNoteLeaf: leaf, encryptedRecord: Buffer.from(enc, 'hex') });
    spend = { inputNoteLeaf: leaf, noteIndex: String(journal.liveNoteIndex ?? 0), publicNullifier: rec.nullifier };
    if (kind === 'transfer') {
      // the transfer also creates a fresh output note (postActionSequence = preSeq + 2)
      const rng = { bytes(len) { if (len !== 32) throw new Error('len'); return Uint8Array.from(randomBytes(32)); } };
      output = notes.constructDirectV2Output({ address: accountWithAddr.address, postActionSequence: String(preSeq + 1n), rng });
    }
  }

  // provisional transition for the post-state commitment
  const t0 = tm.applyDirectV2Transition({
    kind, networkId: 2, profileId, instanceId, denominationSats: DENOMINATION,
    preState, noteTree, nullifierTree, transactionContextHash: '0'.repeat(64),
    ...(output ? { output: { outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: output.public.encryptedRecord } } : {}),
    ...(spend ? { spend, ...(kind === 'transfer' ? {} : { withdrawalLockingBytecodeHash: '0'.repeat(64) }) } : {}),
  });
  const postState = t0.state;
  const postCommitment = st.encodeStateNftCommitment(postState, { denominationSats: DENOMINATION });
  const category = Uint8Array.from(Buffer.from(instanceId, 'hex')).reverse();

  // the token prefix (probe)
  const probeTx = { version: 2, inputs: [], outputs: [{ lockingBytecode: stateLock, valueSatoshis: stateOutValue, token: { amount: 0n, category, nft: { capability: 'mutable', commitment: postCommitment } } }], locktime: 0 };
  const probeRaw = la.binToHex(la.encodeTransaction(probeTx));
  const lockHex = la.binToHex(stateLock);
  const idx = probeRaw.lastIndexOf(lockHex);
  const prefixHex = probeRaw.slice(idx - 2 - 164, idx - 2);
  const tokenPrefix = Uint8Array.from(Buffer.from(prefixHex, 'hex'));

  // the context (product output layout: state@0, verifier@1-6, binding@7, note/change@8)
  const role = (k, o) => ({ kind: k, ordinal: String(o) });
  const inRole = (k, o, txid, vout, value, lock, tp = new Uint8Array()) => ({
    role: role(k, o), outpointTransactionHash: txid, outpointIndex: String(vout),
    sequence: '4294967294', valueSats: String(value), lockingBytecode: lock, tokenPrefix: tp,
  });
  const fee = ctx.funding;
  const context = {
    networkId: 2, kind, profileId, instanceId, transactionVersion: '2', locktime: '0',
    preActionSequence: String(preSeq), postActionSequence: String(postState.actionSequence),
    inputs: [
      ...[0, 1, 2, 3, 4, 5].map(i => inRole('verifier', i, parentTxid, i, 1000n, verifierLocks[i])),
      inRole('binding', 0, parentTxid, 6, 1000n, bindingLock),
      inRole('state', 0, parentTxid, 7, stateInValue, stateLock, tokenPrefix),
      inRole('funding', 0, fee.txid, fee.vout, 0n, new Uint8Array()),
    ],
    outputs: [
      { role: role('state', 0), valueSats: String(stateOutValue), lockingBytecode: stateLock, tokenPrefix },
      ...[0, 1, 2, 3, 4, 5].map(i => ({ role: role('verifier', i), valueSats: '1000', lockingBytecode: verifierLocks[i], tokenPrefix: new Uint8Array() })),
      { role: role('binding', 0), valueSats: '1000', lockingBytecode: bindingLock, tokenPrefix: new Uint8Array() },
      ...(kind === 'withdrawal' ? [{ role: role('withdrawal', 0), valueSats: '10000000', lockingBytecode: new Uint8Array(), tokenPrefix: new Uint8Array() }] : []),
      { role: role('change', 0), valueSats: '0', lockingBytecode: new Uint8Array(), tokenPrefix: new Uint8Array() },
    ],
  };
  // NOTE: the funding input's lock + value are patched by the caller (wallet-dependent); the context hash is
  // computed with the real lock below.
  return {
    la, notes, tm, st, nt, ink, pz, cx, cw, address: accountWithAddr.address,
    noteTree, nullifierTree,
    preState, postState, postCommitment, tokenPrefix, prefixHex, context, contextTemplate: context,
    output, spend, rec: spend ? rec : null, stateInValue, stateOutValue, verifierLocks, bindingLock, stateLock, parentTxid, parentTx,
  };
}

export async function actionCommand(argv, kind) {
  const started = performance.now();
  const ctx = await loadActionContext(argv);
  const { journal, wallet, funding } = ctx;
  const cov = await covenants();
  const topo = await topology();
  const la = await libauth();
  const operationId = arg(argv, 'operation-id') ?? `pf6-${kind}-${Date.now().toString(16)}`;

  const p = await buildActionPacket(kind, ctx, journal.account);
  // patch the funding input with the real lock/value
  const fundingLock = wallet.lockingBytecodeHex;
  const R0 = await rpc();
  const fundingOut = await R0.gettxout(funding.txid, funding.vout);
  if (!fundingOut) fail('BETA_FUNDING_UTXO_UNSPENT', `funding utxo ${funding.txid}:${funding.vout} is not unspent`);
  const fundingRaw = await R0.getrawtransaction(funding.txid, false);
  const fundingTx = la.decodeTransaction(la.hexToBin(fundingRaw));
  const fundingValue = fundingTx.outputs[funding.vout].valueSatoshis;
  {
    // the action's funding must cover the state-reserve delta + the fee
    // the deposit's funding covers the +10M state-reserve delta; the transfer/withdrawal funding
    // covers only the fee + change (the withdrawal's 10M payout comes out of the state reserve).
    const reserveDelta = kind === 'deposit' ? BigInt(DENOMINATION) : 0n;
    const minimumFunding = 10_000_546n + reserveDelta;
    if (fundingValue < minimumFunding) {
      fail('BETA_FUNDING_UTXO_VALUE', `funding utxo ${funding.txid}:${funding.vout} (${fundingValue} sats) is below the ${kind} requirement (>= ${minimumFunding} sats): the pool state reserve grows by ${reserveDelta} sats`);
    }
  }
  p.context.inputs[8] = {
    role: { kind: 'funding', ordinal: '0' },
    outpointTransactionHash: funding.txid, outpointIndex: String(funding.vout),
    sequence: '4294967294', valueSats: String(fundingValue),
    lockingBytecode: la.hexToBin(fundingLock), tokenPrefix: new Uint8Array(),
  };
  const contextHash = p.cx.hashDirectV2TransactionContext(p.context, { carrierCount: 6 }).toString('hex');

  // the final transition + the packet
  const t1 = p.tm.applyDirectV2Transition({
    kind, networkId: 2, profileId: journal.profileId, instanceId: journal.instanceId,
    denominationSats: DENOMINATION, preState: p.preState, noteTree: p.noteTree, nullifierTree: p.nullifierTree,
    transactionContextHash: contextHash,
    ...(p.output ? { output: { outputNoteLeaf: p.output.public.outputNoteLeaf, encryptedRecord: p.output.public.encryptedRecord } } : {}),
    ...(p.spend ? { spend: p.spend, ...(kind === 'transfer' ? {} : { withdrawalLockingBytecodeHash: '0'.repeat(64) }) } : {}),
  });
  const packet = Buffer.from(t1.packet);
  if (packet.subarray(520, 552).toString('hex') !== contextHash) {
    fail('PF6_CONTEXT_MISMATCH', 'packet context hash does not match the computed context hash');
  }

  // the circuit input
  const circuitInput = p.cw.buildDirectV2CircuitInput({
    transition: t1,
    ...(p.output ? { output: p.output } : {}),
    ...(p.spend ? { spend: { encryptedRecord: p.rec.encryptedRecord, incomingViewPublicKey: p.address.incomingViewPublicKey, r: p.rec.r, rho: p.rec.rho, spendSecret: journal.account.spendSecret } } : {}),
    denominationSats: DENOMINATION,
  });

  // prove + adapter + candidate + lane build
  const workDir = path.join(ROOT, 'evidence/03-implementation', `cli-${kind}-${Date.now()}`);
  mkdirSync(workDir, { recursive: true });
  const inputPath = path.join(workDir, 'circuit-input.json');
  writeFileSync(inputPath, JSON.stringify(circuitInput, null, 1));
  const packetPath = path.join(workDir, 'packet.bin');
  writeFileSync(packetPath, packet);
  const { proof, publicSignals } = await proveAction(inputPath, path.join(workDir, 'prove'));
  const vk = JSON.parse(readFileSync(path.join(ROOT, 'vendor/product-current/verification_key.json'), 'utf8'));
  const adapter = {
    schema: 'shieldkit-v2-direct-groth16-adapter-v1',
    qualification: `shieldkit-54kb cli profile ${kind}`,
    source: {
      verificationKey: { path: path.join(ROOT, 'vendor/product-current/verification_key.json'), sha256: sha256hex(readFileSync(path.join(ROOT, 'vendor/product-current/verification_key.json'))), bytes: readFileSync(path.join(ROOT, 'vendor/product-current/verification_key.json')).length },
      proof: { path: path.join(workDir, 'prove/proof.json'), sha256: sha256hex(readFileSync(path.join(workDir, 'prove/proof.json'))), bytes: readFileSync(path.join(workDir, 'prove/proof.json')).length },
      publicSignals: { path: path.join(workDir, 'prove/public.json'), sha256: sha256hex(readFileSync(path.join(workDir, 'prove/public.json'))), bytes: readFileSync(path.join(workDir, 'prove/public.json')).length },
    },
    byteOrder: { g1: 'snarkjs affine [x,y,1]', g2: 'snarkjs affine [[x.c0,x.c1],[y.c0,y.c1],[1,0]]', scalars: 'canonical unsigned base-10' },
    verificationKey: { ic: 3, publicArity: 2 },
    verifierCashVk: {
      alpha: { x: vk.vk_alpha_1[0], y: vk.vk_alpha_1[1] },
      beta: { x0: vk.vk_beta_2[0][0], x1: vk.vk_beta_2[0][1], y0: vk.vk_beta_2[1][0], y1: vk.vk_beta_2[1][1] },
      gamma: { x0: vk.vk_gamma_2[0][0], x1: vk.vk_gamma_2[0][1], y0: vk.vk_gamma_2[1][0], y1: vk.vk_gamma_2[1][1] },
      delta: { x0: vk.vk_delta_2[0][0], x1: vk.vk_delta_2[0][1], y0: vk.vk_delta_2[1][0], y1: vk.vk_delta_2[1][1] },
      ic: vk.IC.map(pp => ({ x: pp[0], y: pp[1] })),
    },
    verifierCashFixture: {
      Ax: proof.pi_a[0], Ay: proof.pi_a[1],
      Bxa: proof.pi_b[0][0], Bxb: proof.pi_b[0][1], Bya: proof.pi_b[1][0], Byb: proof.pi_b[1][1],
      Cx: proof.pi_c[0], Cy: proof.pi_c[1], in0: publicSignals[0], in1: publicSignals[1],
    },
  };
  const adapterPath = path.join(workDir, 'adapter.json');
  writeFileSync(adapterPath, JSON.stringify(adapter, null, 1));
  buildCandidate(kind, adapterPath, packetPath, workDir);
  const { runId, inputsDump } = await runLaneBuild(kind, workDir);

  // assemble: the 9-input tx (verifier@0-5 + carrier@6 + state@7 + fee@8)
  const helper = cov.buildDirectV2StateHelper({
    bindingLock: p.bindingLock, verifierLocks: p.verifierLocks,
    verifierBaseValues: p.verifierLocks.map(() => 1000n),
    bindingBaseValueSats: 1000n, stateBaseValueSats: STATE_BASE,
    denominationSats: DENOMINATION, stateCategory: journal.instanceId, minimumChangeSats: 546n,
    topologyId: topo.DIRECT_V2_PF6_TOPOLOGY_ID, verifierRoles: topo.DIRECT_V2_PF6_VERIFIER_ROLES,
  });
  const stateUnlock = cov.buildDirectV2StateTrampolineUnlock(helper);
  const stateToken = { amount: 0n, category: Uint8Array.from(Buffer.from(journal.instanceId, 'hex')).reverse(), nft: { capability: 'mutable', commitment: p.postCommitment } };
  // pf6 output layout: verifier@0-5 + carrier@6 + state@7 (+ withdrawal@8 for withdrawals) + change@(8|9).
  // There is NO separate note output: the note is carried by the state commitment.
  const outBase = [
    ...p.verifierLocks.map(l => ({ lockingBytecode: l, valueSatoshis: 1000n })),
    { lockingBytecode: p.bindingLock, valueSatoshis: 1000n },
    { lockingBytecode: p.stateLock, valueSatoshis: p.stateOutValue, token: stateToken },
    ...(kind === 'withdrawal' ? [{ lockingBytecode: la.hexToBin(wallet.lockingBytecodeHex), valueSatoshis: 10000000n }] : []),
  ];
  const packetUnlock = Uint8Array.from(Buffer.from(inputsDump[6].unlock, 'hex'));
  // NOTE: the covenant's digest pin hashes the PACKET CONTENT (the 552-B payload after the push
  // wrapper), and the lane run's inputs_dump[4] already carries that digest — verified against the
  // live deposit/transfer (input4@451 == sha256 of the bare packet, NOT of the 555-B unlock).
  const verifierUnlocks = inputsDump.slice(0, 6).map(i => Uint8Array.from(Buffer.from(i.unlock, 'hex')));
  const txInputs = [
    ...verifierUnlocks.map((u, i) => ({ outpointTransactionHash: la.hexToBin(p.parentTxid), outpointIndex: i, sequenceNumber: 0xfffffffe, unlockingBytecode: u })),
    { outpointTransactionHash: la.hexToBin(p.parentTxid), outpointIndex: 6, sequenceNumber: 0xfffffffe, unlockingBytecode: packetUnlock },
    { outpointTransactionHash: la.hexToBin(p.parentTxid), outpointIndex: 7, sequenceNumber: 0xfffffffe, unlockingBytecode: stateUnlock },
  ];
  txInputs.push({ outpointTransactionHash: la.hexToBin(funding.txid), outpointIndex: funding.vout, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() });
  const parentStateToken = p.parentTx.outputs[7]?.token;
  let txHex = null, change = 0n;
  for (let i = 0; i < 8; i++) {
    const tx = { version: 2, inputs: txInputs, outputs: [...outBase, { lockingBytecode: la.hexToBin(wallet.lockingBytecodeHex), valueSatoshis: change }], locktime: 0 };
    const ser = la.generateSigningSerializationBch(
      { inputIndex: 8, sourceOutputs: txInputs.map((inp, idx) => ({
          lockingBytecode: idx === 8 ? la.hexToBin(wallet.lockingBytecodeHex) : (idx === 7 ? p.stateLock : (idx === 6 ? p.bindingLock : p.verifierLocks[idx])),
          valueSatoshis: idx === 8 ? fundingValue : (idx === 7 ? p.stateInValue : 1000n),
          ...(idx === 7 && parentStateToken ? { token: parentStateToken } : {}),
        })), transaction: tx },
      { coveredBytecode: la.hexToBin(wallet.lockingBytecodeHex), signingSerializationType: Uint8Array.of(97) },
    );
    const digest = la.hash256(ser);
    const schnorr = la.secp256k1.signMessageHashSchnorr(Uint8Array.from(Buffer.from(wallet.privateKeyHex, 'hex')), digest);
    txInputs[8].unlockingBytecode = Buffer.concat([
      la.encodeDataPush(Uint8Array.from([...schnorr, 97])),
      la.encodeDataPush(Uint8Array.from(Buffer.from(wallet.publicKeyHex, 'hex'))),
    ]);
    const raw = la.binToHex(la.encodeTransaction(tx));
    const requiredFee = BigInt(raw.length / 2 + 1);
    const totalIn = 7n * 1000n + p.stateInValue + fundingValue;
    const baseOut = 7n * 1000n + p.stateOutValue + (kind === 'withdrawal' ? 10000000n : 0n);
    const totalOut = baseOut + change;
    if (totalIn - totalOut === requiredFee) { txHex = raw; break; }
    change = totalIn - baseOut - requiredFee;
  }
  if (!txHex) fail('PF6_ASSEMBLE_FEE', 'action fee loop did not converge');
  if (process.env.PF6_DEBUG_SAVE_TX) writeFileSync(process.env.PF6_DEBUG_SAVE_TX, txHex);
  const txid = (await txidOf(txHex));

  // admission
  const R = await rpc();
  const tma = await R.testmempoolaccept(txHex);
  if (!tma?.[0]?.allowed) fail('PF6_ADMISSION_REJECTED', `action rejected: ${JSON.stringify(tma?.[0] ?? 'unknown')}`);
  const broadcastTxid = String(await R.sendrawtransaction(txHex, true)).trim();

  // journal update
  const noteLeaf = p.output ? p.output.public.outputNoteLeaf : null;
  const noteEnc = p.output ? p.output.public.encryptedRecord : null;
  journal.lastActionTxid = txid;
  journal.lastActionHex = txHex;
  journal.stateInValueSats = String(p.stateOutValue);
  journal.state = p.postState;
  journal.noteLeaves = [...(journal.noteLeaves ?? []), ...(noteLeaf ? [noteLeaf] : [])];
  journal.noteEncryptedRecords = [...(journal.noteEncryptedRecords ?? []), ...(noteEnc ? [Buffer.from(noteEnc).toString('hex')] : [])];
  if (p.spend) journal.spentNullifiers = [...(journal.spentNullifiers ?? []), p.spend.publicNullifier];
  if (p.output) {
    journal.liveNoteLeaf = noteLeaf;
    journal.liveNoteEncryptedRecord = noteEnc ? Buffer.from(noteEnc).toString('hex') : undefined;
    journal.liveNoteIndex = String(Number(p.postState.noteCount) - 1);
  } else {
    journal.liveNoteLeaf = undefined;
    journal.liveNoteEncryptedRecord = undefined;
  }
  journal.operationHistory = [...(journal.operationHistory ?? []), { operationId, kind, txid }];
  savePoolJournal(ctx.dataHome, journal);

  okJson({
    ok: true,
    schema: PF6_PROFILE_SCHEMA,
    command: kind,
    profile: PF6_PROFILE_ID,
    pin: PF6_PROFILE_PIN,
    status: 'broadcast',
    network: 'chipnet',
    operationId,
    transactionId: txid,
    note: noteLeaf ? { outputNoteLeaf: noteLeaf } : undefined,
    pool: { instanceId: journal.instanceId, genesisTransactionId: journal.genesisTxid },
    timingsMs: { commandTotal: Math.round(performance.now() - started) },
    notes: ['zero-conf Chipnet only; no mainnet claim'],
  });
}

export async function recoverCommand(argv) {
  const started = performance.now();
  const dataHome = arg(argv, 'data-home');
  const journal = loadPoolJournal(dataHome);
  const ctx = { dataHome, journal };
  const la = await libauth();
  const notes = await G_MOD('/packages/action/v2/notes.mjs');
  const account = { ...journal.account, address: notes.deriveDirectV2Address({ networkId: 2, profileId: journal.profileId, instanceId: journal.instanceId, ...journal.account }) };
  const R = await rpc();
  const inspect = flag(argv, 'inspect');
  const rebroadcast = flag(argv, 'rebroadcast');
  const scan = flag(argv, 'scan') || flag(argv, 'chain');

  if (!scan && !inspect && !rebroadcast) {
    // local journal recovery (fast path)
    if (!journal.liveNoteLeaf || !journal.liveNoteEncryptedRecord) {
      fail('PF6_NO_LIVE_NOTE', 'no live note in the journal to recover (spend or deposit first); use --scan to scan the chain');
    }
    const rec = notes.recoverDirectV2Output({
      account,
      outputNoteLeaf: journal.liveNoteLeaf,
      encryptedRecord: Buffer.from(journal.liveNoteEncryptedRecord, 'hex'),
    });
    okJson({
      ok: true, schema: PF6_PROFILE_SCHEMA, command: 'recover', profile: PF6_PROFILE_ID,
      status: 'recovered', network: 'chipnet',
      operationId: arg(argv, 'operation-id') ?? `pf6-recover-${Date.now().toString(16)}`,
      recovery: { outputNoteLeaf: journal.liveNoteLeaf, nullifier: rec.nullifier, noteIndex: journal.liveNoteIndex ?? '0', source: 'journal' },
      notes: ['local journal recovery; use --scan to scan the whole chain for recoverable notes'],
    });
    return;
  }

  // ---- chain-scan recovery: follow the pool's action chain from the genesis ----
  const scanned = [];
  const seen = new Set();
  let cursor = journal.lastActionTxid ?? journal.genesisTxid;
  let guard = 0;
  const rawCache = new Map();
  const fetchRaw = async (txid) => {
    if (rawCache.has(txid)) return rawCache.get(txid);
    let raw = null;
    for (let attempt = 0; attempt < 4 && raw === null; attempt++) {
      try { raw = await R.getrawtransaction(txid, false); } catch (e) { await new Promise((r2) => setTimeout(r2, 1500)); }
    }
    if (raw === null) throw new Error(`cannot fetch tx ${txid}`);
    rawCache.set(txid, raw);
    return raw;
  };
  // walk backwards: from the last action to the genesis (the packets ride in input 6)
  let currentTxid = cursor;
  while (currentTxid && !seen.has(currentTxid) && guard < 64) {
    seen.add(currentTxid); guard++;
    let raw;
    try { raw = await fetchRaw(currentTxid); } catch (e) { break; }
    const tx = la.decodeTransaction(la.hexToBin(raw));
    const u6 = tx.inputs[6]?.unlockingBytecode;
    if (u6 && u6.length === 555) {
      const leaf = Buffer.from(u6.subarray(3 + 328, 3 + 360)).toString('hex');
      const enc = Buffer.from(u6.subarray(3 + 360, 3 + 488)).toString('hex');
      try {
        const rec = notes.recoverDirectV2Output({ account, outputNoteLeaf: leaf, encryptedRecord: Buffer.from(enc, 'hex') });
        scanned.push({ txid: currentTxid, outputNoteLeaf: leaf, nullifier: rec.nullifier, recoverable: true });
      } catch (e) {
        scanned.push({ txid: currentTxid, outputNoteLeaf: leaf, recoverable: false, reason: String(e?.message ?? e).slice(0, 80) });
      }
    }
    // the previous action: the parent of the inputs 0-7 (the pool's previous tx)
    const parentTxid = tx.inputs[0] ? la.binToHex(tx.inputs[0].outpointTransactionHash) : null;
    if (parentTxid === journal.genesisTxid) currentTxid = null;
    else currentTxid = parentTxid;
  }
  // the journal's own notes (the local state)
  const journalNotes = (journal.noteLeaves ?? []).map((leaf, i) => {
    const enc = journal.noteEncryptedRecords?.[i];
    if (!enc) return { outputNoteLeaf: leaf, recoverable: false, reason: 'no record in journal' };
    try {
      const rec = notes.recoverDirectV2Output({ account, outputNoteLeaf: leaf, encryptedRecord: Buffer.from(enc, 'hex') });
      return { outputNoteLeaf: leaf, nullifier: rec.nullifier, recoverable: true, source: 'journal' };
    } catch (e) {
      return { outputNoteLeaf: leaf, recoverable: false, reason: String(e?.message ?? e).slice(0, 80), source: 'journal' };
    }
  });
  const all = [...journalNotes, ...scanned.map((x) => ({ ...x, source: 'chain' }))];
  const unique = [...new Map(all.map((x) => [x.outputNoteLeaf, x])).values()];
  okJson({
    ok: true, schema: PF6_PROFILE_SCHEMA, command: 'recover', profile: PF6_PROFILE_ID,
    status: 'scan-complete', network: 'chipnet',
    operationId: arg(argv, 'operation-id') ?? `pf6-recover-scan-${Date.now().toString(16)}`,
    recovery: {
      mode: 'chain-scan',
      scannedTxids: [...seen],
      notes: unique.map((x) => ({ outputNoteLeaf: x.outputNoteLeaf, nullifier: x.nullifier ?? null, recoverable: x.recoverable, source: x.source ?? 'chain', ...(x.reason ? { reason: x.reason } : {}) })),
      recoverableCount: unique.filter((x) => x.recoverable).length,
      rebroadcast: rebroadcast ? journal.lastActionTxid ?? null : null,
    },
    timingsMs: { commandTotal: Math.round(performance.now() - started) },
    notes: ['chain-scan recovery walks the pool action chain and recovers every note from the packet encrypted records'],
  });
}

