// Phase D: prove -> adapter -> pf6 lane build -> 9-input deposit assembly -> sign.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';

const FOLDER = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb';
const G = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth';
const CUSTODY = '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const libauthUrl = 'file://' + FOLDER + '/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js';
const la = await import(libauthUrl);
const { hexToBin, binToHex, encodeTransaction, generateSigningSerializationBch, hash256, secp256k1, encodeDataPush } = la;

const prove = await import('file://' + path.join(FOLDER, 'src/prove-pf6.mjs'));
const pc = JSON.parse(readFileSync(path.join(FOLDER, 'vendor/product-current', 'verification_key.json'), 'utf8'));
const wallet = JSON.parse(readFileSync(path.join(CUSTODY, 'wallet-private.json'), 'utf8'));
const priv = Uint8Array.from(Buffer.from(wallet.privateKeyHex, 'hex'));
const pubHex = wallet.publicKeyHex;
const hotLock = wallet.lockingBytecodeHex;

const gen = JSON.parse(readFileSync('/tmp/pf6-genesis.json', 'utf8'));
const feeUtxo = JSON.parse(readFileSync('/tmp/pf6-fee-utxo.json', 'utf8'));
const constants = JSON.parse(readFileSync(path.join(FOLDER, 'src/fresh-pool-constants.json'), 'utf8'));
const postState = JSON.parse(readFileSync('/tmp/pf6-poststate.json', 'utf8'));

const DENOMINATION = '10000000';
const stateBase = 2500n;
const carrierValue = 1200n;
const stateOutValue = stateBase + 10_000_000n;

// ---- 1) prove ----
const outDir = path.join(FOLDER, 'evidence/03-implementation/deposit-prove');
mkdirSync(outDir, { recursive: true });
const proved = prove.proveGroth16({
  zkeyPath: path.join(FOLDER, 'vendor/product-current/circuit/beta.zkey'),
  wasmPath: path.join(FOLDER, 'vendor/product-current/circuit/main-chipnet.wasm'),
  circuitInputPath: '/tmp/pf6-deposit-input.json',
  outDir,
  proverBin: path.join(FOLDER, 'vendor/product-current/native/prover'),
  snarkjsCli: '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/node_modules/.bin/snarkjs',
});
const proof = JSON.parse(readFileSync(proved.proofPath, 'utf8'));
const publicSignals = JSON.parse(readFileSync(proved.publicPath, 'utf8'));
console.log('proof ok | public:', publicSignals.map(String).join(',').slice(0, 40));

// ---- 2) adapter ----
const vk = {
  alpha: { x: pc.vk_alpha_1[0], y: pc.vk_alpha_1[1] },
  beta: { x0: pc.vk_beta_2[0][0], x1: pc.vk_beta_2[0][1], y0: pc.vk_beta_2[1][0], y1: pc.vk_beta_2[1][1] },
  gamma: { x0: pc.vk_gamma_2[0][0], x1: pc.vk_gamma_2[0][1], y0: pc.vk_gamma_2[1][0], y1: pc.vk_gamma_2[1][1] },
  delta: { x0: pc.vk_delta_2[0][0], x1: pc.vk_delta_2[0][1], y0: pc.vk_delta_2[1][0], y1: pc.vk_delta_2[1][1] },
  ic: pc.IC.map((p) => ({ x: p[0], y: p[1] })),
};
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const adapter = {
  schema: 'shieldkit-v2-direct-groth16-adapter-v1',
  qualification: 'shieldkit-54kb live pf6 deposit; VK d38f3cfc; packet bound via genesis offset 451',
  source: {
    verificationKey: { path: path.join(FOLDER, 'vendor/product-current/verification_key.json'), sha256: sha(path.join(FOLDER, 'vendor/product-current/verification_key.json')), bytes: 2765 },
    proof: { path: proved.proofPath, sha256: sha(proved.proofPath), bytes: readFileSync(proved.proofPath).length },
    publicSignals: { path: proved.publicPath, sha256: sha(proved.publicPath), bytes: readFileSync(proved.publicPath).length },
  },
  byteOrder: {
    g1: 'snarkjs affine [x,y,1] maps directly to Ax/Ay and Cx/Cy',
    g2: 'snarkjs affine [[x.c0,x.c1],[y.c0,y.c1],[1,0]] maps directly to Bxa/Bxb/Bya/Byb; no component reversal',
    scalars: 'canonical unsigned base-10 JSON strings',
  },
  verificationKey: { ic: 3, publicArity: 2 },
  verifierCashVk: vk,
  verifierCashFixture: {
    Ax: proof.pi_a[0], Ay: proof.pi_a[1],
    Bxa: proof.pi_b[0][0], Bxb: proof.pi_b[0][1], Bya: proof.pi_b[1][0], Byb: proof.pi_b[1][1],
    Cx: proof.pi_c[0], Cy: proof.pi_c[1],
    in0: publicSignals[0], in1: publicSignals[1],
  },
};
writeFileSync('/tmp/pf6-deposit-adapter.json', JSON.stringify(adapter, null, 1));
console.log('adapter written');

// ---- 3) pf6 lane build (structural, deposit action) ----
const candidate = {
  schema: 'verifier.cash/candidate/v1',
  id: 'bn254-onetx-pf6-a3-shieldkit-deposit-r1',
  lane: 'bn254-onetx',
  status: 'live-deposit',
  capability: { proofSystem: 'Groth16', field: 'BN254', structure: 'single-tx', proofBinding: 'runtime', vkBinding: 'fixed', deploymentBinding: 'fixed' },
  identity: { humanName: 'pf6 live deposit', construction: 'pf6-a3-shieldkit-deposit', topology: 6, stateModel: 'p2shchain', revision: 'r1', slug: 'pf6-deposit' },
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
    shieldAdapter: { path: '/tmp/pf6-deposit-adapter.json', sha256: sha('/tmp/pf6-deposit-adapter.json') },
    shieldActionPacket: { path: '/tmp/pf6-deposit-packet.bin', sha256: sha('/tmp/pf6-deposit-packet.bin') },
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
  judge: { profile: 'shieldkit-pf6-live-deposit', sourceValueSatoshis: 1000, sequenceNumber: 1, expected: { scriptBytes: null, txOverheadBytes: null, score: null, inputCount: 9, transactionCount: 1 } },
  provenance: { sourceCommit: 'current-worktree', scope: 'live pf6 deposit on chipnet; pool instance ' + gen.instanceId.slice(0, 16) },
};
mkdirSync('/tmp/pf6-deposit-run', { recursive: true });
writeFileSync('/tmp/pf6-deposit-run/candidate.json', JSON.stringify(candidate, null, 1));
console.log('candidate written — invoking lane build next (separate step)');
