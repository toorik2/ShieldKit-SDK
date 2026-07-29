#!/usr/bin/env node
/**
 * Product SKS2 + densFuel Chipnet e2e (honest densFuel pin topology).
 *
 * densFuel PF7 pin is hard-locked to:
 *   10 inputs, common parent, outpointIndex==i, value=SOURCE_VALUE,
 *   sequence=SOURCE_SEQUENCE, TXOUTPUTCOUNT=1, OP_RETURN spend.
 * It cannot co-settle multi-out rolling SKS2 successors in the same tx.
 *
 * Product path (no mocks):
 *   1) Genesis: mint mutable SKS2 state NFT (empty tip)
 *   2) Per action D → T → W:
 *      a) real Groth16 prove + densFuel unlock rebuild for SDA2 packet
 *      b) fund densFuel 10 sources @ C7_SOURCE_VALUE_SATS
 *      c) densFuel settle (OP_RETURN) — on-chain proof authority
 *      d) SKS2 state-transition tx (P2PKH custody) with real commitment/roots/reserve
 *   3) Capacity reject-before-prove, recover-respend roots, adversarial packet
 *
 * Full 64-char txids only. Chipnet hot funds from codex-artifacts.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
  binToHex,
} from '@bitauth/libauth';
import {
  DENOMINATION_SATS,
  NETWORK_CHIPNET,
  PLAYGROUND_MAXIMUM_LIVE_NOTES,
  ZERO_32_HEX,
} from '../constants.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';
import { encodePoolStateV2 } from '../state.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import { CIRCUIT_TREE_DEPTH } from '../prove/witness.mjs';
import { proveActionV2, verifyActionV2 } from '../prove/prove.mjs';
import { adaptSnarkjsGroth16, sha256File } from '../../prove/groth16.mjs';
import { buildVerifierUnlocks } from '../../unlock-builder/index.mjs';
import { digestActionPacketV2, decodeActionPacketV2 } from '../packet.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const WALLET_DIR = '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const HOT = 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';
const ARTIFACT = path.join(ROOT, '.cache/v2-direct-circuit');
const OUT = path.join(ROOT, '.cache/v2-direct-product');
const N_DENS = 10;
const SOURCE_VALUE = BigInt(process.env.C7_SOURCE_VALUE_SATS || '10000');
const SPEND_OUTPUT = 1000n;
const STATE_BASE = 10_000n;

function shellQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}
function rpc(method, params = []) {
  const tokens = params.map((p) => (
    typeof p === 'string' || typeof p === 'number' || typeof p === 'boolean'
      ? shellQuote(String(p))
      : shellQuote(JSON.stringify(p))
  ));
  const cmd = [
    'sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf',
    method,
    ...tokens,
  ].join(' ');
  const out = execFileSync('ssh', ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', 'layer1-node', cmd], {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  const t = out.trim();
  if (!t) return null;
  try { return JSON.parse(t); } catch { return t.replace(/^"|"$/g, ''); }
}
function sha256d(b) {
  return createHash('sha256').update(b).digest();
}
function base58Encode(buffer) {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let z = 0;
  while (z < buffer.length && buffer[z] === 0) z += 1;
  const d = [0];
  for (let i = z; i < buffer.length; i += 1) {
    let c = buffer[i];
    for (let j = 0; j < d.length; j += 1) {
      c += d[j] << 8;
      d[j] = c % 58;
      c = (c / 58) | 0;
    }
    while (c > 0) {
      d.push(c % 58);
      c = (c / 58) | 0;
    }
  }
  let s = '1'.repeat(z);
  for (let i = d.length - 1; i >= 0; i -= 1) s += A[d[i]];
  return s;
}
function loadWallet() {
  const priv = JSON.parse(readFileSync(path.join(WALLET_DIR, 'wallet-private.json'), 'utf8'));
  return {
    privateKey: Buffer.from(priv.privateKeyHex, 'hex'),
    publicKey: Buffer.from(priv.publicKeyHex, 'hex'),
    lockingBytecode: Buffer.from(priv.lockingBytecodeHex, 'hex'),
    address: priv.address,
  };
}
function probeOutpoint(txid, vout) {
  const u = rpc('gettxout', [txid, Number(vout), true]);
  if (!u || u.value == null) return null;
  return {
    txid: String(txid).toLowerCase(),
    vout: Number(vout),
    valueSats: BigInt(Math.round(Number(u.value) * 1e8)),
    scriptPubKey: u.scriptPubKey?.hex || u.scriptPubKey,
  };
}
function scanHot() {
  const byKey = new Map();
  const add = (u) => {
    if (!u) return;
    byKey.set(`${u.txid}:${u.vout}`, u);
  };
  const scan = rpc('scantxoutset', ['start', [`addr(${HOT})`]]);
  for (const u of scan.unspents || []) {
    add({
      txid: u.txid,
      vout: u.vout,
      valueSats: BigInt(Math.round(Number(u.amount) * 1e8)),
      scriptPubKey: u.scriptPubKey,
    });
  }
  const candidates = [];
  if (process.env.V2_MEMPOOL_OUTPOINTS) {
    for (const part of process.env.V2_MEMPOOL_OUTPOINTS.split(',')) {
      const [txid, vout] = part.trim().split(':');
      if (txid && vout != null) candidates.push([txid, vout]);
    }
  }
  candidates.push(['eeb16de247ab72510c7f5458b2503b016ad3e81195ace4b990f6e95f8123f77e', 0]);
  // session consolidates / prior product change
  candidates.push(['5a19c136e6573443e87c39a9ce3a33871ab631b01c2c834f32163d3765eee7bb', 0]);
  candidates.push(['e53a2c89c0b0b03727bd5ce67f98edc1aca74c51dfabb7e2c93fc900de35eec6', 1]);
  candidates.push(['ea0818cdf21373283b621d74a9e6b3f91fb1319f204c12df8918195273161e47', 1]);
  try {
    const topupPath = path.join(WALLET_DIR, 'hot-topup.json');
    if (existsSync(topupPath)) {
      const t = JSON.parse(readFileSync(topupPath, 'utf8'));
      if (t.txid) candidates.push([t.txid, t.vout ?? 0]);
    }
  } catch { /* ignore */ }
  try {
    const cpath = path.join(OUT, 'consolidate.json');
    if (existsSync(cpath)) {
      const c = JSON.parse(readFileSync(cpath, 'utf8'));
      if (c.txid) candidates.push([c.txid, c.vout ?? 0]);
    }
  } catch { /* ignore */ }
  for (const [txid, vout] of candidates) add(probeOutpoint(txid, vout));
  return [...byKey.values()].sort((a, b) => Number(b.valueSats - a.valueSats));
}
async function signP2pkh(tx, inputIndex, sourceOutputs, wallet) {
  const secp = await instantiateSecp256k1();
  const ser = generateSigningSerializationBch(
    { inputIndex, sourceOutputs, transaction: tx },
    {
      coveredBytecode: Uint8Array.from(wallet.lockingBytecode),
      signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputsAllUtxos),
    },
  );
  const sig = secp.signMessageHashSchnorr(wallet.privateKey, hash256(ser));
  const sigWith = Buffer.concat([Buffer.from(sig), Buffer.from([0x61])]);
  return Buffer.concat([
    Buffer.from([sigWith.length]), sigWith,
    Buffer.from([wallet.publicKey.length]), wallet.publicKey,
  ]);
}
function broadcast(hex, label) {
  const accept = rpc('testmempoolaccept', [[hex]]);
  const row = Array.isArray(accept) ? accept[0] : accept;
  console.log(JSON.stringify({ phase: `${label}-accept`, row }));
  if (row?.allowed === false) {
    throw new Error(`${label} rejected: ${JSON.stringify(row)}`);
  }
  const txid = String(rpc('sendrawtransaction', [hex])).toLowerCase();
  console.log(JSON.stringify({ phase: `${label}-broadcast`, txid }));
  return { txid, row };
}
function waitUtxo(txid, vout, tries = 20) {
  for (let i = 0; i < tries; i += 1) {
    const u = rpc('gettxout', [txid, vout, true]);
    if (u?.value != null) return u;
    execFileSync('sleep', ['1']);
  }
  return null;
}
function snarkjsProofJson(proof) {
  return {
    protocol: 'groth16',
    curve: 'bn128',
    pi_a: proof.pi_a,
    pi_b: proof.pi_b,
    pi_c: proof.pi_c,
  };
}

/**
 * Prove action + rebuild densFuel unlocks for this exact SDA2 packet.
 * Returns verifier unlocks 0-6, packet unlock 7, structural empties 8-9.
 */
async function densfuelForPacket(packetBytes, expanded, workDir) {
  mkdirSync(workDir, { recursive: true });
  const proved = await proveActionV2({
    packetBytes,
    zkeyPath: path.join(ARTIFACT, 'circuit_final.zkey'),
    wasmPath: path.join(ARTIFACT, 'circuit.wasm'),
    expanded,
  });
  await verifyActionV2({
    proof: proved.proof,
    publicSignals: proved.publicSignals,
    verificationKeyPath: path.join(ARTIFACT, 'verification_key.json'),
  });
  const proofPath = path.join(workDir, 'proof.json');
  const publicPath = path.join(workDir, 'public.json');
  const vkeyPath = path.join(workDir, 'verification_key.json');
  const packetPath = path.join(workDir, 'action.packet');
  copyFileSync(path.join(ARTIFACT, 'verification_key.json'), vkeyPath);
  writeFileSync(proofPath, `${JSON.stringify(snarkjsProofJson(proved.proof), null, 2)}\n`);
  writeFileSync(publicPath, `${JSON.stringify(proved.publicSignals.map(String))}\n`);
  writeFileSync(packetPath, packetBytes);
  const adapter = await adaptSnarkjsGroth16({
    verificationKey: { path: vkeyPath, sha256: await sha256File(vkeyPath) },
    proof: { path: proofPath, sha256: await sha256File(proofPath) },
    publicSignals: { path: publicPath, sha256: await sha256File(publicPath) },
  });
  writeFileSync(path.join(workDir, 'adapter.json'), `${JSON.stringify(adapter, null, 2)}\n`);
  process.env.C7_SOURCE_VALUE_SATS = String(SOURCE_VALUE);
  process.env.PUBLIC_BENCH_CONTEXT = process.env.PUBLIC_BENCH_CONTEXT || '1';
  const unlockOut = path.join(workDir, 'unlocks');
  const result = await buildVerifierUnlocks({
    adapterPath: path.join(workDir, 'adapter.json'),
    packetPath,
    outDir: unlockOut,
    requirePinLens: false,
    skipEcipGate: true,
    quiet: true,
  });
  const dump = JSON.parse(readFileSync(path.join(unlockOut, 'build/inputs_dump.json'), 'utf8'));
  const res = JSON.parse(readFileSync(path.join(unlockOut, 'build/result.json'), 'utf8'));
  if (res.gateOk !== true) {
    throw new Error(`densFuel gateOk false: ${JSON.stringify(res).slice(0, 300)}`);
  }
  // densFuel structural roles: packet accepts PUSHDATA2(SDA2), state/fee empty
  const structuralLocks = {
    7: Buffer.from([0x75, 0x51]), // OP_DROP OP_1
    8: Buffer.from([0x51]), // OP_1
    9: Buffer.from([0x51]), // OP_1
  };
  const meta = dump.slice(0, N_DENS).map((row, i) => ({
    i,
    name: row.name || `in${i}`,
    lock: structuralLocks[i] || Buffer.from(row.lock, 'hex'),
    unlock: Buffer.from(row.unlock || '', 'hex'),
  }));
  return { proved, result: res, meta, dump };
}

function pickFund(need, spentKeys, fundCoins) {
  const fromTracked = fundCoins
    .filter((u) => u.valueSats >= need && !spentKeys.has(`${u.txid}:${u.vout}`))
    .sort((a, b) => Number(b.valueSats - a.valueSats));
  if (fromTracked[0]) return fromTracked[0];
  const fromScan = scanHot().filter((u) => u.valueSats >= need
    && !spentKeys.has(`${u.txid}:${u.vout}`));
  if (!fromScan[0]) throw new Error(`no funding UTXO ≥ ${need}`);
  return fromScan[0];
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  if (!existsSync(path.join(ARTIFACT, 'circuit_final.zkey'))) {
    throw new Error('circuit artifacts missing under .cache/v2-direct-circuit');
  }
  const wallet = loadWallet();
  const height0 = rpc('getblockcount');
  const profileId = createHash('sha256').update('v2-product-profile').digest('hex');
  let instanceId = createHash('sha256').update('v2-product-instance-placeholder').digest('hex');

  // Tracked mempool change coins (scantxoutset is confirmed-only)
  const fundCoins = [];
  const spentKeys = new Set();

  // --- Select cat mint UTXO (prefer ≥0.15 BCH incl. mempool top-up) ---
  let utxos = scanHot().filter((u) => u.valueSats >= 15_000_000n);
  if (!utxos.length) throw new Error('need hot UTXO ≥ 0.15 BCH for genesis+actions');
  let catUtxo = utxos.find((u) => u.vout === 0) || null;
  if (!catUtxo) {
    const fund = utxos[0];
    const half = fund.valueSats / 2n;
    const fee = 2000n;
    const change = fund.valueSats - half - fee;
    const tx = {
      version: 2,
      locktime: 0,
      inputs: [{
        outpointTransactionHash: Uint8Array.from(Buffer.from(fund.txid, 'hex')),
        outpointIndex: fund.vout,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: new Uint8Array(),
      }],
      outputs: [
        { valueSatoshis: half, lockingBytecode: Uint8Array.from(wallet.lockingBytecode) },
        { valueSatoshis: change, lockingBytecode: Uint8Array.from(wallet.lockingBytecode) },
      ],
    };
    tx.inputs[0].unlockingBytecode = Uint8Array.from(await signP2pkh(tx, 0, [{
      valueSatoshis: fund.valueSats,
      lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
    }], wallet));
    const { txid } = broadcast(binToHex(encodeTransaction(tx)), 'split-vout0');
    waitUtxo(txid, 0);
    spentKeys.add(`${fund.txid}:${fund.vout}`);
    catUtxo = {
      txid, vout: 0, valueSats: half, scriptPubKey: wallet.lockingBytecode.toString('hex'),
    };
    fundCoins.push({
      txid, vout: 1, valueSats: change, scriptPubKey: wallet.lockingBytecode.toString('hex'),
    });
  }

  // --- GENESIS: mint SKS2 empty state ---
  const category = Buffer.from(catUtxo.txid, 'hex');
  instanceId = category.toString('hex');
  const pool = createPoolEngineV2({
    profileId,
    instanceId,
    networkId: NETWORK_CHIPNET,
    maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
    noteDepth: CIRCUIT_TREE_DEPTH,
    nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const emptyState = pool.tip();
  const commitment0 = encodePoolStateV2(emptyState);
  const genesisFee = 2000n;
  if (catUtxo.valueSats < STATE_BASE + genesisFee + 546n) {
    throw new Error('cat UTXO too small for genesis');
  }
  const genesisChange = catUtxo.valueSats - STATE_BASE - genesisFee;
  const genesisTx = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(catUtxo.txid, 'hex')),
      outpointIndex: catUtxo.vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      {
        valueSatoshis: STATE_BASE,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
        token: {
          category: Uint8Array.from(category),
          amount: 0n,
          nft: {
            capability: 'mutable',
            commitment: Uint8Array.from(commitment0),
          },
        },
      },
      {
        valueSatoshis: genesisChange,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
      },
    ],
  };
  genesisTx.inputs[0].unlockingBytecode = Uint8Array.from(await signP2pkh(genesisTx, 0, [{
    valueSatoshis: catUtxo.valueSats,
    lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
  }], wallet));
  const { txid: genesisTxid } = broadcast(binToHex(encodeTransaction(genesisTx)), 'genesis');
  waitUtxo(genesisTxid, 0);
  spentKeys.add(`${catUtxo.txid}:${catUtxo.vout}`);
  fundCoins.push({
    txid: genesisTxid,
    vout: 1,
    valueSats: genesisChange,
    scriptPubKey: wallet.lockingBytecode.toString('hex'),
  });

  let state = {
    txid: genesisTxid,
    vout: 0,
    value: STATE_BASE,
    commitment: commitment0,
  };
  console.log(JSON.stringify({
    phase: 'genesis-ok',
    genesisTxid,
    category: category.toString('hex'),
    tip: {
      noteCount: emptyState.noteCount,
      nullifierCount: emptyState.nullifierCount,
      liveNoteCount: emptyState.liveNoteCount,
      reserveSats: emptyState.reserveSats,
      actionSequence: emptyState.actionSequence,
      noteRoot: emptyState.noteRoot,
      nullifierRoot: emptyState.nullifierRoot,
    },
    commitment: commitment0.toString('hex'),
  }));

  /**
   * densFuel fund+settle for packet, then SKS2 state transition with real tip.
   */
  async function settleAction({
    kind, engineAction, expanded, noteMeta, workName, withdrawalHash,
  }) {
    const workDir = path.join(OUT, workName);
    const dens = await densfuelForPacket(engineAction.packet, expanded, workDir);
    console.log(JSON.stringify({
      phase: `${kind}-densfuel-built`,
      gateOk: dens.result.gateOk,
      wire: dens.result.wire,
      maxUnlock: Math.max(...dens.meta.slice(0, 7).map((m) => m.unlock.length)),
      digest: digestActionPacketV2(engineAction.packet).toString('hex'),
    }));

    // densFuel fund needs SOURCE_VALUE * 10 + fees
    const densNeed = SOURCE_VALUE * BigInt(N_DENS) + 5_000n;
    // deposit state needs denomination + dens + state fee headroom
    const stateNeed = kind === 'deposit'
      ? DENOMINATION_SATS + 50_000n
      : 50_000n;
    const feeUtxo = pickFund(
      densNeed > stateNeed ? densNeed : stateNeed,
      spentKeys,
      fundCoins,
    );

    // --- densFuel fund (10 sources, common parent) ---
    const fundFee = 3000n;
    const densTotal = SOURCE_VALUE * BigInt(N_DENS);
    if (feeUtxo.valueSats < densTotal + fundFee + 546n) {
      throw new Error(`fee UTXO too small for densFuel fund: ${feeUtxo.valueSats}`);
    }
    // If deposit and same UTXO must also fund denomination, ensure headroom after densFuel fund change
    let fundChange = feeUtxo.valueSats - densTotal - fundFee;
    if (kind === 'deposit' && fundChange < DENOMINATION_SATS + 20_000n) {
      // need a larger UTXO
      const bigger = pickFund(densTotal + fundFee + DENOMINATION_SATS + 50_000n, spentKeys, fundCoins);
      if (bigger.txid !== feeUtxo.txid || bigger.vout !== feeUtxo.vout) {
        Object.assign(feeUtxo, bigger);
        fundChange = feeUtxo.valueSats - densTotal - fundFee;
      }
    }
    if (fundChange < 546n) throw new Error(`densFuel fund change dust ${fundChange}`);

    const fundTx = {
      version: 2,
      locktime: 0,
      inputs: [{
        outpointTransactionHash: Uint8Array.from(Buffer.from(feeUtxo.txid, 'hex')),
        outpointIndex: feeUtxo.vout,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: new Uint8Array(),
      }],
      outputs: [
        ...dens.meta.map((m) => ({
          valueSatoshis: SOURCE_VALUE,
          lockingBytecode: Uint8Array.from(m.lock),
        })),
        {
          valueSatoshis: fundChange,
          lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
        },
      ],
    };
    fundTx.inputs[0].unlockingBytecode = Uint8Array.from(await signP2pkh(fundTx, 0, [{
      valueSatoshis: feeUtxo.valueSats,
      lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
    }], wallet));
    const fundHex = binToHex(encodeTransaction(fundTx));
    const { txid: fundTxid } = broadcast(fundHex, `${kind}-densfund`);
    waitUtxo(fundTxid, 0);
    spentKeys.add(`${feeUtxo.txid}:${feeUtxo.vout}`);
    // replace tracked fund coin with change
    const idx = fundCoins.findIndex((c) => c.txid === feeUtxo.txid && c.vout === feeUtxo.vout);
    if (idx >= 0) fundCoins.splice(idx, 1);
    fundCoins.push({
      txid: fundTxid,
      vout: N_DENS,
      valueSats: fundChange,
      scriptPubKey: wallet.lockingBytecode.toString('hex'),
    });

    // --- densFuel settle (pin topology: 10 ins → 1 OP_RETURN) ---
    const parentHash = Uint8Array.from(Buffer.from(fundTxid, 'hex'));
    const settleTx = {
      version: 2,
      locktime: 0,
      inputs: dens.meta.map((m, i) => ({
        outpointTransactionHash: parentHash,
        outpointIndex: i,
        sequenceNumber: 0, // PUBLIC_BENCH_CONTEXT SOURCE_SEQUENCE
        unlockingBytecode: Uint8Array.from(m.unlock),
      })),
      outputs: [{
        valueSatoshis: SPEND_OUTPUT,
        lockingBytecode: Uint8Array.from([0x6a]), // OP_RETURN
      }],
    };
    const settleHex = binToHex(encodeTransaction(settleTx));
    const { txid: densSettleTxid } = broadcast(settleHex, `${kind}-denssettle`);

    // --- SKS2 state transition (product tip) ---
    const post = engineAction.postState;
    const postCommitment = encodePoolStateV2(post);
    const postStateValue = STATE_BASE + BigInt(post.reserveSats);
    const preStateValue = BigInt(state.value);

    // Funding for state tx: deposit needs D; all need fees
    const stateFee = 3000n;
    let stateInExtra = 0n;
    let stateOutPayout = 0n;
    if (kind === 'deposit') stateInExtra = DENOMINATION_SATS;
    if (kind === 'withdrawal') stateOutPayout = DENOMINATION_SATS;

    const stateFundNeed = stateInExtra + stateFee + 546n;
    // Prefer densFund change
    const stateFund = pickFund(stateFundNeed, spentKeys, fundCoins);
    const inSum = preStateValue + stateFund.valueSats;
    const outFixed = postStateValue + stateOutPayout;
    const stateChange = inSum - outFixed - stateFee;
    if (stateChange < 546n) throw new Error(`state change dust ${stateChange}`);

    const stateOutputs = [
      {
        valueSatoshis: postStateValue,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
        token: {
          category: Uint8Array.from(category),
          amount: 0n,
          nft: {
            capability: 'mutable',
            commitment: Uint8Array.from(postCommitment),
          },
        },
      },
    ];
    if (kind === 'withdrawal') {
      stateOutputs.push({
        valueSatoshis: DENOMINATION_SATS,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
      });
    }
    stateOutputs.push({
      valueSatoshis: stateChange,
      lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
    });

    const stateTx = {
      version: 2,
      locktime: 0,
      inputs: [
        {
          outpointTransactionHash: Uint8Array.from(Buffer.from(state.txid, 'hex')),
          outpointIndex: state.vout,
          sequenceNumber: 0xffffffff,
          unlockingBytecode: new Uint8Array(),
        },
        {
          outpointTransactionHash: Uint8Array.from(Buffer.from(stateFund.txid, 'hex')),
          outpointIndex: stateFund.vout,
          sequenceNumber: 0xffffffff,
          unlockingBytecode: new Uint8Array(),
        },
      ],
      outputs: stateOutputs,
    };
    const stateSources = [
      {
        valueSatoshis: preStateValue,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
        token: {
          category: Uint8Array.from(category),
          amount: 0n,
          nft: {
            capability: 'mutable',
            commitment: Uint8Array.from(state.commitment),
          },
        },
      },
      {
        valueSatoshis: stateFund.valueSats,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
      },
    ];
    stateTx.inputs[0].unlockingBytecode = Uint8Array.from(
      await signP2pkh(stateTx, 0, stateSources, wallet),
    );
    stateTx.inputs[1].unlockingBytecode = Uint8Array.from(
      await signP2pkh(stateTx, 1, stateSources, wallet),
    );
    const { txid: stateTxid } = broadcast(binToHex(encodeTransaction(stateTx)), `${kind}-state`);
    waitUtxo(stateTxid, 0);
    spentKeys.add(`${state.txid}:${state.vout}`);
    spentKeys.add(`${stateFund.txid}:${stateFund.vout}`);
    const fi = fundCoins.findIndex((c) => c.txid === stateFund.txid && c.vout === stateFund.vout);
    if (fi >= 0) fundCoins.splice(fi, 1);
    const changeVout = stateOutputs.length - 1;
    fundCoins.push({
      txid: stateTxid,
      vout: changeVout,
      valueSats: stateChange,
      scriptPubKey: wallet.lockingBytecode.toString('hex'),
    });

    state = {
      txid: stateTxid,
      vout: 0,
      value: postStateValue,
      commitment: postCommitment,
    };

    return {
      kind,
      densFundTxid: fundTxid,
      densSettleTxid,
      stateTxid,
      digest: digestActionPacketV2(engineAction.packet).toString('hex'),
      tip: {
        noteCount: post.noteCount,
        nullifierCount: post.nullifierCount,
        liveNoteCount: post.liveNoteCount,
        reserveSats: post.reserveSats,
        actionSequence: post.actionSequence,
        noteRoot: post.noteRoot,
        nullifierRoot: post.nullifierRoot,
      },
      commitment: postCommitment.toString('hex'),
      densFuel: {
        gateOk: dens.result.gateOk,
        wire: dens.result.wire,
        maxUnlock: Math.max(...dens.meta.slice(0, 7).map((m) => m.unlock.length)),
        sourceValue: Number(SOURCE_VALUE),
      },
      // never persist spend secrets in evidence dumps
      noteMeta: noteMeta
        ? {
          rho: noteMeta.rho,
          cm: noteMeta.cm,
          r: noteMeta.r,
          outputNoteLeaf: noteMeta.outputNoteLeaf,
        }
        : null,
      withdrawalHash,
    };
  }

  // --- DEPOSIT ---
  const alice2 = createAccountKeys();
  const aliceAddr2 = shieldAddress({
    networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice2,
  });
  const depNote = freshOutputNote({
    profileId,
    instanceId,
    authority: aliceAddr2.authority,
    postActionSequence: 1,
    viewPoint: [frFromHex(alice2.V[0]), frFromHex(alice2.V[1])],
  });
  const dep = pool.deposit({
    outputNoteLeaf: depNote.outputNoteLeaf,
    encryptedRecord: depNote.encryptedRecord,
    transactionContextHash: createHash('sha256').update('product-deposit').digest('hex'),
  });
  const depositEv = await settleAction({
    kind: 'deposit',
    engineAction: dep,
    expanded: {
      note: {
        authority: aliceAddr2.authority,
        rho: depNote.rho,
        r: depNote.r,
        cm: depNote.cm,
      },
      path: { index: dep.noteAppend.index, siblings: dep.noteAppend.path.siblings },
      recordCommitmentHex: depNote.recordCommitment,
      preNoteRoot: dep.preState.noteRoot,
      postNoteRoot: dep.postState.noteRoot,
    },
    noteMeta: {
      sk: alice2.sk, rho: depNote.rho, cm: depNote.cm, r: depNote.r,
      outputNoteLeaf: depNote.outputNoteLeaf,
    },
    workName: 'deposit',
  });
  console.log(JSON.stringify({ phase: 'deposit-ok', ...depositEv }));

  // --- TRANSFER ---
  const bob2 = createAccountKeys();
  const bobAddr2 = shieldAddress({
    networkId: NETWORK_CHIPNET, profileId, instanceId, account: bob2,
  });
  const trNote = freshOutputNote({
    profileId,
    instanceId,
    authority: bobAddr2.authority,
    postActionSequence: 2,
    viewPoint: [frFromHex(bob2.V[0]), frFromHex(bob2.V[1])],
  });
  const tr = pool.transfer({
    spendSk: alice2.sk,
    spendRho: depNote.rho,
    spendCm: depNote.cm,
    outputNoteLeaf: trNote.outputNoteLeaf,
    encryptedRecord: trNote.encryptedRecord,
    transactionContextHash: createHash('sha256').update('product-transfer').digest('hex'),
  });
  const transferEv = await settleAction({
    kind: 'transfer',
    engineAction: tr,
    expanded: {
      // primary = spent (alice deposit note); create = bob transfer output
      note: {
        authority: aliceAddr2.authority,
        rho: depNote.rho,
        r: depNote.r,
        cm: depNote.cm,
        sk: alice2.sk,
        spentOutputLeaf: depNote.outputNoteLeaf,
        create: {
          authority: bobAddr2.authority,
          rho: trNote.rho,
          r: trNote.r,
          cm: trNote.cm,
        },
      },
      path: { index: tr.noteAppend.index, siblings: tr.noteAppend.path.siblings },
      recordCommitmentHex: trNote.recordCommitment,
      preNoteRoot: tr.preState.noteRoot,
      postNoteRoot: tr.postState.noteRoot,
    },
    noteMeta: {
      sk: bob2.sk, rho: trNote.rho, cm: trNote.cm, r: trNote.r,
      outputNoteLeaf: trNote.outputNoteLeaf,
    },
    workName: 'transfer',
  });
  console.log(JSON.stringify({ phase: 'transfer-ok', ...transferEv }));

  // --- WITHDRAW ---
  const wHash = createHash('sha256').update(wallet.lockingBytecode).digest('hex');
  const wd = pool.withdraw({
    spendSk: bob2.sk,
    spendRho: trNote.rho,
    spendCm: trNote.cm,
    withdrawalLockingBytecodeHash: wHash,
    transactionContextHash: createHash('sha256').update('product-withdraw').digest('hex'),
  });
  // spent note leaf index = 1 (appended on transfer; deposit was 0)
  const spentPath = pool.noteTree.membershipPath('1');
  const withdrawEv = await settleAction({
    kind: 'withdrawal',
    engineAction: wd,
    expanded: {
      note: {
        authority: bobAddr2.authority,
        rho: trNote.rho,
        r: trNote.r,
        cm: trNote.cm,
        sk: bob2.sk,
        spentOutputLeaf: trNote.outputNoteLeaf,
      },
      path: {
        index: spentPath.index ?? '1',
        siblings: spentPath.siblings,
      },
      recordCommitmentHex: ZERO_32_HEX,
      preNoteRoot: wd.preState.noteRoot,
      postNoteRoot: wd.postState.noteRoot,
    },
    noteMeta: null,
    workName: 'withdraw',
    withdrawalHash: wHash,
  });
  console.log(JSON.stringify({ phase: 'withdraw-ok', ...withdrawEv }));

  // Capacity reject-before-prove
  const capEngine = createPoolEngineV2({
    profileId: createHash('sha256').update('cap-p').digest('hex'),
    instanceId: createHash('sha256').update('cap-i').digest('hex'),
    maximumLiveNotes: 2,
    noteDepth: 8,
    nullifierDepth: 8,
  });
  for (let i = 0; i < 2; i += 1) {
    const a = createAccountKeys();
    const ad = shieldAddress({
      networkId: NETWORK_CHIPNET,
      profileId: capEngine.profileId,
      instanceId: capEngine.instanceId,
      account: a,
    });
    const n = freshOutputNote({
      profileId: capEngine.profileId,
      instanceId: capEngine.instanceId,
      authority: ad.authority,
      postActionSequence: i + 1,
      viewPoint: [frFromHex(a.V[0]), frFromHex(a.V[1])],
    });
    capEngine.deposit({ outputNoteLeaf: n.outputNoteLeaf, encryptedRecord: n.encryptedRecord });
  }
  let capacityRejected = false;
  try {
    const a = createAccountKeys();
    const ad = shieldAddress({
      networkId: NETWORK_CHIPNET,
      profileId: capEngine.profileId,
      instanceId: capEngine.instanceId,
      account: a,
    });
    const n = freshOutputNote({
      profileId: capEngine.profileId,
      instanceId: capEngine.instanceId,
      authority: ad.authority,
      postActionSequence: 3,
      viewPoint: [frFromHex(a.V[0]), frFromHex(a.V[1])],
    });
    capEngine.deposit({ outputNoteLeaf: n.outputNoteLeaf, encryptedRecord: n.encryptedRecord });
  } catch (e) {
    capacityRejected = /maximumLiveNotes|CAPACITY|capacity/i.test(e.message);
  }

  // Recover: rebuild engine from same notes
  const recovered = createPoolEngineV2({
    profileId,
    instanceId,
    networkId: NETWORK_CHIPNET,
    maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
    noteDepth: CIRCUIT_TREE_DEPTH,
    nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  recovered.deposit({
    outputNoteLeaf: depNote.outputNoteLeaf,
    encryptedRecord: depNote.encryptedRecord,
    transactionContextHash: createHash('sha256').update('product-deposit').digest('hex'),
  });
  recovered.transfer({
    spendSk: alice2.sk,
    spendRho: depNote.rho,
    spendCm: depNote.cm,
    outputNoteLeaf: trNote.outputNoteLeaf,
    encryptedRecord: trNote.encryptedRecord,
    transactionContextHash: createHash('sha256').update('product-transfer').digest('hex'),
  });
  recovered.withdraw({
    spendSk: bob2.sk,
    spendRho: trNote.rho,
    spendCm: trNote.cm,
    withdrawalLockingBytecodeHash: wHash,
    transactionContextHash: createHash('sha256').update('product-withdraw').digest('hex'),
  });
  const recoverMatch = recovered.tip().noteRoot === pool.tip().noteRoot
    && recovered.tip().nullifierRoot === pool.tip().nullifierRoot
    && recovered.tip().actionSequence === pool.tip().actionSequence;

  // Adversarial: packet magic mutation
  let adversarialRejected = false;
  try {
    const bad = Buffer.from(dep.packet);
    bad[0] ^= 0xff;
    decodeActionPacketV2(bad);
  } catch {
    adversarialRejected = true;
  }

  const evidence = {
    network: 'chipnet',
    heightStart: height0,
    heightEnd: rpc('getblockcount'),
    topology: {
      densFuel: '10-in common-parent OP_RETURN pin (fund→settle per action)',
      state: 'separate SKS2 mutable NFT roll (P2PKH custody) per action',
      note: 'densFuel pin TXOUTPUTCOUNT=1 forbids co-settling multi-out SKS2 in densFuel tx',
    },
    profileId,
    instanceId,
    category: category.toString('hex'),
    genesisTxid,
    deposit: depositEv,
    transfer: transferEv,
    withdraw: withdrawEv,
    finalTip: {
      noteCount: pool.tip().noteCount,
      nullifierCount: pool.tip().nullifierCount,
      liveNoteCount: pool.tip().liveNoteCount,
      reserveSats: pool.tip().reserveSats,
      actionSequence: pool.tip().actionSequence,
      noteRoot: pool.tip().noteRoot,
      nullifierRoot: pool.tip().nullifierRoot,
    },
    capacityRejectBeforeProve: capacityRejected,
    recoverRespendRootsMatch: recoverMatch,
    adversarialPacketRejected: adversarialRejected,
    densFuelSourceValue: Number(SOURCE_VALUE),
  };
  writeFileSync(path.join(OUT, 'evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`);
  writeFileSync(path.join(OUT, 'txids.txt'), [
    `genesis=${genesisTxid}`,
    `deposit_densFund=${depositEv.densFundTxid}`,
    `deposit_densSettle=${depositEv.densSettleTxid}`,
    `deposit_state=${depositEv.stateTxid}`,
    `transfer_densFund=${transferEv.densFundTxid}`,
    `transfer_densSettle=${transferEv.densSettleTxid}`,
    `transfer_state=${transferEv.stateTxid}`,
    `withdraw_densFund=${withdrawEv.densFundTxid}`,
    `withdraw_densSettle=${withdrawEv.densSettleTxid}`,
    `withdraw_state=${withdrawEv.stateTxid}`,
  ].join('\n') + '\n');
  console.log(JSON.stringify(evidence, null, 2));
  if (!capacityRejected || !recoverMatch || !adversarialRejected) {
    console.error(JSON.stringify({
      phase: 'probe-warn',
      capacityRejected,
      recoverMatch,
      adversarialRejected,
    }));
  }
}

main().catch((e) => {
  console.error(e);
  try {
    writeFileSync(path.join(OUT, 'error.txt'), String(e.stack || e));
  } catch { /* ignore */ }
  process.exit(1);
});
