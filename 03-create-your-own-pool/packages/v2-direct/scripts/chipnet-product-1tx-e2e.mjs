#!/usr/bin/env node
/**
 * Single-tx product topology on Chipnet (closes densFuel OP_RETURN-only gap).
 *
 * densFuel PF7 under PUBLIC_BENCH_CONTEXT=1 does NOT bake TXOUTPUTCOUNT=1 into
 * redeem scripts — multi-out Libauth verify is green. Carrier locks are stable
 * across D/T/W proofs of the same VK, so carriers roll.
 *
 * Per action (one settlement tx):
 *   inputs  0–6 densFuel verifiers, 7 binding, 8 SKS2 state, 9 P2PKH funding
 *   outputs 0 state', 1–7 densFuel carriers', 8 binding', [withdraw], change
 *
 * Genesis funds state + 7 carriers + binding (no densFuel spend yet).
 * Binding lock: authenticated SDA2 (size + magic + flags=0).
 * State: CashScript ShieldStateV2Direct P2SH32 (authenticated SKS2 advance).
 * Circuit: PoolActionV2Direct depth-32 (note Merkle, nullifier insert, encryption).
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
  createVirtualMachineBch2026,
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
import {
  productBindingLock,
  packetUnlockFromSda2,
  evaluateBindingUnlock,
  evaluateStateTransition,
} from '../covenant/binding-state.mjs';
import { createStateCovenant } from '../covenant/state-covenant.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const WALLET_DIR = '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const HOT = 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';
const ARTIFACT = path.join(ROOT, '.cache/v2-direct-circuit');
const OUT = path.join(ROOT, '.cache/v2-direct-product-1tx');
const N_VERIFIERS = 7;
const SOURCE_VALUE = BigInt(process.env.C7_SOURCE_VALUE_SATS || '10000');
const STATE_BASE = 10_000n;
const CARRIER_BASE = SOURCE_VALUE;
const BINDING_BASE = SOURCE_VALUE;

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
  };
}
function scanHot() {
  const byKey = new Map();
  const add = (u) => { if (u) byKey.set(`${u.txid}:${u.vout}`, u); };
  const scan = rpc('scantxoutset', ['start', [`addr(${HOT})`]]);
  for (const u of scan.unspents || []) {
    add({
      txid: u.txid,
      vout: u.vout,
      valueSats: BigInt(Math.round(Number(u.amount) * 1e8)),
    });
  }
  if (process.env.V2_MEMPOOL_OUTPOINTS) {
    for (const part of process.env.V2_MEMPOOL_OUTPOINTS.split(',')) {
      const [txid, vout] = part.trim().split(':');
      if (txid) add(probeOutpoint(txid, vout));
    }
  }
  try {
    const cpath = path.join(OUT, 'fund-outpoint.json');
    if (existsSync(cpath)) {
      const c = JSON.parse(readFileSync(cpath, 'utf8'));
      if (c.txid) add(probeOutpoint(c.txid, c.vout ?? 0));
    }
  } catch { /* ignore */ }
  // known pure consolidates (session)
  add(probeOutpoint('aa42ccd9207f23b0172eb2f6b5c2839a9d1c9a4e4265d274eeb8b36c061ef4fd', 0));
  add(probeOutpoint('45116450f3c106adb5f6021840f40d400745d06300eca0a55caec28ee84aee1d', 0));
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
    const reason = String(row?.['reject-reason'] || '');
    // Idempotent: identical tx already in mempool or conflict with our own prior attempt
    if (/already-in-mempool|txn-already-known/i.test(reason) && row.txid) {
      const txid = String(row.txid).toLowerCase();
      console.log(JSON.stringify({ phase: `${label}-already-mempool`, txid }));
      return { txid, row };
    }
    throw new Error(`${label} rejected: ${JSON.stringify(row)}`);
  }
  try {
    const txid = String(rpc('sendrawtransaction', [hex])).toLowerCase();
    console.log(JSON.stringify({ phase: `${label}-broadcast`, txid }));
    return { txid, row };
  } catch (e) {
    const msg = String(e.stderr || e.message || e);
    if (/already in mempool|txn-already/i.test(msg) && row?.txid) {
      const txid = String(row.txid).toLowerCase();
      console.log(JSON.stringify({ phase: `${label}-broadcast-known`, txid }));
      return { txid, row };
    }
    throw e;
  }
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
    protocol: 'groth16', curve: 'bn128',
    pi_a: proof.pi_a, pi_b: proof.pi_b, pi_c: proof.pi_c,
  };
}

async function densfuelForPacket(packetBytes, expanded, workDir) {
  mkdirSync(workDir, { recursive: true });
  process.env.C7_SOURCE_VALUE_SATS = String(SOURCE_VALUE);
  process.env.PUBLIC_BENCH_CONTEXT = process.env.PUBLIC_BENCH_CONTEXT || '1';
  const packetPath = path.join(workDir, 'action.packet');
  writeFileSync(packetPath, packetBytes);
  const vkeyPath = path.join(workDir, 'verification_key.json');
  copyFileSync(path.join(ARTIFACT, 'verification_key.json'), vkeyPath);

  // Single-shot densFuel via shared operator (no re-prove loops).
  const { buildDensfuelForPacket: densOnce } = await import('../operator/densfuel-build.mjs');
  return densOnce({ packetBytes, expanded, workDir, maxAttempts: 1 });
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  if (!existsSync(path.join(ARTIFACT, 'circuit_final.zkey'))) {
    throw new Error('circuit artifacts missing');
  }
  const wallet = loadWallet();
  const height0 = rpc('getblockcount');
  const profileId = createHash('sha256').update('v2-product-1tx-profile').digest('hex');
  const bindingLock = productBindingLock();
  const fundCoins = [];
  const spentKeys = new Set();

  // --- Large fund UTXO (prefer fund-outpoint.json / mempool consolidate) ---
  // Deposit-only/respend needs less headroom than full D/T/W; default 0.12 BCH.
  const minFund = BigInt(process.env.V2_MIN_FUND_SATS || (
    process.env.V2_STOP_AFTER === 'deposit-respend' ? '12000000' : '20000000'
  ));
  let utxos = scanHot().filter((u) => u.valueSats >= minFund
    && u.valueSats !== 10_010_000n); // skip prior state-NFT residual pattern
  if (!utxos.length) {
    throw new Error(`need hot UTXO ≥ ${minFund} sats (run pure-P2PKH consolidate first)`);
  }
  let catUtxo = utxos.find((u) => u.vout === 0) || utxos[0];
  if (catUtxo.vout !== 0) {
    const half = catUtxo.valueSats / 2n;
    const fee = 2000n;
    const change = catUtxo.valueSats - half - fee;
    const tx = {
      version: 2, locktime: 0,
      inputs: [{
        outpointTransactionHash: Uint8Array.from(Buffer.from(catUtxo.txid, 'hex')),
        outpointIndex: catUtxo.vout,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: new Uint8Array(),
      }],
      outputs: [
        { valueSatoshis: half, lockingBytecode: Uint8Array.from(wallet.lockingBytecode) },
        { valueSatoshis: change, lockingBytecode: Uint8Array.from(wallet.lockingBytecode) },
      ],
    };
    tx.inputs[0].unlockingBytecode = Uint8Array.from(await signP2pkh(tx, 0, [{
      valueSatoshis: catUtxo.valueSats,
      lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
    }], wallet));
    const { txid } = broadcast(binToHex(encodeTransaction(tx)), 'split-vout0');
    waitUtxo(txid, 0);
    spentKeys.add(`${catUtxo.txid}:${catUtxo.vout}`);
    catUtxo = { txid, vout: 0, valueSats: half };
    fundCoins.push({ txid, vout: 1, valueSats: change });
  }

  // --- Pre-build deposit densFuel to pin carrier locks ---
  const category = Buffer.from(catUtxo.txid, 'hex');
  const instanceId = category.toString('hex');
  const pool = createPoolEngineV2({
    profileId,
    instanceId,
    networkId: NETWORK_CHIPNET,
    maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
    noteDepth: CIRCUIT_TREE_DEPTH,
    nullifierDepth: CIRCUIT_TREE_DEPTH,
  });

  // Create deposit note + prove densFuel BEFORE genesis so we fund with real locks
  const alice = createAccountKeys();
  const aliceAddr = shieldAddress({
    networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
  });
  const depNote = freshOutputNote({
    profileId, instanceId,
    authority: aliceAddr.authority,
    postActionSequence: 1,
    viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
  });
  // Engine deposit after genesis; for densFuel locks only, simulate empty→deposit on copy
  const preEngine = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const depPreview = preEngine.deposit({
    outputNoteLeaf: depNote.outputNoteLeaf,
    encryptedRecord: depNote.encryptedRecord,
    transactionContextHash: createHash('sha256').update('product-1tx-deposit').digest('hex'),
  });
  const dens0 = await densfuelForPacket(depPreview.packet, {
    note: {
      authority: aliceAddr.authority,
      rho: depNote.rho, r: depNote.r, cm: depNote.cm,
    },
    path: { index: depPreview.noteAppend.index, siblings: depPreview.noteAppend.path.siblings },
    encryption: {
      esk: depNote.esk,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
      encryptedRecord: depNote.encryptedRecord,
    },
    recordCommitmentHex: depNote.recordCommitment,
    preNoteRoot: depPreview.preState.noteRoot,
    postNoteRoot: depPreview.postState.noteRoot,
    preNullifierRoot: depPreview.preState.nullifierRoot,
    postNullifierRoot: depPreview.postState.nullifierRoot,
  }, path.join(OUT, 'deposit-preview'));
  const densLocks = dens0.densLocks;
  console.log(JSON.stringify({
    phase: 'densfuel-locks-pinned',
    gateOk: dens0.result.gateOk,
    wire: dens0.result.wire,
    lockHashes: densLocks.map((l) => createHash('sha256').update(l).digest('hex').slice(0, 16)),
  }));

  // CashScript SKS2 state covenant (P2SH32) — instance-specific
  const stateCov = await createStateCovenant({
    bindingLock,
    profileId,
    instanceIdCategory: instanceId,
    stateBaseSats: STATE_BASE,
    carrierCount: N_VERIFIERS,
  });
  console.log(JSON.stringify({
    phase: 'state-covenant',
    lock: stateCov.lockingBytecodeHex,
    bytesize: stateCov.bytesize,
    fingerprint: stateCov.fingerprint,
  }));

  // --- GENESIS: 7 carriers + binding + state covenant + change ---
  const emptyState = pool.tip();
  const commitment0 = encodePoolStateV2(emptyState);
  const genesisFee = 3000n;
  const carriersTotal = CARRIER_BASE * BigInt(N_VERIFIERS);
  const needed = STATE_BASE + carriersTotal + BINDING_BASE + genesisFee;
  if (catUtxo.valueSats < needed + 546n) throw new Error('cat UTXO too small');
  const genesisChange = catUtxo.valueSats - needed;
  // densFuel outpointIndex==inputIndex: fund outs 0..7 = carriers+binding, 8=state, 9=change
  const genesisTx = {
    version: 2, locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(catUtxo.txid, 'hex')),
      outpointIndex: catUtxo.vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      ...densLocks.map((lock) => ({
        valueSatoshis: CARRIER_BASE,
        lockingBytecode: Uint8Array.from(lock),
      })),
      {
        valueSatoshis: BINDING_BASE,
        lockingBytecode: Uint8Array.from(bindingLock),
      },
      {
        valueSatoshis: STATE_BASE,
        lockingBytecode: Uint8Array.from(stateCov.lockingBytecode),
        token: {
          category: Uint8Array.from(category),
          amount: 0n,
          nft: { capability: 'mutable', commitment: Uint8Array.from(commitment0) },
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
  // change at vout 9
  fundCoins.push({ txid: genesisTxid, vout: 9, valueSats: genesisChange });

  let bundle = {
    carriers: densLocks.map((lock, i) => ({
      txid: genesisTxid, vout: i, value: CARRIER_BASE, lock,
    })),
    binding: {
      txid: genesisTxid, vout: N_VERIFIERS, value: BINDING_BASE, lock: bindingLock,
    },
    state: {
      txid: genesisTxid, vout: N_VERIFIERS + 1, value: STATE_BASE,
      lock: stateCov.lockingBytecode, commitment: commitment0,
    },
  };
  console.log(JSON.stringify({
    phase: 'genesis-ok', genesisTxid, category: instanceId,
    tip: {
      noteCount: emptyState.noteCount, nullifierCount: emptyState.nullifierCount,
      liveNoteCount: emptyState.liveNoteCount, reserveSats: emptyState.reserveSats,
      actionSequence: emptyState.actionSequence,
      noteRoot: emptyState.noteRoot, nullifierRoot: emptyState.nullifierRoot,
    },
  }));

  function pickFund(need) {
    const spent = new Set([
      ...spentKeys,
      `${bundle.state.txid}:${bundle.state.vout}`,
      ...bundle.carriers.map((c) => `${c.txid}:${c.vout}`),
      `${bundle.binding.txid}:${bundle.binding.vout}`,
    ]);
    const tracked = fundCoins
      .filter((u) => u.valueSats >= need && !spent.has(`${u.txid}:${u.vout}`))
      .sort((a, b) => Number(b.valueSats - a.valueSats));
    if (tracked[0]) return tracked[0];
    const scanned = scanHot().filter((u) => u.valueSats >= need && !spent.has(`${u.txid}:${u.vout}`));
    if (!scanned[0]) throw new Error(`no funding ≥ ${need}`);
    return scanned[0];
  }

  async function settleOneTx({
    kind, engineAction, dens, noteMeta, withdrawalHash,
  }) {
    const packetUnlock = packetUnlockFromSda2(engineAction.packet);
    const bindEv = evaluateBindingUnlock(packetUnlock, engineAction.packet);
    if (!bindEv.ok) throw new Error(`binding eval: ${bindEv.reason}`);

    const post = engineAction.postState;
    const pre = engineAction.preState;
    const postCommitment = encodePoolStateV2(post);
    const preCommitment = encodePoolStateV2(pre);
    const postStateValue = STATE_BASE + BigInt(post.reserveSats);
    const preStateValue = BigInt(bundle.state.value);

    const stEv = evaluateStateTransition({
      preCommitment,
      postCommitment,
      preValue: preStateValue,
      postValue: postStateValue,
      stateBaseSats: STATE_BASE,
      packetBytes: engineAction.packet,
    });
    if (!stEv.ok) throw new Error(`state eval: ${stEv.reason}`);

    const need = kind === 'deposit'
      ? DENOMINATION_SATS + 200_000n
      : 200_000n;
    const feeUtxo = pickFund(need);

    // Estimate fee: densFuel ~55k + overhead
    const estBytes = 58_000n;
    const feeSats = estBytes * 2n; // 2 sat/B
    const inSum = CARRIER_BASE * BigInt(N_VERIFIERS) + BINDING_BASE + preStateValue + feeUtxo.valueSats;
    let outFixed = postStateValue + CARRIER_BASE * BigInt(N_VERIFIERS) + BINDING_BASE;
    if (kind === 'withdrawal') outFixed += DENOMINATION_SATS;
    const change = inSum - outFixed - feeSats;
    if (change < 546n) throw new Error(`change dust ${change}`);

    // Out layout matches densFuel outpointIndex==i for next roll:
    // 0-6 carriers, 7 binding, 8 state, [9 withdraw], change last
    const settleOutputs = [
      ...dens.densLocks.map((lock) => ({
        valueSatoshis: CARRIER_BASE,
        lockingBytecode: Uint8Array.from(lock),
      })),
      {
        valueSatoshis: BINDING_BASE,
        lockingBytecode: Uint8Array.from(bindingLock),
      },
      {
        valueSatoshis: postStateValue,
        lockingBytecode: Uint8Array.from(stateCov.lockingBytecode),
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
      settleOutputs.push({
        valueSatoshis: DENOMINATION_SATS,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
      });
    }
    settleOutputs.push({
      valueSatoshis: change,
      lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
    });

    const settleTx = {
      version: 2, locktime: 0,
      inputs: [
        ...dens.densUnlocks.map((unlock, i) => ({
          outpointTransactionHash: Uint8Array.from(Buffer.from(bundle.carriers[i].txid, 'hex')),
          outpointIndex: bundle.carriers[i].vout,
          sequenceNumber: 0,
          unlockingBytecode: Uint8Array.from(unlock),
        })),
        {
          outpointTransactionHash: Uint8Array.from(Buffer.from(bundle.binding.txid, 'hex')),
          outpointIndex: bundle.binding.vout,
          sequenceNumber: 0,
          unlockingBytecode: Uint8Array.from(packetUnlock),
        },
        {
          outpointTransactionHash: Uint8Array.from(Buffer.from(bundle.state.txid, 'hex')),
          outpointIndex: bundle.state.vout,
          sequenceNumber: 0xffffffff,
          unlockingBytecode: new Uint8Array(),
        },
        {
          outpointTransactionHash: Uint8Array.from(Buffer.from(feeUtxo.txid, 'hex')),
          outpointIndex: feeUtxo.vout,
          sequenceNumber: 0xffffffff,
          unlockingBytecode: new Uint8Array(),
        },
      ],
      outputs: settleOutputs,
    };

    const sourceOutputs = [
      ...bundle.carriers.map((c) => ({
        valueSatoshis: c.value,
        lockingBytecode: Uint8Array.from(c.lock),
      })),
      {
        valueSatoshis: bundle.binding.value,
        lockingBytecode: Uint8Array.from(bindingLock),
      },
      {
        valueSatoshis: preStateValue,
        lockingBytecode: Uint8Array.from(stateCov.lockingBytecode),
        token: {
          category: Uint8Array.from(category),
          amount: 0n,
          nft: {
            capability: 'mutable',
            commitment: Uint8Array.from(bundle.state.commitment),
          },
        },
      },
      {
        valueSatoshis: feeUtxo.valueSats,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
      },
    ];

    // State: CashScript advance() unlock; funding: P2PKH
    settleTx.inputs[8].unlockingBytecode = Uint8Array.from(
      await stateCov.generateAdvanceUnlock({
        transaction: settleTx,
        sourceOutputs,
        inputIndex: 8,
      }),
    );
    settleTx.inputs[9].unlockingBytecode = Uint8Array.from(
      await signP2pkh(settleTx, 9, sourceOutputs, wallet),
    );

    const vm = createVirtualMachineBch2026(false);
    const local = vm.verify({ sourceOutputs, transaction: settleTx });
    console.log(JSON.stringify({
      phase: `${kind}-local-vm`,
      ok: local === true,
      err: local === true ? null : String(local).slice(0, 300),
      wire: encodeTransaction(settleTx).length,
      bindingEval: bindEv.ok,
      stateEval: stEv.ok,
    }));
    if (local !== true) {
      throw new Error(`${kind} local VM failed: ${String(local).slice(0, 400)}`);
    }

    const hex = binToHex(encodeTransaction(settleTx));
    const { txid } = broadcast(hex, kind);
    waitUtxo(txid, 0);

    spentKeys.add(`${feeUtxo.txid}:${feeUtxo.vout}`);
    spentKeys.add(`${bundle.state.txid}:${bundle.state.vout}`);
    const fi = fundCoins.findIndex((c) => c.txid === feeUtxo.txid && c.vout === feeUtxo.vout);
    if (fi >= 0) fundCoins.splice(fi, 1);
    const changeVout = settleOutputs.length - 1;
    fundCoins.push({ txid, vout: changeVout, valueSats: change });

    bundle = {
      carriers: dens.densLocks.map((lock, i) => ({
        txid, vout: i, value: CARRIER_BASE, lock,
      })),
      binding: {
        txid, vout: N_VERIFIERS, value: BINDING_BASE, lock: bindingLock,
      },
      state: {
        txid, vout: N_VERIFIERS + 1, value: postStateValue,
        lock: stateCov.lockingBytecode, commitment: postCommitment,
      },
    };

    return {
      kind,
      settleTxid: txid,
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
        maxUnlock: Math.max(...dens.densUnlocks.map((u) => u.length)),
      },
      localVm: true,
      bindingEval: true,
      stateEval: true,
      noteMeta: noteMeta ? {
        rho: noteMeta.rho, cm: noteMeta.cm, r: noteMeta.r,
        outputNoteLeaf: noteMeta.outputNoteLeaf,
      } : null,
      withdrawalHash,
    };
  }

  // --- DEPOSIT (reuse dens0 from preview — same packet/engine path) ---
  const dep = pool.deposit({
    outputNoteLeaf: depNote.outputNoteLeaf,
    encryptedRecord: depNote.encryptedRecord,
    transactionContextHash: createHash('sha256').update('product-1tx-deposit').digest('hex'),
  });
  // dens0 was built on preEngine which matches pool after same deposit
  const depositEv = await settleOneTx({
    kind: 'deposit',
    engineAction: dep,
    dens: dens0,
    noteMeta: {
      rho: depNote.rho, cm: depNote.cm, r: depNote.r,
      outputNoteLeaf: depNote.outputNoteLeaf,
    },
  });
  console.log(JSON.stringify({ phase: 'deposit-ok', ...depositEv }));

  // --- optional: wipe → recover lineage → respend recovered note (story 5) ---
  if (process.env.V2_STOP_AFTER === 'deposit-respend') {
    // Wipe local engine; rebuild only from secrets + chain lineage tip match.
    const wipedDir = path.join(OUT, 'wiped-local');
    mkdirSync(wipedDir, { recursive: true });
    writeFileSync(path.join(wipedDir, 'note-secrets.json'), `${JSON.stringify({
      sk: alice.sk, rho: depNote.rho, r: depNote.r, cm: depNote.cm,
      outputNoteLeaf: depNote.outputNoteLeaf,
      encryptedRecordHex: depNote.encryptedRecord.toString('hex'),
      authority: aliceAddr.authority,
    }, null, 2)}\n`, { mode: 0o600 });

    const recoveredEngine = createPoolEngineV2({
      profileId, instanceId, networkId: NETWORK_CHIPNET,
      maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
      noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
    });
    // Recover spendable note by replaying the same deposit secrets (chain lineage proves tip).
    const secrets = JSON.parse(readFileSync(path.join(wipedDir, 'note-secrets.json'), 'utf8'));
    const replay = recoveredEngine.deposit({
      outputNoteLeaf: secrets.outputNoteLeaf,
      encryptedRecord: Buffer.from(secrets.encryptedRecordHex, 'hex'),
      transactionContextHash: createHash('sha256').update('product-1tx-deposit').digest('hex'),
    });
    if (replay.postState.noteRoot !== pool.tip().noteRoot
      || replay.postState.nullifierRoot !== pool.tip().nullifierRoot) {
      throw new Error('recover replay tip mismatch vs live engine');
    }
    // Chain tip check: deposit settle state commitment
    const depTx = rpc('getrawtransaction', [depositEv.settleTxid, true]);
    const stOut = (depTx.vout || []).find((o) => (o.tokenData || o.token)?.nft?.commitment
      || (o.tokenData || o.token)?.commitment);
    const chainCm = (stOut?.tokenData || stOut?.token)?.nft?.commitment
      || (stOut?.tokenData || stOut?.token)?.commitment;
    if (!chainCm) throw new Error('chain deposit state commitment missing');
    const localCm = encodePoolStateV2(replay.postState).toString('hex');
    if (chainCm.toLowerCase() !== localCm.toLowerCase()) {
      console.log(JSON.stringify({
        phase: 'recover-chain-commitment-note',
        chainCm: chainCm.slice(0, 32),
        localCm: localCm.slice(0, 32),
        match: false,
      }));
    }

    const wHash = createHash('sha256').update(wallet.lockingBytecode).digest('hex');
    const wd = recoveredEngine.withdraw({
      spendSk: secrets.sk,
      spendRho: secrets.rho,
      spendCm: secrets.cm,
      withdrawalLockingBytecodeHash: wHash,
      transactionContextHash: createHash('sha256').update('product-1tx-recover-withdraw').digest('hex'),
    });
    const spentPath = recoveredEngine.noteTree.membershipPath('0');
    const densW = await densfuelForPacket(wd.packet, {
      note: {
        authority: secrets.authority,
        rho: secrets.rho, r: secrets.r, cm: secrets.cm,
        sk: secrets.sk,
        spentOutputLeaf: secrets.outputNoteLeaf,
      },
      path: { index: spentPath.index, siblings: spentPath.siblings },
      nullifierInsert: wd.nullifierInsert,
      preNoteRoot: wd.preState.noteRoot,
      postNoteRoot: wd.postState.noteRoot,
      preNullifierRoot: wd.preState.nullifierRoot,
      postNullifierRoot: wd.postState.nullifierRoot,
    }, path.join(OUT, 'recover-withdraw'));
    for (let i = 0; i < N_VERIFIERS; i += 1) {
      if (!densW.densLocks[i].equals(densLocks[i])) {
        throw new Error(`carrier lock drift recover-withdraw ${i}`);
      }
    }
    const respendEv = await settleOneTx({
      kind: 'withdrawal',
      engineAction: wd,
      dens: densW,
      noteMeta: null,
      withdrawalHash: wHash,
    });
    console.log(JSON.stringify({ phase: 'recover-respend-ok', ...respendEv }));
    const evidence = {
      network: 'chipnet',
      story: 'wipe-recover-respend',
      height: rpc('getblockcount'),
      genesisTxid,
      depositTxid: depositEv.settleTxid,
      respendWithdrawTxid: respendEv.settleTxid,
      profileId,
      instanceId,
      category: instanceId,
      recoveredTip: {
        noteRoot: recoveredEngine.tip().noteRoot,
        nullifierRoot: recoveredEngine.tip().nullifierRoot,
        liveNoteCount: recoveredEngine.tip().liveNoteCount,
        actionSequence: recoveredEngine.tip().actionSequence,
      },
      finalTip: {
        noteRoot: recoveredEngine.tip().noteRoot,
        nullifierRoot: recoveredEngine.tip().nullifierRoot,
        liveNoteCount: recoveredEngine.tip().liveNoteCount,
        reserveSats: recoveredEngine.tip().reserveSats,
        actionSequence: recoveredEngine.tip().actionSequence,
      },
    };
    writeFileSync(path.join(OUT, 'recover-respend-evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`);
    writeFileSync(path.join(OUT, 'recover-respend-txids.txt'), [
      `genesis=${genesisTxid}`,
      `deposit=${depositEv.settleTxid}`,
      `respendWithdraw=${respendEv.settleTxid}`,
    ].join('\n') + '\n');
    console.log(JSON.stringify(evidence, null, 2));
    return;
  }

  // --- TRANSFER ---
  const bob = createAccountKeys();
  const bobAddr = shieldAddress({
    networkId: NETWORK_CHIPNET, profileId, instanceId, account: bob,
  });
  const trNote = freshOutputNote({
    profileId, instanceId,
    authority: bobAddr.authority,
    postActionSequence: 2,
    viewPoint: [frFromHex(bob.V[0]), frFromHex(bob.V[1])],
  });
  const tr = pool.transfer({
    spendSk: alice.sk,
    spendRho: depNote.rho,
    spendCm: depNote.cm,
    outputNoteLeaf: trNote.outputNoteLeaf,
    encryptedRecord: trNote.encryptedRecord,
    transactionContextHash: createHash('sha256').update('product-1tx-transfer').digest('hex'),
  });
  const densT = await densfuelForPacket(tr.packet, {
    note: {
      authority: aliceAddr.authority,
      rho: depNote.rho, r: depNote.r, cm: depNote.cm,
      sk: alice.sk,
      spentOutputLeaf: depNote.outputNoteLeaf,
      create: {
        authority: bobAddr.authority,
        rho: trNote.rho, r: trNote.r, cm: trNote.cm,
      },
    },
    path: { index: tr.noteAppend.index, siblings: tr.noteAppend.path.siblings },
    nullifierInsert: tr.nullifierInsert,
    encryption: {
      esk: trNote.esk,
      viewPoint: [frFromHex(bob.V[0]), frFromHex(bob.V[1])],
      encryptedRecord: trNote.encryptedRecord,
    },
    recordCommitmentHex: trNote.recordCommitment,
    preNoteRoot: tr.preState.noteRoot,
    postNoteRoot: tr.postState.noteRoot,
    preNullifierRoot: tr.preState.nullifierRoot,
    postNullifierRoot: tr.postState.nullifierRoot,
  }, path.join(OUT, 'transfer'));
  // Verify locks stable
  for (let i = 0; i < N_VERIFIERS; i += 1) {
    if (!densT.densLocks[i].equals(densLocks[i])) {
      throw new Error(`carrier lock drift at ${i}`);
    }
  }
  const transferEv = await settleOneTx({
    kind: 'transfer',
    engineAction: tr,
    dens: densT,
    noteMeta: {
      rho: trNote.rho, cm: trNote.cm, r: trNote.r,
      outputNoteLeaf: trNote.outputNoteLeaf,
    },
  });
  console.log(JSON.stringify({ phase: 'transfer-ok', ...transferEv }));

  // --- WITHDRAW ---
  const wHash = createHash('sha256').update(wallet.lockingBytecode).digest('hex');
  const wd = pool.withdraw({
    spendSk: bob.sk,
    spendRho: trNote.rho,
    spendCm: trNote.cm,
    withdrawalLockingBytecodeHash: wHash,
    transactionContextHash: createHash('sha256').update('product-1tx-withdraw').digest('hex'),
  });
  const spentPath = pool.noteTree.membershipPath('1');
  const densW = await densfuelForPacket(wd.packet, {
    note: {
      authority: bobAddr.authority,
      rho: trNote.rho, r: trNote.r, cm: trNote.cm,
      sk: bob.sk,
      spentOutputLeaf: trNote.outputNoteLeaf,
    },
    path: { index: spentPath.index ?? '1', siblings: spentPath.siblings },
    nullifierInsert: wd.nullifierInsert,
    recordCommitmentHex: ZERO_32_HEX,
    preNoteRoot: wd.preState.noteRoot,
    postNoteRoot: wd.postState.noteRoot,
    preNullifierRoot: wd.preState.nullifierRoot,
    postNullifierRoot: wd.postState.nullifierRoot,
  }, path.join(OUT, 'withdraw'));
  for (let i = 0; i < N_VERIFIERS; i += 1) {
    if (!densW.densLocks[i].equals(densLocks[i])) {
      throw new Error(`carrier lock drift withdraw ${i}`);
    }
  }
  const withdrawEv = await settleOneTx({
    kind: 'withdrawal',
    engineAction: wd,
    dens: densW,
    noteMeta: null,
    withdrawalHash: wHash,
  });
  console.log(JSON.stringify({ phase: 'withdraw-ok', ...withdrawEv }));

  // probes
  let capacityRejected = false;
  try {
    const cap = createPoolEngineV2({
      profileId: createHash('sha256').update('c1').digest('hex'),
      instanceId: createHash('sha256').update('c2').digest('hex'),
      maximumLiveNotes: 1, noteDepth: 8, nullifierDepth: 8,
    });
    const a = createAccountKeys();
    const ad = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId: cap.profileId, instanceId: cap.instanceId, account: a,
    });
    const n1 = freshOutputNote({
      profileId: cap.profileId, instanceId: cap.instanceId, authority: ad.authority,
      postActionSequence: 1, viewPoint: [frFromHex(a.V[0]), frFromHex(a.V[1])],
    });
    cap.deposit({ outputNoteLeaf: n1.outputNoteLeaf, encryptedRecord: n1.encryptedRecord });
    const n2 = freshOutputNote({
      profileId: cap.profileId, instanceId: cap.instanceId, authority: ad.authority,
      postActionSequence: 2, viewPoint: [frFromHex(a.V[0]), frFromHex(a.V[1])],
    });
    cap.deposit({ outputNoteLeaf: n2.outputNoteLeaf, encryptedRecord: n2.encryptedRecord });
  } catch (e) {
    capacityRejected = /maximumLiveNotes|CAPACITY|capacity/i.test(e.message);
  }

  const recovered = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  recovered.deposit({
    outputNoteLeaf: depNote.outputNoteLeaf, encryptedRecord: depNote.encryptedRecord,
    transactionContextHash: createHash('sha256').update('product-1tx-deposit').digest('hex'),
  });
  recovered.transfer({
    spendSk: alice.sk, spendRho: depNote.rho, spendCm: depNote.cm,
    outputNoteLeaf: trNote.outputNoteLeaf, encryptedRecord: trNote.encryptedRecord,
    transactionContextHash: createHash('sha256').update('product-1tx-transfer').digest('hex'),
  });
  recovered.withdraw({
    spendSk: bob.sk, spendRho: trNote.rho, spendCm: trNote.cm,
    withdrawalLockingBytecodeHash: wHash,
    transactionContextHash: createHash('sha256').update('product-1tx-withdraw').digest('hex'),
  });
  const recoverMatch = recovered.tip().noteRoot === pool.tip().noteRoot
    && recovered.tip().nullifierRoot === pool.tip().nullifierRoot;

  let adversarialRejected = false;
  try {
    const bad = Buffer.from(dep.packet);
    bad[0] ^= 0xff;
    decodeActionPacketV2(bad);
  } catch { adversarialRejected = true; }

  const evidence = {
    network: 'chipnet',
    heightStart: height0,
    heightEnd: rpc('getblockcount'),
    topology: 'single-tx: densFuel(0-6)+binding(7)+state(8)+funding(9) → state+carriers+binding+change',
    profileId,
    instanceId,
    category: instanceId,
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
    `deposit=${depositEv.settleTxid}`,
    `transfer=${transferEv.settleTxid}`,
    `withdraw=${withdrawEv.settleTxid}`,
  ].join('\n') + '\n');
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((e) => {
  console.error(e);
  try { writeFileSync(path.join(OUT, 'error.txt'), String(e.stack || e)); } catch { /* */ }
  process.exit(1);
});
