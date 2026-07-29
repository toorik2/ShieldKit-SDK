#!/usr/bin/env node
/**
 * Single-pool forensics (Chipnet, 0-conf):
 *   ONE pool instance
 *   5 deposits from 5 distinct transparent funders
 *   5 withdrawals to 5 distinct transparent destinations
 *
 * densFuel pin envelope: bindPinCompatibleTransactionContext inside
 * buildDensfuelForPacket (first-try; no densFuel re-prove loops).
 */
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeTransaction, binToHex,
  encodeCashAddress, CashAddressNetworkPrefix, CashAddressType,
  hash160, instantiateSecp256k1,
} from '@bitauth/libauth';
import { DENOMINATION_SATS, NETWORK_CHIPNET, ZERO_32_HEX } from '../constants.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';
import { encodePoolStateV2 } from '../state.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import { CIRCUIT_TREE_DEPTH } from '../prove/witness.mjs';
import { productBindingLock } from '../covenant/binding-state.mjs';
import { createStateCovenant } from '../covenant/state-covenant.mjs';
import { buildDensfuelForPacket, N_VERIFIERS, SOURCE_VALUE } from '../operator/densfuel-build.mjs';
import {
  assembleProductSettle, rollBundleAfterSettle, STATE_BASE, CARRIER_BASE, BINDING_BASE,
  signP2pkhInput,
} from '../operator/product-settle.mjs';
import { resolveWithdrawalPayout } from '../operator/withdraw-payout.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const WALLET_DIR = process.env.V2_CHIPNET_WALLET_DIR
  || '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const OUT = path.join(ROOT, '.cache/v2-direct-forensics-1pool-5x5');
const N = 5;
const FUNDER_SATS = 14_000_000n;
const HOT = 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';
const json = (obj) => JSON.stringify(obj, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));

function shellQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}
function rpc(method, params = []) {
  const tokens = params.map((p) => (
    typeof p === 'string' || typeof p === 'number' || typeof p === 'boolean'
      ? shellQuote(String(p)) : shellQuote(JSON.stringify(p))
  ));
  const cmd = [
    'sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf',
    method, ...tokens,
  ].join(' ');
  const out = execFileSync('ssh', ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', 'layer1-node', cmd], {
    encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  });
  const t = out.trim();
  if (!t) return null;
  try { return JSON.parse(t); } catch { return t.replace(/^"|"$/g, ''); }
}
function loadHot() {
  const priv = JSON.parse(readFileSync(path.join(WALLET_DIR, 'wallet-private.json'), 'utf8'));
  return {
    privateKey: Buffer.from(priv.privateKeyHex, 'hex'),
    publicKey: Buffer.from(priv.publicKeyHex, 'hex'),
    lockingBytecode: Buffer.from(priv.lockingBytecodeHex, 'hex'),
    address: priv.address || HOT,
  };
}
function loadCold() {
  const priv = JSON.parse(readFileSync(path.join(WALLET_DIR, 'cold/cold-private.json'), 'utf8'));
  return {
    privateKey: Buffer.from(priv.privateKeyHex, 'hex'),
    publicKey: Buffer.from(priv.publicKeyHex, 'hex'),
    lockingBytecode: Buffer.from(priv.lockingBytecodeHex, 'hex'),
  };
}
function broadcast(hex, label) {
  const accept = rpc('testmempoolaccept', [[hex]]);
  const row = Array.isArray(accept) ? accept[0] : accept;
  console.log(json({
    phase: `${label}-accept`, allowed: row?.allowed,
    reason: row?.['reject-reason'] || null, txid: row?.txid,
  }));
  if (row?.allowed === false) {
    throw new Error(`${label} rejected first try: ${JSON.stringify(row)}`);
  }
  const txid = String(rpc('sendrawtransaction', [hex])).toLowerCase();
  console.log(json({ phase: `${label}-broadcast`, txid }));
  return txid;
}
function probe(txid, vout) {
  const u = rpc('gettxout', [txid, Number(vout), true]);
  if (!u?.value) return null;
  return {
    txid: String(txid).toLowerCase(), vout: Number(vout),
    valueSats: BigInt(Math.round(Number(u.value) * 1e8)),
  };
}
async function makeP2pkh() {
  const secp = await instantiateSecp256k1();
  let sk;
  do { sk = randomBytes(32); } while (!secp.validatePrivateKey(sk));
  const pk = secp.derivePublicKeyCompressed(sk);
  const pkh = hash160(pk);
  const lockingBytecode = Buffer.from([0x76, 0xa9, 0x14, ...pkh, 0x88, 0xac]);
  const enc = encodeCashAddress({
    prefix: CashAddressNetworkPrefix.testnet,
    type: CashAddressType.p2pkh,
    payload: pkh,
  });
  return {
    privateKey: Buffer.from(sk),
    publicKey: Buffer.from(pk),
    lockingBytecode,
    address: typeof enc === 'string' ? enc : enc.address,
    privateKeyHex: Buffer.from(sk).toString('hex'),
    publicKeyHex: Buffer.from(pk).toString('hex'),
    lockingBytecodeHex: lockingBytecode.toString('hex'),
  };
}
async function ensureVout0(utxo, hot, label) {
  if (utxo.vout === 0) return utxo;
  const fee = 1000n;
  if (utxo.valueSats <= fee + 546n) throw new Error(`${label} dust for vout0 split`);
  const keep = utxo.valueSats - fee;
  const tx = {
    version: 2, locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(utxo.txid, 'hex')),
      outpointIndex: utxo.vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      { valueSatoshis: keep, lockingBytecode: Uint8Array.from(hot.lockingBytecode) },
    ],
  };
  tx.inputs[0].unlockingBytecode = Uint8Array.from(
    await signP2pkhInput(tx, 0, [{
      valueSatoshis: utxo.valueSats,
      lockingBytecode: Uint8Array.from(hot.lockingBytecode),
    }], hot),
  );
  const txid = broadcast(binToHex(encodeTransaction(tx)), `${label}-vout0`);
  return { txid, vout: 0, valueSats: keep };
}

function assertLocks(dens, bundle, label) {
  for (let k = 0; k < N_VERIFIERS; k += 1) {
    if (!dens.densLocks[k].equals(bundle.carriers[k].lock)) {
      throw new Error(`lock drift ${label} @${k}`);
    }
  }
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  process.env.V2_DENSFUEL_ATTEMPTS = '1';
  process.env.V2_DENSFUEL_TMPDIR = process.env.V2_DENSFUEL_TMPDIR || '/home/toorik/.cache/skd';
  process.env.V2_PIN_BIND = process.env.V2_PIN_BIND || '1';
  process.env.V2_SKIP_ECIP_GATE = process.env.V2_SKIP_ECIP_GATE || '0';
  const hot = loadHot();

  // --- bank: cold top-up if needed ---
  let bank = null;
  if (process.env.V2_MEMPOOL_OUTPOINTS) {
    const [t, v] = process.env.V2_MEMPOOL_OUTPOINTS.split(':');
    bank = probe(t, v);
  }
  const need = FUNDER_SATS * BigInt(N) + 50_000_000n; // funders + cat + fees
  if (!bank || bank.valueSats < need) {
    const cold = loadCold();
    const coldSrc = process.env.COLD_SRC
      || 'ae0528899e681137729048c9c5a399fdd13b5bf1c8fa43b5089af0397020873c:1';
    const [ct, cv] = coldSrc.split(':');
    const cu = probe(ct, cv);
    if (!cu || cu.valueSats < 170_000_000n) {
      throw new Error(`need cold UTXO ≥1.7 BCH, got ${cu?.valueSats} from ${coldSrc}`);
    }
    const SEND = 160_000_000n;
    const FEE = 400n;
    const change = cu.valueSats - SEND - FEE;
    const tx = {
      version: 2, locktime: 0,
      inputs: [{
        outpointTransactionHash: Uint8Array.from(Buffer.from(cu.txid, 'hex')),
        outpointIndex: cu.vout,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: new Uint8Array(),
      }],
      outputs: [
        { valueSatoshis: SEND, lockingBytecode: Uint8Array.from(hot.lockingBytecode) },
        { valueSatoshis: change, lockingBytecode: Uint8Array.from(cold.lockingBytecode) },
      ],
    };
    tx.inputs[0].unlockingBytecode = Uint8Array.from(
      await signP2pkhInput(tx, 0, [{
        valueSatoshis: cu.valueSats,
        lockingBytecode: Uint8Array.from(cold.lockingBytecode),
      }], cold),
    );
    const txid = broadcast(binToHex(encodeTransaction(tx)), 'cold-topup');
    bank = { txid, vout: 0, valueSats: SEND };
  }
  if (bank.vout !== 0) {
    const half = bank.valueSats / 2n;
    const fee = 2000n;
    const ch = bank.valueSats - half - fee;
    const tx = {
      version: 2, locktime: 0,
      inputs: [{
        outpointTransactionHash: Uint8Array.from(Buffer.from(bank.txid, 'hex')),
        outpointIndex: bank.vout,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: new Uint8Array(),
      }],
      outputs: [
        { valueSatoshis: half, lockingBytecode: Uint8Array.from(hot.lockingBytecode) },
        { valueSatoshis: ch, lockingBytecode: Uint8Array.from(hot.lockingBytecode) },
      ],
    };
    tx.inputs[0].unlockingBytecode = Uint8Array.from(
      await signP2pkhInput(tx, 0, [{
        valueSatoshis: bank.valueSats,
        lockingBytecode: Uint8Array.from(hot.lockingBytecode),
      }], hot),
    );
    const txid = broadcast(binToHex(encodeTransaction(tx)), 'split-vout0');
    bank = { txid, vout: 0, valueSats: half };
  }

  // --- fanout: N funders + 1 cat + residual fee ---
  const funders = [];
  const dests = [];
  for (let i = 0; i < N; i += 1) {
    funders.push(await makeP2pkh());
    dests.push(await makeP2pkh());
  }
  writeFileSync(path.join(OUT, 'ephemeral-keys.json'), `${JSON.stringify({
    funders: funders.map((w) => ({
      address: w.address,
      privateKeyHex: w.privateKeyHex,
      publicKeyHex: w.publicKeyHex,
      lockingBytecodeHex: w.lockingBytecodeHex,
    })),
    dests: dests.map((w) => ({
      address: w.address,
      privateKeyHex: w.privateKeyHex,
      publicKeyHex: w.publicKeyHex,
      lockingBytecodeHex: w.lockingBytecodeHex,
    })),
  }, null, 2)}\n`);

  const CAT_SATS = 12_000_000n;
  const fanFee = 3000n;
  const outs = [];
  for (let i = 0; i < N; i += 1) {
    outs.push({
      valueSatoshis: FUNDER_SATS,
      lockingBytecode: Uint8Array.from(funders[i].lockingBytecode),
    });
  }
  outs.push({ valueSatoshis: CAT_SATS, lockingBytecode: Uint8Array.from(hot.lockingBytecode) });
  const fixed = FUNDER_SATS * BigInt(N) + CAT_SATS + fanFee;
  if (bank.valueSats < fixed + 5_000_000n) throw new Error('bank too small for fanout');
  const residual = bank.valueSats - fixed;
  outs.push({ valueSatoshis: residual, lockingBytecode: Uint8Array.from(hot.lockingBytecode) });
  const fanTx = {
    version: 2, locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(bank.txid, 'hex')),
      outpointIndex: bank.vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: outs,
  };
  fanTx.inputs[0].unlockingBytecode = Uint8Array.from(
    await signP2pkhInput(fanTx, 0, [{
      valueSatoshis: bank.valueSats,
      lockingBytecode: Uint8Array.from(hot.lockingBytecode),
    }], hot),
  );
  const fanTxid = broadcast(binToHex(encodeTransaction(fanTx)), 'fanout');
  const funderCoins = funders.map((w, i) => ({
    wallet: w, txid: fanTxid, vout: i, valueSats: FUNDER_SATS,
  }));
  let catUtxo = { txid: fanTxid, vout: N, valueSats: CAT_SATS };
  let feeCoin = { txid: fanTxid, vout: N + 1, valueSats: residual };
  console.log(json({
    phase: 'fanout-ok',
    fanTxid,
    funderAddresses: funders.map((w) => w.address),
    destAddresses: dests.map((w) => w.address),
    topology: 'single-pool-5-in-5-out',
  }));

  // --- single pool genesis (locks from first deposit densFuel) ---
  catUtxo = await ensureVout0(catUtxo, hot, 'cat');
  const profileId = createHash('sha256').update('v2-forensics-1pool-5x5').digest('hex');
  const category = Buffer.from(catUtxo.txid, 'hex');
  const instanceId = category.toString('hex');
  const bindingLock = productBindingLock();

  // 5 independent shielded accounts (distinct authorities / notes)
  const accounts = Array.from({ length: N }, () => createAccountKeys());
  const addrs = accounts.map((account) => shieldAddress({
    networkId: NETWORK_CHIPNET, profileId, instanceId, account,
  }));
  const notes = accounts.map((account, i) => freshOutputNote({
    profileId,
    instanceId,
    authority: addrs[i].authority,
    postActionSequence: i + 1,
    viewPoint: [frFromHex(account.V[0]), frFromHex(account.V[1])],
  }));

  // densFuel for deposit #0 against empty tip (also pins genesis carrier locks)
  const previewEngine = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: 32, noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const preview0 = previewEngine.deposit({
    outputNoteLeaf: notes[0].outputNoteLeaf,
    encryptedRecord: notes[0].encryptedRecord,
    transactionContextHash: createHash('sha256').update('1pool-d-0').digest('hex'),
  });
  const dens0 = await buildDensfuelForPacket({
    packetBytes: preview0.packet,
    expanded: {
      note: {
        authority: addrs[0].authority,
        rho: notes[0].rho, r: notes[0].r, cm: notes[0].cm,
      },
      path: { index: preview0.noteAppend.index, siblings: preview0.noteAppend.path.siblings },
      encryption: {
        esk: notes[0].esk,
        viewPoint: [frFromHex(accounts[0].V[0]), frFromHex(accounts[0].V[1])],
        encryptedRecord: notes[0].encryptedRecord,
      },
      recordCommitmentHex: notes[0].recordCommitment,
      preNoteRoot: preview0.preState.noteRoot,
      postNoteRoot: preview0.postState.noteRoot,
      preNullifierRoot: preview0.preState.nullifierRoot,
      postNullifierRoot: preview0.postState.nullifierRoot,
    },
    workDir: path.join(OUT, 'deposit-0-dens'),
    maxAttempts: 1,
    pinSeed: '1pool-d-0',
  });
  console.log(json({
    phase: 'deposit-0-densfuel',
    gateOk: dens0.result?.gateOk,
    pinBind: dens0.pinBind,
  }));

  const stateCov = await createStateCovenant({
    bindingLock, profileId, instanceIdCategory: category,
    stateBaseSats: STATE_BASE, carrierCount: N_VERIFIERS,
  });
  const empty = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: 32, noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const commitment0 = encodePoolStateV2(empty.tip());
  const genFee = 3000n;
  const genFixed = CARRIER_BASE * BigInt(N_VERIFIERS) + BINDING_BASE + STATE_BASE + genFee;
  if (catUtxo.valueSats < genFixed + 546n) throw new Error('cat utxo too small for genesis');
  const genChange = catUtxo.valueSats - genFixed;
  const genesisTx = {
    version: 2, locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(catUtxo.txid, 'hex')),
      outpointIndex: catUtxo.vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      ...dens0.densLocks.map((lock) => ({
        valueSatoshis: CARRIER_BASE, lockingBytecode: Uint8Array.from(lock),
      })),
      { valueSatoshis: BINDING_BASE, lockingBytecode: Uint8Array.from(bindingLock) },
      {
        valueSatoshis: STATE_BASE,
        lockingBytecode: Uint8Array.from(stateCov.lockingBytecode),
        token: {
          category: Uint8Array.from(category), amount: 0n,
          nft: { capability: 'mutable', commitment: Uint8Array.from(commitment0) },
        },
      },
      { valueSatoshis: genChange, lockingBytecode: Uint8Array.from(hot.lockingBytecode) },
    ],
  };
  genesisTx.inputs[0].unlockingBytecode = Uint8Array.from(
    await signP2pkhInput(genesisTx, 0, [{
      valueSatoshis: catUtxo.valueSats,
      lockingBytecode: Uint8Array.from(hot.lockingBytecode),
    }], hot),
  );
  const genesisTxid = broadcast(binToHex(encodeTransaction(genesisTx)), 'genesis');

  let bundle = {
    carriers: dens0.densLocks.map((lock, k) => ({
      txid: genesisTxid, vout: k, value: CARRIER_BASE, lock,
    })),
    binding: {
      txid: genesisTxid, vout: N_VERIFIERS, value: BINDING_BASE, lock: bindingLock,
    },
    state: {
      txid: genesisTxid, vout: N_VERIFIERS + 1, value: STATE_BASE,
      lock: stateCov.lockingBytecode, commitment: commitment0,
    },
  };
  // merge genChange into fee residual path
  feeCoin = { txid: genesisTxid, vout: N_VERIFIERS + 2, valueSats: genChange };

  const pool = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: 32, noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });

  const deposits = [];
  for (let i = 0; i < N; i += 1) {
    const depTxCtx = i === 0
      ? (dens0.pinBind?.transactionContextHash
        ?? createHash('sha256').update('1pool-d-0').digest('hex'))
      : createHash('sha256').update(`1pool-d-${i}`).digest('hex');
    const act = pool.deposit({
      outputNoteLeaf: notes[i].outputNoteLeaf,
      encryptedRecord: notes[i].encryptedRecord,
      transactionContextHash: depTxCtx,
    });

    let dens;
    if (i === 0) {
      dens = dens0;
      if (createHash('sha256').update(act.packet).digest('hex')
        !== createHash('sha256').update(dens0.packetBytes).digest('hex')) {
        throw new Error('deposit-0 packet drift vs pin-bound dens0');
      }
    } else {
      dens = await buildDensfuelForPacket({
        packetBytes: act.packet,
        expanded: {
          note: {
            authority: addrs[i].authority,
            rho: notes[i].rho, r: notes[i].r, cm: notes[i].cm,
          },
          path: { index: act.noteAppend.index, siblings: act.noteAppend.path.siblings },
          encryption: {
            esk: notes[i].esk,
            viewPoint: [frFromHex(accounts[i].V[0]), frFromHex(accounts[i].V[1])],
            encryptedRecord: notes[i].encryptedRecord,
          },
          recordCommitmentHex: notes[i].recordCommitment,
          preNoteRoot: act.preState.noteRoot,
          postNoteRoot: act.postState.noteRoot,
          preNullifierRoot: act.preState.nullifierRoot,
          postNullifierRoot: act.postState.nullifierRoot,
        },
        workDir: path.join(OUT, `deposit-${i}-dens`),
        maxAttempts: 1,
        pinSeed: `1pool-d-${i}`,
      });
      console.log(json({
        phase: `deposit-${i}-densfuel`,
        gateOk: dens.result?.gateOk,
        pinBind: dens.pinBind,
      }));
      assertLocks(dens, bundle, `deposit-${i}`);
    }

    // Settle must use pin-bound packet
    const engineAction = { ...act, packet: dens.packetBytes };
    const funderU = probe(funderCoins[i].txid, funderCoins[i].vout);
    if (!funderU) throw new Error(`funder ${i} spent`);
    const settled = await assembleProductSettle({
      kind: 'deposit',
      engineAction,
      dens,
      bundle,
      wallet: funderCoins[i].wallet,
      feeUtxo: funderU,
      category,
      profileId,
    });
    const depositTxid = broadcast(settled.hex, `deposit-${i}`);
    bundle = rollBundleAfterSettle({
      settleTxid: depositTxid,
      densLocks: settled.densLocks,
      bindingLockHex: settled.bindingLockHex,
      stateLockingBytecode: settled.stateLockingBytecode,
      postCommitment: settled.postCommitment,
      postStateValue: STATE_BASE + BigInt(act.postState.reserveSats),
    });
    deposits.push({
      index: i,
      depositTxid,
      fundingAddress: funderCoins[i].wallet.address,
      fundingOutpoint: `${funderU.txid}:${funderU.vout}`,
      noteCm: notes[i].cm,
      noteIndex: String(act.noteAppend.index),
      pinBind: dens.pinBind,
      accountIndex: i,
    });
    console.log(json({
      phase: 'deposit-ok',
      i,
      depositTxid,
      from: funderCoins[i].wallet.address,
      tipNotes: act.postState.noteCount,
      tipLive: act.postState.liveNoteCount,
    }));
  }

  // --- 5 withdrawals (spend notes 0..4 → dests 0..4) ---
  const withdrawals = [];
  for (let i = 0; i < N; i += 1) {
    const payout = resolveWithdrawalPayout({
      toCashAddr: dests[i].address,
      defaultLockingBytecode: dests[i].lockingBytecode,
    });
    const noteIdx = String(i);
    const wd = pool.withdraw({
      spendSk: accounts[i].sk,
      spendRho: notes[i].rho,
      spendCm: notes[i].cm,
      withdrawalLockingBytecodeHash: payout.hashHex,
      transactionContextHash: createHash('sha256').update(`1pool-w-${i}`).digest('hex'),
    });
    const spentPath = pool.noteTree.membershipPath(noteIdx);
    const densW = await buildDensfuelForPacket({
      packetBytes: wd.packet,
      expanded: {
        note: {
          authority: addrs[i].authority,
          rho: notes[i].rho, r: notes[i].r, cm: notes[i].cm,
          sk: accounts[i].sk,
          spentOutputLeaf: notes[i].outputNoteLeaf,
        },
        path: { index: spentPath.index ?? noteIdx, siblings: spentPath.siblings },
        nullifierInsert: wd.nullifierInsert,
        recordCommitmentHex: ZERO_32_HEX,
        preNoteRoot: wd.preState.noteRoot,
        postNoteRoot: wd.postState.noteRoot,
        preNullifierRoot: wd.preState.nullifierRoot,
        postNullifierRoot: wd.postState.nullifierRoot,
      },
      workDir: path.join(OUT, `withdraw-${i}-dens`),
      maxAttempts: 1,
      pinSeed: `1pool-w-${i}`,
    });
    console.log(json({
      phase: `withdraw-${i}-densfuel`,
      gateOk: densW.result?.gateOk,
      pinBind: densW.pinBind,
    }));
    assertLocks(densW, bundle, `withdraw-${i}`);
    const feeU = probe(feeCoin.txid, feeCoin.vout);
    if (!feeU || feeU.valueSats < 300_000n) {
      throw new Error(`fee coin low at withdraw ${i}: ${feeU?.valueSats}`);
    }
    const settled = await assembleProductSettle({
      kind: 'withdrawal',
      engineAction: { ...wd, packet: densW.packetBytes },
      dens: densW,
      bundle,
      wallet: hot,
      feeUtxo: feeU,
      category,
      profileId,
      withdrawalLockingBytecode: payout.lockingBytecode,
      withdrawalHashHex: payout.hashHex,
    });
    const withdrawTxid = broadcast(settled.hex, `withdraw-${i}`);
    bundle = rollBundleAfterSettle({
      settleTxid: withdrawTxid,
      densLocks: settled.densLocks,
      bindingLockHex: settled.bindingLockHex,
      stateLockingBytecode: settled.stateLockingBytecode,
      postCommitment: settled.postCommitment,
      postStateValue: STATE_BASE + BigInt(wd.postState.reserveSats),
    });
    feeCoin = {
      txid: withdrawTxid,
      vout: settled.changeVout,
      valueSats: settled.change,
    };
    withdrawals.push({
      index: i,
      withdrawTxid,
      payoutAddress: dests[i].address,
      spentNoteIndex: noteIdx,
      pinBind: densW.pinBind,
    });
    console.log(json({
      phase: 'withdraw-ok',
      i,
      withdrawTxid,
      to: dests[i].address,
      tipLive: wd.postState.liveNoteCount,
    }));
  }

  const publicTrace = {
    network: 'chipnet',
    purpose: 'single-pool 5 deposit / 5 withdraw forensics (pin-compatible witness)',
    topology: 'ONE pool, 5 notes anonymity set, then 5 withdrawals',
    confBar: '0-conf-mempool',
    densFuelPolicy: 'first-try only + pin-compatible transactionContextHash bind',
    height: rpc('getblockcount'),
    fanoutTxid: fanTxid,
    genesisTxid,
    profileId,
    instanceId,
    categoryHex: category.toString('hex'),
    denominationSats: String(DENOMINATION_SATS),
    deposits: deposits.map((d) => ({
      index: d.index,
      settleTxid: d.depositTxid,
      fundingAddress: d.fundingAddress,
      fundingOutpoint: d.fundingOutpoint,
      noteCm: d.noteCm,
      noteIndex: d.noteIndex,
      pinBind: d.pinBind,
    })),
    withdrawals: withdrawals.map((w) => ({
      index: w.index,
      settleTxid: w.withdrawTxid,
      payoutAddress: w.payoutAddress,
      spentNoteIndex: w.spentNoteIndex,
      pinBind: w.pinBind,
    })),
    publicDepositAddresses: deposits.map((d) => d.fundingAddress),
    publicWithdrawAddresses: withdrawals.map((w) => w.payoutAddress),
    publicDepositTxids: deposits.map((d) => d.depositTxid),
    publicWithdrawTxids: withdrawals.map((w) => w.withdrawTxid),
  };
  const groundTruth = {
    note: 'CONFIDENTIAL — single pool; link deposit i → withdraw i by note index (same account)',
    links: deposits.map((d, i) => ({
      depositIndex: d.index,
      depositTxid: d.depositTxid,
      depositFundingAddress: d.fundingAddress,
      withdrawIndex: withdrawals[i].index,
      withdrawTxid: withdrawals[i].withdrawTxid,
      payoutAddress: withdrawals[i].payoutAddress,
      noteIndex: d.noteIndex,
      noteCm: d.noteCm,
      genesisTxid,
      instanceId,
    })),
    funders: funders.map((w) => ({ address: w.address, privateKeyHex: w.privateKeyHex })),
    withdrawDests: dests.map((w) => ({ address: w.address, privateKeyHex: w.privateKeyHex })),
  };

  writeFileSync(path.join(OUT, 'public-trace.json'), `${JSON.stringify(publicTrace, null, 2)}\n`);
  writeFileSync(path.join(OUT, 'ground-truth.json'), `${JSON.stringify(groundTruth, null, 2)}\n`);
  writeFileSync(path.join(OUT, 'txids.txt'), [
    `fanout=${fanTxid}`,
    `genesis=${genesisTxid}`,
    ...deposits.map((d) => `deposit${d.index}=${d.depositTxid}`),
    ...withdrawals.map((w) => `withdraw${w.index}=${w.withdrawTxid}`),
  ].join('\n') + '\n');
  writeFileSync(path.join(OUT, 'links-ground-truth.txt'), [
    '# SINGLE POOL — depositTxid fundingAddress → withdrawTxid payoutAddress',
    ...groundTruth.links.map((L) => (
      `${L.depositTxid} ${L.depositFundingAddress} → ${L.withdrawTxid} ${L.payoutAddress}`
    )),
  ].join('\n') + '\n');

  console.log(JSON.stringify({
    phase: 'done',
    ok: true,
    topology: 'single-pool',
    out: OUT,
    genesisTxid,
    fanoutTxid: fanTxid,
    links: groundTruth.links.map((L) => ({
      from: L.depositFundingAddress,
      deposit: L.depositTxid,
      withdraw: L.withdrawTxid,
      to: L.payoutAddress,
    })),
  }, null, 2));
}

main()
  .then(() => {
    // densFuel/snarkjs may leave open handles; force exit after success.
    process.exit(0);
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
