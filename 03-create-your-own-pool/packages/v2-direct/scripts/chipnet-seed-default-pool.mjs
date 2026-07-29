#!/usr/bin/env node
/**
 * Seed the Protocol-design-v2 **default active Chipnet pool**:
 *   genesis + 5 deposits (leave 5 live notes as anonymity-set tickets)
 *   write public descriptor (no note secrets) under Protocol-design-v2/demo/
 *   write ops secrets gitignored under .cache/
 *
 * Ops only — uses agent hot/cold under codex-artifacts (never committed).
 */
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
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

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const WALLET_DIR = process.env.V2_CHIPNET_WALLET_DIR
  || '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const OUT = path.join(ROOT, '.cache/v2-direct-default-pool-seed');
const DEMO_DIR = path.join(ROOT, 'Protocol-design-v2/demo');
const N = 5;
const FUNDER_SATS = 14_000_000n;
const json = (o) => JSON.stringify(o, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2);

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
    address: priv.address,
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
  console.log(json({ phase: `${label}-accept`, allowed: row?.allowed, reason: row?.['reject-reason'] || null }));
  if (row?.allowed === false) throw new Error(`${label} rejected: ${JSON.stringify(row)}`);
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
  const keep = utxo.valueSats - fee;
  const tx = {
    version: 2, locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(utxo.txid, 'hex')),
      outpointIndex: utxo.vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [{ valueSatoshis: keep, lockingBytecode: Uint8Array.from(hot.lockingBytecode) }],
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
  mkdirSync(DEMO_DIR, { recursive: true });
  process.env.V2_DENSFUEL_TMPDIR = process.env.V2_DENSFUEL_TMPDIR || '/home/toorik/.cache/skd';
  process.env.V2_PIN_BIND = '1';
  const hot = loadHot();

  // cold top-up
  const coldSrc = process.env.COLD_SRC
    || '4c6055ae0f4a1069ad0cb1bb81677bbd7de7af2fc8e51f6f42d25561caa8454d:1';
  const [ct, cv] = coldSrc.split(':');
  const cu = probe(ct, cv);
  if (!cu || cu.valueSats < 200_000_000n) throw new Error(`cold low ${cu?.valueSats}`);
  const cold = loadCold();
  const SEND = 180_000_000n;
  const FEE = 400n;
  const change = cu.valueSats - SEND - FEE;
  const topTx = {
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
  topTx.inputs[0].unlockingBytecode = Uint8Array.from(
    await signP2pkhInput(topTx, 0, [{
      valueSatoshis: cu.valueSats, lockingBytecode: Uint8Array.from(cold.lockingBytecode),
    }], cold),
  );
  const topTxid = broadcast(binToHex(encodeTransaction(topTx)), 'cold-topup');
  let bank = { txid: topTxid, vout: 0, valueSats: SEND };

  // fanout: N funders + cat + residual
  const funders = [];
  for (let i = 0; i < N; i += 1) funders.push(await makeP2pkh());
  const CAT_SATS = 12_000_000n;
  const fanFee = 3000n;
  const outs = funders.map((w) => ({
    valueSatoshis: FUNDER_SATS, lockingBytecode: Uint8Array.from(w.lockingBytecode),
  }));
  outs.push({ valueSatoshis: CAT_SATS, lockingBytecode: Uint8Array.from(hot.lockingBytecode) });
  const fixed = FUNDER_SATS * BigInt(N) + CAT_SATS + fanFee;
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
      valueSatoshis: bank.valueSats, lockingBytecode: Uint8Array.from(hot.lockingBytecode),
    }], hot),
  );
  const fanTxid = broadcast(binToHex(encodeTransaction(fanTx)), 'fanout');
  const funderCoins = funders.map((w, i) => ({
    wallet: w, txid: fanTxid, vout: i, valueSats: FUNDER_SATS,
  }));
  let catUtxo = { txid: fanTxid, vout: N, valueSats: CAT_SATS };
  catUtxo = await ensureVout0(catUtxo, hot, 'cat');

  const profileId = createHash('sha256').update('v2-default-active-pool-chipnet').digest('hex');
  const category = Buffer.from(catUtxo.txid, 'hex');
  const instanceId = category.toString('hex');
  const bindingLock = productBindingLock();

  const accounts = Array.from({ length: N }, () => createAccountKeys());
  const addrs = accounts.map((account) => shieldAddress({
    networkId: NETWORK_CHIPNET, profileId, instanceId, account,
  }));
  const notes = accounts.map((account, i) => freshOutputNote({
    profileId, instanceId, authority: addrs[i].authority,
    postActionSequence: i + 1,
    viewPoint: [frFromHex(account.V[0]), frFromHex(account.V[1])],
  }));

  // densFuel for deposit 0 → genesis locks
  const pre = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: 32, noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const preview0 = pre.deposit({
    outputNoteLeaf: notes[0].outputNoteLeaf,
    encryptedRecord: notes[0].encryptedRecord,
    transactionContextHash: createHash('sha256').update('default-pool-d-0').digest('hex'),
  });
  const dens0 = await buildDensfuelForPacket({
    packetBytes: preview0.packet,
    expanded: {
      note: { authority: addrs[0].authority, rho: notes[0].rho, r: notes[0].r, cm: notes[0].cm },
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
    workDir: path.join(OUT, 'dens-0'),
    maxAttempts: 1,
    pinSeed: 'default-pool-d-0',
  });
  console.log(json({ phase: 'dens-0', gateOk: dens0.result?.gateOk, pinBind: dens0.pinBind }));

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
      valueSatoshis: catUtxo.valueSats, lockingBytecode: Uint8Array.from(hot.lockingBytecode),
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

  const pool = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: 32, noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });

  const deposits = [];
  for (let i = 0; i < N; i += 1) {
    const depTxCtx = i === 0
      ? (dens0.pinBind?.transactionContextHash
        ?? createHash('sha256').update('default-pool-d-0').digest('hex'))
      : createHash('sha256').update(`default-pool-d-${i}`).digest('hex');
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
        throw new Error('deposit-0 packet drift');
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
        workDir: path.join(OUT, `dens-${i}`),
        maxAttempts: 1,
        pinSeed: `default-pool-d-${i}`,
      });
      console.log(json({ phase: `dens-${i}`, gateOk: dens.result?.gateOk, pinBind: dens.pinBind }));
      assertLocks(dens, bundle, `deposit-${i}`);
    }
    const funderU = probe(funderCoins[i].txid, funderCoins[i].vout);
    if (!funderU) throw new Error(`funder ${i} spent`);
    const settled = await assembleProductSettle({
      kind: 'deposit',
      engineAction: { ...act, packet: dens.packetBytes },
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
      noteCm: notes[i].cm,
      noteIndex: String(act.noteAppend.index),
      liveAfter: act.postState.liveNoteCount,
    });
    console.log(json({
      phase: 'deposit-ok', i, depositTxid, tipLive: act.postState.liveNoteCount,
    }));
  }

  const tip = pool.tip();
  const liveTip = {
    carriers: bundle.carriers.map((c) => ({
      txid: c.txid,
      vout: c.vout,
      value: String(c.value),
      lockHex: Buffer.from(c.lock).toString('hex'),
    })),
    binding: {
      txid: bundle.binding.txid,
      vout: bundle.binding.vout,
      value: String(bundle.binding.value),
      lockHex: Buffer.from(bundle.binding.lock).toString('hex'),
    },
    state: {
      txid: bundle.state.txid,
      vout: bundle.state.vout,
      value: String(bundle.state.value),
      lockHex: Buffer.from(bundle.state.lock).toString('hex'),
      commitmentHex: Buffer.from(bundle.state.commitment).toString('hex'),
    },
  };

  // PUBLIC descriptor — safe to ship (no note secrets / no WIFs)
  const publicDescriptor = {
    schema: 'shieldkit/v2-direct-pool-descriptor/v1',
    role: 'default-active-chipnet-pool',
    networkId: NETWORK_CHIPNET,
    network: 'chipnet',
    profileId,
    instanceId,
    maximumLiveNotes: 32,
    noteDepth: CIRCUIT_TREE_DEPTH,
    nullifierDepth: CIRCUIT_TREE_DEPTH,
    genesisTxid,
    genesisVout: 0,
    denominationSats: String(DENOMINATION_SATS),
    liveTip,
    tipSummary: {
      noteCount: tip.noteCount,
      nullifierCount: tip.nullifierCount,
      liveNoteCount: tip.liveNoteCount,
      reserveSats: tip.reserveSats,
      actionSequence: tip.actionSequence,
      noteRoot: tip.noteRoot,
      nullifierRoot: tip.nullifierRoot,
    },
    publicDepositTxids: deposits.map((d) => d.depositTxid),
    seededAt: new Date().toISOString(),
    maturity: 'dev-keys-only-not-for-real-money-privacy',
    note: 'Public tip only. 5 live notes seeded as anonymity-set tickets; spend keys are NOT published.',
  };

  const publicPath = path.join(DEMO_DIR, 'chipnet-default-pool.json');
  writeFileSync(publicPath, `${json(publicDescriptor)}\n`);

  // OPS secrets — gitignored .cache only
  const ops = {
    warning: 'CONFIDENTIAL ops — do not commit. Note secrets for the 5 seed tickets.',
    profileId,
    instanceId,
    genesisTxid,
    fanTxid,
    accounts: accounts.map((a, i) => ({
      index: i,
      sk: a.sk,
      ivk: a.ivk,
      S: a.S,
      V: a.V,
      authority: addrs[i].authority,
      note: {
        rho: notes[i].rho,
        r: notes[i].r,
        cm: notes[i].cm,
        esk: notes[i].esk,
        outputNoteLeaf: notes[i].outputNoteLeaf,
        recordCommitment: notes[i].recordCommitment,
        encryptedRecordHex: notes[i].encryptedRecord.toString('hex'),
      },
      depositTxid: deposits[i].depositTxid,
    })),
    funders: funders.map((w) => ({
      address: w.address,
      privateKeyHex: w.privateKeyHex,
    })),
  };
  writeFileSync(path.join(OUT, 'ops-secrets.json'), `${json(ops)}\n`, { mode: 0o600 });
  writeFileSync(path.join(OUT, 'public-descriptor.json'), `${json(publicDescriptor)}\n`);
  writeFileSync(path.join(OUT, 'run-summary.json'), `${json({
    genesisTxid, fanTxid, deposits, tip: publicDescriptor.tipSummary, publicPath,
  })}\n`);

  console.log(json({
    phase: 'done',
    ok: true,
    genesisTxid,
    instanceId,
    liveNoteCount: tip.liveNoteCount,
    reserveSats: tip.reserveSats,
    publicDescriptor: publicPath,
    opsSecrets: path.join(OUT, 'ops-secrets.json'),
  }));
}

main()
  .then(() => {
    // densFuel/snarkjs/tsx can leave open handles; force clean exit after success.
    process.exit(0);
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
