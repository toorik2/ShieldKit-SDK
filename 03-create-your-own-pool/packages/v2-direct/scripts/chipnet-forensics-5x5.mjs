#!/usr/bin/env node
/**
 * Privacy forensics setup (Chipnet, 0-conf):
 *   5 deposits from 5 distinct transparent funders
 *   5 withdrawals to 5 distinct transparent destinations
 *
 * Architecture: **five independent 1-note pools** (G→D→W each) for clear
 * deposit↔withdraw forensics links. densFuel pin envelope is handled by
 * deterministic pin-compatible `transactionContextHash` binding (option 3)
 * inside buildDensfuelForPacket — not by note re-sampling or densFuel retries.
 *
 * HARD RULE (global): first try only — densFuel maxAttempts=1, no re-prove /
 * re-broadcast loops. Fail → stop and fix root cause immediately.
 */
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeTransaction, binToHex,
  encodeCashAddress, CashAddressNetworkPrefix, CashAddressType,
  cashAddressToLockingBytecode, hash160, instantiateSecp256k1,
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
const OUT = path.join(ROOT, '.cache/v2-direct-forensics-5x5');
const N = 5;
const FUNDER_SATS = 14_000_000n;
const HOT = 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';

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
  console.log(JSON.stringify({
    phase: `${label}-accept`, allowed: row?.allowed,
    reason: row?.['reject-reason'] || null, txid: row?.txid,
  }));
  if (row?.allowed === false) {
    throw new Error(`${label} rejected first try: ${JSON.stringify(row)}`);
  }
  const txid = String(rpc('sendrawtransaction', [hex])).toLowerCase();
  console.log(JSON.stringify({ phase: `${label}-broadcast`, txid }));
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
  // CashToken genesis category = prevout txid only accepted for minting from vout=0
  // pure-P2PKH in product path; non-zero vout → bad-txns-token-invalid-category.
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

async function onePool(i, funder, dest, catUtxoIn, hot, feeCoin) {
  const catUtxo = await ensureVout0(catUtxoIn, hot, `pool-${i}-cat`);
  const profileId = createHash('sha256').update(`v2-forensics-pool-${i}`).digest('hex');
  // Product path: category bytes = funding prevout txid (requires vout=0 mint parent)
  const category = Buffer.from(catUtxo.txid, 'hex');
  const instanceId = category.toString('hex');
  const bindingLock = productBindingLock();
  const account = createAccountKeys();
  const addr = shieldAddress({
    networkId: NETWORK_CHIPNET, profileId, instanceId, account,
  });

  // One note + one densFuel. Pin envelope is guaranteed by
  // bindPinCompatibleTransactionContext inside buildDensfuelForPacket.
  const pre = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: 32, noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const note = freshOutputNote({
    profileId, instanceId, authority: addr.authority,
    postActionSequence: 1,
    viewPoint: [frFromHex(account.V[0]), frFromHex(account.V[1])],
  });
  const preview = pre.deposit({
    outputNoteLeaf: note.outputNoteLeaf,
    encryptedRecord: note.encryptedRecord,
    transactionContextHash: createHash('sha256').update(`forensics-d-${i}`).digest('hex'),
  });
  const dens0 = await buildDensfuelForPacket({
    packetBytes: preview.packet,
    expanded: {
      note: {
        authority: addr.authority, rho: note.rho, r: note.r, cm: note.cm,
      },
      path: { index: preview.noteAppend.index, siblings: preview.noteAppend.path.siblings },
      encryption: {
        esk: note.esk,
        viewPoint: [frFromHex(account.V[0]), frFromHex(account.V[1])],
        encryptedRecord: note.encryptedRecord,
      },
      recordCommitmentHex: note.recordCommitment,
      preNoteRoot: preview.preState.noteRoot,
      postNoteRoot: preview.postState.noteRoot,
      preNullifierRoot: preview.preState.nullifierRoot,
      postNullifierRoot: preview.postState.nullifierRoot,
    },
    workDir: path.join(OUT, `pool-${i}-dens0`),
    maxAttempts: 1,
    pinSeed: `forensics-d-${i}`,
  });
  console.log(JSON.stringify({
    phase: `pool-${i}-densfuel`,
    gateOk: dens0.result?.gateOk,
    pinBind: dens0.pinBind && {
      nfail: dens0.pinBind.nfail,
      searchIndex: dens0.pinBind.searchIndex,
      changed: dens0.pinBind.changed,
    },
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
  if (catUtxo.valueSats < genFixed + 546n) {
    throw new Error(`pool-${i} cat utxo too small`);
  }
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
  const genesisTxid = broadcast(binToHex(encodeTransaction(genesisTx)), `pool-${i}-genesis`);

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

  // Deposit: same note; use pin-bound transactionContextHash from dens0.
  const pool = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: 32, noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const depTxCtx = dens0.pinBind?.transactionContextHash
    ?? createHash('sha256').update(`forensics-d-${i}`).digest('hex');
  const act = pool.deposit({
    outputNoteLeaf: note.outputNoteLeaf,
    encryptedRecord: note.encryptedRecord,
    transactionContextHash: depTxCtx,
  });
  if (createHash('sha256').update(act.packet).digest('hex')
    !== createHash('sha256').update(dens0.packetBytes).digest('hex')) {
    throw new Error(`pool-${i} deposit packet drift vs pin-bound dens0`);
  }
  const dens = dens0;
  const funderU = probe(funder.txid, funder.vout);
  if (!funderU) throw new Error(`pool-${i} funder spent`);
  const depSettled = await assembleProductSettle({
    kind: 'deposit',
    engineAction: act,
    dens,
    bundle,
    wallet: funder.wallet,
    feeUtxo: funderU,
    category,
    profileId,
  });
  const depositTxid = broadcast(depSettled.hex, `pool-${i}-deposit`);
  bundle = rollBundleAfterSettle({
    settleTxid: depositTxid,
    densLocks: depSettled.densLocks,
    bindingLockHex: depSettled.bindingLockHex,
    stateLockingBytecode: depSettled.stateLockingBytecode,
    postCommitment: depSettled.postCommitment,
    postStateValue: STATE_BASE + BigInt(act.postState.reserveSats),
  });

  // Withdraw to dest
  const payout = resolveWithdrawalPayout({
    toCashAddr: dest.address,
    defaultLockingBytecode: dest.lockingBytecode,
  });
  const wd = pool.withdraw({
    spendSk: account.sk,
    spendRho: note.rho,
    spendCm: note.cm,
    withdrawalLockingBytecodeHash: payout.hashHex,
    transactionContextHash: createHash('sha256').update(`forensics-w-${i}`).digest('hex'),
  });
  const spentPath = pool.noteTree.membershipPath('0');
  // Withdraw densFuel: first try; pin-bind rewrites tx context inside densFuel path.
  const densW = await buildDensfuelForPacket({
    packetBytes: wd.packet,
    expanded: {
      note: {
        authority: addr.authority,
        rho: note.rho, r: note.r, cm: note.cm,
        sk: account.sk,
        spentOutputLeaf: note.outputNoteLeaf,
      },
      path: { index: spentPath.index ?? '0', siblings: spentPath.siblings },
      nullifierInsert: wd.nullifierInsert,
      recordCommitmentHex: ZERO_32_HEX,
      preNoteRoot: wd.preState.noteRoot,
      postNoteRoot: wd.postState.noteRoot,
      preNullifierRoot: wd.preState.nullifierRoot,
      postNullifierRoot: wd.postState.nullifierRoot,
    },
    workDir: path.join(OUT, `pool-${i}-withdraw`),
    maxAttempts: 1,
    pinSeed: `forensics-w-${i}`,
  });
  for (let k = 0; k < N_VERIFIERS; k += 1) {
    if (!densW.densLocks[k].equals(bundle.carriers[k].lock)) {
      throw new Error(`pool-${i} withdraw lock drift @${k}`);
    }
  }
  console.log(JSON.stringify({
    phase: `pool-${i}-withdraw-densfuel`,
    gateOk: densW.result?.gateOk,
    pinBind: densW.pinBind && {
      nfail: densW.pinBind.nfail,
      searchIndex: densW.pinBind.searchIndex,
      changed: densW.pinBind.changed,
    },
  }));
  // Settle must use the pin-bound packet that densFuel proved.
  const wdFinal = { ...wd, packet: densW.packetBytes };
  const feeU = probe(feeCoin.txid, feeCoin.vout);
  if (!feeU || feeU.valueSats < 300_000n) {
    throw new Error(`pool-${i} fee coin insufficient`);
  }
  const wdSettled = await assembleProductSettle({
    kind: 'withdrawal',
    engineAction: wdFinal,
    dens: densW,
    bundle,
    wallet: hot,
    feeUtxo: feeU,
    category,
    profileId,
    withdrawalLockingBytecode: payout.lockingBytecode,
    withdrawalHashHex: payout.hashHex,
  });
  const withdrawTxid = broadcast(wdSettled.hex, `pool-${i}-withdraw`);
  const nextFee = {
    txid: withdrawTxid,
    vout: wdSettled.changeVout,
    valueSats: wdSettled.change,
  };
  // genesis change for next cat utxo
  const nextCat = {
    txid: genesisTxid,
    vout: N_VERIFIERS + 2,
    valueSats: genChange,
  };

  return {
    poolIndex: i,
    profileId,
    instanceId,
    genesisTxid,
    depositTxid,
    withdrawTxid,
    fundingAddress: funder.wallet.address,
    fundingOutpoint: `${funderU.txid}:${funderU.vout}`,
    payoutAddress: dest.address,
    noteCm: note.cm,
    nextCat,
    nextFee,
  };
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  process.env.V2_DENSFUEL_ATTEMPTS = '1';
  process.env.V2_DENSFUEL_TMPDIR = process.env.V2_DENSFUEL_TMPDIR || '/home/toorik/.cache/skd';
  const hot = loadHot();

  // Resume from prior fanout (keys + txid) to avoid re-funding
  if (process.env.V2_FANOUT_TXID && existsSync(path.join(OUT, 'ephemeral-keys.json'))) {
    const keys = JSON.parse(readFileSync(path.join(OUT, 'ephemeral-keys.json'), 'utf8'));
    const fanTxid = process.env.V2_FANOUT_TXID.toLowerCase();
    const funders = keys.funders.map((w, i) => ({
      wallet: {
        privateKey: Buffer.from(w.privateKeyHex, 'hex'),
        publicKey: Buffer.from(w.publicKeyHex, 'hex'),
        lockingBytecode: Buffer.from(w.lockingBytecodeHex, 'hex'),
        address: w.address,
        privateKeyHex: w.privateKeyHex,
        publicKeyHex: w.publicKeyHex,
        lockingBytecodeHex: w.lockingBytecodeHex,
      },
      txid: fanTxid,
      vout: i,
      valueSats: FUNDER_SATS,
    }));
    const dests = keys.dests.map((w) => ({
      privateKey: Buffer.from(w.privateKeyHex, 'hex'),
      publicKey: Buffer.from(w.publicKeyHex, 'hex'),
      lockingBytecode: Buffer.from(w.lockingBytecodeHex, 'hex'),
      address: w.address,
      privateKeyHex: w.privateKeyHex,
      publicKeyHex: w.publicKeyHex,
      lockingBytecodeHex: w.lockingBytecodeHex,
    }));
    const catCoins = Array.from({ length: N }, (_, i) => ({
      txid: fanTxid, vout: N + i, valueSats: 8_000_000n,
    }));
    let feeCoin = { txid: fanTxid, vout: 2 * N, valueSats: probe(fanTxid, 2 * N)?.valueSats || 0n };
    console.log(JSON.stringify({ phase: 'resume-fanout', fanTxid, fee: String(feeCoin.valueSats) }));
    const results = [];
    for (let i = 0; i < N; i += 1) {
      const r = await onePool(i, funders[i], dests[i], catCoins[i], hot, feeCoin);
      feeCoin = r.nextFee;
      results.push(r);
      console.log(JSON.stringify({
        phase: 'pool-ok', i,
        deposit: r.depositTxid, withdraw: r.withdrawTxid,
        from: r.fundingAddress, to: r.payoutAddress,
      }));
    }
    const publicTrace = {
      network: 'chipnet',
      purpose: 'onchain privacy forensics — adversarial deposit↔withdraw linking',
      topology: 'five independent 1-note pools',
      confBar: '0-conf-mempool',
      densFuelPolicy: 'single-shot densFuel; pin-envelope note selection only',
      height: rpc('getblockcount'),
      fanoutTxid: fanTxid,
      denominationSats: String(DENOMINATION_SATS),
      deposits: results.map((r) => ({
        index: r.poolIndex,
        settleTxid: r.depositTxid,
        fundingAddress: r.fundingAddress,
        fundingOutpoint: r.fundingOutpoint,
        genesisTxid: r.genesisTxid,
        instanceId: r.instanceId,
        noteCm: r.noteCm,
      })),
      withdrawals: results.map((r) => ({
        index: r.poolIndex,
        settleTxid: r.withdrawTxid,
        payoutAddress: r.payoutAddress,
      })),
      publicDepositAddresses: results.map((r) => r.fundingAddress),
      publicWithdrawAddresses: results.map((r) => r.payoutAddress),
      publicDepositTxids: results.map((r) => r.depositTxid),
      publicWithdrawTxids: results.map((r) => r.withdrawTxid),
    };
    const groundTruth = {
      note: 'CONFIDENTIAL — each pool is 1-note so link is poolIndex match',
      links: results.map((r) => ({
        depositIndex: r.poolIndex,
        depositTxid: r.depositTxid,
        depositFundingAddress: r.fundingAddress,
        withdrawIndex: r.poolIndex,
        withdrawTxid: r.withdrawTxid,
        payoutAddress: r.payoutAddress,
        instanceId: r.instanceId,
        genesisTxid: r.genesisTxid,
      })),
      funders: keys.funders,
      withdrawDests: keys.dests,
      results,
    };
    writeFileSync(path.join(OUT, 'public-trace.json'), `${JSON.stringify(publicTrace, null, 2)}\n`);
    writeFileSync(path.join(OUT, 'ground-truth.json'), `${JSON.stringify(groundTruth, null, 2)}\n`);
    writeFileSync(path.join(OUT, 'txids.txt'), [
      `fanout=${fanTxid}`,
      ...results.flatMap((r) => [
        `pool${r.poolIndex}_genesis=${r.genesisTxid}`,
        `pool${r.poolIndex}_deposit=${r.depositTxid}`,
        `pool${r.poolIndex}_withdraw=${r.withdrawTxid}`,
      ]),
    ].join('\n') + '\n');
    writeFileSync(path.join(OUT, 'links-ground-truth.txt'), [
      '# depositTxid fundingAddress → withdrawTxid payoutAddress',
      ...groundTruth.links.map((L) => (
        `${L.depositTxid} ${L.depositFundingAddress} → ${L.withdrawTxid} ${L.payoutAddress}`
      )),
    ].join('\n') + '\n');
    console.log(JSON.stringify({
      phase: 'done', ok: true, out: OUT,
      links: groundTruth.links.map((L) => ({
        from: L.depositFundingAddress,
        deposit: L.depositTxid,
        withdraw: L.withdrawTxid,
        to: L.payoutAddress,
      })),
    }, null, 2, (k, v) => (typeof v === 'bigint' ? v.toString() : v)));
    return;
  }

  // Fund: cold top-up 1.6 BCH if needed
  let bank = null;
  if (process.env.V2_MEMPOOL_OUTPOINTS) {
    const [t, v] = process.env.V2_MEMPOOL_OUTPOINTS.split(':');
    bank = probe(t, v);
  }
  const need = FUNDER_SATS * BigInt(N) + 80_000_000n;
  if (!bank || bank.valueSats < need) {
    const cold = loadCold();
    const coldSrc = process.env.COLD_SRC || '69c291a6709c4acbaae29b38851895ec39b326cb7aee1e4c5131ff4a57ab78cb:1';
    const [ct, cv] = coldSrc.split(':');
    const cu = probe(ct, cv);
    if (!cu || cu.valueSats < 170_000_000n) throw new Error('need cold UTXO ≥1.7 BCH');
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

  // Ensure vout0
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

  // Fan-out: N funders + residual bank for genesis cats/fees
  // Split bank into: N funder coins + N cat coins (~0.08 each) + fee residual
  const funders = [];
  const dests = [];
  for (let i = 0; i < N; i += 1) {
    funders.push(await makeP2pkh());
    dests.push(await makeP2pkh());
  }
  // Persist keys before any spend (gitignored .cache)
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
  const CAT_SATS = 8_000_000n;
  const fanFee = 3000n;
  const outs = [];
  for (let i = 0; i < N; i += 1) {
    outs.push({ valueSatoshis: FUNDER_SATS, lockingBytecode: Uint8Array.from(funders[i].lockingBytecode) });
  }
  for (let i = 0; i < N; i += 1) {
    outs.push({ valueSatoshis: CAT_SATS, lockingBytecode: Uint8Array.from(hot.lockingBytecode) });
  }
  const fixed = FUNDER_SATS * BigInt(N) + CAT_SATS * BigInt(N) + fanFee;
  if (bank.valueSats < fixed + 1_000_000n) throw new Error('bank too small for fanout');
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
  const catCoins = Array.from({ length: N }, (_, i) => ({
    txid: fanTxid, vout: N + i, valueSats: CAT_SATS,
  }));
  let feeCoin = { txid: fanTxid, vout: 2 * N, valueSats: residual };
  console.log(JSON.stringify({
    phase: 'fanout-ok',
    funderAddresses: funders.map((w) => w.address),
    destAddresses: dests.map((w) => w.address),
  }));

  const results = [];
  for (let i = 0; i < N; i += 1) {
    const r = await onePool(i, funderCoins[i], dests[i], catCoins[i], hot, feeCoin);
    feeCoin = r.nextFee;
    results.push(r);
    console.log(JSON.stringify({
      phase: 'pool-ok', i,
      deposit: r.depositTxid, withdraw: r.withdrawTxid,
      from: r.fundingAddress, to: r.payoutAddress,
    }));
  }

  // Shuffle presentation of links is identity (pool i deposit → pool i withdraw)
  // but deposit/withdraw order on chain is sequential; ground truth is 1:1 by pool.
  const publicTrace = {
    network: 'chipnet',
    purpose: 'onchain privacy forensics — adversarial deposit↔withdraw linking',
    topology: 'five independent 1-note pools (densFuel pin-safe first deposit)',
    confBar: '0-conf-mempool',
    densFuelPolicy: 'first-try only + pin-compatible transactionContextHash bind',
    height: rpc('getblockcount'),
    fanoutTxid: fanTxid,
    denominationSats: String(DENOMINATION_SATS),
    deposits: results.map((r) => ({
      index: r.poolIndex,
      settleTxid: r.depositTxid,
      fundingAddress: r.fundingAddress,
      fundingOutpoint: r.fundingOutpoint,
      genesisTxid: r.genesisTxid,
      instanceId: r.instanceId,
      noteCm: r.noteCm,
    })),
    withdrawals: results.map((r) => ({
      index: r.poolIndex,
      settleTxid: r.withdrawTxid,
      payoutAddress: r.payoutAddress,
    })),
    publicDepositAddresses: results.map((r) => r.fundingAddress),
    publicWithdrawAddresses: results.map((r) => r.payoutAddress),
    publicDepositTxids: results.map((r) => r.depositTxid),
    publicWithdrawTxids: results.map((r) => r.withdrawTxid),
  };
  const groundTruth = {
    note: 'CONFIDENTIAL — each pool is 1-note so link is poolIndex match',
    links: results.map((r) => ({
      depositIndex: r.poolIndex,
      depositTxid: r.depositTxid,
      depositFundingAddress: r.fundingAddress,
      withdrawIndex: r.poolIndex,
      withdrawTxid: r.withdrawTxid,
      payoutAddress: r.payoutAddress,
      instanceId: r.instanceId,
      genesisTxid: r.genesisTxid,
    })),
    funders: funders.map((w) => ({
      address: w.address,
      privateKeyHex: w.privateKeyHex,
      lockingBytecodeHex: w.lockingBytecodeHex,
    })),
    withdrawDests: dests.map((w) => ({
      address: w.address,
      privateKeyHex: w.privateKeyHex,
      lockingBytecodeHex: w.lockingBytecodeHex,
    })),
    results,
  };
  const json = (obj) => JSON.stringify(obj, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2);
  writeFileSync(path.join(OUT, 'public-trace.json'), `${json(publicTrace)}\n`);
  writeFileSync(path.join(OUT, 'ground-truth.json'), `${json(groundTruth)}\n`);
  writeFileSync(path.join(OUT, 'txids.txt'), [
    `fanout=${fanTxid}`,
    ...results.flatMap((r) => [
      `pool${r.poolIndex}_genesis=${r.genesisTxid}`,
      `pool${r.poolIndex}_deposit=${r.depositTxid}`,
      `pool${r.poolIndex}_withdraw=${r.withdrawTxid}`,
    ]),
  ].join('\n') + '\n');
  writeFileSync(path.join(OUT, 'links-ground-truth.txt'), [
    '# depositTxid fundingAddress → withdrawTxid payoutAddress',
    ...groundTruth.links.map((L) => (
      `${L.depositTxid} ${L.depositFundingAddress} → ${L.withdrawTxid} ${L.payoutAddress}`
    )),
  ].join('\n') + '\n');
  console.log(json({
    phase: 'done', ok: true, out: OUT,
    links: groundTruth.links.map((L) => ({
      from: L.depositFundingAddress,
      deposit: L.depositTxid,
      withdraw: L.withdrawTxid,
      to: L.payoutAddress,
    })),
  }));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
