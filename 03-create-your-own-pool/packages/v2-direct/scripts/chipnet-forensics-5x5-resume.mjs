#!/usr/bin/env node
/**
 * Resume forensics 5x5 from checkpoint.json after densFuel intermittency mid-deposits.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DENOMINATION_SATS, NETWORK_CHIPNET, ZERO_32_HEX } from '../constants.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import { CIRCUIT_TREE_DEPTH } from '../prove/witness.mjs';
import { buildDensfuelForPacket, N_VERIFIERS } from '../operator/densfuel-build.mjs';
import {
  assembleProductSettle, rollBundleAfterSettle, STATE_BASE,
} from '../operator/product-settle.mjs';
import { resolveWithdrawalPayout } from '../operator/withdraw-payout.mjs';
import { randomBytes } from 'node:crypto';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const WALLET_DIR = process.env.V2_CHIPNET_WALLET_DIR
  || '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const OUT = path.join(ROOT, '.cache/v2-direct-forensics-5x5');
const N = 5;

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
  };
}
function broadcast(hex, label) {
  const accept = rpc('testmempoolaccept', [[hex]]);
  const row = Array.isArray(accept) ? accept[0] : accept;
  console.log(JSON.stringify({
    phase: `${label}-accept`, allowed: row?.allowed,
    reason: row?.['reject-reason'] || null, txid: row?.txid,
  }));
  if (row?.allowed === false) throw new Error(`${label} rejected: ${JSON.stringify(row)}`);
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
function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i -= 1) {
    const j = randomBytes(1)[0] % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}
function walletFromHex(o) {
  return {
    privateKey: Buffer.from(o.privateKeyHex, 'hex'),
    publicKey: Buffer.from(o.publicKeyHex, 'hex'),
    lockingBytecode: Buffer.from(o.lockingBytecodeHex, 'hex'),
    address: o.address,
    privateKeyHex: o.privateKeyHex,
    publicKeyHex: o.publicKeyHex,
    lockingBytecodeHex: o.lockingBytecodeHex,
  };
}
function bundleFromCk(b) {
  return {
    carriers: b.carriers.map((c) => ({
      txid: c.txid, vout: c.vout, value: BigInt(c.value),
      lock: Buffer.from(c.lockHex, 'hex'),
    })),
    binding: {
      txid: b.binding.txid, vout: b.binding.vout,
      value: BigInt(b.binding.value), lock: Buffer.from(b.binding.lockHex, 'hex'),
    },
    state: {
      txid: b.state.txid, vout: b.state.vout,
      value: BigInt(b.state.value),
      lock: Buffer.from(b.state.lockHex, 'hex'),
      commitment: Buffer.from(b.state.commitmentHex, 'hex'),
    },
  };
}

async function main() {
  const ckPath = path.join(OUT, 'checkpoint.json');
  if (!existsSync(ckPath)) throw new Error('missing checkpoint.json');
  const ck = JSON.parse(readFileSync(ckPath, 'utf8'));
  const {
    profileId, instanceId, genesisTxid, fanTxid,
    deposits, funderCoins, withdrawDests, shieldAccounts: saRaw,
  } = ck;
  let bundle = bundleFromCk(ck.bundle);
  let hotFeeCoin = {
    txid: ck.hotFeeCoin.txid,
    vout: ck.hotFeeCoin.vout,
    valueSats: BigInt(ck.hotFeeCoin.valueSats),
  };
  const category = Buffer.from(instanceId, 'hex');
  const hot = loadHot();
  const funders = funderCoins.map((c) => ({
    ...walletFromHex(c),
    txid: c.txid, vout: c.vout, valueSats: BigInt(c.valueSats), address: c.address,
  }));
  const dests = withdrawDests.map(walletFromHex);

  // Rebuild pool to tip by replaying deposits
  const pool = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: 32,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  for (const d of deposits) {
    pool.deposit({
      outputNoteLeaf: d.note.outputNoteLeaf,
      encryptedRecord: Buffer.from(d.note.encryptedRecordHex, 'hex'),
      transactionContextHash: createHash('sha256').update(`forensics-dep-${d.index}`).digest('hex'),
    });
  }

  // Checkpoint only stores sk/V/authority (not full S) — enough for prove + deposit/withdraw
  const shieldAccounts = saRaw.map((sa, i) => ({
    account: { sk: sa.sk, V: sa.V },
    authority: sa.authority,
    index: i,
  }));

  async function doDeposit(i) {
    const sa = shieldAccounts[i];
    const note = freshOutputNote({
      profileId, instanceId,
      authority: sa.authority,
      postActionSequence: BigInt(i + 1),
      viewPoint: [frFromHex(sa.account.V[0]), frFromHex(sa.account.V[1])],
    });
    const act = pool.deposit({
      outputNoteLeaf: note.outputNoteLeaf,
      encryptedRecord: note.encryptedRecord,
      transactionContextHash: createHash('sha256').update(`forensics-dep-${i}`).digest('hex'),
    });
    const dens = await buildDensfuelForPacket({
      packetBytes: act.packet,
      expanded: {
        note: {
          authority: sa.authority,
          rho: note.rho, r: note.r, cm: note.cm,
        },
        path: { index: act.noteAppend.index, siblings: act.noteAppend.path.siblings },
        encryption: {
          esk: note.esk,
          viewPoint: [frFromHex(sa.account.V[0]), frFromHex(sa.account.V[1])],
          encryptedRecord: note.encryptedRecord,
        },
        recordCommitmentHex: note.recordCommitment,
        preNoteRoot: act.preState.noteRoot,
        postNoteRoot: act.postState.noteRoot,
        preNullifierRoot: act.preState.nullifierRoot,
        postNullifierRoot: act.postState.nullifierRoot,
      },
      workDir: path.join(OUT, `deposit-${i}-resume`),
      maxAttempts: 1, // first-try only — never multi-retry
    });
    for (let k = 0; k < N_VERIFIERS; k += 1) {
      if (!dens.densLocks[k].equals(bundle.carriers[k].lock)) {
        throw new Error(`lock drift deposit ${i} @${k}`);
      }
    }
    const coin = funders[i];
    const u = probe(coin.txid, coin.vout);
    if (!u) throw new Error(`funder ${i} spent ${coin.txid}:${coin.vout}`);
    const settled = await assembleProductSettle({
      kind: 'deposit',
      engineAction: act,
      dens,
      bundle,
      wallet: coin,
      feeUtxo: u,
      category,
      profileId,
    });
    const txid = broadcast(settled.hex, `deposit-${i}`);
    bundle = rollBundleAfterSettle({
      settleTxid: txid,
      densLocks: settled.densLocks,
      bindingLockHex: settled.bindingLockHex,
      stateLockingBytecode: settled.stateLockingBytecode,
      postCommitment: settled.postCommitment,
      postStateValue: STATE_BASE + BigInt(act.postState.reserveSats),
    });
    const entry = {
      index: i,
      settleTxid: txid,
      fundingOutpoint: `${u.txid}:${u.vout}`,
      fundingAddress: coin.address,
      fundingValueSats: String(u.valueSats),
      note: {
        rho: note.rho, r: note.r, cm: note.cm,
        outputNoteLeaf: note.outputNoteLeaf,
        encryptedRecordHex: Buffer.from(note.encryptedRecord).toString('hex'),
        recordCommitment: note.recordCommitment,
        esk: note.esk,
        sk: sa.account.sk,
        authority: sa.authority,
      },
      shieldAccountIndex: i,
      digest: act.digest,
      packetDigest: createHash('sha256').update(act.packet).digest('hex'),
    };
    deposits.push(entry);
    console.log(JSON.stringify({
      phase: 'deposit-ok', i, txid, fundingAddress: coin.address, cm: note.cm,
    }));
    return entry;
  }

  // Continue deposits from deposits.length .. N-1
  for (let i = deposits.length; i < N; i += 1) {
    await doDeposit(i);
  }

  // Withdrawals shuffled
  const noteOrder = shuffle([...Array(N).keys()]);
  const withdrawals = [];
  for (let w = 0; w < N; w += 1) {
    const noteIdx = noteOrder[w];
    const dep = deposits[noteIdx];
    const dest = dests[w];
    const payout = resolveWithdrawalPayout({
      toCashAddr: dest.address,
      defaultLockingBytecode: dest.lockingBytecode,
    });
    const sa = shieldAccounts[noteIdx];
    const wd = pool.withdraw({
      spendSk: dep.note.sk,
      spendRho: dep.note.rho,
      spendCm: dep.note.cm,
      withdrawalLockingBytecodeHash: payout.hashHex,
      transactionContextHash: createHash('sha256').update(`forensics-wd-${w}`).digest('hex'),
    });
    const spentPath = pool.noteTree.membershipPath(String(noteIdx));
    const dens = await buildDensfuelForPacket({
      packetBytes: wd.packet,
      expanded: {
        note: {
          authority: sa.authority,
          rho: dep.note.rho, r: dep.note.r, cm: dep.note.cm,
          sk: dep.note.sk,
          spentOutputLeaf: dep.note.outputNoteLeaf,
        },
        path: { index: spentPath.index ?? String(noteIdx), siblings: spentPath.siblings },
        nullifierInsert: wd.nullifierInsert,
        recordCommitmentHex: ZERO_32_HEX,
        preNoteRoot: wd.preState.noteRoot,
        postNoteRoot: wd.postState.noteRoot,
        preNullifierRoot: wd.preState.nullifierRoot,
        postNullifierRoot: wd.postState.nullifierRoot,
      },
      workDir: path.join(OUT, `withdraw-${w}`),
      maxAttempts: 1, // first-try only — never multi-retry
    });
    for (let k = 0; k < N_VERIFIERS; k += 1) {
      if (!dens.densLocks[k].equals(bundle.carriers[k].lock)) {
        throw new Error(`lock drift withdraw ${w}`);
      }
    }
    const feeU = probe(hotFeeCoin.txid, hotFeeCoin.vout);
    if (!feeU || feeU.valueSats < 300_000n) {
      throw new Error(`hot fee coin low ${hotFeeCoin.txid}:${hotFeeCoin.vout}`);
    }
    const settled = await assembleProductSettle({
      kind: 'withdrawal',
      engineAction: wd,
      dens,
      bundle,
      wallet: hot,
      feeUtxo: feeU,
      category,
      profileId,
      withdrawalLockingBytecode: payout.lockingBytecode,
      withdrawalHashHex: payout.hashHex,
    });
    const txid = broadcast(settled.hex, `withdraw-${w}`);
    bundle = rollBundleAfterSettle({
      settleTxid: txid,
      densLocks: settled.densLocks,
      bindingLockHex: settled.bindingLockHex,
      stateLockingBytecode: settled.stateLockingBytecode,
      postCommitment: settled.postCommitment,
      postStateValue: STATE_BASE + BigInt(wd.postState.reserveSats),
    });
    hotFeeCoin = { txid, vout: settled.changeVout, valueSats: settled.change };
    withdrawals.push({
      withdrawIndex: w,
      settleTxid: txid,
      spentDepositIndex: noteIdx,
      spentDepositTxid: dep.settleTxid,
      payoutAddress: dest.address,
      payoutLockingBytecodeHex: dest.lockingBytecodeHex,
      withdrawalHashHex: payout.hashHex,
      feeOutpoint: `${feeU.txid}:${feeU.vout}`,
      digest: wd.digest,
    });
    console.log(JSON.stringify({
      phase: 'withdraw-ok', w, txid, spentDepositIndex: noteIdx, payoutAddress: dest.address,
    }));
  }

  const publicTrace = {
    network: 'chipnet',
    purpose: 'onchain privacy forensics — adversarial deposit↔withdraw linking',
    confBar: '0-conf-mempool',
    height: rpc('getblockcount'),
    profileId,
    instanceId,
    category: instanceId,
    genesisTxid,
    fanoutTxid: fanTxid,
    denominationSats: String(DENOMINATION_SATS),
    deposits: deposits.map((d) => ({
      index: d.index,
      settleTxid: d.settleTxid,
      fundingOutpoint: d.fundingOutpoint,
      fundingAddress: d.fundingAddress,
      fundingValueSats: d.fundingValueSats,
      noteCm: d.note.cm,
      packetDigest: d.packetDigest,
    })),
    withdrawals: withdrawals.map((w) => ({
      withdrawIndex: w.withdrawIndex,
      settleTxid: w.settleTxid,
      payoutAddress: w.payoutAddress,
      withdrawalHashHex: w.withdrawalHashHex,
      feeOutpoint: w.feeOutpoint,
    })),
    publicDepositAddresses: deposits.map((d) => d.fundingAddress),
    publicWithdrawAddresses: withdrawals.map((w) => w.payoutAddress),
    publicDepositTxids: deposits.map((d) => d.settleTxid),
    publicWithdrawTxids: withdrawals.map((w) => w.settleTxid),
  };
  const groundTruth = {
    note: 'CONFIDENTIAL — deposit index → withdraw mapping for scoring',
    shuffleNoteOrder: noteOrder,
    links: withdrawals.map((w) => ({
      depositIndex: w.spentDepositIndex,
      depositTxid: w.spentDepositTxid,
      depositFundingAddress: deposits[w.spentDepositIndex].fundingAddress,
      withdrawIndex: w.withdrawIndex,
      withdrawTxid: w.settleTxid,
      payoutAddress: w.payoutAddress,
    })),
    deposits,
    withdrawals,
    depositFunders: funders.map((w) => ({
      address: w.address,
      privateKeyHex: w.privateKeyHex,
      publicKeyHex: w.publicKeyHex,
      lockingBytecodeHex: w.lockingBytecodeHex,
    })),
    withdrawDests: dests.map((w) => ({
      address: w.address,
      privateKeyHex: w.privateKeyHex,
      publicKeyHex: w.publicKeyHex,
      lockingBytecodeHex: w.lockingBytecodeHex,
    })),
  };
  writeFileSync(path.join(OUT, 'public-trace.json'), `${JSON.stringify(publicTrace, null, 2)}\n`);
  writeFileSync(path.join(OUT, 'ground-truth.json'), `${JSON.stringify(groundTruth, null, 2)}\n`);
  writeFileSync(path.join(OUT, 'txids.txt'), [
    `genesis=${genesisTxid}`,
    `fanout=${fanTxid}`,
    ...deposits.map((d, i) => `deposit${i}=${d.settleTxid}`),
    ...withdrawals.map((w, i) => `withdraw${i}=${w.settleTxid}`),
  ].join('\n') + '\n');
  writeFileSync(path.join(OUT, 'links-ground-truth.txt'), [
    '# depositIndex depositTxid fundingAddress → withdrawIndex withdrawTxid payoutAddress',
    ...groundTruth.links.map((L) => (
      `${L.depositIndex} ${L.depositTxid} ${L.depositFundingAddress} → ${L.withdrawIndex} ${L.withdrawTxid} ${L.payoutAddress}`
    )),
  ].join('\n') + '\n');
  console.log(JSON.stringify({
    phase: 'done', ok: true,
    deposits: deposits.map((d) => d.settleTxid),
    withdrawals: withdrawals.map((w) => w.settleTxid),
    groundTruthLinks: groundTruth.links,
    out: OUT,
  }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
