#!/usr/bin/env node
/**
 * Live Chipnet contention (skeptic gap):
 *   Two clients race a deposit from the same empty tip.
 *   Winner settles on-chain; loser gets spent-tip reject; loser re-syncs,
 *   re-proves against winner tip, settles second deposit.
 *
 * 0-conf mempool bar. Requires V2_MEMPOOL_OUTPOINTS fund ≥0.25 BCH.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeTransaction, binToHex, generateSigningSerializationBch, hash256,
  instantiateSecp256k1, SigningSerializationTypeBch,
} from '@bitauth/libauth';
import { NETWORK_CHIPNET } from '../constants.mjs';
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
} from '../operator/product-settle.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const WALLET_DIR = process.env.V2_CHIPNET_WALLET_DIR
  || '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const OUT = path.join(ROOT, '.cache/v2-direct-live-contention');

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
    method, ...tokens,
  ].join(' ');
  const out = execFileSync('ssh', ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', 'layer1-node', cmd], {
    encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
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
  console.log(JSON.stringify({
    phase: `${label}-accept`, allowed: row?.allowed,
    reason: row?.['reject-reason'] || null, txid: row?.txid,
  }));
  if (row?.allowed === false) {
    return { ok: false, reason: row?.['reject-reason'] || 'rejected', row };
  }
  const txid = String(rpc('sendrawtransaction', [hex])).toLowerCase();
  console.log(JSON.stringify({ phase: `${label}-broadcast`, txid }));
  return { ok: true, txid, row };
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

async function main() {
  mkdirSync(OUT, { recursive: true });
  const wallet = loadWallet();
  const profileId = createHash('sha256').update('v2-live-contention-profile').digest('hex');

  let fund = null;
  if (process.env.V2_MEMPOOL_OUTPOINTS) {
    const [txid, vout] = process.env.V2_MEMPOOL_OUTPOINTS.split(':');
    fund = probeOutpoint(txid, vout);
  }
  // residual after capacity deposits
  if (!fund) {
    fund = probeOutpoint('ac65f7f865f1b6f8397bd12261b92b9cf044275b3e3f7541ed268d06db6554ff', 9)
      || probeOutpoint('ac65f7f865f1b6f8397bd12261b92b9cf044275b3e3f7541ed268d06db6554ff', 10);
  }
  if (!fund || fund.valueSats < 20_000_000n) {
    throw new Error('need fund ≥0.20 BCH via V2_MEMPOOL_OUTPOINTS');
  }

  let catUtxo = fund;
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
    const r = broadcast(binToHex(encodeTransaction(tx)), 'split');
    if (!r.ok) throw new Error(`split failed: ${r.reason}`);
    catUtxo = { txid: r.txid, vout: 0, valueSats: half };
    fund = { txid: r.txid, vout: 1, valueSats: change };
  }

  const category = Buffer.from(catUtxo.txid, 'hex');
  const instanceId = category.toString('hex');
  const bindingLock = productBindingLock();
  const alice = createAccountKeys();
  const aliceAddr = shieldAddress({
    networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
  });

  // Pin densFuel locks via client-A deposit preview
  const preA = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: 32,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const noteA = freshOutputNote({
    profileId, instanceId, authority: aliceAddr.authority,
    postActionSequence: 1,
    viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
  });
  const prevA = preA.deposit({
    outputNoteLeaf: noteA.outputNoteLeaf,
    encryptedRecord: noteA.encryptedRecord,
    transactionContextHash: createHash('sha256').update('contention-A').digest('hex'),
  });
  const densPin = await buildDensfuelForPacket({
    packetBytes: prevA.packet,
    expanded: {
      note: {
        authority: aliceAddr.authority,
        rho: noteA.rho, r: noteA.r, cm: noteA.cm,
      },
      path: { index: prevA.noteAppend.index, siblings: prevA.noteAppend.path.siblings },
      encryption: {
        esk: noteA.esk,
        viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
        encryptedRecord: noteA.encryptedRecord,
      },
      recordCommitmentHex: noteA.recordCommitment,
      preNoteRoot: prevA.preState.noteRoot,
      postNoteRoot: prevA.postState.noteRoot,
      preNullifierRoot: prevA.preState.nullifierRoot,
      postNullifierRoot: prevA.postState.nullifierRoot,
    },
    workDir: path.join(OUT, 'pin'),
  });

  const stateCov = await createStateCovenant({
    bindingLock, profileId, instanceIdCategory: category,
    stateBaseSats: STATE_BASE, carrierCount: N_VERIFIERS,
  });
  const emptyPool = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: 32,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const commitment0 = encodePoolStateV2(emptyPool.tip());
  const genFee = 3000n;
  const needed = CARRIER_BASE * BigInt(N_VERIFIERS) + BINDING_BASE + STATE_BASE + genFee;
  const genChange = catUtxo.valueSats - needed;
  if (genChange < 546n) throw new Error('genesis change dust');
  const genesisTx = {
    version: 2, locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(catUtxo.txid, 'hex')),
      outpointIndex: catUtxo.vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      ...densPin.densLocks.map((lock) => ({
        valueSatoshis: CARRIER_BASE,
        lockingBytecode: Uint8Array.from(lock),
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
      { valueSatoshis: genChange, lockingBytecode: Uint8Array.from(wallet.lockingBytecode) },
    ],
  };
  genesisTx.inputs[0].unlockingBytecode = Uint8Array.from(await signP2pkh(genesisTx, 0, [{
    valueSatoshis: catUtxo.valueSats,
    lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
  }], wallet));
  const g = broadcast(binToHex(encodeTransaction(genesisTx)), 'genesis');
  if (!g.ok) throw new Error(`genesis failed: ${g.reason}`);
  const genesisTxid = g.txid;

  const emptyBundle = {
    carriers: densPin.densLocks.map((lock, i) => ({
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
  // Split genesis change for two fee UTXOs so both clients have funding
  const changeVout = N_VERIFIERS + 2;
  const halfFee = genChange / 2n - 1000n;
  const feeSplitTx = {
    version: 2, locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(genesisTxid, 'hex')),
      outpointIndex: changeVout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      { valueSatoshis: halfFee, lockingBytecode: Uint8Array.from(wallet.lockingBytecode) },
      { valueSatoshis: genChange - halfFee - 500n, lockingBytecode: Uint8Array.from(wallet.lockingBytecode) },
    ],
  };
  feeSplitTx.inputs[0].unlockingBytecode = Uint8Array.from(await signP2pkh(feeSplitTx, 0, [{
    valueSatoshis: genChange,
    lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
  }], wallet));
  const fs = broadcast(binToHex(encodeTransaction(feeSplitTx)), 'fee-split');
  if (!fs.ok) throw new Error(`fee-split failed: ${fs.reason}`);
  const feeA = { txid: fs.txid, vout: 0, valueSats: halfFee };
  const feeB = { txid: fs.txid, vout: 1, valueSats: genChange - halfFee - 500n };

  // Client A and B both build deposit from empty tip
  async function buildDeposit(label, note) {
    const eng = createPoolEngineV2({
      profileId, instanceId, networkId: NETWORK_CHIPNET,
      maximumLiveNotes: 32,
      noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
    });
    const act = eng.deposit({
      outputNoteLeaf: note.outputNoteLeaf,
      encryptedRecord: note.encryptedRecord,
      transactionContextHash: createHash('sha256').update(label).digest('hex'),
    });
    const dens = await buildDensfuelForPacket({
      packetBytes: act.packet,
      expanded: {
        note: {
          authority: aliceAddr.authority,
          rho: note.rho, r: note.r, cm: note.cm,
        },
        path: { index: act.noteAppend.index, siblings: act.noteAppend.path.siblings },
        encryption: {
          esk: note.esk,
          viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
          encryptedRecord: note.encryptedRecord,
        },
        recordCommitmentHex: note.recordCommitment,
        preNoteRoot: act.preState.noteRoot,
        postNoteRoot: act.postState.noteRoot,
        preNullifierRoot: act.preState.nullifierRoot,
        postNullifierRoot: act.postState.nullifierRoot,
      },
      workDir: path.join(OUT, label),
    });
    return { eng, act, dens, note };
  }

  const noteB = freshOutputNote({
    profileId, instanceId, authority: aliceAddr.authority,
    postActionSequence: 1,
    viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
  });
  // A reuses noteA (seq 1), B uses noteB (also seq 1 from empty tip) — race
  const clientA = await buildDeposit('clientA', noteA);
  const clientB = await buildDeposit('clientB', noteB);

  const settleA = await assembleProductSettle({
    kind: 'deposit',
    engineAction: clientA.act,
    dens: clientA.dens,
    bundle: emptyBundle,
    wallet,
    feeUtxo: feeA,
    category,
    profileId,
  });
  const win = broadcast(settleA.hex, 'clientA');
  if (!win.ok) throw new Error(`winner failed: ${win.reason}`);

  const settleB1 = await assembleProductSettle({
    kind: 'deposit',
    engineAction: clientB.act,
    dens: clientB.dens,
    bundle: emptyBundle, // stale tip
    wallet,
    feeUtxo: feeB,
    category,
    profileId,
  });
  const lose1 = broadcast(settleB1.hex, 'clientB-stale');
  const loserStaleRejected = lose1.ok === false;

  // B re-syncs: replay A deposit, then deposit noteB as second note
  const engB2 = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: 32,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  engB2.deposit({
    outputNoteLeaf: noteA.outputNoteLeaf,
    encryptedRecord: noteA.encryptedRecord,
    transactionContextHash: createHash('sha256').update('contention-A').digest('hex'),
  });
  const noteB2 = freshOutputNote({
    profileId, instanceId, authority: aliceAddr.authority,
    postActionSequence: 2,
    viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
  });
  const actB2 = engB2.deposit({
    outputNoteLeaf: noteB2.outputNoteLeaf,
    encryptedRecord: noteB2.encryptedRecord,
    transactionContextHash: createHash('sha256').update('clientB-reprove').digest('hex'),
  });
  const densB2 = await buildDensfuelForPacket({
    packetBytes: actB2.packet,
    expanded: {
      note: {
        authority: aliceAddr.authority,
        rho: noteB2.rho, r: noteB2.r, cm: noteB2.cm,
      },
      path: { index: actB2.noteAppend.index, siblings: actB2.noteAppend.path.siblings },
      encryption: {
        esk: noteB2.esk,
        viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
        encryptedRecord: noteB2.encryptedRecord,
      },
      recordCommitmentHex: noteB2.recordCommitment,
      preNoteRoot: actB2.preState.noteRoot,
      postNoteRoot: actB2.postState.noteRoot,
      preNullifierRoot: actB2.preState.nullifierRoot,
      postNullifierRoot: actB2.postState.nullifierRoot,
    },
    workDir: path.join(OUT, 'clientB-reprove'),
  });
  const nextBundle = rollBundleAfterSettle({
    settleTxid: win.txid,
    densLocks: settleA.densLocks,
    bindingLockHex: settleA.bindingLockHex,
    stateLockingBytecode: settleA.stateLockingBytecode,
    postCommitment: settleA.postCommitment,
    postStateValue: STATE_BASE + BigInt(clientA.act.postState.reserveSats),
  });
  const settleB2 = await assembleProductSettle({
    kind: 'deposit',
    engineAction: actB2,
    dens: densB2,
    bundle: nextBundle,
    wallet,
    feeUtxo: feeB,
    category,
    profileId,
  });
  const lose2 = broadcast(settleB2.hex, 'clientB-reprove');
  const loserSettledAfterReprove = lose2.ok === true;

  const evidence = {
    network: 'chipnet',
    height: rpc('getblockcount'),
    topology: 'two-client deposit race on same empty tip',
    genesisTxid,
    winnerTxid: win.txid,
    loserStaleRejected,
    loserStaleReason: lose1.reason || null,
    loserReproveTxid: lose2.txid || null,
    loserSettledAfterReprove,
    liveOnChain: true,
    needsReproof: loserStaleRejected && loserSettledAfterReprove,
    ok: loserStaleRejected && loserSettledAfterReprove,
  };
  writeFileSync(path.join(OUT, 'contention.json'), `${JSON.stringify(evidence, null, 2)}\n`);
  writeFileSync(path.join(OUT, 'txids.txt'), [
    `genesis=${genesisTxid}`,
    `winner=${win.txid}`,
    `loserReprove=${lose2.txid || 'none'}`,
    `loserStaleRejected=${loserStaleRejected}`,
  ].join('\n') + '\n');
  console.log(JSON.stringify({ phase: 'done', ...evidence }));
  if (!evidence.ok) process.exitCode = 2;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
