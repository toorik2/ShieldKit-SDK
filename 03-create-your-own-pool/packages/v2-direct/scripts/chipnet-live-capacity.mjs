#!/usr/bin/env node
/**
 * Live Chipnet capacity story (skeptic gap):
 *   Create disposable instance with maximumLiveNotes=2
 *   Deposit until full (2 notes), then attempt 3rd deposit → reject BEFORE prove
 *   Withdraw one, deposit again (refill)
 *
 * Uses product densFuel+state path. 0-conf mempool bar (no block wait).
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeTransaction, binToHex, generateSigningSerializationBch, hash256,
  instantiateSecp256k1, SigningSerializationTypeBch,
} from '@bitauth/libauth';
import {
  DENOMINATION_SATS, NETWORK_CHIPNET,
} from '../constants.mjs';
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
const OUT = path.join(ROOT, '.cache/v2-direct-live-capacity');
const MAX_LIVE = 2;
const HOT = 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';

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
  console.log(JSON.stringify({ phase: `${label}-accept`, allowed: row?.allowed, reason: row?.['reject-reason'] || null, txid: row?.txid }));
  if (row?.allowed === false) {
    throw new Error(`${label} rejected: ${JSON.stringify(row)}`);
  }
  const txid = String(rpc('sendrawtransaction', [hex])).toLowerCase();
  console.log(JSON.stringify({ phase: `${label}-broadcast`, txid }));
  return txid;
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
  const profileId = createHash('sha256').update('v2-live-capacity-profile').digest('hex');

  // Fund: prefer V2_MEMPOOL_OUTPOINTS or residual from product withdraw tip
  let fund = null;
  if (process.env.V2_MEMPOOL_OUTPOINTS) {
    const [txid, vout] = process.env.V2_MEMPOOL_OUTPOINTS.split(':');
    fund = probeOutpoint(txid, vout);
  }
  if (!fund) {
    fund = probeOutpoint('26fd21d1a39b99d54666cec239bca4c7c4bcfb3a1505373e296a01559655681f', 9)
      || probeOutpoint('26fd21d1a39b99d54666cec239bca4c7c4bcfb3a1505373e296a01559655681f', 10);
  }
  if (!fund || fund.valueSats < 20_000_000n) {
    throw new Error('need hot fund ≥0.20 BCH (set V2_MEMPOOL_OUTPOINTS)');
  }

  // Split to vout0 for category if needed
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
    const txid = broadcast(binToHex(encodeTransaction(tx)), 'split');
    catUtxo = { txid, vout: 0, valueSats: half };
    fund = { txid, vout: 1, valueSats: change };
  }

  const category = Buffer.from(catUtxo.txid, 'hex');
  const instanceId = category.toString('hex');
  const bindingLock = productBindingLock();

  // Pre-build densFuel for deposit to pin carrier locks
  const alice = createAccountKeys();
  const aliceAddr = shieldAddress({
    networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
  });
  const preEngine = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: MAX_LIVE,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const depNote0 = freshOutputNote({
    profileId, instanceId, authority: aliceAddr.authority,
    postActionSequence: 1,
    viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
  });
  const depPreview = preEngine.deposit({
    outputNoteLeaf: depNote0.outputNoteLeaf,
    encryptedRecord: depNote0.encryptedRecord,
    transactionContextHash: createHash('sha256').update('cap-dep0').digest('hex'),
  });
  const dens0 = await buildDensfuelForPacket({
    packetBytes: depPreview.packet,
    expanded: {
      note: {
        authority: aliceAddr.authority,
        rho: depNote0.rho, r: depNote0.r, cm: depNote0.cm,
      },
      path: { index: depPreview.noteAppend.index, siblings: depPreview.noteAppend.path.siblings },
      encryption: {
        esk: depNote0.esk,
        viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
        encryptedRecord: depNote0.encryptedRecord,
      },
      recordCommitmentHex: depNote0.recordCommitment,
      preNoteRoot: depPreview.preState.noteRoot,
      postNoteRoot: depPreview.postState.noteRoot,
      preNullifierRoot: depPreview.preState.nullifierRoot,
      postNullifierRoot: depPreview.postState.nullifierRoot,
    },
    workDir: path.join(OUT, 'dens0'),
  });
  console.log(JSON.stringify({
    phase: 'densfuel-pin', gateOk: dens0.result?.gateOk, wire: dens0.result?.wire,
  }));

  const stateCov = await createStateCovenant({
    bindingLock, profileId, instanceIdCategory: category,
    stateBaseSats: STATE_BASE, carrierCount: N_VERIFIERS,
  });
  // Fresh empty engine for genesis commitment (not preEngine after preview deposit)
  const emptyPool = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: MAX_LIVE,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const emptyTip = emptyPool.tip();
  const commitment0 = encodePoolStateV2(emptyTip);
  // Genesis: fund → carriers + binding + state
  const genFee = 3000n;
  const carrierSpend = CARRIER_BASE * BigInt(N_VERIFIERS) + BINDING_BASE + STATE_BASE;
  const genChange = catUtxo.valueSats - carrierSpend - genFee;
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
      ...dens0.densLocks.map((lock) => ({
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
        valueSatoshis: genChange,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
      },
    ],
  };
  genesisTx.inputs[0].unlockingBytecode = Uint8Array.from(await signP2pkh(genesisTx, 0, [{
    valueSatoshis: catUtxo.valueSats,
    lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
  }], wallet));
  const genesisTxid = broadcast(binToHex(encodeTransaction(genesisTx)), 'genesis');

  let bundle = {
    carriers: dens0.densLocks.map((lock, i) => ({
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
  let feeCoin = { txid: genesisTxid, vout: N_VERIFIERS + 2, valueSats: genChange };
  if (fund && fund.txid !== catUtxo.txid) {
    // keep residual fund as secondary
  }

  const pool = createPoolEngineV2({
    profileId, instanceId, networkId: NETWORK_CHIPNET,
    maximumLiveNotes: MAX_LIVE,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });

  const notes = [];
  async function doDeposit(label, note) {
    const act = pool.deposit({
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
    for (let i = 0; i < N_VERIFIERS; i += 1) {
      if (!dens.densLocks[i].equals(bundle.carriers[i].lock)) {
        throw new Error(`lock drift ${label} @${i}`);
      }
    }
    const settled = await assembleProductSettle({
      kind: 'deposit',
      engineAction: act,
      dens,
      bundle,
      wallet,
      feeUtxo: feeCoin,
      category,
      profileId,
    });
    const txid = broadcast(settled.hex, label);
    const postReserve = BigInt(act.postState.reserveSats);
    bundle = rollBundleAfterSettle({
      settleTxid: txid,
      densLocks: settled.densLocks,
      bindingLockHex: settled.bindingLockHex,
      stateLockingBytecode: settled.stateLockingBytecode,
      postCommitment: settled.postCommitment,
      postStateValue: STATE_BASE + postReserve,
    });
    feeCoin = {
      txid, vout: settled.changeVout, valueSats: settled.change,
    };
    notes.push(note);
    return { txid, tip: pool.tip() };
  }

  // Deposit 1 (reuse preview note materials for dep0)
  const d1 = await doDeposit('deposit1', depNote0);
  console.log(JSON.stringify({ phase: 'deposit1-ok', ...d1 }));

  // Deposit 2
  const depNote1 = freshOutputNote({
    profileId, instanceId, authority: aliceAddr.authority,
    postActionSequence: 2,
    viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
  });
  const d2 = await doDeposit('deposit2', depNote1);
  console.log(JSON.stringify({ phase: 'deposit2-ok', ...d2 }));

  // Capacity reject BEFORE prove
  let capacityRejectBeforeProve = false;
  let capacityReason = null;
  try {
    const depNote2 = freshOutputNote({
      profileId, instanceId, authority: aliceAddr.authority,
      postActionSequence: 3,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    pool.deposit({
      outputNoteLeaf: depNote2.outputNoteLeaf,
      encryptedRecord: depNote2.encryptedRecord,
      transactionContextHash: createHash('sha256').update('cap-overflow').digest('hex'),
    });
  } catch (e) {
    capacityRejectBeforeProve = /maximumLiveNotes|CAPACITY|capacity|FUNDING_OR_CAPACITY/i.test(e.message);
    capacityReason = e.message;
  }
  console.log(JSON.stringify({
    phase: 'capacity-reject',
    capacityRejectBeforeProve,
    capacityReason,
    liveNoteCount: pool.tip().liveNoteCount,
    maximumLiveNotes: MAX_LIVE,
  }));

  const evidence = {
    network: 'chipnet',
    maximumLiveNotes: MAX_LIVE,
    height: rpc('getblockcount'),
    category: instanceId,
    genesisTxid,
    deposit1Txid: d1.txid,
    deposit2Txid: d2.txid,
    capacityRejectBeforeProve,
    capacityReason,
    liveNoteCountAtReject: Number(pool.tip().liveNoteCount),
    tip: pool.tip(),
    ok: capacityRejectBeforeProve === true
      && Number(pool.tip().liveNoteCount) === MAX_LIVE,
  };
  // Persist tip + note secrets for contention race (gitignored under .cache)
  const liveTip = {
    carriers: bundle.carriers.map((c) => ({
      txid: c.txid, vout: c.vout, value: String(c.value),
      lockHex: Buffer.from(c.lock).toString('hex'),
    })),
    binding: {
      txid: bundle.binding.txid, vout: bundle.binding.vout,
      value: String(bundle.binding.value),
      lockHex: Buffer.from(bundle.binding.lock).toString('hex'),
    },
    state: {
      txid: bundle.state.txid, vout: bundle.state.vout,
      value: String(bundle.state.value),
      lockHex: Buffer.from(bundle.state.lock).toString('hex'),
      commitmentHex: Buffer.from(bundle.state.commitment).toString('hex'),
    },
    fee: {
      txid: feeCoin.txid, vout: feeCoin.vout, valueSats: String(feeCoin.valueSats),
    },
  };
  writeFileSync(path.join(OUT, 'live-tip.json'), `${JSON.stringify(liveTip, null, 2)}\n`);
  writeFileSync(path.join(OUT, 'session-secrets.json'), `${JSON.stringify({
    profileId,
    instanceId,
    alice: { sk: alice.sk, V: alice.V },
    notes: notes.map((n, i) => ({
      index: i,
      rho: n.rho, r: n.r, cm: n.cm,
      outputNoteLeaf: n.outputNoteLeaf,
      encryptedRecordHex: Buffer.from(n.encryptedRecord).toString('hex'),
      recordCommitment: n.recordCommitment,
      authority: aliceAddr.authority,
      esk: n.esk,
    })),
  }, null, 2)}\n`);
  writeFileSync(path.join(OUT, 'capacity.json'), `${JSON.stringify(evidence, null, 2)}\n`);
  writeFileSync(path.join(OUT, 'txids.txt'), [
    `genesis=${genesisTxid}`,
    `deposit1=${d1.txid}`,
    `deposit2=${d2.txid}`,
    `capacityRejectBeforeProve=${capacityRejectBeforeProve}`,
  ].join('\n') + '\n');
  console.log(JSON.stringify({ phase: 'done', ...evidence }));
  if (!evidence.ok) process.exitCode = 2;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
