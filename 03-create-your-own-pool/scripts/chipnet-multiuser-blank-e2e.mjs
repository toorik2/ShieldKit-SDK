#!/usr/bin/env node
/**
 * Chipnet blank multi-user e2e (shared pool, no pre-seeded tipForest).
 *
 * 1) create-pool (fresh genesis, liveNoteCount=0)
 * 2) wallet A deposit
 * 3) wallet B deposit (same pool; tipForest publicized — no A secrets)
 * 4) A withdraw (own note only)
 * 5) tip-cache wipe + rebuild public tip from settle packets / residual state
 * 6) B withdraw if still open
 *
 * Report: full 64-char txids only.
 */
import { spawnSync } from 'node:child_process';
import {
  existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, cpSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
import { createChainRpc } from '../packages/kit/chipnet-rpc.mjs';
import { completeAction } from '../packages/kit/complete-action.mjs';
import { discoverStateTip } from '../packages/kit/state-tip.mjs';
import { parsePf7CarrierAuthority } from '../packages/prove/authority.mjs';
import {
  rebuildPublicTip,
  rebuildPublicTipFromRawTransactions,
  publicTipToWitnessForest,
  createNoteWallet,
  ownedNoteFromOpenMeta,
  assertNoGlobalOpenSetGate,
  syncTipForestFromSettlementLog,
  mergeTipForestForAct,
  decodeTipNftFields,
} from '../packages/pool/index.mjs';
import {
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  hexToBin,
  binToHex,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
  decodeTransaction,
} from '../packages/action/node_modules/@bitauth/libauth/build/index.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUT = process.env.E2E_OUT
  || path.join(ROOT, '.cache', `e2e-multiuser-blank-${new Date().toISOString().replace(/[:.]/g, '').slice(0, 15)}`);
const PIN = path.join(ROOT, '.cache/profile-build-live/artifacts');
const WALLETS = path.join(ROOT, '.cache/e2e-full-20260725/local-wallets.json');

function mustFullTxid(id, label) {
  if (typeof id !== 'string' || !/^[0-9a-f]{64}$/.test(id)) {
    throw new Error(`${label}: expected full 64-char hex txid, got ${id}`);
  }
  if (id.includes('…') || id.includes('...')) throw new Error(`${label}: truncated txid forbidden`);
  return id;
}

/** Public tipForest for multi-user: keep trees/state, drop foreign secrets. */
function publicizeTipForest(tf) {
  if (!tf) return null;
  return {
    schema: tf.schema || 'shieldkit/tip-forest/v1',
    state: { ...tf.state },
    noteLeaves: [...(tf.noteLeaves || [])],
    nullifierLeaves: (tf.nullifierLeaves || []).map((row) => [...row]),
    openNoteMeta: [], // secrets live only in each wallet
  };
}

async function consolidateHot(rpc, hot, needSats) {
  const unspents = await rpc.scanAddress(hot.address, hot.lockingBytecodeHex);
  unspents.sort((a, b) => b.sats - a.sats);
  const large = unspents.find((u) => u.sats >= needSats);
  if (large) return large;

  const selected = [];
  let sum = 0n;
  for (const u of unspents) {
    selected.push({
      ...u,
      privateKeyHex: hot.privateKeyHex,
      publicKeyHex: hot.publicKeyHex,
      lockingBytecodeHex: hot.lockingBytecodeHex,
    });
    sum += BigInt(u.sats);
    if (sum >= BigInt(needSats) + 500_000n) break;
  }
  if (sum < BigInt(needSats) + 50_000n) throw new Error(`insufficient funds sum=${sum}`);

  const lock = hexToBin(hot.lockingBytecodeHex);
  const priv = hexToBin(hot.privateKeyHex);
  const pub = hexToBin(hot.publicKeyHex);
  const secp = await instantiateSecp256k1();
  const sourceOutputs = selected.map((u) => ({
    lockingBytecode: lock,
    valueSatoshis: BigInt(u.sats),
  }));

  const build = (fee) => {
    const change = Number(sum) - needSats - fee;
    const outputs = [{ lockingBytecode: lock, valueSatoshis: BigInt(needSats) }];
    if (change >= 546) outputs.push({ lockingBytecode: lock, valueSatoshis: BigInt(change) });
    const tx = {
      version: 2,
      locktime: 0,
      inputs: selected.map((u) => ({
        outpointTransactionHash: hexToBin(u.txid),
        outpointIndex: Number(u.vout),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: new Uint8Array(0),
      })),
      outputs,
    };
    for (let i = 0; i < selected.length; i++) {
      const ss = generateSigningSerializationBch({
        inputIndex: i,
        sourceOutputs,
        transaction: tx,
      }, {
        coveredBytecode: lock,
        signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputs),
      });
      const sig = secp.signMessageHashSchnorr(priv, hash256(ss));
      if (typeof sig === 'string') throw new Error(sig);
      const sigWithType = new Uint8Array([...sig, 0x41]);
      const unlock = new Uint8Array(1 + sigWithType.length + 1 + pub.length);
      unlock[0] = sigWithType.length;
      unlock.set(sigWithType, 1);
      unlock[1 + sigWithType.length] = pub.length;
      unlock.set(pub, 2 + sigWithType.length);
      tx.inputs[i].unlockingBytecode = unlock;
    }
    return tx;
  };

  let fee = 400 + selected.length * 150;
  let tx = build(fee);
  let hex = binToHex(encodeTransaction(tx));
  const wire = hex.length / 2;
  if (fee < wire) {
    fee = wire;
    tx = build(fee);
    hex = binToHex(encodeTransaction(tx));
  }
  const txid = await rpc.sendrawtransaction(hex);
  console.error(JSON.stringify({ phase: 'consolidate', txid, needSats }));
  await new Promise((r) => setTimeout(r, 2000));
  return { txid, vout: 0, sats: needSats };
}

async function actDeposit({
  pool, hot, funding, tipForest, wallet, label,
}) {
  const instance = JSON.parse(readFileSync(path.join(pool, 'instance.json'), 'utf8'));
  const bundleDirectory = path.join(pool, 'bundle');
  const vs = JSON.parse(readFileSync(path.join(bundleDirectory, 'artifacts/verifier-set.bin'), 'utf8'));
  const authority = parsePf7CarrierAuthority(vs);
  const rpc = await createChainRpc({ network: 'chipnet' });
  const cat = (instance.categoryTxid || instance.stateNftCategory || '').toLowerCase();
  const tip = await discoverStateTip({
    rpc,
    stateLockingBytecode: authority.settlementKernel.stateLock,
    stateNftCategory: cat,
    instanceId: instance.instanceId,
  });
  const wsh = createHash('sha256').update(Buffer.from(hot.lockingBytecodeHex, 'hex')).digest('hex');
  const seed = randomBytes(32).toString('hex');
  const workDir = path.join(pool, 'runs', `${label}-${Date.now()}`);
  mkdirSync(workDir, { recursive: true });

  // Product invariant: my notes may be << global live
  const myCount = wallet.privateBalanceNotes();
  assertNoGlobalOpenSetGate(myCount, 99); // never equality-gated

  const result = await completeAction({
    kind: 'deposit',
    bundleDirectory,
    expectedProfile: {
      profileId: instance.profileId,
      instanceId: instance.instanceId,
      network: 'chipnet',
    },
    stateTxid: tip.stateTxid,
    stateOutpointIndex: tip.vout ?? 0,
    feePrivateKey: Buffer.from(hot.privateKeyHex, 'hex'),
    funding: {
      txid: funding.txid,
      vout: funding.vout,
      sats: funding.sats,
      publicKeyHex: hot.publicKeyHex,
    },
    workDir,
    witnessSeed: seed,
    withdrawalScriptHash: wsh,
    withdrawalLockingBytecode: Buffer.from(hot.lockingBytecodeHex, 'hex'),
    priorCycles: [],
    priorOpenNotes: [], // do not require foreign notes
    tipForest: tipForest || null,
    actionKind: 'deposit',
    transferHops: 0,
    digests: {
      deposit: '00'.repeat(32),
      transfer: '00'.repeat(32),
      withdrawal: '00'.repeat(32),
    },
  });

  // Broadcast
  const prepA = await rpc.testmempoolaccept(result.prepHex);
  if (!prepA?.[0]?.allowed && !prepA?.[0]?._backend) {
    // electrum always allows; still try broadcast
  }
  await rpc.sendrawtransaction(result.prepHex);
  await rpc.sendrawtransaction(result.settleHex);

  mustFullTxid(result.settleTxid, `${label}.settle`);
  mustFullTxid(result.prepTxid, `${label}.prep`);

  // Persist full spend secrets into private wallet (not tip residual).
  // After backup restore, wallet alone + public tip rebuild must withdraw.
  const forest = result.tipForest;
  const metas = forest?.openNoteMeta || [];
  const myMeta = metas.find((m) => m.witnessSeed === seed) || metas[metas.length - 1];
  if (!myMeta?.note1 || myMeta.key1 == null || !myMeta.nfLeaf1) {
    throw new Error(`${label}: deposit residual openNoteMeta missing note1/key1/nfLeaf1 — cannot seed wallet`);
  }
  const depositDigest = result.digests?.deposit || result.digest || '00'.repeat(32);
  wallet.addOpenNote(ownedNoteFromOpenMeta(myMeta, {
    witnessSeed: seed,
    depositDigest,
    createdSeq: forest?.state?.actionSequence,
  }));

  return {
    prepTxid: result.prepTxid,
    settleTxid: result.settleTxid,
    settleHex: result.settleHex,
    tipForest: result.tipForest,
    publicTipForest: publicizeTipForest(result.tipForest),
    seed,
    label,
  };
}

async function actWithdraw({
  pool, hot, funding, tipForest, wallet, label,
}) {
  const instance = JSON.parse(readFileSync(path.join(pool, 'instance.json'), 'utf8'));
  const bundleDirectory = path.join(pool, 'bundle');
  const vs = JSON.parse(readFileSync(path.join(bundleDirectory, 'artifacts/verifier-set.bin'), 'utf8'));
  const authority = parsePf7CarrierAuthority(vs);
  const rpc = await createChainRpc({ network: 'chipnet' });
  const cat = (instance.categoryTxid || instance.stateNftCategory || '').toLowerCase();
  const tip = await discoverStateTip({
    rpc,
    stateLockingBytecode: authority.settlementKernel.stateLock,
    stateNftCategory: cat,
    instanceId: instance.instanceId,
  });
  const note = wallet.lastOpen();
  if (!note.note1 || note.key1 == null || !note.nfLeaf1) {
    throw new Error(`${label}: wallet note missing spend secrets — deposit must write full openNoteMeta`);
  }
  const wsh = createHash('sha256').update(Buffer.from(hot.lockingBytecodeHex, 'hex')).digest('hex');
  const workDir = path.join(pool, 'runs', `${label}-${Date.now()}`);
  mkdirSync(workDir, { recursive: true });

  // Public tip trees/state only + openNoteMeta from *wallet* (no residual tipForest secrets)
  const base = publicizeTipForest(tipForest) || tipForest;
  if (!base?.noteLeaves || !base?.state) {
    throw new Error(`${label}: public tipForest required for withdraw`);
  }
  const forestForAct = {
    schema: base.schema || 'shieldkit/tip-forest/v1',
    state: { ...base.state },
    noteLeaves: [...(base.noteLeaves || [])],
    nullifierLeaves: (base.nullifierLeaves || []).map((row) => [...row]),
    openNoteMeta: [wallet.toOpenNoteMeta(note.noteIndex)],
  };

  const result = await completeAction({
    kind: 'withdrawal',
    bundleDirectory,
    expectedProfile: {
      profileId: instance.profileId,
      instanceId: instance.instanceId,
      network: 'chipnet',
    },
    stateTxid: tip.stateTxid,
    stateOutpointIndex: tip.vout ?? 0,
    feePrivateKey: Buffer.from(hot.privateKeyHex, 'hex'),
    funding: {
      txid: funding.txid,
      vout: funding.vout,
      sats: funding.sats,
      publicKeyHex: hot.publicKeyHex,
    },
    workDir,
    witnessSeed: note.witnessSeed,
    withdrawalScriptHash: wsh,
    withdrawalLockingBytecode: Buffer.from(hot.lockingBytecodeHex, 'hex'),
    priorCycles: [],
    priorOpenNotes: [{
      witnessSeed: note.witnessSeed,
      depositDigest: note.depositDigest,
      phase: 'deposit',
    }],
    tipForest: forestForAct,
    actionKind: 'withdrawal',
    transferHops: 0,
    digests: {
      deposit: '00'.repeat(32),
      transfer: '00'.repeat(32),
      withdrawal: '00'.repeat(32),
    },
  });

  await rpc.sendrawtransaction(result.prepHex);
  await rpc.sendrawtransaction(result.settleHex);
  mustFullTxid(result.settleTxid, `${label}.settle`);
  wallet.markSpent(note.noteIndex);

  return {
    prepTxid: result.prepTxid,
    settleTxid: result.settleTxid,
    settleHex: result.settleHex,
    tipForest: result.tipForest,
    publicTipForest: publicizeTipForest(result.tipForest),
    label,
    spentNoteIndex: note.noteIndex,
  };
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  if (!existsSync(path.join(PIN, 'verifier-set.bin'))) {
    throw new Error(`pin missing: ${PIN}`);
  }
  if (!existsSync(WALLETS)) throw new Error(`wallets missing: ${WALLETS}`);
  const hot = JSON.parse(readFileSync(WALLETS, 'utf8')).hot;
  const rpc = await createChainRpc({ network: 'chipnet' });

  const pool = path.join(OUT, 'pool');
  if (existsSync(pool)) rmSync(pool, { recursive: true, force: true });

  console.error(JSON.stringify({ phase: 'create-pool', pool, pin: PIN }));
  const cr = spawnSync(process.execPath, [
    path.join(ROOT, '03-create-your-own-pool/scripts/create-pool.mjs'),
    '--out', pool,
    '--with-genesis',
    '--network', 'chipnet',
    '--wallets', WALLETS,
    '--pin-artifacts', PIN,
    '--scan-fund',
    '--max-notes', '16',
    '--broadcast',
  ], { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (cr.status !== 0) {
    console.error(cr.stderr || cr.stdout);
    throw new Error(`create-pool failed ${cr.status}`);
  }

  const instance = JSON.parse(readFileSync(path.join(pool, 'instance.json'), 'utf8'));
  const walletA = createNoteWallet({
    profileId: instance.profileId?.replace(/^sha256:/, '') || instance.profileId,
    instanceId: instance.instanceId?.replace(/^sha256:/, '') || instance.instanceId,
  });
  const walletB = createNoteWallet({
    profileId: instance.profileId?.replace(/^sha256:/, '') || instance.profileId,
    instanceId: instance.instanceId?.replace(/^sha256:/, '') || instance.instanceId,
  });

  // Fresh pool: no tipForest, openNotes empty — blank-machine start
  const fundA = await consolidateHot(rpc, hot, 12_000_000);
  const depA = await actDeposit({
    pool, hot, funding: fundA, tipForest: null, wallet: walletA, label: 'dep-A',
  });
  console.error(JSON.stringify({ phase: 'dep-A-ok', settle: depA.settleTxid }));

  await new Promise((r) => setTimeout(r, 2500));
  const fundB = await consolidateHot(rpc, hot, 12_000_000);

  // B joins multi-user tip by rebuilding public tip from chain settlement log (no A secrets)
  const vs = JSON.parse(readFileSync(path.join(pool, 'bundle/artifacts/verifier-set.bin'), 'utf8'));
  const authority = parsePf7CarrierAuthority(vs);
  let genesisHex = null;
  try {
    genesisHex = await rpc._electrumCall('blockchain.transaction.get', [instance.genesisTxid, false]);
  } catch {
    genesisHex = null;
  }
  if (typeof genesisHex !== 'string') {
    throw new Error('cannot fetch genesis hex for chain-as-log tip rebuild');
  }
  let tipNftCommitmentHex;
  try {
    const tipRaw = await rpc._electrumCall('blockchain.transaction.get', [depA.settleTxid, false]);
    const tipTx = decodeTransaction(hexToBin(tipRaw));
    tipNftCommitmentHex = binToHex(tipTx.outputs[0].token.nft.commitment);
  } catch {
    tipNftCommitmentHex = undefined;
  }

  const syncedForB = await syncTipForestFromSettlementLog({
    genesisTransactionId: instance.genesisTxid,
    genesisTransactionHex: genesisHex,
    settleTransactionHexes: [depA.settleHex],
    profileId: (instance.profileId || '').replace(/^sha256:/, ''),
    instanceId: (instance.instanceId || '').replace(/^sha256:/, ''),
    stateNftCategory: (instance.categoryTxid || instance.stateNftCategory || '').toLowerCase(),
    stateLockingBytecodeHex: Buffer.from(authority.settlementKernel.stateLock).toString('hex'),
    stateCarrierBaseSatoshis: '1080',
    tipNftCommitmentHex,
    myOpenNotes: [], // B has no notes yet
    secretMetaByIndex: {},
  });
  console.error(JSON.stringify({
    phase: 'tip-rebuild-for-B',
    events: syncedForB.publicTip.eventCount,
    live: syncedForB.publicTip.state.liveNoteCount,
    seq: syncedForB.publicTip.state.actionSequence,
  }));

  const depB = await actDeposit({
    pool,
    hot,
    funding: fundB,
    tipForest: syncedForB.bareForest, // public tip only — zero foreign journal
    wallet: walletB,
    label: 'dep-B',
  });
  console.error(JSON.stringify({ phase: 'dep-B-ok', settle: depB.settleTxid }));

  // A holds 1 of 2 live notes
  assertNoGlobalOpenSetGate(walletA.privateBalanceNotes(), 2);
  assertNoGlobalOpenSetGate(walletB.privateBalanceNotes(), 2);

  await new Promise((r) => setTimeout(r, 2000));
  const fundW = await consolidateHot(rpc, hot, 100_000);
  // A withdraw: public tip trees after B deposit + secrets from wallet A only
  const tipForAWdr = publicizeTipForest(depB.tipForest);

  const wdrA = await actWithdraw({
    pool, hot, funding: fundW, tipForest: tipForAWdr, wallet: walletA, label: 'wdr-A',
  });
  console.error(JSON.stringify({ phase: 'wdr-A-ok', settle: wdrA.settleTxid }));

  // Tip cache wipe: discard residual forests, full chain-as-log replay of genesis+settles.
  // Secrets come only from walletB.listOpen() — empty secretMetaByIndex.
  await new Promise((r) => setTimeout(r, 2500));
  let tipNftAfterAWdr;
  try {
    const tipRaw = await rpc._electrumCall('blockchain.transaction.get', [wdrA.settleTxid, false]);
    const tipTx = decodeTransaction(hexToBin(tipRaw));
    tipNftAfterAWdr = binToHex(tipTx.outputs[0].token.nft.commitment);
  } catch {
    tipNftAfterAWdr = undefined;
  }

  const wipedRebuild = await syncTipForestFromSettlementLog({
    genesisTransactionId: instance.genesisTxid,
    genesisTransactionHex: genesisHex,
    settleTransactionHexes: [depA.settleHex, depB.settleHex, wdrA.settleHex],
    profileId: (instance.profileId || '').replace(/^sha256:/, ''),
    instanceId: (instance.instanceId || '').replace(/^sha256:/, ''),
    stateNftCategory: (instance.categoryTxid || instance.stateNftCategory || '').toLowerCase(),
    stateLockingBytecodeHex: Buffer.from(authority.settlementKernel.stateLock).toString('hex'),
    stateCarrierBaseSatoshis: '1080',
    tipNftCommitmentHex: tipNftAfterAWdr,
    myOpenNotes: walletB.listOpen(), // full spend secrets in wallet
    secretMetaByIndex: {}, // no residual tipForest secrets
  });
  console.error(JSON.stringify({
    phase: 'tip-cache-wipe-rebuild',
    events: wipedRebuild.publicTip.eventCount,
    live: wipedRebuild.publicTip.state.liveNoteCount,
    seq: wipedRebuild.publicTip.state.actionSequence,
    openMeta: wipedRebuild.tipForest.openNoteMeta.length,
    secretsFromWallet: Boolean(wipedRebuild.tipForest.openNoteMeta[0]?.note1?.sk),
  }));
  if (wipedRebuild.publicTip.eventCount !== 3) {
    throw new Error(`expected 3 public events after wipe rebuild, got ${wipedRebuild.publicTip.eventCount}`);
  }
  if (Number(wipedRebuild.publicTip.state.liveNoteCount) !== 1) {
    throw new Error(`expected liveNoteCount=1 after A withdraw, got ${wipedRebuild.publicTip.state.liveNoteCount}`);
  }
  if (!wipedRebuild.tipForest.openNoteMeta[0]?.note1?.sk) {
    throw new Error('wipe rebuild openNoteMeta must carry note1 from walletB only');
  }

  // B withdraws using ONLY rebuilt tip from chain log + B wallet secrets
  const fundW2 = await consolidateHot(rpc, hot, 100_000);
  const wdrB = await actWithdraw({
    pool,
    hot,
    funding: fundW2,
    tipForest: wipedRebuild.bareForest, // public tip only; actWithdraw injects wallet secrets
    wallet: walletB,
    label: 'wdr-B',
  });
  console.error(JSON.stringify({ phase: 'wdr-B-ok', settle: wdrB.settleTxid }));

  const report = {
    ok: true,
    mode: 'chipnet-multiuser-blank',
    out: OUT,
    genesisTxid: mustFullTxid(instance.genesisTxid, 'genesis'),
    categoryTxid: instance.categoryTxid || null,
    instanceId: instance.instanceId,
    deposits: [
      { wallet: 'A', prepTxid: depA.prepTxid, settleTxid: depA.settleTxid },
      { wallet: 'B', prepTxid: depB.prepTxid, settleTxid: depB.settleTxid },
    ],
    withdraws: [
      { wallet: 'A', prepTxid: wdrA.prepTxid, settleTxid: wdrA.settleTxid, noteIndex: wdrA.spentNoteIndex },
      { wallet: 'B', prepTxid: wdrB.prepTxid, settleTxid: wdrB.settleTxid, noteIndex: wdrB.spentNoteIndex },
    ],
    tipCacheWipe: {
      ok: true,
      method: 'syncTipForestFromSettlementLog',
      eventsReplayed: wipedRebuild.publicTip.eventCount,
      rebuiltActionSequence: wipedRebuild.publicTip.state.actionSequence,
      rebuiltLiveNoteCount: wipedRebuild.publicTip.state.liveNoteCount,
      rebuiltStateCommitment: wipedRebuild.publicTip.state.stateCommitment,
      secretsSource: 'walletB.listOpen-only',
      residualSecretMeta: false,
      withdrawAfterRebuild: true,
      settleTxidAfterRebuild: wdrB.settleTxid,
    },
    walletsAfter: {
      A: { openNotes: walletA.privateBalanceNotes() },
      B: { openNotes: walletB.privateBalanceNotes() },
    },
    explorer: 'https://chipnet.chaingraph.cash/tx/',
  };

  writeFileSync(path.join(OUT, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);
  writeFileSync(
    path.join('/tmp/grok-goal-16e8b0c59f85/implementer', 'blank-multiuser-e2e.json'),
    `${JSON.stringify(report, null, 2)}\n`,
  );
  console.log(JSON.stringify(report, null, 2));
}

main().catch((e) => {
  console.error(JSON.stringify({ ok: false, err: String(e.message || e), stack: e.stack }));
  process.exit(1);
});
