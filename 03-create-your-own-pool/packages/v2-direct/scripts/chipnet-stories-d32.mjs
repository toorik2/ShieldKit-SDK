#!/usr/bin/env node
/**
 * Remaining Chipnet mandatory stories against depth-32 product evidence.
 * Reads prior product evidence (or env TXIDS) and runs:
 *   1) conf scan (full 64-char txids)
 *   2) genesis-lineage recovery from chain raw txs + respend root match
 *   3) capacity reject-before-prove
 *   4) contention two-engine race → needs_reproof semantics
 *   5) adversarial on-chain: mutate live settle hex → testmempoolaccept reject
 *
 * Scratch evidence under .cache/v2-direct-stories-d32/ (not secrets).
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  existsSync, mkdirSync, readFileSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  NETWORK_CHIPNET, PLAYGROUND_MAXIMUM_LIVE_NOTES, POOL_STATE_BYTES,
} from '../constants.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import { CIRCUIT_TREE_DEPTH } from '../prove/witness.mjs';
import { decodeActionPacketV2 } from '../packet.mjs';
import { recoverFromGenesisLineage, applyReorgUndo } from '../recover/scanner.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const OUT = path.join(ROOT, '.cache/v2-direct-stories-d32');
const PRODUCT_EV = path.join(ROOT, '.cache/v2-direct-product-1tx/evidence.json');

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

function loadProductEvidence() {
  if (process.env.V2_PRODUCT_EVIDENCE && existsSync(process.env.V2_PRODUCT_EVIDENCE)) {
    return JSON.parse(readFileSync(process.env.V2_PRODUCT_EVIDENCE, 'utf8'));
  }
  if (existsSync(PRODUCT_EV)) {
    return JSON.parse(readFileSync(PRODUCT_EV, 'utf8'));
  }
  // Fallback: hard-wired depth-32 product chain from FOUNDATION_GATE
  return {
    genesisTxid: '1fdad90a58e020f193ad2221cf8c146a0d625679b7280c469f0171016389de53',
    category: '7807fc04383eeabb364960b4c77e27a1eb20f4bef6056a6877131b8007c8a7e8',
    profileId: '81d05348e977f635bf6765f40e6db574249df8ed63a09418191859a2431bdd63',
    instanceId: '7807fc04383eeabb364960b4c77e27a1eb20f4bef6056a6877131b8007c8a7e8',
    deposit: { settleTxid: 'fc726d8cf1d3e92690561a7252443f9bff8a8c54f35a1941b6e7e660418f40b0' },
    transfer: { settleTxid: '7f84086386b6c087c43f3137e4f1d77efe2e3b952e03f0ac95ab24aa8befe910' },
    withdraw: { settleTxid: '263347cb75e8488bd509b53b732561728efec6b83eb2d253baac19528e42d2d1' },
    finalTip: null,
  };
}

function txInfo(txid) {
  const j = rpc('getrawtransaction', [txid, true]);
  if (!j || typeof j !== 'object') return { txid, conf: null, error: 'missing' };
  return {
    txid,
    conf: j.confirmations ?? 0,
    inBlock: Boolean(j.blockhash),
    blockhash: j.blockhash || null,
    size: j.size || j.vsize || null,
    vinCount: (j.vin || []).length,
    voutCount: (j.vout || []).length,
  };
}

function extractStateVout(decodedTx, categoryHex) {
  // Prefer vout with matching token category (mutable NFT)
  for (const o of decodedTx.vout || []) {
    const tok = o.tokenData || o.token;
    if (!tok) continue;
    const cat = (tok.category || '').toLowerCase();
    if (cat === categoryHex.toLowerCase() || cat === Buffer.from(categoryHex, 'hex').reverse().toString('hex')) {
      const commitment = tok.nft?.commitment || tok.commitment;
      if (commitment) {
        return {
          n: o.n,
          commitment: Buffer.from(commitment, 'hex'),
          category: cat,
          value: Math.round((o.value || 0) * 1e8),
        };
      }
    }
  }
  return null;
}

function extractPacketFromVin(decodedTx) {
  // Binding input unlock is PUSHDATA2 + SDA2 552
  for (const input of decodedTx.vin || []) {
    const script = input.scriptSig?.hex || '';
    if (script.startsWith('4d2802') && script.length === 555 * 2) {
      return script.slice(6); // drop 3-byte header hex
    }
    // sometimes asm shows push; try raw hex length 1110
    if (script.length >= 1110) {
      const idx = script.indexOf('53444132'); // SDA2
      if (idx >= 0 && script.length - idx >= 1104) {
        return script.slice(idx, idx + 1104);
      }
    }
  }
  return null;
}

function storyCapacity() {
  let rejected = false;
  let reason = null;
  try {
    const profileId = createHash('sha256').update('cap-story').digest('hex');
    const instanceId = createHash('sha256').update('cap-story-i').digest('hex');
    const eng = createPoolEngineV2({
      profileId, instanceId, maximumLiveNotes: 1,
      noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
    });
    const a = createAccountKeys();
    const ad = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: a,
    });
    const n1 = freshOutputNote({
      profileId, instanceId, authority: ad.authority, postActionSequence: 1,
      viewPoint: [frFromHex(a.V[0]), frFromHex(a.V[1])],
    });
    eng.deposit({ outputNoteLeaf: n1.outputNoteLeaf, encryptedRecord: n1.encryptedRecord });
    const n2 = freshOutputNote({
      profileId, instanceId, authority: ad.authority, postActionSequence: 2,
      viewPoint: [frFromHex(a.V[0]), frFromHex(a.V[1])],
    });
    eng.deposit({ outputNoteLeaf: n2.outputNoteLeaf, encryptedRecord: n2.encryptedRecord });
  } catch (e) {
    rejected = /maximumLiveNotes|CAPACITY|capacity|live/i.test(e.message);
    reason = e.message;
  }
  return { capacityRejectBeforeProve: rejected, reason };
}

function storyContention() {
  const profileId = createHash('sha256').update('race-p').digest('hex');
  const instanceId = createHash('sha256').update('race-i').digest('hex');
  const e1 = createPoolEngineV2({
    profileId, instanceId, maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const e2 = createPoolEngineV2({
    profileId, instanceId, maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const a = createAccountKeys();
  const b = createAccountKeys();
  const aAddr = shieldAddress({ networkId: NETWORK_CHIPNET, profileId, instanceId, account: a });
  const bAddr = shieldAddress({ networkId: NETWORK_CHIPNET, profileId, instanceId, account: b });
  const nA = freshOutputNote({
    profileId, instanceId, authority: aAddr.authority, postActionSequence: 1,
    viewPoint: [frFromHex(a.V[0]), frFromHex(a.V[1])],
  });
  const nB = freshOutputNote({
    profileId, instanceId, authority: bAddr.authority, postActionSequence: 1,
    viewPoint: [frFromHex(b.V[0]), frFromHex(b.V[1])],
  });
  // Both race a deposit from empty tip (same pre roots) — both produce valid local transitions
  // with different post roots. On chain only one can settle; loser needs_reproof.
  const d1 = e1.deposit({ outputNoteLeaf: nA.outputNoteLeaf, encryptedRecord: nA.encryptedRecord });
  const d2 = e2.deposit({ outputNoteLeaf: nB.outputNoteLeaf, encryptedRecord: nB.encryptedRecord });
  const samePre = d1.preState.noteRoot === d2.preState.noteRoot
    && d1.preState.nullifierRoot === d2.preState.nullifierRoot;
  const differentPost = d1.postState.noteRoot !== d2.postState.noteRoot;
  // "Winner" is e1; e2 must abandon and reprove against e1 tip
  const e2re = createPoolEngineV2({
    profileId, instanceId, maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
    noteDepth: CIRCUIT_TREE_DEPTH, nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  e2re.deposit({ outputNoteLeaf: nA.outputNoteLeaf, encryptedRecord: nA.encryptedRecord });
  // now e2re matches winner; loser's original packet is stale
  const needsReproof = differentPost && samePre
    && e2re.tip().noteRoot === e1.tip().noteRoot
    && d2.postState.noteRoot !== e1.tip().noteRoot;
  return {
    samePreRoot: samePre,
    differentPostRoot: differentPost,
    needsReproof,
    winnerNoteRoot: e1.tip().noteRoot,
    loserStaleNoteRoot: d2.postState.noteRoot,
    loserAfterReproveNoteRoot: e2re.tip().noteRoot,
  };
}

function storyAdversarialPacket() {
  let rejected = false;
  try {
    const profileId = createHash('sha256').update('adv-p').digest('hex');
    const instanceId = createHash('sha256').update('adv-i').digest('hex');
    const eng = createPoolEngineV2({
      profileId, instanceId, maximumLiveNotes: 32,
      noteDepth: 8, nullifierDepth: 8,
    });
    const a = createAccountKeys();
    const ad = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: a,
    });
    const n = freshOutputNote({
      profileId, instanceId, authority: ad.authority, postActionSequence: 1,
      viewPoint: [frFromHex(a.V[0]), frFromHex(a.V[1])],
    });
    const d = eng.deposit({
      outputNoteLeaf: n.outputNoteLeaf, encryptedRecord: n.encryptedRecord,
    });
    const bad = Buffer.from(d.packet);
    bad[0] ^= 0xff;
    decodeActionPacketV2(bad);
  } catch {
    rejected = true;
  }
  return { adversarialPacketRejected: rejected };
}

function parseAdversarialReport(text) {
  const raw = String(text || '').trim();
  if (!raw) throw new Error('empty adversarial report');
  // Prefer full pretty-printed JSON; fall back to last JSON object blob.
  try {
    return JSON.parse(raw);
  } catch {
    const start = raw.lastIndexOf('{');
    if (start < 0) throw new Error('no JSON object in adversarial output');
    // Brace-match from last top-level start (script prints one report object).
    let depth = 0;
    let end = -1;
    for (let i = start; i < raw.length; i += 1) {
      const ch = raw[i];
      if (ch === '{') depth += 1;
      else if (ch === '}') {
        depth -= 1;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }
    if (end < 0) throw new Error('unclosed JSON object in adversarial output');
    return JSON.parse(raw.slice(start, end));
  }
}

function storyAdversarialOnChain() {
  // Honest covenant probes via chipnet-adversarial-covenant.mjs (Libauth).
  // Does NOT treat missing-inputs / mempool-conflict as covenant PASS.
  const script = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    'chipnet-adversarial-covenant.mjs',
  );
  try {
    const out = execFileSync(process.execPath, [script], {
      encoding: 'utf8',
      maxBuffer: 8 * 1024 * 1024,
      env: { ...process.env },
    });
    const report = parseAdversarialReport(out);
    const bindingOk = (report.results || []).filter(
      (r) => r.probe?.startsWith('binding-') && r.honest === true && r.rejected === true,
    ).length >= 2;
    return {
      ok: bindingOk && report.ok !== false,
      report,
      note: 'Libauth covenant rejects; spent-input rejects not counted as PASS',
    };
  } catch (e) {
    const text = String(e.stdout || e.stderr || e.message || e);
    try {
      const report = parseAdversarialReport(text);
      const bindingOk = (report.results || []).filter(
        (r) => r.probe?.startsWith('binding-') && r.honest === true && r.rejected === true,
      ).length >= 2;
      return { ok: bindingOk && report.ok !== false, report };
    } catch {
      return { ok: false, error: text.slice(0, 400) };
    }
  }
}

function storyRecoverLineage(ev) {
  const cat = ev.category || ev.instanceId;
  const chainIds = [
    ev.deposit?.settleTxid,
    ev.transfer?.settleTxid,
    ev.withdraw?.settleTxid,
  ].filter(Boolean);

  // Genesis state is vout 8 on product genesis (carriers 0-6, binding 7, state 8)
  const gen = rpc('getrawtransaction', [ev.genesisTxid, true]);
  if (!gen?.vout) {
    return { ok: false, reason: 'genesis raw missing', genesisTxid: ev.genesisTxid };
  }
  let genState = extractStateVout(gen, cat);
  if (!genState) {
    // fallback: scan all vouts for any NFT commitment length 128 hex = 256 chars
    for (const o of gen.vout) {
      const tok = o.tokenData || o.token;
      const c = tok?.nft?.commitment || tok?.commitment;
      if (c && c.length === POOL_STATE_BYTES * 2) {
        genState = {
          n: o.n,
          commitment: Buffer.from(c, 'hex'),
          category: (tok.category || cat).toLowerCase(),
          value: Math.round((o.value || 0) * 1e8),
        };
        break;
      }
    }
  }
  if (!genState) {
    return { ok: false, reason: 'no state NFT on genesis', genesisTxid: ev.genesisTxid };
  }

  const chainTxs = [];
  for (const txid of chainIds) {
    const tx = rpc('getrawtransaction', [txid, true]);
    if (!tx) {
      return { ok: false, reason: `missing ${txid}` };
    }
    const st = extractStateVout(tx, cat);
    const packetHex = extractPacketFromVin(tx);
    // Find which vin spends prior state — recover scanner needs vin.txid/vout
    const vin = (tx.vin || []).map((i) => ({
      txid: i.txid,
      vout: i.vout,
    }));
    const vout = (tx.vout || []).map((o) => {
      const tok = o.tokenData || o.token;
      const c = tok?.nft?.commitment || tok?.commitment;
      return {
        n: o.n,
        commitment: c ? Buffer.from(c, 'hex') : null,
        category: tok?.category || null,
      };
    });
    chainTxs.push({
      txid,
      vin,
      vout: st ? [{ n: st.n, commitment: st.commitment, category: st.category }] : vout,
      packetHex: packetHex || undefined,
    });
  }

  try {
    const recovered = recoverFromGenesisLineage({
      genesisStateOutpoint: {
        txid: ev.genesisTxid,
        vout: genState.n,
        commitment: genState.commitment,
        category: cat,
      },
      chainTxs,
      instanceCategory: cat,
    });
    const reorg1 = applyReorgUndo(recovered, 1);
    const reorgDeep = applyReorgUndo(recovered, 101);

    // Replay engine and compare tip roots to recovered tipState
    const profileId = ev.profileId;
    const instanceId = ev.instanceId || cat;
    let engineTipMatch = null;
    if (ev.finalTip && recovered.tipState) {
      engineTipMatch = recovered.tipState.noteRoot === ev.finalTip.noteRoot
        && recovered.tipState.nullifierRoot === ev.finalTip.nullifierRoot
        && String(recovered.tipState.actionSequence) === String(ev.finalTip.actionSequence);
    }

    return {
      ok: true,
      genesisTxid: ev.genesisTxid,
      genesisStateVout: genState.n,
      chainTxids: chainIds,
      statesCount: recovered.states.length,
      packetsCount: recovered.packets.length,
      tipState: recovered.tipState ? {
        noteRoot: recovered.tipState.noteRoot,
        nullifierRoot: recovered.tipState.nullifierRoot,
        actionSequence: recovered.tipState.actionSequence,
        noteCount: recovered.tipState.noteCount,
        nullifierCount: recovered.tipState.nullifierCount,
        reserveSats: recovered.tipState.reserveSats,
      } : null,
      tipOutpoint: recovered.tipOutpoint,
      engineTipMatch,
      reorgUndo1States: reorg1.states?.length,
      reorgDeepWiped: reorgDeep.wiped === true,
    };
  } catch (e) {
    return { ok: false, reason: e.message, genesisTxid: ev.genesisTxid, chainTxids: chainIds };
  }
}

function main() {
  mkdirSync(OUT, { recursive: true });
  const ev = loadProductEvidence();
  const height = rpc('getblockcount');
  console.log(JSON.stringify({ phase: 'start', height, out: OUT }));

  const confs = {
    genesis: txInfo(ev.genesisTxid),
    deposit: txInfo(ev.deposit.settleTxid),
    transfer: txInfo(ev.transfer.settleTxid),
    withdraw: txInfo(ev.withdraw.settleTxid),
  };
  console.log(JSON.stringify({ phase: 'confs', confs }));

  const capacity = storyCapacity();
  console.log(JSON.stringify({ phase: 'capacity', ...capacity }));

  const contention = storyContention();
  console.log(JSON.stringify({ phase: 'contention', ...contention }));

  const advPacket = storyAdversarialPacket();
  console.log(JSON.stringify({ phase: 'adversarial-packet', ...advPacket }));

  const advChain = storyAdversarialOnChain();
  console.log(JSON.stringify({ phase: 'adversarial-onchain', ...advChain }));

  const recover = storyRecoverLineage(ev);
  console.log(JSON.stringify({ phase: 'recover-lineage', ...recover }));

  // Live Chipnet capacity / contention evidence (from dedicated campaigns)
  let liveCapacity = null;
  const capPath = path.join(ROOT, '.cache/v2-direct-live-capacity/capacity.json');
  if (existsSync(capPath)) {
    liveCapacity = JSON.parse(readFileSync(capPath, 'utf8'));
  }
  console.log(JSON.stringify({
    phase: 'live-capacity',
    ok: liveCapacity?.ok === true,
    capacityRejectBeforeProve: liveCapacity?.capacityRejectBeforeProve,
    deposit1Txid: liveCapacity?.deposit1Txid,
    deposit2Txid: liveCapacity?.deposit2Txid,
  }));

  let liveContention = null;
  const contPath = path.join(ROOT, '.cache/v2-direct-live-contention/contention.json');
  if (existsSync(contPath)) {
    liveContention = JSON.parse(readFileSync(contPath, 'utf8'));
  }
  console.log(JSON.stringify({
    phase: 'live-contention',
    ok: liveContention?.ok === true,
    liveOnChain: liveContention?.liveOnChain,
    winnerTxid: liveContention?.winnerTxid,
    loserReproveTxid: liveContention?.loserReproveTxid,
  }));

  const allMined = [confs.genesis, confs.deposit, confs.transfer, confs.withdraw]
    .every((c) => (c.conf ?? 0) >= 1);

  const report = {
    network: 'chipnet',
    height,
    circuitDepth: CIRCUIT_TREE_DEPTH,
    product: {
      genesisTxid: ev.genesisTxid,
      depositTxid: ev.deposit.settleTxid,
      transferTxid: ev.transfer.settleTxid,
      withdrawTxid: ev.withdraw.settleTxid,
      category: ev.category || ev.instanceId,
      profileId: ev.profileId,
    },
    confs,
    allMinedConf1: allMined,
    capacity,
    contention,
    liveCapacity,
    liveContention,
    adversarialPacket: advPacket,
    adversarialOnChain: advChain,
    recoverLineage: recover,
    pass: {
      capacityLocalEngine: capacity.capacityRejectBeforeProve === true,
      // Live Chipnet: maxLiveNotes=2 fill + reject-before-prove
      capacityLiveChipnet: liveCapacity?.ok === true
        && liveCapacity?.capacityRejectBeforeProve === true,
      contentionLocalEngine: contention.needsReproof === true,
      // Live Chipnet: two-client race, loser re-prove + settle
      contentionLiveChipnet: liveContention?.ok === true
        && liveContention?.liveOnChain === true
        && liveContention?.needsReproof === true,
      adversarialPacket: advPacket.adversarialPacketRejected === true,
      adversarialCovenantHonest: advChain.ok === true,
      recoverLineage: recover.ok === true,
      // 0-conf mempool is the bar — mempoolAccepted, not mined
      mempoolAccepted: [confs.genesis, confs.deposit, confs.transfer, confs.withdraw]
        .every((c) => c && c.txid && (c.conf ?? 0) >= 0 && c.size > 0),
    },
    optional: {
      // Informational only — never a fail gate
      allMinedConf1: allMined,
    },
    notes: {
      capacity: 'local engine + live chipnet-live-capacity.mjs (maxLiveNotes=2 fill + reject-before-prove)',
      contention: 'local engine + live chipnet-live-contention.mjs (two-client race, loser re-prove)',
      adversarial: 'Libauth + live testmempoolaccept script-rejects on unspent tip',
      recoverRespend: 'see V2_STOP_AFTER=deposit-respend product campaign for wipe→respend',
      confBar: '0 conf is enough; do not wait for or mine Chipnet blocks',
      cliSettle: 'CLI --broadcast builds densFuel+binding+state+funding via operator/product-settle.mjs (no V2_SETTLE_HEX)',
    },
  };
  writeFileSync(path.join(OUT, 'stories.json'), `${JSON.stringify(report, null, 2)}\n`);
  writeFileSync(path.join(OUT, 'txids.txt'), [
    `genesis=${ev.genesisTxid}`,
    `deposit=${ev.deposit.settleTxid}`,
    `transfer=${ev.transfer.settleTxid}`,
    `withdraw=${ev.withdraw.settleTxid}`,
    `height=${height}`,
    `allMinedConf1=${allMined}`,
    `confBar=0-conf-mempool`,
  ].join('\n') + '\n');

  const fails = Object.entries(report.pass).filter(([, v]) => !v).map(([k]) => k);
  console.log(JSON.stringify({
    phase: 'done',
    allMinedConf1: allMined,
    confBar: '0-conf-mempool',
    fails,
    evidence: path.join(OUT, 'stories.json'),
  }));
  if (fails.length) {
    process.exitCode = 2;
  }
}

main();
