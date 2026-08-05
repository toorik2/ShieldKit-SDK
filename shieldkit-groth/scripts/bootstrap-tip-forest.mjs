#!/usr/bin/env node
/**
 * Rebuild tipForest for tip after: openNotes deposits + one extra deposit/withdraw residual.
 *
 * Required args:
 *   --ticket-state  state.json with openNotes for current live notes
 *   --withdraw-ci   withdrawal.circuitInput.json of the residual spent note
 *   --out           state.json to write (merges tipForest + openNotes)
 *   --tip-txid      optional chain tip txid
 */
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { generateFreshWitnessInputs, serializeTipForest } from '../packages/action/witness.mjs';
import {
  createShieldedTransitionReference, DOMAIN_TAGS, frToHex, frFromHex, DENOMINATION_SATS,
} from '../packages/action/transition.mjs';

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : null;
}

async function main() {
  const ticketStatePath = arg('ticket-state');
  const withdrawCiPath = arg('withdraw-ci');
  const outPath = arg('out');
  const tipTxid = arg('tip-txid');
  const bundleDirectory = arg('ticket-bundle') || path.join(path.dirname(ticketStatePath), 'bundle');
  if (!ticketStatePath || !withdrawCiPath || !outPath) {
    console.error('required: --ticket-state --withdraw-ci --out [--tip-txid] [--ticket-bundle]');
    process.exit(2);
  }

  const ticket = JSON.parse(readFileSync(ticketStatePath, 'utf8'));
  const instance = JSON.parse(readFileSync(path.join(path.dirname(ticketStatePath), 'instance.json'), 'utf8'));
  const wci = JSON.parse(readFileSync(withdrawCiPath, 'utf8'));
  const notes = ticket.openNotes.map((n) => ({
    witnessSeed: n.witnessSeed,
    depositDigest: n.depositDigest,
    phase: n.phase || 'deposit',
  }));
  const expectedProfile = {
    profileId: instance.profileId,
    instanceId: instance.instanceId,
    network: 'chipnet',
  };
  const digests = {
    deposit: 'd1'.repeat(32),
    transfer: 'd2'.repeat(32),
    withdrawal: 'd3'.repeat(32),
  };
  const wsh = 'ab'.repeat(32);

  // Forest of exactly openNotes.length via last note as deposit action
  const head = notes.slice(0, -1);
  const last = notes[notes.length - 1];
  const w10 = await generateFreshWitnessInputs({
    bundleDirectory,
    expectedProfile,
    witnessSeed: last.witnessSeed,
    priorOpenNotes: head,
    actionKind: 'deposit',
    transferHops: 0,
    transactionContextDigests: {
      deposit: last.depositDigest,
      transfer: digests.transfer,
      withdrawal: digests.withdrawal,
    },
    withdrawalScriptHash: wsh,
  });

  const reference = await createShieldedTransitionReference();
  const tip = {
    state: { ...w10.tipForest.state },
    noteLeaves: w10.tipForest.noteLeaves.map((h) => frFromHex(h, 'leaf')),
    nullifierLeaves: new Map(
      w10.tipForest.nullifierLeaves.map(([k, v]) => [String(k), frFromHex(v, 'nf')]),
    ),
    openNoteMeta: w10.tipForest.openNoteMeta.map((m) => ({
      noteIndex: m.noteIndex,
      leaf: frFromHex(m.leaf, 'leaf'),
      key1: BigInt(m.key1),
      nfLeaf1: frFromHex(m.nfLeaf1, 'nfLeaf'),
      witnessSeed: m.witnessSeed,
      note1: m.note1,
    })),
  };

  function noteTreeSiblings(leafFrs, index) {
    let empty = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_EMPTY, 0n);
    let layer = new Map();
    for (let i = 0; i < leafFrs.length; i += 1) layer.set(BigInt(i), leafFrs[i]);
    const siblings = [];
    let idx = BigInt(index);
    for (let level = 0; level < 32; level += 1) {
      siblings.push(layer.get(idx ^ 1n) ?? empty);
      const parents = new Map();
      const parentKeys = new Set([...layer.keys()].map((key) => key >> 1n));
      parentKeys.add(idx >> 1n);
      for (const parent of parentKeys) {
        parents.set(
          parent,
          reference.poseidon(
            DOMAIN_TAGS.NOTE_TREE_NODE,
            layer.get(parent << 1n) ?? empty,
            layer.get((parent << 1n) | 1n) ?? empty,
          ),
        );
      }
      layer = parents;
      idx >>= 1n;
      empty = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_NODE, empty, empty);
    }
    return siblings;
  }
  function rootFromPath(leaf, index, siblings, tag) {
    let current = leaf;
    for (let level = 0; level < siblings.length; level += 1) {
      const sib = typeof siblings[level] === 'bigint' ? siblings[level] : frFromHex(siblings[level], 'sib');
      current = ((index >> BigInt(level)) & 1n) === 0n
        ? reference.poseidon(tag, current, sib)
        : reference.poseidon(tag, sib, current);
    }
    return current;
  }
  function sparsePath(target, leaves) {
    let nodes = new Map(leaves);
    let key = target;
    const siblings = [];
    let empty = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_EMPTY, 0n);
    for (let level = 0; level < 128; level += 1) {
      siblings.push(nodes.get((key ^ 1n).toString()) ?? empty);
      const parents = new Map();
      for (const parent of new Set([...nodes.keys()].map((e) => (BigInt(e) >> 1n).toString()))) {
        const base = BigInt(parent) << 1n;
        parents.set(
          parent,
          reference.poseidon(
            DOMAIN_TAGS.NULLIFIER_TREE_NODE,
            nodes.get(base.toString()) ?? empty,
            nodes.get((base | 1n).toString()) ?? empty,
          ),
        );
      }
      nodes = parents;
      key >>= 1n;
      empty = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_NODE, empty, empty);
    }
    return siblings;
  }

  const cm = BigInt(wci.inputCm);
  const nf = BigInt(wci.inputNf);
  const leaf1 = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, cm);
  const nfLeaf1 = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, nf);
  const key1 = BigInt(`0x${Buffer.from(nf.toString(16).padStart(64, '0'), 'hex').subarray(16, 32).toString('hex')}`);
  const depIndex = tip.noteLeaves.length;
  const depSib = noteTreeSiblings(tip.noteLeaves, depIndex);
  const noteRoot11 = rootFromPath(leaf1, BigInt(depIndex), depSib, DOMAIN_TAGS.NOTE_TREE_NODE);
  if (noteRoot11 !== BigInt(wci.preNoteRoot)) {
    throw new Error(`noteRoot after residual deposit mismatch`);
  }

  tip.noteLeaves.push(leaf1);
  tip.state = reference.buildState({
    ...tip.state,
    noteRoot: frToHex(noteRoot11),
    nextLeafIndex: '11',
    actionSequence: '11',
    liveNoteCount: String(Number(tip.state.liveNoteCount) + 1),
    reserveSats: String(BigInt(tip.state.reserveSats) + DENOMINATION_SATS),
  });
  tip.openNoteMeta.push({
    noteIndex: depIndex,
    leaf: leaf1,
    key1,
    nfLeaf1,
    witnessSeed: null,
    note1: {
      sk: BigInt(wci.inSk).toString(16).padStart(64, '0'),
      recoveryPublicKey: tip.openNoteMeta[0]?.note1?.recoveryPublicKey || '0'.repeat(64),
      rho: BigInt(wci.inRho).toString(16).padStart(64, '0'),
      r: BigInt(wci.inR).toString(16).padStart(64, '0'),
    },
  });

  const open = tip.openNoteMeta[tip.openNoteMeta.length - 1];
  const nfPath = sparsePath(open.key1, tip.nullifierLeaves);
  const nullRoot = rootFromPath(open.nfLeaf1, open.key1, nfPath, DOMAIN_TAGS.NULLIFIER_TREE_NODE);
  if (nullRoot !== BigInt(wci.postNullifierRoot)) {
    throw new Error('nullifierRoot after residual withdraw mismatch');
  }
  tip.nullifierLeaves.set(open.key1.toString(), open.nfLeaf1);
  tip.openNoteMeta = tip.openNoteMeta.slice(0, -1);
  tip.state = reference.buildState({
    ...tip.state,
    nullifierRoot: frToHex(nullRoot),
    actionSequence: String(Number(tip.state.actionSequence) + 1),
    liveNoteCount: String(Number(tip.state.liveNoteCount) - 1),
    reserveSats: String(BigInt(tip.state.reserveSats) - DENOMINATION_SATS),
  });

  const expect = BigInt(wci.postStateCommitment).toString(16).padStart(64, '0');
  if (tip.state.stateCommitment !== expect) {
    throw new Error(`stateCommitment mismatch built=${tip.state.stateCommitment} expect=${expect}`);
  }

  const forest = serializeTipForest(tip);
  let out = {};
  try { out = JSON.parse(readFileSync(outPath, 'utf8')); } catch { /* */ }
  out.openNotes = notes;
  out.tipForest = forest;
  if (tipTxid) out.stateTxid = tipTxid;
  out.tipMeta = {
    ...(out.tipMeta || {}),
    actionSequence: forest.state.actionSequence,
    liveNoteCount: forest.state.liveNoteCount,
    nextLeafIndex: forest.state.nextLeafIndex,
    stateCommitment: forest.state.stateCommitment,
    source: 'bootstrap-tip-forest',
  };
  out.feeUtxos = Array.isArray(out.feeUtxos) ? out.feeUtxos : [];
  out.history = Array.isArray(out.history) ? out.history : [];
  writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`);
  console.log(JSON.stringify({
    ok: true,
    out: outPath,
    actionSequence: forest.state.actionSequence,
    stateCommitment: forest.state.stateCommitment,
    liveNoteCount: forest.state.liveNoteCount,
    nextLeafIndex: forest.state.nextLeafIndex,
  }));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
