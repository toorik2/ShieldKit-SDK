// Typed, local witness material for the pinned V2 low128 G1 relation. This is
// deliberately profile-bound and does not initialize setup, make proofs, or
// construct BCH transactions.
import { createHash } from 'node:crypto';
import {
  DENOMINATION_SATS, DOMAIN_TAGS, NULLIFIER_TREE_DEPTH, NOTE_TREE_DEPTH,
  OUTPUT_RECORD_BYTES, createShieldedTransitionReference, frToHex, frFromHex, frToBytes,
} from './transition.mjs';
import { loadVerifierProfileBundle } from '../profile/load.mjs';
import { constructRecipientOutput, deriveRecipientWallet } from '../recover/recovery.mjs';
import { hexToBytes, unpackBabyJubPoint } from '../recover/portable-core.mjs';

const HEX_32 = /^[0-9a-f]{64}$/;
const KINDS = Object.freeze(['deposit', 'transfer', 'withdrawal']);

export class FreshWitnessInputsError extends Error {
  constructor(message) { super(message); this.name = 'FreshWitnessInputsError'; }
}
const fail = (message) => { throw new FreshWitnessInputsError(message); };
const hex32 = (value, label) => {
  if (typeof value !== 'string' || !HEX_32.test(value)) fail(`${label} must be 32 lowercase hexadecimal bytes`);
  return value;
};
const exactKeys = (value, label, expected) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} has missing or unknown properties`);
};
const idHex = (value, label) => {
  if (typeof value !== 'string' || !value.startsWith('sha256:')) fail(`${label} must be a sha256 identifier`);
  return hex32(value.slice('sha256:'.length), label);
};
const toDec = (hex) => BigInt(`0x${hex}`).toString();
const idLimbs = (hex) => [BigInt(`0x${hex.slice(0, 32)}`).toString(), BigInt(`0x${hex.slice(32)}`).toString()];
const recordBits = (record) => Array.from(record, (byte) => Array.from({ length: 8 }, (_, bit) => String((byte >> (7 - bit)) & 1))).flat();
const sha256 = (...parts) => {
  const hash = createHash('sha256'); for (const part of parts) hash.update(part); return hash.digest();
};

function deterministicRng(seed, label) {
  let counter = 0;
  return Object.freeze({ bytes(length) {
    const chunks = [];
    while (Buffer.concat(chunks).length < length) {
      const count = Buffer.alloc(4); count.writeUInt32BE(counter++);
      chunks.push(sha256(Buffer.from('shield.cash/fresh-witness-rng/v2\\0', 'utf8'), seed, Buffer.from(label, 'utf8'), count));
    }
    return Buffer.concat(chunks).subarray(0, length);
  } });
}

function emptySiblings(reference, depth, emptyTag, nodeTag) {
  const siblings = []; let empty = reference.poseidon(emptyTag, 0n);
  for (let level = 0; level < depth; level += 1) { siblings.push(frToHex(empty)); empty = reference.poseidon(nodeTag, empty, empty); }
  return siblings;
}
function rootFromPath(reference, leaf, index, siblings, tag) {
  let current = leaf;
  for (let level = 0; level < siblings.length; level += 1) {
    const sibling = BigInt(`0x${siblings[level]}`);
    current = ((index >> BigInt(level)) & 1n) === 0n ? reference.poseidon(tag, current, sibling) : reference.poseidon(tag, sibling, current);
  }
  return current;
}
/** Return the pre-insertion sparse path for `target`, where `leaves` is a map of occupied u128 keys to Fr leaves. */
function sparsePath(reference, target, leaves) {
  let nodes = new Map(leaves); let key = target; const siblings = [];
  let empty = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_EMPTY, 0n);
  for (let level = 0; level < NULLIFIER_TREE_DEPTH; level += 1) {
    siblings.push(frToHex(nodes.get((key ^ 1n).toString()) ?? empty));
    const parents = new Map(); const parentKeys = new Set([...nodes.keys()].map((entry) => (BigInt(entry) >> 1n).toString()));
    for (const parent of parentKeys) {
      const base = BigInt(parent) << 1n;
      parents.set(parent, reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_NODE, nodes.get(base.toString()) ?? empty, nodes.get((base | 1n).toString()) ?? empty));
    }
    nodes = parents; key >>= 1n; empty = reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_NODE, empty, empty);
  }
  return siblings;
}
function noteKey(note) {
  // Must match shielded-transition spendNote key derivation exactly.
  return BigInt(`0x${frToBytes(frFromHex(note.nf, 'input nullifier')).subarray(16, 32).toString('hex')}`);
}
function circuitInput({ kind, action, prepared, reference, maximumLiveNotes, recoveryEphemeralScalar = '0', recoverySpendPoint = undefined, recoveryViewPoint = undefined }) {
  const pre = prepared.preState; const post = prepared.postState; const profileId = pre.profileId; const instanceId = pre.instanceId;
  const spend = action.spend ? reference.deriveNote({ ...action.spend.note, profileId, instanceId }) : undefined;
  const output = action.outputNote ? reference.deriveOutputNote({ ...action.outputNote, profileId, instanceId }) : undefined;
  const inputViewPoint = spend ? unpackBabyJubPoint(hexToBytes(spend.recoveryPublicKey)) : undefined;
  const zero = '0'; const withdrawal = action.withdrawal;
  return Object.freeze({
    publicDigestHi: BigInt(`0x${prepared.publicInputs[0]}`).toString(), publicDigestLo: BigInt(`0x${prepared.publicInputs[1]}`).toString(),
    isDeposit: kind === 'deposit' ? '1' : '0', isTransfer: kind === 'transfer' ? '1' : '0', isWithdrawal: kind === 'withdrawal' ? '1' : '0',
    profileHi: idLimbs(profileId)[0], profileLo: idLimbs(profileId)[1], instanceHi: idLimbs(instanceId)[0], instanceLo: idLimbs(instanceId)[1],
    preNoteRoot: toDec(pre.noteRoot), preNullifierRoot: toDec(pre.nullifierRoot), preNextLeafIndex: pre.nextLeafIndex, preActionSequence: pre.actionSequence, preLiveNoteCount: pre.liveNoteCount, preReserveSats: pre.reserveSats, preMaximumReserve: pre.maximumReserve, preStateCommitment: toDec(pre.stateCommitment),
    postNoteRoot: toDec(post.noteRoot), postNullifierRoot: toDec(post.nullifierRoot), postNextLeafIndex: post.nextLeafIndex, postActionSequence: post.actionSequence, postLiveNoteCount: post.liveNoteCount, postReserveSats: post.reserveSats, postMaximumReserve: post.maximumReserve, postStateCommitment: toDec(post.stateCommitment), maximumLiveNotes: maximumLiveNotes.toString(),
    inSk: spend ? toDec(spend.sk) : zero, inRho: spend ? toDec(spend.rho) : zero, inR: spend ? toDec(spend.r) : zero, inputAk: spend ? toDec(spend.ak) : zero, inputCm: spend ? toDec(spend.cm) : zero, inputNf: spend ? toDec(spend.nf) : zero, inputViewX: inputViewPoint?.[0].toString() ?? zero, inputViewY: inputViewPoint?.[1].toString() ?? zero,
    outputAk: output ? toDec(output.ak) : zero, outputRho: output ? toDec(output.rho) : zero, outputR: output ? toDec(output.r) : zero, outputCm: output ? toDec(output.cm) : zero,
    appendSiblings: (action.noteAppendPath?.siblings ?? Array(NOTE_TREE_DEPTH).fill('0'.repeat(64))).map(toDec), noteSiblings: (action.spend?.noteSiblings ?? Array(NOTE_TREE_DEPTH).fill('0'.repeat(64))).map(toDec), noteIndex: action.spend?.noteIndex ?? zero, nullifierSiblings: (action.spend?.nullifierSiblings ?? Array(NULLIFIER_TREE_DEPTH).fill('0'.repeat(64))).map(toDec),
    boundaryAmount: kind === 'transfer' ? zero : DENOMINATION_SATS.toString(), withdrawalScriptHi: withdrawal ? idLimbs(withdrawal.scriptHash)[0] : zero, withdrawalScriptLo: withdrawal ? idLimbs(withdrawal.scriptHash)[1] : zero,
    recordBits: recordBits(action.outputRecord), recoverySpendX: recoverySpendPoint?.x ?? zero, recoverySpendY: recoverySpendPoint?.y ?? zero, recoveryViewX: recoveryViewPoint?.x ?? zero, recoveryViewY: recoveryViewPoint?.y ?? zero, recoveryEphemeralScalar, transactionContextHi: idLimbs(action.transactionContextDigest)[0], transactionContextLo: idLimbs(action.transactionContextDigest)[1],
  });
}

/**
 * Merkle siblings for note-tree index `index`.
 * `leafFrs` maps contiguous indices 0..n-1 → leaf Fr; the leaf at `index` may be
 * absent (append path) or present (auth path) — sibling selection ignores self.
 */
function noteTreeSiblings(reference, leafFrs, index) {
  let empty = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_EMPTY, 0n);
  let layer = new Map();
  for (let i = 0; i < leafFrs.length; i += 1) {
    if (leafFrs[i] !== undefined && leafFrs[i] !== null) layer.set(BigInt(i), leafFrs[i]);
  }
  const siblings = [];
  let idx = BigInt(index);
  for (let level = 0; level < NOTE_TREE_DEPTH; level += 1) {
    siblings.push(frToHex(layer.get(idx ^ 1n) ?? empty));
    const parents = new Map();
    const parentKeys = new Set([...layer.keys()].map((key) => key >> 1n));
    parentKeys.add(idx >> 1n);
    for (const parent of parentKeys) {
      const left = layer.get(parent << 1n) ?? empty;
      const right = layer.get((parent << 1n) | 1n) ?? empty;
      parents.set(parent, reference.poseidon(DOMAIN_TAGS.NOTE_TREE_NODE, left, right));
    }
    layer = parents;
    idx >>= 1n;
    empty = reference.poseidon(DOMAIN_TAGS.NOTE_TREE_NODE, empty, empty);
  }
  return siblings;
}

async function materializeCycleNotes(reference, profileId, instanceId, seed) {
  const recipient1Seed = sha256(Buffer.from('shield.cash/fresh-witness-wallet/deposit/v2\\0', 'utf8'), seed);
  const recipient2Seed = sha256(Buffer.from('shield.cash/fresh-witness-wallet/transfer/v2\\0', 'utf8'), seed);
  const recipient1 = await deriveRecipientWallet({ seed: recipient1Seed, profileId, instanceId });
  const recipient2 = await deriveRecipientWallet({ seed: recipient2Seed, profileId, instanceId });
  const depositOutput = await constructRecipientOutput({ address: recipient1.address, kind: 'deposit', slot: 0, rng: deterministicRng(seed, 'deposit') });
  const transferOutput = await constructRecipientOutput({ address: recipient2.address, kind: 'transfer', slot: 0, rng: deterministicRng(seed, 'transfer') });
  const note1 = { sk: recipient1.spendSecret, recoveryPublicKey: recipient1.address.recoveryPublicKey, rho: depositOutput.output.rho, r: depositOutput.output.r };
  const note2 = { sk: recipient2.spendSecret, recoveryPublicKey: recipient2.address.recoveryPublicKey, rho: transferOutput.output.rho, r: transferOutput.output.r };
  const outputNote1 = { ak: depositOutput.output.ak, rho: depositOutput.output.rho, r: depositOutput.output.r };
  const outputNote2 = { ak: transferOutput.output.ak, rho: transferOutput.output.rho, r: transferOutput.output.r };
  const derived1 = reference.deriveNote({ ...note1, profileId, instanceId });
  const derived2 = reference.deriveNote({ ...note2, profileId, instanceId });
  if (derived1.cm !== depositOutput.output.cm || derived2.cm !== transferOutput.output.cm) fail('public recipient output commitment mismatch');
  return {
    depositOutput, transferOutput, note1, note2, outputNote1, outputNote2, derived1, derived2,
    leaf1: reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived1.cm}`)),
    leaf2: reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived2.cm}`)),
    nfLeaf1: reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, BigInt(`0x${derived1.nf}`)),
    nfLeaf2: reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, BigInt(`0x${derived2.nf}`)),
    key1: noteKey(derived1), key2: noteKey(derived2),
  };
}

/**
 * Append one deposit note onto `tip` (allows liveNoteCount > 0).
 * This is the multi-note anonymity path: stack deposits before any withdraw.
 * Mutates tip in place. Returns the deposit action object.
 */
function advanceDepositOntoTip(reference, profileId, instanceId, tip, material, depositDigest) {
  const { note1, outputNote1, leaf1, depositOutput } = material;
  const baseSeq = BigInt(tip.state.actionSequence);
  const baseLive = BigInt(tip.state.liveNoteCount);
  const baseReserve = BigInt(tip.state.reserveSats);
  const maximum = BigInt(tip.state.maximumReserve);
  if (baseReserve + DENOMINATION_SATS > maximum) {
    fail(`deposit would exceed maximum reserve (live=${baseLive}, maxReserve=${maximum})`);
  }
  const depIndex = tip.noteLeaves.length;
  if (String(depIndex) !== tip.state.nextLeafIndex) {
    fail(`note leaf index desync tip.leaves=${depIndex} state.nextLeaf=${tip.state.nextLeafIndex}`);
  }
  const depSiblings = noteTreeSiblings(reference, tip.noteLeaves, depIndex);
  const depositPost = reference.buildState({
    ...tip.state,
    noteRoot: frToHex(rootFromPath(reference, leaf1, BigInt(depIndex), depSiblings, DOMAIN_TAGS.NOTE_TREE_NODE)),
    nextLeafIndex: String(depIndex + 1),
    actionSequence: (baseSeq + 1n).toString(),
    liveNoteCount: (baseLive + 1n).toString(),
    reserveSats: (baseReserve + DENOMINATION_SATS).toString(),
  });
  const deposit = {
    kind: 'deposit', networkId: 2, profileId, instanceId,
    preState: tip.state, postState: depositPost,
    depositSats: DENOMINATION_SATS.toString(), outputNote: outputNote1,
    noteAppendPath: { siblings: depSiblings }, outputRecord: depositOutput.record,
    transactionContextDigest: depositDigest,
  };
  tip.noteLeaves = [...tip.noteLeaves, leaf1];
  tip.openNoteMeta = tip.openNoteMeta || [];
  tip.openNoteMeta.push({
    noteIndex: depIndex,
    leaf: leaf1,
    note1: material.note1,
    key1: material.key1,
    nfLeaf1: material.nfLeaf1,
    witnessSeed: material.witnessSeedHex || null,
  });
  tip.state = depositPost;
  return deposit;
}

/**
 * Withdraw the last open (live) note on tip. Mutates tip.
 */
function advanceWithdrawOpenTip(reference, profileId, instanceId, tip, withdrawalScriptHash, withdrawalDigest) {
  const meta = tip.openNoteMeta;
  if (!meta?.length) fail('withdrawal requires at least one open live note');
  const open = meta[meta.length - 1];
  const baseSeq = BigInt(tip.state.actionSequence);
  const baseLive = BigInt(tip.state.liveNoteCount);
  const baseReserve = BigInt(tip.state.reserveSats);
  if (baseLive < 1n || baseReserve < DENOMINATION_SATS) fail('withdrawal underflows live reserve');
  const spendSiblings = noteTreeSiblings(reference, tip.noteLeaves, open.noteIndex);
  const nfPath = sparsePath(reference, open.key1, new Map(tip.nullifierLeaves));
  const withdrawalPost = reference.buildState({
    ...tip.state,
    nullifierRoot: frToHex(rootFromPath(reference, open.nfLeaf1, open.key1, nfPath, DOMAIN_TAGS.NULLIFIER_TREE_NODE)),
    actionSequence: (baseSeq + 1n).toString(),
    liveNoteCount: (baseLive - 1n).toString(),
    reserveSats: (baseReserve - DENOMINATION_SATS).toString(),
  });
  const withdrawal = {
    kind: 'withdrawal', networkId: 2, profileId, instanceId,
    preState: tip.state, postState: withdrawalPost,
    spend: {
      note: open.note1,
      noteIndex: String(open.noteIndex),
      noteSiblings: spendSiblings,
      nullifierSiblings: nfPath,
    },
    withdrawal: { amountSats: DENOMINATION_SATS.toString(), scriptHash: withdrawalScriptHash },
    outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES),
    transactionContextDigest: withdrawalDigest,
  };
  tip.nullifierLeaves = new Map(tip.nullifierLeaves);
  tip.nullifierLeaves.set(open.key1.toString(), open.nfLeaf1);
  tip.openNoteMeta = meta.slice(0, -1);
  tip.state = withdrawalPost;
  return withdrawal;
}

/**
 * Transfer the last open note → new note (live count unchanged). Mutates tip.
 */
function advanceTransferOpenTip(reference, profileId, instanceId, tip, material, transferDigest) {
  const meta = tip.openNoteMeta;
  if (!meta?.length) fail('transfer requires at least one open live note');
  const open = meta[meta.length - 1];
  const { note2, outputNote2, leaf2, nfLeaf2, key2, transferOutput } = material;
  const baseSeq = BigInt(tip.state.actionSequence);
  const xferIndex = tip.noteLeaves.length;
  const spendSiblings = noteTreeSiblings(reference, tip.noteLeaves, open.noteIndex);
  const xferSiblings = noteTreeSiblings(reference, tip.noteLeaves, xferIndex);
  const nfPath = sparsePath(reference, open.key1, new Map(tip.nullifierLeaves));
  const transferPost = reference.buildState({
    ...tip.state,
    noteRoot: frToHex(rootFromPath(reference, leaf2, BigInt(xferIndex), xferSiblings, DOMAIN_TAGS.NOTE_TREE_NODE)),
    nullifierRoot: frToHex(rootFromPath(reference, open.nfLeaf1, open.key1, nfPath, DOMAIN_TAGS.NULLIFIER_TREE_NODE)),
    nextLeafIndex: String(xferIndex + 1),
    actionSequence: (baseSeq + 1n).toString(),
    // live + reserve unchanged
  });
  const transfer = {
    kind: 'transfer', networkId: 2, profileId, instanceId,
    preState: tip.state, postState: transferPost,
    spend: {
      note: open.note1,
      noteIndex: String(open.noteIndex),
      noteSiblings: spendSiblings,
      nullifierSiblings: nfPath,
    },
    outputNote: outputNote2,
    noteAppendPath: { siblings: xferSiblings },
    outputRecord: transferOutput.record,
    transactionContextDigest: transferDigest,
  };
  tip.noteLeaves = [...tip.noteLeaves, leaf2];
  tip.nullifierLeaves = new Map(tip.nullifierLeaves);
  tip.nullifierLeaves.set(open.key1.toString(), open.nfLeaf1);
  tip.openNoteMeta = [
    ...meta.slice(0, -1),
    {
      noteIndex: xferIndex,
      leaf: leaf2,
      note1: note2,
      key1: key2,
      nfLeaf1: nfLeaf2,
      witnessSeed: material.witnessSeedHex || null,
    },
  ];
  tip.state = transferPost;
  return transfer;
}

/**
 * Legacy single-note cycle: requires empty live set, ends empty after withdrawal.
 * Used when openNotes is empty (classic D→T→W battery).
 */
function advanceOneCycle(reference, profileId, instanceId, tip, material, digests, withdrawalScriptHash, transferHops = 1) {
  if (transferHops !== 0 && transferHops !== 1) fail('transferHops must be 0 or 1 in this build');
  const baseLive = BigInt(tip.state.liveNoteCount);
  const baseReserve = BigInt(tip.state.reserveSats);
  if (baseLive !== 0n || baseReserve !== 0n) {
    fail('full cycle advance requires empty live set (use openNotes stacking for multi-note)');
  }
  const deposit = advanceDepositOntoTip(reference, profileId, instanceId, tip, material, digests.deposit);
  if (transferHops === 0) {
    const withdrawal = advanceWithdrawOpenTip(reference, profileId, instanceId, tip, withdrawalScriptHash, digests.withdrawal);
    return {
      deposit, transfer: null, withdrawal,
      depositOutput: material.depositOutput, transferOutput: material.transferOutput, transferHops: 0,
    };
  }
  const transfer = advanceTransferOpenTip(reference, profileId, instanceId, tip, material, digests.transfer);
  const withdrawal = advanceWithdrawOpenTip(reference, profileId, instanceId, tip, withdrawalScriptHash, digests.withdrawal);
  return {
    deposit, transfer, withdrawal,
    depositOutput: material.depositOutput, transferOutput: material.transferOutput, transferHops: 1,
  };
}

function finalizeActions(reference, maximumLiveNotes, actions, depositOutput, transferOutput) {
  const result = {};
  for (const kind of KINDS) {
    if (!actions[kind]) continue;
    const prepared = reference.transition({ ...actions[kind], publicInputs: reference.prepareTransition(actions[kind]).publicInputs });
    const recoveryWitness = kind === 'deposit' ? depositOutput.recoveryWitness : kind === 'transfer' ? transferOutput.recoveryWitness : undefined;
    result[kind] = Object.freeze({
      action: actions[kind], actionPacket: prepared.actionPacket, actionPacketHex: prepared.actionPacket.toString('hex'),
      actionDigest: prepared.actionDigest, publicInputs: prepared.publicInputs,
      circuitInput: circuitInput({
        kind, action: actions[kind], prepared, reference, maximumLiveNotes,
        recoveryEphemeralScalar: recoveryWitness?.ephemeralScalar ?? '0',
        recoverySpendPoint: recoveryWitness?.spendPoint, recoveryViewPoint: recoveryWitness?.recoveryPoint,
      }),
    });
  }
  return result;
}

/**
 * Generate relation-valid witness material for one authenticated development-only bundle.
 *
 * Modes:
 * 1. **Full cycle** (default): empty tip → D→[T]→W ending empty. Uses `priorCycles` of completed full cycles.
 * 2. **Open-note stack** (`priorOpenNotes`): live notes already on tip. Deposit stacks; transfer/withdraw act on LIFO open note.
 *
 * `transactionContextDigests` come from the fixed-point settlement builder (never fabricated here).
 */
export async function generateFreshWitnessInputs(input) {
  const optionalPrior = input.priorCycles !== undefined;
  const optionalOpen = input.priorOpenNotes !== undefined;
  const optionalHops = input.transferHops !== undefined;
  const optionalKind = input.actionKind !== undefined;
  const required = ['bundleDirectory', 'expectedProfile', 'transactionContextDigests', 'withdrawalScriptHash', 'witnessSeed'];
  if (optionalPrior) required.push('priorCycles');
  if (optionalOpen) required.push('priorOpenNotes');
  if (optionalHops) required.push('transferHops');
  if (optionalKind) required.push('actionKind');
  exactKeys(input, 'fresh witness input', required);
  if (typeof input.bundleDirectory !== 'string' || input.bundleDirectory.length === 0) fail('bundleDirectory must be non-empty');
  exactKeys(input.expectedProfile, 'expectedProfile', ['instanceId', 'network', 'profileId']);
  if (input.expectedProfile.network !== 'chipnet' && input.expectedProfile.network !== 'mainnet') {
    fail('expectedProfile network must be chipnet or mainnet');
  }
  idHex(input.expectedProfile.profileId, 'expectedProfile profileId'); idHex(input.expectedProfile.instanceId, 'expectedProfile instanceId');
  exactKeys(input.transactionContextDigests, 'transactionContextDigests', KINDS);
  for (const kind of KINDS) hex32(input.transactionContextDigests[kind], `${kind} transactionContextDigest`);
  hex32(input.withdrawalScriptHash, 'withdrawalScriptHash'); hex32(input.witnessSeed, 'witnessSeed');
  const transferHops = optionalHops ? Number(input.transferHops) : 1;
  if (transferHops !== 0 && transferHops !== 1) fail('transferHops must be 0 (deposit-withdraw) or 1 (full)');
  const actionKind = optionalKind ? input.actionKind : null;
  if (actionKind !== null && !KINDS.includes(actionKind)) fail('actionKind must be deposit|transfer|withdrawal');
  if (optionalPrior) {
    if (!Array.isArray(input.priorCycles)) fail('priorCycles must be an array');
    for (const [i, cycle] of input.priorCycles.entries()) {
      const priorKeys = ['transactionContextDigests', 'witnessSeed'];
      if (cycle.transferHops !== undefined) priorKeys.push('transferHops');
      exactKeys(cycle, `priorCycles[${i}]`, priorKeys);
      hex32(cycle.witnessSeed, `priorCycles[${i}].witnessSeed`);
      exactKeys(cycle.transactionContextDigests, `priorCycles[${i}].transactionContextDigests`, KINDS);
      for (const kind of KINDS) hex32(cycle.transactionContextDigests[kind], `priorCycles[${i}].${kind}`);
      if (cycle.transferHops !== undefined && cycle.transferHops !== 0 && cycle.transferHops !== 1) {
        fail(`priorCycles[${i}].transferHops must be 0 or 1`);
      }
    }
  }
  if (optionalOpen) {
    if (!Array.isArray(input.priorOpenNotes)) fail('priorOpenNotes must be an array');
    for (const [i, note] of input.priorOpenNotes.entries()) {
      const keys = ['witnessSeed', 'depositDigest'];
      if (note.phase !== undefined) keys.push('phase');
      if (note.transferDigest !== undefined) keys.push('transferDigest');
      exactKeys(note, `priorOpenNotes[${i}]`, keys);
      hex32(note.witnessSeed, `priorOpenNotes[${i}].witnessSeed`);
      hex32(note.depositDigest, `priorOpenNotes[${i}].depositDigest`);
      if (note.phase !== undefined && note.phase !== 'deposit' && note.phase !== 'transfer') {
        fail(`priorOpenNotes[${i}].phase must be deposit|transfer`);
      }
      if (note.transferDigest !== undefined) hex32(note.transferDigest, `priorOpenNotes[${i}].transferDigest`);
    }
  }
  const bundle = await loadVerifierProfileBundle(input.bundleDirectory, input.expectedProfile);
  if (bundle.manifest.setup.mode !== 'development-only' || bundle.manifest.setup.provenance.method !== 'local-initialization') fail('fresh witness pipeline accepts only authenticated development-only local profiles');
  if (bundle.manifest.network.name !== 'chipnet' || bundle.manifest.profile.relation.id !== 'shielded-action-v2' || bundle.manifest.profile.publicInputAbi.id !== 'shielded-action-public-input-v1') fail('bundle does not select the pinned Chipnet V2 relation and packet ABI');
  const profileId = idHex(bundle.profileId, 'bundle profileId'); const instanceId = idHex(bundle.instanceId, 'bundle instanceId'); const maximumReserve = bundle.manifest.genesis.reserveCapSatoshis;
  const maximumLiveNotes = BigInt(maximumReserve) / DENOMINATION_SATS;
  const reference = await createShieldedTransitionReference();
  const tip = {
    state: reference.emptyState({ profileId, instanceId, maximumReserve }),
    noteLeaves: [],
    nullifierLeaves: new Map(),
    openNoteMeta: [],
  };
  // 1) Completed full cycles (end empty live set; tree retains spent leaves).
  for (const cycle of input.priorCycles ?? []) {
    const seed = Buffer.from(cycle.witnessSeed, 'hex');
    const material = await materializeCycleNotes(reference, profileId, instanceId, seed);
    material.witnessSeedHex = cycle.witnessSeed;
    const hops = cycle.transferHops === undefined ? 1 : Number(cycle.transferHops);
    advanceOneCycle(reference, profileId, instanceId, tip, material, cycle.transactionContextDigests, input.withdrawalScriptHash, hops);
  }
  // 2) Live open notes currently in the pool (multi-note anonymity set).
  for (const open of input.priorOpenNotes ?? []) {
    const seed = Buffer.from(open.witnessSeed, 'hex');
    const material = await materializeCycleNotes(reference, profileId, instanceId, seed);
    material.witnessSeedHex = open.witnessSeed;
    advanceDepositOntoTip(reference, profileId, instanceId, tip, material, open.depositDigest);
    if (open.phase === 'transfer') {
      if (!open.transferDigest) fail('priorOpenNotes transfer phase requires transferDigest');
      advanceTransferOpenTip(reference, profileId, instanceId, tip, material, open.transferDigest);
    }
  }

  const seed = Buffer.from(input.witnessSeed, 'hex');
  const material = await materializeCycleNotes(reference, profileId, instanceId, seed);
  material.witnessSeedHex = input.witnessSeed;
  const digests = input.transactionContextDigests;
  const openCount = (input.priorOpenNotes ?? []).length;
  const stackMode = openCount > 0 || actionKind === 'deposit' || actionKind === 'transfer' || actionKind === 'withdrawal';

  let actions;
  let depositOutput = material.depositOutput;
  let transferOutput = material.transferOutput;
  let transferHopsOut = transferHops;

  if (stackMode && (openCount > 0 || actionKind)) {
    // Multi-note / single-action path: build only the requested action onto live tip.
    const kind = actionKind || 'deposit';
    actions = { deposit: null, transfer: null, withdrawal: null };
    if (kind === 'deposit') {
      actions.deposit = advanceDepositOntoTip(reference, profileId, instanceId, tip, material, digests.deposit);
    } else if (kind === 'transfer') {
      actions.transfer = advanceTransferOpenTip(reference, profileId, instanceId, tip, material, digests.transfer);
    } else {
      // Withdraw spends LIFO open note — seed must match that open note's deposit seed.
      // Rebuild: prior open notes already applied; if witnessSeed matches last open, use its material.
      const last = (input.priorOpenNotes ?? [])[(input.priorOpenNotes ?? []).length - 1];
      if (!last) fail('withdrawal requires priorOpenNotes (live notes)');
      if (last.witnessSeed !== input.witnessSeed) {
        fail('withdrawal witnessSeed must equal the open note being spent (LIFO seed)');
      }
      // Tip already includes all priorOpenNotes including the one to spend; withdraw it.
      actions.withdrawal = advanceWithdrawOpenTip(
        reference, profileId, instanceId, tip, input.withdrawalScriptHash, digests.withdrawal,
      );
    }
    transferHopsOut = null;
  } else {
    // Classic empty→full-cycle→empty battery.
    const advanced = advanceOneCycle(
      reference, profileId, instanceId, tip, material, digests, input.withdrawalScriptHash, transferHops,
    );
    actions = { deposit: advanced.deposit, transfer: advanced.transfer, withdrawal: advanced.withdrawal };
    depositOutput = advanced.depositOutput;
    transferOutput = advanced.transferOutput;
  }

  const result = finalizeActions(reference, maximumLiveNotes, actions, depositOutput, transferOutput);
  return Object.freeze({
    schema: 'shield.cash/fresh-witness-inputs/v2',
    qualification: 'development-only V2 relation witness material; no proof, PF7 verification, G2 settlement, Chipnet, or privacy claim',
    profile: Object.freeze({ profileId, instanceId, stateNftCategory: bundle.manifest.genesis.stateNftCategory, reserveCapSatoshis: maximumReserve, setupMode: bundle.manifest.setup.mode }),
    actions: Object.freeze(result),
    tipState: Object.freeze({ ...tip.state }),
    priorCycleCount: (input.priorCycles ?? []).length,
    priorOpenNoteCount: (input.priorOpenNotes ?? []).length,
    liveNoteCount: tip.state.liveNoteCount,
    transferHops: transferHopsOut,
  });
}
