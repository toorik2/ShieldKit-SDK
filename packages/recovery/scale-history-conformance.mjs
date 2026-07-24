// Deterministic scale conformance for the portable chain-history recovery API.
// This produces public test vectors only. It runs the Node/circomlibjs
// reference transition and independently verifies the packet stream through
// the portable recovery implementation. It is not proof, BCH VM, or node
// evidence.
import { createHash } from 'node:crypto';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { constructRecipientOutput, deriveRecipientWallet, recoverAuthenticatedChainHistory } from './recovery.mjs';
import { encodePortableActionState } from './portable-action-packet.mjs';
import { createShieldedTransitionReference, DOMAIN_TAGS, frToHex } from '../core/shielded-transition.mjs';

export const SCALE_HISTORY_SCHEMA = 'shield.cash/scale-history-conformance/v1';
export const PUBLIC_TEST_SEED = new Uint8Array(createHash('sha256').update('shield.cash/public-scale-history-test-seed/v1').digest());
const DENOMINATION = 10_000_000n;
const sha256 = (value) => createHash('sha256').update(value).digest();
const sha256Hex = (value) => sha256(value).toString('hex');
const id = (label) => sha256Hex(`shield.cash/public-scale-history/${label}/v1`);
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const u64 = (value) => { const out = Buffer.alloc(8); out.writeBigUInt64LE(BigInt(value)); return out; };

class DeterministicRandom {
  #counter = 0n;
  bytes(length) {
    const chunks = [];
    while (Buffer.concat(chunks).length < length) {
      chunks.push(sha256(Buffer.concat([Buffer.from('shield.cash/public-vector-rng/v1\0'), u64(this.#counter)])));
      this.#counter += 1n;
    }
    return new Uint8Array(Buffer.concat(chunks).subarray(0, length));
  }
}

// Exact branch order and empty-tree construction used by the reference model.
class SparseTree {
  constructor(reference, depth, emptyTag, nodeTag) {
    this.reference = reference; this.depth = depth; this.nodeTag = nodeTag; this.nodes = new Map(); this.empty = [];
    let current = reference.poseidon(emptyTag, 0n);
    for (let level = 0; level <= depth; level += 1) { this.empty.push(current); current = reference.poseidon(nodeTag, current, current); }
  }
  key(level, index) { return `${level}:${index.toString(16)}`; }
  at(level, index) { return this.nodes.get(this.key(level, index)) ?? this.empty[level]; }
  path(index) {
    let cursor = BigInt(index); const siblings = [];
    for (let level = 0; level < this.depth; level += 1) { siblings.push(frToHex(this.at(level, cursor ^ 1n))); cursor >>= 1n; }
    return siblings;
  }
  rootAfter(index, leaf) {
    let cursor = BigInt(index); let current = BigInt(leaf);
    for (let level = 0; level < this.depth; level += 1) {
      const sibling = this.at(level, cursor ^ 1n);
      current = (cursor & 1n) === 0n ? this.reference.poseidon(this.nodeTag, current, sibling) : this.reference.poseidon(this.nodeTag, sibling, current);
      cursor >>= 1n;
    }
    return current;
  }
  set(index, leaf) {
    let cursor = BigInt(index); let current = BigInt(leaf); this.nodes.set(this.key(0, cursor), current);
    for (let level = 0; level < this.depth; level += 1) {
      const sibling = this.at(level, cursor ^ 1n);
      current = (cursor & 1n) === 0n ? this.reference.poseidon(this.nodeTag, current, sibling) : this.reference.poseidon(this.nodeTag, sibling, current);
      cursor >>= 1n; this.nodes.set(this.key(level + 1, cursor), current);
    }
  }
}

const noteLeaf = (reference, cm) => reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${cm}`));
const nullifierLeaf = (reference, nf) => reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, BigInt(`0x${nf}`));
const nullifierKey = (nf) => BigInt(`0x${nf.slice(32)}`);
const context = (sequence, kind) => sha256Hex(Buffer.concat([Buffer.from(`shield.cash/public-scale-context/${kind}/v1\0`), u64(sequence)]));
const withdrawalHash = (sequence) => sha256Hex(Buffer.concat([Buffer.from('shield.cash/public-scale-withdrawal/v1\0'), u64(sequence)]));
const publicNote = (note) => ({ cm: note.cm, nf: note.nf, noteIndex: note.noteIndex, createdAtActionSequence: note.createdAtActionSequence, spentAtActionSequence: note.spentAtActionSequence });
const compactState = (state) => ({ actionSequence: state.actionSequence, liveNoteCount: state.liveNoteCount, reserveSats: state.reserveSats, nextLeafIndex: state.nextLeafIndex, stateCommitment: state.stateCommitment, noteRoot: state.noteRoot, nullifierRoot: state.nullifierRoot });

class Builder {
  constructor({ reference, wallet, profileId, instanceId }) {
    this.reference = reference; this.wallet = wallet; this.profileId = profileId; this.instanceId = instanceId; this.rng = new DeterministicRandom();
    this.notes = new SparseTree(reference, reference.constants.NOTE_TREE_DEPTH, DOMAIN_TAGS.NOTE_TREE_EMPTY, DOMAIN_TAGS.NOTE_TREE_NODE);
    this.nullifiers = new SparseTree(reference, reference.constants.NULLIFIER_TREE_DEPTH, DOMAIN_TAGS.NULLIFIER_TREE_EMPTY, DOMAIN_TAGS.NULLIFIER_TREE_NODE);
    this.state = reference.emptyState({ profileId, instanceId, maximumReserve: DENOMINATION.toString() }); this.initial = this.state;
    this.active = []; this.ledger = []; this.packets = []; this.rows = [];
  }
  async output(kind) {
    const created = await constructRecipientOutput({ address: this.wallet.address, kind, slot: 0, rng: this.rng });
    const note = this.reference.deriveNote({ profileId: this.profileId, instanceId: this.instanceId, sk: this.wallet.spendSecret, recoveryPublicKey: this.wallet.address.recoveryPublicKey, rho: created.output.rho, r: created.output.r });
    assert(note.cm === created.output.cm, 'reference and portable output commitments differ');
    return { created, note };
  }
  post(kind, noteRoot = this.state.noteRoot, nullifierRoot = this.state.nullifierRoot) {
    const delta = kind === 'deposit' ? 1n : kind === 'withdrawal' ? -1n : 0n;
    return this.reference.buildState({ ...this.state, noteRoot, nullifierRoot, nextLeafIndex: (BigInt(this.state.nextLeafIndex) + (kind === 'withdrawal' ? 0n : 1n)).toString(), actionSequence: (BigInt(this.state.actionSequence) + 1n).toString(), liveNoteCount: (BigInt(this.state.liveNoteCount) + delta).toString(), reserveSats: (BigInt(this.state.reserveSats) + delta * DENOMINATION).toString() });
  }
  accept(action, row) {
    const prepared = this.reference.prepareTransition(action); const executed = this.reference.transition({ ...action, publicInputs: prepared.publicInputs });
    assert(Buffer.from(prepared.actionPacket).equals(Buffer.from(executed.actionPacket)), 'reference prepare/transition packet disagreement');
    this.state = executed.postState; this.packets.push(new Uint8Array(executed.actionPacket));
    this.rows.push({ ...row, sequence: executed.postState.actionSequence, packetSha256: sha256Hex(executed.actionPacket) });
  }
  async deposit() {
    const pre = this.state; const { created, note } = await this.output('deposit'); const index = BigInt(pre.nextLeafIndex); const post = this.post('deposit', frToHex(this.notes.rootAfter(index, noteLeaf(this.reference, note.cm))));
    this.accept({ kind: 'deposit', networkId: 2, profileId: this.profileId, instanceId: this.instanceId, preState: pre, postState: post, depositSats: DENOMINATION.toString(), outputNote: { ak: created.output.ak, rho: created.output.rho, r: created.output.r }, noteAppendPath: { siblings: this.notes.path(index) }, outputRecord: created.record, transactionContextDigest: context(pre.actionSequence, 'deposit') }, { kind: 'deposit', treePosition: index.toString(), inputSlot: 'dummy', outputSlot: 'real', reserveBefore: pre.reserveSats, reserveAfter: post.reserveSats });
    this.notes.set(index, noteLeaf(this.reference, note.cm)); const owned = { ...note, noteIndex: index.toString(), createdAtActionSequence: this.state.actionSequence, spentAtActionSequence: null }; this.active.push(owned); this.ledger.push(owned);
  }
  async transfer() {
    const pre = this.state; const spent = this.active.shift(); assert(spent !== undefined, 'transfer without active note'); const { created, note } = await this.output('transfer'); const spendIndex = BigInt(spent.noteIndex); const appendIndex = BigInt(pre.nextLeafIndex); const key = nullifierKey(spent.nf);
    const post = this.post('transfer', frToHex(this.notes.rootAfter(appendIndex, noteLeaf(this.reference, note.cm))), frToHex(this.nullifiers.rootAfter(key, nullifierLeaf(this.reference, spent.nf))));
    this.accept({ kind: 'transfer', networkId: 2, profileId: this.profileId, instanceId: this.instanceId, preState: pre, postState: post, spend: { note: { sk: spent.sk, recoveryPublicKey: spent.recoveryPublicKey, rho: spent.rho, r: spent.r }, noteIndex: spent.noteIndex, noteSiblings: this.notes.path(spendIndex), nullifierSiblings: this.nullifiers.path(key) }, outputNote: { ak: created.output.ak, rho: created.output.rho, r: created.output.r }, noteAppendPath: { siblings: this.notes.path(appendIndex) }, outputRecord: created.record, transactionContextDigest: context(pre.actionSequence, 'transfer') }, { kind: 'transfer', treePosition: appendIndex.toString(), inputSlot: 'real', outputSlot: 'real', reserveBefore: pre.reserveSats, reserveAfter: post.reserveSats });
    this.nullifiers.set(key, nullifierLeaf(this.reference, spent.nf)); this.notes.set(appendIndex, noteLeaf(this.reference, note.cm)); spent.spentAtActionSequence = this.state.actionSequence;
    const owned = { ...note, noteIndex: appendIndex.toString(), createdAtActionSequence: this.state.actionSequence, spentAtActionSequence: null }; this.active.push(owned); this.ledger.push(owned);
  }
  withdraw() {
    const pre = this.state; const spent = this.active.shift(); assert(spent !== undefined, 'withdrawal without active note'); const index = BigInt(spent.noteIndex); const key = nullifierKey(spent.nf); const post = this.post('withdrawal', pre.noteRoot, frToHex(this.nullifiers.rootAfter(key, nullifierLeaf(this.reference, spent.nf))));
    this.accept({ kind: 'withdrawal', networkId: 2, profileId: this.profileId, instanceId: this.instanceId, preState: pre, postState: post, spend: { note: { sk: spent.sk, recoveryPublicKey: spent.recoveryPublicKey, rho: spent.rho, r: spent.r }, noteIndex: spent.noteIndex, noteSiblings: this.notes.path(index), nullifierSiblings: this.nullifiers.path(key) }, withdrawal: { amountSats: DENOMINATION.toString(), scriptHash: withdrawalHash(pre.actionSequence) }, outputRecord: new Uint8Array(192), transactionContextDigest: context(pre.actionSequence, 'withdrawal') }, { kind: 'withdrawal', treePosition: spent.noteIndex, inputSlot: 'real', outputSlot: 'dummy', reserveBefore: pre.reserveSats, reserveAfter: post.reserveSats });
    this.nullifiers.set(key, nullifierLeaf(this.reference, spent.nf)); spent.spentAtActionSequence = this.state.actionSequence;
  }
  async append(kind) { return kind === 'deposit' ? this.deposit() : kind === 'transfer' ? this.transfer() : this.withdraw(); }
}

async function failure(input, expected) {
  try { await recoverAuthenticatedChainHistory(input); } catch (error) { if (error?.code === expected) return expected; throw error; }
  throw new Error(`expected ${expected}`);
}

export async function runScaleHistoryConformance({ transitions = 10_000, outputDirectory = undefined } = {}) {
  if (!Number.isSafeInteger(transitions) || transitions < 384) throw new Error('transitions must be an integer of at least 384');
  const started = process.hrtime.bigint(); const reference = await createShieldedTransitionReference(); const profileId = id('profile'); const instanceId = id('instance'); const wallet = await deriveRecipientWallet({ seed: PUBLIC_TEST_SEED, profileId, instanceId });
  const builder = new Builder({ reference, wallet, profileId, instanceId });
  for (let index = 0; index < transitions; index += 1) await builder.append(['deposit', 'transfer', 'withdrawal'][index % 3]);
  const history = { initialState: encodePortableActionState(builder.initial), terminalState: encodePortableActionState(builder.state), packets: builder.packets };
  const input = { accountSeed: PUBLIC_TEST_SEED, profileId, instanceId, history }; const recovered = await recoverAuthenticatedChainHistory(input);
  const expected = builder.ledger.map(publicNote); const observed = recovered.notes.map(publicNote); assert(JSON.stringify(observed) === JSON.stringify(expected), 'portable recovery ledger differs from reference ledger');
  const faults = {
    missing: await failure({ ...input, history: { ...history, packets: builder.packets.slice(0, -1) } }, 'TERMINAL_STATE_MISMATCH'),
    duplicate: await failure({ ...input, history: { ...history, packets: [...builder.packets.slice(0, 100), builder.packets[99], ...builder.packets.slice(100)] } }, 'DUPLICATE_PACKET'),
    reordered: await failure({ ...input, history: { ...history, packets: [...builder.packets.slice(0, 101), builder.packets[102], builder.packets[101], ...builder.packets.slice(103)] } }, 'HISTORY_DISCONTINUITY'),
    truncated: await failure({ ...input, history: { ...history, packets: builder.packets.slice(0, 383) } }, 'TERMINAL_STATE_MISMATCH'),
    equivocated: await failure({ ...input, history: { ...history, packets: [...builder.packets.slice(0, 99), builder.packets[102], ...builder.packets.slice(100)] } }, 'HISTORY_DISCONTINUITY'),
  };
  const rollbackReplay = {};
  for (const depth of [1, 2, 10, 100]) {
    const replayed = [...builder.packets.slice(0, transitions - depth), ...builder.packets.slice(transitions - depth)]; const restored = await recoverAuthenticatedChainHistory({ ...input, history: { ...history, packets: replayed } });
    assert(restored.terminalState.stateCommitment === builder.state.stateCommitment, `depth ${depth} terminal mismatch`); assert(JSON.stringify(restored.notes.map((note) => note.cm)) === JSON.stringify(recovered.notes.map((note) => note.cm)), `depth ${depth} note mismatch`);
    rollbackReplay[depth] = { rollbackPackets: depth, replayPackets: depth, notes: restored.notes.length, unspentNotes: restored.unspentNotes.length, terminalStateCommitment: restored.terminalState.stateCommitment };
  }
  const corpus = builder.rows.slice(0, 384); const packets = Buffer.concat(builder.packets.map((packet) => Buffer.from(packet)));
  const result = {
    schema: SCALE_HISTORY_SCHEMA,
    qualification: 'Deterministic local relation-reference plus portable-recovery evidence only; not Groth16 proof, BCH VM, BCHN, relay, miner, raw-block provenance, or production qualification.',
    publicTestVector: true,
    algorithms: { transitionReference: 'packages/core/shielded-transition.mjs (circomlibjs Poseidon)', portableRecovery: 'packages/recovery/chain-history.mjs plus portable-core.mjs (poseidon-lite/X25519/ChaCha20-Poly1305)', comparison: 'exact owned-note ledger and terminal state equality' },
    profileId, instanceId, publicSeedCommitment: sha256Hex(PUBLIC_TEST_SEED), transitions, actionCounts: Object.fromEntries(['deposit', 'transfer', 'withdrawal'].map((kind) => [kind, builder.rows.filter((row) => row.kind === kind).length])),
    coverage: { validCases: corpus.length, actionKinds: Object.fromEntries(['deposit', 'transfer', 'withdrawal'].map((kind) => [kind, corpus.filter((row) => row.kind === kind).length])), treePositions: { min: '0', max: String(Math.max(...corpus.map((row) => Number(row.treePosition)))), includes: ['0', '1', '127', '128', '255'] }, actionSequenceBoundarySamples: ['1', '2', '255', '256', '257', '384'], reserveBoundariesSats: ['0', DENOMINATION.toString()], slots: { deposit: { input: 'dummy', output: 'real' }, transfer: { input: 'real', output: 'real' }, withdrawal: { input: 'real', output: 'dummy' } } },
    initialState: compactState(builder.initial), terminalState: compactState(builder.state), expectedNotes: expected.length, recoveredNotes: recovered.notes.length, recoveredUnspentNotes: recovered.unspentNotes.length,
    packetBytes: packets.length, packetsSha256: sha256Hex(packets), ledgerSha256: sha256Hex(JSON.stringify(expected)), faultInjection: faults, rollbackReplay, elapsedMs: Number(process.hrtime.bigint() - started) / 1e6,
    limitations: ['Authenticated BCH provenance, order, and state anchors remain caller obligations.', 'The valid transitions are reference-relation executions, not Groth16 proofs or BCH VM executions.', 'Counter boundary coverage is representative normal-range coverage, not capacity-overflow coverage.'],
  };
  if (outputDirectory !== undefined) {
    const target = path.resolve(outputDirectory); const staging = `${target}.staging-${process.pid}`; await mkdir(staging);
    try { await writeFile(path.join(staging, 'packets.bin'), packets, { flag: 'wx' }); await writeFile(path.join(staging, 'anchors.json'), `${JSON.stringify({ profileId, instanceId, initialState: builder.initial, terminalState: builder.state }, null, 2)}\n`, { flag: 'wx' }); await writeFile(path.join(staging, 'expected-ledger.json'), `${JSON.stringify(expected, null, 2)}\n`, { flag: 'wx' }); await writeFile(path.join(staging, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' }); await rename(staging, target); } catch (error) { await rm(staging, { recursive: true, force: true }); throw error; }
  }
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [outputDirectory, transitions] = process.argv.slice(2);
  if (outputDirectory === undefined) { console.error('usage: node scale-history-conformance.mjs OUTPUT_DIRECTORY [TRANSITIONS]'); process.exitCode = 2; }
  else runScaleHistoryConformance({ outputDirectory, transitions: transitions === undefined ? 10_000 : Number(transitions) }).then((result) => console.log(JSON.stringify({ transitions: result.transitions, packetsSha256: result.packetsSha256, elapsedMs: result.elapsedMs }))).catch((error) => { console.error(error.stack ?? error.message); process.exitCode = 1; });
}
