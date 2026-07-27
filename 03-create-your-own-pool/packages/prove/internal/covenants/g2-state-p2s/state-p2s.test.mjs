// This is a state-covenant feasibility test, not proof, binding, relay, or G2
// qualification. SCAR packets come from the real local transition reference.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  createVirtualMachineBch2026,
  bigIntToVmNumber,
  encodeDataPush,
  hexToBin,
} from '@bitauth/libauth';
import {
  createShieldedTransitionReference,
  DENOMINATION_SATS,
  DOMAIN_TAGS,
  NOTE_TREE_DEPTH,
  NULLIFIER_TREE_DEPTH,
  OUTPUT_RECORD_BYTES,
  frToHex,
} from '../../../../action/transition.mjs';
import {
  BABYJUB_BASE8,
  babyJubMul,
  bytesToHex,
  packBabyJubPoint,
} from '../../../../recover/portable-core.mjs';

const here = new URL('.', import.meta.url);
const hex = text => Uint8Array.from(Buffer.from(text, 'hex'));
const sha256 = bytes => createHash('sha256').update(bytes).digest();
const concat = items => Uint8Array.from(Buffer.concat(items.map(item => Buffer.from(item))));
const cashcRoot = process.env.CASHC_ROOT || resolve(
  fileURLToPath(new URL('../../../../unlock-builder/vendor/verifier/vendor/cashc-resched/packages/cashc/', import.meta.url)),
);
const cashc = await import(pathToFileURL(resolve(cashcRoot, 'dist/index.js')).href);
assert.equal(cashc.version, '0.14.0-next.1');

function rootFromPath(reference, leaf, index, siblings, tag) {
  let current = leaf;
  for (let level = 0; level < siblings.length; level += 1) current = ((index >> BigInt(level)) & 1n) === 0n ? reference.poseidon(tag, current, siblings[level]) : reference.poseidon(tag, siblings[level], current);
  return current;
}
function emptySiblings(reference, depth, emptyTag, nodeTag) {
  const siblings = []; let empty = reference.poseidon(emptyTag, 0n);
  for (let level = 0; level < depth; level += 1) { siblings.push(empty); empty = reference.poseidon(nodeTag, empty, empty); }
  return siblings;
}
const field = value => frToHex(BigInt(value));
const recoveryKey = scalar => bytesToHex(
  packBabyJubPoint(babyJubMul(BABYJUB_BASE8, BigInt(scalar))),
);
const bound = (reference, action) => ({ ...action, publicInputs: reference.prepareTransition(action).publicInputs });

async function fixtures() {
  const reference = await createShieldedTransitionReference();
  const profileId = createHash('sha256').update('g1-reference-profile').digest('hex');
  const instanceId = createHash('sha256').update('g1-reference-instance').digest('hex');
  const initial = reference.emptyState({ profileId, instanceId, maximumReserve: '30000000' });
  const notePathEmpty = emptySiblings(reference, NOTE_TREE_DEPTH, DOMAIN_TAGS.NOTE_TREE_EMPTY, DOMAIN_TAGS.NOTE_TREE_NODE);
  const nullifierPathEmpty = emptySiblings(reference, NULLIFIER_TREE_DEPTH, DOMAIN_TAGS.NULLIFIER_TREE_EMPTY, DOMAIN_TAGS.NULLIFIER_TREE_NODE);
  const note1 = {
    sk: field(11), recoveryPublicKey: recoveryKey(31), rho: field(12), r: field(13),
  };
  const note2 = {
    sk: field(21), recoveryPublicKey: recoveryKey(41), rho: field(22), r: field(23),
  };
  const derived1 = reference.deriveNote({ ...note1, profileId, instanceId });
  const derived2 = reference.deriveNote({ ...note2, profileId, instanceId });
  const rootAfterDeposit = frToHex(rootFromPath(reference, reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived1.cm}`)), 0n, notePathEmpty, DOMAIN_TAGS.NOTE_TREE_NODE));
  const depositPost = reference.buildState({ ...initial, noteRoot: rootAfterDeposit, nextLeafIndex: '1', actionSequence: '1', liveNoteCount: '1', reserveSats: DENOMINATION_SATS.toString() });
  const deposit = { kind: 'deposit', networkId: 2, profileId, instanceId, preState: initial, postState: depositPost, depositSats: DENOMINATION_SATS.toString(), outputNote: { ak: derived1.ak, rho: note1.rho, r: note1.r }, noteAppendPath: { siblings: notePathEmpty.map(frToHex) }, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 1), transactionContextDigest: createHash('sha256').update('deposit-context').digest('hex') };
  const appendForIndex1 = [reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived1.cm}`)), ...notePathEmpty.slice(1)];
  const rootAfterTransfer = frToHex(rootFromPath(reference, reference.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${derived2.cm}`)), 1n, appendForIndex1, DOMAIN_TAGS.NOTE_TREE_NODE));
  const nullKey = BigInt(`0x${Buffer.from(derived1.nf, 'hex').subarray(16).toString('hex')}`);
  const postNullifier = frToHex(rootFromPath(reference, reference.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, BigInt(`0x${derived1.nf}`)), nullKey, nullifierPathEmpty, DOMAIN_TAGS.NULLIFIER_TREE_NODE));
  const transferPost = reference.buildState({ ...depositPost, noteRoot: rootAfterTransfer, nullifierRoot: postNullifier, nextLeafIndex: '2', actionSequence: '2' });
  const transfer = { kind: 'transfer', networkId: 2, profileId, instanceId, preState: depositPost, postState: transferPost, spend: { note: note1, noteIndex: '0', noteSiblings: notePathEmpty.map(frToHex), nullifierSiblings: nullifierPathEmpty.map(frToHex) }, outputNote: { ak: derived2.ak, rho: note2.rho, r: note2.r }, noteAppendPath: { siblings: appendForIndex1.map(frToHex) }, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 2), transactionContextDigest: createHash('sha256').update('transfer-context').digest('hex') };
  const withdrawalPost = reference.buildState({ ...depositPost, nullifierRoot: postNullifier, actionSequence: '2', liveNoteCount: '0', reserveSats: '0' });
  const withdrawal = { kind: 'withdrawal', networkId: 2, profileId, instanceId, preState: depositPost, postState: withdrawalPost, spend: { note: note1, noteIndex: '0', noteSiblings: notePathEmpty.map(frToHex), nullifierSiblings: nullifierPathEmpty.map(frToHex) }, withdrawal: { amountSats: DENOMINATION_SATS.toString(), scriptHash: sha256(Uint8Array.of(0x51)).toString('hex') }, outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES), transactionContextDigest: createHash('sha256').update('withdrawal-context').digest('hex') };
  return { reference, profileId, instanceId, actions: [deposit, transfer, withdrawal].map(action => reference.transition(bound(reference, action))) };
}

function compile() {
  return cashc.compileString(awaitedSource, { optimizeFor: 'size' });
}
const awaitedSource = await readFile(new URL('ShieldStateV1.cash', here), 'utf8');

function instantiate(artifact, { bindingLock, profileId, instanceId, category, carrierBase }) {
  const base = cashc.utils.scriptToBytecode(cashc.utils.asmToScript(artifact.bytecode));
  const args = [bindingLock, hex(profileId), hex(instanceId), category, bigIntToVmNumber(carrierBase)];
  return concat([...args.reverse().map(encodeDataPush), base]);
}
function token(category, commitment) { return { category, amount: 0n, nft: { capability: 'mutable', commitment } }; }
function transactionFor({ accepted, lock, bindingLock, category, reference, profileId, carrierBase }) {
  void profileId;
  const preCommitment = reference.stateNftCommitment({ networkId: 2, instanceId: accepted.preState.instanceId, stateCommitment: accepted.preState.stateCommitment, actionSequence: accepted.preState.actionSequence });
  const postCommitment = reference.stateNftCommitment({ networkId: 2, instanceId: accepted.postState.instanceId, stateCommitment: accepted.postState.stateCommitment, actionSequence: accepted.postState.actionSequence });
  const sourceOutputs = Array.from({ length: 10 }, () => ({ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1_000n }));
  sourceOutputs[7] = { lockingBytecode: bindingLock, valueSatoshis: 1_000n };
  sourceOutputs[8] = { lockingBytecode: lock, valueSatoshis: carrierBase + BigInt(accepted.preState.reserveSats), token: token(category, preCommitment) };
  const outputs = [{ lockingBytecode: lock, valueSatoshis: carrierBase + BigInt(accepted.postState.reserveSats), token: token(category, postCommitment) }];
  if (accepted.kind === 'withdrawal') outputs.push({ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: DENOMINATION_SATS }, { lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1_000n });
  else outputs.push({ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1_000n });
  return {
    version: 2, locktime: 0,
    inputs: sourceOutputs.map((_, index) => ({ outpointTransactionHash: new Uint8Array(32).fill(index + 1), outpointIndex: index, sequenceNumber: 0, unlockingBytecode: index === 7 ? concat([Uint8Array.of(0x4d, 0xf0, 0x02), accepted.actionPacket]) : index === 8 ? Uint8Array.from(Buffer.from('4b424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242', 'hex')) : new Uint8Array() })),
    outputs,
    sourceOutputs,
  };
}

test('full frozen state semantics compile far beyond the 190-byte bare-P2S limit', () => {
  const artifact = compile();
  const base = cashc.utils.scriptToBytecode(cashc.utils.asmToScript(artifact.bytecode));
  assert.equal(base.length, 729);
  const lock = instantiate(artifact, { bindingLock: Uint8Array.of(0x51), profileId: '11'.repeat(32), instanceId: '22'.repeat(32), category: new Uint8Array(32).fill(0x33), carrierBase: 1000n });
  assert.equal(lock.length, 833);
  assert.ok(base.length > 190);
  assert.ok(lock.length > 190);
});

test('the archived >190-byte lock is not an accepting path for the current action packets', async () => {
  const artifact = compile(); const { reference, profileId, instanceId, actions } = await fixtures();
  const bindingLock = Uint8Array.of(0x51); const category = new Uint8Array(32).fill(0x33); const carrierBase = 1000n;
  const lock = instantiate(artifact, { bindingLock, profileId, instanceId, category, carrierBase });
  assert.equal(lock.length, 833);
  for (const accepted of actions) {
    const program = transactionFor({ accepted, lock, bindingLock, category, reference, profileId, carrierBase });
    for (const standard of [false, true]) {
      const result = createVirtualMachineBch2026(standard).evaluate({ inputIndex: 8, sourceOutputs: program.sourceOutputs, transaction: program });
      assert.notEqual(result.error, undefined, `${accepted.kind}, standard=${standard}: archived candidate unexpectedly accepted`);
    }
  }
});
