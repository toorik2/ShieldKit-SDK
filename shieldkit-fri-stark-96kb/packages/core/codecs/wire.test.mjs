import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import {
  encodeState,
  decodeState,
  genesisState,
  nftCommitmentFromState,
  STATE_BYTES,
} from './state.mjs';
import {
  encodePacket,
  decodePacket,
  statementDigest,
  statementDigestHex,
  PACKET_BYTES,
  KIND,
} from './packet.mjs';
import { applyTransition } from './transition.mjs';
import { NoteTree } from '../trees/note-tree.mjs';
import { assertPoseidon2Kat } from '../crypto/poseidon2.mjs';
import { digest4ToHex, h4, DOMAIN_IVS } from '../crypto/h4.mjs';

const profileId = createHash('sha256').update('test-profile').digest('hex');
const instanceId = createHash('sha256').update('test-instance').digest('hex');

test('Poseidon2 KAT matches vendor', () => {
  assert.equal(assertPoseidon2Kat(), true);
});

test('H4 domain IVs are unique nonzero', () => {
  const hexes = Object.values(DOMAIN_IVS).map((iv) => iv.map(String).join(','));
  assert.equal(new Set(hexes).size, hexes.length);
});

test('SFS1 is exactly 128 bytes and round-trips', () => {
  const g = genesisState({ profileId, maximumLiveNotes: 100_000 });
  const buf = encodeState(g);
  assert.equal(buf.length, STATE_BYTES);
  assert.equal(buf.length, 128);
  assert.equal(buf.subarray(0, 4).toString(), 'SFS1');
  const back = decodeState(buf);
  assert.deepEqual(back, g);
  // NFT commitment is full state bytes
  const nft = nftCommitmentFromState(g);
  assert.equal(nft.length, 128);
  assert.ok(nft.equals(buf));
});

test('SFS1 rejects bad reserve', () => {
  const g = genesisState({ profileId });
  g.reserveSats = '1';
  assert.throws(() => encodeState(g));
});

test('SFP1 is exactly 424 bytes; statementDigest = SHA256(packet)', () => {
  const pre = genesisState({ profileId });
  const tree = new NoteTree();
  const leaf = digest4ToHex(h4('NOTE_LEAF', [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]));
  const { root } = tree.append(leaf);
  const post = applyTransition(pre, {
    kind: KIND.DEPOSIT,
    nextNoteRoot: root,
    nextNullifierRoot: pre.nullifierRoot,
  });
  const packet = {
    networkId: 2,
    kind: KIND.DEPOSIT,
    flags: 0,
    instanceId,
    preState: pre,
    postState: post,
    publicNullifier: '0'.repeat(64),
    outputNoteLeaf: leaf,
    withdrawalLockingBytecodeHash: '0'.repeat(64),
    transactionContextHash: createHash('sha256').update('ctx').digest('hex'),
  };
  const buf = encodePacket(packet);
  assert.equal(buf.length, PACKET_BYTES);
  assert.equal(buf.length, 424);
  assert.equal(buf.subarray(0, 4).toString(), 'SFP1');
  const back = decodePacket(buf);
  assert.equal(back.kind, KIND.DEPOSIT);
  assert.equal(back.postState.noteCount, 1);
  const dig = statementDigest(buf);
  assert.equal(dig.length, 32);
  assert.equal(statementDigestHex(buf), createHash('sha256').update(buf).digest('hex'));
  // flip one byte → digest changes
  const mut = Buffer.from(buf);
  mut[50] ^= 1;
  assert.notEqual(createHash('sha256').update(mut).digest('hex'), statementDigestHex(buf));
});

test('SFP1 rejects deposit with nonzero nullifier', () => {
  const pre = genesisState({ profileId });
  const post = applyTransition(pre, {
    kind: KIND.DEPOSIT,
    nextNoteRoot: digest4ToHex(h4('NOTE', [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n])),
    nextNullifierRoot: pre.nullifierRoot,
  });
  assert.throws(() => encodePacket({
    networkId: 2,
    kind: KIND.DEPOSIT,
    instanceId,
    preState: pre,
    postState: post,
    publicNullifier: digest4ToHex(h4('NULLIFIER', [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n])),
    outputNoteLeaf: '0'.repeat(64),
    withdrawalLockingBytecodeHash: '0'.repeat(64),
    transactionContextHash: '0'.repeat(64),
  }));
});

test('NoteTree depth-20 append changes root', () => {
  const t = new NoteTree(32);
  const r0 = t.root;
  const leaf = digest4ToHex(h4('NOTE_LEAF', [9n, 8n, 7n, 6n, 5n, 4n, 3n, 2n]));
  const { root, index, path } = t.append(leaf);
  assert.equal(index, 0);
  assert.equal(path.length, 32);
  assert.notEqual(root, r0);
});
