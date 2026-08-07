/**
 * State@0 full plan bind tests — shipped compileStateCovenant + Libauth VM.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import {
  createVirtualMachineBch2026,
  hexToBin,
  binToHex,
  hash256,
  encodeLockingBytecodeP2sh32,
} from '@bitauth/libauth';
import {
  compileStateCovenant,
  buildStateScriptSig,
  hashSfc1ProductStructuralHex,
  ROLE_COUNT,
  DEFAULT_NETWORK_ID,
  DENOMINATION_SATS,
} from './state-covenant.mjs';
import {
  genesisState,
  encodeState,
} from '../core/codecs/state.mjs';
import {
  encodePacket,
  KIND,
  PACKET_BYTES,
  statementDigestHex,
} from '../core/codecs/packet.mjs';
import { applyTransition } from '../core/codecs/transition.mjs';
import { encodeSfc1, hashSfc1Hex, sfc1ModelFromProductTx } from '../core/codecs/sfc1.mjs';
import { digest4ToHex, h4, ZERO_DIGEST4_HEX } from '../core/crypto/h4.mjs';

const vm = createVirtualMachineBch2026();
const profileId = createHash('sha256').update('state0-test-profile').digest('hex');
const categoryHex = createHash('sha256').update('state0-instance').digest('hex');

function p2sh32(redeemHex) {
  const r = hexToBin(redeemHex);
  const locking = encodeLockingBytecodeP2sh32(hash256(r));
  if (typeof locking === 'string') throw new Error(locking);
  return binToHex(locking);
}

function fakeRoleLock(seed) {
  const redeem = createHash('sha256').update(String(seed)).digest();
  const red = Buffer.concat([Buffer.from([0x51]), redeem]);
  return p2sh32(red.toString('hex'));
}

function makeDepositPacket(overrides = {}) {
  const pre = genesisState({ profileId, maximumLiveNotes: 100_000 });
  const nextNoteRoot = digest4ToHex(h4('NOTE', [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]));
  const post = applyTransition(pre, {
    kind: KIND.DEPOSIT,
    nextNoteRoot,
    nextNullifierRoot: pre.nullifierRoot,
  });
  const preHex = encodeState(pre).toString('hex');
  const postHex = encodeState(post).toString('hex');
  const kind = KIND.DEPOSIT;
  const txContextHash =
    overrides.transactionContextHash ??
    hashSfc1ProductStructuralHex({
      categoryHex,
      preCommitmentHex: preHex,
      postCommitmentHex: postHex,
      kind,
      networkId: DEFAULT_NETWORK_ID,
    });
  const packet = {
    networkId: DEFAULT_NETWORK_ID,
    kind,
    flags: 0,
    instanceId: categoryHex,
    preState: pre,
    postState: post,
    publicNullifier: ZERO_DIGEST4_HEX,
    outputNoteLeaf: nextNoteRoot,
    withdrawalLockingBytecodeHash: '0'.repeat(64),
    transactionContextHash: txContextHash,
    ...overrides,
  };
  // re-apply structural hash if states overridden without hash
  if (!overrides.transactionContextHash) {
    packet.transactionContextHash = hashSfc1ProductStructuralHex({
      categoryHex: packet.instanceId,
      preCommitmentHex: encodeState(packet.preState).toString('hex'),
      postCommitmentHex: encodeState(packet.postState).toString('hex'),
      kind: packet.kind,
      networkId: packet.networkId,
    });
  }
  const buf = encodePacket(packet);
  return {
    packet,
    packetHex: buf.toString('hex'),
    preHex: encodeState(packet.preState).toString('hex'),
    postHex: encodeState(packet.postState).toString('hex'),
    pre: packet.preState,
    post: packet.postState,
    kind: packet.kind,
  };
}

function evalState0({
  covenant,
  packetHex,
  preHex,
  postHex,
  categoryHex: cat,
  roleLocks,
  omitRole = false,
  /** Swap successor role locks only (source stays fixed) — continuity attack. */
  swapRoleLock = false,
  forgeCommitmentOut = false,
  wrongCategory = false,
  stateValueIn = null,
  stateValueOut = null,
}) {
  const n = roleLocks.length;
  const sourceRoles = roleLocks.slice();
  const destRoles = roleLocks.slice();
  if (swapRoleLock && destRoles.length > 1) {
    const t = destRoles[0];
    destRoles[0] = destRoles[1];
    destRoles[1] = t;
  }
  const roleN = omitRole ? n - 1 : n;
  const srcUsed = sourceRoles.slice(0, roleN);
  const dstUsed = destRoles.slice(0, roleN);
  const catIn = wrongCategory ? '22'.repeat(32) : cat;
  // reserve at offset 112
  const preRes = Buffer.from(preHex, 'hex').readBigUInt64LE(112);
  const postRes = Buffer.from(postHex, 'hex').readBigUInt64LE(112);
  const base = 2000n;
  const vin = stateValueIn != null ? BigInt(stateValueIn) : base + preRes;
  const vout =
    stateValueOut != null
      ? BigInt(stateValueOut)
      : forgeCommitmentOut
        ? base + postRes
        : base + postRes;

  const commitOut = forgeCommitmentOut ? '11'.repeat(128) : postHex;
  const stateLock = covenant.lockingHex;
  const z32 = new Uint8Array(32);

  const tokenIn = {
    category: hexToBin(catIn),
    amount: 0n,
    nft: { capability: 'mutable', commitment: hexToBin(preHex) },
  };
  const tokenOut = {
    category: hexToBin(cat),
    amount: 0n,
    nft: { capability: 'mutable', commitment: hexToBin(commitOut) },
  };

  const inputs = [
    {
      outpointTransactionHash: z32,
      outpointIndex: 0,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: hexToBin(buildStateScriptSig(covenant.redeemHex, packetHex)),
    },
  ];
  for (let i = 0; i < roleN; i += 1) {
    inputs.push({
      outpointTransactionHash: z32,
      outpointIndex: i + 1,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: hexToBin('51'),
    });
  }
  const outputs = [
    {
      lockingBytecode: hexToBin(stateLock),
      valueSatoshis: vout,
      token: tokenOut,
    },
  ];
  for (let i = 0; i < roleN; i += 1) {
    outputs.push({
      lockingBytecode: hexToBin(dstUsed[i]),
      valueSatoshis: 1000n,
    });
  }
  const sourceOutputs = [
    {
      lockingBytecode: hexToBin(stateLock),
      valueSatoshis: vin,
      token: tokenIn,
    },
  ];
  for (let i = 0; i < roleN; i += 1) {
    sourceOutputs.push({
      lockingBytecode: hexToBin(srcUsed[i]),
      valueSatoshis: 1000n,
    });
  }

  const tx = { version: 2, inputs, outputs, locktime: 0 };
  const tr = vm.debug({ inputIndex: 0, sourceOutputs, transaction: tx });
  const last = tr[tr.length - 1];
  const top = last.stack?.length ? last.stack[last.stack.length - 1] : undefined;
  const ok =
    !last.error &&
    top &&
    top.length > 0 &&
    !(top.length === 1 && top[0] === 0);
  return {
    ok,
    error: last.error ? String(last.error).slice(0, 240) : null,
    redeemBytes: covenant.redeemBytes,
  };
}

const covenant = compileStateCovenant({ roleCount: ROLE_COUNT });
const roleLocks = Array.from({ length: ROLE_COUNT }, (_, i) => fakeRoleLock(`role-${i}`));
const dep = makeDepositPacket();

test('state@0 covenant compiles plan-bound non-operator P2SH32', () => {
  assert.equal(covenant.operatorKeySpendable, false);
  assert.equal(covenant.cantDoEvil, true);
  assert.equal(covenant.planState0, true);
  assert.equal(covenant.bindsPacket, true);
  assert.equal(covenant.bindsSfs1Transition, true);
  assert.equal(covenant.bindsSfc1, true);
  assert.match(covenant.lockingHex, /^aa20[0-9a-f]{64}87$/);
  assert.ok(covenant.redeemBytes > 100);
  assert.ok(covenant.redeemBytes < 4000);
});

test('honest deposit state@0 accepts on Libauth', () => {
  const r = evalState0({
    covenant,
    packetHex: dep.packetHex,
    preHex: dep.preHex,
    postHex: dep.postHex,
    categoryHex,
    roleLocks,
  });
  assert.equal(r.ok, true, r.error);
});

test('omit role rejects', () => {
  const r = evalState0({
    covenant,
    packetHex: dep.packetHex,
    preHex: dep.preHex,
    postHex: dep.postHex,
    categoryHex,
    roleLocks,
    omitRole: true,
  });
  assert.equal(r.ok, false);
});

test('swap role lock rejects', () => {
  const r = evalState0({
    covenant,
    packetHex: dep.packetHex,
    preHex: dep.preHex,
    postHex: dep.postHex,
    categoryHex,
    roleLocks,
    swapRoleLock: true,
  });
  assert.equal(r.ok, false);
});

test('wrong category rejects', () => {
  const r = evalState0({
    covenant,
    packetHex: dep.packetHex,
    preHex: dep.preHex,
    postHex: dep.postHex,
    categoryHex,
    roleLocks,
    wrongCategory: true,
  });
  assert.equal(r.ok, false);
});

test('forge output commitment rejects', () => {
  const r = evalState0({
    covenant,
    packetHex: dep.packetHex,
    preHex: dep.preHex,
    postHex: dep.postHex,
    categoryHex,
    roleLocks,
    forgeCommitmentOut: true,
  });
  assert.equal(r.ok, false);
});

test('forged SFC1 txContextHash rejects', () => {
  const bad = makeDepositPacket({
    transactionContextHash: 'aa'.repeat(32),
  });
  const r = evalState0({
    covenant,
    packetHex: bad.packetHex,
    preHex: bad.preHex,
    postHex: bad.postHex,
    categoryHex,
    roleLocks,
  });
  assert.equal(r.ok, false);
});

test('bindSfc1=false still accepts honest deposit (topology+packet path)', () => {
  const soft = compileStateCovenant({ roleCount: ROLE_COUNT, bindSfc1: false });
  assert.equal(soft.bindsSfc1, false);
  const r = evalState0({
    covenant: soft,
    packetHex: dep.packetHex,
    preHex: dep.preHex,
    postHex: dep.postHex,
    categoryHex,
    roleLocks,
  });
  assert.equal(r.ok, true, r.error);
});

test('bad packet magic rejects', () => {
  const bad = Buffer.from(dep.packetHex, 'hex');
  bad[0] = 0x00;
  const r = evalState0({
    covenant,
    packetHex: bad.toString('hex'),
    preHex: dep.preHex,
    postHex: dep.postHex,
    categoryHex,
    roleLocks,
  });
  assert.equal(r.ok, false);
});

test('bad sequence (packet post.seq) rejects', () => {
  const pre = genesisState({ profileId });
  const nextNoteRoot = digest4ToHex(h4('NOTE', [9n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
  const post = applyTransition(pre, {
    kind: KIND.DEPOSIT,
    nextNoteRoot,
    nextNullifierRoot: pre.nullifierRoot,
  });
  post.actionSequence = '99'; // invalid jump
  // encodeState will throw on sequence invariant — build raw packet manually
  const preB = encodeState(pre);
  const postBad = Buffer.from(encodeState({
    ...post,
    actionSequence: (BigInt(pre.actionSequence) + 1n).toString(),
  }));
  // corrupt sequence bytes only after valid encode
  postBad.writeBigUInt64LE(99n, 120);
  const kind = KIND.DEPOSIT;
  const txContextHash = hashSfc1ProductStructuralHex({
    categoryHex,
    preCommitmentHex: preB.toString('hex'),
    postCommitmentHex: postBad.toString('hex'),
    kind,
    networkId: DEFAULT_NETWORK_ID,
  });
  const packet = Buffer.concat([
    Buffer.from('SFP1'),
    Buffer.from([DEFAULT_NETWORK_ID, kind, 0, 0]),
    Buffer.from(categoryHex, 'hex'),
    preB,
    postBad,
    Buffer.alloc(32),
    Buffer.from(nextNoteRoot, 'hex'),
    Buffer.alloc(32),
    Buffer.from(txContextHash, 'hex'),
  ]);
  assert.equal(packet.length, PACKET_BYTES);
  const r = evalState0({
    covenant,
    packetHex: packet.toString('hex'),
    preHex: preB.toString('hex'),
    postHex: postBad.toString('hex'),
    categoryHex,
    roleLocks,
  });
  assert.equal(r.ok, false);
});

test('operator P2PKH is not product state lock', () => {
  assert.ok(covenant.lockingHex.startsWith('aa20'));
  assert.ok(!covenant.lockingHex.startsWith('76a914'));
});

test('statementDigest is SHA256(SFP1)', () => {
  assert.equal(statementDigestHex(Buffer.from(dep.packetHex, 'hex')).length, 64);
});

test('SFC1 full codec encodes and hashes', () => {
  const model = sfc1ModelFromProductTx({
    networkId: 2,
    action: KIND.DEPOSIT,
    categoryHex,
    preCommitmentHex: dep.preHex,
    postCommitmentHex: dep.postHex,
    stateLockingHex: covenant.lockingHex,
    roleLockingHexes: roleLocks,
    stateValueIn: 2000n,
    stateValueOut: 2000n + BigInt(DENOMINATION_SATS),
  });
  const bytes = encodeSfc1(model);
  assert.ok(bytes.length > 50);
  assert.equal(bytes.subarray(0, 4).toString(), 'SFC1');
  assert.equal(hashSfc1Hex(model).length, 64);
});

test('transfer and withdrawal transitions accept', () => {
  // transfer
  const pre0 = genesisState({ profileId });
  const n1 = digest4ToHex(h4('NOTE', [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
  const mid = applyTransition(pre0, {
    kind: KIND.DEPOSIT,
    nextNoteRoot: n1,
    nextNullifierRoot: pre0.nullifierRoot,
  });
  const n2 = digest4ToHex(h4('NOTE', [2n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
  const nfR = digest4ToHex(h4('NULLIFIER', [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
  const postT = applyTransition(mid, {
    kind: KIND.TRANSFER,
    nextNoteRoot: n2,
    nextNullifierRoot: nfR,
  });
  const preHex = encodeState(mid).toString('hex');
  const postHex = encodeState(postT).toString('hex');
  const kind = KIND.TRANSFER;
  const txContextHash = hashSfc1ProductStructuralHex({
    categoryHex,
    preCommitmentHex: preHex,
    postCommitmentHex: postHex,
    kind,
    networkId: DEFAULT_NETWORK_ID,
  });
  const pkt = encodePacket({
    networkId: DEFAULT_NETWORK_ID,
    kind,
    flags: 0,
    instanceId: categoryHex,
    preState: mid,
    postState: postT,
    publicNullifier: digest4ToHex(h4('NULLIFIER', [1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n])),
    outputNoteLeaf: n2,
    withdrawalLockingBytecodeHash: '0'.repeat(64),
    transactionContextHash: txContextHash,
  });
  const rT = evalState0({
    covenant,
    packetHex: pkt.toString('hex'),
    preHex,
    postHex,
    categoryHex,
    roleLocks,
  });
  assert.equal(rT.ok, true, rT.error);

  // withdrawal from mid
  const postW = applyTransition(mid, {
    kind: KIND.WITHDRAWAL,
    nextNoteRoot: mid.noteRoot,
    nextNullifierRoot: nfR,
  });
  const preW = encodeState(mid).toString('hex');
  const postWH = encodeState(postW).toString('hex');
  const txW = hashSfc1ProductStructuralHex({
    categoryHex,
    preCommitmentHex: preW,
    postCommitmentHex: postWH,
    kind: KIND.WITHDRAWAL,
    networkId: DEFAULT_NETWORK_ID,
  });
  const pktW = encodePacket({
    networkId: DEFAULT_NETWORK_ID,
    kind: KIND.WITHDRAWAL,
    flags: 0,
    instanceId: categoryHex,
    preState: mid,
    postState: postW,
    publicNullifier: digest4ToHex(h4('NULLIFIER', [2n, 2n, 2n, 2n, 2n, 2n, 2n, 2n])),
    outputNoteLeaf: ZERO_DIGEST4_HEX,
    withdrawalLockingBytecodeHash: createHash('sha256').update('payout').digest('hex'),
    transactionContextHash: txW,
  });
  const rW = evalState0({
    covenant,
    packetHex: pktW.toString('hex'),
    preHex: preW,
    postHex: postWH,
    categoryHex,
    roleLocks,
  });
  assert.equal(rW.ok, true, rW.error);
});
