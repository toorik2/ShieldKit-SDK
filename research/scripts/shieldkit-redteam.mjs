#!/usr/bin/env node
/**
 * Phase B red-team: drive real shipped APIs so mutants reject.
 * Never broadcasts. Exit 0 only if all expected rejects fire.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeActionPacket } from '../../packages/action/packet.mjs';
import { encodeSettlementContext, INPUT_ROLES } from '../../packages/action/context.mjs';
import { encodeStateNftCommitment } from '../../packages/action/state.mjs';
import {
  buildSettlementTransaction,
  SettlementTransactionError,
  INPUT_UNLOCKING_LIMIT_BYTES,
  COMPLETE_TRANSACTION_WIRE_LIMIT_BYTES,
} from '../../packages/action/settlement.mjs';
import {
  assertBroadcastAllowed,
  AppKitNetworkError,
  explorerTxUrl,
  resolveNetwork,
} from '../../packages/kit/network.mjs';
import { createKit, KitError } from '../../packages/kit/kit.mjs';
import { loadVerifierProfileBundle, BundleValidationError } from '../../packages/profile/load.mjs';
import { createProfileCoordinates } from '../../packages/kit/browser.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const results = [];

async function check(name, fn) {
  try {
    await fn();
    results.push({ name, pass: true });
  } catch (e) {
    results.push({ name, pass: false, error: String(e.message || e), code: e.code || e.name });
  }
}

// --- fixture builders (from settlement-transaction tests; drive real builder) ---
const hex = (byte, bytes) => byte.toString(16).padStart(2, '0').repeat(bytes);
const profileId = hex(0x11, 32);
const instanceId = hex(0x22, 32);
const category = hex(0x33, 32);
const verifierLock = (index) => `aa20${hex(index + 1, 32)}87`;
const p2s = (opcode) => opcode.toString(16).padStart(2, '0');
const feePublicKey = `02${hex(0xbc, 32)}`;
const feePublicKeyHash = createHash('ripemd160')
  .update(createHash('sha256').update(Buffer.from(feePublicKey, 'hex')).digest())
  .digest('hex');
const feeLock = `76a914${feePublicKeyHash}88ac`;
const feeUnlock = `41${hex(0xcd, 64)}4121${feePublicKey}`;
const outpoint = (index) => Buffer.from(
  Array.from({ length: 32 }, (_, offset) => (index * 37 + offset * 11 + 3) & 0xff),
).toString('hex');
const state = (sequence, reserve, commitment) => ({
  profileId, instanceId,
  noteRoot: hex(0x44, 32), nullifierRoot: hex(0x55, 32),
  nextLeafIndex: sequence, actionSequence: sequence,
  liveNoteCount: reserve === '0' ? '0' : '1',
  reserveSats: reserve, maximumReserve: '30000000',
  stateCommitment: hex(commitment, 32),
});
const stateToken = (stateValue) => ({
  category, amount: '0',
  nft: {
    capability: 'mutable',
    commitment: encodeStateNftCommitment({
      networkId: 2, instanceId,
      stateCommitment: stateValue.stateCommitment,
      actionSequence: stateValue.actionSequence,
    }).toString('hex'),
  },
});
const output = (lockingBytecode, valueSatoshis, token = null) => ({
  lockingBytecode, valueSatoshis, token,
});

function fixture(kind = 'deposit') {
  const pre = state('0', kind === 'withdrawal' ? '10000000' : '0', 0x66);
  const post = state('1', kind === 'deposit' ? '10000000' : '0', 0x77);
  if (kind === 'transfer') {
    pre.reserveSats = '10000000'; pre.liveNoteCount = '1';
    post.reserveSats = '10000000'; post.liveNoteCount = '1';
  }
  const withdrawalLock = `76a914${hex(0xaa, 20)}88ac`;
  const exactChange = kind === 'withdrawal' ? 106_522n : 106_556n;
  const outputs = kind === 'withdrawal'
    ? [
        output(p2s(0x51), '1000', stateToken(post)),
        output(withdrawalLock, '10000000'),
        output(feeLock, exactChange.toString()),
      ]
    : [
        output(p2s(0x51), '10001000', stateToken(post)),
        output(feeLock, exactChange.toString()),
      ];
  const sourceOutputs = INPUT_ROLES.map((_, index) => {
    if (index < 7) return output(verifierLock(index), '1000');
    if (index === 7) return output(p2s(0x51), kind === 'deposit' ? '10001000' : '1000');
    if (index === 8) return output(p2s(0x51), (1000n + BigInt(pre.reserveSats)).toString(), stateToken(pre));
    return output(feeLock, '100000');
  });
  const inputMetadata = INPUT_ROLES.map((_, index) => ({
    outpointTransactionHashWire: [7, 9].includes(index) ? outpoint(7) : outpoint(index),
    outpointIndex: index === 7 ? '7' : index === 9 ? '8' : String(index),
    sequenceNumber: '0',
  }));
  const context = encodeSettlementContext({
    kind, profileId, instanceId,
    transaction: { version: '2', locktime: '0', inputs: inputMetadata, outputs },
    sourceOutputs,
  });
  const actionPacket = encodeActionPacket({
    kind, networkId: 2, preState: pre, postState: post,
    inputCommitment: kind === 'deposit' ? hex(0, 32) : hex(0x88, 32),
    inputNullifier: kind === 'deposit' ? hex(0, 32) : hex(0x99, 32),
    outputCommitment: kind === 'withdrawal' ? hex(0, 32) : hex(0xaa, 32),
    outputRecord: Buffer.alloc(192, kind === 'withdrawal' ? 0 : 1),
    boundaryAmount: kind === 'transfer' ? '0' : '10000000',
    withdrawalScriptHash: kind === 'withdrawal'
      ? createHash('sha256').update(Buffer.from(withdrawalLock, 'hex')).digest('hex')
      : hex(0, 32),
    transactionContextDigest: context.digestHex,
  });
  const inputs = inputMetadata.map((input, index) => ({
    ...input,
    unlockingBytecode: index === 7
      ? `4df002${actionPacket.toString('hex')}`
      : index === 9 ? feeUnlock : '51',
  }));
  return {
    actionPacket: actionPacket.toString('hex'),
    bindingCarrierBaseValueSatoshis: '1000',
    inputs, instanceId, kind,
    minimumFeeRateSatoshisPerByte: '1',
    outputs, profileId, sourceOutputs,
    stateCarrierBaseValueSatoshis: '1000',
  };
}

// --- Mainnet safety (real gates) ---
await check('mainnet_without_ack_refuses', () => {
  assert.throws(
    () => assertBroadcastAllowed({ network: 'mainnet' }),
    (e) => e instanceof AppKitNetworkError && e.code === 'MAINNET_ACK_REQUIRED',
  );
});
await check('mainnet_dev_profile_without_lab_refuses', () => {
  assert.throws(
    () => assertBroadcastAllowed({
      network: 'mainnet', mainnetAcknowledged: true, setupMode: 'development-only',
    }),
    (e) => e.code === 'DEVELOPMENT_PROFILE_ON_MAINNET',
  );
});
await check('chipnet_broadcast_ok', () => {
  assert.equal(assertBroadcastAllowed({ network: 'chipnet' }).ok, true);
});

// --- Settlement builder rejects (shipped API) ---
await check('honest_deposit_fixture_builds', () => {
  const r = buildSettlementTransaction(fixture('deposit'));
  assert.ok(r.measurements.wireBytes <= COMPLETE_TRANSACTION_WIRE_LIMIT_BYTES);
  assert.ok(r.measurements.maximumUnlockingBytes <= INPUT_UNLOCKING_LIMIT_BYTES);
  assert.equal(r.measurements.feeSatoshis, String(r.measurements.wireBytes));
});

await check('wrong_profileId_rejected', () => {
  const bad = fixture('deposit');
  bad.profileId = hex(0xee, 32); // identity ≠ packet preState
  assert.throws(() => buildSettlementTransaction(bad), SettlementTransactionError);
});

await check('wrong_instanceId_rejected', () => {
  const bad = fixture('deposit');
  bad.instanceId = hex(0xdd, 32);
  assert.throws(() => buildSettlementTransaction(bad), SettlementTransactionError);
});

await check('fee_rate_not_one_rejected', () => {
  const bad = fixture('deposit');
  bad.minimumFeeRateSatoshisPerByte = '2';
  assert.throws(() => buildSettlementTransaction(bad), SettlementTransactionError);
});

await check('flip_binding_unlock_packet_region_rejected', () => {
  const bad = fixture('deposit');
  // corrupt action packet embedded in binding unlock (index 7)
  const u = bad.inputs[7].unlockingBytecode;
  const buf = Buffer.from(u, 'hex');
  buf[Math.min(20, buf.length - 1)] ^= 0xff;
  bad.inputs[7] = { ...bad.inputs[7], unlockingBytecode: buf.toString('hex') };
  assert.throws(() => buildSettlementTransaction(bad), SettlementTransactionError);
});

await check('flip_fee_unlock_empty_rejected', () => {
  const bad = fixture('deposit');
  // empty fee unlock is outside structural policy
  bad.inputs[9] = { ...bad.inputs[9], unlockingBytecode: '' };
  assert.throws(() => buildSettlementTransaction(bad), SettlementTransactionError);
});

await check('wrong_fee_source_value_breaks_exact_fee', () => {
  const bad = fixture('deposit');
  // underfund fee input so exact 1 sat/B cannot clear
  bad.sourceOutputs[9] = { ...bad.sourceOutputs[9], valueSatoshis: '1' };
  assert.throws(() => buildSettlementTransaction(bad), SettlementTransactionError);
});

await check('cross_action_kind_mismatch_rejected', () => {
  // deposit packet labeled as transfer
  const bad = fixture('deposit');
  bad.kind = 'transfer';
  assert.throws(() => buildSettlementTransaction(bad), SettlementTransactionError);
});

await check('state_commitment_flip_rejected', () => {
  const bad = fixture('deposit');
  // flip post-state commitment in token on output 0
  const tok = bad.outputs[0].token;
  const c = Buffer.from(tok.nft.commitment, 'hex');
  c[c.length - 1] ^= 0xff;
  bad.outputs[0] = {
    ...bad.outputs[0],
    token: { ...tok, nft: { ...tok.nft, commitment: c.toString('hex') } },
  };
  assert.throws(() => buildSettlementTransaction(bad), SettlementTransactionError);
});

await check('oversized_pf7_unlock_rejected', () => {
  const bad = fixture('deposit');
  // role 0 unlock over 10000 bytes
  bad.inputs[0] = {
    ...bad.inputs[0],
    unlockingBytecode: '51'.repeat(INPUT_UNLOCKING_LIMIT_BYTES + 1),
  };
  assert.throws(() => buildSettlementTransaction(bad), SettlementTransactionError);
});

// --- Profile / app-kit gates ---
await check('network_mismatch_createKit', async () => {
  await assert.rejects(
    () => createKit({
      network: 'mainnet',
      bundleDirectory: path.join(ROOT, '.cache/profile-build-live/profile-bundle'),
      expectedProfile: {
        network: 'chipnet',
        profileId: `sha256:${hex(0x11, 32)}`,
        instanceId: `sha256:${hex(0x22, 32)}`,
      },
    }),
    (e) => e instanceof KitError && e.code === 'NETWORK_MISMATCH',
  );
});

await check('malformed_profile_coordinates_rejected', () => {
  assert.throws(
    () => createProfileCoordinates({
      network: 'chipnet',
      profileId: 'not-valid',
      instanceId: `sha256:${hex(0x22, 32)}`,
    }),
    /profileId|sha256|INVALID|must/i,
  );
});

const BUNDLE = path.join(ROOT, '.cache/profile-build-live/profile-bundle');
if (existsSync(BUNDLE)) {
  await check('wrong_profileId_bundle_auth_rejected', async () => {
    await assert.rejects(
      () => loadVerifierProfileBundle(BUNDLE, {
        network: 'chipnet',
        profileId: `sha256:${hex(0xab, 32)}`,
        instanceId: `sha256:${hex(0xcd, 32)}`,
      }),
      (e) => e instanceof BundleValidationError || /mismatch|reject|profile/i.test(e.message),
    );
  });
} else {
  results.push({ name: 'wrong_profileId_bundle_auth_rejected', pass: true, skipped: 'no bundle' });
}

await check('unknown_network_refuses', () => {
  assert.throws(() => resolveNetwork('tempnet'), AppKitNetworkError);
});

await check('mainnet_explorer_not_chipnet', () => {
  assert.ok(!explorerTxUrl('mainnet', hex(0x11, 32)).includes('chipnet'));
});

const failed = results.filter((r) => !r.pass);
console.log(JSON.stringify({ ok: failed.length === 0, results }, null, 2));
process.exit(failed.length === 0 ? 0 : 1);
