import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { OperationCoordinator, hashBytes } from './coordinator.mjs';
import { DurableOperationStore, ReservationLedger } from './durable-store.mjs';
import {
  createSingleSendAdmission,
  transactionIdFromHex,
  classifySendFailure,
} from '../chain/admission.mjs';
import { ERROR_CODES, CliError } from '../contracts/errors.mjs';
import { writeHomeManifest } from '../home/resolve.mjs';
import { showDesign } from '../registry/designs.mjs';

function fakeHex(n = 100) {
  return 'ab'.repeat(n);
}

const TEST_IDENTITY = Object.freeze({ profileId: '11'.repeat(32), instanceId: '22'.repeat(32) });
const TEST_DESCRIPTOR = '33'.repeat(32);
const PF10 = showDesign('pf10');

function boundHome(prefix) {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  writeHomeManifest(dir, {
    backendId: PF10.backendId,
    designId: PF10.id,
    profileId: TEST_IDENTITY.profileId,
    instanceId: TEST_IDENTITY.instanceId,
    genesisDescriptorHash: TEST_DESCRIPTOR,
  });
  return dir;
}
const wholeTxValid = async ({ rawTransactionHex, expectedTransactionId, identity, destination }) => ({
  wholeTxVm: true,
  complete: true,
  valid: true,
  rawTransactionSha256: hashBytes(rawTransactionHex),
  transactionId: expectedTransactionId,
  profileId: identity.profileId,
  instanceId: identity.instanceId,
  ...(destination === null ? {} : { destinationAddress: destination }),
});
function begin(coord, kind = 'deposit') { return coord.begin({ kind, identity: TEST_IDENTITY }); }
async function stage(coord, operationId, rawTransactionHex, expectedTransactionId) {
  return coord.stageDurable(operationId, { rawTransactionHex, expectedTransactionId, validate: wholeTxValid });
}

function mockRpc({
  failSend = false,
  rejectSend = false,
  rejectMessage = 'mandatory-script-verify-flag-failed',
  dropFromMempool = false,
  tmaReject = false,
} = {}) {
  const mempool = new Set();
  let lastHex = null;
  return {
    async testmempoolaccept(hex) {
      if (tmaReject) {
        const txid = transactionIdFromHex(hex);
        return [{ allowed: false, txid, 'reject-reason': 'min relay fee not met' }];
      }
      return [{ allowed: true, txid: transactionIdFromHex(hex) }];
    },
    async sendrawtransaction(hex) {
      if (rejectSend) {
        const err = new Error(rejectMessage);
        err.code = 'RPC_TRANSACTION_REJECTED';
        throw err;
      }
      if (failSend) throw new Error('ECONNRESET network blip');
      lastHex = hex;
      const id = transactionIdFromHex(hex);
      if (!dropFromMempool) mempool.add(id);
      return id;
    },
    async getmempoolentry(id) {
      if (!mempool.has(id)) throw new Error('missing');
      return { size: 1 };
    },
    async getrawmempool() {
      return [...mempool];
    },
    async getrawtransaction(id) {
      return { txid: id, hex: lastHex };
    },
  };
}

test('classifySendFailure distinguishes rejection vs indeterminate', () => {
  assert.equal(
    classifySendFailure(new Error('mandatory-script-verify-flag-failed'), { sendAttempted: true }),
    'rejected',
  );
  assert.equal(
    classifySendFailure(new Error('ECONNRESET'), { sendAttempted: true }),
    'indeterminate',
  );
  const rej = new Error('txn-mempool-conflict');
  rej.code = 'RPC_TRANSACTION_REJECTED';
  assert.equal(classifySendFailure(rej, { sendAttempted: true }), 'rejected');
});

test('durable pre-send required; second automatic mutation rejected', async () => {
  const dir = boundHome('sk-coord-');
  try {
    const admission = createSingleSendAdmission(mockRpc());
    const coord = new OperationCoordinator({ admission, homePath: dir });
    const op = begin(coord);
    const hex = fakeHex();
    const txid = transactionIdFromHex(hex);

    await assert.rejects(
      () => coord.admitOnce(op.operationId),
      (e) => e instanceof CliError && e.code === ERROR_CODES.DURABILITY_REQUIRED,
    );

    await stage(coord, op.operationId, hex, txid);

    // Exact bytes on disk before send
    const store = new DurableOperationStore(dir);
    const disk = store.load(op.operationId);
    assert.equal(disk.rawTransactionHex, hex);
    assert.equal(disk.state, 'prepared-durable');

    const accepted = await coord.admitOnce(op.operationId);
    assert.equal(accepted.state, 'accepted-zero-conf');
    assert.equal(accepted.admissionEvidence.txid.length, 64);
    assert.equal(accepted.admissionEvidence.tmaIsAcceptance, false);

    await assert.rejects(
      () => coord.admitOnce(op.operationId),
      (e) => e instanceof CliError && e.code === ERROR_CODES.SEND_ALREADY_ATTEMPTED,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rejected vs send-indeterminate are distinct coordinator states', async () => {
  // Policy reject → rejected
  {
    const admission = createSingleSendAdmission(mockRpc({ rejectSend: true }));
    const dir = boundHome('sk-rejected-');
    const coord = new OperationCoordinator({ admission, homePath: dir });
    const op = begin(coord);
    const hex = fakeHex();
    const txid = transactionIdFromHex(hex);
    await stage(coord, op.operationId, hex, txid);
    const rejected = await coord.admitOnce(op.operationId);
    assert.equal(rejected.state, 'rejected');
    assert.equal(rejected.admissionEvidence.rejected, true);
    assert.equal(rejected.admissionEvidence.indeterminate, false);
  }

  // TMA reject → safe-pre-send-failure (mutation never crossed; NOT send-attempted)
  {
    const admission = createSingleSendAdmission(mockRpc({ tmaReject: true }));
    const dir = boundHome('sk-tma-rejected-');
    const coord = new OperationCoordinator({ admission, homePath: dir });
    const op = begin(coord);
    const hex = fakeHex(80);
    const txid = transactionIdFromHex(hex);
    await stage(coord, op.operationId, hex, txid);
    const failed = await coord.admitOnce(op.operationId);
    assert.equal(failed.state, 'safe-pre-send-failure');
    assert.equal(failed.sendAttempted, false);
    assert.equal(failed.admissionEvidence.rejected, true);
    assert.equal(failed.admissionEvidence.sendAttempted, false);
    assert.equal(failed.admissionEvidence.mutationCrossed, false);
    // history must not claim a network mutation was crossed
    assert.ok(!failed.history.some((h) => h.state === 'send-attempted'));
    assert.ok(failed.history.some((h) => h.state === 'safe-pre-send-failure'));
    // cannot use automatic re-admit; not SEND_ALREADY_ATTEMPTED (that would imply mutation)
    await assert.rejects(
      () => coord.admitOnce(op.operationId),
      (e) => e instanceof CliError && e.code === ERROR_CODES.DURABILITY_REQUIRED,
    );
  }

  // Network blip after send → send-indeterminate
  {
    const admission = createSingleSendAdmission(mockRpc({ failSend: true }));
    const dir = boundHome('sk-network-');
    const coord = new OperationCoordinator({ admission, homePath: dir });
    const op = begin(coord);
    const hex = fakeHex(90);
    const txid = transactionIdFromHex(hex);
    await stage(coord, op.operationId, hex, txid);
    await assert.rejects(
      () => coord.admitOnce(op.operationId),
      (e) => e.code === ERROR_CODES.SEND_INDETERMINATE,
    );
    assert.equal(coord.get(op.operationId).state, 'send-indeterminate');
  }
});

test('explicit rebroadcast requires ack + CAS + preserved durable bytes', async () => {
  const dir = boundHome('sk-rb-');
  try {
    const hex = fakeHex();
    const txid = transactionIdFromHex(hex);

    // First: force indeterminate
    const bad = createSingleSendAdmission(mockRpc({ failSend: true }));
    const coord = new OperationCoordinator({ admission: bad, homePath: dir });
    const op = begin(coord);
    await stage(coord, op.operationId, hex, txid);
    await assert.rejects(() => coord.admitOnce(op.operationId));
    assert.equal(coord.get(op.operationId).state, 'send-indeterminate');

    // Automatic rebroadcast path is forbidden (no ack)
    await assert.rejects(
      () => coord.rebroadcastExplicit(op.operationId, { acknowledge: false }),
      (e) => e instanceof CliError && e.code === ERROR_CODES.REBROADCAST_ACK_REQUIRED,
    );
    await assert.rejects(
      () => coord.rebroadcastExplicit(op.operationId, {
        acknowledge: true,
        casToken: 'wrong',
      }),
      (e) => e instanceof CliError && e.code === ERROR_CODES.REBROADCAST_CAS_REQUIRED,
    );

    // Crash recovery: new coordinator from home with good admission
    const good = createSingleSendAdmission(mockRpc());
    const recovered = OperationCoordinator.recoverFromHome(dir, { admission: good });
    const recoveredOp = recovered.get(op.operationId);
    assert.ok(recoveredOp);
    assert.equal(recoveredOp.rawTransactionHex, hex);
    assert.equal(recoveredOp.state, 'send-indeterminate');

    const cas = recoveredOp.casToken;
    const rb = await recovered.rebroadcastExplicit(op.operationId, {
      acknowledge: true,
      casToken: cas,
      expectedBytes: hex,
    });
    assert.equal(rb.state, 'accepted-zero-conf');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('crash between durable stage and send preserves exact bytes', async () => {
  const dir = boundHome('sk-crash-');
  try {
    const admission = createSingleSendAdmission(mockRpc());
    const coord = new OperationCoordinator({ admission, homePath: dir });
    const op = begin(coord);
    const hex = fakeHex(110);
    const txid = transactionIdFromHex(hex);
    await stage(coord, op.operationId, hex, txid);

    // Simulate crash: drop in-memory coordinator, recover from disk
    const recovered = OperationCoordinator.recoverFromHome(dir, { admission });
    const loaded = recovered.get(op.operationId);
    assert.equal(loaded.state, 'prepared-durable');
    assert.equal(loaded.rawTransactionHex, hex);

    const accepted = await recovered.admitOnce(op.operationId);
    assert.equal(accepted.state, 'accepted-zero-conf');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('TMA preflight reject does not mark send-attempted; restage of new op works', async () => {
  const dir = boundHome('sk-tma-');
  try {
    const hex = fakeHex(70);
    const txid = transactionIdFromHex(hex);
    const bad = createSingleSendAdmission(mockRpc({ tmaReject: true }));
    const coord = new OperationCoordinator({ admission: bad, homePath: dir });
    const op = begin(coord);
    await stage(coord, op.operationId, hex, txid);
    const failed = await coord.admitOnce(op.operationId);
    assert.equal(failed.state, 'safe-pre-send-failure');
    assert.equal(failed.sendAttempted, false);

    // Durable journal agrees — no send-attempted
    const store = new DurableOperationStore(dir);
    const disk = store.load(op.operationId);
    assert.equal(disk.state, 'safe-pre-send-failure');
    assert.equal(disk.sendAttempted, false);

    // New operation can stage and admit successfully after fee fix
    const good = createSingleSendAdmission(mockRpc());
    const coord2 = new OperationCoordinator({ admission: good, homePath: dir });
    const op2 = begin(coord2);
    const hex2 = fakeHex(71);
    const txid2 = transactionIdFromHex(hex2);
    await stage(coord2, op2.operationId, hex2, txid2);
    const ok = await coord2.admitOnce(op2.operationId);
    assert.equal(ok.state, 'accepted-zero-conf');
    assert.equal(ok.sendAttempted, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('reservations: note/funding exclusive; destination binding rejects fee wallet', async () => {
  const dir = boundHome('sk-res-');
  try {
    const ledger = new ReservationLedger(dir);
    const admission = createSingleSendAdmission(mockRpc());
    const coord = new OperationCoordinator({
      admission,
      homePath: dir,
      reservations: ledger,
    });
    const a = begin(coord, 'transfer');
    const b = begin(coord, 'transfer');

    coord.reserve(a.operationId, {
      noteId: 'nn'.repeat(32),
      fundingOutpoint: `${'aa'.repeat(32)}:0`,
      destinationAddress: 'bchtest:qptestdestination0000000000000000000000',
      forbiddenDestinations: ['bchtest:qfeechange000000000000000000000000'],
    });

    assert.throws(
      () => coord.reserve(b.operationId, { noteId: 'nn'.repeat(32) }),
      (e) => e.code === 'RESERVATION_HELD',
    );
    assert.throws(
      () => coord.reserve(b.operationId, {
        destinationAddress: 'bchtest:qfeechange000000000000000000000000',
        forbiddenDestinations: ['bchtest:qfeechange000000000000000000000000'],
      }),
      (e) => e.code === 'DESTINATION_BINDING_FAILED',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an incomplete/false validation result never creates a sendable operation', async () => {
  const dir = boundHome('sk-invalid-validation-');
  try {
    const coord = new OperationCoordinator({ admission: createSingleSendAdmission(mockRpc()), homePath: dir });
    const op = begin(coord);
    const hex = fakeHex(72); const txid = transactionIdFromHex(hex);
    await assert.rejects(() => coord.stageDurable(op.operationId, {
      rawTransactionHex: hex, expectedTransactionId: txid,
      validate: async () => ({ wholeTxVm: true, complete: false, valid: true }),
    }), (e) => e.code === ERROR_CODES.DURABILITY_REQUIRED);
    assert.equal(coord.get(op.operationId).state, 'preparing');
    await assert.rejects(() => coord.admitOnce(op.operationId), (e) => e.code === ERROR_CODES.DURABILITY_REQUIRED);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a branded admission cannot claim acceptance without the exact post-send/readback contract', async () => {
  const dir = boundHome('sk-lax-admission-');
  try {
    let sends = 0;
    const admission = {
      kind: 'SingleSendAdmission',
      async sendOnce() {
        sends += 1;
        return { accepted: true, readback: { match: true } };
      },
    };
    const coord = new OperationCoordinator({ admission, homePath: dir });
    const op = begin(coord);
    const hex = fakeHex(79);
    await stage(coord, op.operationId, hex, transactionIdFromHex(hex));
    await assert.rejects(
      () => coord.admitOnce(op.operationId),
      (error) => error.code === ERROR_CODES.SEND_INDETERMINATE,
    );
    assert.equal(sends, 1);
    assert.equal(coord.get(op.operationId).state, 'send-indeterminate');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('validation evidence must explicitly bind exact bytes/profile/txid and withdrawal destination', async () => {
  const dir = boundHome('sk-validation-binding-');
  try {
    const coord = new OperationCoordinator({ admission: createSingleSendAdmission(mockRpc()), homePath: dir });
    const hex = fakeHex(76);
    const txid = transactionIdFromHex(hex);
    for (const incomplete of [
      { wholeTxVm: true, complete: true, valid: true },
      { wholeTxVm: true, complete: true, valid: true, rawTransactionSha256: hashBytes(hex), transactionId: txid },
      { wholeTxVm: true, complete: true, valid: true, rawTransactionSha256: hashBytes(hex), transactionId: txid, profileId: '22'.repeat(32) },
    ]) {
      const op = begin(coord);
      await assert.rejects(() => coord.stageDurable(op.operationId, {
        rawTransactionHex: hex,
        expectedTransactionId: txid,
        validate: async () => incomplete,
      }), (error) => error.code === ERROR_CODES.DURABILITY_REQUIRED);
      assert.equal(coord.get(op.operationId).state, 'preparing');
    }

    const withdrawal = begin(coord, 'withdraw');
    await assert.rejects(() => stage(coord, withdrawal.operationId, hex, txid), /reserve and validate an exact destination/);
    coord.reserve(withdrawal.operationId, { destinationAddress: 'bchtest:qbounddestination' });
    await assert.rejects(() => coord.stageDurable(withdrawal.operationId, {
      rawTransactionHex: hex,
      expectedTransactionId: txid,
      validate: async (input) => ({
        ...(await wholeTxValid(input)),
        destinationAddress: 'bchtest:qdifferentdestination',
      }),
    }), (error) => error.code === ERROR_CODES.DURABILITY_REQUIRED);
    const prepared = await stage(coord, withdrawal.operationId, hex, txid);
    assert.equal(prepared.state, 'prepared-durable');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('qualified mutation refuses an in-memory coordinator', () => {
  const coord = new OperationCoordinator({ admission: createSingleSendAdmission(mockRpc()) });
  assert.throws(() => begin(coord), (e) => e.code === ERROR_CODES.DURABILITY_REQUIRED);
});

test('operation ids are never usable as filesystem paths', () => {
  const dir = boundHome('sk-opid-');
  try {
    const coord = new OperationCoordinator({ admission: createSingleSendAdmission(mockRpc()), homePath: dir });
    assert.throws(() => coord.begin({ operationId: '../../outside', kind: 'deposit', identity: TEST_IDENTITY }), /operationId/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('local commit uses a durable idempotency key and atomically releases reservations', async () => {
  const dir = boundHome('sk-commit-');
  try {
    const coord = new OperationCoordinator({ admission: createSingleSendAdmission(mockRpc()), homePath: dir });
    const op = begin(coord); coord.reserve(op.operationId, { noteId: 'aa'.repeat(32) });
    const hex = fakeHex(75); await stage(coord, op.operationId, hex, transactionIdFromHex(hex));
    await coord.admitOnce(op.operationId);
    let key = null;
    const committed = await coord.commitLocal(op.operationId, { commitFn: async (_record, { idempotencyKey }) => { key = idempotencyKey; } });
    assert.equal(committed.state, 'committed'); assert.ok(key);
    assert.deepEqual(new ReservationLedger(dir).snapshot().notes, {});
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('two recovered coordinators can automatically send one operation exactly once', async () => {
  const dir = boundHome('sk-race-send-');
  try {
    let sends = 0;
    const base = mockRpc();
    const rpc = { ...base, async sendrawtransaction(hex) { sends += 1; return base.sendrawtransaction(hex); } };
    const admission = createSingleSendAdmission(rpc);
    const initial = new OperationCoordinator({ admission, homePath: dir });
    const op = begin(initial); const hex = fakeHex(73); const txid = transactionIdFromHex(hex);
    await stage(initial, op.operationId, hex, txid);
    const left = OperationCoordinator.recoverFromHome(dir, { admission });
    const right = OperationCoordinator.recoverFromHome(dir, { admission });
    const result = await Promise.allSettled([left.admitOnce(op.operationId), right.admitOnce(op.operationId)]);
    assert.equal(sends, 1);
    assert.equal(result.filter((x) => x.status === 'fulfilled').length, 1);
    assert.equal(result.filter((x) => x.status === 'rejected').length, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('rebroadcast compare-and-swap is consumed atomically by one coordinator', async () => {
  const dir = boundHome('sk-race-rebroadcast-');
  try {
    const hex = fakeHex(74); const txid = transactionIdFromHex(hex);
    const initial = new OperationCoordinator({ admission: createSingleSendAdmission(mockRpc({ failSend: true })), homePath: dir });
    const op = begin(initial); await stage(initial, op.operationId, hex, txid);
    await assert.rejects(() => initial.admitOnce(op.operationId));
    let sends = 0; const base = mockRpc();
    const rpc = { ...base, async sendrawtransaction(raw) { sends += 1; return base.sendrawtransaction(raw); } };
    const admission = createSingleSendAdmission(rpc);
    const left = OperationCoordinator.recoverFromHome(dir, { admission });
    const right = OperationCoordinator.recoverFromHome(dir, { admission });
    const cas = left.get(op.operationId).casToken;
    const result = await Promise.allSettled([
      left.rebroadcastExplicit(op.operationId, { acknowledge: true, casToken: cas, expectedBytes: hex }),
      right.rebroadcastExplicit(op.operationId, { acknowledge: true, casToken: cas, expectedBytes: hex }),
    ]);
    assert.equal(sends, 1);
    assert.equal(result.filter((x) => x.status === 'fulfilled').length, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
