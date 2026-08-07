/**
 * Phase 3 safety conformance suite — crash points, single-writer, destination,
 * whole-tx validation, exact readback, indeterminate delivery, rebroadcast,
 * chain reconstruction.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';

import { OperationCoordinator, hashBytes } from './coordinator.mjs';
import { DurableOperationStore } from './durable-store.mjs';
import {
  createSingleSendAdmission,
  createChainReader,
  transactionIdFromHex,
  CHIPNET_GENESIS_HASH,
} from '../chain/admission.mjs';
import { reconstructChainHistory } from '../chain/sync.mjs';
import { acquireHomeLock, writeHomeManifest } from '../home/resolve.mjs';
import { loadClosedCatalog } from '../registry/designs.mjs';
import { dispatch } from '../front-controller.mjs';
import { CliError } from '../contracts/errors.mjs';

const pf10 = loadClosedCatalog().designs.find((d) => d.id === 'pf10');
// An exact test profile pin.  The catalog's `pf10` alias is deliberately a
// family selector, so it must not be copied into a bound-home fixture.
const EXACT_TEST_PROFILE_ID = '11'.repeat(32);
const EXACT_TEST_INSTANCE_ID = '22'.repeat(32);
const EXACT_TEST_DESCRIPTOR_HASH = '33'.repeat(32);
const TEST_IDENTITY = { profileId: EXACT_TEST_PROFILE_ID, instanceId: EXACT_TEST_INSTANCE_ID };

function boundHome(prefix) {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  writeHomeManifest(dir, {
    backendId: pf10.backendId,
    profileId: EXACT_TEST_PROFILE_ID,
    designId: pf10.id,
    instanceId: EXACT_TEST_INSTANCE_ID,
    genesisDescriptorHash: EXACT_TEST_DESCRIPTOR_HASH,
  });
  return dir;
}

function validationEvidence({ rawTransactionHex, expectedTransactionId, identity, destination }) {
  return {
    wholeTxVm: true,
    complete: true,
    valid: true,
    rawTransactionSha256: hashBytes(rawTransactionHex),
    transactionId: expectedTransactionId,
    profileId: identity.profileId,
    instanceId: identity.instanceId,
    ...(destination === null ? {} : { destinationAddress: destination }),
  };
}

function capture(argv, env = process.env) {
  let out = '';
  const stdout = new Writable({
    write(chunk, _e, cb) { out += String(chunk); cb(); },
  });
  return dispatch(argv, { stdout, env: { ...env } }).then((r) => ({ ...r, out }));
}

function mockRpc() {
  const mempool = new Set();
  let last = null;
  return {
    async sendrawtransaction(hex) {
      last = hex;
      const id = transactionIdFromHex(hex);
      mempool.add(id);
      return id;
    },
    async getmempoolentry(id) {
      if (!mempool.has(id)) throw new Error('x');
      return { size: 1 };
    },
    async getrawmempool() { return [...mempool]; },
    async getrawtransaction(id) {
      return { txid: id, hex: last };
    },
    async getblockchaininfo() {
      return {
        blocks: 42,
        bestblockhash: '11'.repeat(32),
        chain: 'chipnet',
      };
    },
    async getblockhash(height) { assert.equal(height, 0); return CHIPNET_GENESIS_HASH; },
  };
}

test('conformance: crash before send keeps prepared-durable; after send-attempted stays post-send', async () => {
  const dir = boundHome('sk-conf-crash-');
  try {
    const rpc = mockRpc();
    const admission = createSingleSendAdmission(rpc);
    const coord = new OperationCoordinator({ admission, homePath: dir });
    const op = coord.begin({ kind: 'deposit', identity: TEST_IDENTITY });
    const hex = 'ee'.repeat(100);
    const txid = transactionIdFromHex(hex);

    // Crash point A: after begin, before stage
    let recovered = OperationCoordinator.recoverFromHome(dir, { admission });
    assert.equal(recovered.get(op.operationId).state, 'preparing');
    assert.equal(recovered.get(op.operationId).rawTransactionHex, null);

    await coord.stageDurable(op.operationId, {
      rawTransactionHex: hex,
      expectedTransactionId: txid,
      validate: async (input) => {
        const { rawTransactionHex } = input;
        assert.equal(rawTransactionHex, hex);
        return { ...validationEvidence(input), exactBytes: true };
      },
    });

    // Crash point B: after durable stage, before send
    recovered = OperationCoordinator.recoverFromHome(dir, { admission });
    assert.equal(recovered.get(op.operationId).state, 'prepared-durable');
    assert.equal(recovered.get(op.operationId).rawTransactionHex, hex);

    // Mark send-attempted without completing admit (simulate crash mid-send record)
    recovered.store.update(op.operationId, { predicate: () => true, mutate: (o) => {
      o.sendAttempted = true;
      o.state = 'send-attempted';
      o.history.push({ state: 'send-attempted', at: Date.now() });
    }});

    // Crash point C: after send-attempted
    recovered = OperationCoordinator.recoverFromHome(dir, { admission });
    assert.equal(recovered.get(op.operationId).state, 'send-attempted');
    assert.equal(recovered.get(op.operationId).sendAttempted, true);
    // Automatic second mutation still forbidden
    await assert.rejects(
      () => recovered.admitOnce(op.operationId),
      (e) => e instanceof CliError,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('conformance: single-writer home lock + reservation exclusivity', async () => {
  const dir = boundHome('sk-conf-lock-');
  try {
    const lock = acquireHomeLock(dir);
    assert.throws(() => acquireHomeLock(dir), (e) => e instanceof CliError);
    lock.release();

    const admission = createSingleSendAdmission(mockRpc());
    const coord = new OperationCoordinator({ admission, homePath: dir });
    const a = coord.begin({ kind: 'deposit', identity: TEST_IDENTITY });
    const b = coord.begin({ kind: 'deposit', identity: TEST_IDENTITY });
    coord.reserve(a.operationId, { fundingOutpoint: `${'ff'.repeat(32)}:1` });
    assert.throws(
      () => coord.reserve(b.operationId, { fundingOutpoint: `${'ff'.repeat(32)}:1` }),
      (e) => e.code === 'RESERVATION_HELD',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('conformance: whole-tx validation of exact bytes + exact readback on accept', async () => {
  const dir = boundHome('sk-conf-vm-');
  try {
    const rpc = mockRpc();
    const admission = createSingleSendAdmission(rpc);
    const coord = new OperationCoordinator({ admission, homePath: dir });
    const op = coord.begin({ kind: 'withdraw', identity: TEST_IDENTITY });
    const hex = 'dd'.repeat(80);
    const txid = transactionIdFromHex(hex);
    const destination = 'bchtest:qconformancewithdrawaldestination';
    coord.reserve(op.operationId, { destinationAddress: destination });
    let validatedHex = null;
    await coord.stageDurable(op.operationId, {
      rawTransactionHex: hex,
      expectedTransactionId: txid,
      validate: async (input) => {
        const { rawTransactionHex, expectedTransactionId } = input;
        validatedHex = rawTransactionHex;
        assert.equal(expectedTransactionId, txid);
        assert.equal(rawTransactionHex, hex);
        assert.equal(input.destination, destination);
        return validationEvidence(input);
      },
    });
    assert.equal(validatedHex, hex);
    const accepted = await coord.admitOnce(op.operationId);
    assert.equal(accepted.state, 'accepted-zero-conf');
    assert.equal(accepted.admissionEvidence.readback.match, true);
    assert.equal(accepted.admissionEvidence.readback.rawTransactionHex, hex);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('conformance: known transaction ids remain observations, never canonical lineage', async () => {
  const known = 'aa'.repeat(32);
  const rpc = {
    async getblockchaininfo() {
      return { blocks: 7, bestblockhash: 'bb'.repeat(32), chain: 'chipnet' };
    },
    async getrawtransaction(txid) {
      if (txid !== known) throw new Error('missing');
      return { txid, hex: 'cc'.repeat(40), confirmations: 3 };
    },
    async getblockhash(height) { assert.equal(height, 0); return CHIPNET_GENESIS_HASH; },
  };
  const reader = createChainReader(rpc, {
    transport: { kind: 'product-rpc' },
    genesisHash: CHIPNET_GENESIS_HASH,
  });
  const delta = await reconstructChainHistory(reader, {
    knownTxids: [known, '00'.repeat(32)],
    expectedGenesis: reader.genesisHash,
  });
  assert.equal(delta.tip.kind, 'tip');
  assert.equal(delta.tip.height, 7);
  assert.equal(delta.reconstructed, false);
  assert.equal(delta.canonicalLineageVerified, false);
  assert.match(delta.lineageStatus, /do not prove canonical pool lineage/i);
  assert.equal(delta.missing.length, 1);
  assert.ok(delta.observations.some((o) => o.txid === known && o.present));
});

test('conformance: pool sync refuses mock txid observation as canonical history', async () => {
  const dir = boundHome('sk-conf-sync-home-');
  try {
    const r = await capture(
      ['--design', 'pf10', '--home', dir, 'pool', 'sync'],
      {
        ...process.env,
        SHIELDKIT_CHAIN_READER_MOCK: '1',
        SHIELDKIT_SYNC_KNOWN_TXIDS: `${'aa'.repeat(32)}`,
      },
    );
    assert.equal(r.exitCode, 2, r.out);
    const env = JSON.parse(r.out);
    assert.equal(env.ok, false);
    assert.equal(env.code, 'CAPABILITY_BLOCKED');
    assert.match(env.error, /canonical-lineage/i);
    assert.doesNotMatch(JSON.stringify(env), /reconstructed"\s*:\s*true/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('conformance: pool sync rejects maintainer SSH only after a valid bound context exists', async () => {
  const dir = boundHome('sk-conf-ssh-home-');
  try {
    const r = await capture(
      ['--design', 'pf10', '--home', dir, 'pool', 'sync'],
      { ...process.env, SHIELDKIT_MAINTAINER_SSH: '1' },
    );
    assert.equal(r.exitCode, 2, r.out);
    const env = JSON.parse(r.out);
    assert.equal(env.code, 'MAINTAINER_PATH_FORBIDDEN');
    assert.equal(env.identity.profileId, EXACT_TEST_PROFILE_ID);
    assert.equal(env.identity.homeId.length, 64);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('conformance: durable store atomic write survives list/load', () => {
  const dir = boundHome('sk-conf-store-');
  try {
    const store = new DurableOperationStore(dir);
    store.save({
      operationId: 'a'.repeat(64),
      state: 'prepared-durable',
      rawTransactionHex: 'ab'.repeat(20),
      expectedTransactionId: 'cd'.repeat(32),
      history: [{ state: 'prepared-durable', at: 1 }],
    });
    const loaded = store.load('a'.repeat(64));
    assert.equal(loaded.rawTransactionHex, 'ab'.repeat(20));
    assert.ok(loaded.contentSha256);
    assert.equal(store.list().length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
