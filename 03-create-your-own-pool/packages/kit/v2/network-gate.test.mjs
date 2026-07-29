import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  mkdtempSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  openV2DeliveryJournal,
} from './delivery-journal.mjs';
import {
  V2HttpsTransportError,
  createV2FixtureOnlyTransport,
} from './https-transport.mjs';
import {
  V2_EXACT_RESUBMISSION_ACKNOWLEDGEMENT,
  V2NetworkGateError,
  broadcastAction,
  createV2HighFeeConfirmation,
  createV2SignedBroadcastMetadata,
  rebroadcastExactAction,
  reconcileObservedAction,
  verifyV2SignedSettlementEvidence,
} from './network-gate.mjs';
import { createV2InputRoleLayout } from './transaction-policy.mjs';
import { canonicalizeV2Evidence } from './vm-evidence.mjs';
import {
  FIXTURE_CERTIFICATE_SHA256,
  buildRawTransaction,
  createFixtureEvidence,
  createGateFixture,
  createRollingFixtureArtifacts,
} from './v2-test-fixtures.mjs';

const rejects = async (promise, code) =>
  await assert.rejects(
    promise,
    (error) =>
      error instanceof V2NetworkGateError && error.code === code,
  );

const digest = (value) =>
  createHash('sha256')
    .update(canonicalizeV2Evidence(value))
    .digest('hex');

function deepFreeze(value) {
  for (const child of Object.values(value)) {
    if (child && typeof child === 'object') deepFreeze(child);
  }
  return Object.freeze(value);
}

function recommitMetadata(value) {
  const copy = structuredClone(value);
  delete copy.metadataHash;
  copy.inputRoleLayoutHash = digest(copy.inputRoleLayout);
  return deepFreeze({
    ...copy,
    metadataHash: digest(copy),
  });
}

function journalFor(t) {
  const parent = mkdtempSync(join(tmpdir(), 'shieldkit-v2-gate-'));
  chmodSync(parent, 0o700);
  const journal = openV2DeliveryJournal(
    join(parent, 'delivery.sqlite'),
  );
  t.after(() => {
    journal.close();
    rmSync(parent, { recursive: true, force: true });
  });
  return journal;
}

const identityFor = (metadata) => ({
  operationId: metadata.operationId,
  txid: metadata.txid,
  metadataHash: metadata.metadataHash,
  evidenceHash: metadata.vmEvidenceHash,
  carrierCount: metadata.carrierCount,
  roleLayoutHash: metadata.inputRoleLayoutHash,
});

test('offline qualification reuses the complete production settlement evidence boundary', () => {
  const value = createGateFixture();
  const verified = verifyV2SignedSettlementEvidence({
    binding: value.store.binding(),
    localVmEvidence: value.operation.localVmEvidence,
    metadata: value.metadata,
    packet: value.operation.packet,
  });
  assert.deepEqual(
    {
      action: verified.action,
      evidenceHash: verified.evidenceHash,
      feeSats: verified.feeSats,
      metadataHash: verified.metadataHash,
      transactionId: verified.transactionId,
    },
    {
      action: 'deposit',
      evidenceHash: value.metadata.vmEvidenceHash,
      feeSats: value.metadata.feeSats,
      metadataHash: value.metadata.metadataHash,
      transactionId: value.metadata.txid,
    },
  );

  const changedPacket = Buffer.from(value.operation.packet);
  changedPacket[changedPacket.length - 1] ^= 1;
  assert.throws(
    () => verifyV2SignedSettlementEvidence({
      binding: value.store.binding(),
      localVmEvidence: value.operation.localVmEvidence,
      metadata: value.metadata,
      packet: changedPacket,
    }),
    (error) =>
      error instanceof V2NetworkGateError
      && error.code === 'ACTION_PACKET_BINDING_MISMATCH',
  );
});

// All transports in this file use the explicitly fixture-only injection
// boundary. These tests do not claim live BCH VM, node, TLS, or network proof.
test('broadcast gate orders claim -> submission -> local store finalization and never duplicates a send', async (t) => {
  const value = createGateFixture();
  const delivery = journalFor(t);
  const logs = [];
  const first = await broadcastAction({
    ...value,
    delivery,
    log: (entry) => logs.push(entry),
  });
  assert.deepEqual(first, {
    status: 'mempool',
    txid: value.metadata.txid,
    replayed: false,
  });
  assert.equal(value.sends(), 1);
  assert.deepEqual(value.transitions, ['broadcast', 'mempool']);
  assert.equal(delivery.record('op-1').state, 'locally_reconciled');
  const second = await broadcastAction({ ...value, delivery });
  assert.equal(second.status, 'mempool');
  assert.equal(value.sends(), 1);
  assert.ok(
    logs.every(
      (entry) =>
        !JSON.stringify(entry).includes(value.metadata.rawTxHex),
    ),
  );
});

test('broadcast gate accepts profile-bound N=7/10-input and N=10/13-input layouts', async (t) => {
  for (const carrierCount of [7, 10]) {
    await t.test(`carrierCount=${carrierCount}`, async (inner) => {
      const value = createGateFixture({
        carrierCount,
        operationId: `op-carriers-${carrierCount}`,
      });
      const delivery = journalFor(inner);
      const result = await broadcastAction({ ...value, delivery });
      assert.equal(result.status, 'mempool');
      assert.equal(value.metadata.carrierCount, carrierCount);
      assert.equal(
        value.metadata.inputRoleLayout.length,
        carrierCount + 3,
      );
      assert.equal(
        delivery.record(value.metadata.operationId).carrierCount,
        carrierCount,
      );
      assert.equal(value.sends(), 1);
    });
  }
});

test('broadcast gate parses exact evidence again and rejects substituted evidence before claim', async (t) => {
  const value = createGateFixture();
  const delivery = journalFor(t);
  const otherRaw = buildRawTransaction({
    outputValueSatoshis: 998_999n,
  });
  value.operation.localVmEvidence = createFixtureEvidence({
    rawTransactionHex: otherRaw,
  });
  await rejects(
    broadcastAction({ ...value, delivery }),
    'VM_EVIDENCE_BINDING_MISMATCH',
  );
  assert.equal(value.sends(), 0);
  assert.equal(delivery.record('op-1'), null);
});

test('signed metadata rejects reordered layouts and self-consistent carrier-count substitutions before claim', async (t) => {
  await t.test('reordered layout', async (inner) => {
    const value = createGateFixture();
    const reordered = structuredClone(value.metadata);
    [
      reordered.inputRoleLayout[0],
      reordered.inputRoleLayout[1],
    ] = [
      reordered.inputRoleLayout[1],
      reordered.inputRoleLayout[0],
    ];
    const metadata = recommitMetadata(reordered);
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({ ...value, metadata, delivery }),
      'INPUT_ROLE_LAYOUT_MISMATCH',
    );
    assert.equal(delivery.record(value.metadata.operationId), null);
  });
  await t.test('carrier-count substitution', async (inner) => {
    const value = createGateFixture();
    const substituted = structuredClone(value.metadata);
    substituted.carrierCount = 10;
    substituted.inputRoleLayout = createV2InputRoleLayout(10);
    const metadata = recommitMetadata(substituted);
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({ ...value, metadata, delivery }),
      'INPUT_TOPOLOGY_MISMATCH',
    );
    assert.equal(delivery.record(value.metadata.operationId), null);
  });
});

test('rolling source lineage and exact state commitment are re-derived before any delivery claim', async (t) => {
  await t.test('swapped verifier siblings', async (inner) => {
    const value = createGateFixture({
      swapVerifierSiblings: true,
    });
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({ ...value, delivery }),
      'ROLLING_PARENT_MISMATCH',
    );
    assert.equal(value.sends(), 0);
    assert.equal(delivery.record(value.metadata.operationId), null);
  });
  await t.test('durable state differs from parent NFT bytes', async (inner) => {
    const expected = createGateFixture({
      operationId: 'op-state-reference',
    }).tip;
    const value = createGateFixture({
      tip: {
        ...expected,
        state: '45'.repeat(128),
      },
    });
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({ ...value, delivery }),
      'STATE_COMMITMENT_MISMATCH',
    );
    assert.equal(value.sends(), 0);
    assert.equal(delivery.record(value.metadata.operationId), null);
  });
});

test('packet, context, successor state, and carrier renewal mutations fail before any delivery claim', async (t) => {
  await t.test('persisted packet substitution', async (inner) => {
    const value = createGateFixture();
    value.operation.packet = Buffer.from(value.operation.packet);
    value.operation.packet[360] ^= 1;
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({ ...value, delivery }),
      'ACTION_PACKET_BINDING_MISMATCH',
    );
    assert.equal(value.sends(), 0);
    assert.equal(delivery.record(value.metadata.operationId), null);
  });
  await t.test('missing durable packet', async (inner) => {
    const value = createGateFixture();
    value.operation.packet = null;
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({ ...value, delivery }),
      'ACTION_PACKET_REQUIRED',
    );
    assert.equal(value.sends(), 0);
    assert.equal(delivery.record(value.metadata.operationId), null);
  });
  await t.test('packet context byte in signed transaction', async (inner) => {
    const artifacts = createRollingFixtureArtifacts();
    const raw = Buffer.from(artifacts.rawTransactionHex, 'hex');
    const packetOffset = raw.indexOf(artifacts.packet);
    assert.notEqual(packetOffset, -1);
    raw[packetOffset + 520] ^= 1;
    const value = createGateFixture({
      rawTransactionHex: raw.toString('hex'),
    });
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({ ...value, delivery }),
      'TRANSACTION_CONTEXT_MISMATCH',
    );
    assert.equal(value.sends(), 0);
    assert.equal(delivery.record(value.metadata.operationId), null);
  });
  await t.test('successor state NFT commitment', async (inner) => {
    const value = createGateFixture({
      mutateStateOutputCommitment: true,
    });
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({ ...value, delivery }),
      'ACTION_PACKET_STATE_MISMATCH',
    );
    assert.equal(value.sends(), 0);
    assert.equal(delivery.record(value.metadata.operationId), null);
  });
  await t.test('verifier carrier base value renewal', async (inner) => {
    const value = createGateFixture({
      successorVerifierValueDeltaSats: 1n,
    });
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({ ...value, delivery }),
      'ROLLING_BUNDLE_INVALID',
    );
    assert.equal(value.sends(), 0);
    assert.equal(delivery.record(value.metadata.operationId), null);
  });
});

test('metadata derives evidence commitments and rejects a caller fee inconsistent with evaluated source outputs', () => {
  const rawTransactionHex = buildRawTransaction({
    outputValueSatoshis: 999_000n,
  });
  const evidence = createFixtureEvidence({ rawTransactionHex });
  assert.throws(
    () =>
      createV2SignedBroadcastMetadata({
        operationId: 'op-bad-fee',
        rawTxHex: rawTransactionHex,
        feeSats: '999',
        action: 'deposit',
        profileId: '66'.repeat(32),
        instanceId: '77'.repeat(32),
        network: 'chipnet',
        tip: {
          state: '33'.repeat(128),
          txid: '44'.repeat(32),
          vout: 7,
          actionSequence: 9,
          height: 100,
          blockHash: '55'.repeat(32),
        },
        localVmEvidence: evidence,
      }),
    (error) => error?.code === 'FEE_METADATA_MISMATCH',
  );
});

test('fee gate accepts the full ordinary band and requires exact immutable confirmation only above 10 sat/byte', async (t) => {
  await t.test('below one sat/byte', async (inner) => {
    const provisional = createGateFixture();
    const value = createGateFixture({
      feeSats: provisional.metadata.sizeBytes - 1,
    });
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({ ...value, delivery }),
      'FEE_TOO_LOW',
    );
    assert.equal(value.sends(), 0);
  });
  await t.test('exactly ten sat/byte', async (inner) => {
    const provisional = createGateFixture();
    const value = createGateFixture({
      feeSats: provisional.metadata.sizeBytes * 10,
    });
    const delivery = journalFor(inner);
    await broadcastAction({ ...value, delivery });
    assert.equal(value.sends(), 1);
  });
  await t.test('above ten sat/byte', async (inner) => {
    const provisional = createGateFixture();
    const value = createGateFixture({
      feeSats: provisional.metadata.sizeBytes * 10 + 1,
    });
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({ ...value, delivery }),
      'HIGH_FEE_CONFIRMATION_REQUIRED',
    );
    const confirmation = createV2HighFeeConfirmation(value.metadata);
    await broadcastAction({
      ...value,
      delivery,
      highFeeConfirmation: confirmation,
    });
    assert.equal(value.sends(), 1);
  });
});

test('pre-send binding rejects stale tip, profile/instance, network, and serialized transaction mismatches', async (t) => {
  const cases = [
    [
      'stale tip',
      (value) => {
        value.store.canonicalState = () => ({
          state: Buffer.alloc(128, 0xee),
          outpoint: { txid: Buffer.alloc(32, 0x44), vout: 7 },
          actionSequence: 9,
          height: 100,
          blockHash: Buffer.alloc(32, 0x55),
        });
      },
      'STALE_TIP',
    ],
    [
      'profile',
      (value) => {
        value.store.binding = () => ({
          profileId: Buffer.alloc(32, 0xee),
          instanceId: Buffer.from(value.metadata.instanceId, 'hex'),
        });
      },
      'PROFILE_INSTANCE_MISMATCH',
    ],
    [
      'network',
      (value) => {
        value.endpoint.network = 'mainnet';
      },
      'NETWORK_MISMATCH',
    ],
    [
      'carrier count',
      (value) => {
        const binding = value.store.binding();
        value.store.binding = () => ({
          ...binding,
          carrierCount: binding.carrierCount + 1,
        });
      },
      'CARRIER_COUNT_MISMATCH',
    ],
    [
      'transaction',
      (value) => {
        value.operation.signedTx = Buffer.alloc(1, 0xee);
      },
      'TRANSACTION_MUTATED',
    ],
  ];
  for (const [name, mutate, code] of cases) {
    await t.test(name, async (inner) => {
      const value = createGateFixture();
      const delivery = journalFor(inner);
      mutate(value);
      await rejects(broadcastAction({ ...value, delivery }), code);
      assert.equal(value.sends(), 0);
    });
  }
});

test('ambiguous timeout is journaled once and can never auto-resend', async (t) => {
  let attempts = 0;
  const value = createGateFixture({
    transportHandler: async () => {
      attempts += 1;
      throw new V2HttpsTransportError(
        'RPC_TIMEOUT_AMBIGUOUS',
        'fixture timeout',
        { ambiguous: true },
      );
    },
  });
  const delivery = journalFor(t);
  await rejects(
    broadcastAction({ ...value, delivery }),
    'RPC_TIMEOUT_AMBIGUOUS',
  );
  assert.equal(attempts, 1);
  assert.equal(delivery.record('op-1').state, 'indeterminate');
  await rejects(
    broadcastAction({ ...value, delivery }),
    'RECOVERY_REQUIRED',
  );
  assert.equal(attempts, 1);
});

test('fresh authenticated tip synchronization is mandatory and runs before the first durable claim', async (t) => {
  await t.test('missing synchronizer', async (inner) => {
    const value = createGateFixture();
    const delivery = journalFor(inner);
    await rejects(
      broadcastAction({
        ...value,
        synchronizeCanonicalTip: undefined,
        delivery,
      }),
      'TIP_SYNCHRONIZER_REQUIRED',
    );
    assert.equal(delivery.record(value.metadata.operationId), null);
    assert.equal(value.sends(), 0);
  });

  await t.test('synchronizer observes a competing tip', async (inner) => {
    const value = createGateFixture();
    const delivery = journalFor(inner);
    const prior = value.store.canonicalState();
    const competing = {
      ...prior,
      state: Buffer.from(prior.state),
      outpoint: {
        ...prior.outpoint,
        txid: Buffer.from('ab'.repeat(32), 'hex'),
      },
      blockHash: Buffer.from(prior.blockHash),
    };
    let calls = 0;
    value.synchronizeCanonicalTip = async (request) => {
      calls += 1;
      assert.equal(request.phase, 'pre-broadcast');
      assert.equal(request.operationId, value.metadata.operationId);
      assert.equal(Object.isFrozen(request), true);
      assert.equal(Object.isFrozen(request.priorCanonicalTip), true);
      value.store.canonicalState = () => competing;
      return competing;
    };
    await rejects(
      broadcastAction({ ...value, delivery }),
      'STALE_TIP',
    );
    assert.equal(calls, 1);
    assert.equal(delivery.record(value.metadata.operationId), null);
    assert.equal(value.sends(), 0);
  });
});

test('authenticated observation reconciles an ambiguous send without invoking transport again', async (t) => {
  let attempts = 0;
  const value = createGateFixture({
    transportHandler: async () => {
      attempts += 1;
      throw new V2HttpsTransportError(
        'RPC_TIMEOUT_AMBIGUOUS',
        'fixture timeout',
        { ambiguous: true },
      );
    },
  });
  const delivery = journalFor(t);
  await rejects(
    broadcastAction({ ...value, delivery }),
    'RPC_TIMEOUT_AMBIGUOUS',
  );
  assert.equal(attempts, 1);
  assert.equal(delivery.record('op-1').state, 'indeterminate');

  let observationRequest;
  const recovered = await reconcileObservedAction({
    store: value.store,
    delivery,
    metadata: value.metadata,
    loadRawTransaction: async (request) => {
      observationRequest = request;
      return value.metadata.rawTxHex;
    },
  });
  assert.deepEqual(observationRequest, {
    networkId: 2,
    transactionId: value.metadata.txid,
  });
  assert.deepEqual(recovered, {
    status: 'mempool',
    txid: value.metadata.txid,
    replayed: true,
  });
  assert.equal(attempts, 1);
  assert.deepEqual(value.transitions, ['broadcast', 'mempool']);
  assert.equal(
    delivery.record('op-1').state,
    'locally_reconciled',
  );
  assert.equal(
    delivery.record('op-1').submissionKind,
    'authenticated-transaction-read',
  );
});

test('exact-byte resubmission requires literal acknowledgement and the current journal CAS token', async (t) => {
  let sends = 0;
  const value = createGateFixture({
    transportHandler: async () => {
      sends += 1;
      throw new V2HttpsTransportError(
        'RPC_TIMEOUT_AMBIGUOUS',
        'fixture timeout',
        { ambiguous: true },
      );
    },
  });
  const delivery = journalFor(t);
  await rejects(
    broadcastAction({ ...value, delivery }),
    'RPC_TIMEOUT_AMBIGUOUS',
  );
  const unresolved = delivery.record(value.metadata.operationId);
  assert.equal(unresolved.state, 'indeterminate');
  assert.equal(unresolved.attemptCount, 1);

  const successfulTransport = createV2FixtureOnlyTransport(
    async ({ rawTxHex }) => {
      sends += 1;
      assert.equal(rawTxHex, value.metadata.rawTxHex);
      return {
        txid: value.metadata.txid,
        redirected: false,
        tlsProtocol: 'TLSv1.3',
        peerCertificateSha256: FIXTURE_CERTIFICATE_SHA256,
      };
    },
  );
  const base = {
    store: value.store,
    delivery,
    transport: successfulTransport,
    endpoint: value.endpoint,
    metadata: value.metadata,
    synchronizeCanonicalTip: value.synchronizeCanonicalTip,
    priorAttemptToken: unresolved.attemptToken,
  };
  await rejects(
    rebroadcastExactAction({
      ...base,
      acknowledgement: 'yes',
    }),
    'EXACT_RESUBMISSION_ACKNOWLEDGEMENT_REQUIRED',
  );
  await rejects(
    rebroadcastExactAction({
      ...base,
      priorAttemptToken: '00000000-0000-4000-8000-000000000000',
      acknowledgement: V2_EXACT_RESUBMISSION_ACKNOWLEDGEMENT,
    }),
    'RECOVERY_TOKEN_MISMATCH',
  );
  assert.equal(sends, 1);
  assert.equal(
    delivery.record(value.metadata.operationId).attemptCount,
    1,
  );

  const recovered = await rebroadcastExactAction({
    ...base,
    acknowledgement: V2_EXACT_RESUBMISSION_ACKNOWLEDGEMENT,
  });
  assert.deepEqual(recovered, {
    status: 'mempool',
    txid: value.metadata.txid,
    replayed: true,
  });
  assert.equal(sends, 2);
  const reconciled = delivery.record(value.metadata.operationId);
  assert.equal(reconciled.state, 'locally_reconciled');
  assert.equal(reconciled.attemptCount, 2);
  assert.notEqual(reconciled.attemptToken, unresolved.attemptToken);

  const idempotent = await rebroadcastExactAction({
    ...base,
    priorAttemptToken: reconciled.attemptToken,
    acknowledgement: V2_EXACT_RESUBMISSION_ACKNOWLEDGEMENT,
  });
  assert.equal(idempotent.replayed, true);
  assert.equal(sends, 2);
});

test('unobserved or divergent transaction recovery remains unresolved and never sends', async (t) => {
  const cases = [
    [
      'not observed',
      () => null,
      'TRANSACTION_NOT_OBSERVED',
    ],
    [
      'different raw transaction',
      () => createGateFixture({
        operationId: 'different-operation',
        feeSats: '3000',
      }).metadata.rawTxHex,
      'OBSERVED_TRANSACTION_MISMATCH',
    ],
  ];
  for (const [name, loadRawTransaction, code] of cases) {
    await t.test(name, async (inner) => {
      const value = createGateFixture({
        operationId: `recover-${name.replaceAll(' ', '-')}`,
      });
      const delivery = journalFor(inner);
      delivery.claimOrCreate(identityFor(value.metadata));
      await rejects(
        reconcileObservedAction({
          store: value.store,
          delivery,
          metadata: value.metadata,
          loadRawTransaction,
        }),
        code,
      );
      assert.equal(
        delivery.record(value.metadata.operationId).state,
        'attempted',
      );
      assert.equal(value.sends(), 0);
      assert.equal(value.operation.journalState, 'signed');
    });
  }
});

test('TLS, redirect, and RPC txid mismatches become durable indeterminate states', async (t) => {
  const cases = [
    [
      'TLS certificate pin',
      {
        txid: null,
        redirected: false,
        tlsProtocol: 'TLSv1.3',
        peerCertificateSha256: 'bb'.repeat(32),
      },
      'TRANSPORT_SECURITY_VIOLATION',
    ],
    [
      'redirect',
      {
        txid: null,
        redirected: true,
        tlsProtocol: 'TLSv1.3',
        peerCertificateSha256: FIXTURE_CERTIFICATE_SHA256,
      },
      'TRANSPORT_SECURITY_VIOLATION',
    ],
    [
      'RPC txid',
      {
        txid: 'ff'.repeat(32),
        redirected: false,
        tlsProtocol: 'TLSv1.3',
        peerCertificateSha256: FIXTURE_CERTIFICATE_SHA256,
      },
      'RPC_TXID_MISMATCH',
    ],
  ];
  for (const [name, reply, code] of cases) {
    await t.test(name, async (inner) => {
      let attempts = 0;
      let fixture;
      fixture = createGateFixture({
        operationId: `op-${name.replaceAll(' ', '-').toLowerCase()}`,
        transportHandler: async () => {
          attempts += 1;
          return {
            ...reply,
            txid: reply.txid ?? fixture.metadata.txid,
          };
        },
      });
      const delivery = journalFor(inner);
      await rejects(
        broadcastAction({ ...fixture, delivery }),
        code,
      );
      assert.equal(attempts, 1);
      assert.equal(
        delivery.record(fixture.metadata.operationId).state,
        'indeterminate',
      );
    });
  }
});

test('a submitted RPC survives pool-store failure and replays only local finalization', async (t) => {
  const value = createGateFixture();
  const delivery = journalFor(t);
  const transition = value.store.transitionOperation;
  value.store.transitionOperation = () => {
    throw new Error('fixture crash after durable RPC submission');
  };
  await rejects(
    broadcastAction({ ...value, delivery }),
    'BROADCAST_RECORD_INDETERMINATE',
  );
  assert.equal(value.sends(), 1);
  assert.equal(delivery.record('op-1').state, 'submitted');
  value.store.transitionOperation = transition;
  const replay = await broadcastAction({ ...value, delivery });
  assert.equal(replay.status, 'mempool');
  assert.equal(value.sends(), 1);
  assert.equal(
    delivery.record('op-1').state,
    'locally_reconciled',
  );
});

test('crash/reopen refuses transport and carrier/layout-divergent metadata replay fails closed', async (t) => {
  const value = createGateFixture();
  const parent = mkdtempSync(join(tmpdir(), 'shieldkit-v2-reopen-'));
  chmodSync(parent, 0o700);
  const path = join(parent, 'delivery.sqlite');
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  let delivery = openV2DeliveryJournal(path);
  const identity = {
    operationId: value.metadata.operationId,
    txid: value.metadata.txid,
    metadataHash: value.metadata.metadataHash,
    evidenceHash: value.metadata.vmEvidenceHash,
    carrierCount: value.metadata.carrierCount,
    roleLayoutHash: value.metadata.inputRoleLayoutHash,
  };
  delivery.claimOrCreate(identity);
  delivery.close();
  delivery = openV2DeliveryJournal(path);
  await rejects(
    broadcastAction({ ...value, delivery }),
    'RECOVERY_REQUIRED',
  );
  assert.equal(value.sends(), 0);
  delivery.close();

  const divergent = createGateFixture({
    operationId: 'op-divergent',
    feeSats: '3000',
  });
  delivery = openV2DeliveryJournal(path);
  delivery.claimOrCreate({
    operationId: divergent.metadata.operationId,
    txid: divergent.metadata.txid,
    metadataHash: divergent.metadata.metadataHash,
    evidenceHash: divergent.metadata.vmEvidenceHash,
    carrierCount: 10,
    roleLayoutHash: 'ff'.repeat(32),
  });
  await rejects(
    broadcastAction({ ...divergent, delivery }),
    'DIVERGENT_REBROADCAST',
  );
  assert.equal(divergent.sends(), 0);
  delivery.close();
});

test('unbranded injected transports are rejected before any durable claim', async (t) => {
  const value = createGateFixture();
  value.transport = {
    sendRawTransaction: async () => {
      throw new Error('must not execute');
    },
  };
  const delivery = journalFor(t);
  await rejects(
    broadcastAction({ ...value, delivery }),
    'TRANSPORT_REQUIRED',
  );
  assert.equal(delivery.record('op-1'), null);
  assert.equal(
    createV2FixtureOnlyTransport(async () => ({})).fixtureOnly,
    true,
  );
});
