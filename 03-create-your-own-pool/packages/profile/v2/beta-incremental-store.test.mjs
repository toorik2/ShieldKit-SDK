import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { encodeStateNftCommitment } from "../../action/v2/state.mjs";
import { applyDirectV2Transition, createDirectV2PoolModel } from "../../action/v2/transition.mjs";
import {
  openV2BetaIncrementalStore,
  V2BetaIncrementalStoreError,
} from "./beta-incremental-store.mjs";

const b = (byte, length = 32) => Buffer.alloc(length, byte);
const sha256 = (value) => createHash("sha256").update(value).digest();
const PROFILE_ID = b(0x11);
const INSTANCE_ID = b(0x22);
const RUNTIME_MATERIAL_SHA256 = b(0x33);
const RUNTIME_MANIFEST_SHA256 = b(0x34);
const DEPLOYMENT_ZERO_CONF_EVIDENCE_SHA256 = b(0x35);
const DENOMINATION_SATS = "10000000";
const state = () => encodeStateNftCommitment(createDirectV2PoolModel({
  profileId: PROFILE_ID.toString("hex"),
  maximumLiveNotes: "210000000",
  denominationSats: DENOMINATION_SATS,
}).state, { denominationSats: DENOMINATION_SATS });
function withStore(run) {
  const root = mkdtempSync(join(tmpdir(), "shieldkit-beta-incremental-"));
  const databasePath = join(root, "private", "store.sqlite");
  let store = openV2BetaIncrementalStore({ databasePath });
  try { return run({ store, databasePath }); } finally { store.close(); rmSync(root, { recursive: true, force: true }); }
}
function initialize(store) {
  return store.initialize({
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    networkId: 2,
    denominationSats: DENOMINATION_SATS,
    state: state(),
    outpoint: { txid: b(0x44), vout: 0 },
    acceptanceId: b(0x55),
    runtimeMaterialSha256: RUNTIME_MATERIAL_SHA256,
    runtimeManifestSha256: RUNTIME_MANIFEST_SHA256,
    deploymentZeroConfEvidenceSha256: DEPLOYMENT_ZERO_CONF_EVIDENCE_SHA256,
  });
}
function bootstrapFunding(sourceTransactionId = b(0x71)) {
  return {
    sourceTransactionId,
    utxos: Array.from({ length: 10 }, (_, index) => ({
      txid: sourceTransactionId,
      vout: index + 1,
      valueSats: index < 5 ? "10000000" : "1000000",
    })),
  };
}
function deposit(store, operationId = "deposit-1") {
  store.putFundingUtxo({ txid: b(0x61), vout: 0, valueSats: "20000000" });
  store.reserveOperation({
    operationId,
    kind: "deposit",
    selectedNoteId: null,
    funding: { txid: b(0x61), vout: 0 },
  });
  const transition = store.deriveProvingTransition({
    operationId,
    outputNoteLeaf: b(9),
    encryptedRecord: b(0x70, 128),
    publicNullifier: null,
    withdrawalLockingBytecodeHash: null,
    transactionContextHash: b(0x62),
  });
  store.stageOperationArtifacts({
    operationId,
    packet: transition.packet,
    proofArtifact: Buffer.from("test-proof"),
    transactionArtifact: Buffer.from("test-transaction"),
  });
  return transition;
}

test("beta store accepts only an exact zero-conf successor and reopens its tip", () => withStore(({ store: initialStore, databasePath }) => {
  let store = initialStore;
  initialize(store);
  const transition = deposit(store);
  const tip = store.applyAcceptedZeroConfSuccessor({
    operationId: "deposit-1",
    successor: { txid: b(0x63), vout: 1, acceptanceId: b(0x64) },
    change: { txid: b(0x65), vout: 0, valueSats: "10000000" },
    ownedOutputNoteId: null,
    ownedOutputRecordId: null,
    ownedOutputNullifier: null,
  });
  assert.equal(tip.actionSequence, 1);
  assert.equal(tip.state.toString("hex"), encodeStateNftCommitment(transition.state, { denominationSats: DENOMINATION_SATS }).toString("hex"));
  const acceptedResume = store.stagedOperation("deposit-1");
  assert.equal(acceptedResume.state, "accepted_zero_conf");
  assert.equal(acceptedResume.localWalletCommitComplete, false);
  assert.equal(acceptedResume.packet.toString("hex"), transition.packet.toString("hex"));
  assert.equal(acceptedResume.proofArtifact.toString(), "test-proof");
  assert.equal(store.activeOperation().localWalletCommitPending, true);
  for (const file of [databasePath, `${databasePath}-wal`, `${databasePath}-shm`]) {
    assert.equal(lstatSync(file).mode & 0o777, 0o600);
  }
  store.close();
  store = openV2BetaIncrementalStore({ databasePath });
  assert.equal(store.optimisticTip().state.toString("hex"), tip.state.toString("hex"));
  assert.equal(store.activeOperation().localWalletCommitPending, true);
  assert.throws(() => store.markLocalWalletCommitComplete({ operationId: "deposit-1", transactionId: b(0xff), transactionArtifactSha256: sha256(Buffer.from("test-transaction")) }), V2BetaIncrementalStoreError);
  const committed = store.markLocalWalletCommitComplete({ operationId: "deposit-1", transactionId: b(0x63), transactionArtifactSha256: sha256(Buffer.from("test-transaction")) });
  assert.equal(committed.localWalletCommitComplete, true);
  assert.equal(store.markLocalWalletCommitComplete({ operationId: "deposit-1", transactionId: b(0x63), transactionArtifactSha256: sha256(Buffer.from("test-transaction")) }).localWalletCommitComplete, true);
  assert.equal(store.activeOperation(), null);
}));

test("beta store immutably binds runtime material, manifest, and deployment zero-conf evidence", () => withStore(({ store }) => {
  initialize(store);
  assert.deepEqual(store.binding(), {
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    networkId: 2,
    denominationSats: DENOMINATION_SATS,
    runtimeMaterialSha256: RUNTIME_MATERIAL_SHA256,
    runtimeManifestSha256: RUNTIME_MANIFEST_SHA256,
    deploymentZeroConfEvidenceSha256: DEPLOYMENT_ZERO_CONF_EVIDENCE_SHA256,
  });
  assert.throws(() => store.initialize({
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    networkId: 2,
    denominationSats: DENOMINATION_SATS,
    state: state(),
    outpoint: { txid: b(0x44), vout: 0 },
    acceptanceId: b(0x55),
    runtimeMaterialSha256: b(0xee),
    runtimeManifestSha256: RUNTIME_MANIFEST_SHA256,
    deploymentZeroConfEvidenceSha256: DEPLOYMENT_ZERO_CONF_EVIDENCE_SHA256,
  }), V2BetaIncrementalStoreError);
}));

test("beta store telemetry reports measured SQLite/WAL bytes and authenticated counters", () => withStore(({ store }) => {
  initialize(store);
  const before = store.telemetry();
  assert.deepEqual(Object.keys(before).sort(), [
    "databaseBytes", "liveCount", "noteCount", "nullifierCount", "schema", "walBytes",
  ]);
  assert.equal(before.noteCount, 0);
  assert.equal(before.nullifierCount, 0);
  assert.equal(before.liveCount, 0);
  assert.ok(before.databaseBytes > 0);
  assert.ok(before.walBytes >= 0);
  const transition = deposit(store, "deposit.telemetry");
  store.applyAcceptedZeroConfSuccessor({
    operationId: "deposit.telemetry",
    successor: { txid: b(0x63), vout: 0, acceptanceId: b(0x64) },
    change: { txid: b(0x65), vout: 0, valueSats: "10000000" },
    ownedOutputNoteId: null,
    ownedOutputRecordId: null,
    ownedOutputNullifier: null,
  });
  assert.equal(transition.state.noteCount, "1");
  const after = store.telemetry();
  assert.equal(after.noteCount, 1);
  assert.equal(after.nullifierCount, 0);
  assert.equal(after.liveCount, 1);
}));

test("beta bootstrap funding publishes all ten exact reserves atomically and idempotently", () => withStore(({ store }) => {
  initialize(store);
  assert.throws(() => store.assertBootstrapFundingComplete(), V2BetaIncrementalStoreError);
  const input = bootstrapFunding();
  const first = store.initializeBootstrapFunding(input);
  assert.equal(first.outputCount, 10);
  assert.equal(first.sourceTransactionId.toString("hex"), input.sourceTransactionId.toString("hex"));
  assert.equal(first.setSha256.length, 32);
  assert.deepEqual(store.assertBootstrapFundingComplete(), first);
  assert.deepEqual(store.initializeBootstrapFunding(input), first);
  assert.equal(store.availableFundingUtxos().length, 10);
  const changed = bootstrapFunding(); changed.utxos[4] = { ...changed.utxos[4], valueSats: "9999999" };
  assert.throws(() => store.initializeBootstrapFunding(changed), V2BetaIncrementalStoreError);
  assert.deepEqual(store.assertBootstrapFundingComplete(), first);
}));

test("beta bootstrap funding rolls back every new reserve if one existing row conflicts", () => withStore(({ store }) => {
  initialize(store);
  const input = bootstrapFunding(b(0x72));
  store.putFundingUtxo({ txid: input.sourceTransactionId, vout: 10, valueSats: "999999" });
  assert.throws(() => store.initializeBootstrapFunding(input), V2BetaIncrementalStoreError);
  assert.throws(() => store.assertBootstrapFundingComplete(), V2BetaIncrementalStoreError);
  const remaining = store.availableFundingUtxos();
  assert.equal(remaining.length, 1);
  assert.equal(remaining[0].vout, 10);
  assert.equal(remaining[0].valueSats, "999999");
}));

test("beta store only migrates a legacy schema when it is uninitialized", () => {
  const root = mkdtempSync(join(tmpdir(), "shieldkit-beta-migration-"));
  const databasePath = join(root, "private", "store.sqlite");
  let store;
  try {
    store = openV2BetaIncrementalStore({ databasePath });
    store.close();
    store = null;
    const emptyLegacy = new DatabaseSync(databasePath);
    try {
      emptyLegacy.exec("ALTER TABLE metadata DROP COLUMN runtime_material_sha256; ALTER TABLE metadata DROP COLUMN runtime_manifest_sha256; ALTER TABLE metadata DROP COLUMN deployment_zero_conf_evidence_sha256;");
    } finally { emptyLegacy.close(); }
    store = openV2BetaIncrementalStore({ databasePath });
    initialize(store);
    store.close();
    store = null;
    const initializedLegacy = new DatabaseSync(databasePath);
    try {
      initializedLegacy.exec("ALTER TABLE metadata DROP COLUMN deployment_zero_conf_evidence_sha256; UPDATE metadata SET schema_version=2 WHERE singleton=1;");
    } finally { initializedLegacy.close(); }
    assert.throws(() => openV2BetaIncrementalStore({ databasePath }), V2BetaIncrementalStoreError);
  } finally {
    if (store) store.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("beta database rejects a hardlinked terminal path", () => {
  const root = mkdtempSync(join(tmpdir(), "shieldkit-beta-hardlink-"));
  try {
    const parent = join(root, "private"); mkdirSync(parent, { mode: 0o700 }); chmodSync(parent, 0o700);
    const source = join(parent, "source.sqlite"); writeFileSync(source, "x", { mode: 0o600 });
    const linked = join(parent, "linked.sqlite"); linkSync(source, linked);
    assert.throws(() => openV2BetaIncrementalStore({ databasePath: linked }), V2BetaIncrementalStoreError);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("beta O(depth) packet state matches the normative direct transition", () => withStore(({ store }) => {
  initialize(store);
  const transition = deposit(store);
  const model = createDirectV2PoolModel({
    profileId: PROFILE_ID.toString("hex"), maximumLiveNotes: "210000000", denominationSats: DENOMINATION_SATS,
  });
  const reference = applyDirectV2Transition({
    kind: "deposit", networkId: 2, profileId: PROFILE_ID.toString("hex"), instanceId: INSTANCE_ID.toString("hex"),
    denominationSats: DENOMINATION_SATS, preState: model.state, noteTree: model.noteTree, nullifierTree: model.nullifierTree,
    transactionContextHash: b(0x62).toString("hex"),
    output: { outputNoteLeaf: b(9).toString("hex"), encryptedRecord: b(0x70, 128) },
  });
  assert.deepEqual(transition.state, reference.state);
}));

test("derived successors are one-shot, store-local, and never persist an unbound packet", () => withStore(({ store }) => {
  initialize(store);
  store.putFundingUtxo({ txid: b(0xa1), vout: 0, valueSats: "20000000" });
  store.reserveOperation({ operationId: "derived-deposit", kind: "deposit", selectedNoteId: null, funding: { txid: b(0xa1), vout: 0 } });
  let depositDerivations = 0;
  const deriveDeposit = store.deriveProvingSuccessor.bind(store);
  store.deriveProvingSuccessor = (value) => {
    depositDerivations += 1;
    return deriveDeposit(value);
  };
  const successor = store.deriveProvingSuccessor({
    operationId: "derived-deposit", outputNoteLeaf: b(9), encryptedRecord: b(0x70, 128),
    publicNullifier: null, withdrawalLockingBytecodeHash: null,
  });
  assert.equal(depositDerivations, 1);
  assert.equal(store.operation("derived-deposit").packet, null);
  assert.throws(() => store.finalizeProvingTransition({
    derivedSuccessor: { ...successor }, operationId: "derived-deposit", transactionContextHash: b(0xa2),
  }), V2BetaIncrementalStoreError);
  assert.throws(() => store.finalizeProvingTransition({
    derivedSuccessor: successor, operationId: "another-action", transactionContextHash: b(0xa2),
  }), V2BetaIncrementalStoreError);
  const transition = store.finalizeProvingTransition({
    derivedSuccessor: successor, operationId: "derived-deposit", transactionContextHash: b(0xa2),
  });
  assert.equal(store.operation("derived-deposit").packet.toString("hex"), transition.packet.toString("hex"));
  assert.throws(() => store.finalizeProvingTransition({
    derivedSuccessor: successor, operationId: "derived-deposit", transactionContextHash: b(0xa2),
  }), V2BetaIncrementalStoreError);
  store.stageOperationArtifacts({ operationId: "derived-deposit", packet: transition.packet, proofArtifact: Buffer.from("proof"), transactionArtifact: Buffer.from("transaction") });
  store.putEncryptedRecord({ recordId: "derived-record", record: b(0x70, 128) });
  store.applyAcceptedZeroConfSuccessor({
    operationId: "derived-deposit", successor: { txid: b(0xa3), vout: 0, acceptanceId: b(0xa4) }, change: null,
    ownedOutputNoteId: "derived-note", ownedOutputRecordId: "derived-record", ownedOutputNullifier: b(0x13),
  });
  store.markLocalWalletCommitComplete({ operationId: "derived-deposit", transactionId: b(0xa3), transactionArtifactSha256: sha256(Buffer.from("transaction")) });
  store.putFundingUtxo({ txid: b(0xa5), vout: 0, valueSats: "20000000" });
  store.reserveOperation({ operationId: "derived-withdrawal", kind: "withdrawal", selectedNoteId: "derived-note", funding: { txid: b(0xa5), vout: 0 } });
  let withdrawalDerivations = 0;
  const deriveWithdrawal = store.deriveProvingSuccessor.bind(store);
  store.deriveProvingSuccessor = (value) => {
    withdrawalDerivations += 1;
    return deriveWithdrawal(value);
  };
  const withdrawal = store.deriveProvingSuccessor({
    operationId: "derived-withdrawal", outputNoteLeaf: null, encryptedRecord: null,
    publicNullifier: b(0x13), withdrawalLockingBytecodeHash: b(0xa6),
  });
  assert.equal(withdrawalDerivations, 1);
  assert.equal(store.operation("derived-withdrawal").packet, null);
  const finalizedWithdrawal = store.finalizeProvingTransition({
    derivedSuccessor: withdrawal, operationId: "derived-withdrawal", transactionContextHash: b(0xa7),
  });
  assert.equal(finalizedWithdrawal.state.actionSequence, "2");
}));

test("derived successor capabilities reject cross-store and stale finalization", () => withStore(({ store }) => {
  initialize(store);
  store.putFundingUtxo({ txid: b(0xb1), vout: 0, valueSats: "20000000" });
  store.reserveOperation({ operationId: "stale-successor", kind: "deposit", selectedNoteId: null, funding: { txid: b(0xb1), vout: 0 } });
  const successor = store.deriveProvingSuccessor({
    operationId: "stale-successor", outputNoteLeaf: b(9), encryptedRecord: b(0x70, 128),
    publicNullifier: null, withdrawalLockingBytecodeHash: null,
  });
  withStore(({ store: other }) => {
    initialize(other);
    assert.throws(() => other.finalizeProvingTransition({
      derivedSuccessor: successor, operationId: "stale-successor", transactionContextHash: b(0xb2),
    }), V2BetaIncrementalStoreError);
  });
  store.rollbackActiveSuffix({ operationId: "stale-successor" });
  assert.throws(() => store.finalizeProvingTransition({
    derivedSuccessor: successor, operationId: "stale-successor", transactionContextHash: b(0xb2),
  }), V2BetaIncrementalStoreError);
}));

test("accepted owned deposit persists its real nullifier through an O(depth) withdrawal", () => withStore(({ store }) => {
  initialize(store);
  store.putEncryptedRecord({ recordId: "owned-record", record: b(0x70, 128) });
  const depositTransition = deposit(store, "deposit-owned");
  store.applyAcceptedZeroConfSuccessor({
    operationId: "deposit-owned",
    successor: { txid: b(0x91), vout: 0, acceptanceId: b(0x92) },
    change: null,
    ownedOutputNoteId: "owned-note",
    ownedOutputRecordId: "owned-record",
    ownedOutputNullifier: b(0x13),
  });
  store.markLocalWalletCommitComplete({ operationId: "deposit-owned", transactionId: b(0x91), transactionArtifactSha256: sha256(Buffer.from("test-transaction")) });
  store.putFundingUtxo({ txid: b(0x95), vout: 0, valueSats: "20000000" });
  assert.deepEqual(store.availableFundingUtxos(), [{ txid: b(0x95), vout: 0, valueSats: "20000000" }]);
  store.reserveOperation({ operationId: "withdraw-owned", kind: "withdrawal", selectedNoteId: "owned-note", funding: { txid: b(0x95), vout: 0 } });
  assert.deepEqual(store.availableFundingUtxos(), []);
  const withdrawal = store.deriveProvingTransition({
    operationId: "withdraw-owned", outputNoteLeaf: null, encryptedRecord: null,
    publicNullifier: b(0x13), withdrawalLockingBytecodeHash: b(0x14), transactionContextHash: b(0x15),
  });
  store.stageOperationArtifacts({ operationId: "withdraw-owned", packet: withdrawal.packet, proofArtifact: Buffer.from("withdraw-proof"), transactionArtifact: Buffer.from("withdraw-transaction") });
  store.applyAcceptedZeroConfSuccessor({
    operationId: "withdraw-owned", successor: { txid: b(0x93), vout: 0, acceptanceId: b(0x94) },
    change: null, ownedOutputNoteId: null, ownedOutputRecordId: null, ownedOutputNullifier: null,
  });
  assert.deepEqual(store.availableFundingUtxos(), []);
  const model = createDirectV2PoolModel({ profileId: PROFILE_ID.toString("hex"), maximumLiveNotes: "210000000", denominationSats: DENOMINATION_SATS });
  const referenceDeposit = applyDirectV2Transition({
    kind: "deposit", networkId: 2, profileId: PROFILE_ID.toString("hex"), instanceId: INSTANCE_ID.toString("hex"), denominationSats: DENOMINATION_SATS,
    preState: model.state, noteTree: model.noteTree, nullifierTree: model.nullifierTree, transactionContextHash: b(0x62).toString("hex"),
    output: { outputNoteLeaf: b(9).toString("hex"), encryptedRecord: b(0x70, 128) },
  });
  const referenceWithdrawal = applyDirectV2Transition({
    kind: "withdrawal", networkId: 2, profileId: PROFILE_ID.toString("hex"), instanceId: INSTANCE_ID.toString("hex"), denominationSats: DENOMINATION_SATS,
    preState: referenceDeposit.state, noteTree: referenceDeposit.noteTree, nullifierTree: referenceDeposit.nullifierTree,
    transactionContextHash: b(0x15).toString("hex"), withdrawalLockingBytecodeHash: b(0x14).toString("hex"),
    spend: { inputNoteLeaf: b(9).toString("hex"), noteIndex: "0", publicNullifier: b(0x13).toString("hex") },
  });
  assert.deepEqual(withdrawal.state, referenceWithdrawal.state);
  store.putFundingUtxo({ txid: b(0x96), vout: 0, valueSats: "20000000" });
  assert.throws(() => store.reserveOperation({ operationId: "re-spend", kind: "withdrawal", selectedNoteId: "owned-note", funding: { txid: b(0x96), vout: 0 } }), V2BetaIncrementalStoreError);
  assert.equal(depositTransition.witness.note.depth, 32);
}));

test("beta store has one active operation and rollback releases its reservation", () => withStore(({ store }) => {
  initialize(store);
  store.putFundingUtxo({ txid: b(0x71), vout: 0, valueSats: "20000000" });
  store.reserveOperation({ operationId: "one", kind: "deposit", selectedNoteId: null, funding: { txid: b(0x71), vout: 0 } });
  assert.throws(() => store.reserveOperation({ operationId: "two", kind: "deposit", selectedNoteId: null, funding: { txid: b(0x71), vout: 0 } }), V2BetaIncrementalStoreError);
  assert.equal(store.rollbackActiveSuffix({ operationId: "one" }).state, "rejected");
  store.reserveOperation({ operationId: "two", kind: "deposit", selectedNoteId: null, funding: { txid: b(0x71), vout: 0 } });
}));

test("safe pre-send abort keeps the exact reserved and staged finalization semantics", () => {
  for (const staged of [false, true]) withStore(({ store }) => {
    initialize(store);
    const operationId = staged ? "abort-staged" : "abort-reserved";
    if (staged) deposit(store, operationId);
    else {
      store.putFundingUtxo({ txid: b(0xc1), vout: 0, valueSats: "20000000" });
      store.reserveOperation({ operationId, kind: "deposit", selectedNoteId: null, funding: { txid: b(0xc1), vout: 0 } });
    }
    const marker = { operationId, kind: "deposit", reason: "action-failed-before-network-send" };
    assert.equal(store.activeOperation().state, staged ? "staged" : "reserved");
    assert.deepEqual(store.markSafePreSendAbort(marker), marker);
    assert.deepEqual(store.safePreSendAbortMarker(operationId), marker);
    assert.equal(store.finalizeSafePreSendAbort(marker).state, "rejected");
    assert.equal(store.activeOperation(), null);
    assert.equal(store.availableFundingUtxos().length, 1);
  });
});

test("an exactly rejected safe pre-send abort replays without changing the tip or reservations", () => withStore(({ store }) => {
  initialize(store);
  const funding = { txid: b(0xc2), vout: 0 };
  store.putFundingUtxo({ ...funding, valueSats: "20000000" });
  store.reserveOperation({ operationId: "abort-replay", kind: "deposit", selectedNoteId: null, funding });
  const marker = { operationId: "abort-replay", kind: "deposit", reason: "action-failed-before-network-send" };
  store.markSafePreSendAbort(marker);
  assert.equal(store.finalizeSafePreSendAbort(marker).state, "rejected");
  assert.deepEqual(store.safePreSendAbortMarker(marker.operationId), marker);

  store.reserveOperation({ operationId: "next-active", kind: "deposit", selectedNoteId: null, funding });
  const before = {
    tip: store.optimisticTip(),
    active: store.activeOperation(),
    availableFunding: store.availableFundingUtxos(),
    rejected: store.operation(marker.operationId),
  };
  assert.deepEqual(store.markSafePreSendAbort(marker), marker);
  assert.deepEqual(store.safePreSendAbortMarker(marker.operationId), marker);
  assert.deepEqual(store.finalizeSafePreSendAbort(marker), before.rejected);
  for (const mismatch of [
    { ...marker, kind: "withdrawal" },
    { ...marker, reason: "different-safe-pre-send-reason" },
  ]) {
    assert.throws(() => store.markSafePreSendAbort(mismatch), V2BetaIncrementalStoreError);
    assert.throws(() => store.finalizeSafePreSendAbort(mismatch), V2BetaIncrementalStoreError);
  }
  assert.deepEqual(store.optimisticTip(), before.tip);
  assert.deepEqual(store.activeOperation(), before.active);
  assert.deepEqual(store.availableFundingUtxos(), before.availableFunding);
  assert.deepEqual(store.operation(marker.operationId), before.rejected);
  assert.equal(store.operation("next-active").state, "reserved");
}));

test("a rollback rejection cannot be relabeled as a safe pre-send abort", () => withStore(({ store }) => {
  initialize(store);
  store.putFundingUtxo({ txid: b(0xc3), vout: 0, valueSats: "20000000" });
  store.reserveOperation({ operationId: "plain-rejection", kind: "deposit", selectedNoteId: null, funding: { txid: b(0xc3), vout: 0 } });
  store.rollbackActiveSuffix({ operationId: "plain-rejection" });
  const marker = { operationId: "plain-rejection", kind: "deposit", reason: "action-failed-before-network-send" };
  assert.equal(store.safePreSendAbortMarker(marker.operationId), null);
  assert.throws(() => store.markSafePreSendAbort(marker), V2BetaIncrementalStoreError);
  assert.throws(() => store.finalizeSafePreSendAbort(marker), V2BetaIncrementalStoreError);
  assert.equal(store.operation(marker.operationId).state, "rejected");
  assert.equal(store.availableFundingUtxos().length, 1);
}));

test("beta read-only resume surfaces expose exact staged artifacts and only available resources", () => withStore(({ store }) => {
  initialize(store);
  store.putFundingUtxo({ txid: b(0x61), vout: 0, valueSats: "20000000" });
  assert.deepEqual(store.availableFundingUtxos(), [{ txid: b(0x61), vout: 0, valueSats: "20000000" }]);
  store.reserveOperation({ operationId: "resume-deposit", kind: "deposit", selectedNoteId: null, funding: { txid: b(0x61), vout: 0 } });
  assert.deepEqual(store.availableFundingUtxos(), []);
  assert.deepEqual(store.availableOwnedNotes(), []);
  assert.deepEqual(store.activeOperation(), { operationId: "resume-deposit", kind: "deposit", state: "reserved", localWalletCommitPending: false, selectedNoteId: null, funding: { txid: b(0x61), vout: 0 } });
  const transition = store.deriveProvingTransition({ operationId: "resume-deposit", outputNoteLeaf: b(9), encryptedRecord: b(0x70, 128), publicNullifier: null, withdrawalLockingBytecodeHash: null, transactionContextHash: b(0x62) });
  store.stageOperationArtifacts({ operationId: "resume-deposit", packet: transition.packet, proofArtifact: Buffer.from("exact-proof"), transactionArtifact: Buffer.from("exact-transaction") });
  const staged = store.stagedOperation("resume-deposit");
  assert.equal(staged.packet.toString("hex"), transition.packet.toString("hex"));
  assert.equal(staged.proofArtifact.toString(), "exact-proof");
  assert.equal(staged.transactionArtifact.toString(), "exact-transaction");
  assert.equal(staged.proofArtifactSha256.length, 32);
  assert.equal(staged.transactionArtifactSha256.length, 32);
  assert.equal(staged.expectedTip.actionSequence, 0);
  assert.equal(staged.state, "staged");
  assert.deepEqual(staged.resources, { selectedNoteId: null, funding: { txid: b(0x61), vout: 0, valueSats: "20000000" } });
  assert.equal(store.activeOperation().state, "staged");
}));

test("beta staged artifact tampering cannot advance the tip", () => withStore(({ store, databasePath }) => {
  initialize(store); const transition = deposit(store);
  const db = new DatabaseSync(databasePath);
  try { db.prepare("UPDATE operations SET proof_artifact=? WHERE operation_id='deposit-1'").run(Buffer.from("altered")); } finally { db.close(); }
  assert.throws(() => store.applyAcceptedZeroConfSuccessor({
    operationId: "deposit-1", successor: { txid: b(0x80), vout: 0, acceptanceId: b(0x81) },
    change: null, ownedOutputNoteId: null, ownedOutputRecordId: null, ownedOutputNullifier: null,
  }), V2BetaIncrementalStoreError);
}));
