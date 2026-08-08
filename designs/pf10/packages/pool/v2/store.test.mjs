import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import {
  decodeTransactionBch,
  encodeTransaction,
} from "@bitauth/libauth";

import {
  encodeDirectV2Address,
} from "../../action/v2/address.mjs";
import {
  buildDirectV2CircuitInput,
} from "../../action/v2/circuit-witness.mjs";
import {
  constructDirectV2Output,
  deriveDirectV2Address,
} from "../../action/v2/notes.mjs";
import {
  decodeActionPacket,
  encodeActionPacket,
} from "../../action/v2/packet.mjs";
import {
  decodeStateNftCommitment,
  encodeStateNftCommitment,
} from "../../action/v2/state.mjs";
import {
  applyDirectV2Transition,
  createDirectV2PoolModel,
} from "../../action/v2/transition.mjs";
import {
  hashIndexedNullifierLeaf,
} from "../../action/v2/poseidon.mjs";
import {
  parseV2RawTransaction,
} from "../../kit/v2/transaction-policy.mjs";
import {
  openExistingV2DirectStore,
  openV2DirectStore,
  V2_AUTHENTICATED_SNAPSHOT_CRASH_STAGES,
  V2_AUTHENTICATED_STREAM_CRASH_STAGES,
  V2_OPERATION_CREATE_CRASH_STAGES,
  V2_OPERATION_MANUAL_RETRY_CRASH_STAGES,
  V2_OPERATION_MAX_AUTOMATIC_CONFLICTS,
  V2_OPERATION_PREPARE_CRASH_STAGES,
  V2_OPERATION_REBASE_CRASH_STAGES,
  V2_OPERATION_SETTLE_CRASH_STAGES,
  V2_PROVING_TRANSITION_SCHEMA,
  V2_STORE_SCHEMA_VERSION,
  V2StoreCrashInjection,
  V2StoreError,
} from "./store.mjs";

const b = (byte, length = 32) => Buffer.alloc(length, byte);
const fr = (value) => Buffer.from(value.toString(16).padStart(64, "0"), "hex");
function testNoteNullifier(noteId) {
  const value = createHash("sha256")
    .update(`ShieldKit/V2Direct/TestOwnedNote/${noteId}`)
    .digest();
  value[0] = 0;
  if (value.equals(Buffer.alloc(32))) value[31] = 1;
  return value;
}
function putTestOwnedNote(
  store,
  {
    noteId,
    recordId,
    noteIndex = createHash("sha256").update(noteId).digest().readUInt32LE(0),
    nullifier = testNoteNullifier(noteId),
  },
) {
  store.putOwnedNote({ noteId, recordId, noteIndex, nullifier });
}
const FR_MINUS_ONE =
  21888242871839275222246405745257275088548364400416034343698204186575808495616n;
const PROFILE_ID = b(0x11);
const INSTANCE_ID = b(0x22);
const RUNTIME_MATERIALS_SHA256 = b(0x33);
const NETWORK_ID = 2;
const DENOMINATION_SATS = "10000000";
const CARRIER_COUNT = 7;
const stateContext = Object.freeze({ denominationSats: DENOMINATION_SATS });
const SHIELD_ADDRESS = encodeDirectV2Address(deriveDirectV2Address({
  networkId: NETWORK_ID,
  profileId: PROFILE_ID.toString("hex"),
  instanceId: INSTANCE_ID.toString("hex"),
  spendSecret: fr(3n).toString("hex"),
  incomingViewSecret: fr(4n).toString("hex"),
}));
const RECIPIENT_ADDRESS = deriveDirectV2Address({
  networkId: NETWORK_ID,
  profileId: PROFILE_ID.toString("hex"),
  instanceId: INSTANCE_ID.toString("hex"),
  spendSecret: fr(3n).toString("hex"),
  incomingViewSecret: fr(4n).toString("hex"),
});
function scalarRng(start) {
  let next = BigInt(start);
  return Object.freeze({
    bytes() {
      const value = next;
      next += 1n;
      return fr(value);
    },
  });
}
const FUNDING_PUBLIC_KEY = Buffer.from(
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "hex",
);
function p2pkhForPublicKey(publicKey) {
  const sha = createHash("sha256").update(publicKey).digest();
  const hash = createHash("ripemd160").update(sha).digest();
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    hash,
    Buffer.from([0x88, 0xac]),
  ]);
}
const FUNDING_LOCK = p2pkhForPublicKey(FUNDING_PUBLIC_KEY);
const CHANGE_LOCK = Buffer.from(
  "76a914111111111111111111111111111111111111111188ac",
  "hex",
);
const WITHDRAWAL_LOCK = Buffer.from(
  "76a914222222222222222222222222222222222222222288ac",
  "hex",
);
function fundingSource(tag, valueSats) {
  const value = Buffer.alloc(8);
  value.writeBigUInt64LE(BigInt(valueSats));
  const rawSourceTransaction = Buffer.concat([
    Buffer.from("0200000001", "hex"),
    createHash("sha256").update(tag).digest(),
    Buffer.from("0000000000ffffffff01", "hex"),
    value,
    Buffer.from([FUNDING_LOCK.length]),
    FUNDING_LOCK,
    Buffer.alloc(4),
  ]);
  const parsed = parseV2RawTransaction(rawSourceTransaction.toString("hex"));
  return Object.freeze({
    rawSourceTransaction,
    txid: Buffer.from(parsed.txid, "hex"),
    vout: 0,
    valueSats,
    lockingBytecode: FUNDING_LOCK,
    compressedPublicKey: FUNDING_PUBLIC_KEY,
  });
}
function intentFixture({
  operationId,
  kind,
  selectedNoteId,
  fundingValueSats,
  fundingTag = operationId,
}) {
  return {
    kind,
    target: kind === "withdrawal"
      ? {
        type: "withdrawal_locking_bytecode",
        bytes: WITHDRAWAL_LOCK,
      }
      : { type: "shield_address", bytes: SHIELD_ADDRESS },
    selectedNoteId,
    funding: fundingSource(fundingTag, fundingValueSats),
    changeLockingBytecode: CHANGE_LOCK,
    feePolicy: {
      feeRateSatsPerByte: "1",
      maximumFeeSats: (
        BigInt(fundingValueSats) < 100_000n
          ? BigInt(fundingValueSats)
          : 100_000n
      ).toString(),
    },
  };
}
const seed = () => {
  const model = createDirectV2PoolModel({
    profileId: PROFILE_ID.toString("hex"),
    maximumLiveNotes: "210000000",
    denominationSats: DENOMINATION_SATS,
  });
  return {
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    networkId: NETWORK_ID,
    denominationSats: DENOMINATION_SATS,
    carrierCount: CARRIER_COUNT,
    runtimeMaterialsSha256: RUNTIME_MATERIALS_SHA256,
    state: encodeStateNftCommitment(model.state, stateContext),
    outpoint: { txid: b(0x44), vout: 0 },
    actionSequence: 0,
    height: 100,
    blockHash: b(0x55),
  };
};
function nullifierLeaf({
  physicalIndex,
  leafType,
  key,
  successorIndex,
  successorKey,
}) {
  const leafHash = Buffer.from(
    hashIndexedNullifierLeaf([
      BigInt(leafType),
      BigInt(physicalIndex),
      BigInt(`0x${Buffer.from(key).toString("hex")}`),
      BigInt(successorIndex),
      BigInt(`0x${Buffer.from(successorKey).toString("hex")}`),
    ]).toString(16).padStart(64, "0"),
    "hex",
  );
  return {
    physicalIndex,
    leafType,
    leafHash,
    key: Buffer.from(key),
    successorIndex,
    successorKey: Buffer.from(successorKey),
  };
}
const canonical = ({ state, outpoint, actionSequence, height, blockHash }) => ({
  state,
  outpoint,
  actionSequence,
  height,
  blockHash,
});
function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), "shieldkit-v2-store-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const initial = seed();
  const path = join(directory, "private", "pool.sqlite");
  return {
    directory,
    path,
    initial,
    store: openV2DirectStore({ path, ...initial }),
  };
}
const blankArtifacts = () => ({
  packet: null,
  proof: null,
  unsignedTx: null,
  signedTx: null,
  localVmEvidence: null,
});
function packetFixture(store, expected, kind, byte) {
  const preState = decodeStateNftCommitment(expected.state, stateContext);
  const publicNullifier = kind === "deposit"
    ? Buffer.alloc(32)
    : fr(BigInt(byte + 1));
  const outputNoteLeaf = kind === "withdrawal"
    ? Buffer.alloc(32)
    : fr(BigInt(byte + 2));
  const derived = store.derivePacketPostState({
    kind,
    publicNullifier,
    outputNoteLeaf,
  });
  const postState = derived.state;
  const encryptedRecord = kind === "withdrawal"
    ? Buffer.alloc(128)
    : b((byte + 7) & 0xff, 128);
  const packet = encodeActionPacket({
    kind,
    networkId: NETWORK_ID,
    instanceId: INSTANCE_ID.toString("hex"),
    preState,
    postState,
    publicNullifier: publicNullifier.toString("hex"),
    outputNoteLeaf: outputNoteLeaf.toString("hex"),
    encryptedRecord,
    withdrawalLockingBytecodeHash: kind === "withdrawal"
      ? createHash("sha256").update(WITHDRAWAL_LOCK).digest("hex")
      : Buffer.alloc(32).toString("hex"),
    transactionContextHash: b((byte + 4) & 0xff).toString("hex"),
  }, stateContext);
  return Object.freeze({
    packet,
    decoded: decodeActionPacket(packet, stateContext),
    postState: derived.stateBytes,
    encryptedRecord,
  });
}
function mutatePacket(packet, mutate) {
  const decoded = decodeActionPacket(packet, stateContext);
  const copy = {
    ...decoded,
    preState: { ...decoded.preState },
    postState: { ...decoded.postState },
    encryptedRecord: Buffer.from(decoded.encryptedRecord),
  };
  mutate(copy);
  return encodeActionPacket(copy, stateContext);
}
function advanceReference(reference, prepared, spend = null) {
  const packet = prepared.decoded;
  const common = {
    kind: packet.kind,
    networkId: packet.networkId,
    profileId: PROFILE_ID.toString("hex"),
    instanceId: INSTANCE_ID.toString("hex"),
    denominationSats: DENOMINATION_SATS,
    preState: reference.state,
    noteTree: reference.noteTree,
    nullifierTree: reference.nullifierTree,
    transactionContextHash: packet.transactionContextHash,
    expectedPostState: packet.postState,
  };
  if (packet.kind !== "withdrawal") {
    common.output = {
      outputNoteLeaf: packet.outputNoteLeaf,
      encryptedRecord: packet.encryptedRecord,
    };
  }
  if (packet.kind !== "deposit") {
    common.spend = {
      inputNoteLeaf: spend.inputNoteLeaf,
      noteIndex: String(spend.noteIndex),
      publicNullifier: packet.publicNullifier,
    };
  }
  if (packet.kind === "withdrawal") {
    common.withdrawalLockingBytecodeHash =
      packet.withdrawalLockingBytecodeHash;
  }
  return applyDirectV2Transition(common);
}
function operationRequest(
  operationId,
  kind,
  expected,
  {
    selectedNoteId = kind === "deposit"
      ? null
      : `${operationId}-input-note`,
    fundingValueSats = "1",
    fundingTag = operationId,
    crashAt = null,
  } = {},
) {
  return {
    operationId,
    kind,
    expectedState: expected.state,
    expectedOutpoint: expected.outpoint,
    expectedActionSequence: expected.actionSequence,
    expectedHeight: expected.height,
    expectedBlockHash: expected.blockHash,
    runtimeMaterialsSha256: RUNTIME_MATERIALS_SHA256,
    actionMaterialSha256: b(0xa6),
    privateActionRecordSha256: b(0xa9),
    intent: intentFixture({
      operationId,
      kind,
      selectedNoteId,
      fundingValueSats,
      fundingTag,
    }),
    ...blankArtifacts(),
    crashAt,
  };
}
function create(
  store,
  operationId,
  kind,
  expected = store.canonicalState(),
  options = {},
) {
  return store.createOperation(
    operationRequest(operationId, kind, expected, options),
  );
}
function operationTransactions({
  expected,
  operation,
  packet,
}) {
  const decoded = decodeActionPacket(packet, stateContext);
  const fundingValue = BigInt(operation.intent.funding.valueSats);
  const boundary = operation.kind === "deposit"
    ? BigInt(DENOMINATION_SATS)
    : 0n;
  const parentHash = Uint8Array.from(expected.outpoint.txid);
  const fundingHash = Uint8Array.from(operation.intent.funding.txid);
  const bindingUnlock = Buffer.concat([
    Buffer.from("4d2802", "hex"),
    packet,
    Buffer.from([0x01, 0x51]),
  ]);
  const fundingUnlock = Buffer.concat([
    Buffer.from([0x41]),
    Buffer.alloc(64),
    Buffer.from([0x61, 0x21]),
    FUNDING_PUBLIC_KEY,
  ]);
  assert.equal(fundingUnlock.length, 100);
  const makeInputs = (signed) => [
    ...Array.from({ length: CARRIER_COUNT + 2 }, (_, index) => ({
      outpointTransactionHash: parentHash,
      outpointIndex: index === CARRIER_COUNT + 1 ? 0 : index + 1,
      sequenceNumber: 0,
      unlockingBytecode: index === CARRIER_COUNT
        ? bindingUnlock
        : Uint8Array.of(0x51),
    })),
    {
      outpointTransactionHash: fundingHash,
      outpointIndex: operation.intent.funding.vout,
      sequenceNumber: 0,
      unlockingBytecode: signed ? fundingUnlock : new Uint8Array(),
    },
  ];
  const tokenlessOutput = (valueSatoshis, lockingBytecode) => ({
    valueSatoshis,
    lockingBytecode: Uint8Array.from(lockingBytecode),
  });
  const makeOutputs = (changeValue) => {
    const outputs = [
      {
        valueSatoshis: BigInt(decoded.postState.reserveSats) + 1_000n,
        lockingBytecode: Uint8Array.of(0x51),
        token: {
          category: Uint8Array.from(Buffer.from(INSTANCE_ID).reverse()),
          amount: 0n,
          nft: {
            capability: "mutable",
            commitment: encodeStateNftCommitment(
              decoded.postState,
              stateContext,
            ),
          },
        },
      },
      ...Array.from(
        { length: CARRIER_COUNT },
        (_, index) => tokenlessOutput(
          1_000n + BigInt(index),
          Uint8Array.of(0x51),
        ),
      ),
      tokenlessOutput(2_000n, Uint8Array.of(0x51)),
    ];
    if (operation.kind === "withdrawal") {
      outputs.push(
        tokenlessOutput(BigInt(DENOMINATION_SATS), WITHDRAWAL_LOCK),
      );
    }
    outputs.push(tokenlessOutput(changeValue, CHANGE_LOCK));
    return outputs;
  };
  const encode = (signed, changeValue) => Buffer.from(encodeTransaction({
    version: 2,
    inputs: makeInputs(signed),
    outputs: makeOutputs(changeValue),
    locktime: 0,
  }));
  const sizingSigned = encode(true, 546n);
  const feeSats = BigInt(sizingSigned.length);
  const changeValueSats = fundingValue - boundary - feeSats;
  assert.ok(changeValueSats >= 546n);
  const signed = encode(true, changeValueSats);
  const unsigned = encode(false, changeValueSats);
  assert.equal(signed.length, sizingSigned.length);
  return Object.freeze({
    unsigned,
    signed,
    changeIndex: operation.kind === "withdrawal"
      ? CARRIER_COUNT + 3
      : CARRIER_COUNT + 2,
    changeValueSats,
    feeSats,
  });
}
function mutateTransaction(raw, mutate) {
  const decoded = decodeTransactionBch(raw);
  assert.notEqual(typeof decoded, "string");
  mutate(decoded);
  return Buffer.from(encodeTransaction(decoded));
}
function mutateBothTransactions(transactions, mutate) {
  return {
    ...transactions,
    unsigned: mutateTransaction(transactions.unsigned, mutate),
    signed: mutateTransaction(transactions.signed, mutate),
  };
}
function ready(
  store,
  operationId,
  kind,
  byte,
  fundingByte = byte,
  {
    broadcast = true,
    sign = true,
    transformTransactions = (value) => value,
  } = {},
) {
  const expected = store.canonicalState();
  const packet = packetFixture(store, expected, kind, byte);
  const noteId = kind === "deposit" ? null : `${operationId}-input-note`;
  const operation = create(store, operationId, kind, expected, {
    selectedNoteId: noteId,
    fundingValueSats: kind === "deposit" ? "10200000" : "200000",
    fundingTag: `${operationId}:${fundingByte}`,
  });
  const utxo = operation.intent.funding.txid;
  store.putFundingUtxo({
    txid: utxo,
    vout: 0,
    valueSats: operation.intent.funding.valueSats,
  });
  if (noteId !== null) {
    const recordId = `${operationId}-input-record`;
    store.putEncryptedRecord({ recordId, record: b(byte + 1, 128) });
    putTestOwnedNote(store, {
      noteId,
      recordId,
      nullifier: Buffer.from(packet.decoded.publicNullifier, "hex"),
    });
  }
  store.reserveResources({
    operationId,
    noteId,
    utxoTxid: utxo,
    utxoVout: 0,
    crashAt: null,
  });
  for (const to of ["tip_synced", "proving"]) {
    store.transitionOperation({ operationId, to, reason: null });
  }
  const transactions = transformTransactions(operationTransactions({
    expected,
    operation,
    packet: packet.packet,
  }));
  store.updateOperationArtifacts({
    operationId,
    packet: packet.packet,
    proof: b(byte + 1),
    unsignedTx: transactions.unsigned,
    signedTx: null,
    localVmEvidence: null,
  });
  store.transitionOperation({ operationId, to: "proved", reason: null });
  if (!sign) {
    return { expected, utxo, noteId, ...packet, ...transactions };
  }
  store.updateOperationArtifacts({
    operationId,
    packet: packet.packet,
    proof: b(byte + 1),
    unsignedTx: transactions.unsigned,
    signedTx: transactions.signed,
    localVmEvidence: b(byte + 4),
  });
  store.transitionOperation({ operationId, to: "signed", reason: null });
  if (broadcast) {
    store.transitionOperation({ operationId, to: "broadcast", reason: null });
  }
  return { expected, utxo, noteId, ...packet, ...transactions };
}
function confirmedArgs(
  store,
  operationId,
  expected,
  utxo,
  byte,
  {
    height = 101,
    blockHash = b(0x99),
    noteId = null,
    crashAt = null,
    kind = "deposit",
  } = {},
) {
  const operation = store.operation(operationId);
  assert.equal(operation.kind, kind);
  const packet = decodeActionPacket(operation.packet, stateContext);
  const signed = parseV2RawTransaction(
    operation.signedTx.toString("hex"),
  );
  const successorTxid = Buffer.from(signed.txid, "hex");
  const changeVout = kind === "withdrawal"
    ? CARRIER_COUNT + 3
    : CARRIER_COUNT + 2;
  return {
    operationId,
    expected: {
      state: expected.state,
      outpoint: expected.outpoint,
      actionSequence: expected.actionSequence,
    },
    next: {
      state: encodeStateNftCommitment(packet.postState, stateContext),
      outpoint: { txid: successorTxid, vout: 0 },
      actionSequence: expected.actionSequence + 1,
      height,
      blockHash,
    },
    records: kind === "withdrawal" ? [] : [{
      recordId: `${operationId}-output-record`,
      record: Buffer.from(packet.encryptedRecord),
    }],
    notes: {
      insert: kind === "withdrawal" ? [] : [{
        noteId: `${operationId}-output-note`,
        recordId: `${operationId}-output-record`,
        noteIndex: Number(packet.preState.noteCount),
        nullifier: testNoteNullifier(`${operationId}-output-note`),
      }],
      spend: kind === "deposit" ? [] : [noteId],
    },
    funding: {
      spend: { txid: utxo, vout: 0 },
      change: [{
        txid: successorTxid,
        vout: changeVout,
        valueSats: signed.outputs[changeVout].valueSatoshis.toString(),
      }],
    },
    undo: b(byte + 9, 5),
    crashAt,
  };
}
function materializedNodes(store, allocatedLeaves, query) {
  const nodes = [];
  for (let depth = 0; depth <= 32; depth += 1) {
    const width = depth === 32
      ? 1
      : Math.ceil(allocatedLeaves / (2 ** depth));
    for (let nodeIndex = 0; nodeIndex < width; nodeIndex += 1) {
      const nodeHash = query({ depth, nodeIndex });
      assert.notEqual(
        nodeHash,
        null,
        `missing materialized node ${depth}:${nodeIndex}`,
      );
      nodes.push({ depth, nodeIndex, nodeHash });
    }
  }
  return nodes;
}
function authenticatedSnapshotFromStore(store) {
  const binding = store.binding();
  const canonicalState = store.canonicalState();
  const decoded = decodeStateNftCommitment(canonicalState.state, {
    denominationSats: binding.denominationSats,
  });
  const noteCount = Number(decoded.noteCount);
  const nullifierCount = Number(decoded.nullifierCount);
  const noteNodes = materializedNodes(
    store,
    noteCount,
    (query) => store.noteNode(query),
  );
  const noteFrontier = [];
  for (let depth = 0; depth < 32; depth += 1) {
    if (
      ((BigInt(noteCount) >> BigInt(depth)) & 1n) === 1n
    ) {
      const nodeHash = store.noteFrontier({ depth });
      assert.notEqual(nodeHash, null, `missing frontier depth ${depth}`);
      noteFrontier.push({ depth, nodeHash });
    }
  }
  return {
    binding,
    canonical: canonicalState,
    noteNodes,
    noteFrontier,
    noteLeaves: Array.from(
      { length: noteCount },
      (_, noteIndex) => store.noteLeaf({ noteIndex }),
    ),
    nullifierNodes: materializedNodes(
      store,
      nullifierCount + 2,
      (query) => store.nullifierNode(query),
    ),
    nullifierLeaves: Array.from(
      { length: nullifierCount + 2 },
      (_, physicalIndex) => store.nullifierLeaf({ physicalIndex }),
    ),
    crashAt: null,
  };
}
function populatedAuthenticatedSnapshot(t) {
  const source = fixture(t);
  const actions = [];
  for (const [index, kind] of ["deposit", "deposit", "transfer"].entries()) {
    const byte = 0x30 + index * 8;
    const operationId = `snapshot-source-${index}`;
    const action = ready(source.store, operationId, kind, byte);
    const confirmed = confirmedArgs(
      source.store,
      operationId,
      action.expected,
      action.utxo,
      byte,
      {
        kind,
        noteId: action.noteId,
        height: 101 + index,
        blockHash: b(0x70 + index),
      },
    );
    source.store.applyConfirmed(confirmed);
    const packet = decodeActionPacket(action.packet, stateContext);
    actions.push({
      transactionId: confirmed.next.outpoint.txid,
      height: confirmed.next.height,
      blockHash: confirmed.next.blockHash,
      kind,
      packet: action.packet,
      transactionContextHash: Buffer.from(
        packet.transactionContextHash,
        "hex",
      ),
    });
  }
  const snapshot = authenticatedSnapshotFromStore(source.store);
  source.store.close();
  return {
    initial: source.initial,
    snapshot,
    actions,
  };
}
function authenticatedStreamFixture(initial, snapshot, actions) {
  const decoded = decodeStateNftCommitment(
    snapshot.canonical.state,
    stateContext,
  );
  const point = (value) => ({
    transactionId: value.outpoint.txid.toString("hex"),
    outputIndex: value.outpoint.vout,
    height: value.height,
    blockHash: value.blockHash.toString("hex"),
    stateHex: value.state.toString("hex"),
  });
  const compact = {
    schema: "shieldkit-v2-recovery-snapshot-v2",
    version: 2,
    networkId: snapshot.binding.networkId,
    profileId: snapshot.binding.profileId.toString("hex"),
    instanceId: snapshot.binding.instanceId.toString("hex"),
    denominationSats: snapshot.binding.denominationSats,
    carrierCount: snapshot.binding.carrierCount,
    runtimeMaterialsSha256: snapshot.binding.runtimeMaterialsSha256.toString("hex"),
    poseidonProfile: "shieldkit-pool-action-v2-direct-poseidon-v1",
    genesis: point({
      state: initial.state,
      outpoint: initial.outpoint,
      height: initial.height,
      blockHash: initial.blockHash,
    }),
    tip: point(snapshot.canonical),
    actionCount: String(snapshot.canonical.actionSequence),
    historySha256: b(0x91).toString("hex"),
    stateHex: snapshot.canonical.state.toString("hex"),
    noteTree: {
      depth: 32,
      count: decoded.noteCount,
      root: decoded.noteRoot,
    },
    nullifierTree: {
      depth: 32,
      count: decoded.nullifierCount,
      root: decoded.nullifierRoot,
    },
    externalAuthenticationBoundary:
      "test fixture authenticated against an exact local lineage",
    contentSha256: b(0x92).toString("hex"),
  };
  const counts = {
    action: actions.length,
    noteNode: snapshot.noteNodes.length,
    noteFrontier: snapshot.noteFrontier.length,
    noteLeaf: snapshot.noteLeaves.length,
    nullifierNode: snapshot.nullifierNodes.length,
    nullifierLeaf: snapshot.nullifierLeaves.length,
  };
  const frames = [
    { type: "header", counts },
    {
      type: "snapshot",
      snapshot: compact,
      material: {
        schema: "shieldkit-v2-recovery-authenticated-material-v2",
        contentSha256: compact.contentSha256,
        binding: snapshot.binding,
        canonical: snapshot.canonical,
      },
    },
  ];
  for (const [index, value] of actions.entries()) {
    frames.push({ type: "action", index, value });
  }
  for (const [type, values] of [
    ["note-node", snapshot.noteNodes],
    ["note-frontier", snapshot.noteFrontier],
    ["note-leaf", snapshot.noteLeaves],
    ["nullifier-node", snapshot.nullifierNodes],
    ["nullifier-leaf", snapshot.nullifierLeaves],
  ]) {
    for (const [index, value] of values.entries()) {
      frames.push({ type, index, value });
    }
  }
  frames.push({
    type: "end",
    counts,
    frameCount: frames.length,
    digest: b(0x93).toString("hex"),
  });
  return { compact, counts, frames };
}

test("creates a trusted 0700 parent and 0600 DB/WAL/SHM files with required pragmas", (t) => {
  const { directory, path, initial, store } = fixture(t);
  const parent = join(path, "..");
  assert.equal(lstatSync(parent).mode & 0o777, 0o700);
  assert.equal(lstatSync(path).mode & 0o777, 0o600);
  assert.deepEqual(store.pragmas(), {
    journalMode: "wal",
    synchronous: 2,
    foreignKeys: 1,
    busyTimeout: 5000,
  });
  for (const sidecar of [`${path}-wal`, `${path}-shm`]) {
    try {
      assert.equal(lstatSync(sidecar).mode & 0o777, 0o600);
    } catch (error) {
      assert.equal(error.code, "ENOENT");
    }
  }
  store.close();
  const reopened = openV2DirectStore({ path, ...initial });
  assert.deepEqual(reopened.canonicalState(), canonical(initial));
  reopened.close();
  assert.throws(
    () => openV2DirectStore({ path, ...initial, state: b(0xee, 128) }),
    /valid V2 genesis|binding/,
  );
  const nonempty = decodeStateNftCommitment(initial.state, stateContext);
  const nonemptyState = encodeStateNftCommitment({
    ...nonempty,
    noteRoot: fr(999n).toString("hex"),
    noteCount: "1",
    reserveSats: DENOMINATION_SATS,
    actionSequence: "1",
  }, stateContext);
  assert.throws(
    () => openV2DirectStore({
      path: join(directory, "nonempty", "pool.sqlite"),
      ...initial,
      state: nonemptyState,
      actionSequence: 1,
    }),
    /exact empty genesis/,
  );
});

test("opens an existing store only under its exact descriptor and runtime binding", (t) => {
  const { path, initial, store } = fixture(t);
  store.close();
  const {
    height: _height,
    blockHash: _blockHash,
    ...existing
  } = initial;
  const reopened = openExistingV2DirectStore({ path, ...existing });
  assert.deepEqual(reopened.canonicalState(), canonical(initial));
  assert.deepEqual(reopened.genesisAnchor(), canonical(initial));
  reopened.close();

  assert.throws(
    () => openExistingV2DirectStore({
      path,
      ...existing,
      instanceId: b(0xee),
    }),
    /binding/,
  );
  assert.throws(
    () => openExistingV2DirectStore({
      path,
      ...existing,
      outpoint: { txid: b(0xee), vout: 0 },
    }),
    /genesis/,
  );
});

test("rejects symlink traversal and terminal symlink targets on initial open and reopen", (t) => {
  const { directory, initial, store } = fixture(t);
  store.close();
  const real = join(directory, "real");
  mkdirSync(real);
  chmodSync(real, 0o700);
  const traversed = join(directory, "traversed");
  symlinkSync(real, traversed);
  assert.throws(
    () => openV2DirectStore({ path: join(traversed, "x.sqlite"), ...initial }),
    /traversal/,
  );
  const untrusted = join(directory, "untrusted");
  mkdirSync(untrusted);
  chmodSync(untrusted, 0o755);
  assert.throws(
    () => openV2DirectStore({ path: join(untrusted, "x.sqlite"), ...initial }),
    /0700/,
  );
  const target = join(real, "target.sqlite");
  openV2DirectStore({ path: target, ...initial }).close();
  const terminal = join(real, "terminal.sqlite");
  symlinkSync(target, terminal);
  assert.throws(
    () => openV2DirectStore({ path: terminal, ...initial }),
    /non-symlink regular file/,
  );
  // Reopen always repeats these checks; no Node path API can hold a parent FD across close/reopen.
});

test("schema v12 rejects legacy or incompatible stores before executing new DDL", (t) => {
  assert.equal(V2_STORE_SCHEMA_VERSION, 12);
  const directory = mkdtempSync(join(tmpdir(), "shieldkit-v2-legacy-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const parent = join(directory, "private");
  mkdirSync(parent, { mode: 0o700 });
  const path = join(parent, "pool.sqlite");
  const legacy = new DatabaseSync(path);
  legacy.exec(
    "CREATE TABLE metadata(singleton INTEGER PRIMARY KEY,schema_version INTEGER NOT NULL) STRICT; INSERT INTO metadata(singleton,schema_version) VALUES(1,6); PRAGMA user_version=6;",
  );
  legacy.close();
  chmodSync(path, 0o600);

  assert.throws(
    () => openV2DirectStore({ path, ...seed() }),
    /schema version 6.*required version 12.*automatic migration is not supported/,
  );
  const inspected = new DatabaseSync(path);
  assert.equal(
    inspected.prepare(
      "SELECT count(*) AS count FROM sqlite_schema WHERE type='table' AND name='operation_intents'",
    ).get().count,
    0,
  );
  assert.equal(
    inspected.prepare(
      "SELECT schema_version FROM metadata WHERE singleton=1",
    ).get().schema_version,
    6,
  );
  inspected.close();

  const partialParent = join(directory, "partial");
  mkdirSync(partialParent, { mode: 0o700 });
  const partialPath = join(partialParent, "pool.sqlite");
  const partial = new DatabaseSync(partialPath);
  partial.exec(
    "CREATE TABLE metadata(singleton INTEGER PRIMARY KEY,schema_version INTEGER NOT NULL) STRICT; INSERT INTO metadata(singleton,schema_version) VALUES(1,12); PRAGMA user_version=12;",
  );
  partial.close();
  chmodSync(partialPath, 0o600);
  assert.throws(
    () => openV2DirectStore({ path: partialPath, ...seed() }),
    /schema layout.*required version 12.*automatic migration is not supported/,
  );
  const partialAfter = new DatabaseSync(partialPath);
  assert.equal(
    partialAfter.prepare(
      "SELECT count(*) AS count FROM sqlite_schema WHERE type='table' AND name='operation_intents'",
    ).get().count,
    0,
  );
  partialAfter.close();

  const tamperedParent = join(directory, "tampered-trigger");
  mkdirSync(tamperedParent, { mode: 0o700 });
  const tamperedPath = join(tamperedParent, "pool.sqlite");
  openV2DirectStore({ path: tamperedPath, ...seed() }).close();
  const tampered = new DatabaseSync(tamperedPath);
  tampered.exec(
    "DROP TRIGGER immutable_operation_action_material; CREATE TRIGGER immutable_operation_action_material BEFORE UPDATE ON pending_operations BEGIN SELECT 1; END;",
  );
  tampered.close();
  chmodSync(tamperedPath, 0o600);
  assert.throws(
    () => openV2DirectStore({ path: tamperedPath, ...seed() }),
    /schema layout.*required version 12.*automatic migration is not supported/,
  );
});

test("runtime materials are reopen-bound, snapshot-bound, and immutable per operation", (t) => {
  const { initial, path, store } = fixture(t);
  assert.deepEqual(store.binding().runtimeMaterialsSha256, RUNTIME_MATERIALS_SHA256);
  assert.throws(
    () => store.assertBinding({
      ...store.binding(),
      runtimeMaterialsSha256: b(0x34),
    }),
    /store binding/,
  );
  const mismatch = operationRequest(
    "runtime-mismatch",
    "deposit",
    store.canonicalState(),
  );
  mismatch.runtimeMaterialsSha256 = b(0x34);
  assert.throws(
    () => store.createOperation(mismatch),
    /runtime materials do not match/,
  );

  const operation = create(store, "runtime-pinned", "deposit");
  assert.deepEqual(operation.runtimeMaterialsSha256, RUNTIME_MATERIALS_SHA256);
  store.close();

  const raw = new DatabaseSync(path);
  assert.throws(
    () => raw.prepare(
      "UPDATE metadata SET runtime_materials_sha256=? WHERE singleton=1",
    ).run(b(0x34)),
    /store runtime materials are immutable/,
  );
  assert.throws(
    () => raw.prepare(
      "UPDATE pending_operations SET runtime_materials_sha256=? WHERE operation_id=?",
    ).run(b(0x34), "runtime-pinned"),
    /operation runtime materials are immutable/,
  );
  raw.close();

  const reopened = openV2DirectStore({ path, ...initial });
  assert.deepEqual(
    reopened.operation("runtime-pinned").runtimeMaterialsSha256,
    RUNTIME_MATERIALS_SHA256,
  );
  reopened.close();
  assert.throws(
    () => openV2DirectStore({
      path,
      ...initial,
      runtimeMaterialsSha256: b(0x34),
    }),
    /store binding/,
  );
});

test("action and private record commitments are required, exact, immutable during ordinary transitions, and atomically rebase-bound", (t) => {
  const environment = fixture(t);
  const { initial, path } = environment;
  let store = environment.store;
  const expected = store.canonicalState();

  const missing = operationRequest(
    "action-material-missing",
    "deposit",
    expected,
  );
  delete missing.actionMaterialSha256;
  assert.throws(
    () => store.createOperation(missing),
    /missing or unknown properties/,
  );

  const privateMissing = operationRequest(
    "private-action-record-missing",
    "deposit",
    expected,
  );
  delete privateMissing.privateActionRecordSha256;
  assert.throws(
    () => store.createOperation(privateMissing),
    /missing or unknown properties/,
  );

  const short = operationRequest(
    "action-material-short",
    "deposit",
    expected,
  );
  short.actionMaterialSha256 = b(0xa6, 31);
  assert.throws(
    () => store.createOperation(short),
    /actionMaterialSha256 must contain exactly 32 bytes/,
  );

  const privateShort = operationRequest(
    "private-action-record-short",
    "deposit",
    expected,
  );
  privateShort.privateActionRecordSha256 = b(0xa9, 31);
  assert.throws(
    () => store.createOperation(privateShort),
    /privateActionRecordSha256 must contain exactly 32 bytes/,
  );

  const operationId = "action-material-pinned";
  const operation = create(store, operationId, "deposit", expected);
  store.putFundingUtxo({
    txid: operation.intent.funding.txid,
    vout: operation.intent.funding.vout,
    valueSats: operation.intent.funding.valueSats,
  });
  store.reserveResources({
    operationId,
    noteId: null,
    utxoTxid: operation.intent.funding.txid,
    utxoVout: operation.intent.funding.vout,
    crashAt: null,
  });
  store.transitionOperation({ operationId, to: "tip_synced", reason: null });
  store.close();

  const raw = new DatabaseSync(path);
  assert.throws(
    () => raw.prepare(
      "UPDATE pending_operations SET action_material_sha256=? WHERE operation_id=?",
    ).run(b(0xa7), operationId),
    /operation action material commitment is immutable outside explicit rebase/,
  );
  assert.throws(
    () => raw.prepare(
      "UPDATE pending_operations SET private_action_record_sha256=? WHERE operation_id=?",
    ).run(b(0xaa), operationId),
    /private action record commitment is immutable outside explicit rebase/,
  );
  raw.close();

  store = openV2DirectStore({ path, ...initial });
  assert.deepEqual(
    store.operation(operationId).actionMaterialSha256,
    b(0xa6),
  );
  assert.deepEqual(
    store.operation(operationId).privateActionRecordSha256,
    b(0xa9),
  );
  const liveTip = store.canonicalState();
  assert.throws(
    () => store.rebaseOperation({
      operationId,
      expectedState: liveTip.state,
      expectedOutpoint: liveTip.outpoint,
      expectedActionSequence: liveTip.actionSequence,
      expectedHeight: liveTip.height,
      expectedBlockHash: liveTip.blockHash,
      actionMaterialSha256: b(0xa7),
      privateActionRecordSha256: b(0xaa),
      crashAt: null,
    }),
    /requires needs_reproof or reorged/,
  );
  store.recordConflictAndMaybeRetry({
    operationId,
    reason: "replacement action material required",
    crashAt: null,
  });
  assert.throws(
    () => store.rebaseOperation({
      operationId,
      expectedState: liveTip.state,
      expectedOutpoint: liveTip.outpoint,
      expectedActionSequence: liveTip.actionSequence,
      expectedHeight: liveTip.height,
      expectedBlockHash: liveTip.blockHash,
      actionMaterialSha256: b(0xa7, 31),
      privateActionRecordSha256: b(0xaa),
      crashAt: null,
    }),
    /actionMaterialSha256 must contain exactly 32 bytes/,
  );
  assert.throws(
    () => store.rebaseOperation({
      operationId,
      expectedState: liveTip.state,
      expectedOutpoint: liveTip.outpoint,
      expectedActionSequence: liveTip.actionSequence,
      expectedHeight: liveTip.height,
      expectedBlockHash: liveTip.blockHash,
      actionMaterialSha256: b(0xa7),
      crashAt: null,
    }),
    /missing or unknown properties/,
  );
  assert.throws(
    () => store.rebaseOperation({
      operationId,
      expectedState: liveTip.state,
      expectedOutpoint: liveTip.outpoint,
      expectedActionSequence: liveTip.actionSequence,
      expectedHeight: liveTip.height,
      expectedBlockHash: liveTip.blockHash,
      actionMaterialSha256: b(0xa7),
      privateActionRecordSha256: b(0xaa, 31),
      crashAt: null,
    }),
    /privateActionRecordSha256 must contain exactly 32 bytes/,
  );
  const rebased = store.rebaseOperation({
    operationId,
    expectedState: liveTip.state,
    expectedOutpoint: liveTip.outpoint,
    expectedActionSequence: liveTip.actionSequence,
    expectedHeight: liveTip.height,
    expectedBlockHash: liveTip.blockHash,
    actionMaterialSha256: b(0xa7),
    privateActionRecordSha256: b(0xaa),
    crashAt: null,
  });
  assert.equal(rebased.journalState, "tip_synced");
  assert.deepEqual(rebased.actionMaterialSha256, b(0xa7));
  assert.deepEqual(rebased.privateActionRecordSha256, b(0xaa));

  store.recordConflictAndMaybeRetry({
    operationId,
    reason: "verify atomic rebase rollback",
    crashAt: null,
  });
  for (const crashAt of V2_OPERATION_REBASE_CRASH_STAGES) {
    assert.throws(
      () => store.rebaseOperation({
        operationId,
        expectedState: liveTip.state,
        expectedOutpoint: liveTip.outpoint,
        expectedActionSequence: liveTip.actionSequence,
        expectedHeight: liveTip.height,
        expectedBlockHash: liveTip.blockHash,
        actionMaterialSha256: b(0xa8),
        privateActionRecordSha256: b(0xab),
        crashAt,
      }),
      V2StoreCrashInjection,
    );
    const afterCrash = store.operation(operationId);
    assert.equal(afterCrash.journalState, "needs_reproof");
    assert.deepEqual(afterCrash.actionMaterialSha256, b(0xa7));
    assert.deepEqual(afterCrash.privateActionRecordSha256, b(0xaa));
    store.close();
    store = openV2DirectStore({ path, ...initial });
    const reopened = store.operation(operationId);
    assert.equal(reopened.journalState, "needs_reproof");
    assert.deepEqual(reopened.actionMaterialSha256, b(0xa7));
    assert.deepEqual(reopened.privateActionRecordSha256, b(0xaa));
  }
  store.close();
});

test("persists complete tree/frontier/nullifier and immutable record/UTXO APIs", (t) => {
  const { store } = fixture(t);
  store.putNoteNode({ depth: 2, nodeIndex: 3, nodeHash: b(1) });
  store.putNoteFrontier({ depth: 2, nodeHash: b(2) });
  store.putNullifierNode({ depth: 3, nodeIndex: 4, nodeHash: b(3) });
  store.putNullifierLeaf(nullifierLeaf({
    physicalIndex: 0,
    leafType: 1,
    key: b(0),
    successorIndex: 1,
    successorKey: b(0),
  }));
  store.putNullifierLeaf(nullifierLeaf({
    physicalIndex: 1,
    leafType: 3,
    key: b(0),
    successorIndex: 1,
    successorKey: b(0),
  }));
  assert.equal(store.normalKeyPredecessor({ key: fr(0n) }).physicalIndex, 0);
  store.putNullifierLeaf(nullifierLeaf({
    physicalIndex: 2,
    leafType: 2,
    key: fr(0n),
    successorIndex: 1,
    successorKey: b(0),
  }));
  store.putNullifierLeaf(nullifierLeaf({
    physicalIndex: 3,
    leafType: 2,
    key: fr(1n),
    successorIndex: 1,
    successorKey: b(0),
  }));
  assert.equal(store.normalKeyPredecessor({ key: fr(2n) }).physicalIndex, 3);
  assert.equal(
    store.normalKeyPredecessor({ key: fr(FR_MINUS_ONE) }).physicalIndex,
    3,
  );
  assert.throws(
    () => store.normalKeyPredecessor({ key: fr(0n) }),
    /already exists/,
  );
  assert.deepEqual(store.noteNode({ depth: 2, nodeIndex: 3 }), b(1));
  assert.deepEqual(store.noteFrontier({ depth: 2 }), b(2));
  assert.deepEqual(store.nullifierNode({ depth: 3, nodeIndex: 4 }), b(3));
  assert.equal(store.nullifierLeaf({ physicalIndex: 2 }).leafType, 2);
  assert.throws(
    () =>
      store.putNullifierLeaf({
        physicalIndex: 3,
        leafType: 1,
        leafHash: b(8),
        key: b(0),
        successorIndex: 1,
        successorKey: b(0),
      }),
    /sentinel ordering/,
  );
  assert.throws(
    () => store.putNoteNode({ depth: 32, nodeIndex: 1, nodeHash: b(9) }),
    /integer range/,
  );
  assert.throws(
    () =>
      store.putNullifierNode({ depth: 0, nodeIndex: 2 ** 32, nodeHash: b(9) }),
    /integer range/,
  );
  assert.throws(
    () => store.noteNode({ depth: 32, nodeIndex: 1 }),
    /integer range/,
  );
  assert.throws(
    () => store.putNoteFrontier({ depth: 32, nodeHash: b(9) }),
    /integer range/,
  );
  store.putEncryptedRecord({ recordId: "record", record: b(9, 128) });
  store.putEncryptedRecord({ recordId: "record", record: b(9, 128) });
  assert.throws(
    () => store.putEncryptedRecord({ recordId: "record", record: b(10, 128) }),
    /immutable/,
  );
  store.putFundingUtxo({ txid: b(11), vout: 0, valueSats: "4" });
  store.putFundingUtxo({ txid: b(11), vout: 0, valueSats: "4" });
  assert.throws(
    () => store.putFundingUtxo({ txid: b(11), vout: 0, valueSats: "5" }),
    /immutable/,
  );
  assert.throws(
    () => store.putFundingUtxo({ txid: b(12), vout: 0, valueSats: "0" }),
    /nonzero/,
  );
  assert.throws(
    () =>
      store.putFundingUtxo({
        txid: b(13),
        vout: 0,
        valueSats: "2100000000000001",
      }),
    /nonzero/,
  );
  assert.throws(
    () =>
      store.putNullifierLeaf({
        physicalIndex: 0,
        leafType: 1,
        leafHash: b(14),
        key: b(0),
        successorIndex: 2,
        successorKey: fr(FR_MINUS_ONE + 1n),
      }),
    /sentinel ordering/,
  );
});

test("deposit reserves only a funding UTXO; transfer/withdraw require one note and reject double reservation", (t) => {
  const { store } = fixture(t);
  const deposit = create(store, "deposit", "deposit");
  const depositFunding = deposit.intent.funding.txid;
  store.putFundingUtxo({
    txid: depositFunding,
    vout: 0,
    valueSats: deposit.intent.funding.valueSats,
  });
  store.reserveResources({
    operationId: "deposit",
    noteId: null,
    utxoTxid: depositFunding,
    utxoVout: 0,
    crashAt: null,
  });
  assert.equal(store.operation("deposit").journalState, "funding_selected");
  store.markConflict({ operationId: "deposit", reason: "tip conflict" });
  assert.equal(
    store.fundingUtxo({ txid: depositFunding, vout: 0 })
      .reservationOperationId,
    null,
  );
  const transfer = create(store, "transfer", "transfer", undefined, {
    selectedNoteId: "n",
  });
  const transferFunding = transfer.intent.funding.txid;
  store.putFundingUtxo({
    txid: transferFunding,
    vout: 0,
    valueSats: transfer.intent.funding.valueSats,
  });
  assert.throws(
    () =>
      store.reserveResources({
        operationId: "transfer",
        noteId: null,
        utxoTxid: transferFunding,
        utxoVout: 0,
        crashAt: null,
      }),
    /immutable operation intent/,
  );
  store.putEncryptedRecord({ recordId: "r", record: b(22, 128) });
  putTestOwnedNote(store, { noteId: "n", recordId: "r" });
  store.reserveResources({
    operationId: "transfer",
    noteId: "n",
    utxoTxid: transferFunding,
    utxoVout: 0,
    crashAt: null,
  });
  const withdrawal = create(store, "withdraw", "withdrawal", undefined, {
    selectedNoteId: "n",
  });
  const withdrawalFunding = withdrawal.intent.funding.txid;
  store.putFundingUtxo({
    txid: withdrawalFunding,
    vout: 0,
    valueSats: withdrawal.intent.funding.valueSats,
  });
  assert.throws(
    () =>
      store.reserveResources({
        operationId: "withdraw",
        noteId: "n",
        utxoTxid: withdrawalFunding,
        utxoVout: 0,
        crashAt: null,
      }),
    /unavailable/,
  );
});

test("operation creation and immutable intent are atomic, strict, secret-free, and durable across reopen", (t) => {
  const { path, initial, store } = fixture(t);
  const expected = store.canonicalState();
  for (const [index, crashAt] of V2_OPERATION_CREATE_CRASH_STAGES.entries()) {
    assert.throws(
      () =>
        create(store, `create-crash-${index}`, "deposit", expected, {
          crashAt,
        }),
      V2StoreCrashInjection,
    );
    assert.throws(
      () => store.operation(`create-crash-${index}`),
      /does not exist/,
    );
  }
  store.close();
  const reopened = openV2DirectStore({ path, ...initial });
  for (const index of V2_OPERATION_CREATE_CRASH_STAGES.keys()) {
    assert.throws(
      () => reopened.operation(`create-crash-${index}`),
      /does not exist/,
    );
  }

  const incomplete = operationRequest(
    "incomplete-intent",
    "deposit",
    expected,
  );
  incomplete.intent = {
    ...incomplete.intent,
    funding: { ...incomplete.intent.funding },
  };
  delete incomplete.intent.funding.rawSourceTransaction;
  assert.throws(
    () => reopened.createOperation(incomplete),
    /missing or unknown properties/,
  );
  const secretBearing = operationRequest(
    "secret-bearing-intent",
    "deposit",
    expected,
  );
  secretBearing.intent = {
    ...secretBearing.intent,
    spendSecret: b(0xee),
  };
  assert.throws(
    () => reopened.createOperation(secretBearing),
    /missing or unknown properties/,
  );

  const durable = create(reopened, "durable-intent", "deposit", expected);
  const expectedIntent = intentFixture({
    operationId: "durable-intent",
    kind: "deposit",
    selectedNoteId: null,
    fundingValueSats: "1",
  });
  assert.deepEqual(durable.intent, expectedIntent);
  durable.intent.target.bytes[0] ^= 0xff;
  durable.intent.funding.rawSourceTransaction[0] ^= 0xff;
  assert.deepEqual(reopened.operation("durable-intent").intent, expectedIntent);
  const schema = new DatabaseSync(path, { readOnly: true });
  const intentColumns = schema.prepare(
    "PRAGMA table_info(operation_intents)",
  ).all().map(({ name }) => name);
  assert.equal(
    intentColumns.some((name) => /secret|private/i.test(name)),
    false,
  );
  schema.close();
  const tamper = new DatabaseSync(path);
  assert.throws(
    () =>
      tamper.prepare(
        "UPDATE operation_intents SET target_bytes=? WHERE operation_id=?",
      ).run(Buffer.alloc(168), "durable-intent"),
    /operation intent is immutable/,
  );
  tamper.close();
  reopened.close();

  const reopenedAgain = openV2DirectStore({ path, ...initial });
  assert.deepEqual(
    reopenedAgain.operation("durable-intent").intent,
    expectedIntent,
  );
  assert.equal(reopenedAgain.operation("durable-intent").retryCount, 0);
  reopenedAgain.close();
});

test("prepareAction atomically creates the immutable intent and reserves both resources", (t) => {
  const { store } = fixture(t);
  const expected = store.canonicalState();
  for (
    const [index, crashAt] of V2_OPERATION_PREPARE_CRASH_STAGES.entries()
  ) {
    const operationId = `prepare-crash-${index}`;
    const noteId = `${operationId}-note`;
    const request = operationRequest(
      operationId,
      "transfer",
      expected,
      {
        selectedNoteId: noteId,
        fundingValueSats: "50000",
        crashAt,
      },
    );
    const recordId = `${operationId}-record`;
    store.putEncryptedRecord({ recordId, record: b(0x70 + index, 128) });
    putTestOwnedNote(store, { noteId, recordId });
    store.putFundingUtxo({
      txid: request.intent.funding.txid,
      vout: request.intent.funding.vout,
      valueSats: request.intent.funding.valueSats,
    });
    assert.throws(
      () => store.prepareAction(request),
      V2StoreCrashInjection,
    );
    assert.throws(() => store.operation(operationId), /does not exist/);
    assert.equal(
      store.ownedNote(noteId).reservationOperationId,
      null,
    );
    assert.equal(
      store.fundingUtxo({
        txid: request.intent.funding.txid,
        vout: request.intent.funding.vout,
      }).reservationOperationId,
      null,
    );
  }

  const operationId = "prepare-committed";
  const noteId = `${operationId}-note`;
  const request = operationRequest(
    operationId,
    "transfer",
    expected,
    {
      selectedNoteId: noteId,
      fundingValueSats: "50000",
      crashAt: null,
    },
  );
  const recordId = `${operationId}-record`;
  store.putEncryptedRecord({ recordId, record: b(0x7f, 128) });
  putTestOwnedNote(store, { noteId, recordId });
  store.putFundingUtxo({
    txid: request.intent.funding.txid,
    vout: request.intent.funding.vout,
    valueSats: request.intent.funding.valueSats,
  });
  const prepared = store.prepareAction(request);
  assert.equal(prepared.journalState, "funding_selected");
  assert.equal(
    store.ownedNote(noteId).reservationOperationId,
    operationId,
  );
  assert.equal(
    store.fundingUtxo({
      txid: request.intent.funding.txid,
      vout: request.intent.funding.vout,
    }).reservationOperationId,
    operationId,
  );
});

test("journal artifacts resume, reservation crashes rollback, and broadcast never changes canonical state", (t) => {
  const { initial, store } = fixture(t);
  const crashOperation = create(store, "crash", "deposit");
  const crashFunding = crashOperation.intent.funding.txid;
  store.putFundingUtxo({
    txid: crashFunding,
    vout: 0,
    valueSats: crashOperation.intent.funding.valueSats,
  });
  assert.throws(
    () =>
      store.reserveResources({
        operationId: "crash",
        noteId: null,
        utxoTxid: crashFunding,
        utxoVout: 0,
        crashAt: "reservation.after_utxo",
      }),
    V2StoreCrashInjection,
  );
  assert.equal(store.operation("crash").journalState, "draft");
  assert.equal(
    store.fundingUtxo({ txid: crashFunding, vout: 0 })
      .reservationOperationId,
    null,
  );
  const reproofOperation = create(store, "reproof", "deposit");
  const reproofFunding = reproofOperation.intent.funding.txid;
  store.putFundingUtxo({
    txid: reproofFunding,
    vout: 0,
    valueSats: reproofOperation.intent.funding.valueSats,
  });
  store.reserveResources({
    operationId: "reproof",
    noteId: null,
    utxoTxid: reproofFunding,
    utxoVout: 0,
    crashAt: null,
  });
  store.transitionOperation({
    operationId: "reproof",
    to: "tip_synced",
    reason: null,
  });
  store.transitionOperation({
    operationId: "reproof",
    to: "proving",
    reason: null,
  });
  store.updateOperationArtifacts({
    operationId: "reproof",
    packet: packetFixture(store, store.canonicalState(), "deposit", 1).packet,
    proof: b(2),
    unsignedTx: b(3),
    signedTx: null,
    localVmEvidence: null,
  });
  store.recordConflictAndMaybeRetry({
    operationId: "reproof",
    reason: "tip changed",
    crashAt: null,
  });
  assert.equal(store.operation("reproof").proof, null);
  assert.equal(
    store.fundingUtxo({ txid: reproofFunding, vout: 0 })
      .reservationOperationId,
    null,
  );
  const live = ready(store, "broadcast", "deposit", 31);
  assert.deepEqual(store.operation("broadcast").signedTx, live.signed);
  assert.deepEqual(store.canonicalState(), canonical(initial));
  assert.equal(live.noteId, null);
  assert.throws(
    () =>
      store.updateOperationArtifacts({
        operationId: "broadcast",
        packet: live.packet,
        proof: b(32),
        unsignedTx: b(33),
        signedTx: b(0xee),
        localVmEvidence: b(35),
      }),
    /immutable/,
  );
  create(store, "nonempty", "deposit");
  assert.throws(
    () =>
      store.createOperation({
        operationId: "nonempty-artifacts",
        kind: "deposit",
        expectedState: initial.state,
        expectedOutpoint: initial.outpoint,
        expectedActionSequence: 0,
        expectedHeight: initial.height,
        expectedBlockHash: initial.blockHash,
        runtimeMaterialsSha256: RUNTIME_MATERIALS_SHA256,
        actionMaterialSha256: b(0xa6),
        privateActionRecordSha256: b(0xa9),
        intent: intentFixture({
          operationId: "nonempty-artifacts",
          kind: "deposit",
          selectedNoteId: null,
          fundingValueSats: "1",
        }),
        packet: b(1, 552),
        proof: null,
        unsignedTx: null,
        signedTx: null,
        localVmEvidence: null,
        crashAt: null,
      }),
    /must be null/,
  );
});

test("signed-operation inspection rejects transaction, packet, token, payout, fee, and signature drift", (t) => {
  const cases = [
    {
      name: "signed-skeleton",
      kind: "deposit",
      transform: (transactions) => ({
        ...transactions,
        signed: mutateTransaction(transactions.signed, (transaction) => {
          transaction.outputs.at(-1).valueSatoshis -= 1n;
        }),
      }),
      pattern: /differ from the proved unsigned transaction/,
    },
    {
      name: "funding-outpoint",
      kind: "deposit",
      transform: (transactions) =>
        mutateBothTransactions(transactions, (transaction) => {
          transaction.inputs[CARRIER_COUNT + 2].outpointIndex = 1;
        }),
      pattern: /immutable intent outpoint/,
    },
    {
      name: "funding-sighash",
      kind: "deposit",
      transform: (transactions) => ({
        ...transactions,
        signed: mutateTransaction(transactions.signed, (transaction) => {
          const unlock = Buffer.from(
            transaction.inputs[CARRIER_COUNT + 2].unlockingBytecode,
          );
          unlock[65] = 0x41;
          transaction.inputs[CARRIER_COUNT + 2].unlockingBytecode = unlock;
        }),
      }),
      pattern: /sighash 0x61/,
    },
    {
      name: "funding-public-key",
      kind: "deposit",
      transform: (transactions) => ({
        ...transactions,
        signed: mutateTransaction(transactions.signed, (transaction) => {
          const unlock = Buffer.from(
            transaction.inputs[CARRIER_COUNT + 2].unlockingBytecode,
          );
          unlock[99] ^= 1;
          transaction.inputs[CARRIER_COUNT + 2].unlockingBytecode = unlock;
        }),
      }),
      pattern: /compressed public key/,
    },
    {
      name: "binding-packet",
      kind: "deposit",
      transform: (transactions) =>
        mutateBothTransactions(transactions, (transaction) => {
          const unlock = Buffer.from(
            transaction.inputs[CARRIER_COUNT].unlockingBytecode,
          );
          unlock[20] ^= 1;
          transaction.inputs[CARRIER_COUNT].unlockingBytecode = unlock;
        }),
      pattern: /persisted action packet/,
    },
    {
      name: "state-commitment",
      kind: "deposit",
      transform: (transactions) =>
        mutateBothTransactions(transactions, (transaction) => {
          const commitment = Buffer.from(
            transaction.outputs[0].token.nft.commitment,
          );
          commitment[127] ^= 1;
          transaction.outputs[0].token.nft.commitment = commitment;
        }),
      pattern: /post-state commitment/,
    },
    {
      name: "state-category",
      kind: "deposit",
      transform: (transactions) =>
        mutateBothTransactions(transactions, (transaction) => {
          const category = Buffer.from(transaction.outputs[0].token.category);
          category[0] ^= 1;
          transaction.outputs[0].token.category = category;
        }),
      pattern: /mutable instance NFT/,
    },
    {
      name: "change-lock",
      kind: "deposit",
      transform: (transactions) =>
        mutateBothTransactions(transactions, (transaction) => {
          transaction.outputs.at(-1).lockingBytecode =
            Uint8Array.from(WITHDRAWAL_LOCK);
        }),
      pattern: /immutable P2PKH lock/,
    },
    {
      name: "fee",
      kind: "deposit",
      transform: (transactions) =>
        mutateBothTransactions(transactions, (transaction) => {
          transaction.outputs.at(-1).valueSatoshis -= 1n;
        }),
      pattern: /fee must exactly match/,
    },
    {
      name: "output-count",
      kind: "deposit",
      transform: (transactions) =>
        mutateBothTransactions(transactions, (transaction) => {
          transaction.outputs.pop();
        }),
      pattern: /wrong action-specific output count/,
    },
    {
      name: "version",
      kind: "deposit",
      transform: (transactions) =>
        mutateBothTransactions(transactions, (transaction) => {
          transaction.version = 1;
        }),
      pattern: /version, locktime, or sequence/,
    },
    {
      name: "withdrawal-payout",
      kind: "withdrawal",
      transform: (transactions) =>
        mutateBothTransactions(transactions, (transaction) => {
          transaction.outputs[CARRIER_COUNT + 2].valueSatoshis -= 1n;
        }),
      pattern: /exact denomination/,
    },
  ];
  for (const [index, entry] of cases.entries()) {
    const environment = fixture(t);
    if (entry.kind === "withdrawal") {
      const bootstrap = ready(
        environment.store,
        `signed-drift-${entry.name}-bootstrap`,
        "deposit",
        0x70,
      );
      environment.store.applyConfirmed(confirmedArgs(
        environment.store,
        `signed-drift-${entry.name}-bootstrap`,
        bootstrap.expected,
        bootstrap.utxo,
        0x70,
      ));
    }
    const baseline = environment.store.canonicalState();
    const operationId = `signed-drift-${entry.name}`;
    const proved = ready(
      environment.store,
      operationId,
      entry.kind,
      0x80 + index,
      0x80 + index,
      {
        sign: false,
        transformTransactions: entry.transform,
      },
    );
    environment.store.updateOperationArtifacts({
      operationId,
      packet: proved.packet,
      proof: b(0x81 + index),
      unsignedTx: proved.unsigned,
      signedTx: proved.signed,
      localVmEvidence: b(0xa0 + index),
    });
    assert.throws(
      () => environment.store.transitionOperation({
        operationId,
        to: "signed",
        reason: null,
      }),
      entry.pattern,
      entry.name,
    );
    assert.equal(
      environment.store.operation(operationId).journalState,
      "proved",
    );
    assert.deepEqual(
      environment.store.canonicalState(),
      baseline,
    );
  }
});

test("generic transitions cannot forge confirmation or settlement, and confirmed settlement is exact, idempotent, and crash-safe", (t) => {
  const { store } = fixture(t);
  const signed = ready(
    store,
    "signed-no-abandon",
    "deposit",
    0x45,
    0x45,
    { broadcast: false },
  );
  assert.equal(store.operation("signed-no-abandon").journalState, "signed");
  assert.throws(
    () => store.abandonOperation({
      operationId: "signed-no-abandon",
      reason: "unsafe cancellation",
      crashAt: null,
    }),
    /cannot be abandoned/,
  );
  assert.equal(
    store.fundingUtxo({ txid: signed.utxo, vout: 0 })
      .reservationOperationId,
    "signed-no-abandon",
  );
  store.transitionOperation({
    operationId: "signed-no-abandon",
    to: "broadcast",
    reason: null,
  });
  assert.throws(
    () => store.transitionOperation({
      operationId: "signed-no-abandon",
      to: "confirmed",
      reason: null,
    }),
    /use applyConfirmed/,
  );
  assert.equal(
    store.operation("signed-no-abandon").journalState,
    "broadcast",
  );

  const confirmed = confirmedArgs(
    store,
    "signed-no-abandon",
    signed.expected,
    signed.utxo,
    0x45,
  );
  store.applyConfirmed(confirmed);
  assert.throws(
    () => store.transitionOperation({
      operationId: "signed-no-abandon",
      to: "settled",
      reason: null,
    }),
    /use settleConfirmedOperation/,
  );
  assert.equal(
    store.operation("signed-no-abandon").journalState,
    "confirmed",
  );
  assert.deepEqual(
    V2_OPERATION_SETTLE_CRASH_STAGES,
    ["settle.before_commit"],
  );
  assert.throws(
    () => store.settleConfirmedOperation({
      operationId: "signed-no-abandon",
      crashAt: "settle.before_commit",
    }),
    V2StoreCrashInjection,
  );
  assert.equal(
    store.operation("signed-no-abandon").journalState,
    "confirmed",
  );
  const settled = store.settleConfirmedOperation({
    operationId: "signed-no-abandon",
    crashAt: null,
  });
  assert.equal(settled.journalState, "settled");
  assert.equal(
    store.settleConfirmedOperation({
      operationId: "signed-no-abandon",
      crashAt: null,
    }).journalState,
    "settled",
  );
});

test("operation listing is strict, deterministic, and returns complete immutable intents", (t) => {
  const { store } = fixture(t);
  const first = create(store, "list-b", "deposit");
  const second = create(store, "list-a", "withdrawal", undefined, {
    selectedNoteId: "list-note",
    fundingValueSats: "50000",
  });
  assert.throws(
    () => store.listOperations({ states: [] }),
    /nonempty unique array/,
  );
  assert.throws(
    () => store.listOperations({ states: ["draft", "draft"] }),
    /nonempty unique array/,
  );
  assert.throws(
    () => store.listOperations({ states: ["unknown"] }),
    /nonempty unique array/,
  );
  const listed = store.listOperations({ states: ["draft"] });
  assert.deepEqual(
    listed.map((entry) => entry.operationId),
    ["list-a", "list-b"],
  );
  assert.deepEqual(
    listed.find((entry) => entry.operationId === "list-b").intent,
    first.intent,
  );
  assert.deepEqual(
    listed.find((entry) => entry.operationId === "list-a").intent,
    second.intent,
  );
  assert.equal(Object.isFrozen(listed), true);
});

test("automatic conflict retries rebase only to the exact live tip, preserve intent, and stop durably at three", (t) => {
  const environment = fixture(t);
  const { path, initial } = environment;
  let store = environment.store;
  assert.equal(V2_OPERATION_MAX_AUTOMATIC_CONFLICTS, 3);
  const operationId = "retry-cap";
  const noteId = "retry-cap-note";
  const expected = store.canonicalState();
  const operation = create(store, operationId, "transfer", expected, {
    selectedNoteId: noteId,
    fundingValueSats: "50000",
  });
  const intent = operation.intent;
  store.putEncryptedRecord({
    recordId: "retry-cap-record",
    record: b(0x51, 128),
  });
  putTestOwnedNote(store, { noteId, recordId: "retry-cap-record" });
  store.putFundingUtxo({
    txid: intent.funding.txid,
    vout: intent.funding.vout,
    valueSats: intent.funding.valueSats,
  });
  store.reserveResources({
    operationId,
    noteId,
    utxoTxid: intent.funding.txid,
    utxoVout: intent.funding.vout,
    crashAt: null,
  });
  store.transitionOperation({ operationId, to: "tip_synced", reason: null });
  store.transitionOperation({ operationId, to: "proving", reason: null });
  const packet = packetFixture(store, expected, "transfer", 0x51).packet;
  const transactions = operationTransactions({
    expected,
    operation,
    packet,
  });
  store.updateOperationArtifacts({
    operationId,
    packet,
    proof: b(0x52),
    unsignedTx: transactions.unsigned,
    signedTx: null,
    localVmEvidence: null,
  });
  store.transitionOperation({ operationId, to: "proved", reason: null });
  store.updateOperationArtifacts({
    operationId,
    packet,
    proof: b(0x52),
    unsignedTx: transactions.unsigned,
    signedTx: transactions.signed,
    localVmEvidence: b(0x55),
  });
  store.transitionOperation({ operationId, to: "signed", reason: null });
  assert.throws(
    () =>
      store.updateOperationArtifacts({
        operationId,
        packet,
        proof: b(0x52),
        unsignedTx: transactions.unsigned,
        signedTx: transactions.signed,
        localVmEvidence: b(0x55),
      }),
    /immutable after signing/,
  );
  assert.throws(
    () =>
      store.recordConflictAndMaybeRetry({
        operationId,
        reason: "injected conflict",
        crashAt: "conflict.after_counter",
      }),
    V2StoreCrashInjection,
  );
  store.close();
  store = openV2DirectStore({ path, ...initial });
  assert.equal(store.operation(operationId).retryCount, 0);
  assert.equal(store.operation(operationId).journalState, "signed");
  assert.notEqual(store.operation(operationId).signedTx, null);

  const advance = ready(store, "retry-cap-advance", "deposit", 0x60);
  store.applyConfirmed(
    confirmedArgs(
      store,
      "retry-cap-advance",
      advance.expected,
      advance.utxo,
      0x60,
    ),
  );
  const liveTip = store.canonicalState();
  let conflicted = store.recordConflictAndMaybeRetry({
    operationId,
    reason: "canonical tip changed",
    crashAt: null,
  });
  assert.equal(conflicted.journalState, "needs_reproof");
  assert.equal(conflicted.retryCount, 1);
  assert.equal(conflicted.packet, null);
  assert.deepEqual(conflicted.intent, intent);
  assert.equal(
    store.fundingUtxo({
      txid: intent.funding.txid,
      vout: intent.funding.vout,
    }).reservationOperationId,
    null,
  );
  assert.equal(store.ownedNote(noteId).reservationOperationId, null);
  assert.throws(
    () =>
      store.rebaseOperation({
        operationId,
        expectedState: expected.state,
        expectedOutpoint: expected.outpoint,
        expectedActionSequence: expected.actionSequence,
        expectedHeight: expected.height,
        expectedBlockHash: expected.blockHash,
        actionMaterialSha256: b(0xa7),
        privateActionRecordSha256: b(0xaa),
        crashAt: null,
      }),
    /exact current canonical tip/,
  );
  let rebased = store.rebaseOperation({
    operationId,
    expectedState: liveTip.state,
    expectedOutpoint: liveTip.outpoint,
    expectedActionSequence: liveTip.actionSequence,
    expectedHeight: liveTip.height,
    expectedBlockHash: liveTip.blockHash,
    actionMaterialSha256: b(0xa7),
    privateActionRecordSha256: b(0xaa),
    crashAt: null,
  });
  assert.equal(rebased.journalState, "tip_synced");
  assert.equal(rebased.expectedHeight, liveTip.height);
  assert.deepEqual(rebased.expectedBlockHash, liveTip.blockHash);
  assert.deepEqual(rebased.actionMaterialSha256, b(0xa7));
  assert.deepEqual(rebased.intent, intent);
  assert.equal(
    store.fundingUtxo({
      txid: intent.funding.txid,
      vout: intent.funding.vout,
    }).reservationOperationId,
    operationId,
  );
  assert.equal(store.ownedNote(noteId).reservationOperationId, operationId);

  conflicted = store.recordConflictAndMaybeRetry({
    operationId,
    reason: "second conflict",
    crashAt: null,
  });
  assert.equal(conflicted.journalState, "needs_reproof");
  assert.equal(conflicted.retryCount, 2);
  store.close();
  store = openV2DirectStore({ path, ...initial });
  assert.equal(store.operation(operationId).retryCount, 2);
  assert.equal(store.operation(operationId).journalState, "needs_reproof");
  rebased = store.rebaseOperation({
    operationId,
    expectedState: liveTip.state,
    expectedOutpoint: liveTip.outpoint,
    expectedActionSequence: liveTip.actionSequence,
    expectedHeight: liveTip.height,
    expectedBlockHash: liveTip.blockHash,
    actionMaterialSha256: b(0xa8),
    privateActionRecordSha256: b(0xab),
    crashAt: null,
  });
  assert.equal(rebased.retryCount, 2);
  assert.deepEqual(rebased.actionMaterialSha256, b(0xa8));

  conflicted = store.recordConflictAndMaybeRetry({
    operationId,
    reason: "third conflict",
    crashAt: null,
  });
  assert.equal(conflicted.journalState, "conflicted");
  assert.equal(conflicted.retryCount, 3);
  assert.deepEqual(conflicted.intent, intent);
  assert.equal(
    store.fundingUtxo({
      txid: intent.funding.txid,
      vout: intent.funding.vout,
    }).reservationOperationId,
    null,
  );
  assert.equal(store.ownedNote(noteId).reservationOperationId, null);
  store.close();
  store = openV2DirectStore({ path, ...initial });
  assert.equal(store.operation(operationId).retryCount, 3);
  assert.equal(store.operation(operationId).journalState, "conflicted");
  assert.throws(
    () =>
      store.recordConflictAndMaybeRetry({
        operationId,
        reason: "fourth conflict",
        crashAt: null,
      }),
    /current state/,
  );
  store.close();
});

test("manual retry is explicit, atomically clears conflicted residue, and rolls back every injected crash", (t) => {
  const environment = fixture(t);
  const { path, initial } = environment;
  let store = environment.store;
  const operationId = "manual-retry";
  const noteId = "manual-retry-input-note";
  const action = ready(store, operationId, "transfer", 0x80);
  const intent = store.operation(operationId).intent;

  assert.throws(
    () => store.authorizeManualRetry({ operationId, crashAt: null }),
    /manual retry requires a conflicted operation/,
  );

  const rebase = (actionByte, recordByte) => {
    const tip = store.canonicalState();
    return store.rebaseOperation({
      operationId,
      expectedState: tip.state,
      expectedOutpoint: tip.outpoint,
      expectedActionSequence: tip.actionSequence,
      expectedHeight: tip.height,
      expectedBlockHash: tip.blockHash,
      actionMaterialSha256: b(actionByte),
      privateActionRecordSha256: b(recordByte),
      crashAt: null,
    });
  };

  // Exhaust the automatic retry budget using real state transitions. The
  // final conflict is deliberately terminal until a user selects a retry.
  assert.equal(
    store.recordConflictAndMaybeRetry({
      operationId,
      reason: "first conflict",
      crashAt: null,
    }).journalState,
    "needs_reproof",
  );
  rebase(0xa7, 0xaa);
  assert.equal(
    store.recordConflictAndMaybeRetry({
      operationId,
      reason: "second conflict",
      crashAt: null,
    }).journalState,
    "needs_reproof",
  );
  rebase(0xa8, 0xab);
  const conflicted = store.recordConflictAndMaybeRetry({
    operationId,
    reason: "automatic retry limit exhausted",
    crashAt: null,
  });
  assert.equal(conflicted.journalState, "conflicted");
  assert.equal(conflicted.retryCount, V2_OPERATION_MAX_AUTOMATIC_CONFLICTS);
  assert.deepEqual(conflicted.intent, intent);
  assert.deepEqual(conflicted.actionMaterialSha256, b(0xa8));
  assert.deepEqual(conflicted.privateActionRecordSha256, b(0xab));
  assert.throws(
    () => store.transitionOperation({
      operationId,
      to: "needs_reproof",
      reason: null,
    }),
    /use recordConflictAndMaybeRetry to enter needs_reproof/,
  );
  assert.throws(
    () => rebase(0xac, 0xad),
    /operation rebase requires needs_reproof or reorged/,
  );

  // A prior build or interrupted persistence path can leave residue despite
  // the conflicted state. Seed valid-shape stale values directly, then prove
  // the production recovery boundary clears all of them transactionally.
  store.close();
  const raw = new DatabaseSync(path);
  raw.prepare(
    `UPDATE pending_operations SET packet_bytes=?,proof_bytes=?,
      unsigned_tx_bytes=?,signed_tx_bytes=?,local_vm_evidence=?
    WHERE operation_id=?`,
  ).run(
    b(0x90, 552),
    b(0x91),
    b(0x92),
    b(0x93),
    b(0x94),
    operationId,
  );
  raw.prepare(
    "INSERT INTO mempool_overlay(operation_id,overlay_bytes,created_at_ms) VALUES(?,?,?)",
  ).run(operationId, b(0x95), Date.now());
  raw.prepare(
    "UPDATE owned_notes SET reservation_operation_id=? WHERE note_id=?",
  ).run(operationId, noteId);
  raw.prepare(
    "UPDATE funding_utxos SET reservation_operation_id=? WHERE txid=? AND vout=?",
  ).run(operationId, intent.funding.txid, intent.funding.vout);
  raw.close();
  store = openV2DirectStore({ path, ...initial });

  const assertConflictBaseline = (candidate) => {
    const operation = candidate.operation(operationId);
    assert.equal(operation.journalState, "conflicted");
    assert.equal(operation.retryCount, V2_OPERATION_MAX_AUTOMATIC_CONFLICTS);
    assert.deepEqual(operation.intent, intent);
    assert.deepEqual(operation.actionMaterialSha256, b(0xa8));
    assert.deepEqual(operation.privateActionRecordSha256, b(0xab));
    for (const artifact of [
      "packet",
      "proof",
      "unsignedTx",
      "signedTx",
      "localVmEvidence",
    ]) assert.notEqual(operation[artifact], null, `${artifact} remains before retry`);
    assert.equal(candidate.ownedNote(noteId).reservationOperationId, operationId);
    assert.equal(
      candidate.fundingUtxo({
        txid: intent.funding.txid,
        vout: intent.funding.vout,
      }).reservationOperationId,
      operationId,
    );
    const overlay = new DatabaseSync(path, { readOnly: true });
    assert.equal(
      overlay.prepare(
        "SELECT count(*) AS count FROM mempool_overlay WHERE operation_id=?",
      ).get(operationId).count,
      1,
    );
    overlay.close();
  };
  assertConflictBaseline(store);

  for (const crashAt of V2_OPERATION_MANUAL_RETRY_CRASH_STAGES) {
    assert.throws(
      () => store.authorizeManualRetry({ operationId, crashAt }),
      V2StoreCrashInjection,
    );
    assertConflictBaseline(store);
    store.close();
    store = openV2DirectStore({ path, ...initial });
    assertConflictBaseline(store);
  }

  const retried = store.authorizeManualRetry({ operationId, crashAt: null });
  assert.equal(retried.journalState, "needs_reproof");
  assert.equal(retried.retryCount, 0);
  assert.deepEqual(retried.intent, intent);
  assert.deepEqual(retried.actionMaterialSha256, b(0xa8));
  assert.deepEqual(retried.privateActionRecordSha256, b(0xab));
  for (const artifact of [
    "packet",
    "proof",
    "unsignedTx",
    "signedTx",
    "localVmEvidence",
  ]) assert.equal(retried[artifact], null);
  assert.equal(store.ownedNote(noteId).reservationOperationId, null);
  assert.equal(
    store.fundingUtxo({
      txid: intent.funding.txid,
      vout: intent.funding.vout,
    }).reservationOperationId,
    null,
  );
  store.close();

  const reopened = openV2DirectStore({ path, ...initial });
  const durable = reopened.operation(operationId);
  assert.equal(durable.journalState, "needs_reproof");
  assert.equal(durable.retryCount, 0);
  assert.deepEqual(durable.intent, intent);
  assert.deepEqual(durable.actionMaterialSha256, b(0xa8));
  assert.deepEqual(durable.privateActionRecordSha256, b(0xab));
  for (const artifact of [
    "packet",
    "proof",
    "unsignedTx",
    "signedTx",
    "localVmEvidence",
  ]) assert.equal(durable[artifact], null);
  assert.equal(reopened.ownedNote(noteId).reservationOperationId, null);
  assert.equal(
    reopened.fundingUtxo({
      txid: intent.funding.txid,
      vout: intent.funding.vout,
    }).reservationOperationId,
    null,
  );
  const after = new DatabaseSync(path, { readOnly: true });
  assert.equal(
    after.prepare(
      "SELECT count(*) AS count FROM mempool_overlay WHERE operation_id=?",
    ).get(operationId).count,
    0,
  );
  after.close();
  reopened.close();
});

test("abandon releases exact reservations atomically and survives crash/reopen without intent drift", (t) => {
  const { path, initial, store } = fixture(t);
  const operationId = "abandon";
  const noteId = "abandon-note";
  const operation = create(store, operationId, "withdrawal", undefined, {
    selectedNoteId: noteId,
    fundingValueSats: "50000",
  });
  const intent = operation.intent;
  store.putEncryptedRecord({
    recordId: "abandon-record",
    record: b(0x71, 128),
  });
  putTestOwnedNote(store, { noteId, recordId: "abandon-record" });
  store.putFundingUtxo({
    txid: intent.funding.txid,
    vout: intent.funding.vout,
    valueSats: intent.funding.valueSats,
  });
  store.reserveResources({
    operationId,
    noteId,
    utxoTxid: intent.funding.txid,
    utxoVout: intent.funding.vout,
    crashAt: null,
  });
  assert.throws(
    () =>
      store.abandonOperation({
        operationId,
        reason: "user cancelled",
        crashAt: "abandon.after_reservations",
      }),
    V2StoreCrashInjection,
  );
  assert.equal(store.operation(operationId).journalState, "funding_selected");
  assert.equal(store.ownedNote(noteId).reservationOperationId, operationId);
  store.close();

  const reopened = openV2DirectStore({ path, ...initial });
  assert.equal(reopened.operation(operationId).journalState, "funding_selected");
  assert.deepEqual(reopened.operation(operationId).intent, intent);
  assert.equal(
    reopened.fundingUtxo({
      txid: intent.funding.txid,
      vout: intent.funding.vout,
    }).reservationOperationId,
    operationId,
  );
  const abandoned = reopened.abandonOperation({
    operationId,
    reason: "user cancelled",
    crashAt: null,
  });
  assert.equal(abandoned.journalState, "abandoned");
  assert.deepEqual(abandoned.intent, intent);
  assert.equal(reopened.ownedNote(noteId).reservationOperationId, null);
  assert.equal(
    reopened.fundingUtxo({
      txid: intent.funding.txid,
      vout: intent.funding.vout,
    }).reservationOperationId,
    null,
  );
  reopened.close();
});

test("rebase from reorg clears all stale artifacts and overlay atomically after reopen", (t) => {
  const { path, initial, store } = fixture(t);
  const action = ready(store, "rebase-reorg", "deposit", 0x72);
  const intent = store.operation("rebase-reorg").intent;
  store.recordMempoolOverlay({
    operationId: "rebase-reorg",
    overlay: b(0x73, 8),
  });
  store.applyConfirmed(
    confirmedArgs(
      store,
      "rebase-reorg",
      action.expected,
      action.utxo,
      0x72,
    ),
  );
  store.rollbackReorg({
    commonAncestorHeight: initial.height,
    commonAncestorBlockHash: initial.blockHash,
  });
  assert.equal(store.operation("rebase-reorg").journalState, "reorged");
  assert.throws(
    () =>
      store.rebaseOperation({
        operationId: "rebase-reorg",
        expectedState: initial.state,
        expectedOutpoint: initial.outpoint,
        expectedActionSequence: initial.actionSequence,
        expectedHeight: initial.height,
        expectedBlockHash: initial.blockHash,
        actionMaterialSha256: b(0xa7),
        privateActionRecordSha256: b(0xaa),
        crashAt: "rebase.after_artifacts",
      }),
    V2StoreCrashInjection,
  );
  assert.notEqual(store.operation("rebase-reorg").signedTx, null);
  assert.deepEqual(store.operation("rebase-reorg").actionMaterialSha256, b(0xa6));
  store.close();

  const reopened = openV2DirectStore({ path, ...initial });
  assert.equal(reopened.operation("rebase-reorg").journalState, "reorged");
  const before = new DatabaseSync(path, { readOnly: true });
  assert.equal(
    before.prepare(
      "SELECT count(*) AS count FROM mempool_overlay WHERE operation_id='rebase-reorg'",
    ).get().count,
    1,
  );
  before.close();
  const rebased = reopened.rebaseOperation({
    operationId: "rebase-reorg",
    expectedState: initial.state,
    expectedOutpoint: initial.outpoint,
    expectedActionSequence: initial.actionSequence,
    expectedHeight: initial.height,
    expectedBlockHash: initial.blockHash,
    actionMaterialSha256: b(0xa7),
    privateActionRecordSha256: b(0xaa),
    crashAt: null,
  });
  assert.equal(rebased.journalState, "tip_synced");
  assert.deepEqual(rebased.actionMaterialSha256, b(0xa7));
  assert.deepEqual(rebased.intent, intent);
  for (
    const artifact of
      ["packet", "proof", "unsignedTx", "signedTx", "localVmEvidence"]
  ) assert.equal(rebased[artifact], null);
  assert.equal(
    reopened.fundingUtxo({
      txid: intent.funding.txid,
      vout: intent.funding.vout,
    }).reservationOperationId,
    "rebase-reorg",
  );
  const after = new DatabaseSync(path, { readOnly: true });
  assert.equal(
    after.prepare(
      "SELECT count(*) AS count FROM mempool_overlay WHERE operation_id='rebase-reorg'",
    ).get().count,
    0,
  );
  after.close();
  reopened.close();
});

test("operation packets fail closed on bound identity, pre-state, kind, and transition drift", (t) => {
  const { store } = fixture(t);
  const expected = store.canonicalState();
  const valid = packetFixture(store, expected, "deposit", 90);
  const driftedPre = decodeStateNftCommitment(expected.state, stateContext);
  const driftedPreBytes = encodeStateNftCommitment({
    ...driftedPre,
    noteRoot: fr(12345n).toString("hex"),
  }, stateContext);
  const cases = [
    [
      "network",
      mutatePacket(valid.packet, (packet) => {
        packet.networkId = 1;
      }),
      /bound network/,
    ],
    [
      "instance",
      mutatePacket(valid.packet, (packet) => {
        packet.instanceId = b(0xee).toString("hex");
      }),
      /bound network/,
    ],
    [
      "kind",
      packetFixture(store, expected, "transfer", 91).packet,
      /action/,
    ],
    [
      "prestate",
      packetFixture(
        store,
        { ...expected, state: driftedPreBytes },
        "deposit",
        92,
      )
        .packet,
      /expected tip/,
    ],
    [
      "transition",
      mutatePacket(valid.packet, (packet) => {
        packet.postState = { ...packet.preState };
      }),
      /exact action state transition/,
    ],
  ];
  for (const [name, packet, pattern] of cases) {
    const operationId = `packet-drift-${name}`;
    const operation = create(store, operationId, "deposit", expected, {
      fundingValueSats: "50000",
    });
    const fundingTxid = operation.intent.funding.txid;
    store.putFundingUtxo({
      txid: fundingTxid,
      vout: 0,
      valueSats: operation.intent.funding.valueSats,
    });
    store.reserveResources({
      operationId,
      noteId: null,
      utxoTxid: fundingTxid,
      utxoVout: 0,
      crashAt: null,
    });
    store.transitionOperation({
      operationId,
      to: "tip_synced",
      reason: null,
    });
    store.transitionOperation({
      operationId,
      to: "proving",
      reason: null,
    });
    assert.throws(
      () => store.updateOperationArtifacts({
        operationId,
        packet,
        proof: b(1),
        unsignedTx: b(2),
        signedTx: null,
        localVmEvidence: null,
      }),
      pattern,
    );
    assert.equal(store.operation(operationId).packet, null);
  }
});

test("confirmed apply is all-or-nothing, rejects stale expected state, and applies complete local mutations", (t) => {
  const { initial, store } = fixture(t);
  const action = ready(store, "apply", "deposit", 40);
  const args = confirmedArgs(store, "apply", action.expected, action.utxo, 40, {
    crashAt: "confirmed.before_commit",
  });
  assert.throws(() => store.applyConfirmed(args), V2StoreCrashInjection);
  assert.deepEqual(store.canonicalState(), canonical(initial));
  assert.equal(store.noteNode({ depth: 0, nodeIndex: 0 }), null);
  assert.equal(store.noteLeaf({ noteIndex: 0 }), null);
  assert.equal(store.operation("apply").journalState, "broadcast");
  const zeroChange = confirmedArgs(
    store,
    "apply",
    action.expected,
    action.utxo,
    40,
  );
  zeroChange.funding.change[0].valueSats = "0";
  assert.throws(
    () => store.applyConfirmed(zeroChange),
    /nonzero canonical money/,
  );
  const mismatchedChange = confirmedArgs(
    store,
    "apply",
    action.expected,
    action.utxo,
    40,
  );
  mismatchedChange.funding.change[0].txid = b(0xef);
  assert.throws(
    () => store.applyConfirmed(mismatchedChange),
    /exact output of the persisted signed transaction/,
  );
  const mismatchedSuccessor = confirmedArgs(
    store,
    "apply",
    action.expected,
    action.utxo,
    40,
  );
  mismatchedSuccessor.next.outpoint.txid = b(0xed);
  assert.throws(
    () => store.applyConfirmed(mismatchedSuccessor),
    /exact persisted signed transaction/,
  );
  const mismatchedStateVout = confirmedArgs(
    store,
    "apply",
    action.expected,
    action.utxo,
    40,
  );
  mismatchedStateVout.next.outpoint.vout = 1;
  assert.throws(
    () => store.applyConfirmed(mismatchedStateVout),
    /output zero/,
  );
  const mismatchedFunding = confirmedArgs(
    store,
    "apply",
    action.expected,
    action.utxo,
    40,
  );
  mismatchedFunding.funding.spend.txid = b(0xec);
  assert.throws(
    () => store.applyConfirmed(mismatchedFunding),
    /immutable intent outpoint/,
  );
  const mismatchedChangeValue = confirmedArgs(
    store,
    "apply",
    action.expected,
    action.utxo,
    40,
  );
  mismatchedChangeValue.funding.change[0].valueSats = (
    BigInt(mismatchedChangeValue.funding.change[0].valueSats) - 1n
  ).toString();
  assert.throws(
    () => store.applyConfirmed(mismatchedChangeValue),
    /exact output of the persisted signed transaction/,
  );
  const stale = {
    ...confirmedArgs(store, "apply", action.expected, action.utxo, 40),
    expected: {
      ...confirmedArgs(store, "apply", action.expected, action.utxo, 40)
        .expected,
      state: b(0xee, 128),
    },
  };
  assert.throws(() => store.applyConfirmed(stale), /stale/);
  const divergentPacketState = confirmedArgs(
    store,
    "apply",
    action.expected,
    action.utxo,
    40,
  );
  const divergentDecoded = decodeStateNftCommitment(
    divergentPacketState.next.state,
    stateContext,
  );
  divergentPacketState.next.state = encodeStateNftCommitment({
    ...divergentDecoded,
    noteRoot: fr(54321n).toString("hex"),
  }, stateContext);
  assert.throws(
    () => store.applyConfirmed(divergentPacketState),
    /persisted action packet transition/,
  );
  const corruptedRoot = confirmedArgs(
    store,
    "apply",
    action.expected,
    action.utxo,
    40,
  );
  const expectedRoot = Buffer.from(
    decodeStateNftCommitment(action.expected.state, stateContext).noteRoot,
    "hex",
  );
  store.putNoteNode({
    depth: 32,
    nodeIndex: 0,
    nodeHash: fr(999999n),
  });
  assert.throws(
    () => store.applyConfirmed(corruptedRoot),
    /stored root/,
  );
  store.putNoteNode({ depth: 32, nodeIndex: 0, nodeHash: expectedRoot });
  const recordDrift = confirmedArgs(
    store,
    "apply",
    action.expected,
    action.utxo,
    40,
  );
  recordDrift.records[0].record = b(0xee, 128);
  assert.throws(
    () => store.applyConfirmed(recordDrift),
    /exact encrypted record/,
  );
  const applied = store.applyConfirmed(
    confirmedArgs(store, "apply", action.expected, action.utxo, 40),
  );
  assert.equal(applied.actionSequence, 1);
  assert.equal(store.operation("apply").journalState, "confirmed");
  assert.equal(store.fundingUtxo({ txid: action.utxo, vout: 0 }).spent, true);
  assert.equal(store.ownedNote("apply-output-note").spent, false);
  assert.deepEqual(
    store.encryptedRecord("apply-output-record"),
    action.encryptedRecord,
  );
  assert.deepEqual(
    store.noteLeaf({ noteIndex: 0 }),
    {
      noteIndex: 0,
      leafHash: Buffer.from(action.decoded.outputNoteLeaf, "hex"),
      encryptedRecord: action.encryptedRecord,
      actionSequence: 1,
      transactionId: applied.outpoint.txid,
    },
  );
});

test("persistent proving derivation feeds the circuit ABI without rebuilding history", (t) => {
  const { store } = fixture(t);
  const expected = store.canonicalState();
  const operationId = "persistent-deposit";
  const operation = create(store, operationId, "deposit", expected, {
    fundingValueSats: "10200000",
  });
  store.putFundingUtxo({
    txid: operation.intent.funding.txid,
    vout: operation.intent.funding.vout,
    valueSats: operation.intent.funding.valueSats,
  });
  store.reserveResources({
    operationId,
    noteId: null,
    utxoTxid: operation.intent.funding.txid,
    utxoVout: operation.intent.funding.vout,
    crashAt: null,
  });
  for (const to of ["tip_synced", "proving"]) {
    store.transitionOperation({ operationId, to, reason: null });
  }
  const output = constructDirectV2Output({
    address: RECIPIENT_ADDRESS,
    postActionSequence: "1",
    rng: scalarRng(5),
  });
  const transition = store.deriveProvingTransition({
    operationId,
    outputNoteLeaf: Buffer.from(output.public.outputNoteLeaf, "hex"),
    encryptedRecord: output.public.encryptedRecord,
    publicNullifier: null,
    transactionContextHash: b(0x31),
  });
  assert.equal(transition.schema, V2_PROVING_TRANSITION_SCHEMA);
  assert.deepEqual(transition.expectedTip, expected);
  assert.equal(transition.packet.length, 552);
  assert.equal(transition.witness.note.emptyAppendPath.length, 32);
  assert.equal(transition.witness.note.membershipPath.length, 32);
  assert.equal(transition.witness.nullifier, undefined);
  assert.equal(transition.witness.spend, undefined);
  assert.deepEqual(store.canonicalState(), expected);
  const circuitInput = buildDirectV2CircuitInput({
    denominationSats: DENOMINATION_SATS,
    transition,
    output,
  });
  assert.equal(circuitInput.packet.length, 552);
  assert.equal(circuitInput.noteAppendSiblings.length, 32);
  assert.equal(circuitInput.nullifierPredecessorType, "0");
  assert.equal(circuitInput.spendSk, "0");
});

test("persistent proving derivation reads fixed-depth spend and indexed-nullifier paths", (t) => {
  const { store } = fixture(t);
  const deposited = ready(store, "persistent-input", "deposit", 60);
  store.applyConfirmed(
    confirmedArgs(
      store,
      "persistent-input",
      deposited.expected,
      deposited.utxo,
      60,
    ),
  );
  const expected = store.canonicalState();
  const operationId = "persistent-transfer";
  const selectedNoteId = "persistent-input-output-note";
  const operation = create(store, operationId, "transfer", expected, {
    selectedNoteId,
    fundingValueSats: "200000",
  });
  store.putFundingUtxo({
    txid: operation.intent.funding.txid,
    vout: operation.intent.funding.vout,
    valueSats: operation.intent.funding.valueSats,
  });
  store.reserveResources({
    operationId,
    noteId: selectedNoteId,
    utxoTxid: operation.intent.funding.txid,
    utxoVout: operation.intent.funding.vout,
    crashAt: null,
  });
  const request = {
    operationId,
    outputNoteLeaf: fr(999n),
    encryptedRecord: b(0x62, 128),
    publicNullifier: testNoteNullifier(selectedNoteId),
    transactionContextHash: b(0x63),
  };
  assert.throws(
    () => store.deriveProvingTransition(request),
    /operation in proving state/,
  );
  for (const to of ["tip_synced", "proving"]) {
    store.transitionOperation({ operationId, to, reason: null });
  }
  const transition = store.deriveProvingTransition(request);
  assert.deepEqual(store.canonicalState(), expected);
  assert.equal(transition.state.noteCount, "2");
  assert.equal(transition.state.nullifierCount, "1");
  assert.equal(transition.state.actionSequence, "2");
  assert.equal(transition.witness.spend.noteIndex, 0n);
  assert.equal(
    transition.witness.spend.inputNoteLeaf,
    deposited.decoded.outputNoteLeaf,
  );
  assert.deepEqual(
    transition.witness.spend.encryptedRecord,
    deposited.encryptedRecord,
  );
  assert.equal(transition.witness.spend.noteMembershipPath.length, 32);
  assert.equal(transition.witness.note.emptyAppendPath.length, 32);
  assert.equal(transition.witness.nullifier.predecessorPath.length, 32);
  assert.equal(transition.witness.nullifier.append.path.length, 32);
  assert.equal(transition.witness.nullifier.predecessor.type, "min");
  const independentlyDerived = store.derivePacketPostState({
    kind: "transfer",
    publicNullifier: request.publicNullifier,
    outputNoteLeaf: request.outputNoteLeaf,
  });
  assert.deepEqual(independentlyDerived.state, transition.state);
  assert.throws(
    () => store.deriveProvingTransition({
      ...request,
      publicNullifier: fr(778n),
    }),
    /requested persistent note leaf/,
  );
});

test("confirmed transfer and withdrawal apply their exact one-action mutation shapes", (t) => {
  const { initial, store } = fixture(t);
  let reference = createDirectV2PoolModel({
    profileId: PROFILE_ID.toString("hex"),
    maximumLiveNotes: "210000000",
    denominationSats: DENOMINATION_SATS,
  });
  const deposit = ready(store, "deposit-before-transfer", "deposit", 60);
  reference = advanceReference(reference, deposit);
  assert.deepEqual(
    encodeStateNftCommitment(reference.state, stateContext),
    deposit.postState,
  );
  store.applyConfirmed(
    confirmedArgs(
      store,
      "deposit-before-transfer",
      deposit.expected,
      deposit.utxo,
      60,
    ),
  );
  const transfer = ready(store, "transfer-apply", "transfer", 70);
  reference = advanceReference(reference, transfer, {
    inputNoteLeaf: deposit.decoded.outputNoteLeaf,
    noteIndex: 0,
  });
  assert.deepEqual(
    encodeStateNftCommitment(reference.state, stateContext),
    transfer.postState,
  );
  const transferArgs = confirmedArgs(
    store,
    "transfer-apply",
    transfer.expected,
    transfer.utxo,
    70,
    { kind: "transfer", noteId: transfer.noteId },
  );
  const expectedNullifierRoot = Buffer.from(
    decodeStateNftCommitment(transfer.expected.state, stateContext)
      .nullifierRoot,
    "hex",
  );
  store.putNullifierNode({
    depth: 32,
    nodeIndex: 0,
    nodeHash: fr(888888n),
  });
  assert.throws(
    () => store.applyConfirmed(transferArgs),
    /stored root/,
  );
  store.putNullifierNode({
    depth: 32,
    nodeIndex: 0,
    nodeHash: expectedNullifierRoot,
  });
  const transferResult = store.applyConfirmed(
    transferArgs,
  );
  assert.equal(store.ownedNote(transfer.noteId).spent, true);
  assert.equal(store.ownedNote("transfer-apply-output-note").spent, false);
  assert.deepEqual(
    store.noteLeaf({ noteIndex: 1 }).leafHash,
    Buffer.from(transfer.decoded.outputNoteLeaf, "hex"),
  );
  assert.throws(
    () => ready(store, "duplicate-nullifier", "transfer", 70, 170),
    /nullifier already exists/,
  );
  const withdrawal = ready(store, "withdrawal-apply", "withdrawal", 80);
  reference = advanceReference(reference, withdrawal, {
    inputNoteLeaf: transfer.decoded.outputNoteLeaf,
    noteIndex: 1,
  });
  assert.deepEqual(
    encodeStateNftCommitment(reference.state, stateContext),
    withdrawal.postState,
  );
  assert.deepEqual(withdrawal.expected, transferResult);
  store.applyConfirmed(
    confirmedArgs(
      store,
      "withdrawal-apply",
      withdrawal.expected,
      withdrawal.utxo,
      80,
      {
        kind: "withdrawal",
        noteId: withdrawal.noteId,
        height: 102,
      },
    ),
  );
  assert.equal(store.ownedNote(withdrawal.noteId).spent, true);
  assert.equal(store.encryptedRecord("withdrawal-apply-output-record"), null);
  assert.deepEqual(
    store.canonicalState().state,
    encodeStateNftCommitment(reference.state, stateContext),
  );
  const restored = store.rollbackReorg({
    commonAncestorHeight: initial.height,
    commonAncestorBlockHash: initial.blockHash,
  });
  assert.deepEqual(restored, canonical(initial));
  assert.deepEqual(
    store.noteNode({ depth: 32, nodeIndex: 0 }),
    Buffer.from(
      decodeStateNftCommitment(initial.state, stateContext).noteRoot,
      "hex",
    ),
  );
  assert.equal(
    store.normalKeyPredecessor({ key: fr(71n) }).physicalIndex,
    0,
  );
  assert.equal(store.noteLeaf({ noteIndex: 0 }), null);
  assert.equal(store.noteLeaf({ noteIndex: 1 }), null);
});

test("reverse-order reorg rolls back multiple serial same-block actions and persists after reopen", (t) => {
  const { path, initial, store } = fixture(t);
  const block = b(90);
  const one = ready(store, "one", "deposit", 50);
  const first = store.applyConfirmed(
    confirmedArgs(store, "one", one.expected, one.utxo, 50, {
      height: 101,
      blockHash: block,
    }),
  );
  const two = ready(store, "two", "deposit", 60);
  assert.deepEqual(two.expected, first);
  store.applyConfirmed(
    confirmedArgs(store, "two", two.expected, two.utxo, 60, {
      height: 101,
      blockHash: block,
    }),
  );
  assert.equal(store.canonicalState().actionSequence, 2);
  store.close();
  const reopened = openV2DirectStore({ path, ...initial });
  assert.equal(reopened.canonicalState().actionSequence, 2);
  assert.throws(
    () =>
      reopened.rollbackReorg({
        commonAncestorHeight: 100,
        commonAncestorBlockHash: b(0xee),
      }),
    /common ancestor/,
  );
  const restored = reopened.rollbackReorg({
    commonAncestorHeight: 100,
    commonAncestorBlockHash: initial.blockHash,
  });
  assert.deepEqual(restored, canonical(initial));
  assert.equal(reopened.noteLeaf({ noteIndex: 0 }), null);
  assert.equal(reopened.noteLeaf({ noteIndex: 1 }), null);
  assert.equal(reopened.encryptedRecord("one-output-record"), null);
  assert.equal(reopened.operation("one").journalState, "reorged");
  assert.equal(reopened.operation("two").journalState, "reorged");
  assert.equal(
    reopened.fundingUtxo({ txid: one.utxo, vout: 0 }).reservationOperationId,
    "one",
  );
  reopened.close();
});

test("row-level undo stays linear over hundreds of actions and leaves unrelated rows alone on rollback", (t) => {
  const { initial, store } = fixture(t);
  const block = b(0xa1);
  store.putNoteNode({
    depth: 0,
    nodeIndex: 0xffff_ffff,
    nodeHash: fr(0xa2n),
  });
  for (let index = 0; index < 160; index += 1) {
    const operationId = `linear-${index}`;
    const action = ready(store, operationId, "deposit", index + 1);
    store.applyConfirmed(
      confirmedArgs(
        store,
        operationId,
        action.expected,
        action.utxo,
        index + 1,
        {
        height: 200,
        blockHash: block,
        },
      ),
    );
  }
  const stats = store.undoStatistics();
  assert.equal(stats.count, 160);
  assert.ok(
    stats.bytes < stats.count * 10_000,
    `row delta average unexpectedly large: ${stats.bytes / stats.count}`,
  );
  store.rollbackReorg({
    commonAncestorHeight: 100,
    commonAncestorBlockHash: initial.blockHash,
  });
  assert.deepEqual(
    store.noteNode({ depth: 0, nodeIndex: 0xffff_ffff }),
    fr(0xa2n),
  );
  assert.deepEqual(store.canonicalState(), canonical(initial));
});

test("installs externally authenticated terminal material atomically and reopens the exact checkpoint", (t) => {
  const { initial, snapshot } = populatedAuthenticatedSnapshot(t);
  const target = fixture(t);
  target.store.putNoteNode({
    depth: 0,
    nodeIndex: 50,
    nodeHash: fr(0x501n),
  });
  target.store.putNoteFrontier({ depth: 7, nodeHash: fr(0x502n) });
  target.store.putNullifierNode({
    depth: 0,
    nodeIndex: 50,
    nodeHash: fr(0x503n),
  });

  const installed = target.store.installAuthenticatedSnapshot(snapshot);
  assert.deepEqual(installed.canonical, snapshot.canonical);
  assert.deepEqual(installed.note, {
    nodeCount: snapshot.noteNodes.length,
    frontierCount: snapshot.noteFrontier.length,
    leafCount: snapshot.noteLeaves.length,
    root: Buffer.from(
      decodeStateNftCommitment(snapshot.canonical.state, stateContext).noteRoot,
      "hex",
    ),
  });
  assert.deepEqual(installed.nullifier, {
    nodeCount: snapshot.nullifierNodes.length,
    leafCount: snapshot.nullifierLeaves.length,
    orderKeyCount: snapshot.nullifierLeaves.length,
    root: Buffer.from(
      decodeStateNftCommitment(
        snapshot.canonical.state,
        stateContext,
      ).nullifierRoot,
      "hex",
    ),
  });
  assert.equal(target.store.noteNode({ depth: 0, nodeIndex: 50 }), null);
  assert.equal(target.store.noteFrontier({ depth: 7 }), null);
  assert.equal(target.store.nullifierNode({ depth: 0, nodeIndex: 50 }), null);
  assert.deepEqual(target.store.noteLeaf({ noteIndex: 2 }), snapshot.noteLeaves[2]);
  assert.deepEqual(
    target.store.nullifierLeaf({ physicalIndex: 2 }),
    snapshot.nullifierLeaves[2],
  );
  assert.equal(
    target.store.normalKeyPredecessor({ key: fr(1000n) }).physicalIndex,
    2,
  );

  target.store.close();
  const reopened = openV2DirectStore({ path: target.path, ...initial });
  assert.deepEqual(reopened.canonicalState(), snapshot.canonical);
  assert.deepEqual(
    reopened.noteNode({ depth: 32, nodeIndex: 0 }),
    installed.note.root,
  );
  assert.deepEqual(
    reopened.nullifierNode({ depth: 32, nodeIndex: 0 }),
    installed.nullifier.root,
  );
  assert.deepEqual(reopened.noteLeaf({ noteIndex: 0 }), snapshot.noteLeaves[0]);
  reopened.close();
});

test("installs an exact empty-tree genesis snapshot with only the note root node", (t) => {
  const source = fixture(t);
  const snapshot = authenticatedSnapshotFromStore(source.store);
  source.store.close();
  assert.deepEqual(snapshot.noteNodes.map(({ depth, nodeIndex }) => ({
    depth,
    nodeIndex,
  })), [{ depth: 32, nodeIndex: 0 }]);
  assert.deepEqual(snapshot.noteFrontier, []);
  assert.deepEqual(snapshot.noteLeaves, []);
  assert.equal(snapshot.canonical.actionSequence, 0);

  const target = fixture(t);
  const installed = target.store.installAuthenticatedSnapshot(snapshot);
  assert.deepEqual(installed.note, {
    nodeCount: 1,
    frontierCount: 0,
    leafCount: 0,
    root: snapshot.noteNodes[0].nodeHash,
  });
  assert.equal(installed.nullifier.leafCount, 2);
  assert.equal(installed.nullifier.orderKeyCount, 2);
});

test("authenticated snapshot rejects malformed material and active local state before mutation", (t) => {
  const { snapshot } = populatedAuthenticatedSnapshot(t);
  const { store } = fixture(t);
  const original = store.canonicalState();
  const attempt = (change, pattern) => {
    assert.throws(
      () => store.installAuthenticatedSnapshot(change(snapshot)),
      pattern,
    );
    assert.deepEqual(store.canonicalState(), original);
    assert.equal(store.noteLeaf({ noteIndex: 0 }), null);
    assert.equal(store.nullifierLeaf({ physicalIndex: 2 }), null);
  };

  attempt(
    (value) => ({ ...value, unknown: true }),
    /missing or unknown properties/,
  );
  attempt(
    (value) => ({
      ...value,
      binding: { ...value.binding, instanceId: b(0xee) },
    }),
    /store binding/,
  );
  attempt(
    (value) => ({
      ...value,
      binding: { ...value.binding, runtimeMaterialsSha256: b(0xee) },
    }),
    /store binding/,
  );
  attempt(
    (value) => ({
      ...value,
      noteLeaves: value.noteLeaves.slice(0, -1),
    }),
    /note leaves differ/,
  );
  attempt(
    (value) => ({
      ...value,
      noteNodes: value.noteNodes.map((node) =>
        node.depth === 32
          ? { ...node, nodeHash: fr(123456n) }
          : node
      ),
    }),
    /terminal root node/,
  );
  attempt(
    (value) => ({
      ...value,
      noteFrontier: value.noteFrontier.map((entry, index) =>
        index === 0 ? { ...entry, nodeHash: fr(654321n) } : entry
      ),
    }),
    /frontier differs/,
  );
  attempt(
    (value) => ({
      ...value,
      noteNodes: value.noteNodes.map((node, index) =>
        index === 0
          ? { ...node, nodeHash: fr(FR_MINUS_ONE + 1n) }
          : node
      ),
    }),
    /canonical BN254 Fr/,
  );
  attempt(
    (value) => ({
      ...value,
      canonical: {
        ...value.canonical,
        actionSequence: value.canonical.actionSequence + 1,
      },
    }),
    /actionSequence differs/,
  );
  attempt(
    (value) => {
      const minimum = value.nullifierLeaves.find((leaf) =>
        leaf.physicalIndex === 0
      );
      const changed = nullifierLeaf({
        physicalIndex: 0,
        leafType: 1,
        key: b(0),
        successorIndex: 1,
        successorKey: b(0),
      });
      return {
        ...value,
        nullifierLeaves: value.nullifierLeaves.map((leaf) =>
          leaf === minimum ? changed : leaf
        ),
      };
    },
    /successor chain/,
  );

  create(store, "snapshot-blocker", "deposit");
  assert.throws(
    () => store.installAuthenticatedSnapshot(snapshot),
    /pending operations, reservations, or mempool overlay/,
  );
  assert.deepEqual(store.canonicalState(), original);

  const reserved = fixture(t).store;
  const blocker = create(reserved, "snapshot-reservation", "deposit");
  const blockerFunding = blocker.intent.funding.txid;
  reserved.putFundingUtxo({
    txid: blockerFunding,
    vout: 0,
    valueSats: blocker.intent.funding.valueSats,
  });
  reserved.reserveResources({
    operationId: "snapshot-reservation",
    noteId: null,
    utxoTxid: blockerFunding,
    utxoVout: 0,
    crashAt: null,
  });
  assert.throws(
    () => reserved.installAuthenticatedSnapshot(snapshot),
    /pending operations, reservations, or mempool overlay/,
  );

  const overlay = fixture(t).store;
  ready(overlay, "snapshot-overlay", "deposit", 0xa2);
  overlay.recordMempoolOverlay({
    operationId: "snapshot-overlay",
    overlay: b(0xa3, 4),
  });
  assert.throws(
    () => overlay.installAuthenticatedSnapshot(snapshot),
    /pending operations, reservations, or mempool overlay/,
  );
});

test("every authenticated snapshot crash stage rolls back and remains consistent after reopen", (t) => {
  const { initial, snapshot } = populatedAuthenticatedSnapshot(t);
  const directory = mkdtempSync(join(tmpdir(), "shieldkit-v2-snapshot-crash-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (
    const [index, crashAt] of
      V2_AUTHENTICATED_SNAPSHOT_CRASH_STAGES.entries()
  ) {
    const path = join(directory, `stage-${index}`, "pool.sqlite");
    const store = openV2DirectStore({ path, ...initial });
    const marker = fr(BigInt(0x700 + index));
    store.putNoteNode({ depth: 0, nodeIndex: 90, nodeHash: marker });
    assert.throws(
      () =>
        store.installAuthenticatedSnapshot({
          ...snapshot,
          crashAt,
        }),
      (error) =>
        error instanceof V2StoreCrashInjection &&
        error.message.includes(crashAt),
    );
    assert.deepEqual(store.canonicalState(), canonical(initial));
    assert.deepEqual(
      store.noteNode({ depth: 0, nodeIndex: 90 }),
      marker,
      crashAt,
    );
    assert.equal(store.noteLeaf({ noteIndex: 0 }), null, crashAt);
    assert.equal(store.nullifierLeaf({ physicalIndex: 2 }), null, crashAt);
    store.close();

    const reopened = openV2DirectStore({ path, ...initial });
    assert.deepEqual(reopened.canonicalState(), canonical(initial), crashAt);
    assert.deepEqual(
      reopened.noteNode({ depth: 0, nodeIndex: 90 }),
      marker,
      crashAt,
    );
    assert.equal(reopened.noteLeaf({ noteIndex: 0 }), null, crashAt);
    assert.equal(reopened.nullifierLeaf({ physicalIndex: 2 }), null, crashAt);
    reopened.close();
  }
});

test("authenticated funding reconciliation binds the exact canonical tip and preserves inventory on invalid input", (t) => {
  const { store } = fixture(t);
  const tip = store.canonicalState();
  const priorInventory = [
    { txid: b(0xd1), vout: 3, valueSats: "101" },
    { txid: b(0xd2), vout: 4, valueSats: "202" },
  ];
  const replacement = [
    { txid: b(0xe2), vout: 2, valueSats: "404" },
    { txid: b(0xe1), vout: 1, valueSats: "303" },
  ];
  for (const entry of priorInventory) store.putFundingUtxo(entry);

  const assertPriorInventory = () => {
    for (const entry of priorInventory) {
      assert.deepEqual(
        store.fundingUtxo({ txid: entry.txid, vout: entry.vout }),
        {
          valueSats: entry.valueSats,
          reservationOperationId: null,
          spent: false,
        },
      );
    }
    for (const entry of replacement) {
      assert.equal(
        store.fundingUtxo({ txid: entry.txid, vout: entry.vout }),
        null,
      );
    }
  };
  const attempt = (canonical, fundingInventory, pattern) => {
    assert.throws(
      () => store.reconcileAuthenticatedFundingInventory({
        canonical,
        fundingInventory,
      }),
      pattern,
    );
    assert.deepEqual(store.canonicalState(), tip);
    assertPriorInventory();
  };

  for (const canonical of [
    { ...tip, state: b(0xef, 128) },
    { ...tip, outpoint: { ...tip.outpoint, vout: tip.outpoint.vout + 1 } },
    { ...tip, actionSequence: tip.actionSequence + 1 },
    { ...tip, height: tip.height + 1 },
    { ...tip, blockHash: b(0xee) },
  ]) {
    attempt(
      canonical,
      replacement,
      /exact durable canonical tip/,
    );
  }
  attempt(
    tip,
    [{ txid: b(0xe3), vout: 0, valueSats: "01" }],
    /canonical money/,
  );
  attempt(
    tip,
    [
      { txid: b(0xe4), vout: 0, valueSats: "1" },
      { txid: b(0xe4), vout: 0, valueSats: "2" },
    ],
    /duplicate outpoint/,
  );
});

test("authenticated funding reconciliation refuses active work or reservations without mutating inventory", (t) => {
  const { store } = fixture(t);
  const tip = store.canonicalState();
  const prior = { txid: b(0xd5), vout: 0, valueSats: "505" };
  const replacement = [{ txid: b(0xe5), vout: 0, valueSats: "606" }];
  store.putFundingUtxo(prior);
  const assertPriorInventory = () => {
    assert.deepEqual(store.fundingUtxo({ txid: prior.txid, vout: prior.vout }), {
      valueSats: prior.valueSats,
      reservationOperationId: null,
      spent: false,
    });
    assert.equal(store.fundingUtxo({ txid: replacement[0].txid, vout: 0 }), null);
  };
  const attempt = () => {
    assert.throws(
      () => store.reconcileAuthenticatedFundingInventory({
        canonical: tip,
        fundingInventory: replacement,
      }),
      /no active operation or reserved funding UTXO/,
    );
    assert.deepEqual(store.canonicalState(), tip);
    assertPriorInventory();
  };

  create(store, "funding-reconcile-active", "deposit");
  attempt();
  store.abandonOperation({
    operationId: "funding-reconcile-active",
    reason: "test cleanup",
    crashAt: null,
  });

  const reserved = create(store, "funding-reconcile-reserved", "deposit");
  store.putFundingUtxo({
    txid: reserved.intent.funding.txid,
    vout: reserved.intent.funding.vout,
    valueSats: reserved.intent.funding.valueSats,
  });
  store.reserveResources({
    operationId: "funding-reconcile-reserved",
    noteId: null,
    utxoTxid: reserved.intent.funding.txid,
    utxoVout: reserved.intent.funding.vout,
    crashAt: null,
  });
  attempt();
  assert.deepEqual(
    store.fundingUtxo({
      txid: reserved.intent.funding.txid,
      vout: reserved.intent.funding.vout,
    }),
    {
      valueSats: reserved.intent.funding.valueSats,
      reservationOperationId: "funding-reconcile-reserved",
      spent: false,
    },
  );
});

test("authenticated funding reconciliation atomically replaces inventory and survives reopen", (t) => {
  const { initial, path, store } = fixture(t);
  const tip = store.canonicalState();
  const prior = [
    { txid: b(0xd7), vout: 7, valueSats: "707" },
    { txid: b(0xd8), vout: 8, valueSats: "808" },
  ];
  const replacement = [
    { txid: b(0xe8), vout: 8, valueSats: "1008" },
    { txid: b(0xe7), vout: 7, valueSats: "1007" },
  ];
  for (const entry of prior) store.putFundingUtxo(entry);

  const installed = store.reconcileAuthenticatedFundingInventory({
    canonical: tip,
    fundingInventory: replacement,
  });
  assert.deepEqual(installed, [
    { txid: replacement[1].txid, vout: 7, valueSats: "1007" },
    { txid: replacement[0].txid, vout: 8, valueSats: "1008" },
  ]);
  assert.deepEqual(store.canonicalState(), tip);
  for (const entry of prior) {
    assert.equal(store.fundingUtxo({ txid: entry.txid, vout: entry.vout }), null);
  }
  for (const entry of replacement) {
    assert.deepEqual(
      store.fundingUtxo({ txid: entry.txid, vout: entry.vout }),
      {
        valueSats: entry.valueSats,
        reservationOperationId: null,
        spent: false,
      },
    );
  }

  store.close();
  const reopened = openV2DirectStore({ path, ...initial });
  assert.deepEqual(reopened.canonicalState(), tip);
  for (const entry of prior) {
    assert.equal(reopened.fundingUtxo({ txid: entry.txid, vout: entry.vout }), null);
  }
  for (const entry of replacement) {
    assert.deepEqual(
      reopened.fundingUtxo({ txid: entry.txid, vout: entry.vout }),
      {
        valueSats: entry.valueSats,
        reservationOperationId: null,
        spent: false,
      },
    );
  }
  reopened.close();
});

test("bounded authenticated stream stages to SQLite and atomically installs actions, trees, and owned notes", async (t) => {
  const { initial, snapshot, actions } = populatedAuthenticatedSnapshot(t);
  const stream = authenticatedStreamFixture(initial, snapshot, actions);
  const target = fixture(t);
  const spentNullifier = decodeActionPacket(
    actions[2].packet,
    stateContext,
  ).publicNullifier;
  const installed = await target.store.installAuthenticatedSnapshotStream({
    authenticateTerminal: null,
    frames: stream.frames,
    fundingInventory: [],
    recoverOwnedNote(leaf) {
      return leaf.noteIndex === 0
        ? {
          noteId: "stream-owned-note",
          recordId: "stream-owned-record",
          record: leaf.encryptedRecord,
          nullifier: Buffer.from(spentNullifier, "hex"),
        }
        : null;
    },
    crashAt: null,
  });
  assert.deepEqual(installed.canonical, snapshot.canonical);
  assert.equal(installed.actionCount, actions.length);
  assert.equal(installed.note.leafCount, snapshot.noteLeaves.length);
  assert.equal(
    installed.nullifier.leafCount,
    snapshot.nullifierLeaves.length,
  );
  assert.equal(installed.ownedNoteCount, 1);
  assert.equal(target.store.ownedNote("stream-owned-note").spent, true);
  assert.deepEqual(target.store.ownedNoteStatistics(), {
    total: 1,
    unspent: 0,
    spent: 1,
  });
  assert.deepEqual(target.store.encryptedRecord("stream-owned-record"), {
    ...snapshot.noteLeaves[0],
  }.encryptedRecord);
  assert.deepEqual(target.store.recoveryCheckpoint(), {
    contentSha256: Buffer.from(stream.compact.contentSha256, "hex"),
    historySha256: Buffer.from(stream.compact.historySha256, "hex"),
    actionCount: actions.length,
    noteCount: snapshot.noteLeaves.length,
    nullifierCount: snapshot.nullifierLeaves.length - 2,
    externalAuthenticationBoundary:
      stream.compact.externalAuthenticationBoundary,
  });
  for (const [index, action] of actions.entries()) {
    const stored = target.store.recoveryAction(index + 1);
    assert.equal(stored.kind, action.kind);
    assert.deepEqual(stored.transactionId, action.transactionId);
    assert.deepEqual(stored.packet, action.packet);
  }
  target.store.close();
  const reopened = openV2DirectStore({ path: target.path, ...initial });
  assert.deepEqual(reopened.canonicalState(), snapshot.canonical);
  assert.deepEqual(reopened.ownedNoteStatistics(), {
    total: 1,
    unspent: 0,
    spent: 1,
  });
  assert.equal(reopened.recoveryCheckpoint().actionCount, actions.length);
  reopened.close();
});

test("authenticated stream atomically reorgs confirmed and settled operations absent from rebuilt canonical history", async (t) => {
  const { initial, snapshot, actions } = populatedAuthenticatedSnapshot(t);
  for (const [index, state] of ["confirmed", "settled"].entries()) {
    await t.test(state, async (subtest) => {
      const stream = authenticatedStreamFixture(initial, snapshot, actions);
      const target = fixture(subtest);
      const operationId = `stream-orphan-${state}`;
      const live = ready(
        target.store,
        operationId,
        "deposit",
        0xc0 + index,
      );
      target.store.applyConfirmed(confirmedArgs(
        target.store,
        operationId,
        live.expected,
        live.utxo,
        0xc0 + index,
      ));
      if (state === "settled") {
        target.store.settleConfirmedOperation({
          operationId,
          crashAt: null,
        });
      }
      assert.equal(
        target.store.operation(operationId).journalState,
        state,
      );
      assert.equal(target.store.undoStatistics().count, 1);

      await target.store.installAuthenticatedSnapshotStream({
        authenticateTerminal: null,
        frames: stream.frames,
        fundingInventory: [],
        recoverOwnedNote: null,
        crashAt: null,
      });

      assert.equal(
        target.store.operation(operationId).journalState,
        "reorged",
      );
      assert.equal(target.store.undoStatistics().count, 0);
      assert.equal(
        target.store.fundingUtxo({ txid: live.utxo, vout: 0 }),
        null,
      );
      assert.deepEqual(target.store.canonicalState(), snapshot.canonical);
      target.store.close();
    });
  }
});

test("authenticated stream recognizes an exact local settlement in rebuilt history and permits settlement without stale undo data", async (t) => {
  const { initial, snapshot, actions } = populatedAuthenticatedSnapshot(t);
  const stream = authenticatedStreamFixture(initial, snapshot, actions);
  const target = fixture(t);
  const operationId = "snapshot-source-0";
  const local = ready(target.store, operationId, "deposit", 0x30);
  const signed = parseV2RawTransaction(local.signed.toString("hex"));
  assert.deepEqual(
    Buffer.from(signed.txid, "hex"),
    actions[0].transactionId,
  );
  const changeIndex = CARRIER_COUNT + 2;

  await target.store.installAuthenticatedSnapshotStream({
    authenticateTerminal: null,
    frames: stream.frames,
    fundingInventory: [{
      txid: actions[0].transactionId,
      vout: changeIndex,
      valueSats: signed.outputs[changeIndex].valueSatoshis.toString(),
    }],
    recoverOwnedNote: null,
    crashAt: null,
  });

  assert.equal(
    target.store.operation(operationId).journalState,
    "confirmed",
  );
  assert.equal(target.store.undoStatistics().count, 0);
  assert.equal(
    target.store.settleConfirmedOperation({
      operationId,
      crashAt: null,
    }).journalState,
    "settled",
  );
  assert.deepEqual(target.store.fundingUtxo({
    txid: actions[0].transactionId,
    vout: changeIndex,
  }), {
    valueSats: signed.outputs[changeIndex].valueSatoshis.toString(),
    reservationOperationId: null,
    spent: false,
  });
  target.store.close();
});

test("terminal authentication receives the fully validated staged terminal before the live switch", async (t) => {
  const { initial, snapshot, actions } = populatedAuthenticatedSnapshot(t);
  const stream = authenticatedStreamFixture(initial, snapshot, actions);
  const target = fixture(t);
  const original = target.store.canonicalState();
  const recoveredLeafIndexes = [];
  let authenticationCalls = 0;

  const installed = await target.store.installAuthenticatedSnapshotStream({
    authenticateTerminal(terminal) {
      authenticationCalls += 1;
      assert.equal(authenticationCalls, 1);
      assert.ok(Object.isFrozen(terminal));
      assert.ok(Object.isFrozen(terminal.canonical));
      assert.ok(Object.isFrozen(terminal.canonical.outpoint));
      assert.deepEqual(terminal.snapshot, stream.compact);
      assert.deepEqual(terminal.canonical, snapshot.canonical);
      // Every leaf has passed recovery processing, while the committed store is
      // still exactly the old canonical state and has no recovery checkpoint.
      assert.deepEqual(
        recoveredLeafIndexes,
        snapshot.noteLeaves.map(({ noteIndex }) => noteIndex),
      );
      assert.deepEqual(target.store.canonicalState(), original);
      assert.equal(target.store.recoveryCheckpoint(), null);
      assert.equal(target.store.noteLeaf({ noteIndex: 0 }), null);
      assert.equal(target.store.nullifierLeaf({ physicalIndex: 2 }), null);
      return true;
    },
    frames: stream.frames,
    fundingInventory: [],
    recoverOwnedNote(leaf) {
      recoveredLeafIndexes.push(leaf.noteIndex);
      return null;
    },
    crashAt: null,
  });

  assert.equal(authenticationCalls, 1);
  assert.deepEqual(installed.canonical, snapshot.canonical);
  assert.deepEqual(target.store.canonicalState(), snapshot.canonical);
  assert.equal(target.store.recoveryCheckpoint().actionCount, actions.length);
});

test("terminal authentication rejection never mutates persistent state and always releases stream staging", async (t) => {
  const { initial, snapshot, actions } = populatedAuthenticatedSnapshot(t);
  const stream = authenticatedStreamFixture(initial, snapshot, actions);
  const modes = [
    {
      name: "false",
      authenticateTerminal: () => false,
      pattern: /did not return true/,
    },
    {
      name: "throw",
      authenticateTerminal: () => {
        throw new Error("test terminal authentication failure");
      },
      pattern: /test terminal authentication failure/,
    },
    {
      name: "rejection",
      authenticateTerminal: async () => {
        throw new Error("test terminal authentication rejection");
      },
      pattern: /test terminal authentication rejection/,
    },
  ];

  for (const mode of modes) {
    const target = fixture(t);
    const noteMarker = fr(0xa001n);
    const frontierMarker = fr(0xa002n);
    const nullifierMarker = fr(0xa003n);
    const recordMarker = b(0xa4, 128);
    const nullifier = testNoteNullifier(`terminal-auth-${mode.name}`);
    target.store.putNoteNode({
      depth: 0,
      nodeIndex: 500,
      nodeHash: noteMarker,
    });
    target.store.putNoteFrontier({ depth: 7, nodeHash: frontierMarker });
    target.store.putNullifierNode({
      depth: 0,
      nodeIndex: 500,
      nodeHash: nullifierMarker,
    });
    target.store.putEncryptedRecord({
      recordId: `terminal-auth-record-${mode.name}`,
      record: recordMarker,
    });
    target.store.putOwnedNote({
      noteId: `terminal-auth-note-${mode.name}`,
      recordId: `terminal-auth-record-${mode.name}`,
      noteIndex: 500,
      nullifier,
    });
    const original = target.store.canonicalState();

    await assert.rejects(
      target.store.installAuthenticatedSnapshotStream({
        authenticateTerminal: mode.authenticateTerminal,
        frames: stream.frames,
        fundingInventory: [],
        recoverOwnedNote: null,
        crashAt: null,
      }),
      mode.pattern,
      mode.name,
    );
    assert.deepEqual(target.store.canonicalState(), original, mode.name);
    assert.equal(target.store.recoveryCheckpoint(), null, mode.name);
    assert.deepEqual(
      target.store.noteNode({ depth: 0, nodeIndex: 500 }),
      noteMarker,
      mode.name,
    );
    assert.deepEqual(
      target.store.noteFrontier({ depth: 7 }),
      frontierMarker,
      mode.name,
    );
    assert.deepEqual(
      target.store.nullifierNode({ depth: 0, nodeIndex: 500 }),
      nullifierMarker,
      mode.name,
    );
    assert.deepEqual(
      target.store.encryptedRecord(`terminal-auth-record-${mode.name}`),
      recordMarker,
      mode.name,
    );
    assert.deepEqual(
      target.store.ownedNote(`terminal-auth-note-${mode.name}`), {
      recordId: `terminal-auth-record-${mode.name}`,
      noteIndex: 500,
      nullifier,
      reservationOperationId: null,
      spent: false,
    }, mode.name);
    assert.equal(target.store.noteLeaf({ noteIndex: 0 }), null, mode.name);
    assert.equal(target.store.nullifierLeaf({ physicalIndex: 2 }), null, mode.name);

    // A second stream install on the same store proves that the failed call
    // cleared its active flag and transient SQLite staging tables.
    const installed = await target.store.installAuthenticatedSnapshotStream({
      authenticateTerminal: () => true,
      frames: stream.frames,
      fundingInventory: [],
      recoverOwnedNote: null,
      crashAt: null,
    });
    assert.deepEqual(installed.canonical, snapshot.canonical, mode.name);
    assert.deepEqual(target.store.canonicalState(), snapshot.canonical, mode.name);
    target.store.close();
  }
});

test("authenticated stream never switches live state without its verified end frame and rejects action drift", async (t) => {
  const { initial, snapshot, actions } = populatedAuthenticatedSnapshot(t);
  const stream = authenticatedStreamFixture(initial, snapshot, actions);
  const target = fixture(t);
  const original = target.store.canonicalState();
  await assert.rejects(
    target.store.installAuthenticatedSnapshotStream({
      authenticateTerminal: null,
      frames: stream.frames.slice(0, -1),
      fundingInventory: [],
      recoverOwnedNote: null,
      crashAt: null,
    }),
    /verified end frame/,
  );
  assert.deepEqual(target.store.canonicalState(), original);
  assert.equal(target.store.recoveryCheckpoint(), null);

  const changed = stream.frames.map((frame) => frame.type === "action" &&
      frame.index === 0
    ? {
      ...frame,
      value: { ...frame.value, transactionContextHash: b(0xee) },
    }
    : frame);
  await assert.rejects(
    target.store.installAuthenticatedSnapshotStream({
      authenticateTerminal: null,
      frames: changed,
      fundingInventory: [],
      recoverOwnedNote: null,
      crashAt: null,
    }),
    /exact bound state lineage/,
  );
  assert.deepEqual(target.store.canonicalState(), original);
  assert.equal(target.store.recoveryCheckpoint(), null);
});

test("authenticated stream rejects v1 material and requires the exact runtime digest", async (t) => {
  const { initial, snapshot, actions } = populatedAuthenticatedSnapshot(t);
  const stream = authenticatedStreamFixture(initial, snapshot, actions);
  const changed = (mutate) => stream.frames.map((frame) => {
    if (frame.type !== "snapshot") return frame;
    const snapshotFrame = {
      ...frame.snapshot,
    };
    const material = {
      ...frame.material,
      binding: { ...frame.material.binding },
    };
    mutate({ snapshot: snapshotFrame, material });
    return { ...frame, snapshot: snapshotFrame, material };
  });
  const reject = async (frames, pattern) => {
    const target = fixture(t);
    const original = target.store.canonicalState();
    await assert.rejects(
      target.store.installAuthenticatedSnapshotStream({
        authenticateTerminal: null,
        frames,
        fundingInventory: [],
        recoverOwnedNote: null,
        crashAt: null,
      }),
      pattern,
    );
    assert.deepEqual(target.store.canonicalState(), original);
    assert.equal(target.store.recoveryCheckpoint(), null);
    target.store.close();
  };

  await reject(changed(({ snapshot: value }) => {
    value.schema = "shieldkit-v2-recovery-snapshot-v1";
    value.version = 1;
  }), /schema or profile is unsupported/);
  await reject(changed(({ material }) => {
    material.schema = "shieldkit-v2-recovery-authenticated-material-v1";
  }), /material schema is unsupported/);
  await reject(changed(({ snapshot: value }) => {
    value.runtimeMaterialsSha256 = b(0xee).toString("hex");
  }), /material, snapshot, canonical tip, or counts differ/);
  await reject(changed(({ snapshot: value }) => {
    delete value.runtimeMaterialsSha256;
  }), /missing or unknown properties/);
  await reject(changed(({ snapshot: value }) => {
    value.unexpectedRuntimeMaterialsSha256 = value.runtimeMaterialsSha256;
  }), /missing or unknown properties/);
  await reject(changed(({ material }) => {
    delete material.binding.runtimeMaterialsSha256;
  }), /missing or unknown properties/);
  await reject(changed(({ material }) => {
    material.binding.unexpectedRuntimeMaterialsSha256 =
      material.binding.runtimeMaterialsSha256;
  }), /missing or unknown properties/);
});

test("every authenticated stream crash stage leaves the prior checkpoint exact after reopen", async (t) => {
  const { initial, snapshot, actions } = populatedAuthenticatedSnapshot(t);
  const stream = authenticatedStreamFixture(initial, snapshot, actions);
  const directory = mkdtempSync(join(tmpdir(), "shieldkit-v2-stream-crash-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (
    const [index, crashAt] of
      V2_AUTHENTICATED_STREAM_CRASH_STAGES.entries()
  ) {
    const path = join(directory, `stage-${index}`, "pool.sqlite");
    const store = openV2DirectStore({ path, ...initial });
    const marker = fr(BigInt(0x900 + index));
    store.putNoteNode({ depth: 0, nodeIndex: 90, nodeHash: marker });
    await assert.rejects(
      store.installAuthenticatedSnapshotStream({
        authenticateTerminal: null,
        frames: stream.frames,
        fundingInventory: [],
        recoverOwnedNote: null,
        crashAt,
      }),
      (error) =>
        error instanceof V2StoreCrashInjection &&
        error.message.includes(crashAt),
    );
    assert.deepEqual(store.canonicalState(), canonical(initial), crashAt);
    assert.deepEqual(
      store.noteNode({ depth: 0, nodeIndex: 90 }),
      marker,
      crashAt,
    );
    assert.equal(store.recoveryCheckpoint(), null, crashAt);
    store.close();
    const reopened = openV2DirectStore({ path, ...initial });
    assert.deepEqual(reopened.canonicalState(), canonical(initial), crashAt);
    assert.deepEqual(
      reopened.noteNode({ depth: 0, nodeIndex: 90 }),
      marker,
      crashAt,
    );
    assert.equal(reopened.recoveryCheckpoint(), null, crashAt);
    reopened.close();
  }
});

// Foundation-only: no 10k crash campaign, cross-process contention campaign,
// 1/2/10/100/deep reorg qualification, scanner replay, or production claim.
