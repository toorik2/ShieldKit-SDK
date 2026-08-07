import {
  bigIntToCompactUint,
  decodeTransactionBch,
  decodeTransaction,
  encodeDataPush,
  encodeTransaction,
  encodeTransactionOutput,
  generateSigningSerializationBch,
  hash160,
  hash256,
  secp256k1,
  SigningSerializationTypeBch,
} from '@bitauth/libauth';

import {
  createV2FixtureOnlyTransport,
} from './https-transport.mjs';
import {
  createV2SignedBroadcastMetadata,
  parseV2RawTransaction,
} from './network-gate.mjs';
import {
  createV2LocalVmEvidence,
} from './vm-evidence.mjs';
import {
  parseSerializedSourceOutput,
  transactionId,
} from './transaction-policy.mjs';
import {
  encodeActionPacket,
} from '../../action/v2/packet.mjs';
import {
  hashDirectV2TransactionContext,
} from '../../action/v2/context.mjs';
import {
  encodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import {
  decodeDirectV2BindingUnlock,
  deriveDirectV2BindingP2sh32Lock,
  encodeDirectV2BindingUnlock,
} from '../../action/v2/binding-unlock.mjs';

export const FIXTURE_PROFILE_ID = '66'.repeat(32);
export const FIXTURE_INSTANCE_ID = '77'.repeat(32);
export const FIXTURE_PROFILE_SHA256 = '88'.repeat(32);
export const FIXTURE_CERTIFICATE_SHA256 = 'aa'.repeat(32);
export const FIXTURE_CARRIER_COUNT = 7;
export const FIXTURE_DENOMINATION_SATS = '10000000';
export const FIXTURE_STATE_CONTEXT = Object.freeze({
  denominationSats: FIXTURE_DENOMINATION_SATS,
});
export const FIXTURE_CARRIER_BASE_SATS = 100_000n;
export const FIXTURE_STATE_BASE_SATS = 100_000n;
export const FIXTURE_BINDING_BASE_SATS = 100_000n;
export const FIXTURE_FUNDING_VALUE_SATS = 10_200_000n;
export const FIXTURE_BINDING_REDEEM = Buffer.concat([
  // A PUSHDATA2-sized direct script: OP_NOP*256, OP_DROP, OP_TRUE.
  Buffer.alloc(256, 0x61),
  Buffer.from([0x75, 0x51]),
]);
export const FIXTURE_BINDING_LOCK = Buffer.from(
  deriveDirectV2BindingP2sh32Lock(FIXTURE_BINDING_REDEEM),
);

const FIXTURE_FUNDING_PRIVATE_KEY = Buffer.from(
  `${'00'.repeat(31)}01`,
  'hex',
);
const FIXTURE_FUNDING_PUBLIC_KEY = Buffer.from(
  secp256k1.derivePublicKeyCompressed(FIXTURE_FUNDING_PRIVATE_KEY),
);
const FIXTURE_FUNDING_LOCK = Buffer.from(
  `76a914${Buffer.from(hash160(FIXTURE_FUNDING_PUBLIC_KEY)).toString('hex')}88ac`,
  'hex',
);
const FIXTURE_CHANGE_LOCK = Buffer.from(
  `76a914${'aa'.repeat(20)}88ac`,
  'hex',
);
const fr = (value) => BigInt(value).toString(16).padStart(64, '0');

export function fixturePreState() {
  return Object.freeze({
    profileId: FIXTURE_PROFILE_ID,
    noteRoot: fr(1),
    nullifierRoot: fr(2),
    noteCount: '0',
    nullifierCount: '0',
    maximumLiveNotes: '32',
    reserveSats: '0',
    actionSequence: '0',
  });
}

export function fixturePostDepositState() {
  return Object.freeze({
    ...fixturePreState(),
    noteRoot: fr(3),
    noteCount: '1',
    reserveSats: FIXTURE_DENOMINATION_SATS,
    actionSequence: '1',
  });
}

export function fixturePreStateCommitment() {
  return encodeStateNftCommitment(
    fixturePreState(),
    FIXTURE_STATE_CONTEXT,
  );
}

const le32 = (value) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
};

function sourceTransaction(outputs, tag) {
  return Buffer.concat([
    le32(2),
    bigIntToCompactUint(1n),
    Buffer.alloc(32, tag),
    le32(0xffff_ffff),
    bigIntToCompactUint(1n),
    Buffer.from([tag]),
    Buffer.from('ffffffff', 'hex'),
    bigIntToCompactUint(BigInt(outputs.length)),
    ...outputs,
    le32(tag),
  ]).toString('hex');
}

function serializeFixtureTransaction({
  carrierCount,
  unlockingBytecodes,
  outputs,
  outpoints,
}) {
  const inputCount = carrierCount + 3;
  const pieces = [
    le32(2),
    bigIntToCompactUint(BigInt(inputCount)),
  ];
  for (const [index, unlockingBytecode] of unlockingBytecodes.entries()) {
    pieces.push(
      Buffer.from(outpoints[index].txid, 'hex').reverse(),
      le32(outpoints[index].vout),
      bigIntToCompactUint(BigInt(unlockingBytecode.length)),
      unlockingBytecode,
      Buffer.from('ffffffff', 'hex'),
    );
  }
  pieces.push(
    bigIntToCompactUint(BigInt(outputs.length)),
    ...outputs.map((output) => encodeTransactionOutput(output)),
    le32(0),
  );
  return Buffer.concat(pieces);
}

function fixtureSourceOutputObjects({
  carrierCount = FIXTURE_CARRIER_COUNT,
  instanceId = FIXTURE_INSTANCE_ID,
  stateCategoryWire = instanceId,
  sourceValueSatoshis = FIXTURE_CARRIER_BASE_SATS,
  stateCommitment = fixturePreStateCommitment(),
  stateValueSatoshis = sourceValueSatoshis,
  fundingValueSatoshis = sourceValueSatoshis,
  lockingBytecodes = undefined,
} = {}) {
  return Array.from({ length: carrierCount + 3 }, (_, index) => {
    if (index === carrierCount + 1) {
      return {
        valueSatoshis: sourceValueSatoshis,
        lockingBytecode:
          lockingBytecodes?.[index] ?? Buffer.from([0x51]),
        token: {
          category: Buffer.from(stateCategoryWire, 'hex').reverse(),
          amount: 0n,
          nft: {
            capability: 'mutable',
            commitment: Buffer.from(stateCommitment),
          },
        },
      };
    }
    if (index === carrierCount + 2) {
      return {
        valueSatoshis: sourceValueSatoshis,
        lockingBytecode: FIXTURE_FUNDING_LOCK,
      };
    }
    return {
      valueSatoshis: sourceValueSatoshis,
      lockingBytecode:
        lockingBytecodes?.[index] ?? Buffer.from([0x51]),
    };
  }).map((output, index) => {
    if (index === carrierCount + 1) {
      return { ...output, valueSatoshis: stateValueSatoshis };
    }
    if (index === carrierCount + 2) {
      return { ...output, valueSatoshis: fundingValueSatoshis };
    }
    return output;
  });
}

function signFixtureFundingInput({
  carrierCount,
  transaction,
  sourceOutputs,
}) {
  const inputIndex = carrierCount + 2;
  const serialization = generateSigningSerializationBch(
    {
      inputIndex,
      sourceOutputs,
      transaction,
    },
    {
      coveredBytecode: FIXTURE_FUNDING_LOCK,
      signingSerializationType: Uint8Array.of(
        SigningSerializationTypeBch.allOutputs,
      ),
    },
  );
  const signature = secp256k1.signMessageHashSchnorr(
    FIXTURE_FUNDING_PRIVATE_KEY,
    hash256(serialization),
  );
  if (typeof signature === 'string') {
    throw new Error(`fixture funding signature failed: ${signature}`);
  }
  return Buffer.concat([
    Buffer.from(
      encodeDataPush(
        Buffer.concat([
          Buffer.from(signature),
          Buffer.from([SigningSerializationTypeBch.allOutputs]),
        ]),
      ),
    ),
    Buffer.from(encodeDataPush(FIXTURE_FUNDING_PUBLIC_KEY)),
  ]);
}

export function buildRawTransaction({
  carrierCount = FIXTURE_CARRIER_COUNT,
  unlockingBytecodes = Array.from(
    { length: carrierCount + 3 },
    () => Buffer.alloc(0),
  ),
  outputValueSatoshis =
    BigInt((carrierCount + 3) * 100_000) - 1_000n,
  outputLockingBytecode = Buffer.from([0x51]),
  outputs = undefined,
  outpoints = fixtureOutpoints({
    carrierCount,
    sourceTransactionHexes: fixtureSourceTransactions({ carrierCount }),
  }),
  signFunding = true,
  sourceOutputsForSigning = fixtureSourceOutputObjects({ carrierCount }),
} = {}) {
  const inputCount = carrierCount + 3;
  if (
    unlockingBytecodes.length !== inputCount ||
    outpoints.length !== inputCount
  ) {
    throw new Error(
      `test transaction requires ${inputCount} inputs and outpoints`,
    );
  }
  const selectedUnlocks = unlockingBytecodes.map((value) =>
    Buffer.from(value),
  );
  const selectedOutputs = outputs ?? [{
    valueSatoshis: outputValueSatoshis,
    lockingBytecode: outputLockingBytecode,
  }];
  if (signFunding) {
    selectedUnlocks[inputCount - 1] = Buffer.alloc(0);
    const unsignedBytes = serializeFixtureTransaction({
      carrierCount,
      unlockingBytecodes: selectedUnlocks,
      outputs: selectedOutputs,
      outpoints,
    });
    // Libauth's serializers correctly copy Uint8Array slices. Node Buffer
    // overrides slice() with view semantics, so never decode directly from a
    // Buffer here: signing serialization reverses hash copies by design.
    const transaction = decodeTransaction(Uint8Array.from(unsignedBytes));
    if (typeof transaction === 'string') {
      throw new Error(`fixture transaction decode failed: ${transaction}`);
    }
    selectedUnlocks[inputCount - 1] = signFixtureFundingInput({
      carrierCount,
      transaction,
      sourceOutputs: sourceOutputsForSigning,
    });
  }
  return serializeFixtureTransaction({
    carrierCount,
    unlockingBytecodes: selectedUnlocks,
    outputs: selectedOutputs,
    outpoints,
  }).toString('hex');
}

/*
 * Re-sign an already assembled fixture transaction after a test has changed
 * an input outpoint, binding packet, or output. This is deliberately kept in
 * the fixture module: callers must provide the exact serialized source
 * transaction for every input, and each is authenticated against the raw
 * transaction outpoint before it is used for signing.
 */
export function resignFixtureFundingInput({
  rawTransactionHex,
  carrierCount = FIXTURE_CARRIER_COUNT,
  sourceTransactionHexes,
} = {}) {
  const transactionRecord = parseV2RawTransaction(rawTransactionHex);
  const inputCount = carrierCount + 3;
  if (
    !Array.isArray(sourceTransactionHexes) ||
    sourceTransactionHexes.length !== inputCount ||
    transactionRecord.inputs.length !== inputCount
  ) {
    throw new Error(
      `fixture re-signing requires exactly ${inputCount} transaction inputs and sources`,
    );
  }
  const sourceOutputs = transactionRecord.inputs.map((input, index) => {
    const sourceRecord = parseV2RawTransaction(sourceTransactionHexes[index]);
    if (sourceRecord.txid !== input.outpoint.txid) {
      throw new Error(
        `fixture re-signing source ${index} does not match its transaction outpoint`,
      );
    }
    const sourceTransaction = decodeTransactionBch(
      Uint8Array.from(Buffer.from(sourceTransactionHexes[index], 'hex')),
    );
    if (typeof sourceTransaction === 'string') {
      throw new Error(
        `fixture re-signing source ${index} decode failed: ${sourceTransaction}`,
      );
    }
    const sourceOutput = sourceTransaction.outputs[input.outpoint.vout];
    if (sourceOutput === undefined) {
      throw new Error(
        `fixture re-signing source ${index} lacks its referenced output`,
      );
    }
    return sourceOutput;
  });
  const transaction = decodeTransactionBch(
    Uint8Array.from(Buffer.from(rawTransactionHex, 'hex')),
  );
  if (typeof transaction === 'string') {
    throw new Error(`fixture re-signing transaction decode failed: ${transaction}`);
  }
  const fundingIndex = carrierCount + 2;
  transaction.inputs[fundingIndex].unlockingBytecode = Uint8Array.of();
  transaction.inputs[fundingIndex].unlockingBytecode = signFixtureFundingInput({
    carrierCount,
    transaction,
    sourceOutputs,
  });
  return Buffer.from(encodeTransaction(transaction)).toString('hex');
}

export function rawTransactionAtSize(sizeBytes) {
  const carrierCount = FIXTURE_CARRIER_COUNT;
  const outpoints = fixtureOutpoints({
    carrierCount,
    sourceTransactionHexes: fixtureSourceTransactions({ carrierCount }),
  });
  for (let finalLength = 0; finalLength <= 10_000; finalLength += 1) {
    const rawTransactionHex = buildRawTransaction({
      unlockingBytecodes: [
        ...Array.from({ length: 9 }, () => Buffer.alloc(10_000, 0x51)),
        Buffer.alloc(finalLength, 0x51),
      ],
      carrierCount,
      outpoints,
      signFunding: false,
    });
    if (rawTransactionHex.length / 2 === sizeBytes) {
      return rawTransactionHex;
    }
  }
  throw new Error(`unable to build ${sizeBytes}-byte test transaction`);
}

export function pushOnlyUnlockAtSize(sizeBytes) {
  if (
    !Number.isSafeInteger(sizeBytes) ||
    sizeBytes < 0 ||
    sizeBytes > 10_000
  ) {
    throw new Error('push-only fixture size must be in 0..10000');
  }
  if (sizeBytes === 0) return Buffer.alloc(0);
  if (sizeBytes === 1) return Buffer.from([0x00]);
  if (sizeBytes <= 76) {
    return Buffer.concat([
      Buffer.from([sizeBytes - 1]),
      Buffer.alloc(sizeBytes - 1, 0x01),
    ]);
  }
  const payloadBytes = sizeBytes - 3;
  const prefix = Buffer.alloc(3);
  prefix[0] = 0x4d;
  prefix.writeUInt16LE(payloadBytes, 1);
  return Buffer.concat([prefix, Buffer.alloc(payloadBytes, 0x01)]);
}

export function sourceOutputBytes({
  carrierCount = FIXTURE_CARRIER_COUNT,
  instanceId = FIXTURE_INSTANCE_ID,
  stateCategoryWire = instanceId,
  sourceValueSatoshis = FIXTURE_CARRIER_BASE_SATS,
  stateCommitment = fixturePreStateCommitment(),
  stateValueSatoshis = sourceValueSatoshis,
  fundingValueSatoshis = sourceValueSatoshis,
  lockingBytecodes = undefined,
} = {}) {
  return fixtureSourceOutputObjects({
    carrierCount,
    instanceId,
    stateCategoryWire,
    sourceValueSatoshis,
    stateCommitment,
    stateValueSatoshis,
    fundingValueSatoshis,
    lockingBytecodes,
  }).map((output) => Buffer.from(encodeTransactionOutput(output)));
}

export function fixtureSourceTransactions({
  carrierCount = FIXTURE_CARRIER_COUNT,
  sourceOutputs = sourceOutputBytes({ carrierCount }),
} = {}) {
  if (sourceOutputs.length !== carrierCount + 3) {
    throw new Error(
      `test source topology requires ${carrierCount + 3} outputs`,
    );
  }
  const stateInputIndex = carrierCount + 1;
  const fundingInputIndex = carrierCount + 2;
  const rollingParent = sourceTransaction([
    sourceOutputs[stateInputIndex],
    ...sourceOutputs.slice(0, carrierCount),
    sourceOutputs[carrierCount],
  ], 0xa0);
  const fundingParent = sourceTransaction(
    [sourceOutputs[fundingInputIndex]],
    0xa1,
  );
  return [
    ...Array.from({ length: carrierCount + 2 }, () => rollingParent),
    fundingParent,
  ];
}

export function fixtureOutpoints({
  carrierCount = FIXTURE_CARRIER_COUNT,
  sourceTransactionHexes = fixtureSourceTransactions({ carrierCount }),
} = {}) {
  if (sourceTransactionHexes.length !== carrierCount + 3) {
    throw new Error(
      `test source topology requires ${carrierCount + 3} transactions`,
    );
  }
  const rollingParent = transactionId(
    Buffer.from(sourceTransactionHexes[0], 'hex'),
  );
  if (
    sourceTransactionHexes
      .slice(0, carrierCount + 2)
      .some((raw) =>
        transactionId(Buffer.from(raw, 'hex')) !== rollingParent
      )
  ) {
    throw new Error('rolling source fixtures must share one parent');
  }
  return [
    ...Array.from({ length: carrierCount }, (_, index) => ({
      txid: rollingParent,
      vout: index + 1,
    })),
    { txid: rollingParent, vout: carrierCount + 1 },
    { txid: rollingParent, vout: 0 },
    {
      txid: transactionId(
        Buffer.from(sourceTransactionHexes[carrierCount + 2], 'hex'),
      ),
      vout: 0,
    },
  ];
}

const fixtureRole = (kind, ordinal = 0) =>
  Object.freeze({ kind, ordinal: String(ordinal) });

function parsedOutputRecord(serialized, role) {
  const parsed = parseSerializedSourceOutput(
    Buffer.from(serialized).toString('hex'),
  );
  return Object.freeze({
    role,
    valueSats: parsed.valueSatoshis.toString(),
    lockingBytecode: Buffer.from(parsed.lockingBytecode),
    tokenPrefix: Buffer.from(parsed.tokenPrefixHex, 'hex'),
  });
}

function createRollingFixtureAtFee({
  carrierCount,
  feeSats,
  swapVerifierSiblings = false,
  successorVerifierValueDeltaSats = 0n,
  mutateStateOutputCommitment = false,
}) {
  const fee = BigInt(feeSats);
  const changeValue =
    FIXTURE_FUNDING_VALUE_SATS -
    BigInt(FIXTURE_DENOMINATION_SATS) -
    fee;
  if (changeValue <= 0n) {
    throw new Error('fixture fee leaves no change output');
  }
  const preState = fixturePreState();
  const postState = fixturePostDepositState();
  const preCommitment = encodeStateNftCommitment(
    preState,
    FIXTURE_STATE_CONTEXT,
  );
  const postCommitment = encodeStateNftCommitment(
    postState,
    FIXTURE_STATE_CONTEXT,
  );
  const rollingSourceLocks = Array.from(
    { length: carrierCount + 3 },
    () => Buffer.from([0x51]),
  );
  rollingSourceLocks[carrierCount] = FIXTURE_BINDING_LOCK;
  const sourceOutputObjects = fixtureSourceOutputObjects({
    carrierCount,
    stateCommitment: preCommitment,
    stateValueSatoshis: FIXTURE_STATE_BASE_SATS,
    fundingValueSatoshis: FIXTURE_FUNDING_VALUE_SATS,
    lockingBytecodes: rollingSourceLocks,
  });
  const sourceOutputSerializations = sourceOutputObjects.map((output) =>
    Buffer.from(encodeTransactionOutput(output)),
  );
  const sourceTransactionHexes = fixtureSourceTransactions({
    carrierCount,
    sourceOutputs: sourceOutputSerializations,
  });
  const outpoints = fixtureOutpoints({
    carrierCount,
    sourceTransactionHexes,
  });
  if (swapVerifierSiblings) {
    if (carrierCount < 2) {
      throw new Error('swapped fixture requires two verifier carriers');
    }
    [outpoints[0], outpoints[1]] = [outpoints[1], outpoints[0]];
  }
  const outputObjects = [
    {
      valueSatoshis:
        FIXTURE_STATE_BASE_SATS +
        BigInt(FIXTURE_DENOMINATION_SATS),
      lockingBytecode: Buffer.from([0x51]),
      token: {
        category: Buffer.from(FIXTURE_INSTANCE_ID, 'hex').reverse(),
        amount: 0n,
        nft: {
          capability: 'mutable',
          commitment: postCommitment,
        },
      },
    },
    ...Array.from({ length: carrierCount }, () => ({
      valueSatoshis: FIXTURE_CARRIER_BASE_SATS,
      lockingBytecode: Buffer.from([0x51]),
    })),
    {
      valueSatoshis: FIXTURE_BINDING_BASE_SATS,
      lockingBytecode: FIXTURE_BINDING_LOCK,
    },
    {
      valueSatoshis: changeValue,
      lockingBytecode: FIXTURE_CHANGE_LOCK,
    },
  ];
  const successorDelta = BigInt(successorVerifierValueDeltaSats);
  if (successorDelta !== 0n) {
    const changedCarrier =
      outputObjects[1].valueSatoshis + successorDelta;
    const changedChange =
      outputObjects.at(-1).valueSatoshis - successorDelta;
    if (changedCarrier <= 0n || changedChange <= 0n) {
      throw new Error('fixture successor mutation creates nonpositive output');
    }
    outputObjects[1] = {
      ...outputObjects[1],
      valueSatoshis: changedCarrier,
    };
    outputObjects[outputObjects.length - 1] = {
      ...outputObjects.at(-1),
      valueSatoshis: changedChange,
    };
  }
  if (mutateStateOutputCommitment) {
    const mutated = Buffer.from(postCommitment);
    mutated[mutated.length - 1] ^= 1;
    outputObjects[0] = {
      ...outputObjects[0],
      token: {
        ...outputObjects[0].token,
        nft: {
          ...outputObjects[0].token.nft,
          commitment: mutated,
        },
      },
    };
  }
  const inputRoles = [
    ...Array.from({ length: carrierCount }, (_, index) =>
      fixtureRole('verifier', index),
    ),
    fixtureRole('binding'),
    fixtureRole('state'),
    fixtureRole('funding'),
  ];
  const outputRoles = [
    fixtureRole('state'),
    ...Array.from({ length: carrierCount }, (_, index) =>
      fixtureRole('verifier', index),
    ),
    fixtureRole('binding'),
    fixtureRole('change'),
  ];
  const context = {
    networkId: 2,
    kind: 'deposit',
    profileId: FIXTURE_PROFILE_ID,
    instanceId: FIXTURE_INSTANCE_ID,
    transactionVersion: '2',
    locktime: '0',
    preActionSequence: preState.actionSequence,
    postActionSequence: postState.actionSequence,
    inputs: sourceOutputSerializations.map((serialized, index) => ({
      ...parsedOutputRecord(serialized, inputRoles[index]),
      outpointTransactionHash: Buffer.from(
        outpoints[index].txid,
        'hex',
      ).reverse().toString('hex'),
      outpointIndex: String(outpoints[index].vout),
      sequence: '4294967295',
    })),
    outputs: outputObjects.map((output, index) =>
      parsedOutputRecord(
        encodeTransactionOutput(output),
        outputRoles[index],
      ),
    ),
  };
  const transactionContextHash = hashDirectV2TransactionContext(
    context,
    { carrierCount },
  ).toString('hex');
  const packet = encodeActionPacket({
    kind: 'deposit',
    networkId: 2,
    instanceId: FIXTURE_INSTANCE_ID,
    preState,
    postState,
    publicNullifier: '00'.repeat(32),
    outputNoteLeaf: fr(4),
    encryptedRecord: Buffer.alloc(128, 0x44),
    withdrawalLockingBytecodeHash: '00'.repeat(32),
    transactionContextHash,
  }, FIXTURE_STATE_CONTEXT);
  const packetUnlock = encodeDirectV2BindingUnlock({
    packet,
    redeemScript: FIXTURE_BINDING_REDEEM,
    sourceLockingBytecode: FIXTURE_BINDING_LOCK,
  });
  const rawTransactionHex = buildRawTransaction({
    carrierCount,
    unlockingBytecodes: [
      ...Array.from({ length: carrierCount }, () => Buffer.alloc(0)),
      packetUnlock,
      Buffer.alloc(0),
      Buffer.alloc(0),
    ],
    outputs: outputObjects,
    outpoints,
    sourceOutputsForSigning: sourceOutputObjects,
  });
  return Object.freeze({
    rawTransactionHex,
    packet: Buffer.from(packet),
    feeSats: fee.toString(),
    sourceTransactionHexes: Object.freeze(sourceTransactionHexes),
    tip: Object.freeze({
      state: preCommitment.toString('hex'),
      txid: outpoints[0].txid,
      vout: 0,
      actionSequence: Number(preState.actionSequence),
      height: 100,
      blockHash: '55'.repeat(32),
    }),
  });
}

export function createRollingFixtureArtifacts({
  carrierCount = FIXTURE_CARRIER_COUNT,
  feeSats = undefined,
  swapVerifierSiblings = false,
  successorVerifierValueDeltaSats = 0n,
  mutateStateOutputCommitment = false,
} = {}) {
  if (feeSats !== undefined) {
    return createRollingFixtureAtFee({
      carrierCount,
      feeSats: BigInt(feeSats),
      swapVerifierSiblings,
      successorVerifierValueDeltaSats,
      mutateStateOutputCommitment,
    });
  }
  const provisional = createRollingFixtureAtFee({
    carrierCount,
    feeSats: 2_000n,
    swapVerifierSiblings,
    successorVerifierValueDeltaSats,
    mutateStateOutputCommitment,
  });
  return createRollingFixtureAtFee({
    carrierCount,
    feeSats:
      BigInt(provisional.rawTransactionHex.length / 2) * 2n,
    swapVerifierSiblings,
    successorVerifierValueDeltaSats,
    mutateStateOutputCommitment,
  });
}

export function createFixtureEvidence({
  rawTransactionHex,
  carrierCount = FIXTURE_CARRIER_COUNT,
  instanceId = FIXTURE_INSTANCE_ID,
  profileId = FIXTURE_PROFILE_ID,
  sourceTransactionHexes = fixtureSourceTransactions({
    carrierCount,
    sourceOutputs: sourceOutputBytes({ carrierCount, instanceId }),
  }),
} = {}) {
  const transaction = parseV2RawTransaction(rawTransactionHex);
  return createV2LocalVmEvidence({
    rawTransactionHex,
    carrierCount,
    instanceId,
    tool: {
      name: '@bitauth/libauth',
      version: '3.1.0-next.8',
      vm: 'BCH_2026_STANDARD',
      profileId,
      profileSha256: FIXTURE_PROFILE_SHA256,
    },
    inputs: transaction.inputs.map((_input, index) => ({
      sourceTransactionHex: sourceTransactionHexes[index],
    })),
  });
}

export function fixtureTip({
  carrierCount = FIXTURE_CARRIER_COUNT,
  sourceTransactionHexes = fixtureSourceTransactions({ carrierCount }),
} = {}) {
  return {
    state: fixturePreStateCommitment().toString('hex'),
    txid: transactionId(Buffer.from(sourceTransactionHexes[0], 'hex')),
    vout: 0,
    actionSequence: 0,
    height: 100,
    blockHash: '55'.repeat(32),
  };
}

export function fixtureEndpoint(overrides = {}) {
  return {
    url: 'https://node.example.com/rpc',
    network: 'chipnet',
    allowRedirects: false,
    tls: {
      certificateSha256: FIXTURE_CERTIFICATE_SHA256,
      minVersion: 'TLSv1.3',
      rejectUnauthorized: true,
      serverName: 'node.example.com',
    },
    ...overrides,
  };
}

export function createFixtureStore({
  metadata,
  evidence,
  tip = fixtureTip(),
  packet,
} = {}) {
  const operation = {
    operationId: metadata.operationId,
    kind: metadata.action,
    journalState: 'signed',
    expectedState: Buffer.from(tip.state, 'hex'),
    expectedOutpoint: {
      txid: Buffer.from(tip.txid, 'hex'),
      vout: tip.vout,
    },
    expectedActionSequence: tip.actionSequence,
    packet: Buffer.from(packet),
    signedTx: Buffer.from(metadata.rawTxHex, 'hex'),
    localVmEvidence: Buffer.from(evidence),
  };
  const transitions = [];
  const store = {
    operation: () => operation,
    binding: () => ({
      profileId: Buffer.from(metadata.profileId, 'hex'),
      instanceId: Buffer.from(metadata.instanceId, 'hex'),
      networkId: 2,
      denominationSats: FIXTURE_DENOMINATION_SATS,
      carrierCount: metadata.carrierCount,
    }),
    canonicalState: () => ({
      state: Buffer.from(tip.state, 'hex'),
      outpoint: {
        txid: Buffer.from(tip.txid, 'hex'),
        vout: tip.vout,
      },
      actionSequence: tip.actionSequence,
      height: tip.height,
      blockHash: Buffer.from(tip.blockHash, 'hex'),
    }),
    transitionOperation: ({ operationId, to }) => {
      if (
        operationId !== operation.operationId ||
        operation.journalState !== 'signed' ||
        to !== 'broadcast'
      ) {
        throw new Error('invalid fixture store transition');
      }
      operation.journalState = 'broadcast';
      transitions.push('broadcast');
    },
    recordMempoolOverlay: ({ operationId, overlay }) => {
      if (
        operationId !== operation.operationId ||
        operation.journalState !== 'broadcast' ||
        !(overlay instanceof Uint8Array) ||
        overlay.length === 0
      ) {
        throw new Error('invalid fixture mempool overlay');
      }
      operation.journalState = 'mempool';
      transitions.push('mempool');
    },
  };
  return { operation, store, transitions };
}

export function createGateFixture({
  operationId = 'op-1',
  carrierCount = FIXTURE_CARRIER_COUNT,
  rawTransactionHex,
  feeSats,
  evidence,
  tip = undefined,
  transportHandler,
  swapVerifierSiblings = false,
  successorVerifierValueDeltaSats = 0n,
  mutateStateOutputCommitment = false,
} = {}) {
  const artifacts = createRollingFixtureArtifacts({
    carrierCount,
    feeSats,
    swapVerifierSiblings,
    successorVerifierValueDeltaSats,
    mutateStateOutputCommitment,
  });
  const provisional = rawTransactionHex ?? artifacts.rawTransactionHex;
  const parsed = parseV2RawTransaction(provisional);
  const inputValue =
    BigInt(carrierCount) * FIXTURE_CARRIER_BASE_SATS +
    FIXTURE_BINDING_BASE_SATS +
    FIXTURE_STATE_BASE_SATS +
    FIXTURE_FUNDING_VALUE_SATS;
  const outputValue = parsed.outputs.reduce(
    (sum, output) => sum + output.valueSatoshis,
    0n,
  );
  const selectedFee = inputValue - outputValue;
  const selectedTip = tip ?? artifacts.tip;
  const selectedEvidence =
    evidence ??
    createFixtureEvidence({
      rawTransactionHex: provisional,
      carrierCount,
      sourceTransactionHexes: artifacts.sourceTransactionHexes,
    });
  const bindingUnlock = parsed.inputs[carrierCount].unlockingBytecode;
  let packet = artifacts.packet;
  try {
    packet = decodeDirectV2BindingUnlock({
      unlockingBytecode: bindingUnlock,
      sourceLockingBytecode: FIXTURE_BINDING_LOCK,
    }).packet;
  } catch {
    // Malformed-transaction gate fixtures retain the valid operation packet.
  }
  const metadata = createV2SignedBroadcastMetadata({
    operationId,
    rawTxHex: provisional,
    feeSats: selectedFee.toString(),
    action: 'deposit',
    profileId: FIXTURE_PROFILE_ID,
    instanceId: FIXTURE_INSTANCE_ID,
    network: 'chipnet',
    tip: selectedTip,
    localVmEvidence: selectedEvidence,
  });
  const { store, operation, transitions } = createFixtureStore({
    metadata,
    evidence: selectedEvidence,
    tip: selectedTip,
    packet,
  });
  let sends = 0;
  const transport = createV2FixtureOnlyTransport(
    transportHandler ??
      (async () => {
        sends += 1;
        return {
          txid: metadata.txid,
          redirected: false,
          tlsProtocol: 'TLSv1.3',
          peerCertificateSha256: FIXTURE_CERTIFICATE_SHA256,
        };
      }),
  );
  return {
    metadata,
    evidence: selectedEvidence,
    store,
    operation,
    transitions,
    transport,
    endpoint: fixtureEndpoint(),
    synchronizeCanonicalTip: async () => store.canonicalState(),
    sends: () => sends,
    countSend: () => {
      sends += 1;
    },
    tip: selectedTip,
  };
}
