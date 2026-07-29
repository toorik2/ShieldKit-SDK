// These tests use deterministic, directly spendable structural scripts to
// exercise the assembler and BCH_2026 evidence path. They are not PF11
// verifier-artifact qualification; production verifier/state/binding locks
// remain an external pinned dependency.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import test from 'node:test';
import {
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  encodeTransaction,
  hash160,
  hash256,
  secp256k1,
} from '@bitauth/libauth';

import {
  encodeActionPacket,
} from './packet.mjs';
import {
  PF11_ASSEMBLED_SCHEMA,
  PF11_BINDING_INPUT_INDEX,
  PF11_CARRIER_COUNT,
  PF11_DEFAULT_FEE_RATE_SATS_PER_BYTE,
  PF11_FUNDING_INPUT_INDEX,
  PF11_INPUT_COUNT,
  PF11_P2PKH_DUST_SATS,
  PF11_PREPARED_SCHEMA,
  PF11_SIGHASH_TYPE,
  PF11_SIGNED_SCHEMA,
  PF11_STATE_INPUT_INDEX,
  PF11_VERIFIER_ROLES,
  Pf11SettlementError,
  assembleV2DirectSettlement,
  assemblePf11Settlement,
  prepareV2DirectSettlement,
  preparePf11Settlement,
  signV2DirectSettlement,
  signPf11Settlement,
} from './settlement.mjs';
import {
  encodeStateNftCommitment,
} from './state.mjs';
import {
  deriveV2RollingBaseSats,
} from './dust-policy.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  directV2VerifierTopologyById,
} from './topology.mjs';
import {
  parseV2RawTransaction,
} from '../../kit/v2/transaction-policy.mjs';
import {
  createV2LocalVmEvidence,
} from '../../kit/v2/vm-evidence.mjs';
import {
  buildDirectV2BindingLock,
  buildDirectV2BindingRedeem,
  buildDirectV2StateHelper,
  buildDirectV2StateTrampolineLock,
  buildDirectV2StateTrampolineUnlock,
} from '../../unlock-builder/v2/structural-covenants.mjs';

const LIBAUTH_VERSION = createRequire(import.meta.url)(
  '@bitauth/libauth/package.json',
).version;
const D = 10_000n;
const INSTANCE_ID = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index + 1),
).toString('hex');
const PROFILE_ID = '11'.repeat(32);
const PF11_TOPOLOGY = directV2VerifierTopologyById(
  DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
);
const PF10_TOPOLOGY = directV2VerifierTopologyById(
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
);
const PRIVATE_KEY = Uint8Array.from([
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 7,
]);
const FUNDING_PUBLIC_KEY =
  secp256k1.derivePublicKeyCompressed(PRIVATE_KEY);
assert.ok(FUNDING_PUBLIC_KEY instanceof Uint8Array);

const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
const sha256Hex = (value) =>
  createHash('sha256').update(value).digest('hex');
const p2pkh = (hashByte) => Buffer.from([
  0x76,
  0xa9,
  0x14,
  ...Array(20).fill(hashByte),
  0x88,
  0xac,
]);
const fundingLock = () => Buffer.concat([
  Buffer.from([0x76, 0xa9, 0x14]),
  Buffer.from(hash160(FUNDING_PUBLIC_KEY)),
  Buffer.from([0x88, 0xac]),
]);
// Direct P2S-style structural script: consume one supplied stack item, true.
const DIRECT_DROP_TRUE = Buffer.from([0x75, 0x51]);
const DIRECT_UNLOCK = Buffer.from([0x51]);
const DIRECT_BINDING_REDEEM = Buffer.from(DIRECT_DROP_TRUE);
const DIRECT_BINDING_LOCK = Buffer.from(
  encodeLockingBytecodeP2sh32(hash256(DIRECT_BINDING_REDEEM)),
);

function states(kind) {
  const values = {
    deposit: [
      ['0', '0', '0', '0', fr(1), fr(2)],
      ['1', '0', D.toString(), '1', fr(3), fr(2)],
    ],
    transfer: [
      ['1', '0', D.toString(), '1', fr(1), fr(2)],
      ['2', '1', D.toString(), '2', fr(3), fr(4)],
    ],
    withdrawal: [
      ['1', '0', D.toString(), '1', fr(1), fr(2)],
      ['1', '1', '0', '2', fr(1), fr(4)],
    ],
  }[kind];
  return values.map(
    ([
      noteCount,
      nullifierCount,
      reserveSats,
      actionSequence,
      noteRoot,
      nullifierRoot,
    ]) => ({
      profileId: PROFILE_ID,
      noteRoot,
      nullifierRoot,
      noteCount,
      nullifierCount,
      maximumLiveNotes: '8',
      reserveSats,
      actionSequence,
    }),
  );
}

function stateToken(state, overrides = {}) {
  return {
    category: Uint8Array.from(
      Buffer.from(overrides.category ?? INSTANCE_ID, 'hex').reverse(),
    ),
    amount: overrides.amount ?? 0n,
    nft: {
      capability: overrides.capability ?? 'mutable',
      commitment: overrides.commitment ?? encodeStateNftCommitment(state, {
        denominationSats: D.toString(),
      }),
    },
  };
}

function sourceTransaction(outputs, seed) {
  return Buffer.from(encodeTransaction({
    version: 2,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(
        Array.from({ length: 32 }, (_, index) =>
          (seed + index * 17) & 0xff),
      ),
      outpointIndex: seed,
      sequenceNumber: 0,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs,
    locktime: 0,
  })).toString('hex');
}

function makeFixture(kind = 'deposit', options = {}) {
  const topology = options.topology ?? PF11_TOPOLOGY;
  const [preState, postState] = states(kind);
  const verifierPins = Array.from(
    { length: topology.carrierCount },
    () => ({
      baseValueSats: deriveV2RollingBaseSats({
        lockingBytecode: DIRECT_DROP_TRUE,
      }).toString(),
      lockingBytecode: Buffer.from(DIRECT_DROP_TRUE),
    }),
  );
  const pins = {
    topologyId: topology.id,
    verifierRoles: [...topology.verifierRoles],
    bindingBaseSats: deriveV2RollingBaseSats({
      lockingBytecode: DIRECT_BINDING_LOCK,
    }).toString(),
    bindingLockingBytecode: Buffer.from(DIRECT_BINDING_LOCK),
    bindingRedeemBytecode: Buffer.from(DIRECT_BINDING_REDEEM),
    stateBaseSats: deriveV2RollingBaseSats({
      lockingBytecode: DIRECT_DROP_TRUE,
      token: stateToken(postState),
    }).toString(),
    stateLockingBytecode: Buffer.from(DIRECT_DROP_TRUE),
    verifierCarriers: verifierPins,
  };
  options.mutatePins?.(pins);
  const parentOutputs = [
    {
      valueSatoshis: BigInt(pins.stateBaseSats) + BigInt(preState.reserveSats),
      lockingBytecode: Buffer.from(pins.stateLockingBytecode),
      token: stateToken(preState, options.stateTokenOverrides),
    },
    ...verifierPins.map((pin) => ({
      valueSatoshis: BigInt(pin.baseValueSats),
      lockingBytecode: Buffer.from(pin.lockingBytecode),
    })),
    {
      valueSatoshis: BigInt(pins.bindingBaseSats),
      lockingBytecode: Buffer.from(pins.bindingLockingBytecode),
    },
    {
      valueSatoshis: 1_000n,
      lockingBytecode: p2pkh(0x71),
    },
  ];
  options.mutateParentOutputs?.(parentOutputs);
  const previousBundleTransactionHex =
    sourceTransaction(parentOutputs, 31);
  const fundingValue = options.fundingValue
    ?? (kind === 'deposit' ? D + 500_000n : 500_000n);
  const fundingOutput = {
    valueSatoshis: fundingValue,
    lockingBytecode: fundingLock(),
  };
  options.mutateFundingOutput?.(fundingOutput);
  const fundingSourceTransactionHex = options.sameFundingParent
    ? previousBundleTransactionHex
    : sourceTransaction([fundingOutput], 97);
  const input = {
    changeLockingBytecode: options.changeLockingBytecode ?? p2pkh(0x41),
    denominationSats: D.toString(),
    ...(options.feeRateSatsPerByte === undefined
      ? {}
      : { feeRateSatsPerByte: options.feeRateSatsPerByte }),
    funding: {
      outpointIndex: options.sameFundingParent
        ? String(topology.fundingInputIndex)
        : '0',
      publicKey: Buffer.from(FUNDING_PUBLIC_KEY),
      sourceTransactionHex: fundingSourceTransactionHex,
    },
    instanceId: INSTANCE_ID,
    kind,
    networkId: 2,
    payoutLockingBytecode:
      kind === 'withdrawal'
        ? (options.payoutLockingBytecode ?? p2pkh(0x51))
        : null,
    pins,
    postState: options.postState ?? postState,
    preState: options.preState ?? preState,
    previousBundleTransactionHex,
    profileId: PROFILE_ID,
    unlockingBytecodeLengths: options.unlockingBytecodeLengths ?? {
      verifier: Array(topology.carrierCount).fill(DIRECT_UNLOCK.length),
      state: DIRECT_UNLOCK.length,
    },
  };
  return {
    input,
    preState,
    postState,
    fundingValue,
    previousBundleTransactionHex,
    fundingSourceTransactionHex,
    topology,
  };
}

function makeStructuralFixture(kind) {
  const options = {};
  let artifacts;
  options.mutatePins = (pins) => {
    const verifierLocks = pins.verifierCarriers.map(
      () => Buffer.from(DIRECT_DROP_TRUE),
    );
    const bindingLock = buildDirectV2BindingLock({
      networkId: 2,
      profileId: PROFILE_ID,
      stateCategory: INSTANCE_ID,
      denominationSats: D,
    });
    const bindingRedeem = buildDirectV2BindingRedeem({
      networkId: 2,
      profileId: PROFILE_ID,
      stateCategory: INSTANCE_ID,
      denominationSats: D,
    });
    for (const pin of pins.verifierCarriers) {
      pin.baseValueSats = deriveV2RollingBaseSats({
        lockingBytecode: DIRECT_DROP_TRUE,
      }).toString();
    }
    pins.bindingBaseSats = deriveV2RollingBaseSats({
      lockingBytecode: bindingLock,
    }).toString();
    // The rolling base depends on the serialized state output. Its byte size
    // is independent of its eight-byte satoshi value, so one construction
    // gives the fixed point used by the structural helper and trampoline.
    const provisionalHelper = buildDirectV2StateHelper({
      bindingLock,
      verifierLocks,
      verifierBaseValues: pins.verifierCarriers.map(
        (pin) => BigInt(pin.baseValueSats),
      ),
      bindingBaseValueSats: BigInt(pins.bindingBaseSats),
      stateBaseValueSats: 1_000n,
      denominationSats: D,
      stateCategory: INSTANCE_ID,
      minimumChangeSats: BigInt(PF11_P2PKH_DUST_SATS),
    });
    const provisionalStateLock = buildDirectV2StateTrampolineLock({
      helper: provisionalHelper,
      bindingLock,
    });
    pins.stateBaseSats = deriveV2RollingBaseSats({
      lockingBytecode: provisionalStateLock,
      token: stateToken(states(kind)[1]),
    }).toString();
    const helper = buildDirectV2StateHelper({
      bindingLock,
      verifierLocks,
      verifierBaseValues: pins.verifierCarriers.map(
        (pin) => BigInt(pin.baseValueSats),
      ),
      bindingBaseValueSats: BigInt(pins.bindingBaseSats),
      stateBaseValueSats: BigInt(pins.stateBaseSats),
      denominationSats: D,
      stateCategory: INSTANCE_ID,
      minimumChangeSats: BigInt(PF11_P2PKH_DUST_SATS),
    });
    const stateLock = buildDirectV2StateTrampolineLock({
      helper,
      bindingLock,
    });
    assert.equal(
      deriveV2RollingBaseSats({
        lockingBytecode: stateLock,
        token: stateToken(states(kind)[1]),
      }).toString(),
      pins.stateBaseSats,
    );
    const stateUnlock = buildDirectV2StateTrampolineUnlock(helper);
    pins.bindingLockingBytecode = Buffer.from(bindingLock);
    pins.bindingRedeemBytecode = Buffer.from(bindingRedeem);
    pins.stateLockingBytecode = Buffer.from(stateLock);
    for (const [index, pin] of pins.verifierCarriers.entries()) {
      pin.lockingBytecode = verifierLocks[index];
    }
    options.unlockingBytecodeLengths = {
      verifier: pins.verifierCarriers.map(
        (_pin, index) => index === 8 ? 483 : DIRECT_UNLOCK.length,
      ),
      state: stateUnlock.length,
    };
    artifacts = {
      bindingLock: Buffer.from(bindingLock),
      bindingRedeem: Buffer.from(bindingRedeem),
      helper: Buffer.from(helper),
      stateLock: Buffer.from(stateLock),
      stateUnlock: Buffer.from(stateUnlock),
    };
  };
  const fixture = makeFixture(kind, options);
  return { fixture, artifacts };
}

function packetFor(prepared, fixture) {
  const withdrawalHash = fixture.input.kind === 'withdrawal'
    ? sha256Hex(fixture.input.payoutLockingBytecode)
    : '00'.repeat(32);
  return encodeActionPacket({
    kind: fixture.input.kind,
    networkId: fixture.input.networkId,
    instanceId: INSTANCE_ID,
    preState: fixture.preState,
    postState: fixture.postState,
    publicNullifier:
      fixture.input.kind === 'deposit' ? fr(0) : fr(9),
    outputNoteLeaf:
      fixture.input.kind === 'withdrawal' ? fr(0) : fr(7),
    encryptedRecord:
      fixture.input.kind === 'withdrawal'
        ? Buffer.alloc(128)
        : Buffer.alloc(128, 0x44),
    withdrawalLockingBytecodeHash: withdrawalHash,
    transactionContextHash: prepared.contextHash,
  }, {
    denominationSats: D.toString(),
  });
}

function assemble(prepared, fixture, overrides = {}) {
  return assemblePf11Settlement(prepared, {
    actionPacket: overrides.actionPacket ?? packetFor(prepared, fixture),
    stateUnlockingBytecode:
      overrides.stateUnlockingBytecode ?? Buffer.from(DIRECT_UNLOCK),
    verifierUnlockingBytecodes:
      overrides.verifierUnlockingBytecodes
      ?? Array.from(
        { length: PF11_CARRIER_COUNT },
        () => Buffer.from(DIRECT_UNLOCK),
      ),
  });
}

function signerOptions(overrides = {}) {
  const expectedFundingInputIndex =
    overrides.expectedFundingInputIndex ?? PF11_FUNDING_INPUT_INDEX;
  return {
    signFunding: overrides.signFunding ?? ((request) => {
      assert.equal(request.algorithm, 'BCH_SCHNORR_SECP256K1');
      assert.equal(request.fundingInputIndex, expectedFundingInputIndex);
      assert.equal(request.sighashType, PF11_SIGHASH_TYPE);
      assert.equal(request.sighashContract, 'SIGHASH_ALL|UTXOS|FORKID');
      assert.equal(request.publicKeyHex, Buffer.from(
        FUNDING_PUBLIC_KEY,
      ).toString('hex'));
      assert.ok(Object.isFrozen(request));
      return secp256k1.signMessageHashSchnorr(
        PRIVATE_KEY,
        Buffer.from(request.digestHex, 'hex'),
      );
    }),
    createLocalVmEvidence:
      overrides.createLocalVmEvidence
      ?? ((request) => createV2LocalVmEvidence({
        ...request,
        tool: {
          name: '@bitauth/libauth',
          version: LIBAUTH_VERSION,
          vm: 'BCH_2026_STANDARD',
          profileId: PROFILE_ID,
          profileSha256: '33'.repeat(32),
        },
      })),
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

test('prepares, assembles, signs, and locally evaluates every exact PF11 action', async () => {
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const fixture = makeFixture(kind);
    const prepared = preparePf11Settlement(fixture.input);
    assert.equal(prepared.schema, PF11_PREPARED_SCHEMA);
    assert.equal(prepared.topology.inputCount, PF11_INPUT_COUNT);
    assert.equal(
      prepared.topology.outputCount,
      kind === 'withdrawal' ? 15 : 14,
    );
    assert.deepEqual(
      prepared.topology.verifierRoles,
      PF11_VERIFIER_ROLES,
    );
    assert.equal(
      BigInt(prepared.measurements.feeSats),
      BigInt(prepared.measurements.signedSizeBytes)
        * BigInt(PF11_DEFAULT_FEE_RATE_SATS_PER_BYTE),
    );
    assert.equal(
      BigInt(prepared.measurements.changeSats)
        + BigInt(prepared.measurements.feeSats)
        + (kind === 'deposit' ? D : 0n),
      fixture.fundingValue,
    );

    const assembled = assemble(prepared, fixture);
    assert.equal(assembled.schema, PF11_ASSEMBLED_SCHEMA);
    assert.equal(assembled.contextHash, prepared.contextHash);
    assert.equal(assembled.signingRequest.sighashType, 0x61);
    const unsigned = parseV2RawTransaction(
      assembled.unsignedTransactionHex,
    );
    assert.equal(unsigned.inputs.length, PF11_INPUT_COUNT);
    assert.equal(
      unsigned.inputs[PF11_BINDING_INPUT_INDEX].unlockingBytecodeBytes,
      555 + encodeDataPush(fixture.input.pins.bindingRedeemBytecode).length,
    );
    assert.deepEqual(
      unsigned.inputs[PF11_BINDING_INPUT_INDEX]
        .unlockingBytecode.subarray(0, 3),
      Buffer.from([0x4d, 0x28, 0x02]),
    );
    assert.equal(
      unsigned.inputs[PF11_FUNDING_INPUT_INDEX].unlockingBytecodeBytes,
      0,
    );

    const signed = await signPf11Settlement(
      assembled,
      signerOptions(),
    );
    assert.equal(signed.schema, PF11_SIGNED_SCHEMA);
    assert.equal(signed.measurements.inputCount, 14);
    assert.equal(
      signed.measurements.outputCount,
      kind === 'withdrawal' ? 15 : 14,
    );
    assert.equal(signed.measurements.acceptedInputCount, 14);
    assert.equal(signed.measurements.acceptancePercent, 100);
    assert.equal(signed.claims.localBch2026AllInputsAccepted, true);
    assert.equal(
      signed.claims.verifierArtifactProvenanceQualified,
      false,
    );
    assert.equal(signed.claims.broadcasted, false);
    const parsed = parseV2RawTransaction(signed.rawTransactionHex);
    assert.equal(parsed.inputs[PF11_FUNDING_INPUT_INDEX]
      .unlockingBytecodeBytes, 100);
    assert.equal(
      parsed.inputs[PF11_FUNDING_INPUT_INDEX].unlockingBytecode[65],
      PF11_SIGHASH_TYPE,
    );
    assert.equal(
      parsed.inputs[PF11_FUNDING_INPUT_INDEX].unlockingBytecode[66],
      0x21,
    );
    assert.equal(parsed.sizeBytes, prepared.measurements.signedSizeBytes);
  }
});

test('generic assembler preserves the signed PF10 topology through all three stages', async () => {
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const fixture = makeFixture(kind, { topology: PF10_TOPOLOGY });
    const prepared = prepareV2DirectSettlement(fixture.input);
    assert.equal(prepared.topology.id, DIRECT_V2_PF10_FUSED_TOPOLOGY_ID);
    assert.deepEqual(
      prepared.topology.verifierRoles,
      DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
    );
    assert.equal(prepared.topology.inputCount, 13);
    assert.equal(
      prepared.topology.outputCount,
      kind === 'withdrawal' ? 14 : 13,
    );
    assert.throws(
      () => preparePf11Settlement(fixture.input),
      /signed PF11 oracle topology/,
    );

    const assembled = assembleV2DirectSettlement(prepared, {
      actionPacket: packetFor(prepared, fixture),
      stateUnlockingBytecode: Buffer.from(DIRECT_UNLOCK),
      verifierUnlockingBytecodes: Array.from(
        { length: PF10_TOPOLOGY.carrierCount },
        () => Buffer.from(DIRECT_UNLOCK),
      ),
    });
    assert.equal(
      assembled.signingRequest.fundingInputIndex,
      PF10_TOPOLOGY.fundingInputIndex,
    );
    assert.throws(
      () => assemblePf11Settlement(prepared, {
        actionPacket: packetFor(prepared, fixture),
        stateUnlockingBytecode: Buffer.from(DIRECT_UNLOCK),
        verifierUnlockingBytecodes: Array.from(
          { length: PF10_TOPOLOGY.carrierCount },
          () => Buffer.from(DIRECT_UNLOCK),
        ),
      }),
      /signed PF11 oracle topology/,
    );

    const signed = await signV2DirectSettlement(
      assembled,
      signerOptions({
        expectedFundingInputIndex: PF10_TOPOLOGY.fundingInputIndex,
      }),
    );
    assert.equal(signed.measurements.inputCount, 13);
    assert.equal(
      signed.measurements.outputCount,
      kind === 'withdrawal' ? 14 : 13,
    );
    assert.equal(signed.measurements.acceptedInputCount, 13);
    assert.equal(signed.measurements.acceptancePercent, 100);
    await assert.rejects(
      signPf11Settlement(
        assembled,
        signerOptions({
          expectedFundingInputIndex: PF10_TOPOLOGY.fundingInputIndex,
        }),
      ),
      /signed PF11 oracle topology/,
    );
  }
});

test('generic production settlement stages refuse the PF11 semantic oracle', async () => {
  const fixture = makeFixture('deposit');
  const assembly = {
    actionPacket: undefined,
    stateUnlockingBytecode: Buffer.from(DIRECT_UNLOCK),
    verifierUnlockingBytecodes: Array.from(
      { length: PF11_CARRIER_COUNT },
      () => Buffer.from(DIRECT_UNLOCK),
    ),
  };
  assert.throws(
    () => prepareV2DirectSettlement(fixture.input),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'PF11_SEMANTIC_ORACLE_ONLY',
  );
  const prepared = preparePf11Settlement(fixture.input);
  assembly.actionPacket = packetFor(prepared, fixture);
  assert.throws(
    () => assembleV2DirectSettlement(prepared, assembly),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'PF11_SEMANTIC_ORACLE_ONLY',
  );
  const assembled = assemblePf11Settlement(prepared, assembly);
  await assert.rejects(
    signV2DirectSettlement(assembled, signerOptions()),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'PF11_SEMANTIC_ORACLE_ONLY',
  );
});

test('assembler executes the real V2 binding and state structural covenants', async () => {
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const { fixture, artifacts } = makeStructuralFixture(kind);
    const prepared = preparePf11Settlement(fixture.input);
    const packet = packetFor(prepared, fixture);
    const projection = Buffer.alloc(480);
    Buffer.from(sha256Hex(packet), 'hex').copy(projection, 448);
    const verifierUnlocks = Array.from(
      { length: PF11_CARRIER_COUNT },
      () => Buffer.from(DIRECT_UNLOCK),
    );
    verifierUnlocks[8] = Buffer.concat([
      Buffer.from([0x4d, 0xe0, 0x01]),
      projection,
    ]);
    const assembled = assemblePf11Settlement(prepared, {
      actionPacket: packet,
      stateUnlockingBytecode: artifacts.stateUnlock,
      verifierUnlockingBytecodes: verifierUnlocks,
    });
    const signed = await signPf11Settlement(
      assembled,
      signerOptions(),
    );
    assert.equal(signed.measurements.acceptedInputCount, 14);
    assert.equal(signed.measurements.acceptancePercent, 100);
    assert.equal(signed.claims.localBch2026AllInputsAccepted, true);
    assert.equal(artifacts.bindingLock.length, 35);
    assert.equal(artifacts.bindingRedeem.length, 2_278);
    assert.equal(artifacts.helper.length, 2_783);
    assert.equal(artifacts.stateLock.length, 88);
    assert.equal(artifacts.stateUnlock.length, 2_786);
    assert.equal(signed.measurements.sizeBytes <= 100_000, true);
  }
});

test('pins exact common-parent inputs 0..12 and independent funding input 13', async () => {
  const fixture = makeFixture('transfer');
  const prepared = preparePf11Settlement(fixture.input);
  const signed = await signPf11Settlement(
    assemble(prepared, fixture),
    signerOptions(),
  );
  const transaction = parseV2RawTransaction(signed.rawTransactionHex);
  const previousTxid =
    parseV2RawTransaction(fixture.previousBundleTransactionHex).txid;
  const fundingTxid =
    parseV2RawTransaction(fixture.fundingSourceTransactionHex).txid;
  assert.equal(
    prepared.topology.commonParentTransactionHashWire,
    Buffer.from(previousTxid, 'hex').reverse().toString('hex'),
  );
  assert.equal(
    prepared.topology.fundingTransactionHashWire,
    Buffer.from(fundingTxid, 'hex').reverse().toString('hex'),
  );
  assert.deepEqual(
    prepared.topology.commonParentOutputIndices,
    [...Array.from({ length: 12 }, (_, index) => index + 1), 0],
  );
  for (let index = 0; index <= PF11_STATE_INPUT_INDEX; index += 1) {
    assert.equal(transaction.inputs[index].outpoint.txid, previousTxid);
    assert.equal(
      transaction.inputs[index].outpoint.vout,
      index === PF11_STATE_INPUT_INDEX ? 0 : index + 1,
    );
    assert.equal(transaction.inputs[index].sequence, 0);
  }
  assert.equal(
    transaction.inputs[PF11_FUNDING_INPUT_INDEX].outpoint.txid,
    fundingTxid,
  );
  assert.notEqual(fundingTxid, previousTxid);
  assert.equal(transaction.version, 2);
  assert.equal(transaction.locktime, 0);
});

test('rejects parent topology, pinned base/lock drift, and unsafe funding', () => {
  const cases = [
    [
      makeFixture('deposit', { sameFundingParent: true }),
      'FUNDING_NOT_INDEPENDENT',
    ],
    [
      makeFixture('deposit', {
        mutateParentOutputs: (outputs) => {
          outputs[5].valueSatoshis = 9_999n;
        },
      }),
      'ROLLING_BUNDLE_INVALID',
    ],
    [
      makeFixture('deposit', {
        mutateParentOutputs: (outputs) => {
          outputs[12].lockingBytecode = Buffer.from([0x51]);
        },
      }),
      'ROLLING_BUNDLE_INVALID',
    ],
    [
      makeFixture('deposit', {
        mutatePins: (pins) => {
          pins.bindingLockingBytecode = Buffer.from([0x51]);
        },
      }),
      'BINDING_REDEEM_MISMATCH',
    ],
    [
      makeFixture('deposit', {
        mutateParentOutputs: (outputs) => {
          outputs[0].valueSatoshis += 1n;
        },
      }),
      'ROLLING_BUNDLE_INVALID',
    ],
    [
      makeFixture('deposit', {
        mutateParentOutputs: (outputs) => {
          outputs[12].token = {
            category: Buffer.alloc(32, 0x77),
            amount: 1n,
          };
        },
      }),
      'TOKEN_ROLE_MISMATCH',
    ],
    [
      makeFixture('deposit', {
        mutateFundingOutput: (output) => {
          output.lockingBytecode = Buffer.from([0x51]);
        },
      }),
      'UNSAFE_FUNDING_INPUT',
    ],
    [
      makeFixture('deposit', {
        mutateFundingOutput: (output) => {
          output.token = {
            category: Buffer.alloc(32, 0x77),
            amount: 1n,
          };
        },
      }),
      'UNSAFE_FUNDING_INPUT',
    ],
    [
      makeFixture('deposit', {
        mutateFundingOutput: (output) => {
          output.lockingBytecode = p2pkh(0x99);
        },
      }),
      'FUNDING_KEY_MISMATCH',
    ],
  ];
  for (const [fixture, code] of cases) {
    assert.throws(
      () => preparePf11Settlement(fixture.input),
      (error) =>
        error instanceof Pf11SettlementError
        && error.code === code,
    );
  }
});

test('requires exact dust-derived rolling bases for every action and output role', () => {
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const baseline = makeFixture(kind);
    const { pins, postState } = baseline.input;
    for (const pin of pins.verifierCarriers) {
      assert.equal(
        pin.baseValueSats,
        deriveV2RollingBaseSats({
          lockingBytecode: pin.lockingBytecode,
        }).toString(),
      );
    }
    assert.equal(
      pins.bindingBaseSats,
      deriveV2RollingBaseSats({
        lockingBytecode: pins.bindingLockingBytecode,
      }).toString(),
    );
    assert.equal(
      pins.stateBaseSats,
      deriveV2RollingBaseSats({
        lockingBytecode: pins.stateLockingBytecode,
        token: stateToken(postState),
      }).toString(),
    );
    assert.doesNotThrow(() => preparePf11Settlement(baseline.input));

    const mutations = [
      (pins) => {
        pins.verifierCarriers[0].baseValueSats = (
          BigInt(pins.verifierCarriers[0].baseValueSats) + 100n
        ).toString();
      },
      (pins) => {
        pins.bindingBaseSats = (
          BigInt(pins.bindingBaseSats) - 100n
        ).toString();
      },
      (pins) => {
        pins.stateBaseSats = (
          BigInt(pins.stateBaseSats) + 100n
        ).toString();
      },
    ];
    for (const mutate of mutations) {
      const fixture = makeFixture(kind, { mutatePins: mutate });
      assert.throws(
        () => preparePf11Settlement(fixture.input),
        (error) => error instanceof Pf11SettlementError
          && error.code === 'INVALID_BASE_VALUE',
      );
    }
  }
});

test('requires exactly one mutable zero-FT 128-byte state NFT', () => {
  for (const stateTokenOverrides of [
    { category: '33'.repeat(32) },
    { amount: 1n },
    { capability: 'minting' },
    { commitment: Buffer.alloc(127) },
  ]) {
    const fixture = makeFixture('deposit', { stateTokenOverrides });
    assert.throws(
      () => preparePf11Settlement(fixture.input),
      (error) =>
        error instanceof Pf11SettlementError
        && error.code === 'STATE_TOKEN_MISMATCH',
    );
  }
  const fixture = makeFixture('deposit', {
    mutateParentOutputs: (outputs) => {
      outputs[3].token = {
        category: Buffer.alloc(32, 0x77),
        amount: 1n,
      };
    },
  });
  assert.throws(
    () => preparePf11Settlement(fixture.input),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'TOKEN_ROLE_MISMATCH',
  );
});

test('enforces reserve delta, exact payout/change P2PKH, fee policy, and dust', () => {
  const invalidReserve = makeFixture('deposit', {
    postState: {
      ...states('deposit')[1],
      reserveSats: '0',
    },
  });
  assert.throws(
    () => preparePf11Settlement(invalidReserve.input),
    /reserveSats|reserve delta/,
  );
  const sameChange = makeFixture('transfer', {
    changeLockingBytecode: fundingLock(),
  });
  assert.throws(
    () => preparePf11Settlement(sameChange.input),
    /fresh P2PKH/,
  );
  const sameWithdrawalDestinations = makeFixture('withdrawal', {
    changeLockingBytecode: p2pkh(0x51),
  });
  assert.throws(
    () => preparePf11Settlement(sameWithdrawalDestinations.input),
    /payout and change locks must differ/,
  );
  const badPayout = makeFixture('withdrawal', {
    payoutLockingBytecode: Buffer.from([0x51]),
  });
  assert.throws(
    () => preparePf11Settlement(badPayout.input),
    /canonical P2PKH/,
  );
  const highFee = makeFixture('transfer', {
    feeRateSatsPerByte: '11',
  });
  const highFeePrepared = preparePf11Settlement(highFee.input);
  assert.equal(
    highFeePrepared.measurements.feeSats,
    (
      BigInt(highFeePrepared.measurements.signedSizeBytes) * 11n
    ).toString(),
  );
  const baseline = preparePf11Settlement(makeFixture('transfer').input);
  const dust = makeFixture('transfer', {
    fundingValue: BigInt(baseline.measurements.feeSats) + 545n,
  });
  assert.throws(
    () => preparePf11Settlement(dust.input),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'DUST_CHANGE',
  );
  assert.equal(PF11_P2PKH_DUST_SATS, '546');
});

test('freezes exact unlock lengths and canonical packet plus P2SH32 redeem input', () => {
  const fixture = makeFixture('transfer');
  const prepared = preparePf11Settlement(fixture.input);
  assert.throws(
    () => assemble(prepared, fixture, {
      verifierUnlockingBytecodes: [
        Buffer.alloc(2),
        ...Array.from(
          { length: PF11_CARRIER_COUNT - 1 },
          () => Buffer.from(DIRECT_UNLOCK),
        ),
      ],
    }),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'UNLOCKING_SIZE_MISMATCH',
  );
  assert.throws(
    () => assemble(prepared, fixture, {
      stateUnlockingBytecode: Buffer.alloc(2),
    }),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'UNLOCKING_SIZE_MISMATCH',
  );
  const wrongContextPacket = Buffer.from(packetFor(prepared, fixture));
  wrongContextPacket[551] ^= 1;
  assert.throws(
    () => assemble(prepared, fixture, {
      actionPacket: wrongContextPacket,
    }),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'TRANSACTION_CONTEXT_MISMATCH',
  );
  const assembled = assemble(prepared, fixture);
  const parsed = parseV2RawTransaction(assembled.unsignedTransactionHex);
  const binding = parsed.inputs[PF11_BINDING_INPUT_INDEX]
    .unlockingBytecode;
  assert.equal(
    binding.length,
    555 + encodeDataPush(fixture.input.pins.bindingRedeemBytecode).length,
  );
  assert.equal(
    Buffer.from(binding.subarray(3, 555)).toString('hex'),
    packetFor(prepared, fixture).toString('hex'),
  );
  assert.deepEqual(
    Buffer.from(binding.subarray(555)),
    Buffer.from(encodeDataPush(fixture.input.pins.bindingRedeemBytecode)),
  );
});

test('rejects oversized unlock plans and complete transactions above 100000 bytes', () => {
  const oversizedBinding = makeFixture('transfer', {
    mutatePins: (pins) => {
      const redeem = Buffer.alloc(9_443, 0x51);
      pins.bindingRedeemBytecode = redeem;
      pins.bindingLockingBytecode = Buffer.from(
        encodeLockingBytecodeP2sh32(hash256(redeem)),
      );
    },
  });
  assert.throws(
    () => preparePf11Settlement(oversizedBinding.input),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'UNLOCKING_SIZE_MISMATCH',
  );
  const perInput = makeFixture('transfer', {
    unlockingBytecodeLengths: {
      verifier: [10_001, ...Array(10).fill(1)],
      state: 1,
    },
  });
  assert.throws(
    () => preparePf11Settlement(perInput.input),
    /at most|through 10000/,
  );
  const aggregate = makeFixture('transfer', {
    fundingValue: 2_000_000n,
    unlockingBytecodeLengths: {
      verifier: Array(PF11_CARRIER_COUNT).fill(9_000),
      state: 1_000,
    },
  });
  assert.throws(
    () => preparePf11Settlement(aggregate.input),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'TRANSACTION_SIZE_LIMIT',
  );
});

test('detects prepared/assembled mutation and refuses signature or evidence fallback', async () => {
  const fixture = makeFixture('deposit');
  const prepared = preparePf11Settlement(fixture.input);
  assert.ok(Object.isFrozen(prepared));
  assert.ok(Object.isFrozen(prepared.measurements));
  const mutatedPrepared = clone(prepared);
  mutatedPrepared.measurements.feeSats =
    (BigInt(mutatedPrepared.measurements.feeSats) + 1n).toString();
  assert.throws(
    () => assemble(mutatedPrepared, fixture),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'PREPARED_SETTLEMENT_MUTATED',
  );

  const assembled = assemble(prepared, fixture);
  assert.ok(Object.isFrozen(assembled));
  const mutatedAssembly = clone(assembled);
  mutatedAssembly.signingRequest.digestHex = '00'.repeat(32);
  await assert.rejects(
    signPf11Settlement(mutatedAssembly, signerOptions()),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'ASSEMBLED_SETTLEMENT_MUTATED',
  );
  await assert.rejects(
    signPf11Settlement(assembled, {
      ...signerOptions(),
      signFunding: () => Buffer.alloc(64),
    }),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'INVALID_FUNDING_SIGNATURE',
  );
  await assert.rejects(
    signPf11Settlement(assembled, {
      signFunding: signerOptions().signFunding,
      createLocalVmEvidence: () => Buffer.from('{}'),
    }),
    (error) =>
      error instanceof Pf11SettlementError
      && [
        'INVALID_VM_EVIDENCE',
        'NON_CANONICAL_VM_EVIDENCE',
      ].includes(error.code),
  );
  await assert.rejects(
    signPf11Settlement(assembled, {
      signFunding: signerOptions().signFunding,
      createLocalVmEvidence: undefined,
    }),
    (error) =>
      error instanceof Pf11SettlementError
      && error.code === 'LOCAL_VM_EVIDENCE_PRODUCER_REQUIRED',
  );
});
