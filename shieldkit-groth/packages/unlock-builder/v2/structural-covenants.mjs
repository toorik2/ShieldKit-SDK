import { createHash } from 'node:crypto';
import {
  deriveDirectV2BindingP2sh32Lock,
  encodeDirectV2BindingUnlock,
} from '../../action/v2/binding-unlock.mjs';
import {
  DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
  resolveDirectV2VerifierTopology,
} from '../../action/v2/topology.mjs';

const HASH_32 = /^[0-9a-f]{64}$/;
const MAX_MONEY_SATS = 2_100_000_000_000_000n;

const op = Object.freeze({
  ZERO: 0x00,
  ONE: 0x51,
  TWO: 0x52,
  IF: 0x63,
  ELSE: 0x67,
  ENDIF: 0x68,
  VERIFY: 0x69,
  TOALTSTACK: 0x6b,
  FROMALTSTACK: 0x6c,
  TWO_DROP: 0x6d,
  TWO_DUP: 0x6e,
  DEPTH: 0x74,
  DROP: 0x75,
  DUP: 0x76,
  NIP: 0x77,
  OVER: 0x78,
  PICK: 0x79,
  ROT: 0x7b,
  SWAP: 0x7c,
  TUCK: 0x7d,
  CAT: 0x7e,
  SPLIT: 0x7f,
  NUM2BIN: 0x80,
  BIN2NUM: 0x81,
  SIZE: 0x82,
  EQUAL: 0x87,
  EQUALVERIFY: 0x88,
  DEFINE: 0x89,
  INVOKE: 0x8a,
  ONEADD: 0x8b,
  ADD: 0x93,
  SUB: 0x94,
  MUL: 0x95,
  NUMEQUAL: 0x9c,
  NUMEQUALVERIFY: 0x9d,
  NUMNOTEQUAL: 0x9e,
  LESSTHAN: 0x9f,
  GREATERTHAN: 0xa0,
  LESSTHANOREQUAL: 0xa1,
  GREATERTHANOREQUAL: 0xa2,
  WITHIN: 0xa5,
  SHA256: 0xa8,
  HASH160: 0xa9,
  INPUTINDEX: 0xc0,
  ACTIVEBYTECODE: 0xc1,
  TXVERSION: 0xc2,
  TXINPUTCOUNT: 0xc3,
  TXOUTPUTCOUNT: 0xc4,
  TXLOCKTIME: 0xc5,
  UTXOVALUE: 0xc6,
  UTXOBYTECODE: 0xc7,
  OUTPOINTTXHASH: 0xc8,
  OUTPOINTINDEX: 0xc9,
  INPUTBYTECODE: 0xca,
  INPUTSEQUENCE: 0xcb,
  OUTPUTVALUE: 0xcc,
  OUTPUTBYTECODE: 0xcd,
  UTXOTOKENCATEGORY: 0xce,
  UTXOTOKENCOMMITMENT: 0xcf,
  UTXOTOKENAMOUNT: 0xd0,
  OUTPUTTOKENCATEGORY: 0xd1,
  OUTPUTTOKENCOMMITMENT: 0xd2,
  OUTPUTTOKENAMOUNT: 0xd3,
});

export class DirectV2StructuralCovenantError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2StructuralCovenantError';
  }
}

const fail = (message) => {
  throw new DirectV2StructuralCovenantError(message);
};

const sha256 = (bytes) => createHash('sha256').update(bytes).digest();

function verifierTopology({
  topologyId = DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  verifierRoles = DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
} = {}) {
  try {
    return resolveDirectV2VerifierTopology({
      id: topologyId,
      verifierRoles,
    });
  } catch (error) {
    fail(`invalid verifier topology: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
}

function push(data) {
  const value = Buffer.from(data);
  if (value.length === 0) return Buffer.of(op.ZERO);
  if (value.length === 1 && value[0] === 0) return Buffer.of(op.ZERO);
  if (value.length === 1 && value[0] >= 1 && value[0] <= 16) {
    return Buffer.of(0x50 + value[0]);
  }
  if (value.length === 1 && value[0] === 0x81) return Buffer.of(0x4f);
  if (value.length <= 75) return Buffer.concat([Buffer.of(value.length), value]);
  if (value.length <= 255) {
    return Buffer.concat([Buffer.of(0x4c, value.length), value]);
  }
  if (value.length <= 65_535) {
    return Buffer.concat([
      Buffer.of(0x4d, value.length & 0xff, value.length >> 8),
      value,
    ]);
  }
  fail('push exceeds PUSHDATA2');
}

function vmNumber(value) {
  let remaining = BigInt(value);
  if (remaining === 0n) return Buffer.of(op.ZERO);
  if (remaining >= 1n && remaining <= 16n) {
    return Buffer.of(0x50 + Number(remaining));
  }
  const negative = remaining < 0n;
  if (negative) remaining = -remaining;
  const bytes = [];
  while (remaining !== 0n) {
    bytes.push(Number(remaining & 0xffn));
    remaining >>= 8n;
  }
  if ((bytes.at(-1) & 0x80) !== 0) bytes.push(negative ? 0x80 : 0);
  else if (negative) bytes[bytes.length - 1] |= 0x80;
  return push(Buffer.from(bytes));
}

const emit = (out, ...items) => {
  for (const item of items) {
    if (typeof item === 'number') out.push(item);
    else out.push(...item);
  }
};

const emitData = (out, value) => emit(out, push(value));
const emitNumber = (out, value) => emit(out, vmNumber(value));

function appendUnsignedFixedWidth(out, width) {
  // VM numbers are signed-magnitude. Encode one zero sign byte wider, then
  // retain the exact little-endian unsigned field, including a set high bit.
  emitNumber(out, width + 1);
  emit(out, op.NUM2BIN);
  emitNumber(out, width);
  emit(out, op.SPLIT, op.DROP);
}

function exactBytes(value, length, label) {
  const bytes = Buffer.from(value);
  if (bytes.length !== length) fail(`${label} must contain exactly ${length} bytes`);
  return bytes;
}

function exactP2sh32Lock(value, label) {
  const bytes = exactBytes(value, 35, label);
  if (bytes[0] !== 0xaa || bytes[1] !== 0x20 || bytes[34] !== op.EQUAL) {
    fail(`${label} must be canonical P2SH32 locking bytecode`);
  }
  return bytes;
}

function exactHash(value, label) {
  if (typeof value !== 'string' || !HASH_32.test(value)) {
    fail(`${label} must contain exactly 32 lowercase hexadecimal bytes`);
  }
  return Buffer.from(value, 'hex');
}

function positiveMoney(value, label) {
  const parsed = BigInt(value);
  if (parsed <= 0n || parsed > MAX_MONEY_SATS) {
    fail(`${label} must be a positive BCH monetary value`);
  }
  return parsed;
}

function packetSlice(out, offset, length, bindingInputIndex = 11) {
  emitNumber(out, bindingInputIndex);
  emit(out, op.INPUTBYTECODE);
  emitNumber(out, offset + 3);
  emit(out, op.SPLIT, op.NIP);
  emitNumber(out, length);
  emit(out, op.SPLIT, op.DROP);
}

function requirePacketSlice(
  out,
  offset,
  length,
  expected,
  bindingInputIndex = 11,
) {
  packetSlice(out, offset, length, bindingInputIndex);
  emitData(out, expected);
  emit(out, op.EQUALVERIFY);
}

function packetNumber(out, offset, length, bindingInputIndex = 11) {
  packetSlice(out, offset, length, bindingInputIndex);
  emitData(out, Buffer.of(0));
  emit(out, op.CAT, op.BIN2NUM);
}

function requireTokenlessInput(out, index) {
  for (const introspection of [
    op.UTXOTOKENCATEGORY,
    op.UTXOTOKENCOMMITMENT,
    op.UTXOTOKENAMOUNT,
  ]) {
    emitNumber(out, index);
    emit(out, introspection, op.ZERO, op.EQUALVERIFY);
  }
}

function requireTokenlessOutput(out, index) {
  for (const introspection of [
    op.OUTPUTTOKENCATEGORY,
    op.OUTPUTTOKENCOMMITMENT,
    op.OUTPUTTOKENAMOUNT,
  ]) {
    emitNumber(out, index);
    emit(out, introspection, op.ZERO, op.EQUALVERIFY);
  }
}

function appendInputTokenHash(out, index, stateCategoryCapability, state = false) {
  if (!state) {
    requireTokenlessInput(out, index);
    emit(out, op.ZERO, op.SHA256, op.CAT);
    return;
  }
  emitNumber(out, index);
  emit(out, op.UTXOTOKENCATEGORY);
  emitNumber(out, 32);
  emit(out, op.SPLIT, op.ONE, op.EQUALVERIFY, op.DUP);
  emitData(out, stateCategoryCapability.subarray(0, 32));
  emit(out, op.EQUALVERIFY);
  emitData(out, Buffer.of(0xef));
  emit(out, op.SWAP, op.CAT);
  emitData(out, Buffer.of(0x61, 0x80));
  emit(out, op.CAT);
  emitNumber(out, index);
  emit(out, op.UTXOTOKENCOMMITMENT, op.DUP, op.SIZE);
  emitNumber(out, 128);
  emit(out, op.NUMEQUALVERIFY, op.DROP, op.CAT);
  emitNumber(out, index);
  emit(out, op.UTXOTOKENAMOUNT, op.ZERO, op.NUMEQUALVERIFY);
  emit(out, op.SHA256, op.CAT);
}

function appendOutputTokenHash(out, index, stateCategoryCapability, state = false) {
  if (!state) {
    requireTokenlessOutput(out, index);
    emit(out, op.ZERO, op.SHA256, op.CAT);
    return;
  }
  emitNumber(out, index);
  emit(out, op.OUTPUTTOKENCATEGORY);
  emitNumber(out, 32);
  emit(out, op.SPLIT, op.ONE, op.EQUALVERIFY, op.DUP);
  emitData(out, stateCategoryCapability.subarray(0, 32));
  emit(out, op.EQUALVERIFY);
  emitData(out, Buffer.of(0xef));
  emit(out, op.SWAP, op.CAT);
  emitData(out, Buffer.of(0x61, 0x80));
  emit(out, op.CAT);
  emitNumber(out, index);
  emit(out, op.OUTPUTTOKENCOMMITMENT, op.DUP, op.SIZE);
  emitNumber(out, 128);
  emit(out, op.NUMEQUALVERIFY, op.DROP, op.CAT);
  emitNumber(out, index);
  emit(out, op.OUTPUTTOKENAMOUNT, op.ZERO, op.NUMEQUALVERIFY);
  emit(out, op.SHA256, op.CAT);
}

function roleBytes(kind, ordinal = 0) {
  const codes = Object.freeze({
    verifier: 1,
    binding: 2,
    state: 3,
    funding: 4,
    withdrawal: 5,
    change: 6,
  });
  return Buffer.of(codes[kind], ordinal, 0, 0);
}

function appendInputContextRecord(
  out,
  index,
  role,
  stateCategoryCapability,
  stateInputIndex,
) {
  emitData(out, role);
  emit(out, op.CAT);
  emitNumber(out, index);
  emit(out, op.OUTPOINTTXHASH, op.CAT);
  emitNumber(out, index);
  emit(out, op.OUTPOINTINDEX);
  appendUnsignedFixedWidth(out, 4);
  emit(out, op.CAT);
  emitNumber(out, index);
  emit(out, op.INPUTSEQUENCE);
  appendUnsignedFixedWidth(out, 4);
  emit(out, op.CAT);
  emitNumber(out, index);
  emit(out, op.UTXOVALUE);
  appendUnsignedFixedWidth(out, 8);
  emit(out, op.CAT);
  emitNumber(out, index);
  emit(out, op.UTXOBYTECODE, op.SHA256, op.CAT);
  appendInputTokenHash(
    out,
    index,
    stateCategoryCapability,
    index === stateInputIndex,
  );
}

function appendOutputContextRecord(
  out,
  index,
  role,
  stateCategoryCapability,
) {
  emitData(out, role);
  emit(out, op.CAT);
  emitNumber(out, index);
  emit(out, op.OUTPUTVALUE);
  appendUnsignedFixedWidth(out, 8);
  emit(out, op.CAT);
  emitNumber(out, index);
  emit(out, op.OUTPUTBYTECODE, op.SHA256, op.CAT);
  appendOutputTokenHash(out, index, stateCategoryCapability, index === 0);
}

function requireCanonicalP2pkh(out, index, output = false) {
  emitNumber(out, index);
  emit(out, output ? op.OUTPUTBYTECODE : op.UTXOBYTECODE, op.DUP, op.SIZE);
  emitNumber(out, 25);
  emit(out, op.NUMEQUALVERIFY);
  emitNumber(out, 3);
  emit(out, op.SPLIT, op.SWAP);
  emitData(out, Buffer.from('76a914', 'hex'));
  emit(out, op.EQUALVERIFY);
  emitNumber(out, 20);
  emit(out, op.SPLIT, op.NIP);
  emitData(out, Buffer.from('88ac', 'hex'));
  emit(out, op.EQUALVERIFY, op.DROP);
}

function requirePacketKindAndShape(out, topology) {
  packetNumber(out, 5, 1, topology.bindingInputIndex);
  emit(out, op.DUP, op.ONE);
  emitNumber(out, 4);
  emit(out, op.WITHIN, op.VERIFY, op.DUP);
  emitNumber(out, 3);
  emit(out, op.NUMEQUAL);
  emitNumber(out, topology.depositTransferOutputCount);
  emit(out, op.ADD, op.TXOUTPUTCOUNT, op.NUMEQUALVERIFY, op.DROP);
}

/**
 * Build the fixed, instance-specific binding redeem program for one exact,
 * protocol-defined verifier topology.
 *
 * The standard output is P2SH32. Its unlocking bytecode contains exactly two
 * canonical pushes: the 552-byte packet and this redeem program. The program
 * validates the packet/state/category seam, independently binds the complete
 * SHA-256 packet digest carried by the topology's exact digest role, and
 * reconstructs the exact SDC2 context from BCH introspection.
 */
function buildDirectV2BindingProgram({
  networkId,
  profileId,
  stateCategory,
  denominationSats,
  topologyId = DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  verifierRoles = DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
} = {}, contextProbe = false) {
  if (networkId !== 1 && networkId !== 2) fail('networkId must be 1 or 2');
  const topology = verifierTopology({ topologyId, verifierRoles });
  const profile = exactHash(profileId, 'profileId');
  const category = exactHash(stateCategory, 'stateCategory');
  const denomination = positiveMoney(denominationSats, 'denominationSats');
  const categoryCapability = Buffer.concat([category, Buffer.of(1)]);
  const out = [];

  emit(out, op.INPUTINDEX);
  emitNumber(out, topology.bindingInputIndex);
  emit(out, op.NUMEQUALVERIFY, op.TXVERSION);
  emitNumber(out, 2);
  emit(out, op.NUMEQUALVERIFY, op.TXLOCKTIME, op.ZERO, op.NUMEQUALVERIFY);
  emit(out, op.TXINPUTCOUNT);
  emitNumber(out, topology.inputCount);
  emit(out, op.NUMEQUALVERIFY);

  // P2SH32 removes the final redeem-program push before execution, so the
  // redeem program must begin with exactly one remaining stack item: packet.
  emit(out, op.DEPTH, op.ONE, op.NUMEQUALVERIFY);
  emit(out, op.SIZE);
  emitNumber(out, 552);
  emit(out, op.NUMEQUALVERIFY, op.DUP);
  emitData(out, Buffer.from('4d2802', 'hex'));
  emit(out, op.SWAP, op.CAT);
  emitNumber(out, topology.bindingInputIndex);
  emit(out, op.INPUTBYTECODE);
  emitNumber(out, 555);
  emit(out, op.SPLIT, op.DROP, op.EQUALVERIFY, op.DUP, op.SHA256);
  // The topology-pinned digest role carries the exact packet digest within
  // its fixed-width projection signal.
  emitNumber(out, topology.digestCarrierIndex);
  emit(out, op.INPUTBYTECODE);
  emitNumber(out, topology.digestPayloadOffset + 3);
  emit(out, op.SPLIT, op.NIP);
  emitNumber(out, 32);
  emit(out, op.SPLIT, op.DROP, op.EQUALVERIFY, op.DROP);

  requirePacketSlice(
    out,
    0,
    4,
    Buffer.from('SDA2'),
    topology.bindingInputIndex,
  );
  requirePacketSlice(
    out,
    4,
    1,
    Buffer.of(networkId),
    topology.bindingInputIndex,
  );
  requirePacketSlice(
    out,
    6,
    2,
    Buffer.alloc(2),
    topology.bindingInputIndex,
  );
  requirePacketSlice(
    out,
    8,
    32,
    category,
    topology.bindingInputIndex,
  );
  requirePacketSlice(
    out,
    40,
    4,
    Buffer.from('SKS2'),
    topology.bindingInputIndex,
  );
  requirePacketSlice(
    out,
    168,
    4,
    Buffer.from('SKS2'),
    topology.bindingInputIndex,
  );
  requirePacketSlice(
    out,
    44,
    32,
    profile,
    topology.bindingInputIndex,
  );
  requirePacketSlice(
    out,
    172,
    32,
    profile,
    topology.bindingInputIndex,
  );
  requirePacketKindAndShape(out, topology);

  // The packet embeds the exact source and successor NFT commitments.
  packetSlice(out, 40, 128, topology.bindingInputIndex);
  emitNumber(out, topology.stateInputIndex);
  emit(out, op.UTXOTOKENCOMMITMENT, op.EQUALVERIFY);
  packetSlice(out, 168, 128, topology.bindingInputIndex);
  emit(out, op.ZERO, op.OUTPUTTOKENCOMMITMENT, op.EQUALVERIFY);
  for (const [index, categoryOpcode, commitmentOpcode, amountOpcode] of [
    [
      topology.stateInputIndex,
      op.UTXOTOKENCATEGORY,
      op.UTXOTOKENCOMMITMENT,
      op.UTXOTOKENAMOUNT,
    ],
    [0, op.OUTPUTTOKENCATEGORY, op.OUTPUTTOKENCOMMITMENT, op.OUTPUTTOKENAMOUNT],
  ]) {
    emitNumber(out, index);
    emit(out, categoryOpcode);
    emitData(out, categoryCapability);
    emit(out, op.EQUALVERIFY);
    emitNumber(out, index);
    emit(out, commitmentOpcode, op.SIZE);
    emitNumber(out, 128);
    emit(out, op.NUMEQUALVERIFY, op.DROP);
    emitNumber(out, index);
    emit(out, amountOpcode, op.ZERO, op.NUMEQUALVERIFY);
  }

  // Canonical inactive packet fields and exact withdrawal destination.
  packetNumber(out, 5, 1, topology.bindingInputIndex);
  emit(out, op.DUP, op.ONE, op.NUMEQUAL, op.IF);
  requirePacketSlice(
    out,
    296,
    32,
    Buffer.alloc(32),
    topology.bindingInputIndex,
  );
  requirePacketSlice(
    out,
    488,
    32,
    Buffer.alloc(32),
    topology.bindingInputIndex,
  );
  emit(out, op.ELSE, op.DUP, op.TWO, op.NUMEQUAL, op.IF);
  requirePacketSlice(
    out,
    488,
    32,
    Buffer.alloc(32),
    topology.bindingInputIndex,
  );
  emit(out, op.ELSE);
  requirePacketSlice(
    out,
    328,
    160,
    Buffer.alloc(160),
    topology.bindingInputIndex,
  );
  emitNumber(out, topology.withdrawalOutputIndex);
  emit(out, op.OUTPUTVALUE);
  emitNumber(out, denomination);
  emit(out, op.NUMEQUALVERIFY);
  emitNumber(out, topology.withdrawalOutputIndex);
  emit(out, op.OUTPUTBYTECODE, op.SHA256);
  packetSlice(out, 488, 32, topology.bindingInputIndex);
  emit(out, op.EQUALVERIFY, op.ENDIF, op.ENDIF, op.DROP);

  // Build the exact 100-byte SDC2 header.
  emitData(out, Buffer.from('SDC2'));
  packetSlice(out, 4, 2, topology.bindingInputIndex);
  emit(out, op.CAT);
  emitData(out, Buffer.alloc(2));
  emit(out, op.CAT);
  emitData(out, profile);
  emit(out, op.CAT);
  emitData(out, category);
  emit(out, op.CAT, op.TXVERSION);
  appendUnsignedFixedWidth(out, 4);
  emit(out, op.CAT, op.TXLOCKTIME);
  appendUnsignedFixedWidth(out, 4);
  emit(out, op.CAT, op.TXINPUTCOUNT);
  appendUnsignedFixedWidth(out, 2);
  emit(out, op.CAT, op.TXOUTPUTCOUNT);
  appendUnsignedFixedWidth(out, 2);
  emit(out, op.CAT);
  packetSlice(out, 160, 8, topology.bindingInputIndex);
  emit(out, op.CAT);
  packetSlice(out, 288, 8, topology.bindingInputIndex);
  emit(out, op.CAT);

  for (let index = 0; index < topology.inputCount; index += 1) {
    const role = index < topology.carrierCount
      ? roleBytes('verifier', index)
      : index === topology.bindingInputIndex
        ? roleBytes('binding')
        : index === topology.stateInputIndex
          ? roleBytes('state')
          : roleBytes('funding');
    appendInputContextRecord(
      out,
      index,
      role,
      categoryCapability,
      topology.stateInputIndex,
    );
  }
  appendOutputContextRecord(out, 0, roleBytes('state'), categoryCapability);
  for (let index = 0; index < topology.carrierCount; index += 1) {
    appendOutputContextRecord(
      out,
      index + 1,
      roleBytes('verifier', index),
      categoryCapability,
    );
  }
  appendOutputContextRecord(
    out,
    topology.bindingOutputIndex,
    roleBytes('binding'),
    categoryCapability,
  );
  packetNumber(out, 5, 1, topology.bindingInputIndex);
  emitNumber(out, 3);
  emit(out, op.NUMEQUAL, op.IF);
  appendOutputContextRecord(
    out,
    topology.withdrawalOutputIndex,
    roleBytes('withdrawal'),
    categoryCapability,
  );
  appendOutputContextRecord(
    out,
    topology.changeOutputIndex,
    roleBytes('change'),
    categoryCapability,
  );
  emit(out, op.ELSE);
  appendOutputContextRecord(
    out,
    topology.withdrawalOutputIndex,
    roleBytes('change'),
    categoryCapability,
  );
  emit(out, op.ENDIF);
  if (!contextProbe) {
    emit(out, op.SHA256);
    packetSlice(out, 520, 32, topology.bindingInputIndex);
    emit(out, op.EQUAL);
  }
  return Uint8Array.from(out);
}

export function buildDirectV2BindingRedeem(options) {
  return buildDirectV2BindingProgram(options, false);
}

export function buildDirectV2BindingLock(options) {
  const redeem = buildDirectV2BindingRedeem(options);
  return deriveDirectV2BindingP2sh32Lock(redeem);
}

export function buildDirectV2BindingUnlock({
  packet,
  redeem,
} = {}) {
  const packetBytes = exactBytes(packet, 552, 'packet');
  const redeemBytes = Buffer.from(redeem ?? []);
  if (redeemBytes.length === 0) {
    fail('redeem must be nonempty');
  }
  try {
    return Uint8Array.from(encodeDirectV2BindingUnlock({
      packet: packetBytes,
      redeemScript: redeemBytes,
      sourceLockingBytecode:
        deriveDirectV2BindingP2sh32Lock(redeemBytes),
    }));
  } catch (error) {
    fail(`binding unlock is invalid: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
}

function requirePinnedInput(out, index, lock, value) {
  emitNumber(out, index);
  emit(out, op.UTXOBYTECODE, op.SHA256);
  emitData(out, sha256(lock));
  emit(out, op.EQUALVERIFY);
  emitNumber(out, index);
  emit(out, op.UTXOVALUE);
  emitNumber(out, value);
  emit(out, op.NUMEQUALVERIFY);
}

function requirePinnedOutput(out, index, lock, value) {
  emitNumber(out, index);
  emit(out, op.OUTPUTBYTECODE, op.SHA256);
  emitData(out, sha256(lock));
  emit(out, op.EQUALVERIFY);
  emitNumber(out, index);
  emit(out, op.OUTPUTVALUE);
  emitNumber(out, value);
  emit(out, op.NUMEQUALVERIFY);
}

function appendLiveCount(out, stateOffset, bindingInputIndex) {
  packetNumber(out, stateOffset + 100, 4, bindingInputIndex);
  packetNumber(out, stateOffset + 104, 4, bindingInputIndex);
  emit(out, op.SUB);
}

function requireStateInvariants(
  out,
  stateOffset,
  denomination,
  bindingInputIndex,
) {
  // nullifierCount <= noteCount; live <= maximumLiveNotes.
  appendLiveCount(out, stateOffset, bindingInputIndex);
  emit(out, op.DUP, op.ZERO, op.GREATERTHANOREQUAL, op.VERIFY, op.DUP);
  packetNumber(out, stateOffset + 108, 4, bindingInputIndex);
  emit(out, op.LESSTHANOREQUAL, op.VERIFY);
  // reserve = live * denomination.
  emitNumber(out, denomination);
  emit(out, op.MUL);
  packetNumber(out, stateOffset + 112, 8, bindingInputIndex);
  emit(out, op.NUMEQUALVERIFY);
  // maximumLiveNotes is positive and monetary-cap bounded.
  packetNumber(out, stateOffset + 108, 4, bindingInputIndex);
  emit(out, op.DUP, op.ZERO, op.GREATERTHAN, op.VERIFY);
  emitNumber(out, MAX_MONEY_SATS / denomination);
  emit(out, op.LESSTHANOREQUAL, op.VERIFY);
  // noteCount <= actionSequence <= noteCount + nullifierCount.
  packetNumber(out, stateOffset + 120, 8, bindingInputIndex);
  packetNumber(out, stateOffset + 100, 4, bindingInputIndex);
  emit(out, op.GREATERTHANOREQUAL, op.VERIFY);
  packetNumber(out, stateOffset + 120, 8, bindingInputIndex);
  packetNumber(out, stateOffset + 100, 4, bindingInputIndex);
  packetNumber(out, stateOffset + 104, 4, bindingInputIndex);
  emit(out, op.ADD, op.LESSTHANOREQUAL, op.VERIFY);
}

function requireStateTransition(out, denomination, bindingInputIndex) {
  requirePacketSlice(
    out,
    40,
    4,
    Buffer.from('SKS2'),
    bindingInputIndex,
  );
  requirePacketSlice(
    out,
    168,
    4,
    Buffer.from('SKS2'),
    bindingInputIndex,
  );
  // Immutable profile and capacity.
  packetSlice(out, 44, 32, bindingInputIndex);
  packetSlice(out, 172, 32, bindingInputIndex);
  emit(out, op.EQUALVERIFY);
  packetSlice(out, 148, 4, bindingInputIndex);
  packetSlice(out, 276, 4, bindingInputIndex);
  emit(out, op.EQUALVERIFY);
  // actionSequence increments exactly once.
  packetNumber(out, 160, 8, bindingInputIndex);
  emit(out, op.ONEADD);
  packetNumber(out, 288, 8, bindingInputIndex);
  emit(out, op.NUMEQUALVERIFY);
  requireStateInvariants(out, 40, denomination, bindingInputIndex);
  requireStateInvariants(out, 168, denomination, bindingInputIndex);

  packetNumber(out, 5, 1, bindingInputIndex);
  emit(out, op.DUP, op.ONE, op.NUMEQUAL, op.IF);
  // deposit: note +1, nullifier/root unchanged, capacity available, reserve +D.
  packetNumber(out, 140, 4, bindingInputIndex);
  emit(out, op.ONEADD);
  packetNumber(out, 268, 4, bindingInputIndex);
  emit(out, op.NUMEQUALVERIFY);
  packetSlice(out, 144, 4, bindingInputIndex);
  packetSlice(out, 272, 4, bindingInputIndex);
  emit(out, op.EQUALVERIFY);
  packetSlice(out, 108, 32, bindingInputIndex);
  packetSlice(out, 236, 32, bindingInputIndex);
  emit(out, op.EQUALVERIFY);
  appendLiveCount(out, 40, bindingInputIndex);
  packetNumber(out, 148, 4, bindingInputIndex);
  emit(out, op.LESSTHAN, op.VERIFY);
  packetNumber(out, 152, 8, bindingInputIndex);
  emitNumber(out, denomination);
  emit(out, op.ADD);
  packetNumber(out, 280, 8, bindingInputIndex);
  emit(out, op.NUMEQUALVERIFY);
  emit(out, op.ELSE, op.DUP, op.TWO, op.NUMEQUAL, op.IF);
  // transfer: one consumed and one produced note, reserve unchanged.
  packetNumber(out, 140, 4, bindingInputIndex);
  emit(out, op.ONEADD);
  packetNumber(out, 268, 4, bindingInputIndex);
  emit(out, op.NUMEQUALVERIFY);
  packetNumber(out, 144, 4, bindingInputIndex);
  emit(out, op.ONEADD);
  packetNumber(out, 272, 4, bindingInputIndex);
  emit(out, op.NUMEQUALVERIFY);
  appendLiveCount(out, 40, bindingInputIndex);
  emit(out, op.ZERO, op.GREATERTHAN, op.VERIFY);
  packetSlice(out, 152, 8, bindingInputIndex);
  packetSlice(out, 280, 8, bindingInputIndex);
  emit(out, op.EQUALVERIFY);
  emit(out, op.ELSE);
  // withdrawal: nullifier +1, note/root unchanged, reserve -D.
  packetSlice(out, 140, 4, bindingInputIndex);
  packetSlice(out, 268, 4, bindingInputIndex);
  emit(out, op.EQUALVERIFY);
  packetNumber(out, 144, 4, bindingInputIndex);
  emit(out, op.ONEADD);
  packetNumber(out, 272, 4, bindingInputIndex);
  emit(out, op.NUMEQUALVERIFY);
  packetSlice(out, 76, 32, bindingInputIndex);
  packetSlice(out, 204, 32, bindingInputIndex);
  emit(out, op.EQUALVERIFY);
  appendLiveCount(out, 40, bindingInputIndex);
  emit(out, op.ZERO, op.GREATERTHAN, op.VERIFY);
  packetNumber(out, 280, 8, bindingInputIndex);
  emitNumber(out, denomination);
  emit(out, op.ADD);
  packetNumber(out, 152, 8, bindingInputIndex);
  emit(out, op.NUMEQUALVERIFY, op.ENDIF, op.ENDIF, op.DROP);
}

/**
 * Build the full topology-derived structural/state helper. The tiny state lock
 * commits
 * to this helper's canonical push, allowing a large P2S program without a
 * cyclic lock graph: this helper pins every verifier lock, while verifier
 * locks authenticate the unique state category rather than the state lock.
 */
export function buildDirectV2StateHelper({
  bindingLock,
  verifierLocks,
  verifierBaseValues,
  bindingBaseValueSats,
  stateBaseValueSats,
  denominationSats,
  stateCategory,
  minimumChangeSats,
  topologyId = DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  verifierRoles = DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
} = {}) {
  const topology = verifierTopology({ topologyId, verifierRoles });
  const binding = exactP2sh32Lock(bindingLock, 'bindingLock');
  if (
    !Array.isArray(verifierLocks)
    || verifierLocks.length !== topology.carrierCount
  ) {
    fail(
      `verifierLocks must contain exactly ${topology.carrierCount} locks`,
    );
  }
  if (
    !Array.isArray(verifierBaseValues)
    || verifierBaseValues.length !== topology.carrierCount
  ) {
    fail(
      `verifierBaseValues must contain exactly ${topology.carrierCount} values`,
    );
  }
  const locks = verifierLocks.map((lock, index) => {
    const bytes = Buffer.from(lock);
    if (bytes.length === 0 || bytes.length > 10_000) {
      fail(`verifierLocks[${index}] is not a nonempty standard-sized bytecode`);
    }
    return bytes;
  });
  const values = verifierBaseValues.map((value, index) => (
    positiveMoney(value, `verifierBaseValues[${index}]`)
  ));
  const bindingValue = positiveMoney(bindingBaseValueSats, 'bindingBaseValueSats');
  const stateBase = positiveMoney(stateBaseValueSats, 'stateBaseValueSats');
  const denomination = positiveMoney(denominationSats, 'denominationSats');
  const minimumChange = positiveMoney(minimumChangeSats, 'minimumChangeSats');
  const category = exactHash(stateCategory, 'stateCategory');
  const categoryCapability = Buffer.concat([category, Buffer.of(1)]);
  const out = [];

  emit(out, op.TXVERSION);
  emitNumber(out, 2);
  emit(out, op.NUMEQUALVERIFY, op.TXLOCKTIME, op.ZERO, op.NUMEQUALVERIFY);
  emit(out, op.TXINPUTCOUNT);
  emitNumber(out, topology.inputCount);
  emit(out, op.NUMEQUALVERIFY);
  requirePacketKindAndShape(out, topology);
  requirePacketSlice(
    out,
    0,
    4,
    Buffer.from('SDA2'),
    topology.bindingInputIndex,
  );
  requirePacketSlice(
    out,
    8,
    32,
    category,
    topology.bindingInputIndex,
  );
  packetSlice(out, 40, 128, topology.bindingInputIndex);
  emitNumber(out, topology.stateInputIndex);
  emit(out, op.UTXOTOKENCOMMITMENT, op.EQUALVERIFY);
  packetSlice(out, 168, 128, topology.bindingInputIndex);
  emit(out, op.ZERO, op.OUTPUTTOKENCOMMITMENT, op.EQUALVERIFY);

  // All rolling sources share the exact immediately preceding bundle.
  for (let index = 0; index <= topology.bindingInputIndex; index += 1) {
    emitNumber(out, index);
    emit(out, op.OUTPOINTTXHASH);
    emitNumber(out, topology.stateInputIndex);
    emit(out, op.OUTPOINTTXHASH, op.EQUALVERIFY);
    emitNumber(out, index);
    emit(out, op.OUTPOINTINDEX);
    emitNumber(out, index + 1);
    emit(out, op.NUMEQUALVERIFY);
  }
  emitNumber(out, topology.stateInputIndex);
  emit(out, op.OUTPOINTINDEX, op.ZERO, op.NUMEQUALVERIFY);

  // Exact source and successor carrier bundle.
  for (let index = 0; index < topology.carrierCount; index += 1) {
    requirePinnedInput(out, index, locks[index], values[index]);
    requirePinnedOutput(out, index + 1, locks[index], values[index]);
    requireTokenlessInput(out, index);
    requireTokenlessOutput(out, index + 1);
  }
  requirePinnedInput(
    out,
    topology.bindingInputIndex,
    binding,
    bindingValue,
  );
  requirePinnedOutput(
    out,
    topology.bindingOutputIndex,
    binding,
    bindingValue,
  );
  requireTokenlessInput(out, topology.bindingInputIndex);
  requireTokenlessOutput(out, topology.bindingOutputIndex);

  // Unique mutable state NFT and self-preserving state program.
  emitNumber(out, topology.stateInputIndex);
  emit(out, op.UTXOTOKENCATEGORY);
  emitData(out, categoryCapability);
  emit(out, op.EQUALVERIFY);
  emit(out, op.ZERO, op.OUTPUTTOKENCATEGORY);
  emitData(out, categoryCapability);
  emit(out, op.EQUALVERIFY);
  emitNumber(out, topology.stateInputIndex);
  emit(out, op.UTXOTOKENAMOUNT, op.ZERO, op.NUMEQUALVERIFY);
  emit(out, op.ZERO, op.OUTPUTTOKENAMOUNT, op.ZERO, op.NUMEQUALVERIFY);
  emitNumber(out, topology.stateInputIndex);
  emit(out, op.UTXOTOKENCOMMITMENT, op.SIZE);
  emitNumber(out, 128);
  emit(out, op.NUMEQUALVERIFY, op.DROP);
  emit(out, op.ZERO, op.OUTPUTTOKENCOMMITMENT, op.SIZE);
  emitNumber(out, 128);
  emit(out, op.NUMEQUALVERIFY, op.DROP);
  requireStateTransition(out, denomination, topology.bindingInputIndex);
  packetNumber(out, 152, 8, topology.bindingInputIndex);
  emitNumber(out, stateBase);
  emit(out, op.ADD);
  emitNumber(out, topology.stateInputIndex);
  emit(out, op.UTXOVALUE, op.NUMEQUALVERIFY);
  packetNumber(out, 280, 8, topology.bindingInputIndex);
  emitNumber(out, stateBase);
  emit(out, op.ADD, op.ZERO, op.OUTPUTVALUE, op.NUMEQUALVERIFY);

  // One tokenless P2PKH source signs ALL|UTXOS|FORKID (0x61).
  requireTokenlessInput(out, topology.fundingInputIndex);
  requireCanonicalP2pkh(out, topology.fundingInputIndex);
  emitNumber(out, topology.fundingInputIndex);
  emit(out, op.INPUTBYTECODE, op.DUP, op.SIZE);
  emitNumber(out, 100);
  emit(out, op.NUMEQUALVERIFY);
  emit(out, op.DUP, op.ZERO, op.SPLIT, op.NIP, op.ONE, op.SPLIT, op.DROP);
  emitData(out, Buffer.of(0x41));
  emit(out, op.EQUALVERIFY, op.DUP);
  emitNumber(out, 65);
  emit(out, op.SPLIT, op.NIP, op.ONE, op.SPLIT, op.DROP);
  emitData(out, Buffer.of(0x61));
  emit(out, op.EQUALVERIFY, op.DUP);
  emitNumber(out, 66);
  emit(out, op.SPLIT, op.NIP, op.ONE, op.SPLIT, op.DROP);
  emitData(out, Buffer.of(0x21));
  emit(out, op.EQUALVERIFY);
  emitNumber(out, 67);
  emit(out, op.SPLIT, op.NIP);
  emitNumber(out, 33);
  emit(out, op.SPLIT, op.DROP, op.HASH160);
  emitNumber(out, topology.fundingInputIndex);
  emit(out, op.UTXOBYTECODE);
  emitNumber(out, 3);
  emit(out, op.SPLIT, op.NIP);
  emitNumber(out, 20);
  emit(out, op.SPLIT, op.DROP, op.EQUALVERIFY, op.DROP);

  // Exact payout/change topology and fee isolation to the funding UTXO.
  packetNumber(out, 5, 1, topology.bindingInputIndex);
  emit(out, op.DUP);
  emitNumber(out, 3);
  emit(out, op.NUMEQUAL, op.IF);
  requireTokenlessOutput(out, topology.withdrawalOutputIndex);
  requireCanonicalP2pkh(out, topology.withdrawalOutputIndex, true);
  emitNumber(out, topology.withdrawalOutputIndex);
  emit(out, op.OUTPUTVALUE);
  emitNumber(out, denomination);
  emit(out, op.NUMEQUALVERIFY);
  requireTokenlessOutput(out, topology.changeOutputIndex);
  requireCanonicalP2pkh(out, topology.changeOutputIndex, true);
  emitNumber(out, topology.changeOutputIndex);
  emit(out, op.OUTPUTVALUE, op.DUP);
  emitNumber(out, minimumChange);
  emit(out, op.GREATERTHANOREQUAL, op.VERIFY);
  emitNumber(out, topology.fundingInputIndex);
  emit(out, op.UTXOVALUE, op.SWAP, op.GREATERTHAN, op.VERIFY);
  emit(out, op.DROP);
  emit(out, op.ELSE);
  requireTokenlessOutput(out, topology.withdrawalOutputIndex);
  requireCanonicalP2pkh(out, topology.withdrawalOutputIndex, true);
  emitNumber(out, topology.withdrawalOutputIndex);
  emit(out, op.OUTPUTVALUE, op.DUP);
  emitNumber(out, minimumChange);
  emit(out, op.GREATERTHANOREQUAL, op.VERIFY);
  // A deposit additionally funds D; transfer funds only its fee.
  emit(out, op.SWAP, op.ONE, op.NUMEQUAL, op.IF);
  emitNumber(out, denomination);
  emit(out, op.ELSE, op.ZERO, op.ENDIF, op.ADD);
  emitNumber(out, topology.fundingInputIndex);
  emit(out, op.UTXOVALUE, op.SWAP, op.GREATERTHAN, op.VERIFY);
  emit(out, op.ENDIF, op.ONE);
  return Uint8Array.from(out);
}

export function buildDirectV2StateTrampolineUnlock(helper) {
  const bytes = Buffer.from(helper);
  if (bytes.length === 0 || bytes.length > 9_996) {
    fail('state helper cannot fit the 10,000-byte unlocking limit');
  }
  return Uint8Array.from(push(bytes));
}

export function buildDirectV2StateTrampolineLock({
  helper,
  bindingLock,
  topologyId = DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  verifierRoles = DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
} = {}) {
  const topology = verifierTopology({ topologyId, verifierRoles });
  const helperUnlock = Buffer.from(buildDirectV2StateTrampolineUnlock(helper));
  const binding = exactP2sh32Lock(bindingLock, 'bindingLock');
  const out = [];
  emit(out, op.DEPTH, op.ONE, op.NUMEQUALVERIFY, op.INPUTINDEX);
  emitNumber(out, topology.stateInputIndex);
  emit(out, op.NUMEQUALVERIFY, op.ACTIVEBYTECODE, op.ZERO, op.OUTPUTBYTECODE);
  emit(out, op.EQUALVERIFY);
  emitNumber(out, topology.bindingInputIndex);
  emit(out, op.UTXOBYTECODE, op.SHA256);
  emitData(out, sha256(binding));
  emit(out, op.EQUALVERIFY);
  emitNumber(out, topology.stateInputIndex);
  emit(out, op.INPUTBYTECODE, op.SHA256);
  emitData(out, sha256(helperUnlock));
  emit(out, op.EQUALVERIFY, op.ZERO, op.TUCK, op.DEFINE, op.INVOKE);
  return Uint8Array.from(out);
}

export const structuralCovenantInternals = Object.freeze({
  buildBindingContextProbe: (options) => (
    buildDirectV2BindingProgram(options, true)
  ),
  buildP2sh32Lock: (redeem) => (
    deriveDirectV2BindingP2sh32Lock(Buffer.from(redeem))
  ),
  op,
  packetSlice,
  push,
  sha256,
  vmNumber,
});
