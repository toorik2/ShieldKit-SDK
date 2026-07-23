import { createHash } from 'node:crypto';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const DENOMINATION_SATOSHIS = 10_000_000n;

const op = Object.freeze({
  ZERO: 0x00,
  ONE: 0x51,
  TWO: 0x52,
  BEGIN: 0x65,
  UNTIL: 0x66,
  IF: 0x63,
  ELSE: 0x67,
  ENDIF: 0x68,
  VERIFY: 0x69,
  DEPTH: 0x74,
  DROP: 0x75,
  DUP: 0x76,
  NIP: 0x77,
  OVER: 0x78,
  PICK: 0x79,
  ROT: 0x7b,
  TUCK: 0x7d,
  SWAP: 0x7c,
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
  ONESUB: 0x8c,
  ADD: 0x93,
  SUB: 0x94,
  MUL: 0x95,
  NUMEQUAL: 0x9c,
  NUMEQUALVERIFY: 0x9d,
  NUMNOTEQUAL: 0x9e,
  WITHIN: 0xa5,
  SHA256: 0xa8,
  HASH160: 0xa9,
  TOALTSTACK: 0x6b,
  FROMALTSTACK: 0x6c,
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
  throw new Error('push exceeds PUSHDATA2');
}

function vmNumber(value) {
  if (!Number.isSafeInteger(value)) throw new Error('unsafe VM number');
  if (value === 0) return Buffer.of(op.ZERO);
  if (value >= 1 && value <= 16) return Buffer.of(0x50 + value);
  const negative = value < 0;
  let remaining = Math.abs(value);
  const bytes = [];
  while (remaining !== 0) {
    bytes.push(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
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

const emitNumber = (out, value) => emit(out, vmNumber(value));
const emitData = (out, value) => emit(out, push(value));
const emitRawData = (out, value) => {
  const bytes = Buffer.from(value);
  if (bytes.length <= 75) emit(out, Buffer.concat([Buffer.of(bytes.length), bytes]));
  else emitData(out, bytes);
};

function appendNoTokenHash(out, indexOpcodePrefix) {
  for (const introspectionOpcode of indexOpcodePrefix) {
    emit(out, op.OVER, introspectionOpcode, op.ZERO, op.EQUALVERIFY);
  }
  emit(out, op.ZERO, op.SHA256, op.CAT);
}

function appendStateTokenHash(
  out,
  categoryOpcode,
  commitmentOpcode,
  amountOpcode,
) {
  // OP_*TOKENCATEGORY yields wire-order category || capability. Require the
  // mutable capability (0x01), then construct the exact CashTokens prefix:
  // 0xef || category || 0x61 || CompactSize(80) || commitment.
  emit(out, op.OVER, categoryOpcode);
  emitNumber(out, 32);
  emit(out, op.SPLIT, op.ONE, op.EQUALVERIFY);
  emitData(out, Buffer.of(0xef));
  emit(out, op.SWAP, op.CAT);
  emitData(out, Buffer.of(0x61, 0x50));
  emit(out, op.CAT);
  emitNumber(out, 2);
  emit(out, op.PICK, commitmentOpcode, op.SIZE);
  emitNumber(out, 80);
  emit(out, op.NUMEQUALVERIFY, op.CAT);
  emitNumber(out, 2);
  emit(out, op.PICK, amountOpcode, op.ZERO, op.EQUALVERIFY);
  emit(out, op.SHA256, op.CAT);
}

function buildCanonicalTokenHashFunction() {
  const out = [];
  // Entry: [loopIndex, accumulator, categoryCapability, commitment, amount].
  // Exit:  [loopIndex, accumulator || SHA256(canonicalTokenPrefix)].
  emitNumber(out, 2);
  emit(out, op.PICK, op.IF);
  emit(out, op.ZERO, op.EQUALVERIFY, op.SIZE);
  emitNumber(out, 80);
  emit(out, op.NUMEQUALVERIFY, op.SWAP);
  emitNumber(out, 32);
  emit(out, op.SPLIT, op.ONE, op.EQUALVERIFY);
  emitData(out, Buffer.of(0xef));
  emit(out, op.SWAP, op.CAT);
  emitData(out, Buffer.of(0x61, 0x50));
  emit(out, op.CAT, op.SWAP, op.CAT, op.SHA256, op.CAT, op.ELSE);
  emit(out, op.CAT, op.CAT, op.ZERO, op.EQUALVERIFY);
  emit(out, op.ZERO, op.SHA256, op.CAT, op.ENDIF);
  return Uint8Array.from(out);
}

function appendCanonicalTokenHashViaFunction(
  out,
  categoryOpcode,
  commitmentOpcode,
  amountOpcode,
) {
  emit(out, op.OVER, categoryOpcode);
  emitNumber(out, 2);
  emit(out, op.PICK, commitmentOpcode);
  emitNumber(out, 3);
  emit(out, op.PICK, amountOpcode, op.ZERO, op.INVOKE);
}

/**
 * Build an executable loop-compressed reconstruction of SCCT v1.
 *
 * This script is intentionally a feasibility probe, not a complete binding
 * covenant. It derives the header from the authenticated SCAR, iterates all
 * ten input positions and every canonical output position, constructs exact
 * token-prefix hashes, and compares SHA256(SCCT) to SCAR[720:752].
 */
export function buildLoopScctLock({
  raw = false,
  tokenFunction = false,
  delegateTransactionShape = false,
  activeInputIndex = 7,
  loadPacketFromInput7 = false,
} = {}) {
  const out = [];

  if (tokenFunction) {
    emitData(out, buildCanonicalTokenHashFunction());
    emit(out, op.ZERO, op.DEFINE);
  }

  // In the coupled form, the exact pinned state covenant enforces these four
  // facts. The standalone form checks them here.
  if (!delegateTransactionShape) {
    emit(out, op.INPUTINDEX);
    emitNumber(out, activeInputIndex);
    emit(out, op.NUMEQUALVERIFY, op.TXVERSION);
    emitNumber(out, 2);
    emit(out, op.NUMEQUALVERIFY, op.TXLOCKTIME, op.ZERO, op.NUMEQUALVERIFY);
    emit(out, op.TXINPUTCOUNT);
    emitNumber(out, 10);
    emit(out, op.NUMEQUALVERIFY);
  }

  if (loadPacketFromInput7) {
    emitNumber(out, 7);
    emit(out, op.INPUTBYTECODE, op.SIZE);
    emitNumber(out, 755);
    emit(out, op.NUMEQUALVERIFY);
    emitNumber(out, 3);
    emit(out, op.SPLIT, op.SWAP);
    emitData(out, Buffer.of(0x4d, 0xf0, 0x02));
    emit(out, op.EQUALVERIFY);
  }

  // The packet must be exactly SCAR[752]. In direct input-7 mode, also
  // authenticate the exact PUSHDATA2 encoding of that stack item.
  emit(out, op.SIZE);
  emitNumber(out, 752);
  emit(out, op.NUMEQUALVERIFY);
  if (!loadPacketFromInput7) {
    emit(out, op.DUP);
    emitData(out, Buffer.of(0x4d, 0xf0, 0x02));
    emit(out, op.SWAP, op.CAT);
    emitNumber(out, 7);
    emit(out, op.INPUTBYTECODE, op.EQUALVERIFY);
  }

  // Actual output count must match the proof-constrained packet kind:
  // deposit/transfer -> 2, withdrawal -> 3.
  emit(out, op.DUP);
  emitNumber(out, 6);
  emit(out, op.SPLIT, op.NIP, op.ONE, op.SPLIT, op.DROP);
  emitNumber(out, 3);
  emit(out, op.NUMEQUAL);
  emitNumber(out, 2);
  emit(out, op.ADD, op.TXOUTPUTCOUNT, op.NUMEQUALVERIFY);

  // Retain SCAR for the final context-digest comparison and derive:
  // SCCT || SCAR[4:72] || u16le(10) || u16le(actual output count).
  emit(out, op.DUP, op.TOALTSTACK);
  emitNumber(out, 4);
  emit(out, op.SPLIT, op.NIP);
  emitNumber(out, 68);
  emit(out, op.SPLIT, op.DROP);
  emitData(out, Buffer.from('SCCT'));
  emit(out, op.SWAP, op.CAT);
  emitData(out, Buffer.of(10, 0));
  emit(out, op.CAT, op.TXOUTPUTCOUNT);
  emitNumber(out, 2);
  emit(out, op.NUM2BIN, op.CAT);

  // Stable loop stack is [index, accumulator].
  emit(out, op.ZERO, op.SWAP, op.BEGIN);
  emit(out, op.OVER);
  emitNumber(out, 1);
  emit(out, op.NUM2BIN, op.CAT);
  emit(out, op.OVER, op.OUTPOINTTXHASH, op.CAT);
  emit(out, op.OVER, op.OUTPOINTINDEX);
  emitNumber(out, 4);
  emit(out, op.NUM2BIN, op.CAT);
  emit(out, op.OVER, op.INPUTSEQUENCE, op.DUP, op.ZERO, op.NUMEQUALVERIFY);
  emitNumber(out, 4);
  emit(out, op.NUM2BIN, op.CAT);
  emit(out, op.OVER, op.UTXOVALUE);
  emitNumber(out, 8);
  emit(out, op.NUM2BIN, op.CAT);
  emit(out, op.OVER, op.UTXOBYTECODE, op.SHA256, op.CAT);

  if (tokenFunction) {
    appendCanonicalTokenHashViaFunction(
      out,
      op.UTXOTOKENCATEGORY,
      op.UTXOTOKENCOMMITMENT,
      op.UTXOTOKENAMOUNT,
    );
  } else {
    emit(out, op.OVER);
    emitNumber(out, 8);
    emit(out, op.NUMEQUAL, op.IF);
    appendStateTokenHash(
      out,
      op.UTXOTOKENCATEGORY,
      op.UTXOTOKENCOMMITMENT,
      op.UTXOTOKENAMOUNT,
    );
    emit(out, op.ELSE);
    appendNoTokenHash(out, [
      op.UTXOTOKENCATEGORY,
      op.UTXOTOKENCOMMITMENT,
      op.UTXOTOKENAMOUNT,
    ]);
    emit(out, op.ENDIF);
  }

  emit(out, op.SWAP, op.ONEADD, op.SWAP, op.OVER);
  emitNumber(out, 10);
  emit(out, op.NUMEQUAL, op.UNTIL, op.NIP);

  // Output role is 0 for state, otherwise outputCount-index:
  // [0,1] for deposit/transfer; [0,2,1] for withdrawal.
  emit(out, op.ZERO, op.SWAP, op.BEGIN);
  emit(out, op.OVER, op.DUP, op.IF, op.TXOUTPUTCOUNT, op.SWAP, op.SUB, op.ENDIF);
  emitNumber(out, 1);
  emit(out, op.NUM2BIN, op.CAT);
  emit(out, op.OVER, op.OUTPUTVALUE);
  emitNumber(out, 8);
  emit(out, op.NUM2BIN, op.CAT);
  emit(out, op.OVER, op.OUTPUTBYTECODE, op.SHA256, op.CAT);

  if (tokenFunction) {
    appendCanonicalTokenHashViaFunction(
      out,
      op.OUTPUTTOKENCATEGORY,
      op.OUTPUTTOKENCOMMITMENT,
      op.OUTPUTTOKENAMOUNT,
    );
  } else {
    emit(out, op.OVER, op.ZERO, op.NUMEQUAL, op.IF);
    appendStateTokenHash(
      out,
      op.OUTPUTTOKENCATEGORY,
      op.OUTPUTTOKENCOMMITMENT,
      op.OUTPUTTOKENAMOUNT,
    );
    emit(out, op.ELSE);
    appendNoTokenHash(out, [
      op.OUTPUTTOKENCATEGORY,
      op.OUTPUTTOKENCOMMITMENT,
      op.OUTPUTTOKENAMOUNT,
    ]);
    emit(out, op.ENDIF);
  }

  emit(out, op.SWAP, op.ONEADD, op.SWAP, op.OVER, op.TXOUTPUTCOUNT);
  emit(out, op.NUMEQUAL, op.UNTIL, op.NIP);

  if (raw) {
    emit(out, op.FROMALTSTACK, op.DROP);
  } else {
    emit(out, op.SHA256, op.FROMALTSTACK);
    emitNumber(out, 720);
    emit(out, op.SPLIT, op.NIP, op.EQUAL);
  }
  return Uint8Array.from(out);
}

function extractInputBytecodeSlice(out, start, length) {
  emitNumber(out, 7);
  emit(out, op.INPUTBYTECODE);
  emitNumber(out, start);
  emit(out, op.SPLIT, op.NIP);
  emitNumber(out, length);
  emit(out, op.SPLIT, op.DROP);
}

function appendExpectedPreCommitment(out) {
  emitData(out, Buffer.from('5348535401020000', 'hex'));
  extractInputBytecodeSlice(out, 43, 32);
  emit(out, op.CAT);
  extractInputBytecodeSlice(out, 171, 32);
  emit(out, op.CAT);
  extractInputBytecodeSlice(out, 143, 8);
  emit(out, op.CAT);
}

function appendExpectedPostCommitment(out) {
  // The relation constrains identical instance identity across both packet
  // states. Reusing the already-validated source commitment prefix/profile
  // saves thirteen locking bytes over reconstructing it again.
  emitNumber(out, 8);
  emit(out, op.UTXOTOKENCOMMITMENT);
  emitNumber(out, 40);
  emit(out, op.SPLIT, op.DROP);
  extractInputBytecodeSlice(out, 363, 32);
  emit(out, op.CAT);
  extractInputBytecodeSlice(out, 335, 8);
  emit(out, op.CAT);
}

/**
 * Build the smallest measured state-continuity covenant in this probe.
 *
 * It pins the exact binding lock by SHA-256, preserves its own locking
 * bytecode and the unique state category/capability/amount, binds pre/post NFT
 * commitments to the packet states, and preserves the denomination-adjusted
 * reserve delta. It relies only on checks explicitly executed by the pinned
 * binding lock: canonical input 7, global/input/output shape, exact SCCT, and
 * absence of tokens on every non-state input/output.
 */
export function buildStateContinuityLock({ bindingLock }) {
  const binding = Buffer.from(bindingLock);
  const out = [];

  emit(out, op.INPUTINDEX);
  emitNumber(out, 8);
  emit(out, op.NUMEQUALVERIFY);
  emit(out, op.TXVERSION);
  emitNumber(out, 2);
  emit(out, op.NUMEQUALVERIFY, op.TXLOCKTIME, op.ZERO, op.NUMEQUALVERIFY);
  emit(out, op.TXINPUTCOUNT);
  emitNumber(out, 10);
  emit(out, op.NUMEQUALVERIFY);
  emit(out, op.ACTIVEBYTECODE, op.ZERO, op.OUTPUTBYTECODE, op.EQUALVERIFY);

  emitNumber(out, 7);
  emit(out, op.UTXOBYTECODE, op.SHA256);
  emitData(out, sha256(binding));
  emit(out, op.EQUALVERIFY);

  // The authentic genesis outpoint identifies the category. Require a mutable
  // category at the consumed state and preserve those exact 33 bytes.
  emitNumber(out, 8);
  emit(out, op.UTXOTOKENCATEGORY);
  emitNumber(out, 32);
  emit(out, op.SPLIT, op.NIP, op.ONE, op.EQUALVERIFY);
  emitNumber(out, 8);
  emit(out, op.UTXOTOKENCATEGORY, op.ZERO, op.OUTPUTTOKENCATEGORY, op.EQUALVERIFY);
  emitNumber(out, 8);
  emit(out, op.UTXOTOKENAMOUNT, op.ZERO, op.EQUALVERIFY);
  emit(out, op.ZERO, op.OUTPUTTOKENAMOUNT, op.ZERO, op.EQUALVERIFY);

  appendExpectedPreCommitment(out);
  emitNumber(out, 8);
  emit(out, op.UTXOTOKENCOMMITMENT, op.EQUALVERIFY);
  appendExpectedPostCommitment(out);
  emit(out, op.ZERO, op.OUTPUTTOKENCOMMITMENT, op.EQUALVERIFY);

  // Packet kind must be 1..3. Preserve state value by:
  // output0 = input8 + denomination * (2-kind).
  extractInputBytecodeSlice(out, 9, 1);
  emit(out, op.BIN2NUM, op.DUP, op.ONE);
  emitNumber(out, 4);
  emit(out, op.WITHIN, op.VERIFY, op.TWO, op.SWAP, op.SUB);
  emitNumber(out, 10_000_000);
  emit(out, op.MUL);
  emitNumber(out, 8);
  emit(out, op.UTXOVALUE, op.ADD, op.ZERO, op.OUTPUTVALUE, op.NUMEQUALVERIFY);
  emit(out, op.ONE);
  return Uint8Array.from(out);
}

export function buildPacketOnlyBindingLock() {
  const out = [];
  emit(out, op.INPUTINDEX);
  emitNumber(out, 7);
  emit(out, op.NUMEQUALVERIFY, op.SIZE);
  emitNumber(out, 752);
  emit(out, op.NUMEQUALVERIFY, op.DUP);
  emitData(out, Buffer.of(0x4d, 0xf0, 0x02));
  emit(out, op.SWAP, op.CAT);
  emitNumber(out, 7);
  emit(out, op.INPUTBYTECODE, op.EQUALVERIFY, op.DROP, op.ONE);
  return Uint8Array.from(out);
}

function requirePacketSlice(out, start, length, expected) {
  extractInputBytecodeSlice(out, start, length);
  emitRawData(out, expected);
  emit(out, op.EQUALVERIFY);
}

// The G2 fee rule is consensus-critical: every action pays exactly one
// satoshi per final serialized byte. The four loops below derive that equality
// from BCH introspection rather than trusting a packet field or JS builder.
// Input count is fixed at 10. The sole tokenized output is state output 0;
// its canonical CashTokens prefix is 115 bytes: 0xef, 32-byte category plus
// mutable capability, 0x50 commitment length, 80-byte commitment, amount 0.
function appendCompactSizeLength(out) {
  // Entry/exit: [..., n] -> [..., CompactSize(n)]. All relevant scripts are
  // below 65536 bytes, so the only possible encodings are 1 or 3 bytes.
  emit(out, op.DUP, op.ZERO);
  emitNumber(out, 253);
  emit(out, op.WITHIN, op.IF, op.ONE, op.ELSE);
  emitNumber(out, 3);
  emit(out, op.ENDIF);
}

function appendInputValueSum(out) {
  // [index, sum], loop to total input satoshis.
  emit(out, op.ZERO, op.ZERO, op.BEGIN);
  emit(out, op.OVER, op.UTXOVALUE, op.SWAP, op.ADD);
  emit(out, op.SWAP, op.ONEADD, op.SWAP, op.OVER);
  emitNumber(out, 10);
  emit(out, op.NUMEQUAL, op.UNTIL, op.NIP);
}

function appendOutputValueSum(out) {
  // [index, sum], loop to total output satoshis.
  emit(out, op.ZERO, op.ZERO, op.BEGIN);
  emit(out, op.OVER, op.OUTPUTVALUE, op.SWAP, op.ADD);
  emit(out, op.SWAP, op.ONEADD, op.SWAP, op.OVER, op.TXOUTPUTCOUNT);
  emit(out, op.NUMEQUAL, op.UNTIL, op.NIP);
}

function appendInputWireBytes(out) {
  // Per input: 32-byte hash + 4-byte vout + CompactSize(unlock) + unlock +
  // 4-byte sequence. BCH-2026 introspection exposes the exact unlock bytes.
  emit(out, op.ZERO, op.ZERO, op.BEGIN);
  emit(out, op.OVER, op.INPUTBYTECODE, op.SIZE, op.NIP);
  appendCompactSizeLength(out);
  emit(out, op.ADD);
  emitNumber(out, 40);
  emit(out, op.ADD, op.SWAP, op.ADD);
  emit(out, op.SWAP, op.ONEADD, op.SWAP, op.OVER);
  emitNumber(out, 10);
  emit(out, op.NUMEQUAL, op.UNTIL, op.NIP);
}

function appendOutputWireBytes(out) {
  // Per output: value(8) + CompactSize(token prefix + lock) + token prefix
  // + lock. BCH encodes one combined field length, not separate token/script
  // lengths. All non-state tokens were already rejected by SCCT.
  emit(out, op.ZERO, op.ZERO, op.BEGIN);
  emit(out, op.OVER, op.ZERO, op.NUMEQUAL, op.IF);
  emitNumber(out, 115);
  emit(out, op.ELSE, op.ZERO, op.ENDIF, op.TOALTSTACK);
  emit(out, op.OVER, op.OUTPUTBYTECODE, op.SIZE, op.NIP, op.FROMALTSTACK, op.ADD);
  // This keeps the CompactSize derivation closed to its 1/3-byte branches and
  // bounds a withdrawal recipient script even when its hash is proof-bound.
  emit(out, op.DUP, op.ZERO);
  emitNumber(out, 10_001);
  emit(out, op.WITHIN, op.VERIFY);
  appendCompactSizeLength(out);
  emit(out, op.ADD);
  emitNumber(out, 8);
  emit(out, op.ADD, op.SWAP, op.ADD);
  emit(out, op.SWAP, op.ONEADD, op.SWAP, op.OVER, op.TXOUTPUTCOUNT);
  emit(out, op.NUMEQUAL, op.UNTIL, op.NIP);
}

function appendExactOneSatPerByteFee(out) {
  appendInputValueSum(out);
  emit(out, op.TOALTSTACK);
  appendOutputValueSum(out);
  emit(out, op.FROMALTSTACK, op.SWAP, op.SUB, op.TOALTSTACK);

  appendInputWireBytes(out);
  emit(out, op.TOALTSTACK);
  appendOutputWireBytes(out);
  emit(out, op.FROMALTSTACK, op.ADD);
  // version(4) + CompactSize(10 inputs)(1) + CompactSize(outputs)(1) +
  // locktime(4). Input/output counts are bounded below 253 by other checks.
  emitNumber(out, 10);
  emit(out, op.ADD, op.FROMALTSTACK, op.EQUALVERIFY);
}

/**
 * Full executable state/settlement helper for the hash-authenticated state
 * trampoline. Unlike a P2S lock, this helper is carried in input 8's unlocking
 * bytecode, so it is not subject to the 190-byte locking-bytecode limit.
 */
export function buildStateSettlementHelper({
  bindingLock,
  pf7Locks,
  pf7Values,
  bindingCarrierBaseSatoshis = 1_000,
}) {
  if (!Array.isArray(pf7Locks) || pf7Locks.length !== 7) {
    throw new Error('pf7Locks must contain exactly seven locking bytecodes');
  }
  if (
    !Array.isArray(pf7Values)
    || pf7Values.length !== 7
    || pf7Values.some((value) => (
      typeof value !== 'bigint'
      || value <= 0n
      || value > BigInt(Number.MAX_SAFE_INTEGER)
    ))
  ) {
    throw new Error('pf7Values must contain exactly seven positive VM-safe bigints');
  }
  if (
    !Number.isSafeInteger(bindingCarrierBaseSatoshis)
    || bindingCarrierBaseSatoshis <= 0
  ) {
    throw new Error('bindingCarrierBaseSatoshis must be a positive VM-safe integer');
  }
  if (Buffer.from(bindingLock).length === 0) {
    throw new Error('bindingLock must be nonempty');
  }
  const out = Array.from(buildLoopScctLock({
    activeInputIndex: 8,
    loadPacketFromInput7: true,
  }));
  emit(out, op.VERIFY);

  // The real relation authenticates these packet fields through the PF7
  // public-input seam; the helper independently fixes their canonical bytes.
  requirePacketSlice(out, 3, 6, Buffer.from('534341520102', 'hex'));
  requirePacketSlice(out, 10, 1, Buffer.of(0));
  // Preserve profile, instance, and reserve-cap identity across both packet
  // states without embedding post-profile bytes in this pre-profile kernel.
  // The state NFT commits to the instance ID, and the proof binds both state
  // preimages, so genesis selects the immutable instance and reserve cap.
  for (const [preOffset, postOffset, length] of [
    [11, 203, 32],
    [43, 235, 32],
    [163, 355, 8],
  ]) {
    extractInputBytecodeSlice(out, preOffset, length);
    extractInputBytecodeSlice(out, postOffset, length);
    emit(out, op.EQUALVERIFY);
  }

  // Pin every PF7 source lock and value. These checks are separate from SCCT
  // reconstruction because the context digest is proof-bound but otherwise
  // caller-selectable: a new proof must not authorize alternate carrier
  // funding.
  for (let index = 0; index < pf7Locks.length; index += 1) {
    emitNumber(out, index);
    emit(out, op.UTXOBYTECODE, op.SHA256);
    emitData(out, sha256(pf7Locks[index]));
    emit(out, op.EQUALVERIFY);
    emitNumber(out, index);
    emit(out, op.UTXOVALUE);
    emitNumber(out, Number(pf7Values[index]));
    emit(out, op.NUMEQUALVERIFY);
  }

  // Inputs 0..7 and 9 must be vouts 0..8 of one permissionless complete
  // preparation transaction. This prevents a valid proof from selecting or
  // subsidizing itself with another wallet's prepared PF7 carriers. Input 9's
  // signature remains consensus-verified by its P2PKH lock; the helper
  // authenticates its canonical structure, SIGHASH_ALL|FORKID byte,
  // pubkey-derived source lock, and same-key change.
  for (let index = 0; index < 7; index += 1) {
    emitNumber(out, index);
    emit(out, op.OUTPOINTTXHASH);
    emitNumber(out, 7);
    emit(out, op.OUTPOINTTXHASH, op.EQUALVERIFY);
    emitNumber(out, index);
    emit(out, op.OUTPOINTINDEX);
    emitNumber(out, index);
    emit(out, op.NUMEQUALVERIFY);
  }
  emitNumber(out, 7);
  emit(out, op.OUTPOINTTXHASH);
  emitNumber(out, 9);
  emit(out, op.OUTPOINTTXHASH, op.EQUALVERIFY);
  emitNumber(out, 7);
  emit(out, op.OUTPOINTINDEX);
  emitNumber(out, 7);
  emit(out, op.NUMEQUALVERIFY);
  emitNumber(out, 9);
  emit(out, op.OUTPOINTINDEX);
  emitNumber(out, 8);
  emit(out, op.NUMEQUALVERIFY);

  emitNumber(out, 9);
  emit(out, op.INPUTBYTECODE, op.SIZE);
  emitNumber(out, 100);
  emit(out, op.NUMEQUALVERIFY, op.DROP);
  // The next checks intentionally use input 9, not packet input 7.
  emitNumber(out, 9);
  emit(out, op.INPUTBYTECODE, op.ZERO, op.SPLIT, op.NIP, op.ONE, op.SPLIT, op.DROP);
  emitRawData(out, Buffer.of(0x41));
  emit(out, op.EQUALVERIFY);
  emitNumber(out, 9);
  emit(out, op.INPUTBYTECODE);
  emitNumber(out, 65);
  emit(out, op.SPLIT, op.NIP);
  emitNumber(out, 2);
  emit(out, op.SPLIT, op.DROP);
  emitRawData(out, Buffer.of(0x41, 0x21));
  emit(out, op.EQUALVERIFY);
  emitNumber(out, 9);
  emit(out, op.INPUTBYTECODE);
  emitNumber(out, 67);
  emit(out, op.SPLIT, op.NIP);
  emitNumber(out, 33);
  emit(out, op.SPLIT, op.DROP, op.DUP, op.HASH160);
  emitRawData(out, Buffer.from('76a914', 'hex'));
  emit(out, op.SWAP, op.CAT);
  emitRawData(out, Buffer.from('88ac', 'hex'));
  emit(out, op.CAT, op.DUP);
  emitNumber(out, 9);
  emit(out, op.UTXOBYTECODE, op.EQUALVERIFY, op.NIP, op.TXOUTPUTCOUNT);
  emit(out, op.ONESUB, op.OUTPUTBYTECODE, op.EQUALVERIFY);

  // Preserve the exact 32-byte category while requiring mutable capability at
  // input 8 and output 0. The SCCT loop rejects tokens at every other role.
  emitNumber(out, 8);
  emit(out, op.UTXOTOKENCATEGORY);
  emitNumber(out, 32);
  emit(out, op.SPLIT, op.ONE, op.EQUALVERIFY);
  emit(out, op.ZERO, op.OUTPUTTOKENCATEGORY);
  emitNumber(out, 32);
  emit(out, op.SPLIT, op.ONE, op.EQUALVERIFY, op.EQUALVERIFY);

  appendExpectedPreCommitment(out);
  emitNumber(out, 8);
  emit(out, op.UTXOTOKENCOMMITMENT, op.EQUALVERIFY);
  appendExpectedPostCommitment(out);
  emit(out, op.ZERO, op.OUTPUTTOKENCOMMITMENT, op.EQUALVERIFY);

  // output0 = input8 + denomination * (2-kind), with supported kinds 1..3.
  extractInputBytecodeSlice(out, 9, 1);
  emit(out, op.BIN2NUM, op.DUP, op.ONE);
  emitNumber(out, 4);
  emit(out, op.WITHIN, op.VERIFY, op.TWO, op.SWAP, op.SUB);
  emitNumber(out, 10_000_000);
  emit(out, op.MUL);
  emitNumber(out, 8);
  emit(out, op.UTXOVALUE, op.ADD, op.ZERO, op.OUTPUTVALUE, op.NUMEQUALVERIFY);

  // Input 7 carries the public deposit only for a deposit action.
  extractInputBytecodeSlice(out, 9, 1);
  emit(out, op.BIN2NUM, op.ONE, op.NUMEQUAL);
  emitNumber(out, 10_000_000);
  emit(out, op.MUL);
  emitNumber(out, bindingCarrierBaseSatoshis);
  emit(out, op.ADD);
  emitNumber(out, 7);
  emit(out, op.UTXOVALUE, op.NUMEQUALVERIFY);

  // The public boundary amount is D for deposit/withdrawal and zero for a
  // transfer. For withdrawal, output 1 is exactly D under the packet hash.
  extractInputBytecodeSlice(out, 9, 1);
  emit(out, op.BIN2NUM, op.TWO, op.NUMNOTEQUAL);
  emitNumber(out, 10_000_000);
  emit(out, op.MUL);
  extractInputBytecodeSlice(out, 683, 8);
  emit(out, op.BIN2NUM, op.NUMEQUALVERIFY);

  extractInputBytecodeSlice(out, 9, 1);
  emit(out, op.BIN2NUM);
  emitNumber(out, 3);
  emit(out, op.NUMEQUAL, op.IF, op.ONE, op.OUTPUTVALUE);
  emitNumber(out, 10_000_000);
  emit(out, op.NUMEQUALVERIFY, op.ONE, op.OUTPUTBYTECODE, op.SHA256);
  extractInputBytecodeSlice(out, 691, 32);
  emit(out, op.EQUALVERIFY, op.ENDIF);
  // Must execute after every value/token/shape constraint above. This binds
  // the actual fee, including a valid but overpaying re-proved packet, to the
  // exact serialized transaction length at the protocol's fixed rate.
  appendExactOneSatPerByteFee(out);
  emit(out, op.ONE);
  return Uint8Array.from(out);
}

export function buildStateTrampolineUnlock(helper) {
  return Uint8Array.from(push(helper));
}

export function buildStateTrampolineLock({ helper, bindingLock }) {
  const helperUnlock = buildStateTrampolineUnlock(helper);
  const out = [];
  emit(out, op.DEPTH, op.ONE, op.NUMEQUALVERIFY, op.INPUTINDEX);
  emitNumber(out, 8);
  emit(out, op.NUMEQUALVERIFY, op.ACTIVEBYTECODE, op.ZERO, op.OUTPUTBYTECODE);
  emit(out, op.EQUALVERIFY);
  emitNumber(out, 7);
  emit(out, op.UTXOBYTECODE, op.SHA256);
  emitData(out, sha256(bindingLock));
  emit(out, op.EQUALVERIFY);
  emitNumber(out, 8);
  emit(out, op.INPUTBYTECODE, op.SHA256);
  emitData(out, sha256(helperUnlock));
  emit(out, op.EQUALVERIFY, op.ZERO, op.TUCK, op.DEFINE, op.INVOKE);
  return Uint8Array.from(out);
}

export const internals = Object.freeze({ op, push, sha256, vmNumber });
