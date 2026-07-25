// Consensus-valid BCH-2026 code-library plumbing for the research verifier.
//
// OP_EVAL is deliberately not used: Libauth documents it as experimental and non-consensus.
// OP_DEFINE/OP_INVOKE, by contrast, are BCH-2026 consensus operations.  A library input commits
// to function bodies and balanced verifier chunks with a fixed hash chain.  Follower inputs read
// the library's raw unlocking bytecode with OP_INPUTBYTECODE, define those already-committed
// bodies, and invoke the chunks.  The library spend itself is a P2SH32 hash-chain check; it is
// not a bypass input and is included in every VM/reproducibility measurement.
import { createHash } from 'node:crypto';
import {
  decodeAuthenticationInstructions,
  encodeAuthenticationInstruction,
  OpcodesBchSpec,
} from '../node_modules/@bitauth/libauth/build/index.js';
import { Asm, pushBytes } from '../fri_stark/asm.mjs';

const sha256 = (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest());
export const hash256 = (bytes) => sha256(sha256(bytes));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};

// Split only at top-level control-flow boundaries.  Each returned body is a valid standalone
// OP_INVOKE function (<=520 bytes), so no OP_IF/OP_BEGIN control frame is left open across a
// function return.  The bytecode is re-encoded instruction-by-instruction to avoid splitting in
// the middle of a push payload.
// Keep a little headroom below the consensus 520-byte stack-item limit.  A chunk boundary can
// be delayed by a short OP_IF/OP_BEGIN region; the resulting balanced body may therefore be a
// few bytes larger than the target, but it must still remain <= 520 bytes.
export const MAX_FUNCTION_BODY_BYTES = 520;
export function splitTopLevelBytecode(bytecode, chunkTargetBytes = 500) {
  if (!Number.isInteger(chunkTargetBytes) || chunkTargetBytes < 1 || chunkTargetBytes > MAX_FUNCTION_BODY_BYTES) {
    throw new Error(`invalid dynamic chunk target ${chunkTargetBytes}`);
  }
  const instructions = decodeAuthenticationInstructions(bytecode);
  const chunks = [];
  let current = [];
  let currentBytes = 0;
  let controlDepth = 0;
  const flush = () => {
    if (current.length === 0) return;
    const body = Uint8Array.from(current.flatMap((instruction) => [...instruction]));
    if (body.length > MAX_FUNCTION_BODY_BYTES) throw new Error(`dynamic verifier chunk exceeds ${MAX_FUNCTION_BODY_BYTES} bytes: ${body.length}`);
    chunks.push(body);
    current = [];
    currentBytes = 0;
  };
  for (const instruction of instructions) {
    if ('malformed' in instruction) throw new Error('cannot chunk malformed verifier bytecode');
    const encoded = encodeAuthenticationInstruction(instruction);
    if (encoded.length > MAX_FUNCTION_BODY_BYTES) throw new Error(`single verifier instruction exceeds ${MAX_FUNCTION_BODY_BYTES} bytes`);
    if (currentBytes + encoded.length > chunkTargetBytes && controlDepth === 0) {
      flush();
    }
    current.push(encoded);
    currentBytes += encoded.length;
    if (instruction.opcode === OpcodesBchSpec.OP_IF || instruction.opcode === OpcodesBchSpec.OP_NOTIF || instruction.opcode === OpcodesBchSpec.OP_BEGIN) controlDepth += 1;
    if (instruction.opcode === OpcodesBchSpec.OP_ENDIF || instruction.opcode === OpcodesBchSpec.OP_UNTIL) controlDepth -= 1;
    if (controlDepth < 0) throw new Error('unbalanced verifier control flow');
  }
  flush();
  if (controlDepth !== 0) throw new Error('unbalanced verifier control flow at end of program');
  return chunks;
}

// The digest is intentionally a chain over individual item hashes.  It never concatenates a
// witness item larger than the BCH stack-item cap; the expected final digest is the only static
// commitment in the library locking program.
export function itemDigest(items) {
  let state;
  for (const item of items) {
    if (!Number.isInteger(item.id) || item.id < 0 || item.id > 255) throw new Error(`library item id out of byte range: ${item.id}`);
    // Commit the identifier as well as the body.  The loader's OP_DEFINE identifier is part of
    // verifier semantics; hashing only the body would let an artifact accidentally relabel a
    // committed function without changing the library digest.
    const itemHash = hash256(concat(Uint8Array.of(item.id), item.bytes));
    state = state === undefined ? itemHash : hash256(concat(state, itemHash));
  }
  if (state === undefined) throw new Error('library must contain at least one committed item');
  return state;
}

// Build the library's redeem script.  The unlocking pushes items in reverse expected order, so
// the top stack item is item[0].  The script consumes exactly the committed item count and fails
// closed on missing or extra stack items via the final P2SH stack-shape rule.
export function buildLibraryRedeem(items, { inputIndex, totalInputs, digest }) {
  if (!Number.isInteger(inputIndex) || inputIndex < 0) throw new Error('library input index required');
  if (!Number.isInteger(totalInputs) || totalInputs < 1) throw new Error('library total input count required');
  const expected = digest ?? itemDigest(items);
  const a = new Asm();
  a.o('OP_INPUTINDEX').num(inputIndex).o('OP_NUMEQUALVERIFY');
  a.o('OP_TXINPUTCOUNT').num(totalInputs).o('OP_NUMEQUALVERIFY');
  a.push(Uint8Array.of(items[0].id)).o('OP_SWAP').o('OP_CAT').o('OP_HASH256').o('OP_TOALTSTACK');
  for (let i = 1; i < items.length; i++) {
    a.push(Uint8Array.of(items[i].id)).o('OP_SWAP').o('OP_CAT').o('OP_HASH256');
    a.o('OP_FROMALTSTACK').o('OP_SWAP').o('OP_CAT').o('OP_HASH256').o('OP_TOALTSTACK');
  }
  a.o('OP_FROMALTSTACK').push(expected).o('OP_EQUALVERIFY').num(1);
  return a.bytecode();
}

export function buildLibraryUnlocking(items, redeem) {
  const a = new Asm();
  for (let i = items.length - 1; i >= 0; i--) a.push(items[i].bytes);
  a.push(redeem);
  return a.bytecode();
}

// Parse the library's raw unlocking bytecode and define each item.  The raw order is the reverse
// of `items`; each body/chunk is peeled with fixed push-header and payload lengths, then assigned
// its fixed function identifier.  The trailing P2SH redeem push is dropped after all definitions.
export function buildDynamicLoader(items, libraryInputIndex) {
  if (!Number.isInteger(libraryInputIndex) || libraryInputIndex < 0) throw new Error('library input index required');
  const a = new Asm();
  a.num(libraryInputIndex).o('OP_INPUTBYTECODE');
  for (let i = items.length - 1; i >= 0; i--) {
    const item = items[i];
    const encodedPush = pushBytes(item.bytes);
    // Canonical pushes for OP_0, OP_1NEGATE, and OP_1..OP_16 are a single
    // opcode with no payload bytes.  Peel the opcode as one byte and push the
    // semantic body explicitly; treating item.bytes.length as raw bytes would
    // consume the next item and turn (for example) 1 into 0x51.
    if (encodedPush.length === 1) {
      a.num(1).o('OP_SPLIT').o('OP_NIP');
      a.push(item.bytes);
      a.num(item.id).o('OP_DEFINE');
      continue;
    }
    const headerLength = encodedPush.length - item.bytes.length;
    // OP_SPLIT leaves the right-hand remainder on top; swap before dropping the
    // left-hand push header so the remainder remains available for the next item.
    // OP_SPLIT leaves [header, remainder]; OP_NIP removes the header directly
    // and avoids a redundant SWAP/DROP pair.
    a.num(headerLength).o('OP_SPLIT').o('OP_NIP');
    a.num(item.bytes.length).o('OP_SPLIT').o('OP_SWAP');
    a.num(item.id).o('OP_DEFINE');
  }
  // The only remaining item is the library's P2SH redeem push.  Its hash is checked by the VM;
  // dropping it here leaves the caller's original witness stack untouched.
  a.o('OP_DROP');
  return a.bytecode();
}

export function buildLibraryPin(libraryInputIndex, libraryLockHash) {
  if (!Number.isInteger(libraryInputIndex) || libraryInputIndex < 0) throw new Error('library input index required');
  const a = new Asm();
  a.num(libraryInputIndex).o('OP_UTXOBYTECODE').o('OP_HASH256').push(libraryLockHash).o('OP_EQUALVERIFY');
  return a.bytecode();
}

export function buildLibraryArtifact(items, { inputIndex, totalInputs, p2sh }) {
  const digest = itemDigest(items);
  const redeem = buildLibraryRedeem(items, { inputIndex, totalInputs, digest });
  const locking = p2sh(redeem);
  const unlocking = buildLibraryUnlocking(items, redeem);
  return { items, digest, redeem, locking, unlocking };
}

// Shared-witness inputs use the same committed item format, but their bodies are
// data payloads rather than OP_DEFINE function bodies.  The payloads are restored
// onto the caller's main stack in original order after the loader has authenticated
// and removed the trailing P2SH redeem push.
export function witnessPayloadFromPush(encodedPush) {
  const instructions = decodeAuthenticationInstructions(encodedPush);
  if (instructions.length !== 1 || 'malformed' in instructions[0]) {
    throw new Error('shared witness item must be exactly one canonical push');
  }
  const instruction = instructions[0];
  if ('data' in instruction) return Uint8Array.from(instruction.data);
  if (instruction.opcode === 0x4f) return Uint8Array.of(0x81); // OP_1NEGATE
  if (instruction.opcode >= 0x51 && instruction.opcode <= 0x60) return Uint8Array.of(instruction.opcode - 0x50);
  throw new Error(`shared witness item is not a push opcode: ${instruction.opcode}`);
}

export function makeWitnessItems(encodedItems, firstId = 1) {
  if (!Array.isArray(encodedItems) || encodedItems.length < 1) throw new Error('shared witness must contain at least one item');
  if (!Number.isInteger(firstId) || firstId < 1 || firstId + encodedItems.length > 256) throw new Error('shared witness item id out of byte range');
  return encodedItems.map((encoded, index) => {
    if (!(encoded instanceof Uint8Array)) throw new Error(`shared witness item ${index} is not bytecode`);
    const bytes = witnessPayloadFromPush(encoded);
    if (bytes.length > 520) throw new Error(`shared witness item ${index} exceeds the 520-byte stack-item cap`);
    return { id: firstId + index, bytes, kind: 'shared-witness', index };
  });
}

// Parse a committed shared-witness input.  The raw unlocking is encoded by
// buildLibraryUnlocking (reverse item order, then the redeem push).  Each body is
// parked on altstack while the next raw push is peeled; restoring in ascending item
// order reproduces the original witness stack layout exactly.
export function buildWitnessLoader(items, witnessInputIndex) {
  if (!Number.isInteger(witnessInputIndex) || witnessInputIndex < 0) throw new Error('shared witness input index required');
  const a = new Asm();
  a.num(witnessInputIndex).o('OP_INPUTBYTECODE');
  for (let i = items.length - 1; i >= 0; i--) {
    const item = items[i];
    const encodedPush = pushBytes(item.bytes);
    // Special-number/empty pushes are one opcode long and carry no raw
    // payload.  Consume that opcode, then restore the semantic payload as a
    // normal stack item before parking it on the altstack.
    if (encodedPush.length === 1) {
      a.num(1).o('OP_SPLIT').o('OP_NIP');
      a.push(item.bytes).o('OP_TOALTSTACK');
      continue;
    }
    const headerLength = encodedPush.length - item.bytes.length;
    a.num(headerLength).o('OP_SPLIT').o('OP_NIP');
    a.num(item.bytes.length).o('OP_SPLIT').o('OP_SWAP').o('OP_TOALTSTACK');
  }
  // The only remaining raw item is the P2SH redeem push.  It is checked by the
  // witness input's own VM evaluation and is not part of the verifier stack.
  a.o('OP_DROP');
  for (let i = 0; i < items.length; i++) a.o('OP_FROMALTSTACK');
  return a.bytecode();
}

// Items are committed in function-table order followed by verifier-chunk order.  IDs below 100
// are reserved by qfuncs.mjs; dynamic chunks begin at 100 to make accidental collisions visible.
export function makeLibraryItems(definitions, chunks, firstChunkId = 100) {
  if (firstChunkId < 100 || firstChunkId + chunks.length > 256) throw new Error('dynamic chunk function id out of byte range');
  const items = definitions.map(([id, bytes]) => {
    if (!Number.isInteger(id) || id < 1 || id > 99) throw new Error(`static function id out of reserved range: ${id}`);
    if (!(bytes instanceof Uint8Array) || bytes.length > MAX_FUNCTION_BODY_BYTES) throw new Error(`invalid static function body for id ${id}`);
    return { id, bytes, kind: 'function' };
  });
  for (let i = 0; i < chunks.length; i++) {
    if (!(chunks[i] instanceof Uint8Array) || chunks[i].length > MAX_FUNCTION_BODY_BYTES) throw new Error(`invalid dynamic verifier chunk ${i}`);
    items.push({ id: firstChunkId + i, bytes: chunks[i], kind: 'verifier-chunk', index: i });
  }
  return items;
}

export function buildDynamicRedeem({ items, libraryInputIndex, libraryLockHash, prologue, firstChunkId = 100, chunkCount,
  witnessItems, witnessInputIndex, witnessLockHash }) {
  const a = new Asm();
  if (witnessItems !== undefined) {
    if (!Number.isInteger(witnessInputIndex) || !(witnessLockHash instanceof Uint8Array)) {
      throw new Error('shared witness loader requires witnessInputIndex and witnessLockHash');
    }
    a.raw(buildWitnessLoader(witnessItems, witnessInputIndex));
    a.raw(buildLibraryPin(witnessInputIndex, witnessLockHash));
  }
  a.raw(buildDynamicLoader(items, libraryInputIndex));
  a.raw(buildLibraryPin(libraryInputIndex, libraryLockHash));
  a.raw(prologue);
  for (let i = 0; i < chunkCount; i++) a.num(firstChunkId + i).o('OP_INVOKE');
  return a.bytecode();
}
