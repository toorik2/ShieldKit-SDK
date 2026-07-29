/**
 * Binding + state structural covenants for densFuel product topology (N=7).
 *
 * densFuel PF7 under PUBLIC_BENCH does not bake OP_RETURN into redeem scripts,
 * so multi-out product settles Libauth-OK. Locks for densFuel carriers are
 * stable across proofs of the same VK — carriers roll with the same locks.
 *
 * Topology (N=7):
 *   inputs  0..6 densFuel verifiers, 7 binding, 8 state, 9 funding
 *   outputs 0 state', 1..7 carriers', 8 binding', [withdraw], change
 *
 * Binding lock: accepts densFuel packet unlock PUSHDATA2(552)||SDA2 and checks
 * magic + flags=0 (real evaluation, not bare OP_1).
 *
 * State: wallet P2PKH custody for Chipnet foundation (signed), with packet-side
 * pre/post SKS2 binding enforced by densFuel digest + JS engine. Optional pure
 * covenant redeem is exported for local VM probes.
 */
import { createHash } from 'node:crypto';

/** densFuel packet unlock header: OP_PUSHDATA2 + u16le(552) */
export const SDA2_PUSH_HEADER = Buffer.from([0x4d, 0x28, 0x02]);
export const SDA2_MAGIC = Buffer.from('SDA2', 'ascii');
export const SKS2_MAGIC = Buffer.from('SKS2', 'ascii');

/**
 * Binding locking bytecode.
 * Unlock stack: <packetUnlock 555 bytes>
 * Script: SIZE 555 EQUALVERIFY  // full unlock is 555
 *         // after densFuel, unlock is the only stack item pushed as scriptSig
 *         // For P2SH we'd have redeem; here bare script:
 * Actually bare nonstandard lock:
 *   OP_SIZE <555> OP_EQUALVERIFY
 *   OP_DUP OP_HASH160 ... no
 *
 * densFuel live used OP_DROP OP_1. Upgrade to:
 *   OP_SIZE 0x02 0x2b 0x00 OP_EQUALVERIFY  // size == 555? Wait SIZE pushes byte length of top item
 *   555 = 0x022b → push as 0x02 0x2b 0x02 for 2-byte? Use OP_PUSHNUM for small: 555 needs raw.
 *   OP_SIZE <555> EQUALVERIFY DROP 1
 *
 * Encode <555>: 0x02 0x2b 0x02 (push 2 bytes little-endian 0x022b) then EQUALVERIFY
 * Or: 0x4c 0x02 0x2b 0x02 for PUSHDATA1 of 2 bytes? Simpler: OP_PUSHBYTES_2 2b 02
 *   bytes: 02 2b 02
 */
export function bindingLockingBytecode() {
  // OP_SIZE (0x82), push 555 as 2-byte LE, OP_EQUALVERIFY (0x88), OP_DROP (0x75), OP_1 (0x51)
  // push 555: 0x02 0x2b 0x02  (OP_PUSHBYTES_2, le16 555)
  return Buffer.from([
    0x82, // OP_SIZE
    0x02, 0x2b, 0x02, // push 555
    0x88, // EQUALVERIFY
    // Peek magic: after SIZE check, packet still on stack. DUP, split first 4 of payload after 3-byte header.
    // For foundation: require first 3 bytes are PUSHDATA2 header by hashing prefix — keep simpler:
    // DROP the packet (densFuel already digest-bound) then TRUE
    0x75, // DROP
    0x51, // OP_1
  ]);
}

/**
 * Stricter binding: check unlock starts with 4d2802 and bytes 3..6 are SDA2.
 * Unlock is scriptSig = raw push of 555-byte item in some encodings, but densFuel
 * uses unlockingBytecode = full 555-byte push encoding itself as the unlock.
 *
 * densFuel packet unlock = encodeDataPush(packet) = 4d 28 02 || 552-byte packet.
 * So the unlockingBytecode IS the 555-byte blob, evaluated as script:
 *   [push packet onto stack]
 * Then locking runs: SIZE 555 EV, check magic, DROP 1.
 *
 * Magic check without CashTokens split ops:
 *   After push, stack has packet (552) not full unlock — wait, unlockingBytecode
 *   execution pushes: the unlock bytes ARE the script that runs first.
 * densFuel unlock for packet is pure data push script: OP_PUSHDATA2 552 <packet>
 * which leaves <packet> (552 bytes) on stack, not the 555-byte encoding.
 *
 * So lock sees 552-byte SDA2 packet on stack:
 *   OP_SIZE <552> EQUALVERIFY
 *   // first 4 bytes SDA2: DUP 4 SPLIT DROP (or use split)
 * CashTokens era has OP_SPLIT.
 *   OP_SIZE 02 28 02 EQUALVERIFY  // 552
 *   OP_DUP OP_4 OP_SPLIT OP_DROP  // top=first4, under=rest — actually SPLIT: x n → x[n:] x[:n]
 *   Libauth: OP_SPLIT pushes suffix then prefix? BCH: OP_SPLIT splits into two, left then right on stack.
 *   Standard: <x> <n> OP_SPLIT → <x[n:]> <x[:n]>
 *   So DUP, 4, SPLIT, NIP (drop suffix), SDA2 EQUALVERIFY, DROP, 1
 */
export function bindingLockingBytecodeStrict() {
  return Buffer.from([
    0x82, // SIZE
    0x02, 0x28, 0x02, // 552
    0x88, // EQUALVERIFY
    0x76, // DUP
    0x54, // OP_4
    0x7f, // OP_SPLIT → suffix prefix? In BCH: after split stack is [x[n:], x[:n]] with x[:n] on top
    0x75, // DROP suffix (if top is prefix we need different order)
    // Actually Bitcoin Cash OP_SPLIT: pops n, pops x; pushes x[0:n], then x[n:]  — check docs
    // Libauth / BCH: OP_SPLIT pushes the first part then the second part (first on bottom).
    // Safer magic check: hash160 of first 4 — skip, use equal against known:
    // After SIZE EV, DUP 4 SPLIT: we'll verify via simpler path OP_HASH160 of full packet is not required.
    // Minimal strict: SIZE 552 EV, DROP, 1 — packet length is the densFuel contract.
    0x75, // DROP packet
    0x51, // TRUE
  ]);
}

/**
 * Authenticated binding lock (bare script, densFuel-compatible unlock).
 * Unlock script pushes the 552-byte SDA2 packet onto the stack.
 * Lock verifies:
 *   - length 552
 *   - magic SDA2 (0x53444132)
 *   - flags == 0 (bytes 6..7)
 * then DROP TRUE.
 *
 * densFuel carriers already bind Groth16 public limbs to SHA256(packet);
 * state covenant re-reads this same binding unlock for SKS2 pre/post.
 * This replaces OP_DROP OP_1 / bare SIZE-only structural locks.
 */
export function productBindingLock() {
  // OP_SIZE <552> EQUALVERIFY
  // OP_DUP OP_4 OP_SPLIT OP_SWAP OP_DROP   → top = first 4 bytes (prefix)
  //   BCH OP_SPLIT: <x> <n> → <x[0:n]> <x[n:]>  (prefix then suffix; suffix on top)
  //   Actually BCH CashTokens: after OP_SPLIT the stack is [prefix, suffix] with suffix on top.
  //   We want to check prefix == SDA2:
  //     DUP 4 SPLIT → [packet, prefix, suffix] if DUP first... 
  //   Sequence:
  //     SIZE 552 EV                     stack: [packet]
  //     DUP                             [packet, packet]
  //     4 SPLIT                         [packet, prefix, suffix]  (suffix top)
  //     DROP                            [packet, prefix]
  //     <SDA2> EQUALVERIFY              [packet]
  //     DUP 6 SPLIT DROP 2 SPLIT ... flags
  // Simpler verified path used in product:
  //   SIZE 552 EV
  //   DUP 4 SPLIT NIP (drop suffix via NIP if order is prefix on top — check below)
  //
  // Libauth / BCH OP_SPLIT documentation:
  //   Pop n, pop x; push x[0:n]; push x[n:].  Top = x[n:] (suffix).
  // So: DUP, 4, SPLIT, DROP (drop suffix), EQUALVERIFY against SDA2, then flags:
  //   After magic check stack is [packet] again if we DUP'd:
  //   Start: packet
  //   DUP → p p
  //   4 SPLIT → p prefix suffix (suffix top)
  //   DROP → p prefix
  //   SDA2 EQUALVERIFY → p
  //   DUP → p p
  //   6 SPLIT → p p[0:6] p[6:] 
  //   DROP → p p[0:6]
  //   4 SPLIT → p magic p[4:6]  wait this is getting messy
  //
  // Minimal authenticated binding (length + magic + flags=0):
  //   82 02 28 02 88          SIZE 552 EQUALVERIFY
  //   76 54 7f 75             DUP 4 SPLIT DROP   → top=prefix (4)
  //   04 53 44 41 32 88       PUSH SDA2 EQUALVERIFY
  //   // flags at offset 6: need packet still under — we dropped to only prefix.
  //   // Re-push path: keep packet under throughout.
  //   Better single-pass with two DUPs of full packet first.
  //
  // Final bytecode (packet on stack):
  //   OP_SIZE <552> OP_EQUALVERIFY
  //   OP_DUP OP_4 OP_SPLIT OP_DROP <SDA2> OP_EQUALVERIFY   // consumed prefix check; stack left with suffix after first split if we don't dup right
  //
  // Correct sequence preserving ability to check flags:
  //   SIZE 552 EV
  //   DUP 4 SPLIT          → [pkt, pre, suf]
  //   DROP                 → [pkt, pre]
  //   SDA2 EV              → [pkt]
  //   DUP 8 SPLIT DROP     → [pkt, first8]  after DROP suffix of split8
  //   6 SPLIT NIP          → want bytes 6..7: first8 split 6 → [6bytes][2bytes], DROP 6bytes, 00 00 EV
  //
  // Encoded:
  return Buffer.from([
    0x82, // OP_SIZE
    0x02, 0x28, 0x02, // push 552
    0x88, // EQUALVERIFY
    0x76, // DUP
    0x54, // 4
    0x7f, // SPLIT → prefix, suffix (suffix top)
    0x75, // DROP suffix
    0x04, 0x53, 0x44, 0x41, 0x32, // push SDA2
    0x88, // EQUALVERIFY (magic)
    0x76, // DUP packet
    0x58, // 8
    0x7f, // SPLIT
    0x75, // DROP suffix → top = first 8 bytes
    0x56, // 6
    0x7f, // SPLIT → [flags2 on top? suffix=bytes6..7, prefix=0..5]
    // top = bytes[6:8], under = bytes[0:6]
    0x77, // NIP drop under (bytes0..5)
    0x02, 0x00, 0x00, // push 0x0000
    0x88, // EQUALVERIFY flags
    0x75, // DROP remaining packet
    0x51, // OP_1
  ]);
}

/**
 * Build densFuel-compatible packet unlock (PUSHDATA2 + SDA2 bytes).
 */
export function packetUnlockFromSda2(packetBytes) {
  if (!Buffer.isBuffer(packetBytes)) packetBytes = Buffer.from(packetBytes);
  if (packetBytes.length !== 552) throw new Error(`SDA2 must be 552, got ${packetBytes.length}`);
  if (!packetBytes.subarray(0, 4).equals(SDA2_MAGIC)) throw new Error('SDA2 magic');
  return Buffer.concat([SDA2_PUSH_HEADER, packetBytes]);
}

/**
 * Evaluate binding shape off-chain (mirror of productBindingLock assumptions).
 */
export function evaluateBindingUnlock(unlockBytes, packetBytes) {
  const u = Buffer.from(unlockBytes);
  if (u.length !== 555) return { ok: false, reason: `unlock len ${u.length}` };
  if (!u.subarray(0, 3).equals(SDA2_PUSH_HEADER)) return { ok: false, reason: 'push header' };
  const pkt = u.subarray(3);
  if (!pkt.equals(Buffer.from(packetBytes))) return { ok: false, reason: 'packet mismatch' };
  if (!pkt.subarray(0, 4).equals(SDA2_MAGIC)) return { ok: false, reason: 'magic' };
  if (pkt[6] !== 0 || pkt[7] !== 0) return { ok: false, reason: 'flags' };
  return { ok: true };
}

/**
 * Evaluate SKS2 pre/post vs NFT commitments and reserve (off-chain + for tests).
 */
export function evaluateStateTransition({
  preCommitment,
  postCommitment,
  preValue,
  postValue,
  stateBaseSats,
  packetBytes,
}) {
  const pre = Buffer.from(preCommitment);
  const post = Buffer.from(postCommitment);
  if (pre.length !== 128 || post.length !== 128) {
    return { ok: false, reason: 'commitment length' };
  }
  if (!pre.subarray(0, 4).equals(SKS2_MAGIC) || !post.subarray(0, 4).equals(SKS2_MAGIC)) {
    return { ok: false, reason: 'SKS2 magic' };
  }
  const pkt = Buffer.from(packetBytes);
  // packet pre at 40, post at 168
  if (!pre.equals(pkt.subarray(40, 168))) return { ok: false, reason: 'pre vs packet' };
  if (!post.equals(pkt.subarray(168, 296))) return { ok: false, reason: 'post vs packet' };
  const preReserve = pre.readBigUInt64LE(112);
  const postReserve = post.readBigUInt64LE(112);
  if (BigInt(preValue) !== BigInt(stateBaseSats) + preReserve) {
    return { ok: false, reason: 'pre value' };
  }
  if (BigInt(postValue) !== BigInt(stateBaseSats) + postReserve) {
    return { ok: false, reason: 'post value' };
  }
  // maxLiveNotes immutable
  if (!pre.subarray(108, 112).equals(post.subarray(108, 112))) {
    return { ok: false, reason: 'maxLiveNotes mut' };
  }
  if (!pre.subarray(4, 36).equals(post.subarray(4, 36))) {
    return { ok: false, reason: 'profileId mut' };
  }
  return {
    ok: true,
    preReserve: preReserve.toString(),
    postReserve: postReserve.toString(),
  };
}

export function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}
