/**
 * Pool state@0 covenant — full plan bind (can't-do-evil).
 *
 * Unlock: <SFP1 packet 424B>
 * Redeem (P2SH32) binds plan state NFT + packet + SFS1 transitions + structural SFC1 hash.
 *
 * Binds:
 *  - input index 0; co-spend ≥ roleCount roles; role/state lock continuity
 *  - SFP1 magic/size; network; flags=0; kind ∈ {1,2,3}
 *  - instanceId == NFT category; capability mutable
 *  - preState/postState == source/successor 128B commitments; amount 0
 *  - SFS1 magic; profileId continuity; maxLive continuity; sequence+1
 *  - kind-specific note/nullifier/reserve deltas (deposit/transfer/withdraw)
 *  - carrier value: in − pre.reserve == out − post.reserve
 *  - SFC1 product-structural: SHA256(cat||pre||post||kind||network) == packet.txContextHash
 *    (JS: hashSfc1ProductStructural; full plan SFC1 codec in core/codecs/sfc1.mjs)
 *
 * Authority: FRI_STARK_REPLACEMENT_PLAN.md
 */
import { createHash } from 'node:crypto';
import {
  cashAssemblyToBin,
  encodeLockingBytecodeP2sh32,
  encodeDataPush,
  flattenBinArray,
  hash256,
  binToHex,
  hexToBin,
} from '@bitauth/libauth';
import { PACKET_BYTES } from '../core/codecs/packet.mjs';
import { STATE_BYTES } from '../core/codecs/state.mjs';

export const ROLE_COUNT = 17;  // AMENDED 2026-08-06: product config nq=7 (blob + 7 deepquery + 7 aggFRI + comp_trans + comp_final); was 19 @ nq8
export const DENOMINATION_SATS = 10_000_000;
export const DEFAULT_NETWORK_ID = 2;

function n(x) {
  return `<${x}>`;
}

/** Non-destructive slice of top-of-stack blob at offset. */
function take(off, len) {
  return `OP_DUP ${n(off)} OP_SPLIT OP_NIP ${n(len)} OP_SPLIT OP_DROP`;
}

/**
 * Product structural SFC1 hash (on-chain + JS must match).
 * SHA256( category32 || preState128 || postState128 || kind_u8 || network_u8 )
 */
export function hashSfc1ProductStructural({
  categoryHex,
  preCommitmentHex,
  postCommitmentHex,
  kind,
  networkId = DEFAULT_NETWORK_ID,
}) {
  const body = Buffer.concat([
    Buffer.from(categoryHex, 'hex'),
    Buffer.from(preCommitmentHex, 'hex'),
    Buffer.from(postCommitmentHex, 'hex'),
    Buffer.from([kind & 0xff, networkId & 0xff]),
  ]);
  return createHash('sha256').update(body).digest();
}

export function hashSfc1ProductStructuralHex(opts) {
  return hashSfc1ProductStructural(opts).toString('hex');
}

/**
 * @param {object|number} [opts] - roleCount number (legacy) or options object
 */
export function compileStateCovenant(opts = {}) {
  const roleCount =
    typeof opts === 'number' ? opts : (opts.roleCount ?? ROLE_COUNT);
  const networkId =
    typeof opts === 'number' ? DEFAULT_NETWORK_ID : (opts.networkId ?? DEFAULT_NETWORK_ID);
  const bindSfc1 = typeof opts === 'number' ? true : opts.bindSfc1 !== false;
  const rc = Number(roleCount);
  if (!Number.isInteger(rc) || rc < 1 || rc > 40) {
    throw new Error(`bad roleCount ${roleCount}`);
  }
  if (![1, 2].includes(Number(networkId))) {
    throw new Error(`bad networkId ${networkId}`);
  }

  const nInMin = 1 + rc;
  const sfs1 = Buffer.from('SFS1').toString('hex');
  const sfp1 = Buffer.from('SFP1').toString('hex');
  const netByte = Buffer.from([networkId & 0xff]).toString('hex');
  const lines = [];

  // Topology
  lines.push(`OP_INPUTINDEX ${n(0)} OP_EQUALVERIFY`);
  lines.push(`OP_TXINPUTCOUNT ${n(nInMin)} OP_GREATERTHANOREQUAL OP_VERIFY`);
  lines.push(`OP_TXOUTPUTCOUNT ${n(nInMin)} OP_GREATERTHANOREQUAL OP_VERIFY`);

  // Packet size + header
  lines.push(`OP_SIZE ${n(PACKET_BYTES)} OP_EQUALVERIFY`);
  lines.push(`${take(0, 4)} <0x${sfp1}> OP_EQUALVERIFY`);
  lines.push(`${take(4, 1)} OP_BIN2NUM ${n(networkId)} OP_EQUALVERIFY`);
  lines.push(`${take(6, 2)} <0x0000> OP_EQUALVERIFY`);
  // kind ∈ [1,3] → alt
  lines.push(`${take(5, 1)} OP_BIN2NUM OP_DUP ${n(1)} OP_GREATERTHANOREQUAL OP_VERIFY`);
  lines.push(`OP_DUP ${n(3)} OP_LESSTHANOREQUAL OP_VERIFY OP_TOALTSTACK`);

  // Category continuity + instanceId
  // stack: [packet]
  lines.push(`OP_0 OP_UTXOTOKENCATEGORY OP_SIZE ${n(33)} OP_EQUALVERIFY`);
  lines.push(`OP_DUP OP_0 OP_OUTPUTTOKENCATEGORY OP_EQUALVERIFY`);
  // [packet, catblob]; split cat||cap
  // capability mutable = raw 0x01 (OP_EQUAL is bytewise, not numeric)
  lines.push(`${n(32)} OP_SPLIT <0x01> OP_EQUALVERIFY`);
  // Libauth/BCH UTXOTOKENCATEGORY pushes category in reverse-byte order vs NFT genesis id;
  // reverse before comparing to packet.instanceId (plan: category == instanceId).
  lines.push(`OP_REVERSEBYTES`);
  // [packet, cat] → SWAP → [cat, packet] → take inst → [cat, packet, inst]
  // ROT → [packet, inst, cat]; SWAP → [packet, cat, inst]; EQUALVERIFY → [packet]
  lines.push(`OP_SWAP ${take(8, 32)} OP_ROT OP_SWAP OP_EQUALVERIFY`);
  // [packet]

  // Source commitment == preState[40:168]
  lines.push(`OP_0 OP_UTXOTOKENCOMMITMENT OP_SIZE ${n(128)} OP_EQUALVERIFY`);
  // [packet, srcC]
  lines.push(`OP_SWAP ${take(40, 128)} OP_ROT OP_EQUALVERIFY`);
  // After SWAP: [srcC, packet]; take leaves [srcC, packet, pre]; ROT → [packet, pre, srcC]; EQUALVERIFY → [packet]

  // Dest commitment == postState
  lines.push(`OP_0 OP_OUTPUTTOKENCOMMITMENT OP_SIZE ${n(128)} OP_EQUALVERIFY`);
  lines.push(`OP_SWAP ${take(168, 128)} OP_ROT OP_EQUALVERIFY`);

  lines.push(`OP_0 OP_UTXOTOKENAMOUNT ${n(0)} OP_EQUALVERIFY`);
  lines.push(`OP_0 OP_OUTPUTTOKENAMOUNT ${n(0)} OP_EQUALVERIFY`);

  // SFS1 magic
  lines.push(`${take(40, 4)} <0x${sfs1}> OP_EQUALVERIFY`);
  lines.push(`${take(168, 4)} <0x${sfs1}> OP_EQUALVERIFY`);
  // profileId continuity (state offs 4..36 → packet 44..76 and 172..204)
  lines.push(`${take(44, 32)} OP_TOALTSTACK ${take(172, 32)} OP_FROMALTSTACK OP_EQUALVERIFY`);
  // maxLive continuity (state 108 → packet 148 / 276)
  lines.push(`${take(148, 4)} OP_TOALTSTACK ${take(276, 4)} OP_FROMALTSTACK OP_EQUALVERIFY`);
  // sequence +1 (keep packet under numeric ops via TOALT)
  lines.push(`${take(160, 8)} OP_BIN2NUM OP_1ADD OP_TOALTSTACK`);
  lines.push(`${take(288, 8)} OP_BIN2NUM OP_FROMALTSTACK OP_EQUALVERIFY`);

  // Deltas post-pre: SUB is (second - top); leave post under, pre on top → post-pre.
  // dNote
  lines.push(`${take(268, 4)} OP_BIN2NUM OP_TOALTSTACK`);
  lines.push(`${take(140, 4)} OP_BIN2NUM OP_FROMALTSTACK OP_SWAP OP_SUB OP_TOALTSTACK`);
  // After take pre BIN2NUM: [p, preN]; FROMALT postN: [p, preN, postN]; SWAP: [p, postN, preN]; SUB: post-pre.
  // Wait FROMALT brings postN to top: [p, preN, postN]; SWAP → [p, postN, preN]; SUB → postN-preN. Good.
  // Actually code does take(268) post first TOALT, take(140) pre, FROMALT post, SWAP SUB:
  // [p, preN], FROMALT [p, preN, postN], SWAP [p, postN, preN], SUB post-pre. Good.

  // dNf
  lines.push(`${take(272, 4)} OP_BIN2NUM OP_TOALTSTACK`);
  lines.push(`${take(144, 4)} OP_BIN2NUM OP_FROMALTSTACK OP_SWAP OP_SUB OP_TOALTSTACK`);
  // dRes
  lines.push(`${take(280, 8)} OP_BIN2NUM OP_TOALTSTACK`);
  lines.push(`${take(152, 8)} OP_BIN2NUM OP_FROMALTSTACK OP_SWAP OP_SUB OP_TOALTSTACK`);
  // alt: dRes, dNf, dNote, kind
  lines.push(`OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK`);
  // [packet, dRes, dNf, dNote, kind]

  // kind switches
  lines.push(`OP_DUP ${n(1)} OP_EQUAL OP_IF`);
  // deposit
  lines.push(
    `OP_DROP ${n(1)} OP_EQUALVERIFY ${n(0)} OP_EQUALVERIFY ${n(DENOMINATION_SATS)} OP_EQUALVERIFY`,
  );
  lines.push(`OP_ELSE OP_DUP ${n(2)} OP_EQUAL OP_IF`);
  // transfer
  lines.push(
    `OP_DROP ${n(1)} OP_EQUALVERIFY ${n(1)} OP_EQUALVERIFY ${n(0)} OP_EQUALVERIFY`,
  );
  lines.push(`OP_ELSE`);
  // withdraw
  lines.push(`${n(3)} OP_EQUALVERIFY ${n(0)} OP_EQUALVERIFY ${n(1)} OP_EQUALVERIFY`);
  lines.push(`${n(DENOMINATION_SATS)} OP_ADD ${n(0)} OP_EQUALVERIFY`);
  lines.push(`OP_ENDIF OP_ENDIF`);
  // [packet]

  // Carrier: inVal - preRes == outVal - postRes
  // left
  lines.push(`OP_0 OP_UTXOVALUE OP_SWAP ${take(152, 8)} OP_BIN2NUM`);
  // [in, p, preRes] → ROT [p, preRes, in] SWAP [p, in, preRes] SUB [p, left]
  lines.push(`OP_ROT OP_SWAP OP_SUB OP_TOALTSTACK`);
  // right
  lines.push(`OP_0 OP_OUTPUTVALUE OP_SWAP ${take(280, 8)} OP_BIN2NUM`);
  lines.push(`OP_ROT OP_SWAP OP_SUB`);
  lines.push(`OP_FROMALTSTACK OP_EQUALVERIFY`);
  // [packet]

  // State lock continuity
  lines.push(`OP_0 OP_UTXOBYTECODE OP_0 OP_OUTPUTBYTECODE OP_EQUALVERIFY`);

  // Role locks continuity (P2SH32 = 35 bytes)
  for (let i = 1; i <= rc; i += 1) {
    lines.push(`${n(i)} OP_UTXOBYTECODE OP_SIZE ${n(35)} OP_EQUALVERIFY OP_DROP`);
    lines.push(`${n(i)} OP_UTXOBYTECODE ${n(i)} OP_OUTPUTBYTECODE OP_EQUALVERIFY`);
  }

  if (bindSfc1) {
    // Product structural: SHA256(rev(cat32)||pre||post||kind||network) == packet[392:424]
    // Must use OP_SHA256 (single), not OP_HASH256 (double). Stack: keep packet under body.
    // alt: expected_hash, then briefly kind while reordering.
    lines.push(`${take(392, 32)} OP_TOALTSTACK`);
    // [packet] alt=[expected]
    lines.push(`OP_0 OP_UTXOTOKENCATEGORY ${n(32)} OP_SPLIT OP_DROP OP_REVERSEBYTES`);
    lines.push(`OP_0 OP_UTXOTOKENCOMMITMENT OP_CAT`);
    lines.push(`OP_0 OP_OUTPUTTOKENCOMMITMENT OP_CAT`);
    // [packet, body_cat_pre_post]
    // kind byte from packet without destroying packet:
    // SWAP → [body, packet]; take(5,1) → [body, packet, kind]; TOALT → [body, packet]
    // SWAP → [packet, body]; FROMALT kind → [packet, body, kind]; CAT → [packet, body||kind]
    lines.push(`OP_SWAP ${take(5, 1)} OP_TOALTSTACK`);
    lines.push(`OP_SWAP OP_FROMALTSTACK OP_CAT`);
    lines.push(`<0x${netByte}> OP_CAT`);
    // [packet, body_full]; SHA256 once; compare to expected on alt
    lines.push(`OP_SHA256 OP_FROMALTSTACK OP_EQUALVERIFY`);
    lines.push(`OP_DROP`); // packet
  } else {
    lines.push(`OP_DROP`);
  }

  lines.push(`OP_1`);
  const asm = lines.join(' ');
  const redeem = cashAssemblyToBin(asm);
  if (typeof redeem === 'string') {
    throw new Error(`state covenant asm error: ${redeem}`);
  }
  const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
  if (typeof locking === 'string') throw new Error(String(locking));
  return {
    asm,
    redeemBytecode: redeem,
    redeemHex: binToHex(redeem),
    lockingHex: binToHex(locking),
    redeemBytes: redeem.length,
    redeemSha256: createHash('sha256').update(Buffer.from(redeem)).digest('hex'),
    roleCount: rc,
    minInputs: nInMin,
    networkId,
    packetBytes: PACKET_BYTES,
    stateBytes: STATE_BYTES,
    operatorKeySpendable: false,
    cantDoEvil: true,
    pinsRoleLockHashes: false,
    bindsPacket: true,
    bindsSfs1Transition: true,
    bindsSfc1: bindSfc1,
    planState0: true,
  };
}

export function compileStateCovenantFromLocks(roleLockingHexes, opts = {}) {
  const count = Array.isArray(roleLockingHexes)
    ? roleLockingHexes.length
    : ROLE_COUNT;
  return compileStateCovenant({ ...opts, roleCount: count });
}

/**
 * scriptSig for state input: push packet then redeem (P2SH32).
 */
export function buildStateScriptSig(redeemHexOrBytes, packetBytes) {
  const redeem =
    typeof redeemHexOrBytes === 'string'
      ? hexToBin(redeemHexOrBytes)
      : redeemHexOrBytes instanceof Uint8Array
        ? redeemHexOrBytes
        : Uint8Array.from(redeemHexOrBytes);
  const parts = [];
  if (packetBytes != null) {
    const pkt =
      typeof packetBytes === 'string'
        ? hexToBin(packetBytes)
        : packetBytes instanceof Uint8Array
          ? packetBytes
          : Uint8Array.from(packetBytes);
    const p = encodeDataPush(pkt);
    if (typeof p === 'string') throw new Error(p);
    parts.push(p);
  }
  const r = encodeDataPush(redeem);
  if (typeof r === 'string') throw new Error(r);
  parts.push(r);
  return binToHex(flattenBinArray(parts));
}
