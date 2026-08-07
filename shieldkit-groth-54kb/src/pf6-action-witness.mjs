// ShieldKit-Groth-54KB — pf6 action witness constants + packet digest binding.
// Numbers measured from the product build (evidence/03-implementation/product-build-r1.json);
// the digest binding follows design/FREEZE.json.
'use strict';

import { createHash } from 'node:crypto';

import {
  DIRECT_V2_PF6_TOPOLOGY_ID,
  DIRECT_V2_PF6_VERIFIER_ROLES,
} from './topology-pf6.mjs';

export const DIRECT_V2_PF6_ACTION_WITNESS_SCHEMA =
  'shieldkit-v2-direct-pf6-action-witness-v1';

// ---- measured product-build constants (stabilization ON, VK d38f3cfc) ----
export const DIRECT_V2_PF6_VERIFIER_UNLOCK_BYTES = Object.freeze([
  9_853, // exec0
  9_848, // exec1
  9_877, // exec2
  8_893, // exec3
  7_600, // genesis (stabilized target)
  9_350, // terminal (stabilized target)
]);
export const DIRECT_V2_PF6_VERIFIER_UNLOCK_TOTAL =
  DIRECT_V2_PF6_VERIFIER_UNLOCK_BYTES.reduce((a, b) => a + b, 0); // 55,976
export const DIRECT_V2_PF6_STATE_UNLOCK_BYTES = 2_677; // product SKS2 state unlock (P-02 codec; measured in WP-4 e2e)
export const DIRECT_V2_PF6_MAX_UNLOCK_BYTES = 10_000;

// ---- packet / digest binding (frozen design) ----
export const SDA2_PACKET_BYTES = 552;
export const SDA2_PACKET_PUSH_HEADER = Uint8Array.from([0x4d, 0x28, 0x02]);
export const PROJECTION_SIGNAL_PUSH_HEADER = Uint8Array.from([0x4d, 0xe0, 0x01]);
export const PROJECTION_CONTEXT_BYTES = 448;
export const DIGEST_BYTES = 32;
// genesis unlock byte offset of the 32-byte packet digest:
// 3 (push header) + 448 (projection context) = 451
export const GENESIS_DIGEST_OFFSET =
  PROJECTION_SIGNAL_PUSH_HEADER.length + PROJECTION_CONTEXT_BYTES;

/** SHA-256 of the SDA2 packet -> 32-byte digest (the proof's binding input). */
export const packetDigest = (packetBytes) => {
  if (!(packetBytes instanceof Uint8Array) || packetBytes.length !== SDA2_PACKET_BYTES) {
    throw new Error(`SDA2 packet must be exactly ${SDA2_PACKET_BYTES} bytes`);
  }
  return createHash('sha256').update(packetBytes).digest();
};

/** Two unsigned BE u128 limbs of the digest (proof public inputs in0/in1). */
export const packetPublicLimbs = (digest) => {
  if (!(digest instanceof Uint8Array) || digest.length !== DIGEST_BYTES) {
    throw new Error(`digest must be exactly ${DIGEST_BYTES} bytes`);
  }
  return Object.freeze([
    BigInt(`0x${Buffer.from(digest.subarray(0, 16)).toString('hex')}`),
    BigInt(`0x${Buffer.from(digest.subarray(16, 32)).toString('hex')}`),
  ]);
};

/** Build the genesis unlock's projection-signal payload (header + ctx + digest). */
export const encodeProjectionSignal = ({ context, digest }) => {
  if (!(context instanceof Uint8Array) || context.length !== PROJECTION_CONTEXT_BYTES) {
    throw new Error(`projection context must be exactly ${PROJECTION_CONTEXT_BYTES} bytes`);
  }
  if (!(digest instanceof Uint8Array) || digest.length !== DIGEST_BYTES) {
    throw new Error(`digest must be exactly ${DIGEST_BYTES} bytes`);
  }
  return Buffer.concat([PROJECTION_SIGNAL_PUSH_HEADER, context, digest]);
};

/** Encode the packet input unlock bytecode: PUSHDATA2(SDA2[552]). */
export const encodePacketUnlock = (packetBytes) => {
  if (!(packetBytes instanceof Uint8Array) || packetBytes.length !== SDA2_PACKET_BYTES) {
    throw new Error(`SDA2 packet must be exactly ${SDA2_PACKET_BYTES} bytes`);
  }
  return Buffer.concat([SDA2_PACKET_PUSH_HEADER, packetBytes]);
};

export function pf6ActionWitnessIdentity() {
  return Object.freeze({
    schema: DIRECT_V2_PF6_ACTION_WITNESS_SCHEMA,
    topologyId: DIRECT_V2_PF6_TOPOLOGY_ID,
    verifierRoles: DIRECT_V2_PF6_VERIFIER_ROLES,
    verifierUnlockTotal: DIRECT_V2_PF6_VERIFIER_UNLOCK_TOTAL,
    measured: 'evidence/03-implementation/product-build-r1.json',
  });
}
