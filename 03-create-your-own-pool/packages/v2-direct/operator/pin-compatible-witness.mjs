/**
 * Deterministic pin-compatible witness construction (option 3).
 *
 * densFuel live pin requires ECIP nfail ≤ C7_MAXTRY=2 on the Groth16 public
 * limbs (SHA-256 halves of the SDA2 packet digest). Those limbs depend on the
 * full 552-byte packet; the only free field that changes the digest without
 * re-sampling notes or re-touching pool trees is `transactionContextHash`
 * (last 32 bytes).
 *
 * This module **constructs** a context hash so the first prove+densFuel lands
 * in budget. It is not a densFuel / broadcast retry loop:
 *   - cheap offline ECIP measure only (no prove, no unlock, no network)
 *   - deterministic search order from a seed
 *   - then exactly one prove + one densFuel on the bound packet
 */
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import {
  actionPacketPublicLimbsV2,
  decodeActionPacketV2,
  PACKET_OFFSETS,
} from '../packet.mjs';
import {
  PIN_ECIP_MAX_TRY,
  measureEcipPinBudget,
} from '../../unlock-builder/ecip-pin-gate.mjs';
import { resolveCircuitArtifacts } from './prove-local.mjs';

export class PinCompatibleWitnessError extends Error {
  constructor(message, details) {
    super(message);
    this.name = 'PinCompatibleWitnessError';
    if (details) this.details = details;
  }
}

const DEFAULT_MAX_SEARCH = Number(process.env.V2_PIN_CTX_MAX_SEARCH || '4096');

/**
 * Load snarkjs VK IC as affine {x,y} for ECIP measure.
 * @param {string} [verificationKeyPath]
 */
export function loadCircuitIcAffine(verificationKeyPath) {
  const vkPath = verificationKeyPath
    ?? resolveCircuitArtifacts().verificationKeyPath;
  if (!existsSync(vkPath)) {
    throw new PinCompatibleWitnessError(`verification key missing: ${vkPath}`);
  }
  const vk = JSON.parse(readFileSync(vkPath, 'utf8'));
  if (!Array.isArray(vk.IC) || vk.IC.length !== 3) {
    throw new PinCompatibleWitnessError('verification_key.json.IC must be length-3');
  }
  return vk.IC.map((p, i) => {
    if (!Array.isArray(p) || p.length < 2) {
      throw new PinCompatibleWitnessError(`IC[${i}] invalid`);
    }
    return { x: p[0], y: p[1] };
  });
}

/**
 * Measure ECIP pin budget for a fully-formed action packet.
 */
export async function measurePacketEcipPinBudget(packetBytes, {
  verificationKeyPath,
  maxTry = PIN_ECIP_MAX_TRY,
} = {}) {
  const ic = loadCircuitIcAffine(verificationKeyPath);
  const limbs = actionPacketPublicLimbsV2(packetBytes);
  return measureEcipPinBudget({
    ic,
    in0: limbs[0],
    in1: limbs[1],
    maxTry,
  });
}

/**
 * Bind `transactionContextHash` so public limbs sit in the live pin envelope.
 *
 * Search order (deterministic):
 *   0 — keep the packet's existing transactionContextHash
 *   i≥1 — SHA256(`${seed}:${i}`) as the new 32-byte context
 *
 * @param {Uint8Array} packetBytes 552-byte SDA2 packet
 * @param {{
 *   verificationKeyPath?: string,
 *   maxSearch?: number,
 *   seed?: string,
 *   maxTry?: number,
 * }} [opts]
 * @returns {Promise<{
 *   packetBytes: Buffer,
 *   transactionContextHash: string,
 *   nfail: number,
 *   searchIndex: number,
 *   publicLimbs: [string, string],
 *   changed: boolean,
 * }>}
 */
export async function bindPinCompatibleTransactionContext(packetBytes, opts = {}) {
  const maxSearch = opts.maxSearch ?? DEFAULT_MAX_SEARCH;
  const maxTry = opts.maxTry ?? PIN_ECIP_MAX_TRY;
  const seed = opts.seed
    ?? `v2-pin:${createHash('sha256').update(packetBytes).digest('hex').slice(0, 16)}`;

  if (!(packetBytes instanceof Uint8Array) || packetBytes.length !== 552) {
    throw new PinCompatibleWitnessError('packet must be 552-byte SDA2');
  }
  decodeActionPacketV2(packetBytes);

  const ic = loadCircuitIcAffine(opts.verificationKeyPath);
  const packet = Buffer.from(packetBytes);
  const originalCtx = Buffer.from(
    packet.subarray(
      PACKET_OFFSETS.transactionContextHash,
      PACKET_OFFSETS.transactionContextHash + 32,
    ),
  );

  for (let i = 0; i < maxSearch; i += 1) {
    let ctx;
    if (i === 0) {
      ctx = originalCtx;
    } else {
      ctx = createHash('sha256').update(`${seed}:${i}`).digest();
    }
    ctx.copy(packet, PACKET_OFFSETS.transactionContextHash);
    // Round-trip validate after ctx write
    decodeActionPacketV2(packet);
    const limbs = actionPacketPublicLimbsV2(packet);
    const m = await measureEcipPinBudget({
      ic,
      in0: limbs[0],
      in1: limbs[1],
      maxTry,
    });
    if (!m.ok) {
      // Identity break is a tool bug, not a pin miss — fail hard.
      throw new PinCompatibleWitnessError(
        `ECIP offline identity failed at searchIndex=${i} nfail=${m.nfail}`,
        m,
      );
    }
    if (m.withinBudget) {
      return {
        packetBytes: Buffer.from(packet),
        transactionContextHash: ctx.toString('hex'),
        nfail: m.nfail,
        searchIndex: i,
        publicLimbs: [limbs[0], limbs[1]],
        changed: i !== 0,
      };
    }
  }

  throw new PinCompatibleWitnessError(
    `no pin-compatible transactionContextHash in ${maxSearch} searches `
      + `(need ECIP nfail ≤ ${maxTry})`,
    { maxSearch, maxTry, seed },
  );
}

export { PIN_ECIP_MAX_TRY };
