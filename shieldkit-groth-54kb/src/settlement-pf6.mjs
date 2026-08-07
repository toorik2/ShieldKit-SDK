// ShieldKit-Groth-54KB — pf6 settlement v2: REAL binding/state/fee formats
// (extracted from the live PF10 deposit on chipnet; formats unchanged by the swap).
'use strict';

import { createHash } from 'node:crypto';

import { materializePf6Topology } from './topology-pf6.mjs';
import { encodePacketUnlock, SDA2_PACKET_BYTES } from './pf6-action-witness.mjs';

// ---- extracted formats (vendor/chipnet-txs/pf10-deposit.hex, live tx) ----
// Packet input (6): unlock MUST be exactly 555 B (terminal guard) -> bare OP_1 lock.
export const PF6_PACKET_INPUT_LOCK = Uint8Array.from([0x51]); // OP_1 (anyone-can-push; terminal enforces digest binding)
// State input (7): product state covenant unchanged; unlock = PUSHDATA2(2674) + 2674 B payload.
export const PF6_STATE_UNLOCK_BYTES = 2_677;
// Fee input (8): P2PKH (100 B signature class).
export const PF6_FEE_UNLOCK_BYTES = 100;

export class Pf6SettlementError extends Error {
  constructor(code, message) { super(message); this.name = 'Pf6SettlementError'; this.code = code; }
}

/**
 * Build the pf6 deposit/transfer/withdrawal settlement (9 inputs).
 * @param {object} opts
 *  - material: action material entry (verifierRoles + structural)
 *  - packet: Uint8Array(552)
 *  - stateLock: the pool's state covenant lock (88 B class, from pool create)
 *  - stateUnlock: Uint8Array(2677) SKS2 state push (product codec)
 *  - feeLock: P2PKH lock (25 B)
 *  - feeUnlock: Uint8Array(100) signed P2PKH (hot wallet)
 *  - verifierSourceOutpoints: [{txid, vout}] spending the pool's verifier covenant UTXOs
 *  - packetSourceOutpoint: [{txid, vout}] spending the OP_1 carrier UTXO
 *  - stateSourceOutpoint: [{txid, vout}] spending the state covenant UTXO
 *  - outputs: array of {lockingBytecode, valueSatoshis} (9 for deposit/transfer, 10 for withdrawal)
 */
export function buildPf6SettlementTx({ material, packet, stateLock, stateUnlock, feeLock, feeUnlock,
  verifierSourceOutpoints, packetSourceOutpoint, stateSourceOutpoint, outputs, sequenceNumber = 0n }) {
  if (packet.length !== SDA2_PACKET_BYTES) throw new Pf6SettlementError('PACKET_SIZE', 'packet must be 552 B');
  const topo = materializePf6Topology();
  const inputs = [];
  material.verifierRoles.forEach((role, i) => {
    inputs.push({
      outpoint: verifierSourceOutpoints[i],
      unlockingBytecode: Uint8Array.from(Buffer.from(role.unlock, 'hex')),
      sequenceNumber,
    });
  });
  inputs.push({ outpoint: packetSourceOutpoint, unlockingBytecode: encodePacketUnlock(packet), sequenceNumber });
  inputs.push({ outpoint: stateSourceOutpoint, unlockingBytecode: stateUnlock, sequenceNumber });
  inputs.push({ outpoint: null, unlockingBytecode: feeUnlock, sequenceNumber: 0xfffffffen }); // fee filled by coordinator
  if (inputs.length !== topo.inputCount) throw new Pf6SettlementError('INPUT_COUNT', `expected ${topo.inputCount}`);
  if (outputs.length !== topo.depositTransferOutputCount && outputs.length !== topo.withdrawalOutputCount) {
    throw new Pf6SettlementError('OUTPUT_COUNT', `expected ${topo.depositTransferOutputCount} or ${topo.withdrawalOutputCount}`);
  }
  return Object.freeze({
    schema: 'shieldkit-v2-direct-pf6-settlement-v1',
    topologyId: topo.id,
    inputs,
    outputs,
    packetSha256: createHash('sha256').update(packet).digest('hex'),
    digestCarrierIndex: topo.digestCarrierIndex,
    digestPayloadOffset: topo.digestPayloadOffset,
    inputCount: inputs.length,
    outputCount: outputs.length,
  });
}

/** Pool-create outputs for a fresh pf6 pool (6 verifier locks + OP_1 carrier + state covenant + change). */
export function pf6PoolCreateOutputs({ verifierLocks, stateCovenantLock, carrierValueSatoshis = 1200n, stateValueSatoshis }) {
  return [
    ...verifierLocks.map((lock) => ({ lockingBytecode: lock, valueSatoshis: carrierValueSatoshis })),
    { lockingBytecode: PF6_PACKET_INPUT_LOCK, valueSatoshis: carrierValueSatoshis },
    { lockingBytecode: stateCovenantLock, valueSatoshis: stateValueSatoshis },
  ];
}
