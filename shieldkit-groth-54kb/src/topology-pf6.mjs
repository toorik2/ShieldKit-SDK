// ShieldKit-Groth-54KB — frozen pf6 topology (design/01-topology.md, FREEZE v1).
// Mirrors packages/action/v2/topology.mjs pattern; gate IDs and role names
// are frozen — do not rename without a new design revision.
'use strict';

export const DIRECT_V2_PF6_TOPOLOGY_ID = 'pf6-a3-direct-v1';

export const DIRECT_V2_PF6_VERIFIER_ROLES = Object.freeze([
  'exec0',
  'exec1',
  'exec2',
  'exec3',
  'genesis',
  'terminal',
]);

export const DIRECT_V2_PF6_STRUCTURAL_ROLES = Object.freeze([
  'packet',
  'state',
  'fee',
]);

const DEFINITIONS = Object.freeze([
  Object.freeze({
    id: DIRECT_V2_PF6_TOPOLOGY_ID,
    qualificationClass: 'product-build-r1-real-gate-green',
    verifierRoles: DIRECT_V2_PF6_VERIFIER_ROLES,
    structuralRoles: DIRECT_V2_PF6_STRUCTURAL_ROLES,
    // tx input order: exec0..exec3, genesis, terminal, packet, state, fee
    digestCarrierIndex: 4,      // genesis
    digestPayloadOffset: 451,   // 3-byte push header (4d e0 01) + 448 projection bytes
    packetInputIndex: 6,
    stateInputIndex: 7,
    fundingInputIndex: 8,
    inputCount: 9,
    depositTransferOutputCount: 9,
    withdrawalOutputCount: 10,
  }),
]);

const byId = new Map(DEFINITIONS.map((entry) => [entry.id, entry]));

export class DirectV2Pf6TopologyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2Pf6TopologyError';
  }
}

const fail = (message) => {
  throw new DirectV2Pf6TopologyError(message);
};

function equalRoles(left, right) {
  return (
    left.length === right.length
    && left.every((role, index) => role === right[index])
  );
}

export function materializePf6Topology(definition = DEFINITIONS[0]) {
  const carrierCount = definition.verifierRoles.length; // 6
  return Object.freeze({
    id: definition.id,
    qualificationClass: definition.qualificationClass,
    verifierRoles: definition.verifierRoles,
    structuralRoles: definition.structuralRoles,
    carrierCount,
    bindingInputIndex: definition.packetInputIndex,
    stateInputIndex: definition.stateInputIndex,
    fundingInputIndex: definition.fundingInputIndex,
    inputCount: definition.inputCount,
    depositTransferOutputCount: definition.depositTransferOutputCount,
    withdrawalOutputCount: definition.withdrawalOutputCount,
    digestCarrierIndex: definition.digestCarrierIndex,
    digestPayloadOffset: definition.digestPayloadOffset,
    packetInputIndex: definition.packetInputIndex,
    bindingOutputIndex: carrierCount,      // 6 (the carrier output)
    stateOutputIndex: carrierCount + 1,    // 7 (the state output)
    withdrawalOutputIndex: carrierCount + 2, // 8 (withdrawal/change-for-non-withdrawals)
    changeOutputIndex: carrierCount + 3,   // 9 (withdrawal change)
  });
}

/** Resolve only the protocol-defined pf6 topology (exact role match). */
export function resolveDirectV2Pf6VerifierTopology({ id, verifierRoles } = {}) {
  if (typeof id !== 'string' || !byId.has(id)) {
    fail('unsupported direct V2 pf6 topology ID');
  }
  if (
    !Array.isArray(verifierRoles)
    || verifierRoles.some((role) => typeof role !== 'string')
  ) {
    fail('direct V2 pf6 verifier roles must be an ordered string array');
  }
  const definition = byId.get(id);
  if (!equalRoles(verifierRoles, definition.verifierRoles)) {
    fail('direct V2 pf6 verifier roles do not exactly match the topology ID');
  }
  return materializePf6Topology(definition);
}

export function directV2Pf6TopologyById(id) {
  const definition = byId.get(id);
  if (definition === undefined) {
    fail('unsupported direct V2 pf6 topology ID');
  }
  return materializePf6Topology(definition);
}

export function listDirectV2Pf6Topologies() {
  return Object.freeze(DEFINITIONS.map(materializePf6Topology));
}
