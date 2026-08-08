export const DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID =
  'pf11-exact-msm-oracle-v1';
export const DIRECT_V2_PF10_FUSED_TOPOLOGY_ID =
  'pf10-fused-q-genesis-v1';

export const DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES = Object.freeze([
  'exec0',
  'exec1',
  'exec2',
  'exec3',
  'exec4',
  'msm5',
  'msm6',
  'msm7',
  'msm8',
  'miller9',
  'terminal10',
]);

export const DIRECT_V2_PF10_FUSED_VERIFIER_ROLES = Object.freeze([
  'exec0',
  'exec1',
  'exec2',
  'exec3',
  'exec4',
  'msm5',
  'msm6',
  'msm7',
  'fused-q-genesis8',
  'terminal9',
]);

const DEFINITIONS = Object.freeze([
  Object.freeze({
    id: DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
    qualificationClass: 'semantic-oracle-only',
    verifierRoles: DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
    digestCarrierIndex: 8,
    digestPayloadOffset: 448,
  }),
  Object.freeze({
    id: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    qualificationClass: 'candidate-local-libauth-hard-limit-pass',
    verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
    digestCarrierIndex: 8,
    digestPayloadOffset: 448,
  }),
]);

const byId = new Map(DEFINITIONS.map((entry) => [entry.id, entry]));

export class DirectV2TopologyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2TopologyError';
  }
}

const fail = (message) => {
  throw new DirectV2TopologyError(message);
};

function equalRoles(left, right) {
  return (
    left.length === right.length
    && left.every((role, index) => role === right[index])
  );
}

function materialize(definition) {
  const carrierCount = definition.verifierRoles.length;
  return Object.freeze({
    id: definition.id,
    qualificationClass: definition.qualificationClass,
    verifierRoles: definition.verifierRoles,
    carrierCount,
    bindingInputIndex: carrierCount,
    stateInputIndex: carrierCount + 1,
    fundingInputIndex: carrierCount + 2,
    inputCount: carrierCount + 3,
    depositTransferOutputCount: carrierCount + 3,
    withdrawalOutputCount: carrierCount + 4,
    bindingOutputIndex: carrierCount + 1,
    withdrawalOutputIndex: carrierCount + 2,
    changeOutputIndex: carrierCount + 3,
    digestCarrierIndex: definition.digestCarrierIndex,
    digestPayloadOffset: definition.digestPayloadOffset,
  });
}

/**
 * Resolve only a protocol-defined verifier topology. An arbitrary carrier
 * count is never sufficient authority: callers must provide the exact
 * topology ID and ordered role list, both of which are intended to be covered
 * by the signed instance descriptor.
 */
export function resolveDirectV2VerifierTopology({
  id,
  verifierRoles,
} = {}) {
  if (typeof id !== 'string' || !byId.has(id)) {
    fail('unsupported direct V2 verifier topology ID');
  }
  if (
    !Array.isArray(verifierRoles)
    || verifierRoles.some((role) => typeof role !== 'string')
  ) {
    fail('direct V2 verifier roles must be an ordered string array');
  }
  const definition = byId.get(id);
  if (!equalRoles(verifierRoles, definition.verifierRoles)) {
    fail('direct V2 verifier roles do not exactly match the topology ID');
  }
  return materialize(definition);
}

export function directV2VerifierTopologyById(id) {
  const definition = byId.get(id);
  if (definition === undefined) {
    fail('unsupported direct V2 verifier topology ID');
  }
  return materialize(definition);
}

export function listDirectV2VerifierTopologies() {
  return Object.freeze(DEFINITIONS.map(materialize));
}
