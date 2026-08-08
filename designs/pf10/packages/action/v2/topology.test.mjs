import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
  directV2VerifierTopologyById,
  listDirectV2VerifierTopologies,
  resolveDirectV2VerifierTopology,
} from './topology.mjs';

test('derives every role index from the exact protocol-defined topology', () => {
  const pf11 = directV2VerifierTopologyById(
    DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  );
  assert.deepEqual(pf11.verifierRoles, DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES);
  assert.deepEqual({
    carrierCount: pf11.carrierCount,
    binding: pf11.bindingInputIndex,
    state: pf11.stateInputIndex,
    funding: pf11.fundingInputIndex,
    inputs: pf11.inputCount,
    depositOutputs: pf11.depositTransferOutputCount,
    withdrawalOutputs: pf11.withdrawalOutputCount,
  }, {
    carrierCount: 11,
    binding: 11,
    state: 12,
    funding: 13,
    inputs: 14,
    depositOutputs: 14,
    withdrawalOutputs: 15,
  });

  const pf10 = directV2VerifierTopologyById(
    DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  );
  assert.deepEqual(pf10.verifierRoles, DIRECT_V2_PF10_FUSED_VERIFIER_ROLES);
  assert.deepEqual({
    carrierCount: pf10.carrierCount,
    binding: pf10.bindingInputIndex,
    state: pf10.stateInputIndex,
    funding: pf10.fundingInputIndex,
    inputs: pf10.inputCount,
    depositOutputs: pf10.depositTransferOutputCount,
    withdrawalOutputs: pf10.withdrawalOutputCount,
  }, {
    carrierCount: 10,
    binding: 10,
    state: 11,
    funding: 12,
    inputs: 13,
    depositOutputs: 13,
    withdrawalOutputs: 14,
  });
});

test('rejects ID/role mismatches and arbitrary carrier layouts', () => {
  assert.throws(
    () => resolveDirectV2VerifierTopology({
      id: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      verifierRoles: DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
    }),
    /do not exactly match/,
  );
  assert.throws(
    () => resolveDirectV2VerifierTopology({
      id: 'pf9-made-up',
      verifierRoles: Array(9).fill('unknown'),
    }),
    /unsupported/,
  );
  assert.throws(
    () => resolveDirectV2VerifierTopology({
      id: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      verifierRoles: [
        ...DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.slice(0, 8),
        'terminal9',
        'fused-q-genesis8',
      ],
    }),
    /do not exactly match/,
  );
  assert.equal(listDirectV2VerifierTopologies().length, 2);
});

test('rejects PF10 role-count truncation and extension before topology use', () => {
  for (const verifierRoles of [
    DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.slice(0, -1),
    [
      ...DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
      'carrier-after-terminal',
    ],
  ]) {
    assert.throws(
      () => resolveDirectV2VerifierTopology({
        id: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
        verifierRoles,
      }),
      /do not exactly match/,
    );
  }
});
