// ShieldKit-Groth-54KB — pf6 product profile schema + runtime manifest.
// VK pin: d38f3cfc (current v2-beta-product runtime; design/02 v2).
// Verifier material: src/verifier-material/pf6-material.json (measured product build).
'use strict';

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import {
  DIRECT_V2_PF6_TOPOLOGY_ID,
  DIRECT_V2_PF6_VERIFIER_ROLES,
  materializePf6Topology,
} from './topology-pf6.mjs';

export const V2_PF6_TOPOLOGY_SPEC_SCHEMA = 'shieldkit-v2-direct-pf6-topology-spec-v1';
export const V2_PF6_RUNTIME_MANIFEST_SCHEMA = 'shieldkit-v2-direct-pf6-runtime-material-v1';

export const V2_PF6_VK_SHA256 = 'd38f3cfc0c77711d1dc1c3f937764dec2155f7576054e4fd7645147344d967ef';
export const V2_PF6_PACKET_SHA256 = '882edc1044dca3917e21f549d7e26969b818e5a16486ce6f73bad0973e0f1050';
export const V2_PF6_CIRCUIT = Object.freeze({
  r1csSha256: '077f58f5deee5ae38455af3d6c0a647383b24b455e26156585d5a17b7b5b00ed',
  wasmSha256: '87f5878e8b73dcfe5d1dfc48bf237f49875a6e8d3b83a6edc98ff9fef8263d4e',
  zkeySha256: '61683ef21b497625aba4db6568406c8b4b78faee01cf3e73a14739ae88b8e3f3',
});

const HASH = /^[0-9a-f]{64}$/;

export class Pf6ProfileError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'Pf6ProfileError';
    this.code = code;
  }
}

const fail = (code, message) => { throw new Pf6ProfileError(code, message); };

/** Load + validate the pf6 verifier material manifest (locks, unlocks, sources). */
export function loadPf6VerifierMaterial(materialPath) {
  const raw = JSON.parse(readFileSync(materialPath, 'utf8'));
  if (raw.schema !== 'shieldkit-54kb/pf6-verifier-material/v1') fail('MATERIAL_SCHEMA', 'unsupported material schema');
  if (raw.topologyId !== DIRECT_V2_PF6_TOPOLOGY_ID) fail('MATERIAL_TOPOLOGY', 'material topology does not match pf6-a3-direct-v1');
  if (raw.roles.length !== DIRECT_V2_PF6_VERIFIER_ROLES.length) fail('MATERIAL_ROLES', 'verifier role count mismatch');
  raw.roles.forEach((role, index) => {
    if (role.name !== DIRECT_V2_PF6_VERIFIER_ROLES[index]) fail('MATERIAL_ROLE_NAME', `role ${index} name mismatch`);
    if (role.unlockBytes > 10_000) fail('MATERIAL_UNLOCK_CEILING', `role ${role.name} unlock exceeds 10,000 B`);
  });
  const topo = materializePf6Topology();
  return Object.freeze({
    topology: topo,
    roles: Object.freeze(raw.roles.map((r) => Object.freeze({ ...r }))),
    structuralRoles: Object.freeze(raw.structuralRoles.map((r) => Object.freeze({ ...r }))),
    programSources: Object.freeze({ ...raw.programSources }),
    vkBaked: raw.vkBaked,
    packetSha256: raw.packetSha256,
  });
}

/** Build the pf6 runtime manifest (the kit's verifier-material contract). */
export function buildPf6RuntimeManifest({ materialPath, bundleDirectory }) {
  const material = loadPf6VerifierMaterial(materialPath);
  const manifest = {
    schema: V2_PF6_RUNTIME_MANIFEST_SCHEMA,
    topologyId: DIRECT_V2_PF6_TOPOLOGY_ID,
    verifierRoles: DIRECT_V2_PF6_VERIFIER_ROLES,
    inputCount: material.topology.inputCount,
    depositTransferOutputCount: material.topology.depositTransferOutputCount,
    withdrawalOutputCount: material.topology.withdrawalOutputCount,
    digestCarrierIndex: material.topology.digestCarrierIndex,
    digestPayloadOffset: material.topology.digestPayloadOffset,
    packetInputIndex: material.topology.packetInputIndex,
    vkBakedSha256: V2_PF6_VK_SHA256,
    packetSha256: V2_PF6_PACKET_SHA256,
    circuit: V2_PF6_CIRCUIT,
    verifierUnlockTotal: material.roles.reduce((s, r) => s + r.unlockBytes, 0),
    materialSha256: createHash('sha256').update(readFileSync(materialPath)).digest('hex'),
    materialPath: path.resolve(materialPath),
    bundleDirectory,
  };
  return Object.freeze(manifest);
}

export function pf6ProfileIdentity() {
  return Object.freeze({
    schema: V2_PF6_TOPOLOGY_SPEC_SCHEMA,
    topologyId: DIRECT_V2_PF6_TOPOLOGY_ID,
    vk: V2_PF6_VK_SHA256,
    circuit: V2_PF6_CIRCUIT.zkeySha256,
  });
}
