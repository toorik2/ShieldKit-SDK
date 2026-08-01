import assert from 'node:assert/strict';

import {
  buildDirectV2Pf10ActionWitness,
  validateDirectV2Pf10BetaRuntimeMaterial,
  validateDirectV2Pf10RuntimeMaterial,
} from './pf10-action-witness.mjs';
import {
  DIRECT_V2_PF10_BETA_RUNTIME_BUILD_SCHEMA,
} from './pf10-development-runtime-builder.mjs';
import {
  DIRECT_V2_PF10_BETA_ELIGIBILITY,
  DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
} from './pf10-action-witness.mjs';

export function assertPf10BetaRuntimeLane(runtime, inputs) {
  assert.equal(runtime.schema, DIRECT_V2_PF10_BETA_RUNTIME_BUILD_SCHEMA);
  assert.equal(runtime.eligibility, DIRECT_V2_PF10_BETA_ELIGIBILITY);
  assert.equal(Object.hasOwn(runtime, 'libauthEvidence'), false);
  assert.equal(runtime.runtimeMaterial.schema, DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA);
  assert.equal(runtime.runtimeMaterialInput.schema, DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA);
  assert.equal(runtime.runtimeMaterialInput.eligibility, DIRECT_V2_PF10_BETA_ELIGIBILITY);
  assert.equal(runtime.runtimeMaterial.proofArtifactHashes.verificationKey, inputs.proofArtifacts.verificationKey.sha256);
  assert.equal(validateDirectV2Pf10BetaRuntimeMaterial(runtime.runtimeMaterialInput).materialSha256, runtime.runtimeMaterial.materialSha256);
  assert.throws(() => validateDirectV2Pf10RuntimeMaterial(runtime.runtimeMaterialInput), /eligibility|schema/u);
  assert.throws(() => validateDirectV2Pf10RuntimeMaterial({
    ...runtime.runtimeMaterialInput,
    schema: 'shieldkit-v2-direct-pf10-runtime-material-v1',
    eligibility: undefined,
  }), /eligibility/u);
  assert.throws(() => buildDirectV2Pf10ActionWitness({ runtimeMaterial: runtime.runtimeMaterial }), /validateDirectV2Pf10RuntimeMaterial/u);
  assert.throws(() => validateDirectV2Pf10BetaRuntimeMaterial({
    ...runtime.runtimeMaterialInput,
    schema: 'shieldkit-v2-direct-pf10-runtime-material-v1',
    eligibility: 'development-only',
  }), /schema|eligibility/u);
}
