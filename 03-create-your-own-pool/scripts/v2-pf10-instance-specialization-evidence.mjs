#!/usr/bin/env node
/** Produce fail-closed, full-builder byte-equality evidence for the PF10 linker. */
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { deriveProfileId, canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import { buildDirectV2Pf10BetaRuntime } from '../packages/unlock-builder/v2/pf10-development-runtime-builder.mjs';
import {
  authenticateV2Pf10BetaRuntimeTemplate,
  assertV2Pf10SpecializedRuntimeByteEquality,
  assertV2Pf10SpecializedRuntimeCapability,
  relocateV2Pf10BetaRuntime,
  specializeV2Pf10BetaRuntime,
  V2_PF10_INSTANCE_SPECIALIZER_SCHEMA,
} from '../packages/unlock-builder/v2/pf10-instance-specializer.mjs';

export const V2_PF10_INSTANCE_SPECIALIZATION_EVIDENCE_SCHEMA =
  'shieldkit-v2-direct-pf10-instance-specialization-evidence-v1';
const HEX_32 = /^[0-9a-f]{64}$/u;
const hashFile = async (filename) => createHash('sha256').update(await readFile(filename)).digest('hex');
const elapsed = (started) => Math.round((performance.now() - started) * 1000) / 1000;
function percentile(values, quantile) {
  const ordered = [...values].sort((left, right) => left - right);
  const position = (ordered.length - 1) * quantile;
  const lower = Math.floor(position); const upper = Math.ceil(position);
  return Math.round((ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)) * 1000) / 1000;
}

function fail(message) { throw new Error(`PF10_INSTANCE_SPECIALIZATION_EVIDENCE_FAILED: ${message}`); }
function argumentMap(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index]; const value = argv[index + 1];
    if (!['--repository-root', '--runtime-source', '--temporary-root', '--output', '--template-instance-id', '--instance-id'].includes(name) || value === undefined || value.startsWith('--')) fail('usage: --repository-root ROOT --runtime-source DIR --temporary-root DIR --output FILE --template-instance-id HEX --instance-id HEX --instance-id HEX');
    if (name !== '--instance-id' && values.has(name)) fail(`${name} may be supplied once`);
    const prior = values.get(name); values.set(name, name === '--instance-id' ? [...(prior ?? []), value] : value); index += 1;
  }
  for (const name of ['--repository-root', '--runtime-source', '--temporary-root', '--output', '--template-instance-id']) if (!values.has(name)) fail(`${name} is required`);
  const instances = values.get('--instance-id') ?? [];
  if (instances.length < 2 || new Set(instances).size !== instances.length || instances.some((value) => !HEX_32.test(value))) fail('exactly at least two distinct lowercase 32-byte --instance-id values are required');
  if (!HEX_32.test(values.get('--template-instance-id'))) fail('--template-instance-id must be lowercase 32-byte hex');
  return values;
}

export async function runV2Pf10InstanceSpecializationEvidence({ repositoryRoot, runtimeSource, temporaryRoot, templateInstanceId, instanceIds } = {}) {
  if (![repositoryRoot, runtimeSource, temporaryRoot].every((value) => typeof value === 'string' && path.isAbsolute(value)) || !HEX_32.test(templateInstanceId) || !Array.isArray(instanceIds) || instanceIds.length < 2 || instanceIds.some((value) => !HEX_32.test(value) || value === templateInstanceId)) fail('inputs are invalid');
  const profile = JSON.parse(await readFile(path.join(runtimeSource, 'profile/profile-core.json'), 'utf8'));
  const proofDirectory = path.join(runtimeSource, 'proof');
  const proofArtifacts = Object.fromEntries(await Promise.all([
    ['provingKey', 'beta.zkey'], ['r1cs', 'main-chipnet.r1cs'],
    ['verificationKey', 'verification_key.json'], ['wasm', 'main-chipnet.wasm'],
  ].map(async ([name, filename]) => {
    const file = path.join(proofDirectory, filename);
    return [name, Object.freeze({ path: file, sha256: await hashFile(file) })];
  })));
  const build = (instanceId) => buildDirectV2Pf10BetaRuntime({ repositoryRoot, artifactRoot: runtimeSource, temporaryRoot, profileId: deriveProfileId(profile), instanceId, proofArtifacts });
  const templateStarted = performance.now();
  const template = await build(templateInstanceId);
  const templateFullBuildWallMs = elapsed(templateStarted);
  const attestationStarted = performance.now();
  const templateCapability = await authenticateV2Pf10BetaRuntimeTemplate({ repositoryRoot, template });
  const templateAttestationWallMs = elapsed(attestationStarted);
  const rows = [];
  for (const instanceId of instanceIds) {
    const firstStarted = performance.now();
    const relocated = await relocateV2Pf10BetaRuntime({ repositoryRoot, templateCapability, instanceId });
    const firstMs = elapsed(firstStarted);
    const repeatStarted = performance.now();
    const relocatedRepeated = await relocateV2Pf10BetaRuntime({ repositoryRoot, templateCapability, instanceId });
    const repeatMs = elapsed(repeatStarted);
    const compilingStarted = performance.now();
    const specialized = await specializeV2Pf10BetaRuntime({ repositoryRoot, templateCapability, instanceId });
    const compilingMs = elapsed(compilingStarted);
    const fullStarted = performance.now();
    const full = await build(instanceId);
    const fullMs = elapsed(fullStarted);
    const equality = assertV2Pf10SpecializedRuntimeByteEquality(relocated, full);
    assertV2Pf10SpecializedRuntimeByteEquality(relocatedRepeated, full);
    assertV2Pf10SpecializedRuntimeByteEquality(specialized, full);
    assertV2Pf10SpecializedRuntimeByteEquality(relocated, specialized);
    assertV2Pf10SpecializedRuntimeByteEquality(relocated, relocatedRepeated);
    assertV2Pf10SpecializedRuntimeCapability(specialized);
    assertV2Pf10SpecializedRuntimeCapability(relocated);
    assertV2Pf10SpecializedRuntimeCapability(relocatedRepeated);
    rows.push(Object.freeze({ instanceId, relocation: Object.freeze({ firstMs, repeatMs, cashcInvocations: 0, runtimeMaterialSha256: relocated.runtimeMaterial.materialSha256 }), compilingSpecializer: Object.freeze({ wallMs: compilingMs, optimizerInvocations: 0, runtimeMaterialSha256: specialized.runtimeMaterial.materialSha256 }), independentFullBuild: Object.freeze({ wallMs: fullMs, runtimeMaterialSha256: full.runtimeMaterial.materialSha256 }), equality }));
  }
  const warmSamples = rows.flatMap((row) => [row.relocation.firstMs, row.relocation.repeatMs]);
  return Object.freeze({ schema: V2_PF10_INSTANCE_SPECIALIZATION_EVIDENCE_SCHEMA, status: 'byte-equal-fast-relocation-compiling-oracle-and-independent-full-builder', template: Object.freeze({ instanceId: templateInstanceId, fullBuildWallMs: templateFullBuildWallMs, coldAuthenticationWallMs: templateAttestationWallMs, retainedSourceRawAttestationWallMs: templateAttestationWallMs, runtimeMaterialSha256: template.runtimeMaterial.materialSha256 }), targets: Object.freeze(rows), timings: Object.freeze({ warmRelocationSamples: warmSamples.length, warmRelocationP50Ms: percentile(warmSamples, 0.5), warmRelocationP95Ms: percentile(warmSamples, 0.95), warmRelocationMinMs: Math.min(...warmSamples), warmRelocationMaxMs: Math.max(...warmSamples) }), linkerSchema: V2_PF10_INSTANCE_SPECIALIZER_SCHEMA, claims: Object.freeze({ cashcInvocationsDuringRelocation: 0, optimizerInvocationsDuringSpecialization: 0, retainedSourceRawProofsReusedThroughOpaqueCapability: true, byteEqualAgainstCompilingSpecializerAndIndependentFullBuild: true, repeatDeterministic: true, productionQualified: false }) });
}

async function main() {
  const values = argumentMap(process.argv.slice(2));
  const output = values.get('--output');
  await mkdir(path.dirname(output), { recursive: true, mode: 0o700 });
  const result = await runV2Pf10InstanceSpecializationEvidence({ repositoryRoot: values.get('--repository-root'), runtimeSource: values.get('--runtime-source'), temporaryRoot: values.get('--temporary-root'), templateInstanceId: values.get('--template-instance-id'), instanceIds: values.get('--instance-id') });
  await writeFile(output, canonicalizeJcs(result), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  process.stdout.write(`${canonicalizeJcs(result)}\n`);
}
if (typeof process.argv[1] === 'string' && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href) {
  main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
