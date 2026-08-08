import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { buildDirectV2Pf10BetaRuntime } from './pf10-development-runtime-builder.mjs';
import { assertPf10BetaRuntimeLane } from './pf10-beta-runtime-assertions.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '../../../../..');
const artifactRoot = process.env.SHIELDKIT_V2_PF10_BETA_RUNTIME_ARTIFACT_DIR === undefined
  ? path.join(repositoryRoot, '.codex-build')
  : path.resolve(process.env.SHIELDKIT_V2_PF10_BETA_RUNTIME_ARTIFACT_DIR);
const profilePackagePath = process.env.SHIELDKIT_V2_PF10_BETA_RUNTIME_PROFILE_PACKAGE === undefined
  ? path.join(artifactRoot, 'v2-development-profile/profile-package.json')
  : path.resolve(process.env.SHIELDKIT_V2_PF10_BETA_RUNTIME_PROFILE_PACKAGE);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

async function requirePrivateArtifact(filename) {
  try {
    const metadata = await lstat(filename);
    assert.equal(metadata.isFile(), true, `PF10_BETA_RUNTIME_QUALIFICATION_FIXTURE_REQUIRED: ${filename} must be a regular file`);
  } catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    assert.fail(`PF10_BETA_RUNTIME_QUALIFICATION_FIXTURE_REQUIRED: ${filename} is unavailable; provide the exact private artifacts with SHIELDKIT_V2_PF10_BETA_RUNTIME_ARTIFACT_DIR`);
  }
}

test('PF10 beta runtime independently rebuilds from the supplied private artifact closure', async () => {
  const packagePath = profilePackagePath;
  await requirePrivateArtifact(packagePath);
  const profilePackage = JSON.parse(await readFile(packagePath, 'utf8'));
  const proofArtifacts = Object.freeze(Object.fromEntries(await Promise.all(
    Object.entries(profilePackage.proofArtifacts)
      .filter(([name]) => ['provingKey', 'r1cs', 'verificationKey', 'witnessWasm'].includes(name))
      .map(async ([name, record]) => {
        const filename = path.resolve(repositoryRoot, record.path);
        const relative = path.relative(artifactRoot, filename);
        assert.equal(
          relative !== '' && relative !== '..'
            && !relative.startsWith(`..${path.sep}`)
            && !path.isAbsolute(relative),
          true,
          `PF10_BETA_RUNTIME_QUALIFICATION_FIXTURE_REQUIRED: ${filename} must be beneath the private artifact root`,
        );
        await requirePrivateArtifact(filename);
        return [name === 'witnessWasm' ? 'wasm' : name, Object.freeze({
          path: filename,
          sha256: sha256(await readFile(filename)),
        })];
      }),
  )));
  const buildRoot = path.join(repositoryRoot, '.codex-build');
  const temporaryRoot = await mkdtemp(path.join(buildRoot, 'pf10-beta-runtime-qualification-'));
  try {
    const inputs = Object.freeze({ profileId: profilePackage.profileId, proofArtifacts });
    const runtime = await buildDirectV2Pf10BetaRuntime({
      repositoryRoot,
      artifactRoot,
      temporaryRoot,
      profileId: inputs.profileId,
      instanceId: 'be'.repeat(32),
      proofArtifacts: inputs.proofArtifacts,
    });
    assertPf10BetaRuntimeLane(runtime, inputs);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});
