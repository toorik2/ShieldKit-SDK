import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  DIRECT_V2_PF10_BETA_ACTION_WITNESS_SCHEMA,
  DIRECT_V2_PF10_BETA_ELIGIBILITY,
  DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
} from './pf10-action-witness.mjs';
import {
  DIRECT_V2_PF10_BETA_RUNTIME_BUILD_SCHEMA,
  buildDirectV2Pf10BetaRuntime,
} from './pf10-development-runtime-builder.mjs';
import { assertPf10BetaRuntimeLane } from './pf10-beta-runtime-assertions.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '../../../..');
const verificationKeyFixture = path.join(
  repositoryRoot,
  'shieldkit-groth-94kb/packages/prove/test-fixtures/two-public/verification_key.json',
);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

async function generatedBetaInputs(root) {
  const artifactsDirectory = path.join(root, 'proof-artifacts');
  await mkdir(artifactsDirectory, { mode: 0o700 });
  const fixtures = Object.freeze({
    provingKey: Buffer.from('deterministic PF10 beta proving-key fixture\n'),
    r1cs: Buffer.from('deterministic PF10 beta r1cs fixture\n'),
    verificationKey: await readFile(verificationKeyFixture),
    wasm: Buffer.from('deterministic PF10 beta witness-wasm fixture\n'),
  });
  const filenames = Object.freeze({
    provingKey: 'fixture.zkey',
    r1cs: 'fixture.r1cs',
    verificationKey: 'verification_key.json',
    wasm: 'fixture.wasm',
  });
  return Object.freeze({
    profileId: 'ab'.repeat(32),
    proofArtifacts: Object.freeze(Object.fromEntries(await Promise.all(
      Object.entries(fixtures).map(async ([name, bytes]) => {
        const filename = path.join(artifactsDirectory, filenames[name]);
        await writeFile(filename, bytes, { flag: 'wx', mode: 0o600 });
        return [name, Object.freeze({ path: filename, sha256: sha256(bytes) })];
      }),
    ))),
  });
}

test('PF10 beta runtime has a distinct material/build/witness lane with generated portable artifacts', async () => {
  assert.equal(DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA, 'shieldkit-v2-direct-pf10-beta-runtime-material-v1');
  assert.equal(DIRECT_V2_PF10_BETA_RUNTIME_BUILD_SCHEMA, 'shieldkit-v2-direct-pf10-beta-runtime-build-v1');
  assert.equal(DIRECT_V2_PF10_BETA_ACTION_WITNESS_SCHEMA, 'shieldkit-v2-direct-pf10-beta-action-witness-v1');
  assert.equal(DIRECT_V2_PF10_BETA_ELIGIBILITY, 'beta-single-contributor-unqualified');
  const testRoot = await mkdtemp(path.join(tmpdir(), 'shieldkit-pf10-beta-runtime-test-'));
  await chmod(testRoot, 0o700);
  const artifactRoot = path.join(testRoot, 'artifacts');
  const temporaryRoot = path.join(testRoot, 'scratch');
  await mkdir(artifactRoot, { mode: 0o700 });
  await mkdir(temporaryRoot, { mode: 0o700 });
  try {
    const inputs = await generatedBetaInputs(artifactRoot);
    const runtime = await buildDirectV2Pf10BetaRuntime({
      repositoryRoot,
      artifactRoot,
      temporaryRoot,
      profileId: inputs.profileId,
      instanceId: 'be'.repeat(32),
      proofArtifacts: inputs.proofArtifacts,
    });
    assertPf10BetaRuntimeLane(runtime, inputs);
    assert.equal(
      runtime.proofArtifacts.provingKey.path,
      'proof-artifacts/fixture.zkey',
    );
    assert.equal(
      JSON.stringify(runtime).includes(artifactRoot),
      false,
      'runtime output must not leak its private absolute artifact root',
    );
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: inputs.proofArtifacts,
      }),
      /requires an explicit artifactRoot/u,
    );
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot: testRoot,
        artifactRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: inputs.proofArtifacts,
      }),
      /exact checkout containing the loaded PF10 builder/u,
    );
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: {
          ...inputs.proofArtifacts,
          provingKey: {
            path: verificationKeyFixture,
            sha256: sha256(await readFile(verificationKeyFixture)),
          },
        },
      }),
      /PF10 provingKey escapes artifactRoot/u,
    );
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: {
          ...inputs.proofArtifacts,
          provingKey: {
            ...inputs.proofArtifacts.provingKey,
            path: `${artifactRoot}/proof-artifacts/../proof-artifacts/fixture.zkey`,
          },
        },
      }),
      /proofArtifacts must contain exact path\/SHA-256 records/u,
    );
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: {
          ...inputs.proofArtifacts,
          provingKey: {
            ...inputs.proofArtifacts.provingKey,
            sha256: '00'.repeat(32),
          },
        },
      }),
      /SHA-256 differs from the supplied profile pin/u,
    );
    const emptyArtifact = path.join(artifactRoot, 'empty.zkey');
    await writeFile(emptyArtifact, Buffer.alloc(0), { mode: 0o600 });
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: {
          ...inputs.proofArtifacts,
          provingKey: { path: emptyArtifact, sha256: sha256(Buffer.alloc(0)) },
        },
      }),
      /canonical nonempty regular file/u,
    );
    const symlinkArtifact = path.join(artifactRoot, 'symlink.zkey');
    await symlink(inputs.proofArtifacts.provingKey.path, symlinkArtifact);
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: {
          ...inputs.proofArtifacts,
          provingKey: {
            path: symlinkArtifact,
            sha256: inputs.proofArtifacts.provingKey.sha256,
          },
        },
      }),
      /canonical nonempty regular file/u,
    );
    const hardlinkArtifact = path.join(artifactRoot, 'hardlink.zkey');
    await link(inputs.proofArtifacts.provingKey.path, hardlinkArtifact);
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: {
          ...inputs.proofArtifacts,
          provingKey: {
            path: hardlinkArtifact,
            sha256: inputs.proofArtifacts.provingKey.sha256,
          },
        },
      }),
      /canonical nonempty regular file/u,
    );
    await rm(hardlinkArtifact);
    await chmod(artifactRoot, 0o755);
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: inputs.proofArtifacts,
      }),
      /artifactRoot must be an owner-private directory/u,
    );
    await chmod(artifactRoot, 0o700);
    const artifactParentAlias = path.join(testRoot, 'artifact-parent-alias');
    await symlink(testRoot, artifactParentAlias);
    const aliasedArtifactRoot = path.join(artifactParentAlias, 'artifacts');
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot: aliasedArtifactRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: Object.freeze(Object.fromEntries(
          Object.entries(inputs.proofArtifacts).map(([name, record]) => [
            name,
            Object.freeze({
              ...record,
              path: path.join(
                aliasedArtifactRoot,
                path.relative(artifactRoot, record.path),
              ),
            }),
          ]),
        )),
      }),
      /artifactRoot must be a canonical non-symlink directory/u,
    );
    const scratchSymlink = path.join(testRoot, 'scratch-link');
    await symlink(temporaryRoot, scratchSymlink);
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot,
        temporaryRoot: scratchSymlink,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: inputs.proofArtifacts,
      }),
      /temporaryRoot (?:is not readable|must be a canonical non-symlink directory)/u,
    );
    await chmod(temporaryRoot, 0o755);
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: inputs.proofArtifacts,
      }),
      /temporaryRoot must be an owner-private directory/u,
    );
    await chmod(temporaryRoot, 0o700);
    const missingScratch = path.join(testRoot, 'created-scratch');
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot,
        temporaryRoot: missingScratch,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: {
          ...inputs.proofArtifacts,
          provingKey: {
            ...inputs.proofArtifacts.provingKey,
            sha256: '00'.repeat(32),
          },
        },
      }),
      /SHA-256 differs from the supplied profile pin/u,
    );
    assert.deepEqual(
      await readdir(missingScratch),
      [],
      'failed builds must remove only their identity-bound work directory',
    );
    await assert.rejects(
      buildDirectV2Pf10BetaRuntime({
        repositoryRoot,
        artifactRoot,
        temporaryRoot,
        profileId: inputs.profileId,
        instanceId: 'be'.repeat(32),
        proofArtifacts: inputs.proofArtifacts,
        libauthEvidence: inputs.proofArtifacts.r1cs,
      }),
      /does not accept Libauth evidence/u,
    );
  } finally {
    await rm(testRoot, { recursive: true, force: true });
  }
});
