import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  unlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  assertLocalVerifierRuntimeCoherence,
} from '../../../scripts/run-domain-tests.mjs';
import {
  canonicalizeJcs,
} from '../../profile/v2/profile-core.mjs';

const projectRoot = path.resolve(import.meta.dirname, '../../..');
const artifactRoot = path.resolve(projectRoot, '../../.codex-build');
const sourceRuntimeRoot = path.join(
  artifactRoot,
  'v2-pf10-development-runtime',
);
const profileRoot = path.join(artifactRoot, 'v2-development-profile');
const sourceLibauthRoot = path.join(
  artifactRoot,
  'v2-pf10-libauth-qualification',
);
const sourceQualificationEvidence = path.join(
  artifactRoot,
  'v2-dev-proof-qualification/qualification-evidence.json',
);

const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');

async function privateCopyTree(source, destination) {
  await mkdir(destination, { mode: 0o700 });
  for (const entry of await readdir(source, { withFileTypes: true })) {
    const sourcePath = path.join(source, entry.name);
    const destinationPath = path.join(destination, entry.name);
    if (entry.isDirectory()) {
      await privateCopyTree(sourcePath, destinationPath);
    } else if (entry.isFile()) {
      const sourceMetadata = await lstat(sourcePath);
      assert.equal(sourceMetadata.nlink, 1, sourcePath);
      await copyFile(
        sourcePath,
        destinationPath,
        fsConstants.COPYFILE_FICLONE,
      );
      await chmod(destinationPath, 0o600);
      const destinationMetadata = await lstat(destinationPath);
      assert.equal(destinationMetadata.isFile(), true, destinationPath);
      assert.equal(destinationMetadata.isSymbolicLink(), false, destinationPath);
      assert.equal(destinationMetadata.nlink, 1, destinationPath);
    } else {
      throw new Error(`runtime fixture contains a non-file entry: ${sourcePath}`);
    }
  }
}

async function replaceFile(filename, bytes) {
  const temporary = `${filename}.replace-${process.pid}`;
  await writeFile(temporary, bytes, { flag: 'wx', mode: 0o600 });
  await chmod(temporary, 0o600);
  await rename(temporary, filename);
}

async function restoreFile(runtimeRoot, relativePath) {
  await replaceFile(
    path.join(runtimeRoot, relativePath),
    await readFile(path.join(sourceRuntimeRoot, relativePath)),
  );
}

async function restoreLibauthFile(libauthRoot, relativePath) {
  await replaceFile(
    path.join(libauthRoot, relativePath),
    await readFile(path.join(sourceLibauthRoot, relativePath)),
  );
}

function updateManifestedArtifactReferences(value, {
  artifactId,
  bytes,
  sha256: artifactSha256,
}) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      updateManifestedArtifactReferences(entry, {
        artifactId,
        bytes,
        sha256: artifactSha256,
      });
    }
    return;
  }
  if (value === null || typeof value !== 'object') return;
  if (value.id === artifactId) {
    if (Object.hasOwn(value, 'sha256')) value.sha256 = artifactSha256;
    if (Object.hasOwn(value, 'bytes')) value.bytes = bytes;
  }
  for (const entry of Object.values(value)) {
    updateManifestedArtifactReferences(entry, {
      artifactId,
      bytes,
      sha256: artifactSha256,
    });
  }
}

async function mutateManifestedArtifact({
  runtimeRoot,
  artifactId,
  transform,
}) {
  const manifestPath = path.join(runtimeRoot, 'runtime-build-manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const artifact = manifest.artifactManifestTemplate.artifacts.find(
    (entry) => entry.id === artifactId,
  );
  assert.notEqual(artifact, undefined, `missing runtime artifact ${artifactId}`);
  const filename = path.join(runtimeRoot, ...artifact.path.split('/'));
  const mutated = await transform(await readFile(filename));
  await replaceFile(filename, mutated);
  updateManifestedArtifactReferences(manifest, {
    artifactId,
    bytes: mutated.length,
    sha256: sha256(mutated),
  });
  await replaceFile(
    manifestPath,
    Buffer.from(canonicalizeJcs(manifest), 'utf8'),
  );
  return artifact.path;
}

async function expectRejected(runtimeRoot, libauthRoot, pattern) {
  const qualificationEvidenceSha256 = sha256(
    await readFile(sourceQualificationEvidence),
  );
  await assert.rejects(
    () => assertLocalVerifierRuntimeCoherence({
      projectRoot,
      runtimeRoot,
      profileRoot,
      libauthRoot,
      qualificationEvidenceSha256,
    }),
    pattern,
  );
}

test('complete PF10 bundle gate rejects self-hashed semantic substitutions', async (t) => {
  const privateTemporaryRoot = process.env.TMPDIR;
  assert.equal(typeof privateTemporaryRoot, 'string');
  const root = await mkdtemp(path.join(
    privateTemporaryRoot,
    'pf10-runtime-bundle-redteam-',
  ));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const runtimeRoot = path.join(root, 'runtime');
  const libauthRoot = path.join(root, 'libauth');
  await privateCopyTree(sourceRuntimeRoot, runtimeRoot);
  await privateCopyTree(sourceLibauthRoot, libauthRoot);
  assert.equal((await lstat(runtimeRoot)).isDirectory(), true);
  const qualificationEvidenceSha256 = sha256(
    await readFile(sourceQualificationEvidence),
  );

  await assert.doesNotReject(() =>
    assertLocalVerifierRuntimeCoherence({
      projectRoot,
      runtimeRoot,
      profileRoot,
      libauthRoot,
      qualificationEvidenceSha256,
    }));

  for (const [artifactId, pattern] of [
    ['binding-lock', /binding artifacts are not exact/u],
    ['binding-redeem', /binding artifacts are not exact/u],
    ['state-helper', /state helper is not the exact structural helper/u],
    ['state-helper-unlock', /state helper unlock is not canonical/u],
    ['state-lock', /state lock is not the exact structural trampoline/u],
    ['verifier-lock-0', /state helper is not the exact structural helper/u],
  ]) {
    const relativePath = await mutateManifestedArtifact({
      runtimeRoot,
      artifactId,
      transform: async (bytes) => {
        const mutated = Buffer.from(bytes);
        mutated[Math.floor(mutated.length / 2)] ^= 0x01;
        return mutated;
      },
    });
    await expectRejected(runtimeRoot, libauthRoot, pattern);
    await restoreFile(runtimeRoot, relativePath);
    await restoreFile(runtimeRoot, 'runtime-build-manifest.json');
  }

  const packagePath = await mutateManifestedArtifact({
    runtimeRoot,
    artifactId: 'development-profile-package',
    transform: async (bytes) => {
      const value = JSON.parse(bytes.toString('utf8'));
      value.untrustedMutation = true;
      return Buffer.from(canonicalizeJcs(value), 'utf8');
    },
  });
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /bundled development profile is invalid/u,
  );
  await restoreFile(runtimeRoot, packagePath);
  await restoreFile(runtimeRoot, 'runtime-build-manifest.json');

  const corePath = await mutateManifestedArtifact({
    runtimeRoot,
    artifactId: 'profile-core',
    transform: async (bytes) => {
      const value = JSON.parse(bytes.toString('utf8'));
      value.network = { id: 1, name: 'mainnet' };
      return Buffer.from(canonicalizeJcs(value), 'utf8');
    },
  });
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /bundled development profile is invalid/u,
  );
  await restoreFile(runtimeRoot, corePath);
  await restoreFile(runtimeRoot, 'runtime-build-manifest.json');

  const runtimeArtifactPath = await mutateManifestedArtifact({
    runtimeRoot,
    artifactId: 'pf10-runtime-material',
    transform: async (bytes) =>
      Buffer.from(`${JSON.stringify(JSON.parse(bytes.toString('utf8')), null, 2)}\n`),
  });
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /runtime material artifact is not canonical JCS/u,
  );
  await restoreFile(runtimeRoot, runtimeArtifactPath);
  await restoreFile(runtimeRoot, 'runtime-build-manifest.json');

  const manifestPath = path.join(runtimeRoot, 'runtime-build-manifest.json');
  const canonicalManifest = await readFile(manifestPath);
  await replaceFile(
    manifestPath,
    Buffer.from(`${JSON.stringify(JSON.parse(canonicalManifest), null, 2)}\n`),
  );
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /runtime build manifest must be an exact canonical JCS object/u,
  );
  await replaceFile(manifestPath, canonicalManifest);

  const reordered = JSON.parse(canonicalManifest);
  [
    reordered.artifactManifestTemplate.artifacts[0],
    reordered.artifactManifestTemplate.artifacts[1],
  ] = [
    reordered.artifactManifestTemplate.artifacts[1],
    reordered.artifactManifestTemplate.artifacts[0],
  ];
  await replaceFile(
    manifestPath,
    Buffer.from(canonicalizeJcs(reordered), 'utf8'),
  );
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /id is invalid, duplicated, or out of order/u,
  );
  await replaceFile(manifestPath, canonicalManifest);

  const aliased = JSON.parse(canonicalManifest);
  const [aliasSource, aliasTarget] =
    aliased.artifactManifestTemplate.artifacts;
  aliasTarget.path = aliasSource.path;
  aliasTarget.sha256 = aliasSource.sha256;
  await replaceFile(
    manifestPath,
    Buffer.from(canonicalizeJcs(aliased), 'utf8'),
  );
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /path aliases another runtime artifact/u,
  );
  await replaceFile(manifestPath, canonicalManifest);

  const extraBytes = Buffer.from('unreferenced runtime artifact\n');
  await writeFile(
    path.join(runtimeRoot, 'extra.bin'),
    extraBytes,
    { flag: 'wx', mode: 0o600 },
  );
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /contains an unmanifested file: extra\.bin/u,
  );
  const extra = JSON.parse(canonicalManifest);
  extra.artifactManifestTemplate.artifacts.push({
    id: 'zz-unreferenced',
    path: 'extra.bin',
    sha256: sha256(extraBytes),
  });
  await replaceFile(
    manifestPath,
    Buffer.from(canonicalizeJcs(extra), 'utf8'),
  );
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /must contain the exact 57-artifact bundle/u,
  );
  await unlink(path.join(runtimeRoot, 'extra.bin'));
  await replaceFile(manifestPath, canonicalManifest);

  const forgedRawQualificationPath = await mutateManifestedArtifact({
    runtimeRoot,
    artifactId: 'pf10-qualification-raw-evidence',
    transform: async (bytes) => {
      const value = JSON.parse(bytes.toString('utf8'));
      value.claims.production = true;
      return Buffer.from(canonicalizeJcs(value), 'utf8');
    },
  });
  const forgedCanonicalQualificationPath = await mutateManifestedArtifact({
    runtimeRoot,
    artifactId: 'pf10-qualification-evidence',
    transform: async (bytes) => {
      const value = JSON.parse(bytes.toString('utf8'));
      value.claims.production = true;
      value.rawEvidenceSha256 = sha256(await readFile(
        path.join(runtimeRoot, forgedRawQualificationPath),
      ));
      return Buffer.from(canonicalizeJcs(value), 'utf8');
    },
  });
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /development qualification evidence makes invalid claims/u,
  );
  await restoreFile(runtimeRoot, forgedRawQualificationPath);
  await restoreFile(runtimeRoot, forgedCanonicalQualificationPath);
  await replaceFile(manifestPath, canonicalManifest);

  const driftedRawQualificationPath = await mutateManifestedArtifact({
    runtimeRoot,
    artifactId: 'pf10-qualification-raw-evidence',
    transform: async (bytes) => {
      const value = JSON.parse(bytes.toString('utf8'));
      value.measurements.totalWallMs += 1;
      return Buffer.from(canonicalizeJcs(value), 'utf8');
    },
  });
  const driftedCanonicalQualificationPath = await mutateManifestedArtifact({
    runtimeRoot,
    artifactId: 'pf10-qualification-evidence',
    transform: async (bytes) => {
      const value = JSON.parse(bytes.toString('utf8'));
      value.rawEvidenceSha256 = sha256(await readFile(
        path.join(runtimeRoot, driftedRawQualificationPath),
      ));
      return Buffer.from(canonicalizeJcs(value), 'utf8');
    },
  });
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /does not byte-bind the current qualification evidence/u,
  );
  await restoreFile(runtimeRoot, driftedRawQualificationPath);
  await restoreFile(runtimeRoot, driftedCanonicalQualificationPath);
  await replaceFile(manifestPath, canonicalManifest);

  const badRepro = JSON.parse(canonicalManifest);
  badRepro.build.programs.executor.raw = '00'.repeat(32);
  await replaceFile(
    manifestPath,
    Buffer.from(canonicalizeJcs(badRepro), 'utf8'),
  );
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /programs\.executor\.raw does not bind its reproducibility artifact/u,
  );
  await replaceFile(manifestPath, canonicalManifest);

  const forgedReproRawPath = await mutateManifestedArtifact({
    runtimeRoot,
    artifactId: 'repro-executor-raw',
    transform: async (bytes) => {
      const mutated = Buffer.from(bytes);
      mutated[Math.floor(mutated.length / 2)] ^= 0x01;
      return mutated;
    },
  });
  const selfConsistentRepro = JSON.parse(await readFile(manifestPath, 'utf8'));
  selfConsistentRepro.build.programs.executor.raw =
    selfConsistentRepro.artifactManifestTemplate.artifacts.find(
      (entry) => entry.id === 'repro-executor-raw',
    ).sha256;
  await replaceFile(
    manifestPath,
    Buffer.from(canonicalizeJcs(selfConsistentRepro), 'utf8'),
  );
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /retained raw bytecode is not compiled from its source/u,
  );
  await restoreFile(runtimeRoot, forgedReproRawPath);
  await replaceFile(manifestPath, canonicalManifest);

  const publicationPath = path.join(
    libauthRoot,
    'publication-complete.json',
  );
  const summaryPath = path.join(libauthRoot, 'qualification-summary.json');
  const summaryValue = JSON.parse(await readFile(summaryPath, 'utf8'));
  const noncanonicalSummary = Buffer.from(
    `${JSON.stringify(summaryValue, null, 2)}\n`,
  );
  await replaceFile(summaryPath, noncanonicalSummary);
  const publication = JSON.parse(await readFile(publicationPath, 'utf8'));
  const summaryRecord = publication.files.find(
    (entry) => entry.path === 'qualification-summary.json',
  );
  summaryRecord.bytes = noncanonicalSummary.length;
  summaryRecord.sha256 = sha256(noncanonicalSummary);
  await replaceFile(
    publicationPath,
    Buffer.from(canonicalizeJcs(publication), 'utf8'),
  );
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /qualification summary is not canonical JCS/u,
  );
  await restoreLibauthFile(libauthRoot, 'qualification-summary.json');
  await restoreLibauthFile(libauthRoot, 'publication-complete.json');

  const wrongRole = JSON.parse(canonicalManifest);
  wrongRole.finalLocks.verifiers[0].role =
    wrongRole.finalLocks.verifiers[1].role;
  await replaceFile(
    manifestPath,
    Buffer.from(canonicalizeJcs(wrongRole), 'utf8'),
  );
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /verifier final lock is invalid/u,
  );
  await replaceFile(manifestPath, canonicalManifest);

  const wrongBase = JSON.parse(canonicalManifest);
  wrongBase.finalLocks.verifiers[0].baseSats = '1201';
  await replaceFile(
    manifestPath,
    Buffer.from(canonicalizeJcs(wrongBase), 'utf8'),
  );
  await expectRejected(
    runtimeRoot,
    libauthRoot,
    /verifier final lock is invalid/u,
  );
});
