import assert from 'node:assert/strict';
import {
  chmod,
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  PF10_LIBAUTH_PUBLICATION_FILE,
  PF10_LIBAUTH_PUBLICATION_SCHEMA,
  QualificationError,
  QualificationPublicationCommittedError,
  preparePublicationPaths,
  publishStage,
  runPf10LibauthQualification,
  writePrivateFile,
} from './v2-pf10-libauth-qualification.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '..', '..');

const testRoot = async (t) => {
  const buildRoot = path.join(repositoryRoot, '.codex-build');
  await mkdir(buildRoot, { recursive: true, mode: 0o700 });
  await chmod(buildRoot, 0o700);
  const root = await mkdtemp(path.join(
    buildRoot,
    'pf10-libauth-publisher-test-',
  ));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
};

const optionsFor = (root, output = path.join(root, 'published')) => Object.freeze({
  output,
  profileCore: path.join(root, 'profile-core.json'),
  qualificationRoot: path.join(root, 'qualification-root'),
  r1cs: path.join(root, 'circuit.r1cs'),
  setupMetadata: path.join(root, 'setup.json'),
  temporaryRoot: path.join(root, 'temporary'),
  verificationKey: path.join(root, 'verification-key.json'),
  wasm: path.join(root, 'circuit.wasm'),
  zkey: path.join(root, 'circuit.zkey'),
});

test('PF10 Libauth publisher rejects outputs outside the repository before creating them', async (t) => {
  const root = await testRoot(t);
  const outside = path.join('/tmp', `shieldkit-pf10-outside-${process.pid}`);
  await assert.rejects(
    preparePublicationPaths(optionsFor(root, outside)),
    /output must be contained by the private build root/u,
  );
  await assert.rejects(lstat(outside), /ENOENT/u);
});

test('PF10 Libauth publisher normalizes exported API paths before containment checks', async (t) => {
  const root = await testRoot(t);
  const escaped = path.join(
    repositoryRoot,
    `pf10-libauth-path-escape-${process.pid}`,
  );
  t.after(() => rm(escaped, { recursive: true, force: true }));
  const rawEscape = `${repositoryRoot}${path.sep}.codex-build${
    path.sep}..${path.sep}${path.basename(escaped)}`;
  await assert.rejects(
    preparePublicationPaths(optionsFor(root, rawEscape)),
    /output must be contained by the private build root/u,
  );
  await assert.rejects(lstat(escaped), /ENOENT/u);
  await assert.rejects(
    preparePublicationPaths(Object.freeze({
      ...optionsFor(root),
      temporaryRoot: rawEscape,
    })),
    /temporary root must be contained by the private build root/u,
  );
  await assert.rejects(lstat(escaped), /ENOENT/u);
});

test('PF10 Libauth publisher rejects repository and source paths without chmodding them', async (t) => {
  const root = await testRoot(t);
  const sourceDirectory = path.join(
    repositoryRoot,
    'shieldkit-groth-94kb',
    'scripts',
  );
  const before = Object.freeze({
    repository: (await stat(repositoryRoot)).mode & 0o777,
    source: (await stat(sourceDirectory)).mode & 0o777,
  });
  for (const output of [
    path.join(repositoryRoot, 'forbidden-output'),
    path.join(sourceDirectory, 'forbidden-output'),
  ]) {
    await assert.rejects(
      preparePublicationPaths(optionsFor(root, output)),
      /output must be contained by the private build root/u,
    );
  }
  assert.deepEqual({
    repository: (await stat(repositoryRoot)).mode & 0o777,
    source: (await stat(sourceDirectory)).mode & 0o777,
  }, before);
});

test('PF10 Libauth publisher rejects a source-directory temporary root without chmodding it', async (t) => {
  const root = await testRoot(t);
  const sourceDirectory = path.join(
    repositoryRoot,
    'shieldkit-groth-94kb',
    'scripts',
  );
  const before = (await stat(sourceDirectory)).mode & 0o777;
  await assert.rejects(
    preparePublicationPaths(Object.freeze({
      ...optionsFor(root),
      temporaryRoot: sourceDirectory,
    })),
    /temporary root must be contained by the private build root/u,
  );
  assert.equal((await stat(sourceDirectory)).mode & 0o777, before);
});

test('PF10 Libauth publisher rejects a symlinked output parent', async (t) => {
  const root = await testRoot(t);
  const direct = path.join(root, 'direct-parent');
  const linked = path.join(root, 'linked-parent');
  await mkdir(direct, { mode: 0o700 });
  await symlink(direct, linked);
  await assert.rejects(
    preparePublicationPaths(optionsFor(root, path.join(linked, 'published'))),
    /output parent must be a direct directory/u,
  );
});

test('PF10 Libauth publisher refuses a pre-existing output without touching it', async (t) => {
  const root = await testRoot(t);
  const options = optionsFor(root);
  await mkdir(options.output, { mode: 0o700 });
  await assert.rejects(
    preparePublicationPaths(options),
    /refusing to overwrite existing output/u,
  );
  assert.equal((await lstat(options.output)).isDirectory(), true);
});

test('PF10 Libauth publisher cleans its unpublished stage and child directory after an injected child failure', async (t) => {
  const root = await testRoot(t);
  const options = optionsFor(root);
  await assert.rejects(
    runPf10LibauthQualification(options, {
      childRunner: async () => Object.freeze({
        code: 1,
        signal: null,
        stdout: Buffer.from('deliberate unit fixture failure\n'),
        stderr: Buffer.from('deliberate unit fixture failure\n'),
      }),
    }),
    QualificationError,
  );
  await assert.rejects(lstat(options.output), /ENOENT/u);
  assert.deepEqual(
    (await readdir(path.dirname(options.output))).filter((entry) =>
      entry.startsWith('.pf10-libauth-stage-')),
    [],
  );
  assert.deepEqual(await readdir(options.temporaryRoot), []);
});

test('PF10 Libauth publisher atomically publishes only a private staged directory', async (t) => {
  const root = await testRoot(t);
  const outputParent = path.join(root, 'output-parent');
  const output = path.join(outputParent, 'published');
  await mkdir(outputParent, { mode: 0o700 });
  await chmod(outputParent, 0o700);
  const stage = await mkdtemp(path.join(outputParent, '.stage-'));
  await chmod(stage, 0o700);
  await writePrivateFile(path.join(stage, 'fixture.json'), Buffer.from('{"unitFixture":true}\n'), 'unit fixture');
  const completion = await publishStage({
    stage,
    output,
    outputParent,
    files: ['fixture.json'],
  });
  assert.equal(await readFile(path.join(output, 'fixture.json'), 'utf8'), '{"unitFixture":true}\n');
  assert.deepEqual(completion, {
    schema: PF10_LIBAUTH_PUBLICATION_SCHEMA,
    files: [{
      path: 'fixture.json',
      bytes: 21,
      sha256:
        '95737c3405ef61c7473dc5f0c3bbdc3edbcc987260c4823532ae78a7484b86c5',
    }],
  });
  assert.deepEqual(
    JSON.parse(await readFile(
      path.join(output, PF10_LIBAUTH_PUBLICATION_FILE),
      'utf8',
    )),
    completion,
  );
  assert.equal((await lstat(output)).mode & 0o777, 0o700);
  assert.equal((await lstat(path.join(output, 'fixture.json'))).mode & 0o777, 0o600);
  assert.equal(
    (await lstat(path.join(output, PF10_LIBAUTH_PUBLICATION_FILE))).mode
      & 0o777,
    0o600,
  );
  await assert.rejects(lstat(stage), /ENOENT/u);
});

test('PF10 Libauth publisher preserves a destination raced before exclusive reservation', async (t) => {
  const root = await testRoot(t);
  const outputParent = path.join(root, 'raced-output-parent');
  const output = path.join(outputParent, 'published');
  await mkdir(outputParent, { mode: 0o700 });
  await chmod(outputParent, 0o700);
  const stage = await mkdtemp(path.join(outputParent, '.stage-'));
  t.after(() => rm(stage, { recursive: true, force: true }));
  await chmod(stage, 0o700);
  await writePrivateFile(path.join(stage, 'fixture.json'), Buffer.from('stage\n'), 'unit fixture');
  let before;
  await assert.rejects(
    publishStage({
      stage,
      output,
      outputParent,
      files: ['fixture.json'],
      beforeReserve: async () => {
        await mkdir(output, { mode: 0o700 });
        before = await lstat(output);
      },
    }),
    /refusing to overwrite existing output/u,
  );
  const after = await lstat(output);
  assert.equal(after.dev, before.dev);
  assert.equal(after.ino, before.ino);
  assert.deepEqual(await readdir(output), []);
  assert.equal((await lstat(stage)).isDirectory(), true);
});

test('PF10 Libauth publisher removes only its own reservation on pre-commit failure', async (t) => {
  const root = await testRoot(t);
  const outputParent = path.join(root, 'precommit-output-parent');
  const output = path.join(outputParent, 'published');
  await mkdir(outputParent, { mode: 0o700 });
  await chmod(outputParent, 0o700);
  const stage = await mkdtemp(path.join(outputParent, '.stage-'));
  t.after(() => rm(stage, { recursive: true, force: true }));
  await chmod(stage, 0o700);
  await writePrivateFile(
    path.join(stage, 'fixture.json'),
    Buffer.from('stage\n'),
    'unit fixture',
  );
  await assert.rejects(
    publishStage({
      stage,
      output,
      outputParent,
      files: ['fixture.json'],
      beforeCommit: async () => {
        throw new Error('injected pre-commit failure');
      },
    }),
    /injected pre-commit failure/u,
  );
  await assert.rejects(lstat(output), /ENOENT/u);
  assert.equal((await lstat(stage)).isDirectory(), true);
});

test('PF10 Libauth publisher reports a durable committed output after post-commit failure', async (t) => {
  const root = await testRoot(t);
  const outputParent = path.join(root, 'postcommit-output-parent');
  const output = path.join(outputParent, 'published');
  await mkdir(outputParent, { mode: 0o700 });
  await chmod(outputParent, 0o700);
  const stage = await mkdtemp(path.join(outputParent, '.stage-'));
  t.after(() => rm(stage, { recursive: true, force: true }));
  await chmod(stage, 0o700);
  await writePrivateFile(
    path.join(stage, 'fixture.json'),
    Buffer.from('stage\n'),
    'unit fixture',
  );
  await assert.rejects(
    publishStage({
      stage,
      output,
      outputParent,
      files: ['fixture.json'],
      afterCommit: async () => {
        throw new Error('injected post-commit failure');
      },
    }),
    (error) =>
      error instanceof QualificationPublicationCommittedError
      && error.committed === true
      && /publication committed/u.test(error.message)
      && /injected post-commit failure/u.test(error.message),
  );
  assert.equal(await readFile(path.join(output, 'fixture.json'), 'utf8'), 'stage\n');
  assert.equal(
    JSON.parse(await readFile(
      path.join(output, PF10_LIBAUTH_PUBLICATION_FILE),
      'utf8',
    )).schema,
    PF10_LIBAUTH_PUBLICATION_SCHEMA,
  );
});
