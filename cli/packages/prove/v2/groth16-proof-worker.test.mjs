import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import {
  V2_GROTH16_PROOF_RESULT_SCHEMA,
} from './groth16-proof-child.mjs';
import {
  V2Groth16ProofWorkerError,
  proveV2DirectGroth16,
} from './groth16-proof-worker.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-proof-worker-'));
  await chmod(root, 0o700);
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true, force: true });
  });
  const artifacts = {};
  for (const name of ['r1cs', 'wasm', 'provingKey', 'verificationKey']) {
    const bytes = Buffer.from(`artifact:${name}`);
    const filename = path.join(root, `${name}.bin`);
    await writeFile(filename, bytes, { mode: 0o600 });
    artifacts[name] = { path: filename, sha256: hash(bytes) };
  }
  return { root, artifacts };
}

function result(request, overrides = {}) {
  return {
    schema: V2_GROTH16_PROOF_RESULT_SCHEMA,
    claims: {
      proofVerified: true,
      singleThread: true,
      witnessValid: true,
    },
    sourceHashes: Object.fromEntries(
      Object.entries(request.artifacts).map(([name, artifact]) => [
        name,
        artifact.sha256,
      ]),
    ),
    inputSha256: request.input.sha256,
    proof: {
      protocol: 'groth16',
      curve: 'bn128',
      pi_a: ['1', '2', '1'],
      pi_b: [['1', '2'], ['3', '4'], ['1', '0']],
      pi_c: ['5', '6', '1'],
    },
    publicInputs: [...request.expectedPublicInputs],
    timingsMs: {
      proofGeneration: 10,
      proofVerification: 1,
      total: 12,
      witnessCalculation: 0.5,
      witnessCheck: 0.5,
    },
    ...overrides,
  };
}

async function fakeWorker(input, mutate = undefined) {
  const requestPath = input.arguments[1];
  const request = JSON.parse(await readFile(requestPath, 'utf8'));
  const output = mutate?.(result(request), request) ?? result(request);
  await writeFile(request.outputPath, canonicalizeJcs(output), {
    flag: 'wx',
    mode: 0o600,
  });
  return Object.freeze({
    backend: 'test-contained-worker',
    containment: Object.freeze({
      memoryMax: '4294967296',
      memorySwapMax: '0',
    }),
    termination: Object.freeze({
      exitCode: 0,
      signal: null,
      memoryPeak: '123456',
      memoryEvents: Object.freeze({ oom: 0, oomKill: 0 }),
    }),
  });
}

test('returns one exact contained proof and removes every private transient', async (t) => {
  const { root, artifacts } = await fixture(t);
  const proof = await proveV2DirectGroth16({
    artifacts,
    circuitInput: { publicInput0: '1', publicInput1: '2' },
    expectedPublicInputs: ['1', '2'],
    workspaceDirectory: root,
  }, {
    runContainedWorker: fakeWorker,
  });
  assert.equal(proof.claims.singleThread, true);
  assert.deepEqual(proof.publicInputs, ['1', '2']);
  assert.equal(proof.containment.termination.memoryPeak, '123456');
  assert.deepEqual(
    JSON.parse(proof.proofBytes.toString('utf8')).publicInputs,
    ['1', '2'],
  );
  assert.deepEqual(
    (await readdir(root)).sort(),
    [
      'provingKey.bin',
      'r1cs.bin',
      'verificationKey.bin',
      'wasm.bin',
    ],
  );
});

test('fails closed on result binding drift and still removes transients', async (t) => {
  const { root, artifacts } = await fixture(t);
  await assert.rejects(
    () => proveV2DirectGroth16({
      artifacts,
      circuitInput: { publicInput0: '1', publicInput1: '2' },
      expectedPublicInputs: ['1', '2'],
      workspaceDirectory: root,
    }, {
      runContainedWorker: (input) => fakeWorker(
        input,
        (value) => ({ ...value, publicInputs: ['2', '1'] }),
      ),
    }),
    (error) =>
      error instanceof V2Groth16ProofWorkerError
      && error.code === 'PROVER_RESULT_INVALID',
  );
  assert.equal(
    (await readdir(root)).some((name) =>
      name.startsWith('.shieldkit-v2-proof-')
    ),
    false,
  );
});

test('surfaces a structured child failure and never retries uncontained', async (t) => {
  const { root, artifacts } = await fixture(t);
  let calls = 0;
  await assert.rejects(
    () => proveV2DirectGroth16({
      artifacts,
      circuitInput: { publicInput0: '1', publicInput1: '2' },
      expectedPublicInputs: ['1', '2'],
      workspaceDirectory: root,
    }, {
      runContainedWorker: async (input) => {
        calls += 1;
        const request = JSON.parse(await readFile(input.arguments[1], 'utf8'));
        await writeFile(request.failurePath, canonicalizeJcs({
          schema: 'shieldkit-v2-direct-groth16-proof-failure-v1',
          code: 'PROVER_WITNESS_INVALID',
          message: 'witness rejected',
        }), { flag: 'wx', mode: 0o600 });
        throw Object.assign(new Error('worker exit'), {
          code: 'PROVER_WORKER_EXIT',
        });
      },
    }),
    (error) =>
      error instanceof V2Groth16ProofWorkerError
      && error.code === 'PROVER_WITNESS_INVALID'
      && error.message === 'witness rejected',
  );
  assert.equal(calls, 1);
  assert.equal(
    (await readdir(root)).some((name) =>
      name.startsWith('.shieldkit-v2-proof-')
    ),
    false,
  );
});

test('rejects a symlink artifact before launch and cleans up after hash drift', async (t) => {
  const symlinkFixture = await fixture(t);
  const symlinkTarget = path.join(symlinkFixture.root, 'symlink-target.bin');
  await writeFile(symlinkTarget, 'artifact:wasm', { mode: 0o600 });
  await rm(symlinkFixture.artifacts.wasm.path);
  await symlink(symlinkTarget, symlinkFixture.artifacts.wasm.path);
  let launches = 0;
  await assert.rejects(
    () => proveV2DirectGroth16({
      artifacts: symlinkFixture.artifacts,
      circuitInput: { publicInput0: '1', publicInput1: '2' },
      expectedPublicInputs: ['1', '2'],
      workspaceDirectory: symlinkFixture.root,
    }, {
      runContainedWorker: async () => { launches += 1; },
    }),
    (error) => error instanceof V2Groth16ProofWorkerError
      && error.code === 'PROVER_ARTIFACT_HASH_MISMATCH',
  );
  assert.equal(launches, 0);

  const driftFixture = await fixture(t);
  await assert.rejects(
    () => proveV2DirectGroth16({
      artifacts: driftFixture.artifacts,
      circuitInput: { publicInput0: '1', publicInput1: '2' },
      expectedPublicInputs: ['1', '2'],
      workspaceDirectory: driftFixture.root,
    }, {
      runContainedWorker: async (input) => {
        const contained = await fakeWorker(input);
        await writeFile(driftFixture.artifacts.provingKey.path, 'drifted', { mode: 0o600 });
        return contained;
      },
    }),
    (error) => error instanceof V2Groth16ProofWorkerError
      && error.code === 'PROVER_ARTIFACT_CHANGED',
  );
  assert.equal(
    (await readdir(driftFixture.root)).some((name) => name.startsWith('.shieldkit-v2-proof-')),
    false,
  );

  const replacementFixture = await fixture(t);
  await assert.rejects(
    () => proveV2DirectGroth16({
      artifacts: replacementFixture.artifacts,
      circuitInput: { publicInput0: '1', publicInput1: '2' },
      expectedPublicInputs: ['1', '2'],
      workspaceDirectory: replacementFixture.root,
    }, {
      runContainedWorker: async (input) => {
        const contained = await fakeWorker(input);
        await rm(replacementFixture.artifacts.provingKey.path);
        await writeFile(
          replacementFixture.artifacts.provingKey.path,
          'artifact:provingKey',
          { mode: 0o600 },
        );
        return contained;
      },
    }),
    (error) => error instanceof V2Groth16ProofWorkerError
      && error.code === 'PROVER_ARTIFACT_CHANGED',
  );
  assert.equal(
    (await readdir(replacementFixture.root)).some((name) => name.startsWith('.shieldkit-v2-proof-')),
    false,
  );
});

test('rejects malformed proof results and preserves worker exit classifications', async (t) => {
  const malformed = [
    (value) => ({ ...value, proof: null }),
    (value) => ({ ...value, publicInputs: ['1', '2', '3'] }),
    (value) => ({ ...value, claims: { proofVerified: true, singleThread: true } }),
    (value) => ({ ...value, sourceHashes: { ...value.sourceHashes, spoofed: 'x' } }),
    (value) => ({ ...value, timingsMs: { ...value.timingsMs, total: '12' } }),
  ];
  for (const mutate of malformed) {
    const { root, artifacts } = await fixture(t);
    await assert.rejects(
      () => proveV2DirectGroth16({
        artifacts,
        circuitInput: { publicInput0: '1', publicInput1: '2' },
        expectedPublicInputs: ['1', '2'],
        workspaceDirectory: root,
      }, { runContainedWorker: (input) => fakeWorker(input, mutate) }),
      (error) => error instanceof V2Groth16ProofWorkerError
        && error.code === 'PROVER_RESULT_INVALID',
    );
    assert.equal((await readdir(root)).some((name) => name.startsWith('.shieldkit-v2-proof-')), false);
  }
  for (const code of ['PROVER_WORKER_SIGNAL', 'PROVER_WORKER_EXIT']) {
    const { root, artifacts } = await fixture(t);
    await assert.rejects(
      () => proveV2DirectGroth16({
        artifacts,
        circuitInput: { publicInput0: '1', publicInput1: '2' },
        expectedPublicInputs: ['1', '2'],
        workspaceDirectory: root,
      }, {
        runContainedWorker: async () => {
          throw Object.assign(new Error('contained worker stopped'), { code });
        },
      }),
      (error) => error instanceof V2Groth16ProofWorkerError && error.code === code,
    );
    assert.equal((await readdir(root)).some((name) => name.startsWith('.shieldkit-v2-proof-')), false);
  }
});
