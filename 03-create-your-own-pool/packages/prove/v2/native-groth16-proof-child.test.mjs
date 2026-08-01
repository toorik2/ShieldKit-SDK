import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { executeV2NativeGroth16ProofRequest, V2_NATIVE_GROTH16_PROOF_REQUEST_SCHEMA } from './native-groth16-proof-child.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
async function receipt(filename, bytes) {
  const stat = await lstat(filename, { bigint: true });
  return Object.freeze({
    path: filename,
    sha256: hash(bytes),
    identity: Object.freeze({
      dev: stat.dev.toString(), ino: stat.ino.toString(), mode: stat.mode.toString(),
      uid: stat.uid.toString(), gid: stat.gid.toString(), size: stat.size.toString(),
      nlink: stat.nlink.toString(), mtimeNs: stat.mtimeNs.toString(),
      ctimeNs: stat.ctimeNs.toString(), birthtimeNs: stat.birthtimeNs.toString(),
    }),
  });
}

test('native child normalizes strict-JSON native proof objects before JCS result serialization', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-native-child-'));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = (name) => path.join(root, name);
  const artifacts = {};
  for (const name of ['r1cs', 'wasm', 'provingKey']) {
    const bytes = Buffer.from(name);
    const filename = file(name);
    await writeFile(filename, bytes, { mode: 0o600 });
    artifacts[name] = await receipt(filename, bytes);
  }
  const vkBytes = Buffer.from('{}');
  const vk = file('verification-key.json');
  await writeFile(vk, vkBytes, { mode: 0o600 });
  artifacts.verificationKey = await receipt(vk, vkBytes);
  const inputBytes = Buffer.from('{"alpha":"1"}');
  const input = file('input.json');
  await writeFile(input, inputBytes, { mode: 0o600 });
  const prover = file('prover');
  await writeFile(prover, '#!/bin/sh\nprintf \'{"protocol":"groth16"}\' > "$3"\nprintf \'["1","2"]\' > "$4"\nsleep 0.1\n', { mode: 0o700 });
  await chmod(prover, 0o700);
  const outputPath = file('result.json');
  const proofRequest = {
    schema: V2_NATIVE_GROTH16_PROOF_REQUEST_SCHEMA,
    artifacts: { schema: 'shieldkit-v2-beta-receipt-bound-proof-artifacts-v1', installationReceiptSha256: 'a'.repeat(64), artifacts },
    nativeProver: await receipt(prover, await readFile(prover)),
    expectedPublicInputs: ['1', '2'],
    input: { path: input, sha256: hash(inputBytes) },
    witnessPath: file('witness.wtns'), nativeProofPath: file('proof.json'), nativePublicPath: file('public.json'), outputPath, failurePath: file('failure.json'),
  };
  const result = await executeV2NativeGroth16ProofRequest(proofRequest, {
    nproc: 1,
    snarkjsApi: { wtns: { calculate: async (_input, _wasm, witness) => writeFile(witness, 'witness', { mode: 0o600 }) }, groth16: { verify: async (_vk, publicInputs, proof) => publicInputs[0] === '1' && proof.protocol === 'groth16' } },
  });
  assert.equal(Object.getPrototypeOf(result.proof), Object.prototype);
  assert.equal(JSON.parse(await readFile(outputPath, 'utf8')).proof.protocol, 'groth16');
  await writeFile(prover, '#!/bin/sh\nprintf \'{"protocol":"groth16"}\' > "$3"\nprintf \'["1","2"]\' > "$4"\n', { mode: 0o700 });
  proofRequest.nativeProver = await receipt(prover, await readFile(prover));
  proofRequest.witnessPath = file('immediate-witness.wtns');
  proofRequest.nativeProofPath = file('immediate-proof.json');
  proofRequest.nativePublicPath = file('immediate-public.json');
  proofRequest.outputPath = file('immediate-result.json');
  proofRequest.failurePath = file('immediate-failure.json');
  let timeout;
  const settled = await Promise.race([
    executeV2NativeGroth16ProofRequest(proofRequest, {
      nproc: 1,
      snarkjsApi: { wtns: { calculate: async (_input, _wasm, witness) => writeFile(witness, 'witness', { mode: 0o600 }) }, groth16: { verify: async () => true } },
    }).then(() => 'settled', error => {
      assert.equal(error.code, 'NATIVE_PROVER_METRICS_UNAVAILABLE');
      return 'settled';
    }),
    new Promise(resolve => { timeout = setTimeout(() => resolve('timed-out'), 2_000); }),
  ]);
  clearTimeout(timeout);
  assert.equal(settled, 'settled');
  await chmod(prover, 0o600);
  await assert.rejects(
    executeV2NativeGroth16ProofRequest(proofRequest, { nproc: 1 }),
    { code: 'NATIVE_PROVER_ARTIFACT_UNAVAILABLE' },
  );
  await chmod(prover, 0o700);
  await writeFile(artifacts.provingKey.path, 'mutated', { mode: 0o600 });
  await assert.rejects(
    executeV2NativeGroth16ProofRequest(proofRequest, { nproc: 1 }),
    { code: 'NATIVE_PROVER_ARTIFACT_CHANGED' },
  );
});
