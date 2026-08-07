import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { executeV2NativeGroth16ProofRequest, V2_NATIVE_GROTH16_PROOF_REQUEST_SCHEMA } from './native-groth16-proof-child.mjs';
import { parseDirectV2MillerProof } from '../../unlock-builder/v2/identity-aware-miller.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const FIXTURE_PROOF = JSON.parse(await readFile(new URL('../test-fixtures/two-public/proof.json', import.meta.url), 'utf8'));
const FIXTURE_VK_BYTES = await readFile(new URL('../test-fixtures/two-public/verification_key.json', import.meta.url));
const RAPIDSNARK_PROOF = Object.freeze({
  pi_a: FIXTURE_PROOF.pi_a,
  pi_b: FIXTURE_PROOF.pi_b,
  pi_c: FIXTURE_PROOF.pi_c,
  protocol: 'groth16',
});
const proverScript = (proof, sleep = true) => `#!/bin/sh\nprintf '%s' '${JSON.stringify(proof)}' > "$3"\nprintf '%s' '["1","2"]' > "$4"\n${sleep ? 'sleep 0.1\n' : ''}`;
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
  const vkBytes = FIXTURE_VK_BYTES;
  const vk = file('verification-key.json');
  await writeFile(vk, vkBytes, { mode: 0o600 });
  artifacts.verificationKey = await receipt(vk, vkBytes);
  const inputBytes = Buffer.from('{"alpha":"1"}');
  const input = file('input.json');
  await writeFile(input, inputBytes, { mode: 0o600 });
  const prover = file('prover');
  await writeFile(prover, proverScript(RAPIDSNARK_PROOF), { mode: 0o700 });
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
  let verifierProof;
  const result = await executeV2NativeGroth16ProofRequest(proofRequest, {
    nproc: 1,
    snarkjsApi: { wtns: { calculate: async (_input, _wasm, witness) => writeFile(witness, 'witness', { mode: 0o600 }) }, groth16: { verify: async (vkValue, publicInputs, proof) => { verifierProof = proof; return vkValue.protocol === 'groth16' && vkValue.curve === 'bn128' && publicInputs[0] === '1' && proof.protocol === 'groth16' && proof.curve === 'bn128'; } } },
  });
  assert.equal(Object.getPrototypeOf(result.proof), Object.prototype);
  assert.deepEqual(Object.keys(result.proof).sort(), ['curve', 'pi_a', 'pi_b', 'pi_c', 'protocol']);
  assert.deepEqual(verifierProof, result.proof);
  assert.deepEqual(JSON.parse(await readFile(outputPath, 'utf8')).proof, result.proof);
  assert.doesNotThrow(() => parseDirectV2MillerProof(result.proof));

  const malformed = [
    { ...RAPIDSNARK_PROOF, protocol: 'plonk' },
    { ...RAPIDSNARK_PROOF, curve: 'bls12381' },
    { pi_a: RAPIDSNARK_PROOF.pi_a, pi_b: RAPIDSNARK_PROOF.pi_b, pi_c: RAPIDSNARK_PROOF.pi_c, curve: 'bn128' },
    { ...RAPIDSNARK_PROOF, unknown: true },
    { ...RAPIDSNARK_PROOF, pi_a: [RAPIDSNARK_PROOF.pi_a[0], RAPIDSNARK_PROOF.pi_a[1], '2'] },
  ];
  for (const [index, invalidProof] of malformed.entries()) {
    await writeFile(prover, proverScript(invalidProof), { mode: 0o700 });
    const invalid = {
      ...proofRequest,
      nativeProver: await receipt(prover, await readFile(prover)),
      witnessPath: file(`invalid-${index}.wtns`),
      nativeProofPath: file(`invalid-${index}-proof.json`),
      nativePublicPath: file(`invalid-${index}-public.json`),
      outputPath: file(`invalid-${index}-result.json`),
      failurePath: file(`invalid-${index}-failure.json`),
    };
    let verified = false;
    await assert.rejects(
      executeV2NativeGroth16ProofRequest(invalid, {
        nproc: 1,
        snarkjsApi: { wtns: { calculate: async (_input, _wasm, witness) => writeFile(witness, 'witness', { mode: 0o600 }) }, groth16: { verify: async () => { verified = true; return true; } } },
      }),
      { code: 'NATIVE_PROVER_PROOF_SHAPE_INVALID' },
    );
    assert.equal(verified, false);
  }

  await writeFile(prover, proverScript(RAPIDSNARK_PROOF, false), { mode: 0o700 });
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
