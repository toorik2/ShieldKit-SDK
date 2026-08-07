import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
} from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(import.meta.dirname, '../../../..');
const circuitRoot = path.join(
  repositoryRoot,
  'shieldkit-groth-94kb/circuits/v2-direct/tests',
);
const vectorRoot = path.join(import.meta.dirname, 'vectors');
const temporaryRoot = path.join(repositoryRoot, '.codex-build/test-tmp');
const circomCli = fileURLToPath(import.meta.resolve('circom2/cli.js'));

async function compileCircuit(root, name) {
  const source = path.join(circuitRoot, `${name}.circom`);
  const output = path.join(root, name);
  await mkdir(output, { mode: 0o700 });
  await execFileAsync(process.execPath, [
    circomCli,
    source,
    '--wasm',
    '--O1',
    '--sanity_check',
    '2',
    '--output',
    output,
  ], {
    cwd: repositoryRoot,
    env: process.env,
    maxBuffer: 8 * 1024 * 1024,
  });
  const generated = path.join(output, `${name}_js`);
  const calculatorCommonJs = path.join(root, `${name}-witness-calculator.cjs`);
  await copyFile(
    path.join(generated, 'witness_calculator.js'),
    calculatorCommonJs,
  );
  const require = createRequire(import.meta.url);
  const buildCalculator = require(calculatorCommonJs);
  return buildCalculator(await readFile(path.join(generated, `${name}.wasm`)));
}

async function expectWitnessRejection(calculator, input, label) {
  await assert.rejects(
    calculator.calculateWitness(input, true),
    undefined,
    `${label} unexpectedly produced a circuit witness`,
  );
}

test('checked-in Q01 state and packet vectors agree with the compiled Circom source', {
  timeout: 120_000,
}, async (t) => {
  await mkdir(temporaryRoot, { recursive: true, mode: 0o700 });
  await chmod(temporaryRoot, 0o700);
  const root = await mkdtemp(path.join(
    temporaryRoot,
    'v2-circuit-codec-vectors-',
  ));
  await chmod(root, 0o700);
  t.after(async () => {
    await rm(root, { recursive: true, force: true, maxRetries: 1 });
  });

  const [stateCalculator, shaCalculator] = await Promise.all([
    compileCircuit(root, 'state-main'),
    compileCircuit(root, 'sha-layout'),
  ]);

  const stateLines = (
    await readFile(
      path.join(vectorRoot, 'q01-state-boundary-vectors.jsonl'),
      'utf8',
    )
  ).trim().split('\n').map((line) => JSON.parse(line));
  const stateHeader = stateLines.shift();
  assert.deepEqual(
    {
      schema: stateHeader.schema,
      stateBytes: stateHeader.stateBytes,
      vectorCount: stateHeader.vectorCount,
    },
    {
      schema: 'shieldkit/v2-direct-q01-state-boundary-vectors/v1',
      stateBytes: 128,
      vectorCount: stateLines.length,
    },
  );
  for (const vector of stateLines) {
    const input = { bytes: [...Buffer.from(vector.stateHex, 'hex')] };
    if (vector.expect === 'accept') {
      const witness = await stateCalculator.calculateWitness(input, true);
      assert.equal(witness[0], 1n, `${vector.id} witness is not satisfied`);
    } else {
      assert.equal(vector.expect, 'reject', `${vector.id} has unknown verdict`);
      await expectWitnessRejection(stateCalculator, input, vector.id);
    }
  }

  const packetVector = JSON.parse(await readFile(
    path.join(vectorRoot, 'q01-state-packet-public-input.json'),
    'utf8',
  ));
  assert.equal(
    packetVector.schema,
    'shieldkit/v2-direct-q01-codec-vectors/v1',
  );
  const packet = Buffer.from(packetVector.packetHex, 'hex');
  assert.equal(packet.length, 552);
  const shaInput = {
    packet: [...packet],
    publicInput0: packetVector.publicInput0BeU128,
    publicInput1: packetVector.publicInput1BeU128,
  };
  const shaWitness = await shaCalculator.calculateWitness(shaInput, true);
  assert.equal(shaWitness[0], 1n);
  assert.equal(shaWitness[1], BigInt(packetVector.publicInput0BeU128));
  assert.equal(shaWitness[2], BigInt(packetVector.publicInput1BeU128));

  const mutatedPacket = [...packet];
  mutatedPacket[551] ^= 1;
  await expectWitnessRejection(
    shaCalculator,
    { ...shaInput, packet: mutatedPacket },
    'packet byte mutation with unrebound public inputs',
  );
  await expectWitnessRejection(
    shaCalculator,
    {
      ...shaInput,
      publicInput1: (
        BigInt(packetVector.publicInput1BeU128) ^ 1n
      ).toString(),
    },
    'public-input limb mutation',
  );
});
