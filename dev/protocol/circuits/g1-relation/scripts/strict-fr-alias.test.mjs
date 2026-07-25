import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

import {
  DOMAIN_TAGS,
  FR_MODULUS,
  createShieldedTransitionReference,
} from '../../../packages/core/shielded-transition.mjs';

const run = promisify(execFile);
const packageDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceFile = path.join(packageDirectory, 'src', 'g1_relation.circom');
const circom = path.join(packageDirectory, 'node_modules', '.bin', 'circom2');
const snarkjs = path.join(packageDirectory, 'node_modules', '.bin', 'snarkjs');
const includeDirectory = path.join(packageDirectory, 'node_modules', 'circomlib', 'circuits');
const TWO_254 = 1n << 254n;
const LOW_128_MASK = (1n << 128n) - 1n;

function bits(value) {
  return Array.from({ length: 254 }, (_, index) => Number((value >> BigInt(index)) & 1n));
}

function harness(strict) {
  return `pragma circom 2.0.0;
include "bitify.circom";

template NullifierEncoding() {
    signal input nf;
    signal input encodedBits[254];
    signal input keyLow128;
    component recomposed = Bits2Num(254);
    component low = Bits2Num(128);
${strict ? '    component canonical = AliasCheck();' : ''}
    for (var i = 0; i < 254; i++) {
        encodedBits[i] * (encodedBits[i] - 1) === 0;
        recomposed.in[i] <== encodedBits[i];
${strict ? '        canonical.in[i] <== encodedBits[i];' : ''}
        if (i < 128) low.in[i] <== encodedBits[i];
    }
    nf === recomposed.out;
    keyLow128 === low.out;
}

component main { public [nf, keyLow128] } = NullifierEncoding();
`;
}

async function compile(directory, name, strict) {
  const source = path.join(directory, `${name}.circom`);
  const build = path.join(directory, `${name}-build`);
  await writeFile(source, harness(strict));
  await import('node:fs/promises').then(({ mkdir }) => mkdir(build));
  await run(circom, [source, '--r1cs', '--wasm', '--sym', '-l', includeDirectory, '-o', build]);
  return {
    r1cs: path.join(build, `${name}.r1cs`),
    wasm: path.join(build, `${name}_js`, `${name}.wasm`),
    generator: path.join(build, `${name}_js`, 'generate_witness.js'),
  };
}

async function witness(artifacts, directory, name, input) {
  const inputFile = path.join(directory, `${name}.json`);
  const witnessFile = path.join(directory, `${name}.wtns`);
  await writeFile(inputFile, `${JSON.stringify(input)}\n`);
  await run(process.execPath, [artifacts.generator, artifacts.wasm, inputFile, witnessFile]);
  await run(snarkjs, ['wtns', 'check', artifacts.r1cs, witnessFile]);
}

test('all production 254-bit Fr decompositions are strict', async () => {
  const source = await readFile(sourceFile, 'utf8');
  assert.doesNotMatch(source, /\bcomponent\s+\w+\s*=\s*Num2Bits\s*\(\s*254\s*\)/);
  assert.equal((source.match(/\bNum2Bits_strict\s*\(\s*\)/g) ?? []).length, 16);
});

test('R1CS rejects the same derived nullifier encoded at a second sparse-tree key', async () => {
  const reference = await createShieldedTransitionReference();
  const aliasWindow = TWO_254 - FR_MODULUS;
  let nullifier;
  for (let rho = 1n; rho <= 64n; rho++) {
    const candidate = reference.poseidon(
      DOMAIN_TAGS.NULLIFIER,
      1n, 2n, 3n, 4n,
      5n,
      rho,
    );
    if (candidate > 0n && candidate < aliasWindow) {
      nullifier = candidate;
      break;
    }
  }
  assert.notEqual(nullifier, undefined, 'deterministic search must find a protocol-derived nullifier in the alias window');

  const alias = nullifier + FR_MODULUS;
  assert(alias < TWO_254);
  const canonicalKey = nullifier & LOW_128_MASK;
  const aliasKey = alias & LOW_128_MASK;
  assert.notEqual(aliasKey, canonicalKey, 'the alternate encoding must select a second sparse-nullifier key');

  const directory = await mkdtemp(path.join(packageDirectory, '.tmp-fr-alias-'));
  try {
    // Circom's generated witness runner is CommonJS. Override the enclosing
    // package's ESM mode for this isolated build directory.
    await writeFile(path.join(directory, 'package.json'), '{"type":"commonjs"}\n');
    const [legacy, strict] = await Promise.all([
      compile(directory, 'legacy_alias', false),
      compile(directory, 'strict_alias', true),
    ]);
    const canonicalInput = {
      nf: nullifier.toString(),
      encodedBits: bits(nullifier),
      keyLow128: canonicalKey.toString(),
    };
    const aliasInput = {
      nf: nullifier.toString(),
      encodedBits: bits(alias),
      keyLow128: aliasKey.toString(),
    };

    // This demonstrates the exact R1CS-level failure mode: modulo-Fr
    // recomposition alone accepts both encodings and therefore both tree keys.
    await witness(legacy, directory, 'legacy-canonical', canonicalInput);
    await witness(legacy, directory, 'legacy-alias', aliasInput);

    await witness(strict, directory, 'strict-canonical', canonicalInput);
    await assert.rejects(
      witness(strict, directory, 'strict-alias', aliasInput),
      /Assert Failed|Error|Command failed/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
