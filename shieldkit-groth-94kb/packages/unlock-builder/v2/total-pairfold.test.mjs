import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  assertLocalVerifierArtifactCoherence,
} from '../../../scripts/run-domain-tests.mjs';

import {
  binToHex,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
  hexToBin,
} from '@bitauth/libauth';
import {
  compileString,
  utils as cashcUtils,
} from '../vendor/verifier/vendor/cashc-resched/packages/cashc/dist/index.js';

import {
  computeDirectV2ExactMsm,
} from './exact-msm.mjs';
import {
  computeDirectV2IdentityAwareMiller,
  createDirectV2IdentityReferenceProof,
  encodeDirectV2MillerGenesisWitness,
  encodeDirectV2MillerProjectionSignal,
  parseDirectV2MillerVerificationKey,
} from './identity-aware-miller.mjs';
import {
  buildDirectV2PairFoldLoader,
  buildDirectV2PairFoldTerminalUnlock,
  buildDirectV2PairFoldUnlock,
  renderDirectV2TotalPairFoldExecutor,
  renderDirectV2TotalPairFoldTerminal,
  splitDirectV2PairFoldBody,
} from './total-pairfold-cashscript.mjs';
import {
  buildDirectV2TotalPairFoldWitness,
  buildDirectV2TotalPairFoldWitnessPair,
} from './total-pairfold.mjs';
import {
  createLoosenedVm,
  createRealVm,
  evaluatePair,
  realOpCostBudget,
} from '../vendor/verifier/harness/src/harness/vm.ts';

const repoRoot = path.resolve(import.meta.dirname, '../../../..');
const buildRoot = path.join(repoRoot, '.codex-build');
const verificationKeyPath = path.join(
  buildRoot,
  'v2-dev-groth16',
  'verification_key.json',
);
const depositRoot = path.join(
  buildRoot,
  'v2-dev-proof-qualification',
  'deposit',
);
const verifierRoot = path.resolve(
  import.meta.dirname,
  '../vendor/verifier',
);
const optimizerRoot = path.join(
  verifierRoot,
  'tools/singleton-artifact',
);
const lazyAffineLibrary = readFileSync(path.join(
  verifierRoot,
  'build/singleton/bn254/lib/lazy/Bn254LazyAff.cash',
), 'utf8');

const compile = (source) => cashcUtils.asmToBytecode(
  compileString(source, {
    files: { 'Bn254LazyAff.cash': lazyAffineLibrary },
  }).bytecode,
);

const optimize = (bytecode, label) => {
  const directory = mkdtempSync(path.join(tmpdir(), `shieldkit-${label}-`));
  const input = path.join(directory, 'input.hex');
  const optimized = path.join(directory, 'optimized.hex');
  const canonical = path.join(directory, 'canonical.hex');
  writeFileSync(input, binToHex(bytecode));
  let result = spawnSync(
    'node',
    [path.join(optimizerRoot, 'optimize.mjs'), input, optimized],
    { encoding: 'utf8' },
  );
  assert.equal(
    result.status,
    0,
    `${label} optimizer failed: ${result.stderr || result.stdout}`,
  );
  result = spawnSync(
    'node',
    [
      path.join(optimizerRoot, 'minpush_canon.mjs'),
      optimized,
      canonical,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(
    result.status,
    0,
    `${label} canonicalizer failed: ${result.stderr || result.stdout}`,
  );
  return hexToBin(readFileSync(canonical, 'utf8').trim());
};

const encodedLength = (length) =>
  encodeDataPush(new Uint8Array(length)).length;

const pushHeaderLength = (length) => encodedLength(length) - length;

const stateCategory = Uint8Array.from(
  Buffer.from(
    '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f',
    'hex',
  ),
);
const stateCategoryProtocolHex = binToHex(
  Uint8Array.from(stateCategory).reverse(),
);
const stateCommitment = new Uint8Array(128);
stateCommitment.set(Buffer.from('SKS2'));
const parent = new Uint8Array(32).fill(0x5a);
const opTrueRedeem = Uint8Array.from([0x51]);
const opTrueLock = encodeLockingBytecodeP2sh32(hash256(opTrueRedeem));
const opTrueUnlock = encodeDataPush(opTrueRedeem);
const bqLengths = Object.freeze(Array(5).fill(1_216));

const bqLayout = (template) => template.roles.map((role, inputIndex) => ({
  inputIndex,
  offset:
    encodedLength(role.state.length)
    + encodedLength(role.records.length)
    + encodedLength(role.table.length)
    + pushHeaderLength(bqLengths[inputIndex]),
  length: bqLengths[inputIndex],
}));

const buildPrograms = (verificationKey, template) => {
  const shards = bqLayout(template);
  const terminalSource = renderDirectV2TotalPairFoldTerminal({
    verificationKey,
    template,
    stateCategoryHex: stateCategoryProtocolHex,
    bqShards: shards,
    libraryImportPath: 'Bn254LazyAff.cash',
  });
  const terminalRaw = compile(terminalSource);
  const terminalRedeem = optimize(terminalRaw, 'total-terminal');
  const terminalLock = encodeLockingBytecodeP2sh32(
    hash256(terminalRedeem),
  );

  const executorSource = renderDirectV2TotalPairFoldExecutor({
    verificationKey,
    template,
    terminalLockingBytecodeHex: binToHex(terminalLock),
    stateCategoryHex: stateCategoryProtocolHex,
    bqShardBytes: bqLengths,
    libraryImportPath: 'Bn254LazyAff.cash',
  });
  const executorRaw = compile(executorSource);
  // The raw body exceeds BCH's 10,000-byte stack-item ceiling when the loader
  // reconstructs it. The verified deterministic optimizer is therefore
  // mandatory even though the resulting arithmetic path remains expensive.
  const body = optimize(executorRaw, 'total-executor');
  const fragmentOffsets = template.roles.map((role, index) =>
    encodedLength(role.state.length)
    + encodedLength(role.records.length)
    + encodedLength(role.table.length)
    + encodedLength(bqLengths[index])
    + 3);
  const makeLoader = (lengths) => buildDirectV2PairFoldLoader({
    body,
    fragmentOffsets,
    fragmentLengths: lengths,
  });
  const fragments = splitDirectV2PairFoldBody(body);
  const fragmentLayout = fragments.map((fragment) => fragment.length);
  const loader = makeLoader(fragmentLayout);
  return Object.freeze({
    body,
    executorRaw,
    executorSource,
    fragments,
    loader,
    terminalLock,
    terminalRaw,
    terminalRedeem,
    terminalSource,
  });
};

const splitBq = (bigQ) => {
  let offset = 0;
  return bqLengths.map((length) => {
    const shard = Uint8Array.from(bigQ.slice(offset, offset + length));
    offset += length;
    return shard;
  });
};

const actionDigest = (inputs) => Buffer.concat(
  inputs.map((value) => Buffer.from(
    BigInt(value).toString(16).padStart(32, '0'),
    'hex',
  )),
);

const buildInputs = ({
  trace,
  template,
  programs,
  digest,
}) => {
  const bq = splitBq(template.terminal.bigQ);
  const executorUnlocks = template.roles.map((role, index) =>
    buildDirectV2PairFoldUnlock({
      state: role.state,
      records: role.records,
      table: role.table,
      bqShard: bq[index],
      bodyFragment: programs.fragments[index],
      loader: programs.loader.loader,
    }));
  const terminalFixedBytes =
    encodedLength(template.terminal.state.length)
    + encodedLength(template.terminal.records.length)
    + encodedLength(template.terminal.table.length)
    + encodedLength(programs.terminalRedeem.length);
  let terminalPadBytes = Math.max(1, 10_000 - terminalFixedBytes - 3);
  while (
    terminalFixedBytes + encodedLength(terminalPadBytes) > 10_000
  ) {
    terminalPadBytes -= 1;
  }
  const terminalUnlock = buildDirectV2PairFoldTerminalUnlock({
    state: template.terminal.state,
    records: template.terminal.records,
    table: template.terminal.table,
    densityPad: new Uint8Array(terminalPadBytes),
    redeem: programs.terminalRedeem,
  });
  const genesis = encodeDirectV2MillerGenesisWitness(trace);
  const inputs = Array.from({ length: 14 }, (_, index) => ({
    lockingBytecode: opTrueLock,
    unlockingBytecode: opTrueUnlock,
    outpointTransactionHash: parent,
    outpointIndex: index + 1,
  }));
  for (let index = 0; index < 5; index += 1) {
    inputs[index] = {
      ...inputs[index],
      lockingBytecode: programs.loader.lock,
      unlockingBytecode: executorUnlocks[index],
    };
  }
  inputs[8].unlockingBytecode = Uint8Array.from(Buffer.concat([
    encodeDataPush(encodeDirectV2MillerProjectionSignal(trace, digest)),
    encodeDataPush(opTrueRedeem),
  ]));
  inputs[9].unlockingBytecode = Uint8Array.from(Buffer.concat([
    encodeDataPush(genesis.slope),
    encodeDataPush(genesis.endpoint),
    encodeDataPush(genesis.residue),
    encodeDataPush(Uint8Array.from([0])),
    encodeDataPush(opTrueRedeem),
  ]));
  inputs[10] = {
    ...inputs[10],
    lockingBytecode: programs.terminalLock,
    unlockingBytecode: terminalUnlock,
  };
  inputs[12] = {
    ...inputs[12],
    outpointIndex: 0,
    token: {
      amount: 0n,
      category: stateCategory,
      capability: 'mutable',
      commitment: stateCommitment,
    },
  };
  return Object.freeze({
    executorUnlocks,
    inputs,
    terminalUnlock,
  });
};

const evaluateRole = (inputs, index) => evaluatePair(
  createRealVm(),
  inputs[index].lockingBytecode,
  inputs[index].unlockingBytecode,
  undefined,
  { index, inputs },
);

test(
  'total PairFold is semantically complete but five-executor PF11 is killed by the BCH-2026 operation ceiling',
  { timeout: 600_000 },
  async () => {
    await assertLocalVerifierArtifactCoherence();
    const verificationKeyJson = JSON.parse(readFileSync(
      verificationKeyPath,
      'utf8',
    ));
    const verificationKey = parseDirectV2MillerVerificationKey(
      verificationKeyJson,
    );
    const proof = JSON.parse(readFileSync(
      path.join(depositRoot, 'proof.json'),
      'utf8',
    ));
    const publicInputs = JSON.parse(readFileSync(
      path.join(depositRoot, 'public.json'),
      'utf8',
    )).map(BigInt);
    const msm = computeDirectV2ExactMsm(
      verificationKeyJson,
      publicInputs[0],
      publicInputs[1],
    );
    assert.equal(msm.output.infinity, false);
    const finiteTrace = computeDirectV2IdentityAwareMiller({
      verificationKey,
      proof,
      q: msm.output,
    });
    const identityTrace = computeDirectV2IdentityAwareMiller({
      verificationKey,
      proof: createDirectV2IdentityReferenceProof(verificationKey),
      q: null,
    });
    const legacyFiniteTemplate = buildDirectV2TotalPairFoldWitness(finiteTrace);
    const finitePrecomputedTemplate = buildDirectV2TotalPairFoldWitness(
      finiteTrace,
      { precomputedFixedLines: true },
    );
    const pairedFiniteTemplates = buildDirectV2TotalPairFoldWitnessPair(
      finiteTrace,
    );
    assert.deepEqual(
      pairedFiniteTemplates.compact,
      legacyFiniteTemplate,
      'paired compact witness differs from the legacy compact witness',
    );
    assert.deepEqual(
      pairedFiniteTemplates.precomputed,
      finitePrecomputedTemplate,
      'paired precomputed witness differs from the legacy precomputed witness',
    );
    // The remainder of this semantic/VM test therefore executes the paired
    // compact result after proving it exactly matches the legacy bytes.
    const finiteTemplate = pairedFiniteTemplates.compact;
    const identityTemplate = buildDirectV2TotalPairFoldWitness(identityTrace);
    assert.equal(finiteTemplate.terminal.bigQ.length, 6_080);
    assert.equal(identityTemplate.terminal.bigQ.length, 6_080);
    assert.deepEqual(
      identityTemplate.roles.map((role) => role.tableHash256),
      finiteTemplate.roles.map((role) => role.tableHash256),
    );
    assert.equal(
      identityTemplate.terminal.tableHash256,
      finiteTemplate.terminal.tableHash256,
    );

    const programs = buildPrograms(verificationKey, finiteTemplate);
    const cases = [
      {
        branch: 'finite',
        trace: finiteTrace,
        template: finiteTemplate,
        digest: actionDigest(publicInputs),
      },
      {
        branch: 'identity',
        trace: identityTrace,
        template: identityTemplate,
        digest: actionDigest([7n, 7n]),
      },
    ];
    const measurements = [];
    for (const branch of cases) {
      const spend = buildInputs({ ...branch, programs });
      const rows = [10, ...Array(5).keys()].map((index) => {
        const outcome = evaluateRole(spend.inputs, index);
        const loosened = outcome.accepted
          ? null
          : evaluatePair(
            createLoosenedVm(),
            spend.inputs[index].lockingBytecode,
            spend.inputs[index].unlockingBytecode,
            undefined,
            { index, inputs: spend.inputs },
          );
        const unlockBytes = spend.inputs[index].unlockingBytecode.length;
        assert.equal(unlockBytes <= 10_000, true);
        if (index === 10) {
          assert.equal(
            outcome.accepted,
            true,
            `${branch.branch} terminal rejected: ${outcome.error}; `
            + `loosened=${JSON.stringify(loosened)}`,
          );
          assert.equal(
            outcome.operationCost <= realOpCostBudget(unlockBytes),
            true,
          );
        } else {
          assert.equal(
            loosened?.accepted,
            true,
            `${branch.branch} role ${index} is semantically invalid: `
            + JSON.stringify(loosened),
          );
          assert.equal(
            outcome.accepted,
            false,
            `${branch.branch} role ${index} unexpectedly passed the hard gate`,
          );
          assert.equal(
            loosened.operationCost > realOpCostBudget(10_000),
            true,
            `${branch.branch} role ${index} could be rescued by legal density padding`,
          );
        }
        const measured = outcome.accepted ? outcome : loosened;
        return {
          role: index,
          unlockBytes,
          hardAccepted: outcome.accepted,
          hardError: outcome.error,
          semanticAccepted: measured?.accepted,
          operationCost: measured?.operationCost,
          operationBudget: realOpCostBudget(unlockBytes),
          maximumLegalOperationBudget: realOpCostBudget(10_000),
          instructionCount: measured?.instructionCount,
          arithmeticCost: measured?.arithmeticCost,
          stackPushedBytes: measured?.stackPushedBytes,
        };
      });
      measurements.push({
        branch: branch.branch,
        transcript: branch.trace.transcriptVersion,
        rows,
      });
    }
    console.log(JSON.stringify({
      directV2TotalPairFold: {
        optimizer: 'verified deterministic CSE plus fold fixpoint',
        rawExecutorBytes: programs.executorRaw.length,
        executorBodyBytes: programs.body.length,
        loaderBytes: programs.loader.loader.length,
        rawTerminalBytes: programs.terminalRaw.length,
        terminalRedeemBytes: programs.terminalRedeem.length,
        measurements,
      },
    }));
  },
);

test('paired PairFold witness builder rejects an incomplete trace', () => {
  assert.throws(
    () => buildDirectV2TotalPairFoldWitnessPair({}),
    /complete 65-step direct-V2 trace/u,
  );
});

test(
  'total terminal rejects fixed-table, quotient, endpoint, and residue mutations',
  { timeout: 600_000 },
  async () => {
    await assertLocalVerifierArtifactCoherence();
    const verificationKeyJson = JSON.parse(readFileSync(
      verificationKeyPath,
      'utf8',
    ));
    const verificationKey = parseDirectV2MillerVerificationKey(
      verificationKeyJson,
    );
    const proof = JSON.parse(readFileSync(
      path.join(depositRoot, 'proof.json'),
      'utf8',
    ));
    const publicInputs = JSON.parse(readFileSync(
      path.join(depositRoot, 'public.json'),
      'utf8',
    )).map(BigInt);
    const trace = computeDirectV2IdentityAwareMiller({
      verificationKey,
      proof,
      q: computeDirectV2ExactMsm(
        verificationKeyJson,
        publicInputs[0],
        publicInputs[1],
      ).output,
    });
    const template = buildDirectV2TotalPairFoldWitness(trace);
    const programs = buildPrograms(verificationKey, template);
    const spend = buildInputs({
      trace,
      template,
      programs,
      digest: actionDigest(publicInputs),
    });
    const mutateReject = (inputIndex, offset, label) => {
      const inputs = structuredClone(spend.inputs);
      inputs[inputIndex].unlockingBytecode[offset] ^= 1;
      const outcome = evaluateRole(inputs, 10);
      assert.equal(outcome.accepted, false, `${label} unexpectedly accepted`);
    };
    // Executor layout: state push, records push, fixed table push, BQ push.
    const role0 = template.roles[0];
    const recordsOffset = encodedLength(role0.state.length)
      + pushHeaderLength(role0.records.length);
    const tableOffset = encodedLength(role0.state.length)
      + encodedLength(role0.records.length)
      + pushHeaderLength(role0.table.length);
    const bqOffset = bqLayout(template)[0].offset;
    mutateReject(0, bqOffset, 'quotient coefficient');
    // The terminal only consumes executor tables indirectly through their
    // execution, so target its own authenticated table and endpoint directly.
    const terminalTableOffset = encodedLength(template.terminal.state.length)
      + encodedLength(template.terminal.records.length)
      + pushHeaderLength(template.terminal.table.length);
    mutateReject(10, terminalTableOffset, 'terminal fixed table');
    const endpointOffset = encodedLength(template.terminal.state.length)
      + pushHeaderLength(template.terminal.records.length)
      + 64 + 128;
    mutateReject(10, endpointOffset, 'terminal endpoint');
    mutateReject(9, 455, 'residue witness');
    assert.equal(recordsOffset > 0 && tableOffset > recordsOffset, true);
  },
);
