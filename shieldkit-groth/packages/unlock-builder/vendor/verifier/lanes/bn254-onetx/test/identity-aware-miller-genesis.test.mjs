import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import {
  binToHex,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';
import {
  compileString,
  utils as cashcUtils,
} from '../../../vendor/cashc-resched/packages/cashc/dist/index.js';

import {
  BN254_BASE_FIELD,
  computeDirectV2ExactMsm,
} from '../../../../../v2/exact-msm.mjs';
import {
  computeDirectV2IdentityAwareMiller,
  createDirectV2IdentityReferenceProof,
  directV2MillerFixedStep0,
  directV2MillerPairingReference,
  directV2MillerStepFactorSpec,
  encodeDirectV2MillerGenesisHead,
  encodeDirectV2MillerGenesisWitness,
  encodeDirectV2MillerProjectionSignal,
  parseDirectV2MillerVerificationKey,
} from '../../../../../v2/identity-aware-miller.mjs';
import {
  renderDirectV2IdentityAwareMillerGenesis,
} from '../../../../../v2/identity-aware-miller-cashscript.mjs';
import {
  buildDirectV2BindingLock,
} from '../../../../../v2/structural-covenants.mjs';
import {
  bn254,
} from '../../../build/chunked/pairing/_millermath.mjs';
import {
  createRealVm,
  evaluatePair,
  realOpCostBudget,
} from '../../../harness/src/harness/vm.ts';

const verifierRoot = path.resolve(import.meta.dirname, '../../..');
const lazyAffineLibrary = readFileSync(
  path.join(verifierRoot, 'build/singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash'),
  'utf8',
);
const fixtureRoot = path.resolve(
  verifierRoot,
  '../../../prove/test-fixtures/two-public',
);
const verificationKeyJson = JSON.parse(readFileSync(
  path.join(fixtureRoot, 'verification_key.json'),
  'utf8',
));
const proofJson = JSON.parse(readFileSync(
  path.join(fixtureRoot, 'proof.json'),
  'utf8',
));
const verificationKey = parseDirectV2MillerVerificationKey(
  verificationKeyJson,
);

const opTrueRedeem = Uint8Array.from([0x51]);
const opTrueLock = encodeLockingBytecodeP2sh32(hash256(opTrueRedeem));
const opTrueUnlock = encodeDataPush(opTrueRedeem);
const differentLock = encodeLockingBytecodeP2sh32(
  hash256(Uint8Array.from([0x52])),
);
const stateCategory = Uint8Array.from(
  Buffer.from('00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f', 'hex'),
);
const stateCategoryProtocolHex = binToHex(
  Uint8Array.from(stateCategory).reverse(),
);
const stateCommitment = Uint8Array.from(Buffer.alloc(128));
stateCommitment.set(Buffer.from('SKS2', 'ascii'));
const parent = new Uint8Array(32).fill(0x5a);
const TARGET_UNLOCK_BYTES = 9_529;
const unsignedBe = (value, width) => Buffer.from(
  BigInt(value).toString(16).padStart(width * 2, '0'),
  'hex',
);
const digestForInputs = (input0, input1) => Buffer.concat([
  unsignedBe(input0, 16),
  unsignedBe(input1, 16),
]);
const finiteActionDigest = digestForInputs(3n, 5n);
const identityActionDigest = digestForInputs(7n, 7n);

// Input 11 is the real V2 structural binding lock. Input 10 is intentionally
// opaque in this component test: the legacy PairFold terminal cannot consume
// the identity transcript until all five frozen executors are made total.
const bindingLock = buildDirectV2BindingLock({
  networkId: 2,
  profileId: '11'.repeat(32),
  stateCategory: stateCategoryProtocolHex,
  denominationSats: 10_000_000n,
});
const terminalFixtureLock = opTrueLock;

const finiteMsm = computeDirectV2ExactMsm(verificationKeyJson, 3n, 5n);
const finiteTrace = computeDirectV2IdentityAwareMiller({
  verificationKey,
  proof: proofJson,
  q: finiteMsm.output,
});
const identityMsm = computeDirectV2ExactMsm(verificationKeyJson, 7n, 7n);
// Equation-level component reference only: these equal digest halves make the
// exact MSM output canonical Q=O, but no 552-byte packet SHA-256 preimage is
// asserted or substituted here.
const identityTrace = computeDirectV2IdentityAwareMiller({
  verificationKey,
  proof: createDirectV2IdentityReferenceProof(verificationKey),
  q: identityMsm.output,
});

const compileArtifact = (source) => compileString(source, {
  files: {
    'Bn254LazyAff.cash': lazyAffineLibrary,
  },
});

const buildUnlock = (trace, redeem, zeroPaddingBytes) => {
  const witness = encodeDirectV2MillerGenesisWitness(trace);
  return Buffer.concat([
    encodeDataPush(witness.slope),
    encodeDataPush(witness.endpoint),
    encodeDataPush(witness.residue),
    encodeDataPush(Buffer.alloc(zeroPaddingBytes)),
    encodeDataPush(redeem),
  ]);
};

const compileContract = (transform = (source) => source) => {
  let zeroPaddingBytes = 2_600;
  let artifact;
  let redeem;
  let source;
  let unlock;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    source = transform(renderDirectV2IdentityAwareMillerGenesis({
      verificationKey,
      successorLockingBytecodeHex: binToHex(terminalFixtureLock),
      bindingLockingBytecodeHex: binToHex(bindingLock),
      stateCategoryHex: stateCategoryProtocolHex,
      zeroPaddingBytes,
      libraryImportPath: 'Bn254LazyAff.cash',
    }));
    artifact = compileArtifact(source);
    redeem = cashcUtils.asmToBytecode(artifact.bytecode);
    unlock = buildUnlock(finiteTrace, redeem, zeroPaddingBytes);
    const adjustment = TARGET_UNLOCK_BYTES - unlock.length;
    if (adjustment === 0) break;
    zeroPaddingBytes += adjustment;
  }
  assert.equal(unlock.length, TARGET_UNLOCK_BYTES);
  return Object.freeze({
    artifact,
    lock: encodeLockingBytecodeP2sh32(hash256(redeem)),
    redeem,
    source,
    zeroPaddingBytes,
  });
};

const contract = compileContract();

const buildSpend = (
  trace,
  compiled = contract,
  digest = finiteActionDigest,
) => {
  const projectionSignal = encodeDirectV2MillerProjectionSignal(
    trace,
    digest,
  );
  const head = encodeDirectV2MillerGenesisHead(trace);
  const unlock = buildUnlock(
    trace,
    compiled.redeem,
    compiled.zeroPaddingBytes,
  );
  assert.equal(unlock.length, TARGET_UNLOCK_BYTES);
  const inputs = Array.from({ length: 14 }, (_, index) => ({
    lockingBytecode: opTrueLock,
    unlockingBytecode: opTrueUnlock,
    outpointTransactionHash: parent,
    outpointIndex: index + 1,
  }));
  inputs[0].unlockingBytecode = Uint8Array.from(Buffer.concat([
    encodeDataPush(head),
    encodeDataPush(opTrueRedeem),
  ]));
  inputs[8].unlockingBytecode = Uint8Array.from(Buffer.concat([
    encodeDataPush(projectionSignal),
    encodeDataPush(opTrueRedeem),
  ]));
  inputs[9] = {
    ...inputs[9],
    lockingBytecode: compiled.lock,
    unlockingBytecode: Uint8Array.from(unlock),
  };
  inputs[10].lockingBytecode = terminalFixtureLock;
  inputs[11].lockingBytecode = bindingLock;
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
    inputs,
    lock: compiled.lock,
    unlock: Uint8Array.from(unlock),
  });
};

const evaluate = (inputs) => evaluatePair(
  createRealVm(),
  inputs[9].lockingBytecode,
  inputs[9].unlockingBytecode,
  undefined,
  { index: 9, inputs },
);

const cloneInputs = (spend) => structuredClone(spend.inputs);
const expectReject = (inputs, label) => {
  const outcome = evaluate(inputs);
  assert.equal(
    outcome.accepted,
    false,
    `${label} unexpectedly accepted`,
  );
};

const littleEndian = (value, width = 32) => Buffer.from(
  BigInt(value).toString(16).padStart(width * 2, '0'),
  'hex',
).reverse();

const replaceProjectionSignal = (inputs, signal) => {
  inputs[8].unlockingBytecode = Uint8Array.from(Buffer.concat([
    encodeDataPush(signal),
    encodeDataPush(opTrueRedeem),
  ]));
};

const pairingIsOne = (trace) => bn254.fields.Fp12.eql(
  directV2MillerPairingReference(trace),
  bn254.fields.Fp12.ONE,
);

test('finite and canonical-identity authorities are independent 4-pair/3-pair references', () => {
  assert.equal(finiteMsm.output.infinity, false);
  assert.equal(identityMsm.output.infinity, true);
  assert.deepEqual(
    [identityMsm.output.x, identityMsm.output.y],
    [0n, 0n],
  );
  assert.equal(finiteTrace.qInf, false);
  assert.equal(identityTrace.qInf, true);
  assert.deepEqual(finiteTrace.activePairNames, [
    'negA_B',
    'alpha_beta',
    'vkx_gamma',
    'C_delta',
  ]);
  assert.deepEqual(identityTrace.activePairNames, [
    'negA_B',
    'alpha_beta',
    'C_delta',
  ]);
  assert.equal(pairingIsOne(finiteTrace), true);
  assert.equal(pairingIsOne(identityTrace), true);
  assert.equal(finiteTrace.steps.length, 65);
  assert.equal(identityTrace.steps.length, 65);
  assert.equal(
    directV2MillerStepFactorSpec(finiteTrace, 0)
      .some(({ pair }) => pair === 2),
    true,
  );
  assert.equal(
    directV2MillerStepFactorSpec(identityTrace, 0)
      .some(({ pair }) => pair === 2),
    false,
  );
  assert.notDeepEqual(
    encodeDirectV2MillerGenesisHead(finiteTrace),
    encodeDirectV2MillerGenesisHead(identityTrace),
  );
});

test('the frozen finite PairFold executor schedule cannot consume the identity handoff', () => {
  for (let step = 0; step < finiteTrace.steps.length; step += 1) {
    const finiteGammaLines = directV2MillerStepFactorSpec(finiteTrace, step)
      .filter(({ pair }) => pair === 2);
    const identityGammaLines = directV2MillerStepFactorSpec(identityTrace, step)
      .filter(({ pair }) => pair === 2);
    assert.equal(
      finiteGammaLines.length > 0,
      true,
      `finite step ${step} unexpectedly has no vkx/gamma line`,
    );
    assert.equal(
      identityGammaLines.length,
      0,
      `identity step ${step} retained a vkx/gamma line`,
    );
  }
  assert.notEqual(finiteTrace.gamma, identityTrace.gamma);
  assert.notEqual(finiteTrace.z, identityTrace.z);
  assert.equal(finiteTrace.bigQ.length, 190);
  assert.equal(identityTrace.bigQ.length, 190);
  assert.equal(identityTrace.bigQ.slice(145).every((value) => value === 0n), true);
});

test('the transcript serializes the supplied VK, never the verifier-bench global VK', () => {
  const g1 = (point) => {
    const affine = point.toAffine();
    return [affine.x, affine.y];
  };
  const g2 = (point) => {
    const affine = point.toAffine();
    return [
      affine.x.c0,
      affine.x.c1,
      affine.y.c0,
      affine.y.c1,
    ];
  };
  assert.deepEqual(
    finiteTrace.stmtLimbs.slice(10, 24),
    [
      ...g1(verificationKey.alpha),
      ...g2(verificationKey.beta),
      ...g2(verificationKey.gamma),
      ...g2(verificationKey.delta),
    ],
  );

  // Regression: `_szmath.deployedStatementLimbs` reads `_millermath.vk`
  // globally. Using it here would keep this slice unchanged under a supplied
  // alternate VK and would recreate the cross-instance rolling-h bug.
  const alternateJson = structuredClone(verificationKeyJson);
  alternateJson.vk_alpha_1 = structuredClone(verificationKeyJson.IC[1]);
  const alternateKey = parseDirectV2MillerVerificationKey(alternateJson);
  const alternateTrace = computeDirectV2IdentityAwareMiller({
    verificationKey: alternateKey,
    proof: createDirectV2IdentityReferenceProof(alternateKey),
    q: identityMsm.output,
  });
  assert.notDeepEqual(
    identityTrace.stmtLimbs.slice(10, 12),
    alternateTrace.stmtLimbs.slice(10, 12),
  );
  assert.notEqual(identityTrace.gamma, alternateTrace.gamma);
});

test('finite and canonical identity genesis branches accept under real BCH-2026 ceilings', () => {
  const results = [
    ['finite', finiteTrace],
    ['identity', identityTrace],
  ].map(([branch, trace]) => {
    const spend = buildSpend(
      trace,
      contract,
      branch === 'identity' ? identityActionDigest : finiteActionDigest,
    );
    const outcome = evaluate(spend.inputs);
    assert.equal(
      outcome.accepted,
      true,
      `${branch} rejected: ${outcome.error ?? 'unknown'}`,
    );
    assert.equal(spend.unlock.length <= 10_000, true);
    assert.equal(
      outcome.operationCost <= realOpCostBudget(spend.unlock.length),
      true,
    );
    return {
      branch,
      activePairs: trace.activePairNames.length,
      transcript: trace.transcriptVersion,
      redeemBytes: contract.redeem.length,
      unlockBytes: spend.unlock.length,
      zeroPaddingBytes: contract.zeroPaddingBytes,
      operationCost: outcome.operationCost,
      operationBudget: realOpCostBudget(spend.unlock.length),
      instructionCount: outcome.instructionCount,
      arithmeticCost: outcome.arithmeticCost,
      stackPushedBytes: outcome.stackPushedBytes,
    };
  });
  console.log(JSON.stringify({ directV2MillerGenesis: results }));
});

test('malformed identity encodings, forced branches, and gamma-source mutation reject', () => {
  const finiteSpend = buildSpend(finiteTrace);
  const identitySpend = buildSpend(
    identityTrace,
    contract,
    identityActionDigest,
  );

  assert.throws(
    () => computeDirectV2IdentityAwareMiller({
      verificationKey,
      proof: createDirectV2IdentityReferenceProof(verificationKey),
      q: { infinity: true, x: 1n, y: 2n },
    }),
    /conflicting nonzero coordinates and infinity metadata/,
  );

  {
    const inputs = cloneInputs(identitySpend);
    const signal = encodeDirectV2MillerProjectionSignal(
      identityTrace,
      identityActionDigest,
    );
    signal[160] = 1;
    replaceProjectionSignal(inputs, signal);
    expectReject(inputs, 'noncanonical identity (0,1)');
  }
  {
    const inputs = cloneInputs(identitySpend);
    const signal = encodeDirectV2MillerProjectionSignal(
      identityTrace,
      identityActionDigest,
    );
    littleEndian(BN254_BASE_FIELD).copy(signal, 128);
    replaceProjectionSignal(inputs, signal);
    expectReject(inputs, 'field-alias identity x');
  }
  {
    const inputs = cloneInputs(finiteSpend);
    const signal = encodeDirectV2MillerProjectionSignal(
      finiteTrace,
      finiteActionDigest,
    );
    signal.fill(0, 128, 192);
    replaceProjectionSignal(inputs, signal);
    expectReject(inputs, 'forced identity branch over finite witness');
  }
  {
    const inputs = cloneInputs(identitySpend);
    const signal = encodeDirectV2MillerProjectionSignal(
      identityTrace,
      identityActionDigest,
    );
    const finiteSignal = encodeDirectV2MillerProjectionSignal(
      finiteTrace,
      finiteActionDigest,
    );
    finiteSignal.copy(signal, 128, 128, 192);
    replaceProjectionSignal(inputs, signal);
    expectReject(inputs, 'forced finite branch over identity witness');
  }

  const fixed = directV2MillerFixedStep0(verificationKey);
  const gammaCoefficient = (
    fixed.gamma.coefficients[2].c0 % BN254_BASE_FIELD
  ).toString();
  const mutatedCoefficient = (
    (fixed.gamma.coefficients[2].c0 + 1n) % BN254_BASE_FIELD
  ).toString();
  const mutant = compileContract((source) => {
    let replaced = false;
    const changed = source.split('\n').map((line) => {
      if (!line.includes('if (qInf == 0) { pf0 =')) return line;
      const mutated = line.replace(gammaCoefficient, mutatedCoefficient);
      replaced = mutated !== line;
      return mutated;
    }).join('\n');
    assert.equal(replaced, true);
    return changed;
  });
  expectReject(
    buildSpend(finiteTrace, mutant).inputs,
    'mutated fixed gamma source',
  );
});

test('carrier, head, witness, topology, terminal, binding, and state mutations reject', () => {
  const spend = buildSpend(finiteTrace);

  {
    const inputs = cloneInputs(spend);
    inputs[8].unlockingBytecode[0] = 0x4c;
    expectReject(inputs, 'projection carrier header');
  }
  {
    const inputs = cloneInputs(spend);
    const signal = encodeDirectV2MillerProjectionSignal(
      finiteTrace,
      finiteActionDigest,
    );
    replaceProjectionSignal(inputs, signal.subarray(0, 479));
    expectReject(inputs, 'projection carrier length');
  }
  {
    const inputs = cloneInputs(spend);
    inputs[8].unlockingBytecode[3 + 64] ^= 1;
    expectReject(inputs, 'projection transcript context');
  }
  {
    const inputs = cloneInputs(spend);
    inputs[0].unlockingBytecode[3 + 40] ^= 1;
    expectReject(inputs, 'executor head');
  }
  for (const [label, offset] of [
    ['slope witness', 1],
    ['endpoint witness', 65 + 3],
    ['residue witness', 65 + 3 + 384 + 3],
  ]) {
    const inputs = cloneInputs(spend);
    inputs[9].unlockingBytecode[offset] ^= 1;
    expectReject(inputs, label);
  }
  {
    const inputs = cloneInputs(spend);
    inputs[9].unlockingBytecode[
      inputs[9].unlockingBytecode.length - contract.redeem.length - 4
    ] ^= 1;
    expectReject(inputs, 'zero padding');
  }
  {
    const inputs = cloneInputs(spend);
    inputs[10].lockingBytecode = differentLock;
    expectReject(inputs, 'terminal lock');
  }
  {
    const inputs = cloneInputs(spend);
    inputs[11].lockingBytecode = differentLock;
    expectReject(inputs, 'binding lock');
  }
  for (const [index, label] of [
    [0, 'executor-head outpoint'],
    [8, 'source outpoint'],
    [9, 'self outpoint'],
    [10, 'terminal outpoint'],
    [11, 'binding outpoint'],
    [12, 'state outpoint'],
  ]) {
    const inputs = cloneInputs(spend);
    inputs[index].outpointIndex += 1;
    expectReject(inputs, label);
  }
  for (const [index, label] of [
    [0, 'executor-head parent'],
    [8, 'source parent'],
    [10, 'terminal parent'],
    [11, 'binding parent'],
    [12, 'state parent'],
  ]) {
    const inputs = cloneInputs(spend);
    inputs[index].outpointTransactionHash = new Uint8Array(32).fill(0x5b);
    expectReject(inputs, label);
  }
  {
    const inputs = cloneInputs(spend);
    inputs.pop();
    expectReject(inputs, 'input count');
  }
  {
    const inputs = cloneInputs(spend);
    inputs[12].token.category[0] ^= 1;
    expectReject(inputs, 'state category');
  }
  {
    const inputs = cloneInputs(spend);
    inputs[12].token.capability = 'none';
    expectReject(inputs, 'state capability');
  }
  {
    const inputs = cloneInputs(spend);
    inputs[12].token.amount = 1n;
    expectReject(inputs, 'state amount');
  }
  {
    const inputs = cloneInputs(spend);
    inputs[12].token.commitment = inputs[12].token.commitment.subarray(1);
    expectReject(inputs, 'state commitment width');
  }
});

test('cycle-breaking lock omissions are explicit; the state helper owns the full lock-set', () => {
  const spend = buildSpend(finiteTrace);
  for (const [index, label] of [
    [8, 'role 8 source lock'],
    [12, 'state-helper lock'],
  ]) {
    const inputs = cloneInputs(spend);
    inputs[index].lockingBytecode = differentLock;
    const outcome = evaluate(inputs);
    assert.equal(
      outcome.accepted,
      true,
      `${label} was unexpectedly reciprocally pinned: ${outcome.error ?? 'unknown'}`,
    );
  }

  const digestOnly = cloneInputs(spend);
  digestOnly[8].unlockingBytecode[3 + 448] ^= 1;
  const digestOutcome = evaluate(digestOnly);
  assert.equal(
    digestOutcome.accepted,
    true,
    `action digest is owned by binding input 11: ${digestOutcome.error ?? 'unknown'}`,
  );
});
