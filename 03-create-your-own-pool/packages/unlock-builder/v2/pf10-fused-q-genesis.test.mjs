import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

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
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';
import {
  BN254_BASE_FIELD,
  computeDirectV2ExactMsm,
  encodeDirectV2MsmState,
} from './exact-msm.mjs';
import {
  renderDirectV2ExactMsmRole,
} from './exact-msm-cashscript.mjs';
import {
  computeDirectV2IdentityAwareMiller,
  createDirectV2IdentityReferenceProof,
  encodeDirectV2MillerGenesisHead,
  encodeDirectV2MillerGenesisWitness,
  encodeDirectV2MillerProjectionSignal,
  parseDirectV2MillerVerificationKey,
} from './identity-aware-miller.mjs';
import {
  renderDirectV2Pf10FusedQGenesisMillerComponent,
} from './identity-aware-miller-cashscript.mjs';
import {
  buildDirectV2Pf10FusedQGenesisRedeem,
  buildDirectV2Pf10FusedQGenesisUnlock,
  directV2Pf10ExactMsmArgumentPrefix,
} from './pf10-fused-q-genesis.mjs';
import {
  buildDirectV2BindingLock,
  buildDirectV2BindingRedeem,
  buildDirectV2BindingUnlock,
} from './structural-covenants.mjs';
import {
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
const withdrawalRoot = path.join(
  buildRoot,
  'v2-dev-proof-qualification',
  'withdrawal',
);
const verificationKeyJson = JSON.parse(readFileSync(
  verificationKeyPath,
  'utf8',
));
const verificationKey = parseDirectV2MillerVerificationKey(
  verificationKeyJson,
);
const proof = JSON.parse(readFileSync(
  path.join(withdrawalRoot, 'proof.json'),
  'utf8',
));
const publicInputs = JSON.parse(readFileSync(
  path.join(withdrawalRoot, 'public.json'),
  'utf8',
)).map(BigInt);
const packet = readFileSync(path.join(withdrawalRoot, 'packet.bin'));
const packetDigest = createHash('sha256').update(packet).digest();
const msm = computeDirectV2ExactMsm(
  verificationKeyJson,
  publicInputs[0],
  publicInputs[1],
);
const trace = computeDirectV2IdentityAwareMiller({
  verificationKey,
  proof,
  q: msm.output,
});

const lazyAffineLibrary = readFileSync(path.join(
  import.meta.dirname,
  '../vendor/verifier/build/singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash',
), 'utf8');
const compile = (source, files = {}) => cashcUtils.asmToBytecode(
  compileString(source, { files }).bytecode,
);
const optimizerRoot = path.join(
  import.meta.dirname,
  '../vendor/verifier/tools/singleton-artifact',
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
    [path.join(optimizerRoot, 'minpush_canon.mjs'), optimized, canonical],
    { encoding: 'utf8' },
  );
  assert.equal(
    result.status,
    0,
    `${label} canonicalizer failed: ${result.stderr || result.stdout}`,
  );
  return hexToBin(readFileSync(canonical, 'utf8').trim());
};

const opTrueRedeem = Uint8Array.of(0x51);
const opTrueLock = encodeLockingBytecodeP2sh32(hash256(opTrueRedeem));
const opTrueUnlock = encodeDataPush(opTrueRedeem);
const stateCategoryProtocolHex =
  '884e37651c512cf59480b73397f320ab9084128429473634cc38c646ab3d5400';
const stateCategory = Uint8Array.from(
  Buffer.from(stateCategoryProtocolHex, 'hex').reverse(),
);
const stateCommitment = new Uint8Array(128);
stateCommitment.set(Buffer.from('SKS2'));
const bindingOptions = Object.freeze({
  networkId: 2,
  profileId:
    '3abc7912b8a7f72a868950b91f539d6000615b1af317300ede597829ad61985a',
  stateCategory: stateCategoryProtocolHex,
  denominationSats: 10_000_000n,
  topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
});
const bindingRedeem = buildDirectV2BindingRedeem(bindingOptions);
const bindingLock = buildDirectV2BindingLock(bindingOptions);
const bindingUnlock = buildDirectV2BindingUnlock({
  packet,
  redeem: bindingRedeem,
});

const exactPadding = new Uint8Array(256);
const millerPadding = new Uint8Array(256);
const projection = encodeDirectV2MillerProjectionSignal(
  trace,
  packetDigest,
);
const msmState = encodeDirectV2MsmState(msm.states[3]);
const exactPrefix = directV2Pf10ExactMsmArgumentPrefix({
  projectionSignal: projection,
  msmState,
  zInverse: msm.output.zInverse,
  exactMsmZeroPadding: exactPadding,
});
const exactSource = renderDirectV2ExactMsmRole({
  verificationKey: verificationKeyJson,
  windowIndex: 3,
  inputIndex: 8,
  successorInputIndex: 9,
  successorLockingBytecodeHex: binToHex(opTrueLock),
  successorStatePayloadOffset: 0,
  stateInputIndex: 11,
  stateCategoryHex: stateCategoryProtocolHex,
  expectedInputCount: 13,
  packetInputIndex: 10,
  packetLockingBytecodeHex: binToHex(bindingLock),
  fixedWidthZInverse: true,
  zeroPaddingBytes: exactPadding.length,
});
const exactRaw = compile(exactSource);
const exactRedeem = optimize(exactRaw, 'pf10-fused-exact');
const millerSource = renderDirectV2Pf10FusedQGenesisMillerComponent({
  verificationKey,
  ownWitnessPayloadOffset: exactPrefix.length,
  successorLockingBytecodeHex: binToHex(opTrueLock),
  bindingLockingBytecodeHex: binToHex(bindingLock),
  stateCategoryHex: stateCategoryProtocolHex,
  zeroPaddingBytes: millerPadding.length,
  libraryImportPath: 'Bn254LazyAff.cash',
});
const millerRaw = compile(millerSource, {
  'Bn254LazyAff.cash': lazyAffineLibrary,
});
const millerRedeem = optimize(millerRaw, 'pf10-fused-miller');
const redeem = buildDirectV2Pf10FusedQGenesisRedeem({
  millerRedeem,
  exactMsmRedeem: exactRedeem,
});
const witness = encodeDirectV2MillerGenesisWitness(trace);
const unlock = buildDirectV2Pf10FusedQGenesisUnlock({
  projectionSignal: projection,
  msmState,
  zInverse: msm.output.zInverse,
  exactMsmZeroPadding: exactPadding,
  slope: witness.slope,
  endpoint: witness.endpoint,
  residue: witness.residue,
  millerZeroPadding: millerPadding,
  redeem,
});
const lock = encodeLockingBytecodeP2sh32(hash256(redeem));
const parent = new Uint8Array(32).fill(0x5a);
const inputs = Array.from({ length: 13 }, (_, index) => ({
  lockingBytecode: opTrueLock,
  unlockingBytecode: opTrueUnlock,
  outpointTransactionHash: parent,
  outpointIndex: index + 1,
}));
inputs[0].unlockingBytecode = Uint8Array.from(Buffer.concat([
  encodeDataPush(encodeDirectV2MillerGenesisHead(trace)),
  encodeDataPush(opTrueRedeem),
]));
inputs[8] = {
  ...inputs[8],
  lockingBytecode: lock,
  unlockingBytecode: unlock,
};
inputs[10] = {
  ...inputs[10],
  lockingBytecode: bindingLock,
  unlockingBytecode: bindingUnlock,
};
inputs[11] = {
  ...inputs[11],
  outpointIndex: 0,
  token: {
    amount: 0n,
    category: stateCategory,
    capability: 'mutable',
    commitment: stateCommitment,
  },
};
inputs[12] = {
  ...inputs[12],
  outpointTransactionHash: new Uint8Array(32).fill(0x20),
  outpointIndex: 7,
};

const evaluate = (sourceInputs = inputs) => evaluatePair(
  createRealVm(),
  sourceInputs[8].lockingBytecode,
  sourceInputs[8].unlockingBytecode,
  undefined,
  { index: 8, inputs: sourceInputs },
);

const unlockForTrace = (candidateTrace) => {
  const candidateProjection = encodeDirectV2MillerProjectionSignal(
    candidateTrace,
    packetDigest,
  );
  const candidateWitness = encodeDirectV2MillerGenesisWitness(candidateTrace);
  return buildDirectV2Pf10FusedQGenesisUnlock({
    projectionSignal: candidateProjection,
    msmState,
    zInverse: msm.output.zInverse,
    exactMsmZeroPadding: exactPadding,
    slope: candidateWitness.slope,
    endpoint: candidateWitness.endpoint,
    residue: candidateWitness.residue,
    millerZeroPadding: millerPadding,
    redeem,
  });
};

test('PF10 Miller genesis canonicalizes a negative modular representative before serializing its successor head', () => {
  assert.match(
    millerSource,
    /aL = \(mulFp\(mulFp\(fC, fC\), pf0\) \+ P\) % P;/u,
  );
  assert.doesNotMatch(
    millerSource,
    /aL = mulFp\(mulFp\(fC, fC\), pf0\);/u,
  );
});

test('PF10-FusedQGenesis role 8 composes final exact MSM and total Miller genesis under BCH-2026', () => {
  const outcome = evaluate();
  console.log(JSON.stringify({
    pf10FusedQGenesis: {
      exactPrefixBytes: exactPrefix.length,
      exactRawBytes: exactRaw.length,
      exactRedeemBytes: exactRedeem.length,
      millerRawBytes: millerRaw.length,
      millerRedeemBytes: millerRedeem.length,
      fusedRedeemBytes: redeem.length,
      unlockBytes: unlock.length,
      operationCost: outcome.operationCost,
      operationBudget: realOpCostBudget(unlock.length),
      instructionCount: outcome.instructionCount,
      arithmeticCost: outcome.arithmeticCost,
      stackPushedBytes: outcome.stackPushedBytes,
    },
  }));
  assert.equal(
    outcome.accepted,
    true,
    `fused role rejected: ${outcome.error}`,
  );
  assert.equal(unlock.length <= 10_000, true);
  assert.equal(outcome.operationCost <= realOpCostBudget(unlock.length), true);
});

test('PF10-FusedQGenesis rejects Q, packet, MSM-state, and Miller-witness mutations', () => {
  for (const [label, inputIndex, offset] of [
    ['projection Q', 8, 3 + 128],
    ['MSM state', 8, 483 + 2],
    ['Miller slope', 8, exactPrefix.length + 1],
    ['packet', 10, 3 + 551],
  ]) {
    const mutated = structuredClone(inputs);
    mutated[inputIndex].unlockingBytecode[offset] ^= 1;
    assert.equal(evaluate(mutated).accepted, false, `${label} accepted`);
  }
});

test('PF10-FusedQGenesis rejects an identity-Miller branch substituted for its affine MSM Q', () => {
  const identityTrace = computeDirectV2IdentityAwareMiller({
    verificationKey,
    proof: createDirectV2IdentityReferenceProof(verificationKey),
    q: null,
  });
  const identityInputs = structuredClone(inputs);
  identityInputs[0].unlockingBytecode = Uint8Array.from(Buffer.concat([
    encodeDataPush(encodeDirectV2MillerGenesisHead(identityTrace)),
    encodeDataPush(opTrueRedeem),
  ]));
  identityInputs[8].unlockingBytecode = unlockForTrace(identityTrace);
  const outcome = evaluate(identityInputs);
  assert.equal(
    outcome.accepted,
    false,
    'identity Miller branch detached from the affine exact-MSM Q accepted',
  );
});

test('PF10-FusedQGenesis accepts the identity branch only when exact MSM produces Q = O', () => {
  /*
   * This is an algebraic totality fixture, not final-key proof evidence. Keep
   * the real packet and its two SHA-256-derived public inputs, but derive a
   * test-only IC[0] that is exactly the inverse of
   * input0*IC[1] + input1*IC[2]. The resulting exact-MSM output is therefore
   * the canonical identity without relying on an infeasible digest preimage.
   */
  const identityVerificationKeyJson = structuredClone(verificationKeyJson);
  identityVerificationKeyJson.IC[0] = ['0', '1', '0'];
  const publicContribution = computeDirectV2ExactMsm(
    identityVerificationKeyJson,
    publicInputs[0],
    publicInputs[1],
  ).output;
  assert.equal(
    publicContribution.infinity,
    false,
    'test packet unexpectedly has an identity public-input contribution',
  );
  identityVerificationKeyJson.IC[0] = [
    publicContribution.x.toString(),
    (
      (BN254_BASE_FIELD - publicContribution.y)
      % BN254_BASE_FIELD
    ).toString(),
    '1',
  ];

  const identityMsm = computeDirectV2ExactMsm(
    identityVerificationKeyJson,
    publicInputs[0],
    publicInputs[1],
  );
  assert.deepEqual(identityMsm.output, {
    infinity: true,
    x: 0n,
    y: 0n,
    zInverse: 0n,
  });
  const identityVerificationKey =
    parseDirectV2MillerVerificationKey(identityVerificationKeyJson);
  const identityProof =
    createDirectV2IdentityReferenceProof(identityVerificationKey);
  const identityTrace = computeDirectV2IdentityAwareMiller({
    verificationKey: identityVerificationKey,
    proof: identityProof,
    q: identityMsm.output,
  });

  const identityProjection = encodeDirectV2MillerProjectionSignal(
    identityTrace,
    packetDigest,
  );
  const identityMsmState = encodeDirectV2MsmState(identityMsm.states[3]);
  const identityExactPrefix = directV2Pf10ExactMsmArgumentPrefix({
    projectionSignal: identityProjection,
    msmState: identityMsmState,
    zInverse: identityMsm.output.zInverse,
    exactMsmZeroPadding: exactPadding,
  });
  assert.equal(identityExactPrefix.length, exactPrefix.length);

  const identityExactSource = renderDirectV2ExactMsmRole({
    verificationKey: identityVerificationKeyJson,
    windowIndex: 3,
    inputIndex: 8,
    successorInputIndex: 9,
    successorLockingBytecodeHex: binToHex(opTrueLock),
    successorStatePayloadOffset: 0,
    stateInputIndex: 11,
    stateCategoryHex: stateCategoryProtocolHex,
    expectedInputCount: 13,
    packetInputIndex: 10,
    packetLockingBytecodeHex: binToHex(bindingLock),
    fixedWidthZInverse: true,
    zeroPaddingBytes: exactPadding.length,
  });
  const identityExactRedeem = optimize(
    compile(identityExactSource),
    'pf10-fused-exact-identity',
  );
  const identityMillerSource =
    renderDirectV2Pf10FusedQGenesisMillerComponent({
      verificationKey: identityVerificationKey,
      ownWitnessPayloadOffset: identityExactPrefix.length,
      successorLockingBytecodeHex: binToHex(opTrueLock),
      bindingLockingBytecodeHex: binToHex(bindingLock),
      stateCategoryHex: stateCategoryProtocolHex,
      zeroPaddingBytes: millerPadding.length,
      libraryImportPath: 'Bn254LazyAff.cash',
    });
  const identityMillerRedeem = optimize(
    compile(identityMillerSource, {
      'Bn254LazyAff.cash': lazyAffineLibrary,
    }),
    'pf10-fused-miller-identity',
  );
  const identityRedeem = buildDirectV2Pf10FusedQGenesisRedeem({
    millerRedeem: identityMillerRedeem,
    exactMsmRedeem: identityExactRedeem,
  });
  const identityWitness =
    encodeDirectV2MillerGenesisWitness(identityTrace);
  const identityUnlock = buildDirectV2Pf10FusedQGenesisUnlock({
    projectionSignal: identityProjection,
    msmState: identityMsmState,
    zInverse: identityMsm.output.zInverse,
    exactMsmZeroPadding: exactPadding,
    slope: identityWitness.slope,
    endpoint: identityWitness.endpoint,
    residue: identityWitness.residue,
    millerZeroPadding: millerPadding,
    redeem: identityRedeem,
  });
  const identityInputs = structuredClone(inputs);
  identityInputs[0].unlockingBytecode = Uint8Array.from(Buffer.concat([
    encodeDataPush(encodeDirectV2MillerGenesisHead(identityTrace)),
    encodeDataPush(opTrueRedeem),
  ]));
  identityInputs[8] = {
    ...identityInputs[8],
    lockingBytecode: encodeLockingBytecodeP2sh32(
      hash256(identityRedeem),
    ),
    unlockingBytecode: identityUnlock,
  };
  const outcome = evaluate(identityInputs);
  assert.equal(
    outcome.accepted,
    true,
    `coherent exact-MSM identity branch rejected: ${outcome.error}`,
  );
  assert.equal(identityUnlock.length <= 10_000, true);
  assert.equal(
    outcome.operationCost <= realOpCostBudget(identityUnlock.length),
    true,
  );
});
