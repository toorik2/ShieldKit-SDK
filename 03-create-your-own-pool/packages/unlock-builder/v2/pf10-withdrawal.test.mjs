import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
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
  ConsensusBch2025,
  createVirtualMachineBch2026,
  decodeTransaction,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  encodeTokenPrefix,
  encodeTransaction,
  hash160,
  hash256,
  hexToBin,
  maximumSignatureCheckCount,
  secp256k1,
} from '@bitauth/libauth';
import {
  compileString,
  utils as cashcUtils,
} from '../vendor/verifier/vendor/cashc-resched/packages/cashc/dist/index.js';

import {
  deriveV2RollingBaseSats,
} from '../../action/v2/dust-policy.mjs';
import {
  ACTION_PACKET_OFFSETS,
  actionPacketPublicLimbs,
  decodeActionPacket,
  encodeActionPacket,
} from '../../action/v2/packet.mjs';
import {
  encodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import {
  assembleV2DirectSettlement,
  prepareV2DirectSettlement,
  signV2DirectSettlement,
} from '../../action/v2/settlement.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';
import {
  assertV2StandardTransactionEnvelope,
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../../kit/v2/transaction-policy.mjs';
import {
  createV2LocalVmEvidence,
  inspectV2LocalVmEvidence,
} from '../../kit/v2/vm-evidence.mjs';
import {
  deriveProfileId,
} from '../../profile/v2/profile-core.mjs';
import {
  V2_GROTH16_PROOF_RESULT_SCHEMA,
} from '../../prove/v2/groth16-proof-child.mjs';
import {
  sha256File,
} from '../../prove/groth16.mjs';
import {
  computeDirectV2ExactMsm,
  encodeDirectV2MsmState,
} from './exact-msm.mjs';
import {
  renderDirectV2ExactMsmRole,
} from './exact-msm-cashscript.mjs';
import {
  computeDirectV2IdentityAwareMiller,
  createDirectV2IdentityReferenceProof,
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
  buildDirectV2StateHelper,
  buildDirectV2StateTrampolineLock,
  buildDirectV2StateTrampolineUnlock,
} from './structural-covenants.mjs';
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
  DIRECT_V2_PAIRFOLD_RANGES,
} from './total-pairfold.mjs';
import {
  DirectV2Pf10ActionWitnessError,
  DIRECT_V2_PF10_RUNTIME_SCHEMA,
  DIRECT_V2_PF10_STATE_UNLOCK_BYTES,
  DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES,
  buildDirectV2Pf10ActionWitness,
  validateDirectV2Pf10RuntimeMaterial,
} from './pf10-action-witness.mjs';
import {
  buildDirectV2Pf10DevelopmentRuntime,
} from './pf10-development-runtime-builder.mjs';
import {
  ATE_NAF,
  BN_X,
  bn254,
  Fp2B,
} from '../vendor/verifier/build/chunked/pairing/_millermath.mjs';
import {
  createLoosenedVm,
  realOpCostBudget,
} from '../vendor/verifier/harness/src/harness/vm.ts';

const repoRoot = path.resolve(import.meta.dirname, '../../../..');
const buildRoot = path.join(repoRoot, '.codex-build');
const explicitArtifactEnvironment = Object.freeze({
  evidenceRoot: process.env.SHIELDKIT_PF10_QUALIFICATION_ROOT,
  r1cs: process.env.SHIELDKIT_PF10_R1CS,
  setupMetadata: process.env.SHIELDKIT_PF10_SETUP_METADATA,
  verificationKey: process.env.SHIELDKIT_PF10_VERIFICATION_KEY,
  wasm: process.env.SHIELDKIT_PF10_WASM,
  zkey: process.env.SHIELDKIT_PF10_ZKEY,
});
const explicitProfileCorePath = process.env.SHIELDKIT_PF10_PROFILE_CORE;
const explicitArtifactValues = Object.values(explicitArtifactEnvironment);
const explicitArtifactCount = explicitArtifactValues.filter(
  (value) => value !== undefined,
).length;
assert.equal(
  explicitArtifactCount === 0
    || explicitArtifactCount === explicitArtifactValues.length,
  true,
  'PF10 explicit artifact environment must provide the complete coherent set',
);
assert.equal(
  (explicitArtifactCount === 0)
    === (explicitProfileCorePath === undefined),
  true,
  'PF10 profile core must be provided exactly with the complete explicit artifact set',
);
if (explicitArtifactCount !== 0) {
  for (const [name, value] of Object.entries(explicitArtifactEnvironment)) {
    assert.equal(
      typeof value === 'string'
      && path.isAbsolute(value)
      && path.normalize(value) === value,
      true,
      `PF10 explicit artifact environment ${name} must be an absolute normalized path`,
    );
  }
  assert.equal(
    typeof explicitProfileCorePath === 'string'
    && path.isAbsolute(explicitProfileCorePath)
    && path.normalize(explicitProfileCorePath) === explicitProfileCorePath,
    true,
    'PF10 explicit artifact environment must provide an absolute normalized profile core path',
  );
}
const defaultQualificationRoot = path.join(
  buildRoot,
  'v2-dev-proof-qualification',
);
const qualificationRoot =
  explicitArtifactEnvironment.evidenceRoot ?? defaultQualificationRoot;
const verificationKeyPath =
  explicitArtifactEnvironment.verificationKey
  ?? path.join(buildRoot, 'v2-dev-groth16', 'verification_key.json');
const zkeyPath =
  explicitArtifactEnvironment.zkey
  ?? path.join(buildRoot, 'v2-dev-groth16', 'final.zkey');
const r1csPath =
  explicitArtifactEnvironment.r1cs
  ?? path.join(buildRoot, 'v2-circuit-model', 'main-chipnet.r1cs');
const wasmPath =
  explicitArtifactEnvironment.wasm
  ?? path.join(
    buildRoot,
    'v2-circuit-model',
    'main-chipnet_js',
    'main-chipnet.wasm',
  );
const profileCorePath =
  explicitProfileCorePath
  ?? path.join(buildRoot, 'v2-development-profile', 'profile-core.json');
const coherenceArtifactPaths = explicitArtifactCount === 0
  ? undefined
  : Object.freeze({
    ...explicitArtifactEnvironment,
    evidence: path.join(
      explicitArtifactEnvironment.evidenceRoot,
      'qualification-evidence.json',
    ),
  });
const actionKinds = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const actionArtifacts = Object.freeze(Object.fromEntries(
  actionKinds.map((kind) => {
    const root = path.join(
      qualificationRoot,
      kind,
    );
    return [kind, Object.freeze({
      packet: path.join(root, 'packet.bin'),
      input: path.join(root, 'input.json'),
      proof: path.join(root, 'proof.json'),
      public: path.join(root, 'public.json'),
    })];
  }),
));
const referenceArtifacts = actionArtifacts.withdrawal;
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
  'build/singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash',
), 'utf8');

const topologyOptions = Object.freeze({
  topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
});
const carrierCount = DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length;
const networkId = 2;
const denominationSats = 10_000_000n;
const stateContext = Object.freeze({
  denominationSats: denominationSats.toString(),
});
const baseFundingValue = 250_000n;
const minimumChange = 546n;
const exactPadding = new Uint8Array(256);
const nonFinalExactPadding = new Uint8Array(7_500);
const millerPadding = new Uint8Array(256);
const executorDensityPadBytes = 384;
const bqLengths = Object.freeze(Array(5).fill(1_216));
const opcostCompilerOptions = Object.freeze({
  optimizeFor: 'opcost',
  rescheduleStacks: true,
});
const libauthVersion = createRequire(import.meta.url)(
  '@bitauth/libauth/package.json',
).version;

const concat = (...parts) => Uint8Array.from(
  parts.flatMap((part) => [...part]),
);
const push = (value) => Uint8Array.from(encodeDataPush(value));
const sha256 = (value) => createHash('sha256').update(value).digest();
const encodedLength = (length) => push(new Uint8Array(length)).length;
const pushHeaderLength = (length) => encodedLength(length) - length;
const accepts = (state) => (
  state.error === undefined
  && state.stack.length === 1
  && state.stack[0].length > 0
  && state.stack[0].some((byte, index) => (
    byte !== 0
    && !(index === state.stack[0].length - 1 && byte === 0x80)
  ))
);

const { Fp, Fp2 } = bn254.fields;
const fieldOrder = Fp.ORDER;
const modField = (value) => {
  const reduced = BigInt(value) % fieldOrder;
  return reduced < 0n ? reduced + fieldOrder : reduced;
};
const fp2 = (c0, c1) => Fp2.fromBigTuple([
  modField(c0),
  modField(c1),
]);
const scaleFp2 = (value, scalar) => fp2(
  Fp.mul(value.c0, scalar),
  Fp.mul(value.c1, scalar),
);
const fieldLe32 = (value) => Buffer.from(
  modField(value).toString(16).padStart(64, '0'),
  'hex',
).reverse();
const encodeFp2Values = (values) => Buffer.concat(values.flatMap(
  (value) => [fieldLe32(value.c0), fieldLe32(value.c1)],
));
const hash256Hex = (value) => {
  const once = createHash('sha256').update(value).digest();
  return createHash('sha256').update(once).digest('hex');
};

/*
 * Independent deployment-VK-only fixed-line derivation.
 *
 * This deliberately does not consume a proof, public input, MSM output,
 * Miller trace, or the PairFold builder's fixed-line schedule. It walks the
 * two deployment G2 points directly using the BN254 affine formulas and the
 * canonical ATE NAF digits, then applies the exact projective scalings used by
 * the fixed-line executor.
 */
const independentDeploymentFixedTables = (verificationKey) => {
  const gammaBase = verificationKey.gamma.toAffine();
  const deltaBase = verificationKey.delta.toAffine();
  const curveB = Fp2.sub(
    Fp2.sqr(gammaBase.y),
    Fp2.mul(Fp2.sqr(gammaBase.x), gammaBase.x),
  );
  assert.equal(Fp2.eql(curveB, Fp2B), true);
  assert.equal(
    Fp2.eql(
      Fp2.sub(
        Fp2.sqr(deltaBase.y),
        Fp2.mul(Fp2.sqr(deltaBase.x), deltaBase.x),
      ),
      curveB,
    ),
    true,
  );
  const deriveNaf = (value) => {
    const digits = [];
    for (let remaining = value; remaining > 1n; remaining >>= 1n) {
      if ((remaining & 1n) === 0n) {
        digits.unshift(0);
      } else if ((remaining & 3n) === 3n) {
        digits.unshift(-1);
        remaining += 1n;
      } else {
        digits.unshift(1);
      }
    }
    return digits;
  };
  const independentAteNaf = deriveNaf(6n * BN_X + 2n);
  assert.deepEqual(
    independentAteNaf,
    ATE_NAF,
    'independently derived BN254 ATE NAF differs from Miller reference',
  );
  const affineDouble = (x, y) => {
    const c1 = scaleFp2(Fp2.sqr(x), 3n);
    const slope = Fp2.mul(c1, Fp2.inv(Fp2.add(y, y)));
    const nextX = Fp2.sub(Fp2.sqr(slope), Fp2.add(x, x));
    const nextY = Fp2.sub(
      Fp2.mul(slope, Fp2.sub(x, nextX)),
      y,
    );
    return Object.freeze({
      point: Object.freeze({ x: nextX, y: nextY }),
      coefficients: Object.freeze([
        Fp2.sub(scaleFp2(curveB, 3n), Fp2.sqr(y)),
        c1,
        Fp2.neg(Fp2.add(y, y)),
      ]),
    });
  };
  const affineAdd = (rx, ry, qx, qy) => {
    const dx = Fp2.sub(rx, qx);
    const dy = Fp2.sub(ry, qy);
    const slope = Fp2.mul(dy, Fp2.inv(dx));
    const nextX = Fp2.sub(Fp2.sub(Fp2.sqr(slope), rx), qx);
    const nextY = Fp2.sub(
      Fp2.mul(slope, Fp2.sub(rx, nextX)),
      ry,
    );
    return Object.freeze({
      point: Object.freeze({ x: nextX, y: nextY }),
      coefficients: Object.freeze([
        Fp2.sub(Fp2.mul(dy, qx), Fp2.mul(dx, qy)),
        Fp2.neg(dy),
        dx,
      ]),
    });
  };
  const scaleDouble = (coefficients) => {
    const slope = Fp2.mul(
      coefficients[1],
      Fp2.inv(coefficients[2]),
    );
    const scale = Fp2.mul(fp2(4n, 0n), Fp2.sqr(slope));
    return coefficients.map((coefficient) =>
      Fp2.mul(coefficient, scale));
  };
  const normalizeAdd = (coefficients) => {
    const inverse = Fp2.inv(coefficients[2]);
    return coefficients.map((coefficient) =>
      Fp2.mul(coefficient, inverse));
  };
  const psiX = Fp2.pow(
    Fp2.NONRESIDUE,
    (fieldOrder - 1n) / 3n,
  );
  const psiY = Fp2.pow(
    Fp2.NONRESIDUE,
    (fieldOrder - 1n) / 2n,
  );
  const psi = (point) => Object.freeze({
    x: Fp2.mul(Fp2.frobeniusMap(point.x, 1), psiX),
    y: Fp2.mul(Fp2.frobeniusMap(point.y, 1), psiY),
  });

  let gamma = gammaBase;
  let delta = deltaBase;
  const starts = [];
  const encodedSteps = [];
  let terminalGammaDouble;
  let terminalDeltaDouble;
  for (let step = 0; step < independentAteNaf.length; step += 1) {
    starts.push(Object.freeze({ gamma, delta }));
    const gammaDouble = affineDouble(gamma.x, gamma.y);
    const deltaDouble = affineDouble(delta.x, delta.y);
    const fields = [
      ...(step === 0
        ? gammaDouble.coefficients
        : scaleDouble(gammaDouble.coefficients)),
      ...(step === 0
        ? deltaDouble.coefficients
        : scaleDouble(deltaDouble.coefficients)),
    ];
    gamma = gammaDouble.point;
    delta = deltaDouble.point;
    const digit = independentAteNaf[step] ?? 0;
    if (digit !== 0) {
      const gammaAdd = affineAdd(
        gamma.x,
        gamma.y,
        gammaBase.x,
        digit === -1 ? Fp2.neg(gammaBase.y) : gammaBase.y,
      );
      const deltaAdd = affineAdd(
        delta.x,
        delta.y,
        deltaBase.x,
        digit === -1 ? Fp2.neg(deltaBase.y) : deltaBase.y,
      );
      fields.push(
        ...normalizeAdd(gammaAdd.coefficients),
        ...normalizeAdd(deltaAdd.coefficients),
      );
      gamma = gammaAdd.point;
      delta = deltaAdd.point;
    }
    encodedSteps.push(encodeFp2Values(fields));
    if (step === 64) {
      terminalGammaDouble = gammaDouble.coefficients;
      terminalDeltaDouble = deltaDouble.coefficients;
    }
  }

  const gammaQ1 = psi(gammaBase);
  const gammaPp1 = affineAdd(
    gamma.x,
    gamma.y,
    gammaQ1.x,
    gammaQ1.y,
  );
  const gammaQ2 = psi(gammaQ1);
  const gammaPp2 = affineAdd(
    gammaPp1.point.x,
    gammaPp1.point.y,
    gammaQ2.x,
    Fp2.neg(gammaQ2.y),
  );
  const deltaQ1 = psi(deltaBase);
  const deltaPp1 = affineAdd(
    delta.x,
    delta.y,
    deltaQ1.x,
    deltaQ1.y,
  );
  const deltaQ2 = psi(deltaQ1);
  const deltaPp2 = affineAdd(
    deltaPp1.point.x,
    deltaPp1.point.y,
    deltaQ2.x,
    Fp2.neg(deltaQ2.y),
  );
  const coefficientSlope = (coefficients) => Fp2.mul(
    coefficients[1],
    Fp2.inv(coefficients[2]),
  );
  const terminal = encodeFp2Values([
    starts[64].gamma.x,
    starts[64].delta.x,
    coefficientSlope(terminalGammaDouble),
    coefficientSlope(terminalDeltaDouble),
    ...normalizeAdd(gammaPp1.coefficients).slice(0, 2),
    ...normalizeAdd(gammaPp2.coefficients).slice(0, 2),
    ...normalizeAdd(deltaPp1.coefficients).slice(0, 2),
    ...normalizeAdd(deltaPp2.coefficients).slice(0, 2),
  ]);
  const roles = DIRECT_V2_PAIRFOLD_RANGES.map(([start, end]) =>
    Buffer.concat(encodedSteps.slice(start, end)));
  return Object.freeze({
    roles: Object.freeze(roles),
    terminal,
    roleHash256: Object.freeze(roles.map(hash256Hex)),
    terminalHash256: hash256Hex(terminal),
  });
};

const assertDeploymentFixedTables = (
  template,
  independent,
  label,
) => {
  template.roles.forEach((roleTemplate, index) => {
    const fullTable = Buffer.concat([
      roleTemplate.table,
      roleTemplate.remoteTable,
    ]);
    assert.deepEqual(
      fullTable,
      independent.roles[index],
      `${label}: role ${index} fixed table is not deployment-VK-only`,
    );
    assert.equal(
      roleTemplate.fullTableBytes,
      independent.roles[index].length,
      `${label}: role ${index} fixed-table byte count changed`,
    );
    assert.equal(
      roleTemplate.tableHash256,
      independent.roleHash256[index],
      `${label}: role ${index} fixed-table digest changed`,
    );
  });
  assert.deepEqual(
    template.terminal.table,
    independent.terminal,
    `${label}: terminal fixed table is not deployment-VK-only`,
  );
  assert.equal(
    template.terminal.tableHash256,
    independent.terminalHash256,
    `${label}: terminal fixed-table digest changed`,
  );
};

const fixedTableCarrierLayout = ({
  template,
  carrierBytes,
  firstInputIndex,
  payloadOffset,
}) => {
  let cursor = 0;
  const layout = template.roles.map((roleTemplate) => {
    let remaining = roleTemplate.remoteTable.length;
    const slices = [];
    while (remaining > 0) {
      const carrierIndex = Math.floor(cursor / carrierBytes);
      const withinCarrier = cursor % carrierBytes;
      const length = Math.min(
        remaining,
        carrierBytes - withinCarrier,
      );
      slices.push(Object.freeze({
        inputIndex: firstInputIndex + carrierIndex,
        payloadOffset: payloadOffset + withinCarrier,
        length,
      }));
      cursor += length;
      remaining -= length;
    }
    return Object.freeze(slices);
  });
  return Object.freeze({ layout, bytes: cursor });
};

const compile = (
  source,
  files = {},
  compilerOptions = opcostCompilerOptions,
) =>
  cashcUtils.asmToBytecode(
    compileString(source, { files, ...compilerOptions }).bytecode,
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

const proveInIsolatedProcess = (circuitInput) => {
  const directory = mkdtempSync(path.join(
    tmpdir(),
    'shieldkit-pf10-proof-',
  ));
  const inputPath = path.join(directory, 'input.json');
  const outputPath = path.join(directory, 'result.json');
  writeFileSync(inputPath, JSON.stringify(circuitInput));
  const prover = `
import { readFileSync, writeFileSync } from 'node:fs';
import * as snarkjs from 'snarkjs';
const [inputPath, wasmPath, zkeyPath, verificationKeyPath, outputPath] =
  process.argv.slice(1);
try {
  const input = JSON.parse(readFileSync(inputPath, 'utf8'));
  const verificationKey = JSON.parse(
    readFileSync(verificationKeyPath, 'utf8'),
  );
  const generated = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath,
  );
  const verified = await snarkjs.groth16.verify(
    verificationKey,
    generated.publicSignals,
    generated.proof,
  );
  writeFileSync(outputPath, JSON.stringify({ generated, verified }));
  process.exit(verified ? 0 : 2);
} catch (error) {
  process.stderr.write(String(error?.stack ?? error));
  process.exit(1);
}
`;
  const result = spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '--eval',
      prover,
      inputPath,
      wasmPath,
      zkeyPath,
      verificationKeyPath,
      outputPath,
    ],
    {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      timeout: 120_000,
    },
  );
  assert.equal(
    result.status,
    0,
    `isolated Groth16 prover failed: ${
      result.stderr || result.stdout || result.error
    }`,
  );
  return JSON.parse(readFileSync(outputPath, 'utf8'));
};

const p2pkh = (publicKey) => concat(
  Uint8Array.of(0x76, 0xa9, 0x14),
  hash160(publicKey),
  Uint8Array.of(0x88, 0xac),
);

const stateToken = (category, commitment) => ({
  category,
  amount: 0n,
  nft: {
    capability: 'mutable',
    commitment: Uint8Array.from(commitment),
  },
});

const tokenPrefix = (token) => (
  token === undefined
    ? new Uint8Array()
    : Uint8Array.from(encodeTokenPrefix(token))
);

const decodeExactLibauthTransaction = (raw, label) => {
  const decoded = decodeTransaction(Uint8Array.from(raw));
  assert.notEqual(
    typeof decoded,
    'string',
    `${label} is not decodable by the installed Libauth`,
  );
  return decoded;
};

const diagnosticByteSummary = (bytes) => ({
  bytes: bytes.length,
  sha256: sha256(bytes).toString('hex'),
});

const diagnosticScalar = (value) => (
  typeof value === 'bigint' ? value.toString() : value
);

const isInput8VmRejection = (error) => (
  error instanceof Error
  && /rejected input 8:/u.test(error.message)
);

test('PF10 failure tracing cannot replace a transaction or non-input-8 VM rejection', () => {
  assert.equal(
    isInput8VmRejection(new Error(
      'installed BCH_2026_STANDARD Libauth rejected input 8: failed',
    )),
    true,
  );
  assert.equal(
    isInput8VmRejection(new Error(
      'installed BCH_2026_STANDARD Libauth rejected input 7: failed',
    )),
    false,
  );
  assert.equal(
    isInput8VmRejection(new Error(
      'installed BCH_2026_STANDARD Libauth rejected the exact resolved transaction',
    )),
    false,
  );
});

const diagnosticVmState = (state, traceIndex) => ({
  traceIndex,
  ip: diagnosticScalar(state.ip),
  error: state.error ?? null,
  instruction: state.instruction === undefined
    ? null
    : {
      opcode: state.instruction.opcode,
      ...(state.instruction.data === undefined
        ? {}
        : { data: diagnosticByteSummary(state.instruction.data) }),
    },
  stack: {
    depth: state.stack.length,
    top: state.stack
      .slice(-3)
      .reverse()
      .map(diagnosticByteSummary),
  },
  alternateStackDepth: state.alternateStack?.length ?? null,
  controlStackDepth: state.controlStack?.length ?? null,
  metrics: Object.fromEntries(
    Object.entries(state.metrics ?? {}).map(
      ([name, value]) => [name, diagnosticScalar(value)],
    ),
  ),
});

const writeInput8FailureTrace = ({
  actionKind,
  diagnosticRoot,
  request,
}) => {
  const transaction = decodeExactLibauthTransaction(
    hexToBin(request.rawTransactionHex),
    `${actionKind} diagnostic transaction`,
  );
  const sourceOutputs = request.inputs.map((input, index) => {
    const source = decodeExactLibauthTransaction(
      hexToBin(input.sourceTransactionHex),
      `${actionKind} diagnostic source transaction ${index}`,
    );
    const output = source.outputs[
      transaction.inputs[index].outpointIndex
    ];
    assert.notEqual(
      output,
      undefined,
      `${actionKind} diagnostic source output ${index} is missing`,
    );
    return output;
  });
  const program = {
    inputIndex: 8,
    sourceOutputs,
    transaction,
  };
  const vm = createVirtualMachineBch2026(true);
  const trace = vm.debug(program, { maskProgramState: true });
  const failedAt = trace.findIndex(
    (state) => state.error !== undefined,
  );
  assert.notEqual(
    failedAt,
    -1,
    `${actionKind} diagnostic replay did not preserve the VM failure`,
  );
  const phaseStarts = trace.flatMap((state, index) => {
    if (index === 0) return [index];
    const before =
      trace[index - 1].metrics?.evaluatedInstructionCount ?? 0;
    const after = state.metrics?.evaluatedInstructionCount ?? 0;
    return after < before ? [index] : [];
  });
  const phaseIndex = phaseStarts.findLastIndex(
    (start) => start <= failedAt,
  );
  const nearbyStart = Math.max(0, failedAt - 8);
  const unlockingBytecode =
    transaction.inputs[8].unlockingBytecode;
  const result = {
    schema: 'shieldkit-v2-direct/pf10-input8-debug/v1',
    actionKind,
    inputIndex: 8,
    phase:
      ['unlocking', 'locking', 'p2sh-redeem'][phaseIndex]
      ?? `phase-${phaseIndex}`,
    phaseStarts,
    traceLength: trace.length,
    failedAt,
    precedingState: diagnosticVmState(
      trace[Math.max(0, failedAt - 1)],
      Math.max(0, failedAt - 1),
    ),
    failureState: diagnosticVmState(trace[failedAt], failedAt),
    nearbyStates: trace
      .slice(nearbyStart, failedAt + 1)
      .map((state, offset) =>
        diagnosticVmState(state, nearbyStart + offset)),
    transaction: diagnosticByteSummary(
      hexToBin(request.rawTransactionHex),
    ),
    input8: {
      unlockingBytecode: diagnosticByteSummary(unlockingBytecode),
      sourceOutput: {
        valueSatoshis: sourceOutputs[8].valueSatoshis.toString(),
        lockingBytecode: diagnosticByteSummary(
          sourceOutputs[8].lockingBytecode,
        ),
      },
    },
  };
  writeFileSync(
    path.join(
      diagnosticRoot,
      `${actionKind}-input8-vm-debug.json`,
    ),
    `${JSON.stringify(result, null, 2)}\n`,
    {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    },
  );
};

const buildConstructedSourceTransaction = ({
  label,
  outputs,
}) => {
  const seed = sha256(Buffer.from(`shieldkit-v2-pf10:${label}`, 'utf8'));
  const raw = Uint8Array.from(encodeTransaction({
    version: 2,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(seed),
      outpointIndex: seed.readUInt32LE(0),
      sequenceNumber: 0,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs,
    locktime: seed.readUInt32LE(4),
  }));
  const parsed = parseV2RawTransaction(binToHex(raw));
  const decoded = decodeExactLibauthTransaction(raw, label);
  assert.equal(parsed.outputs.length, outputs.length);
  assert.equal(decoded.outputs.length, outputs.length);
  parsed.outputs.forEach((output, index) => {
    const authenticated = parseSerializedSourceOutput(output.serializedHex);
    const libauthOutput = decoded.outputs[index];
    assert.equal(
      authenticated.valueSatoshis,
      libauthOutput.valueSatoshis,
      `${label} output ${index} value changed while decoding`,
    );
    assert.deepEqual(
      authenticated.lockingBytecode,
      Buffer.from(libauthOutput.lockingBytecode),
      `${label} output ${index} lock changed while decoding`,
    );
    assert.equal(
      authenticated.tokenPrefixHex,
      binToHex(tokenPrefix(libauthOutput.token)),
      `${label} output ${index} token prefix changed while decoding`,
    );
  });
  return Object.freeze({
    raw,
    rawTransactionHex: binToHex(raw),
    rawTransactionSha256: sha256(raw).toString('hex'),
    transactionId: parsed.txid,
    parsed,
    decoded,
  });
};

const resolveAuthenticatedSourceOutputs = ({
  parsedTransaction,
  rollingParent,
  fundingParent,
}) => {
  const parents = new Map([
    [rollingParent.transactionId, {
      kind: 'previous-bundle',
      value: rollingParent,
    }],
    [fundingParent.transactionId, {
      kind: 'funding',
      value: fundingParent,
    }],
  ]);
  const inputSources = parsedTransaction.inputs.map((input) => {
    const parent = parents.get(input.outpoint.txid);
    assert.notEqual(
      parent,
      undefined,
      `input ${input.index} does not reference an authenticated parent`,
    );
    const serialized =
      parent.value.parsed.outputs[input.outpoint.vout]?.serializedHex;
    const output = parent.value.decoded.outputs[input.outpoint.vout];
    assert.notEqual(
      serialized,
      undefined,
      `input ${input.index} references a missing serialized parent output`,
    );
    assert.notEqual(
      output,
      undefined,
      `input ${input.index} references a missing Libauth parent output`,
    );
    const authenticated = parseSerializedSourceOutput(serialized);
    assert.equal(authenticated.valueSatoshis, output.valueSatoshis);
    assert.deepEqual(
      authenticated.lockingBytecode,
      Buffer.from(output.lockingBytecode),
    );
    assert.equal(
      authenticated.tokenPrefixHex,
      binToHex(tokenPrefix(output.token)),
    );
    return Object.freeze({
      inputIndex: input.index,
      parentKind: parent.kind,
      transactionId: parent.value.transactionId,
      outputIndex: input.outpoint.vout,
      serializedOutputSha256: authenticated.sha256,
      output,
    });
  });
  return Object.freeze({
    inputSources: Object.freeze(inputSources),
    sourceOutputs: Object.freeze(
      inputSources.map((source) => source.output),
    ),
  });
};

const bqLayout = (template) => template.roles.map((roleTemplate, inputIndex) => ({
  inputIndex,
  offset:
    encodedLength(roleTemplate.state.length)
    + encodedLength(roleTemplate.records.length)
    + encodedLength(roleTemplate.table.length)
    + pushHeaderLength(bqLengths[inputIndex]),
  length: bqLengths[inputIndex],
}));

const splitBq = (bigQ) => {
  let offset = 0;
  return bqLengths.map((length) => {
    const shard = Uint8Array.from(bigQ.slice(offset, offset + length));
    offset += length;
    return shard;
  });
};

const terminalUnlock = (template, redeem) => {
  const fixedBytes =
    encodedLength(template.terminal.state.length)
    + encodedLength(template.terminal.records.length)
    + encodedLength(template.terminal.table.length)
    + encodedLength(redeem.length);
  let paddingBytes = Math.max(1, 10_000 - fixedBytes - 3);
  while (fixedBytes + encodedLength(paddingBytes) > 10_000) {
    paddingBytes -= 1;
  }
  return buildDirectV2PairFoldTerminalUnlock({
    state: template.terminal.state,
    records: template.terminal.records,
    table: template.terminal.table,
    densityPad: new Uint8Array(paddingBytes),
    redeem,
  });
};

test(
  'PF10-FusedQGenesis exact 13-input actions are standard with VK-only fixed-line density carriers',
  { timeout: 600_000 },
  async () => {
    await assertLocalVerifierArtifactCoherence({
      artifactPaths: coherenceArtifactPaths,
    });
    const verificationKeyJson = JSON.parse(readFileSync(
      verificationKeyPath,
      'utf8',
    ));
    const verificationKey = parseDirectV2MillerVerificationKey(
      verificationKeyJson,
    );
    const seedPacket = readFileSync(referenceArtifacts.packet);
    const seedDecoded = decodeActionPacket(seedPacket, stateContext);
    const seedProof = JSON.parse(readFileSync(
      referenceArtifacts.proof,
      'utf8',
    ));
    const seedPublic = JSON.parse(readFileSync(
      referenceArtifacts.public,
      'utf8',
    )).map(BigInt);
    const seedMsm = computeDirectV2ExactMsm(
      verificationKeyJson,
      seedPublic[0],
      seedPublic[1],
    );
    const seedTrace = computeDirectV2IdentityAwareMiller({
      verificationKey,
      proof: seedProof,
      q: seedMsm.output,
    });
    const fixedTemplate = buildDirectV2TotalPairFoldWitness(
      seedTrace,
      { precomputedFixedLines: true },
    );
    const independentFixedTables =
      independentDeploymentFixedTables(verificationKey);
    assertDeploymentFixedTables(
      fixedTemplate,
      independentFixedTables,
      'reference withdrawal trace',
    );
    const fixedDigestMutationChecks = Object.freeze([
      ...independentFixedTables.roles,
      independentFixedTables.terminal,
    ].map((table, index) => {
      const mutated = Buffer.from(table);
      mutated[index % mutated.length] ^= 1;
      const honestHash256 = hash256Hex(table);
      const mutatedHash256 = hash256Hex(mutated);
      assert.notEqual(
        mutatedHash256,
        honestHash256,
        `fixed-table ${index} digest mutation was not detected`,
      );
      return Object.freeze({
        table: index < 5 ? `executor${index}` : 'terminal9',
        honestHash256,
        mutatedHash256,
      });
    }));
    const fixedRemoteBlob = concat(
      ...fixedTemplate.roles.map((roleTemplate) =>
        roleTemplate.remoteTable),
    );
    const exactPaddingPayloadOffset =
      encodedLength(128) + encodedLength(0) + pushHeaderLength(
        nonFinalExactPadding.length,
      );
    const fixedCarrierPads = Object.freeze(Array.from(
      { length: 3 },
      (_, index) => {
        const start = index * nonFinalExactPadding.length;
        const end = start + nonFinalExactPadding.length;
        return concat(
          fixedRemoteBlob.slice(start, end),
          new Uint8Array(
            Math.max(0, end - fixedRemoteBlob.length),
          ),
        );
      },
    ));
    const fixedTableCarriers = fixedTableCarrierLayout({
      template: fixedTemplate,
      carrierBytes: nonFinalExactPadding.length,
      firstInputIndex: 5,
      payloadOffset: exactPaddingPayloadOffset,
    });
    assert.equal(fixedRemoteBlob.length, 20_864);
    assert.equal(fixedTableCarriers.bytes, fixedRemoteBlob.length);
    assert.equal(exactPaddingPayloadOffset, 134);
    assert.deepEqual(
      fixedCarrierPads.map((pad) => pad.length),
      [7_500, 7_500, 7_500],
    );
    const profileId = seedDecoded.preState.profileId;
    const stateCategoryProtocolHex = seedDecoded.instanceId;
    const stateCategory = Uint8Array.from(
      Buffer.from(stateCategoryProtocolHex, 'hex').reverse(),
    );

    const bindingOptions = Object.freeze({
      networkId,
      profileId,
      stateCategory: stateCategoryProtocolHex,
      denominationSats,
      ...topologyOptions,
    });
    const bindingRedeem = buildDirectV2BindingRedeem(bindingOptions);
    const bindingLock = buildDirectV2BindingLock(bindingOptions);

    const seedProjection = encodeDirectV2MillerProjectionSignal(
      seedTrace,
      sha256(seedPacket),
    );
    const exactPrefixBytes = directV2Pf10ExactMsmArgumentPrefix({
      projectionSignal: seedProjection,
      msmState: encodeDirectV2MsmState(seedMsm.states[3]),
      zInverse: seedMsm.output.zInverse,
      exactMsmZeroPadding: exactPadding,
    }).length;
    const fusedStatePayloadOffset =
      encodedLength(480) + pushHeaderLength(128);
    const fusedResiduePayloadOffset =
      exactPrefixBytes
      + encodedLength(64)
      + encodedLength(384)
      + pushHeaderLength(1_152);
    assert.equal(exactPrefixBytes, 905);
    assert.equal(fusedStatePayloadOffset, 485);
    assert.equal(fusedResiduePayloadOffset, 1_360);

    const pairFoldRenderOptions = {
      verificationKey,
      stateCategoryHex: stateCategoryProtocolHex,
      libraryImportPath: 'Bn254LazyAff.cash',
    };
    const terminalSource = renderDirectV2TotalPairFoldTerminal({
      ...pairFoldRenderOptions,
      template: fixedTemplate,
      bqShards: bqLayout(fixedTemplate),
      terminalInputIndex: 9,
      stateInputIndex: 11,
      projectionInputIndex: 8,
      residueInputIndex: 8,
      residuePayloadOffset: fusedResiduePayloadOffset,
    });
    const terminalRaw = compile(terminalSource, {
      'Bn254LazyAff.cash': lazyAffineLibrary,
    });
    const terminalRedeem = optimize(
      terminalRaw,
      'pf10-withdrawal-terminal',
    );
    const terminalLock = encodeLockingBytecodeP2sh32(
      hash256(terminalRedeem),
    );

    const executorSource = renderDirectV2TotalPairFoldExecutor({
      ...pairFoldRenderOptions,
      template: fixedTemplate,
      terminalLockingBytecodeHex: binToHex(terminalLock),
      bqShardBytes: bqLengths,
      terminalInputIndex: 9,
      stateInputIndex: 11,
      projectionInputIndex: 8,
      fixedTableCarriers: fixedTableCarriers.layout,
    });
    const executorRaw = compile(executorSource, {
      'Bn254LazyAff.cash': lazyAffineLibrary,
    });
    const executorBody = optimize(
      executorRaw,
      'pf10-withdrawal-executor',
    );
    const fragments = splitDirectV2PairFoldBody(executorBody);
    const fragmentOffsets = fixedTemplate.roles.map((roleTemplate, index) =>
      encodedLength(roleTemplate.state.length)
      + encodedLength(roleTemplate.records.length)
      + encodedLength(roleTemplate.table.length)
      + encodedLength(bqLengths[index])
      + 3);
    const loader = buildDirectV2PairFoldLoader({
      body: executorBody,
      fragmentOffsets,
      fragmentLengths: fragments.map((fragment) => fragment.length),
      // PF10's index-specialized optimized body retains function ID 7.
      // Use a one-byte identifier outside the compiler-assigned range.
      functionId: 127,
      densityPadBytes: executorDensityPadBytes,
    });

    const exactFinalSource = renderDirectV2ExactMsmRole({
      verificationKey: verificationKeyJson,
      windowIndex: 3,
      inputIndex: 8,
      successorInputIndex: 9,
      successorLockingBytecodeHex: binToHex(terminalLock),
      successorStatePayloadOffset: 0,
      stateInputIndex: 11,
      stateCategoryHex: stateCategoryProtocolHex,
      expectedInputCount: 13,
      packetInputIndex: 10,
      packetLockingBytecodeHex: binToHex(bindingLock),
      fixedWidthZInverse: true,
      zeroPaddingBytes: exactPadding.length,
    });
    const exactFinalRaw = compile(exactFinalSource);
    const exactFinalRedeem = optimize(
      exactFinalRaw,
      'pf10-withdrawal-exact-final',
    );
    const millerSource =
      renderDirectV2Pf10FusedQGenesisMillerComponent({
        verificationKey,
        ownWitnessPayloadOffset: exactPrefixBytes,
        successorLockingBytecodeHex: binToHex(terminalLock),
        bindingLockingBytecodeHex: binToHex(bindingLock),
        stateCategoryHex: stateCategoryProtocolHex,
        zeroPaddingBytes: millerPadding.length,
        libraryImportPath: 'Bn254LazyAff.cash',
      });
    const millerRaw = compile(millerSource, {
      'Bn254LazyAff.cash': lazyAffineLibrary,
    });
    const millerRedeem = optimize(
      millerRaw,
      'pf10-withdrawal-miller',
    );
    const fusedRedeem = buildDirectV2Pf10FusedQGenesisRedeem({
      millerRedeem,
      exactMsmRedeem: exactFinalRedeem,
    });
    const fusedLock = encodeLockingBytecodeP2sh32(hash256(fusedRedeem));

    const exactPrograms = Array(3);
    let successorLock = fusedLock;
    for (let windowIndex = 2; windowIndex >= 0; windowIndex -= 1) {
      const inputIndex = windowIndex + 5;
      const source = renderDirectV2ExactMsmRole({
        verificationKey: verificationKeyJson,
        windowIndex,
        inputIndex,
        successorInputIndex: inputIndex + 1,
        successorLockingBytecodeHex: binToHex(successorLock),
        successorStatePayloadOffset:
          windowIndex === 2 ? fusedStatePayloadOffset : 2,
        stateInputIndex: 11,
        stateCategoryHex: stateCategoryProtocolHex,
        expectedInputCount: 13,
        packetInputIndex: 10,
        packetLockingBytecodeHex: binToHex(bindingLock),
        zeroPaddingBytes: nonFinalExactPadding.length,
        densityCarrierBytes: fixedCarrierPads[windowIndex],
      });
      const raw = compile(source);
      const redeem = optimize(
        raw,
        `pf10-withdrawal-exact-${windowIndex}`,
      );
      const lock = encodeLockingBytecodeP2sh32(hash256(redeem));
      exactPrograms[windowIndex] = Object.freeze({
        lock,
        raw,
        redeem,
        source,
      });
      successorLock = lock;
    }

    const verifierLocks = Object.freeze([
      ...Array(5).fill(loader.lock),
      ...exactPrograms.map((program) => program.lock),
      fusedLock,
      terminalLock,
    ]);
    assert.equal(verifierLocks.length, carrierCount);
    const verifierBaseValues = Object.freeze(verifierLocks.map(
      (lockingBytecode) => deriveV2RollingBaseSats({ lockingBytecode }),
    ));
    const bindingBaseValue = deriveV2RollingBaseSats({
      lockingBytecode: bindingLock,
    });
    let stateBaseValue = 1_000n;
    let helper;
    let stateLock;
    let stateBaseConverged = false;
    for (let iteration = 0; iteration < 8; iteration += 1) {
      helper = buildDirectV2StateHelper({
        bindingLock,
        verifierLocks,
        verifierBaseValues,
        bindingBaseValueSats: bindingBaseValue,
        stateBaseValueSats: stateBaseValue,
        denominationSats,
        stateCategory: stateCategoryProtocolHex,
        minimumChangeSats: minimumChange,
        ...topologyOptions,
      });
      stateLock = buildDirectV2StateTrampolineLock({
        helper,
        bindingLock,
        ...topologyOptions,
      });
      const derivedStateBaseValue = deriveV2RollingBaseSats({
        lockingBytecode: stateLock,
        token: stateToken(stateCategory, new Uint8Array(128)),
      });
      if (derivedStateBaseValue === stateBaseValue) {
        stateBaseConverged = true;
        break;
      }
      stateBaseValue = derivedStateBaseValue;
    }
    assert.equal(
      stateBaseConverged,
      true,
      'PF10 state base did not reach the exact dust-derived fixed point',
    );
    assert.deepEqual(
      {
        verifier: verifierBaseValues,
        binding: bindingBaseValue,
        state: stateBaseValue,
      },
      {
        verifier: Array(carrierCount).fill(1_200n),
        binding: 1_200n,
        state: 2_500n,
      },
      'PF10 rolling outputs changed their exact dust-derived bases',
    );
    const stateUnlock = buildDirectV2StateTrampolineUnlock(helper);
    const proofArtifactHashes = Object.freeze({
      provingKey: await sha256File(zkeyPath),
      r1cs: await sha256File(r1csPath),
      verificationKey: await sha256File(verificationKeyPath),
      wasm: await sha256File(wasmPath),
    });
    const profileCoreBytes = readFileSync(profileCorePath);
    const profileCore = JSON.parse(profileCoreBytes.toString('utf8'));
    assert.equal(
      deriveProfileId(profileCore),
      profileId,
      'profile core does not derive the proof packet profile ID',
    );
    const profileCoreSha256 = sha256(profileCoreBytes).toString('hex');
    const runtimeMaterialInput = {
      schema: DIRECT_V2_PF10_RUNTIME_SCHEMA,
      eligibility: 'development-only',
      profileId,
      instanceId: stateCategoryProtocolHex,
      topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
      proofArtifactHashes,
      verificationKeyBytes: readFileSync(verificationKeyPath),
      executorBody,
      exactMsmRedeems: exactPrograms.map((program) => program.redeem),
      fixedCarrierPads,
      fusedRedeem,
      terminalRedeem,
      stateUnlockingBytecode: stateUnlock,
      bindingRedeemBytecode: bindingRedeem,
      bindingLockingBytecode: bindingLock,
      verifierLockingBytecodes: verifierLocks,
    };
    const runtimeMaterial = validateDirectV2Pf10RuntimeMaterial(
      runtimeMaterialInput,
    );
    const extractedRuntime = await buildDirectV2Pf10DevelopmentRuntime({
      repositoryRoot: repoRoot,
      temporaryRoot: path.join(
        buildRoot,
        'v2-pf10-runtime-builder-test-tmp',
      ),
      profileId,
      instanceId: stateCategoryProtocolHex,
      proofArtifacts: {
        provingKey: {
          path: zkeyPath,
          sha256: proofArtifactHashes.provingKey,
        },
        r1cs: {
          path: r1csPath,
          sha256: proofArtifactHashes.r1cs,
        },
        verificationKey: {
          path: verificationKeyPath,
          sha256: proofArtifactHashes.verificationKey,
        },
        wasm: {
          path: wasmPath,
          sha256: proofArtifactHashes.wasm,
        },
      },
    });
    assert.equal(
      extractedRuntime.runtimeMaterial.materialSha256,
      runtimeMaterial.materialSha256,
      'identity-reference runtime extraction changed the material commitment',
    );
    assert.deepEqual(
      Buffer.from(extractedRuntime.runtimeMaterialInput.executorBody),
      Buffer.from(executorBody),
    );
    assert.deepEqual(
      extractedRuntime.runtimeMaterialInput.exactMsmRedeems.map(
        (value) => Buffer.from(value),
      ),
      exactPrograms.map((program) => Buffer.from(program.redeem)),
    );
    assert.deepEqual(
      extractedRuntime.runtimeMaterialInput.fixedCarrierPads.map(
        (value) => Buffer.from(value),
      ),
      fixedCarrierPads.map((value) => Buffer.from(value)),
    );
    assert.deepEqual(
      Buffer.from(extractedRuntime.runtimeMaterialInput.fusedRedeem),
      Buffer.from(fusedRedeem),
    );
    assert.deepEqual(
      Buffer.from(extractedRuntime.runtimeMaterialInput.terminalRedeem),
      Buffer.from(terminalRedeem),
    );
    assert.deepEqual(
      Buffer.from(
        extractedRuntime.runtimeMaterialInput.stateUnlockingBytecode,
      ),
      Buffer.from(stateUnlock),
    );
    assert.deepEqual(
      Buffer.from(
        extractedRuntime.runtimeMaterialInput.bindingRedeemBytecode,
      ),
      Buffer.from(bindingRedeem),
    );
    assert.deepEqual(
      Buffer.from(
        extractedRuntime.runtimeMaterialInput.bindingLockingBytecode,
      ),
      Buffer.from(bindingLock),
    );
    assert.deepEqual(
      extractedRuntime.runtimeMaterialInput.verifierLockingBytecodes.map(
        (value) => Buffer.from(value),
      ),
      verifierLocks.map((value) => Buffer.from(value)),
    );

    const fundingPrivateKey = new Uint8Array(32).fill(0x21);
    const fundingPublicKey =
      secp256k1.derivePublicKeyCompressed(fundingPrivateKey);
    assert.notEqual(typeof fundingPublicKey, 'string');
    const withdrawalPublicKey =
      secp256k1.derivePublicKeyCompressed(new Uint8Array(32).fill(0x31));
    const changePublicKey =
      secp256k1.derivePublicKeyCompressed(new Uint8Array(32).fill(0x41));
    assert.notEqual(typeof withdrawalPublicKey, 'string');
    assert.notEqual(typeof changePublicKey, 'string');
    const fundingLock = p2pkh(fundingPublicKey);
    const withdrawalLock = p2pkh(withdrawalPublicKey);
    const changeLock = p2pkh(changePublicKey);

    const actionResults = [];
    let identityFixture;
    for (const actionKind of actionKinds) {
      const artifacts = actionArtifacts[actionKind];
      const seedPacket = readFileSync(artifacts.packet);
      const seedDecoded = decodeActionPacket(seedPacket, stateContext);
      const seedInput = JSON.parse(readFileSync(artifacts.input, 'utf8'));
      const seedProof = JSON.parse(readFileSync(artifacts.proof, 'utf8'));
      const seedPublic = JSON.parse(readFileSync(
        artifacts.public,
        'utf8',
      )).map(BigInt);
      assert.equal(seedDecoded.kind, actionKind);
      assert.equal(seedDecoded.instanceId, stateCategoryProtocolHex);
      assert.equal(seedDecoded.preState.profileId, profileId);
      assert.equal(seedDecoded.postState.profileId, profileId);
      const seedMsm = computeDirectV2ExactMsm(
        verificationKeyJson,
        seedPublic[0],
        seedPublic[1],
      );
      const seedTrace = computeDirectV2IdentityAwareMiller({
        verificationKey,
        proof: seedProof,
        q: seedMsm.output,
      });
      assertDeploymentFixedTables(
        buildDirectV2TotalPairFoldWitness(
          seedTrace,
          { precomputedFixedLines: true },
        ),
        independentFixedTables,
        `${actionKind} qualification seed`,
      );

      const preCommitment = encodeStateNftCommitment(
        seedDecoded.preState,
        stateContext,
      );
      const rollingParent = buildConstructedSourceTransaction({
        label: `${actionKind}:previous-bundle`,
        outputs: [
          {
            lockingBytecode: stateLock,
            valueSatoshis:
              stateBaseValue + BigInt(seedDecoded.preState.reserveSats),
            token: stateToken(stateCategory, preCommitment),
          },
          ...verifierLocks.map((lockingBytecode, index) => ({
            lockingBytecode,
            valueSatoshis: verifierBaseValues[index],
          })),
          {
            lockingBytecode: bindingLock,
            valueSatoshis: bindingBaseValue,
          },
        ],
      });
      const fundingParent = buildConstructedSourceTransaction({
        label: `${actionKind}:funding`,
        outputs: [{
          lockingBytecode: fundingLock,
          valueSatoshis:
            baseFundingValue
            + (actionKind === 'deposit' ? denominationSats : 0n),
        }],
      });
      const pins = {
        topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
        verifierRoles: [...DIRECT_V2_PF10_FUSED_VERIFIER_ROLES],
        bindingBaseSats: bindingBaseValue.toString(),
        bindingLockingBytecode: Buffer.from(bindingLock),
        bindingRedeemBytecode: Buffer.from(bindingRedeem),
        stateBaseSats: stateBaseValue.toString(),
        stateLockingBytecode: Buffer.from(stateLock),
        verifierCarriers: verifierLocks.map((lockingBytecode, index) => ({
          baseValueSats: verifierBaseValues[index].toString(),
          lockingBytecode: Buffer.from(lockingBytecode),
        })),
      };
      const prepared = prepareV2DirectSettlement({
        changeLockingBytecode: Buffer.from(changeLock),
        denominationSats: denominationSats.toString(),
        funding: {
          outpointIndex: '0',
          publicKey: Buffer.from(fundingPublicKey),
          sourceTransactionHex: fundingParent.rawTransactionHex,
        },
        instanceId: stateCategoryProtocolHex,
        kind: actionKind,
        networkId,
        payoutLockingBytecode:
          actionKind === 'withdrawal'
            ? Buffer.from(withdrawalLock)
            : null,
        pins,
        postState: seedDecoded.postState,
        preState: seedDecoded.preState,
        previousBundleTransactionHex: rollingParent.rawTransactionHex,
        profileId,
        unlockingBytecodeLengths: {
          verifier: [...DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES],
          state: DIRECT_V2_PF10_STATE_UNLOCK_BYTES,
        },
      });
      assert.equal(prepared.topology.id, DIRECT_V2_PF10_FUSED_TOPOLOGY_ID);
      assert.equal(prepared.topology.inputCount, 13);
      assert.equal(
        prepared.topology.outputCount,
        actionKind === 'withdrawal' ? 14 : 13,
      );
      assert.equal(
        prepared.measurements.feeSats,
        prepared.measurements.signedSizeBytes.toString(),
        `${actionKind} production preparation did not use exactly 1 sat/byte`,
      );
      assert.equal(
        BigInt(prepared.measurements.changeSats),
        baseFundingValue - BigInt(prepared.measurements.feeSats),
      );
      assert.equal(
        prepared.measurements.signedSizeBytes <= 100_000,
        true,
      );
      const contextHash = Buffer.from(prepared.contextHash, 'hex');
      assert.equal(contextHash.length, 32);
      const packet = encodeActionPacket({
        ...seedDecoded,
        withdrawalLockingBytecodeHash: actionKind === 'withdrawal'
          ? sha256(withdrawalLock).toString('hex')
          : '00'.repeat(32),
        transactionContextHash: contextHash.toString('hex'),
      }, stateContext);
      const publicInputs = actionPacketPublicLimbs(packet, stateContext);
      const circuitInput = {
        ...seedInput,
        packet: [...packet],
        publicInput0: publicInputs[0],
        publicInput1: publicInputs[1],
      };

      const proofStarted = performance.now();
      const proofResult = proveInIsolatedProcess(circuitInput);
      const generated = proofResult.generated;
      const proofGenerationMs = performance.now() - proofStarted;
      assert.deepEqual(generated.publicSignals, publicInputs);
      assert.equal(proofResult.verified, true);

      const msm = computeDirectV2ExactMsm(
        verificationKeyJson,
        BigInt(publicInputs[0]),
        BigInt(publicInputs[1]),
      );
      const trace = computeDirectV2IdentityAwareMiller({
        verificationKey,
        proof: generated.proof,
        q: msm.output,
      });
      const template = buildDirectV2TotalPairFoldWitness(trace);
      const precomputedTemplate = buildDirectV2TotalPairFoldWitness(
        trace,
        { precomputedFixedLines: true },
      );
      assertDeploymentFixedTables(
        precomputedTemplate,
        independentFixedTables,
        `${actionKind} fresh proof`,
      );
      assert.deepEqual(
        concat(
          ...precomputedTemplate.roles.map((roleTemplate) =>
            roleTemplate.remoteTable),
        ),
        fixedRemoteBlob,
        'proof-dependent witness changed the fixed-line carrier bytes',
      );
      assert.equal(
        renderDirectV2TotalPairFoldTerminal({
          ...pairFoldRenderOptions,
          template,
          bqShards: bqLayout(template),
          terminalInputIndex: 9,
          stateInputIndex: 11,
          projectionInputIndex: 8,
          residueInputIndex: 8,
          residuePayloadOffset: fusedResiduePayloadOffset,
        }),
        terminalSource,
        'proof-dependent terminal witness changed the fixed verifier program',
      );
      assert.equal(
        renderDirectV2TotalPairFoldExecutor({
          ...pairFoldRenderOptions,
          template: precomputedTemplate,
          terminalLockingBytecodeHex: binToHex(terminalLock),
          bqShardBytes: bqLengths,
          terminalInputIndex: 9,
          stateInputIndex: 11,
          projectionInputIndex: 8,
          fixedTableCarriers: fixedTableCarriers.layout,
        }),
        executorSource,
        'proof-dependent executor witness changed the fixed verifier program',
      );

      const packetDigest = sha256(packet);
      const projection = encodeDirectV2MillerProjectionSignal(
        trace,
        packetDigest,
      );
      const bq = splitBq(template.terminal.bigQ);
      const referenceVerifierUnlocks = Array(carrierCount);
      for (let index = 0; index < 5; index += 1) {
        referenceVerifierUnlocks[index] =
          buildDirectV2PairFoldUnlock({
            state: precomputedTemplate.roles[index].state,
            records: precomputedTemplate.roles[index].records,
            table: precomputedTemplate.roles[index].table,
            bqShard: bq[index],
            bodyFragment: fragments[index],
            densityPad: loader.densityPad,
            loader: loader.loader,
        });
      }
      for (let windowIndex = 0; windowIndex < 3; windowIndex += 1) {
        referenceVerifierUnlocks[windowIndex + 5] = concat(
          push(encodeDirectV2MsmState(msm.states[windowIndex])),
          push(new Uint8Array()),
          push(fixedCarrierPads[windowIndex]),
          push(exactPrograms[windowIndex].redeem),
        );
      }
      const millerWitness = encodeDirectV2MillerGenesisWitness(trace);
      referenceVerifierUnlocks[8] =
        buildDirectV2Pf10FusedQGenesisUnlock({
          projectionSignal: projection,
          msmState: encodeDirectV2MsmState(msm.states[3]),
          zInverse: msm.output.zInverse,
          exactMsmZeroPadding: exactPadding,
          slope: millerWitness.slope,
          endpoint: millerWitness.endpoint,
          residue: millerWitness.residue,
          millerZeroPadding: millerPadding,
          redeem: fusedRedeem,
        });
      referenceVerifierUnlocks[9] = terminalUnlock(
        template,
        terminalRedeem,
      );
      const referenceBindingUnlock = buildDirectV2BindingUnlock({
        packet,
        redeem: bindingRedeem,
      });
      assert.deepEqual(
        referenceVerifierUnlocks.map((value) => value.length),
        [...DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES],
        'reference PF10 verifier unlocks differ from the frozen topology lengths',
      );
      const productionWitness = buildDirectV2Pf10ActionWitness({
        actionPacket: packet,
        denominationSats: denominationSats.toString(),
        proofResult: {
          schema: V2_GROTH16_PROOF_RESULT_SCHEMA,
          claims: {
            proofVerified: true,
            singleThread: true,
            witnessValid: true,
          },
          sourceHashes: proofArtifactHashes,
          proof: generated.proof,
          publicInputs: generated.publicSignals,
          resultSha256: sha256(Buffer.from(
            JSON.stringify(generated),
          )).toString('hex'),
        },
        runtimeMaterial,
      });
      assert.deepEqual(
        productionWitness.publicInputs,
        publicInputs,
      );
      assert.equal(
        productionWitness.materialSha256,
        runtimeMaterial.materialSha256,
      );
      if (actionKind === 'withdrawal') {
        const proofResultForAdapter = Object.freeze({
          schema: V2_GROTH16_PROOF_RESULT_SCHEMA,
          claims: Object.freeze({
            proofVerified: true,
            singleThread: true,
            witnessValid: true,
          }),
          sourceHashes: proofArtifactHashes,
          proof: generated.proof,
          publicInputs: Object.freeze([...generated.publicSignals]),
          resultSha256: sha256(Buffer.from(
            JSON.stringify(generated),
          )).toString('hex'),
        });
        const buildAdapterWitness = ({
          actionPacket = packet,
          proofResult = proofResultForAdapter,
          material = runtimeMaterial,
        } = {}) => buildDirectV2Pf10ActionWitness({
          actionPacket,
          denominationSats: denominationSats.toString(),
          proofResult,
          runtimeMaterial: material,
        });
        const cloneRuntimeInput = () => ({
          ...runtimeMaterialInput,
          proofArtifactHashes: { ...runtimeMaterialInput.proofArtifactHashes },
          verificationKeyBytes: Uint8Array.from(
            runtimeMaterialInput.verificationKeyBytes,
          ),
          executorBody: Uint8Array.from(runtimeMaterialInput.executorBody),
          exactMsmRedeems: runtimeMaterialInput.exactMsmRedeems.map(
            (value) => Uint8Array.from(value),
          ),
          fixedCarrierPads: runtimeMaterialInput.fixedCarrierPads.map(
            (value) => Uint8Array.from(value),
          ),
          fusedRedeem: Uint8Array.from(runtimeMaterialInput.fusedRedeem),
          terminalRedeem: Uint8Array.from(runtimeMaterialInput.terminalRedeem),
          stateUnlockingBytecode: Uint8Array.from(
            runtimeMaterialInput.stateUnlockingBytecode,
          ),
          bindingRedeemBytecode: Uint8Array.from(
            runtimeMaterialInput.bindingRedeemBytecode,
          ),
          bindingLockingBytecode: Uint8Array.from(
            runtimeMaterialInput.bindingLockingBytecode,
          ),
          verifierLockingBytecodes:
            runtimeMaterialInput.verifierLockingBytecodes.map(
              (value) => Uint8Array.from(value),
            ),
        });
        const expects = (code) => (error) =>
          error instanceof DirectV2Pf10ActionWitnessError && error.code === code;

        assert.throws(
          () => buildAdapterWitness({
            material: Object.freeze({ ...runtimeMaterial }),
          }),
          expects('PF10_RUNTIME_UNVALIDATED'),
        );
        const proofHashDrift = {
          ...proofResultForAdapter,
          sourceHashes: {
            ...proofArtifactHashes,
            wasm: '00'.repeat(32),
          },
        };
        assert.throws(
          () => buildAdapterWitness({ proofResult: proofHashDrift }),
          expects('PF10_PROOF_RESULT_INVALID'),
        );
        const publicInputDrift = [...generated.publicSignals];
        publicInputDrift[0] = publicInputDrift[0] === '0' ? '1' : '0';
        assert.throws(
          () => buildAdapterWitness({
            proofResult: {
              ...proofResultForAdapter,
              publicInputs: publicInputDrift,
            },
          }),
          expects('PF10_PUBLIC_INPUT_MISMATCH'),
        );
        assert.throws(
          () => buildAdapterWitness({
            actionPacket: Uint8Array.from(packet.subarray(0, -1)),
          }),
          expects('PF10_PACKET_INVALID'),
        );
        const tamperedPacket = Uint8Array.from(packet);
        tamperedPacket[ACTION_PACKET_OFFSETS.instanceId] ^= 1;
        assert.throws(
          () => buildAdapterWitness({ actionPacket: tamperedPacket }),
          expects('PF10_PACKET_IDENTITY_MISMATCH'),
        );
        const bindingLockDrift = cloneRuntimeInput();
        bindingLockDrift.bindingLockingBytecode[0] ^= 1;
        assert.throws(
          () => validateDirectV2Pf10RuntimeMaterial(bindingLockDrift),
          expects('PF10_BINDING_MISMATCH'),
        );
        const carrierDrift = cloneRuntimeInput();
        carrierDrift.fixedCarrierPads[0][0] ^= 1;
        assert.throws(
          () => buildAdapterWitness({
            material: validateDirectV2Pf10RuntimeMaterial(carrierDrift),
          }),
          expects('PF10_FIXED_TABLE_MISMATCH'),
        );
        const programDrift = cloneRuntimeInput();
        programDrift.verifierLockingBytecodes[0][0] ^= 1;
        assert.throws(
          () => buildAdapterWitness({
            material: validateDirectV2Pf10RuntimeMaterial(programDrift),
          }),
          expects('PF10_PROGRAM_LOCK_MISMATCH'),
        );
      }
      for (let index = 0; index < carrierCount; index += 1) {
        assert.deepEqual(
          Buffer.from(
            productionWitness.verifierUnlockingBytecodes[index],
          ),
          Buffer.from(referenceVerifierUnlocks[index]),
          `production PF10 witness differs at verifier input ${index}`,
        );
      }
      assert.deepEqual(
        Buffer.from(productionWitness.bindingUnlockingBytecode),
        Buffer.from(referenceBindingUnlock),
      );
      assert.deepEqual(
        Buffer.from(productionWitness.stateUnlockingBytecode),
        Buffer.from(stateUnlock),
      );

      const assembled = assembleV2DirectSettlement(prepared, {
        actionPacket: packet,
        stateUnlockingBytecode:
          productionWitness.stateUnlockingBytecode,
        verifierUnlockingBytecodes:
          productionWitness.verifierUnlockingBytecodes,
      });
      assert.equal(assembled.contextHash, prepared.contextHash);
      assert.equal(
        assembled.measurements.signedSizeBytes,
        prepared.measurements.signedSizeBytes,
      );
      const signed = await signV2DirectSettlement(assembled, {
        signFunding: (request) => {
          assert.equal(request.algorithm, 'BCH_SCHNORR_SECP256K1');
          assert.equal(request.contextHash, prepared.contextHash);
          assert.equal(request.fundingInputIndex, 12);
          assert.equal(request.publicKeyHex, binToHex(fundingPublicKey));
          assert.equal(request.sighashContract, 'SIGHASH_ALL|UTXOS|FORKID');
          assert.equal(request.sighashType, 0x61);
          const signature = secp256k1.signMessageHashSchnorr(
            fundingPrivateKey,
            Buffer.from(request.digestHex, 'hex'),
          );
          assert.notEqual(typeof signature, 'string');
          return signature;
        },
        createLocalVmEvidence: (request) => {
          const diagnosticRoot =
            process.env.SHIELDKIT_PF10_DIAGNOSTIC_REQUEST_ROOT;
          if (diagnosticRoot !== undefined) {
            assert.equal(
              path.isAbsolute(diagnosticRoot),
              true,
              'SHIELDKIT_PF10_DIAGNOSTIC_REQUEST_ROOT must be absolute',
            );
            writeFileSync(
              path.join(
                diagnosticRoot,
                `${actionKind}-proof-case.json`,
              ),
              `${JSON.stringify({
                schema:
                  'shieldkit-v2-direct/pf10-proof-case-debug/v1',
                actionKind,
                identity: {
                  profileId,
                  instanceId: stateCategoryProtocolHex,
                  runtimeMaterialSha256:
                    runtimeMaterial.materialSha256,
                  proofArtifactHashes,
                },
                packet: diagnosticByteSummary(packet),
                proof: generated.proof,
                proofSha256: sha256(Buffer.from(
                  JSON.stringify(generated.proof),
                )).toString('hex'),
                publicInputs: generated.publicSignals,
                input8: {
                  projectionSignal:
                    diagnosticByteSummary(projection),
                  msmState: diagnosticByteSummary(
                    encodeDirectV2MsmState(msm.states[3]),
                  ),
                  zInverseLe32: diagnosticByteSummary(
                    fieldLe32(msm.output.zInverse),
                  ),
                  slope: diagnosticByteSummary(
                    millerWitness.slope,
                  ),
                  endpoint: diagnosticByteSummary(
                    millerWitness.endpoint,
                  ),
                  residue: diagnosticByteSummary(
                    millerWitness.residue,
                  ),
                  unlockingBytecode: diagnosticByteSummary(
                    productionWitness
                      .verifierUnlockingBytecodes[8],
                  ),
                  redeemBytecode:
                    diagnosticByteSummary(fusedRedeem),
                },
              }, null, 2)}\n`,
              {
                encoding: 'utf8',
                flag: 'wx',
                mode: 0o600,
              },
            );
            writeFileSync(
              path.join(diagnosticRoot, `${actionKind}.json`),
              `${JSON.stringify(request, null, 2)}\n`,
              {
                encoding: 'utf8',
                flag: 'wx',
                mode: 0o600,
              },
            );
          }
          try {
            return createV2LocalVmEvidence({
              ...request,
              tool: {
                name: '@bitauth/libauth',
                version: libauthVersion,
                vm: 'BCH_2026_STANDARD',
                profileId,
                profileSha256: profileCoreSha256,
              },
            });
          } catch (error) {
            if (
              diagnosticRoot !== undefined
              && isInput8VmRejection(error)
            ) {
              try {
                writeInput8FailureTrace({
                  actionKind,
                  diagnosticRoot,
                  request,
                });
              } catch (diagnosticError) {
                throw new AggregateError(
                  [error, diagnosticError],
                  `${actionKind} VM rejection and diagnostic capture both failed`,
                );
              }
            }
            throw error;
          }
        },
      });
      const rawTransaction = hexToBin(signed.rawTransactionHex);
      const parsed = parseV2RawTransaction(signed.rawTransactionHex);
      assertV2StandardTransactionEnvelope(parsed, { carrierCount });
      assert.equal(parsed.txid, signed.txid);
      assert.equal(parsed.sizeBytes, prepared.measurements.signedSizeBytes);
      assert.equal(
        parsed.inputs.every((input) => input.sequence === 0),
        true,
        `${actionKind} production transaction contains a nonzero sequence`,
      );
      const transaction = decodeExactLibauthTransaction(
        rawTransaction,
        `${actionKind} signed production settlement`,
      );
      const {
        inputSources,
        sourceOutputs,
      } = resolveAuthenticatedSourceOutputs({
        parsedTransaction: parsed,
        rollingParent,
        fundingParent,
      });
      const localVmEvidence = inspectV2LocalVmEvidence(
        Buffer.from(signed.localVmEvidenceHex, 'hex'),
      );
      assert.equal(localVmEvidence.transaction.txid, signed.txid);
      assert.equal(localVmEvidence.transaction.rawTransactionHex,
        signed.rawTransactionHex);
      assert.equal(localVmEvidence.inputs.length, 13);
      localVmEvidence.inputs.forEach((input, index) => {
        assert.equal(input.outpoint.txid,
          inputSources[index].transactionId);
        assert.equal(input.outpoint.vout,
          inputSources[index].outputIndex);
        assert.equal(
          input.sourceOutput.sha256,
          inputSources[index].serializedOutputSha256,
        );
      });

      const rows = DIRECT_V2_PF10_FUSED_VERIFIER_ROLES
        .map((name, index) => ({ name, index }))
        .concat([
          { name: 'binding10', index: 10 },
          { name: 'state11', index: 11 },
          { name: 'funding12', index: 12 },
        ])
        .map(({ name, index }) => {
          const program = {
            inputIndex: index,
            sourceOutputs,
            transaction,
          };
          const hard = createVirtualMachineBch2026(true).evaluate(program);
          const semantic = createLoosenedVm().evaluate(program);
          const unlockBytes =
            transaction.inputs[index].unlockingBytecode.length;
          const densityControlLength =
            ConsensusBch2025.densityControlBaseLength + unlockBytes;
          const maximumOperationCost = realOpCostBudget(unlockBytes);
          const maximumLegalOperationCost = realOpCostBudget(10_000);
          const maximumHashDigestIterations = Math.floor(
            densityControlLength
            * ConsensusBch2025.hashDigestIterationsPerByteStandard,
          );
          const maximumSignatureChecks =
            maximumSignatureCheckCount(unlockBytes);
          assert.equal(unlockBytes <= 10_000, true);
          assert.equal(
            semantic.metrics.hashDigestIterations
              <= maximumHashDigestIterations,
            true,
            `${name} hash digest iterations exceed standard policy`,
          );
          assert.equal(
            semantic.metrics.signatureCheckCount
              <= maximumSignatureChecks,
            true,
            `${name} signature checks exceed standard policy`,
          );
          assert.equal(
            accepts(semantic),
            true,
            `${name} is semantically invalid: ${semantic.error}`,
          );
          assert.equal(
            accepts(hard),
            true,
            `${name} rejected under standard BCH-2026: ${hard.error}`,
          );
          assert.equal(
            semantic.metrics.operationCost <= maximumOperationCost,
            true,
          );
          return {
            name,
            index,
            unlockBytes,
            hardAccepted: accepts(hard),
            hardError: hard.error,
            semanticAccepted: accepts(semantic),
            operationCost: semantic.metrics.operationCost,
            maximumOperationCost,
            maximumLegalOperationCost,
            operationPercent: Number(
              (
                semantic.metrics.operationCost
                * 10_000
                / maximumOperationCost
              ).toFixed(0),
            ) / 100,
            hashDigestIterations:
              semantic.metrics.hashDigestIterations,
            maximumHashDigestIterations,
            signatureCheckCount:
              semantic.metrics.signatureCheckCount,
            maximumSignatureChecks,
            evaluatedInstructionCount:
              semantic.metrics.evaluatedInstructionCount,
            arithmeticCost: semantic.metrics.arithmeticCost,
            stackPushedBytes: semantic.metrics.stackPushedBytes,
            definedFunctions: semantic.metrics.definedFunctions,
          };
        });

      const cloneTransaction = () => ({
        ...transaction,
        inputs: transaction.inputs.map((input) => ({
          ...input,
          unlockingBytecode: Uint8Array.from(input.unlockingBytecode),
        })),
      });
      const mutationChecks = [];
      for (let executorIndex = 0; executorIndex < 5; executorIndex += 1) {
        const mutatedTransaction = cloneTransaction();
        const roleTemplate = precomputedTemplate.roles[executorIndex];
        const localTablePayloadOffset =
          encodedLength(roleTemplate.state.length)
          + encodedLength(roleTemplate.records.length)
          + pushHeaderLength(roleTemplate.table.length);
        mutatedTransaction.inputs[executorIndex]
          .unlockingBytecode[localTablePayloadOffset] ^= 1;
        const mutated = createLoosenedVm().evaluate({
          inputIndex: executorIndex,
          sourceOutputs,
          transaction: mutatedTransaction,
        });
        assert.equal(
          accepts(mutated),
          false,
          `${actionKind} executor ${executorIndex} accepted a local-table mutation`,
        );
        mutationChecks.push(Object.freeze({
          kind: 'local-table',
          mutatedInput: executorIndex,
          rejectingInputs: Object.freeze([executorIndex]),
        }));
      }
      {
        const mutatedTransaction = cloneTransaction();
        const terminalTablePayloadOffset =
          encodedLength(template.terminal.state.length)
          + encodedLength(template.terminal.records.length)
          + pushHeaderLength(template.terminal.table.length);
        mutatedTransaction.inputs[9]
          .unlockingBytecode[terminalTablePayloadOffset] ^= 1;
        const mutated = createLoosenedVm().evaluate({
          inputIndex: 9,
          sourceOutputs,
          transaction: mutatedTransaction,
        });
        assert.equal(
          accepts(mutated),
          false,
          `${actionKind} terminal accepted a local-table mutation`,
        );
        mutationChecks.push(Object.freeze({
          kind: 'local-table',
          mutatedInput: 9,
          rejectingInputs: Object.freeze([9]),
        }));
      }
      for (let carrierInput = 5; carrierInput <= 7; carrierInput += 1) {
        const target = fixedTableCarriers.layout.flatMap(
          (slices, executorIndex) => slices.map((slice) => ({
            executorIndex,
            slice,
          })),
        ).find(({ slice }) => slice.inputIndex === carrierInput);
        assert.notEqual(target, undefined);
        const mutatedTransaction = cloneTransaction();
        mutatedTransaction.inputs[carrierInput]
          .unlockingBytecode[target.slice.payloadOffset] ^= 1;
        const rejectingInputs = [target.executorIndex, carrierInput];
        for (const index of rejectingInputs) {
          const mutated = createLoosenedVm().evaluate({
            inputIndex: index,
            sourceOutputs,
            transaction: mutatedTransaction,
          });
          assert.equal(
            accepts(mutated),
            false,
            `${actionKind} carrier ${carrierInput} mutation was accepted by input ${index}`,
          );
        }
        mutationChecks.push(Object.freeze({
          kind: 'remote-carrier',
          mutatedInput: carrierInput,
          rejectingInputs: Object.freeze(rejectingInputs),
        }));
      }

      const sourceValue = sourceOutputs.reduce(
        (sum, output) => sum + output.valueSatoshis,
        0n,
      );
      const outputValue = transaction.outputs.reduce(
        (sum, output) => sum + output.valueSatoshis,
        0n,
      );
      const feeSats = sourceValue - outputValue;
      assert.equal(feeSats, BigInt(rawTransaction.length));
      assert.equal(feeSats.toString(), signed.measurements.feeSats);
      actionResults.push(Object.freeze({
        kind: actionKind,
        inputCount: transaction.inputs.length,
        outputCount: transaction.outputs.length,
        transactionBytes: rawTransaction.length,
        transactionLimitBytes: 100_000,
        transactionHeadroomBytes: 100_000 - rawTransaction.length,
        feeRateSatsPerByte: '1',
        feeSats: feeSats.toString(),
        proofGenerationMs: Math.round(proofGenerationMs),
        proofVerified: true,
        rawTransactionHex: signed.rawTransactionHex,
        rawTransactionSha256: sha256(rawTransaction).toString('hex'),
        transactionId: signed.txid,
        construction: Object.freeze({
          path: Object.freeze([
            'prepareV2DirectSettlement',
            'assembleV2DirectSettlement',
            'signV2DirectSettlement',
          ]),
          preparedPayloadHash: prepared.payloadHash,
          assemblyHash: assembled.assemblyHash,
          localVmEvidenceHash: signed.evidenceHash,
          inputSequence: 0,
        }),
        sourceParents: Object.freeze({
          previousBundle: Object.freeze({
            rawTransactionHex: rollingParent.rawTransactionHex,
            rawTransactionSha256:
              rollingParent.rawTransactionSha256,
            transactionId: rollingParent.transactionId,
          }),
          funding: Object.freeze({
            rawTransactionHex: fundingParent.rawTransactionHex,
            rawTransactionSha256:
              fundingParent.rawTransactionSha256,
            transactionId: fundingParent.transactionId,
          }),
        }),
        inputSources: Object.freeze(inputSources.map((source) =>
          Object.freeze({
            inputIndex: source.inputIndex,
            parentKind: source.parentKind,
            transactionId: source.transactionId,
            outputIndex: source.outputIndex,
            serializedOutputSha256:
              source.serializedOutputSha256,
          }))),
        sourceOutputs: Object.freeze(sourceOutputs.map((output) =>
          Object.freeze({
            valueSats: output.valueSatoshis.toString(),
            lockingBytecodeHex: binToHex(output.lockingBytecode),
            tokenPrefixHex: binToHex(tokenPrefix(output.token)),
          }))),
        localVmEvidence: Object.freeze({
          hex: signed.localVmEvidenceHex,
          sha256: sha256(Buffer.from(
            signed.localVmEvidenceHex,
            'hex',
          )).toString('hex'),
          evidenceHash: signed.evidenceHash,
        }),
        packetSha256: packetDigest.toString('hex'),
        contextHash: contextHash.toString('hex'),
        rows: Object.freeze(rows),
        mutationChecks: Object.freeze(mutationChecks),
      }));
      if (actionKind === 'withdrawal') {
        identityFixture = Object.freeze({
          precomputedTemplate,
          transaction,
          packetDigest,
          sourceOutputs,
        });
      }
    }

    assert.notEqual(identityFixture, undefined);
    const {
      precomputedTemplate,
      transaction,
      packetDigest,
      sourceOutputs,
    } = identityFixture;

    const identityTrace = computeDirectV2IdentityAwareMiller({
      verificationKey,
      proof: createDirectV2IdentityReferenceProof(verificationKey),
      q: null,
    });
    const identityTemplate = buildDirectV2TotalPairFoldWitness(
      identityTrace,
      { precomputedFixedLines: true },
    );
    assertDeploymentFixedTables(
      identityTemplate,
      independentFixedTables,
      'identity proof branch',
    );
    assert.deepEqual(
      identityTemplate.roles.map((roleTemplate) =>
        roleTemplate.tableHash256),
      precomputedTemplate.roles.map((roleTemplate) =>
        roleTemplate.tableHash256),
      'identity branch changed the deployment-fixed line tables',
    );
    assert.equal(
      renderDirectV2TotalPairFoldExecutor({
        ...pairFoldRenderOptions,
        template: identityTemplate,
        terminalLockingBytecodeHex: binToHex(terminalLock),
        bqShardBytes: bqLengths,
        terminalInputIndex: 9,
        stateInputIndex: 11,
        projectionInputIndex: 8,
        fixedTableCarriers: fixedTableCarriers.layout,
      }),
      executorSource,
      'identity branch changed the fixed executor program',
    );
    const identityTransaction = {
      ...transaction,
      inputs: transaction.inputs.map((input) => ({
        ...input,
        unlockingBytecode: Uint8Array.from(input.unlockingBytecode),
      })),
    };
    const identityBq = splitBq(identityTemplate.terminal.bigQ);
    for (let index = 0; index < 5; index += 1) {
      identityTransaction.inputs[index].unlockingBytecode =
        buildDirectV2PairFoldUnlock({
          state: identityTemplate.roles[index].state,
          records: identityTemplate.roles[index].records,
          table: identityTemplate.roles[index].table,
          bqShard: identityBq[index],
          bodyFragment: fragments[index],
          densityPad: loader.densityPad,
          loader: loader.loader,
        });
    }
    identityTransaction.inputs[8].unlockingBytecode.set(
      encodeDirectV2MillerProjectionSignal(
        identityTrace,
        packetDigest,
      ),
      3,
    );
    identityTransaction.inputs[9].unlockingBytecode =
      terminalUnlock(identityTemplate, terminalRedeem);
    const identityExecutorRows = Array.from({ length: 5 }, (_, index) => {
      const evaluated = createVirtualMachineBch2026(true).evaluate({
        inputIndex: index,
        sourceOutputs,
        transaction: identityTransaction,
      });
      assert.equal(
        accepts(evaluated),
        true,
        `identity executor ${index} rejected: ${evaluated.error}`,
      );
      return Object.freeze({
        index,
        unlockBytes:
          identityTransaction.inputs[index].unlockingBytecode.length,
        operationCost: evaluated.metrics.operationCost,
      });
    });

    const exactRawBytes = exactPrograms.map((program) => program.raw.length);
    const exactRedeemBytes = exactPrograms.map(
      (program) => program.redeem.length,
    );
    const qualificationEvidence = Object.freeze({
      schema: 'shieldkit-v2-direct-pf10-local-libauth-evidence-v2',
      eligibility: 'development-only',
      generatedAt: new Date().toISOString(),
      claims: Object.freeze({
        finalKey: false,
        production: false,
        releaseQualified: false,
        libauthBch2026: true,
        bchnMempool: false,
        bchnMined: false,
        leanBch: false,
        unmodifiedMaintainerBenchmark: false,
        productionSettlementBuilderPath: true,
        authenticatedSerializedParentOutputs: true,
        liveChainParentProvenance: false,
      }),
      qualificationScope: Object.freeze({
        parentTransactions:
          'deterministically constructed local serialized transactions; every child outpoint and source output is authenticated from exact parent bytes; no live-chain provenance is claimed',
        settlementPath:
          'prepareV2DirectSettlement -> assembleV2DirectSettlement -> signV2DirectSettlement -> createV2LocalVmEvidence',
        feePolicy: 'exact signed bytes at 1 satoshi per byte',
        inputSequence: 0,
      }),
      environment: Object.freeze({
        node: process.version,
        platform: process.platform,
        architecture: process.arch,
      }),
      identity: Object.freeze({
        profileId,
        instanceId: stateCategoryProtocolHex,
        topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
        runtimeMaterialSha256: runtimeMaterial.materialSha256,
        proofArtifactHashes,
      }),
      hardLimits: Object.freeze({
        transactionBytes: 100_000,
        unlockingBytecodeBytes: 10_000,
        standardVmResourcePercent: 100,
      }),
      exactDustBases: Object.freeze({
        verifierSats: Object.freeze(
          verifierBaseValues.map((value) => value.toString()),
        ),
        bindingSats: bindingBaseValue.toString(),
        stateSats: stateBaseValue.toString(),
        minimumChangeSats: minimumChange.toString(),
      }),
      pf10FusedQGenesisActions: Object.freeze({
        verdict:
          'production-builder-local-standard-pass-all-actions-precomputed-fixed-lines',
        topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
        actionCount: actionResults.length,
        fixedLineDerivation: {
          inputs: [
            'deployment verification key gamma',
            'deployment verification key delta',
            'BN254 constants',
            'ATE NAF digits',
          ],
          proofOrPublicInputs: false,
          roleTableBytes:
            independentFixedTables.roles.map((table) => table.length),
          roleTableHash256: independentFixedTables.roleHash256,
          terminalTableBytes: independentFixedTables.terminal.length,
          terminalTableHash256:
            independentFixedTables.terminalHash256,
          digestMutationChecks: fixedDigestMutationChecks,
        },
        fixedPrograms: {
          rawExecutorBytes: executorRaw.length,
          executorBodyBytes: executorBody.length,
          loaderBytes: loader.loader.length,
          executorDensityPadBytes,
          fixedLineCarrierBytes: fixedRemoteBlob.length,
          rawTerminalBytes: terminalRaw.length,
          terminalRedeemBytes: terminalRedeem.length,
          exactRawBytes,
          exactRedeemBytes,
          exactFinalRawBytes: exactFinalRaw.length,
          exactFinalRedeemBytes: exactFinalRedeem.length,
          millerRawBytes: millerRaw.length,
          millerRedeemBytes: millerRedeem.length,
          fusedRedeemBytes: fusedRedeem.length,
          bindingRedeemBytes: bindingRedeem.length,
          stateHelperBytes: helper.length,
        },
        actions: actionResults,
        identityExecutorRows,
      }),
    });
    const evidenceOutput =
      process.env.SHIELDKIT_PF10_LIBAUTH_EVIDENCE_OUTPUT;
    if (evidenceOutput !== undefined) {
      assert.equal(
        path.isAbsolute(evidenceOutput),
        true,
        'SHIELDKIT_PF10_LIBAUTH_EVIDENCE_OUTPUT must be absolute',
      );
      writeFileSync(
        evidenceOutput,
        `${JSON.stringify(qualificationEvidence, null, 2)}\n`,
        {
          encoding: 'utf8',
          flag: 'wx',
          mode: 0o600,
        },
      );
    }
    if (
      process.env.SHIELDKIT_PF10_DIAGNOSTIC_REQUEST_ROOT === undefined
    ) {
      console.log(JSON.stringify({ qualificationEvidence }));
    }
  },
);
