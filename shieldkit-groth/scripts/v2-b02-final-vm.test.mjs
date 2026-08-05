/* TEST-ONLY: pure fixtures never resolve or create a qualifying release root. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  createHash,
  generateKeyPairSync,
  sign as signEnvelope,
} from 'node:crypto';
import { createRequire } from 'node:module';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  V2_B02_BCHN_MINED_INPUT_SCHEMA,
  V2_B02_BCHN_MINED_OUTPUT_SCHEMA,
  V2_B02_LANE_ATTESTATION_DOMAIN,
  V2_B02_LANE_ATTESTATION_VERSION,
  V2_B02_LANE_ENVELOPE_SCHEMA,
  V2_B02_LANE_SUBJECT_SCHEMA,
  V2_B02_MACHINE_MANIFEST_SCHEMA,
  V2_B02_RESULT_SCHEMA,
  V2_B02_RESULT_REVALIDATION_SCHEMA,
  V2_B02_TEST_ONLY_STRUCTURAL_SCHEMA,
  V2_B02_VM_INPUT_SCHEMA,
  V2_B02_VM_OUTPUT_SCHEMA,
  V2B02FinalVmError,
  assertV2B02SafeRuntimeForTestOnly,
  measureV2B02RawTransactionForTestOnly,
  parseV2B02Arguments,
  revalidateV2B02FinalVmResult,
  runV2B02FinalVm,
  verifyV2B02StructuralCycleForTestOnly,
} from './v2-b02-final-vm.mjs';
import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  createV2InputRoleLayout,
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  ConsensusBch2025,
  maximumSignatureCheckCount,
} from '@bitauth/libauth';
import {
  V2_Q02_LANE_AUTHORITIES_SCHEMA,
} from './v2-q02-lane-evidence.mjs';

// Node has already initialized the test worker. Production entrypoints require
// an empty loader/preload vector.
process.execArgv.length = 0;

const hash = (value) =>
  createHash('sha256').update(value).digest('hex');
const canonicalBytes = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');
const LIBAUTH_VERSION = createRequire(import.meta.url)(
  '@bitauth/libauth/package.json',
).version;
const u32 = (value) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
};
const u64 = (value) => {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(BigInt(value));
  return bytes;
};
const compact = (value) => {
  if (value < 0xfd) return Buffer.of(value);
  if (value <= 0xffff) {
    const bytes = Buffer.alloc(3);
    bytes[0] = 0xfd;
    bytes.writeUInt16LE(value, 1);
    return bytes;
  }
  if (value <= 0xffff_ffff) {
    return Buffer.concat([Buffer.of(0xfe), u32(value)]);
  }
  throw new Error('test compact uint is too large');
};
const hash256Display = (value) => createHash('sha256')
  .update(createHash('sha256').update(value).digest())
  .digest()
  .reverse()
  .toString('hex');
const MAXIMUM_TARGET = `7fffff${'00'.repeat(29)}`;
const TARGET = BigInt(`0x${MAXIMUM_TARGET}`);
const HEADER_WORK = (1n << 256n) / (TARGET + 1n);

function mineHeader({ merkleRoot, previousBlockHash, time }) {
  for (let nonce = 0; nonce <= 0xffff_ffff; nonce += 1) {
    const header = Buffer.concat([
      u32(4),
      Buffer.from(previousBlockHash, 'hex').reverse(),
      Buffer.from(merkleRoot, 'hex').reverse(),
      u32(time),
      u32(0x207fffff),
      u32(nonce),
    ]);
    const id = hash256Display(header);
    if (BigInt(`0x${id}`) <= TARGET) {
      return Object.freeze({ hex: header.toString('hex'), id });
    }
  }
  throw new Error('test-only low-difficulty header was not mined');
}

function rawTransaction({
  inputCount = 4,
  outputCount = 4,
  unlockLengths = Array(inputCount).fill(1),
  outputScriptLengths = Array(outputCount).fill(1),
} = {}) {
  const inputs = unlockLengths.map((length, index) => {
    const txid = Buffer.alloc(32);
    txid.writeUInt32LE(index + 1);
    return Buffer.concat([
      txid,
      u32(index),
      compact(length),
      Buffer.alloc(length, 0x51),
      u32(0xffff_ffff),
    ]);
  });
  const outputs = outputScriptLengths.map((length) => Buffer.concat([
    u64(546),
    compact(length),
    Buffer.alloc(length, 0x51),
  ]));
  return Buffer.concat([
    u32(2),
    compact(inputCount),
    ...inputs,
    compact(outputCount),
    ...outputs,
    u32(0),
  ]).toString('hex');
}

function rawTransactionOfSize(size, unlockLength) {
  const empty = Buffer.from(rawTransaction({
    inputCount: 1,
    outputCount: 1,
    unlockLengths: [unlockLength],
    outputScriptLengths: [0],
  }), 'hex').length;
  const estimate = size - empty - 4;
  for (
    let scriptLength = Math.max(0, estimate - 8);
    scriptLength <= estimate + 8;
    scriptLength += 1
  ) {
    const raw = rawTransaction({
      inputCount: 1,
      outputCount: 1,
      unlockLengths: [unlockLength],
      outputScriptLengths: [scriptLength],
    });
    if (Buffer.from(raw, 'hex').length === size) return raw;
  }
  throw new Error(`could not construct exact ${size}-byte test transaction`);
}

const role = (index, kind, ordinal = null) =>
  Object.freeze({ index, kind, ordinal });
const outputRoles = (kind, carrierCount = 1) => Object.freeze([
  role(0, 'state'),
  ...Array.from(
    { length: carrierCount },
    (_, ordinal) => role(ordinal + 1, 'verifier', ordinal),
  ),
  role(carrierCount + 1, 'binding'),
  ...(kind === 'withdrawal'
    ? [role(carrierCount + 2, 'withdrawal')]
    : []),
  role(
    kind === 'withdrawal' ? carrierCount + 3 : carrierCount + 2,
    'change',
  ),
]);

function identity() {
  return {
    descriptorSha256: hash('descriptor'),
    finalLocksSha256: hash('locks'),
    instanceId: hash('instance'),
    manifestSha256: hash('manifest'),
    profileId: hash('profile'),
    profileSha256: hash('profile-bytes'),
    releaseBootstrapSha256: hash('bootstrap'),
    releaseRootId: 'test-only-root',
    runtimeMaterialSha256: hash('runtime'),
    sourceCommit: 'a'.repeat(40),
    sourceTree: 'b'.repeat(40),
    topologyId: 'pf10-fused-q-genesis-v1',
  };
}

function structuralCycle() {
  const finalIdentity = identity();
  const identitySha256 = hash(canonicalizeJcs(finalIdentity));
  const actualEvidenceFiles = [];
  const transactions = ['deposit', 'transfer', 'withdrawal'].map(
    (kind) => {
      const rawTransactionHex = rawTransaction({
        inputCount: 4,
        outputCount: kind === 'withdrawal' ? 5 : 4,
      });
      const parsed = parseV2RawTransaction(rawTransactionHex);
      const sourceOutputSha256s = Array.from(
        { length: parsed.inputs.length },
        (_, index) => hash(`${kind}-source-${index}`),
      );
      const inputBindingSha256 = hash(`${kind}-input-bindings`);
      const lanes = Object.fromEntries([
        'maintainer',
        'bchn-mempool',
        'bchn-mined',
        'leanbch',
      ].map((laneRole) => {
        const prefix = `${kind}-${laneRole}`;
        actualEvidenceFiles.push(`${prefix}.json`);
        const resources = ['maintainer', 'leanbch'].includes(laneRole)
          ? Array.from({ length: parsed.inputs.length }, (_, inputIndex) => ({
              hashDigestIterations: {
                maximum: '1',
                percentBasisPoints: 10_000,
                used: '1',
              },
              inputIndex,
              operationCost: {
                maximum: '1',
                percentBasisPoints: 10_000,
                used: '1',
              },
              signatureChecks: {
                maximum: '1',
                percentBasisPoints: 10_000,
                used: '1',
              },
            }))
          : [];
        return [laneRole, {
          accepted: true,
          envelopeSha256: hash(`${prefix}-envelope`),
          identitySha256,
          inputBindingSha256,
          machineManifestSha256: hash(`${prefix}-machine`),
          rawTransactionSha256: hash(parsed.bytes),
          resources,
          role: laneRole,
          runId: hash(`${prefix}-run`),
          sourceOutputSha256s: [...sourceOutputSha256s],
          subjectSha256: hash(`${prefix}-subject`),
          toolSha256: hash(`${prefix}-tool`),
          transactionId: parsed.txid,
        }];
      }));
      return {
        inputBindingSha256,
        kind,
        lanes,
        localAccepted: true,
        outputRoles: outputRoles(kind),
        rawTransactionHex,
        rawTransactionSha256: hash(parsed.bytes),
        serializedBytes: parsed.sizeBytes,
        sourceOutputSha256s,
        transactionId: parsed.txid,
      };
    },
  );
  actualEvidenceFiles.sort();
  return {
    actualEvidenceFiles,
    identity: finalIdentity,
    referencedEvidenceFiles: [...actualEvidenceFiles],
    transactions,
  };
}

const FINAL_CARRIER_COUNT = 10;
const STARTED_AT = '2026-07-29T00:00:00.100Z';
const COMPLETED_AT = '2026-07-29T00:00:00.200Z';
const CAPTURED_AT = '2026-07-29T00:00:00.150Z';

function exactVmMetrics(unlockingBytecodeBytes) {
  const densityControlLength =
    ConsensusBch2025.densityControlBaseLength
    + unlockingBytecodeBytes;
  const maximumOperationCost = Math.floor(
    densityControlLength
      * ConsensusBch2025.operationCostBudgetPerByte,
  );
  return {
    arithmeticCost: String(maximumOperationCost),
    definedFunctions: '0',
    densityControlLength: String(densityControlLength),
    evaluatedInstructionCount: '0',
    hashDigestIterations: '0',
    maximumHashDigestIterations: String(Math.floor(
      densityControlLength
        * ConsensusBch2025.hashDigestIterationsPerByteStandard,
    )),
    maximumOperationCost: String(maximumOperationCost),
    maximumSignatureCheckCount: String(
      maximumSignatureCheckCount(unlockingBytecodeBytes),
    ),
    operationCost: String(maximumOperationCost),
    signatureCheckCount: '0',
    stackPushedBytes: '0',
  };
}

const percentage = (used, maximum) => ({
  maximum,
  percentBasisPoints:
    maximum === '0'
      ? 0
      : Number((BigInt(used) * 10_000n) / BigInt(maximum)),
  used,
});

function localResourceRows(bindings) {
  return bindings.map((binding) => ({
    hashDigestIterations: percentage(
      binding.metrics.hashDigestIterations,
      binding.metrics.maximumHashDigestIterations,
    ),
    inputIndex: binding.index,
    operationCost: percentage(
      binding.metrics.operationCost,
      binding.metrics.maximumOperationCost,
    ),
    signatureChecks: percentage(
      binding.metrics.signatureCheckCount,
      binding.metrics.maximumSignatureCheckCount,
    ),
  }));
}

function laneTool(roleName) {
  const ordinal = [
    'maintainer',
    'bchn-mempool',
    'bchn-mined',
    'leanbch',
  ].indexOf(roleName) + 1;
  return {
    commit: String(ordinal).repeat(40),
    executableSha256: hash(`${roleName}-executable`),
    lockfileSha256: hash(`${roleName}-lockfile`),
    repositoryUrl:
      roleName === 'maintainer'
        ? 'https://github.com/mr-zwets/zk-verifier-bench'
        : `https://example.invalid/${roleName}`,
    runnerSha256: hash(`${roleName}-runner`),
    sourceSha256: hash(`${roleName}-source`),
    tree: String(ordinal + 4).repeat(40),
    version: '1.0.0-test',
  };
}

function transactionClosure(kind, actionIndex) {
  const outputCount =
    kind === 'withdrawal'
      ? FINAL_CARRIER_COUNT + 4
      : FINAL_CARRIER_COUNT + 3;
  const base = rawTransaction({
    inputCount: FINAL_CARRIER_COUNT + 3,
    outputCount,
  });
  const rawTransactionHex =
    `${base.slice(0, -8)}${u32(actionIndex + 1).toString('hex')}`;
  const transaction = parseV2RawTransaction(rawTransactionHex);
  const measured =
    measureV2B02RawTransactionForTestOnly(rawTransactionHex);
  const inputRoleLayout =
    createV2InputRoleLayout(FINAL_CARRIER_COUNT);
  const sourceOutputs = transaction.inputs.map((input, index) => {
    const serializedHex = Buffer.concat([
      u64(546 + index),
      Buffer.of(1, 0x51),
    ]).toString('hex');
    return {
      index,
      outpoint: { ...input.outpoint },
      serializedHex,
      sha256: hash(Buffer.from(serializedHex, 'hex')),
    };
  });
  const inputBindings = transaction.inputs.map((input, index) => ({
    accepted: true,
    index,
    metrics: exactVmMetrics(input.unlockingBytecodeBytes),
    outpoint: { ...input.outpoint },
    role: inputRoleLayout[index],
    sourceOutputSha256: sourceOutputs[index].sha256,
    unlockingBytecodeSha256: hash(input.unlockingBytecode),
  }));
  return {
    hardPolicy: measured.hardPolicy,
    inputBindings,
    inputCount: transaction.inputs.length,
    inputRoleLayout,
    kind,
    localResources: localResourceRows(inputBindings),
    maximumUnlockingBytecodeBytes:
      measured.maximumUnlockingBytecodeBytes,
    narrowerTelemetry: measured.narrowerTelemetry,
    outputCount: transaction.outputs.length,
    outputRoleLayout: outputRoles(kind, FINAL_CARRIER_COUNT),
    rawTransactionHex,
    rawTransactionSha256: measured.rawTransactionSha256,
    serializedBytes: transaction.sizeBytes,
    sourceOutputSha256s: sourceOutputs.map((entry) => entry.sha256),
    sourceOutputs,
    transaction,
    transactionId: transaction.txid,
  };
}

function externalVmStdout(closure) {
  return {
    inputCount: closure.inputCount,
    inputs: closure.inputBindings.map((binding) => ({
      accepted: true,
      error: null,
      hashDigestIterations: Number(
        binding.metrics.hashDigestIterations,
      ),
      inputIndex: binding.index,
      maximumHashDigestIterations: Number(
        binding.metrics.maximumHashDigestIterations,
      ),
      maximumOperationCost: Number(
        binding.metrics.maximumOperationCost,
      ),
      maximumSignatureCheckCount: Number(
        binding.metrics.maximumSignatureCheckCount,
      ),
      operationCost: Number(binding.metrics.operationCost),
      signatureCheckCount: Number(
        binding.metrics.signatureCheckCount,
      ),
      sourceOutputSha256: binding.sourceOutputSha256,
      unlockingBytecodeSha256: binding.unlockingBytecodeSha256,
    })),
    rawTransactionSha256: closure.rawTransactionSha256,
    schema: V2_B02_VM_OUTPUT_SCHEMA,
    transactionId: closure.transactionId,
  };
}

function standaloneResultFixture() {
  const finalIdentity = identity();
  const checkpointHash = hash('standalone-checkpoint');
  const roleNames = [
    'maintainer',
    'bchn-mempool',
    'bchn-mined',
    'leanbch',
  ];
  const keys = new Map(roleNames.map(
    (roleName) => [roleName, generateKeyPairSync('ed25519')],
  ));
  const authorities = roleNames.map((roleName) => ({
    authorityId: `test-only-${roleName}`,
    command: {
      arguments: ['--test-only-nonqualifying'],
      executable: `shieldkit-test-only-${roleName}`,
    },
    organization: 'ShieldKit test-only nonqualifying fixture',
    publicKey: keys.get(roleName).publicKey.export({
      format: 'pem',
      type: 'spki',
    }),
    role: roleName,
    tool: laneTool(roleName),
  }));
  const laneAuthorityArtifact = {
    authorities,
    chipnetPolicy: {
      checkpoint: {
        blockHash: checkpointHash,
        chainwork: '0',
        height: 100,
        maximumTarget: MAXIMUM_TARGET,
      },
      minimumConfirmations: 1,
    },
    evidenceWindow: {
      notAfter: '2027-01-01T00:00:00.000Z',
      notBefore: '2026-01-01T00:00:00.000Z',
    },
    finalLocksSha256: finalIdentity.finalLocksSha256,
    instanceId: finalIdentity.instanceId,
    network: { id: 2, name: 'chipnet' },
    profileId: finalIdentity.profileId,
    schema: V2_Q02_LANE_AUTHORITIES_SCHEMA,
    topologyId: finalIdentity.topologyId,
  };
  const authoritySetSha256 = hash(canonicalBytes(
    laneAuthorityArtifact,
  ));
  const descriptor = {
    descriptorSha256: finalIdentity.descriptorSha256,
    finalLocksSha256: finalIdentity.finalLocksSha256,
    instanceId: finalIdentity.instanceId,
    manifestSha256: finalIdentity.manifestSha256,
    network: { id: 2, name: 'chipnet' },
    profileId: finalIdentity.profileId,
    topologyId: finalIdentity.topologyId,
  };
  const transactions = [
    'deposit',
    'transfer',
    'withdrawal',
  ].map((kind, actionIndex) => {
    const closure = transactionClosure(kind, actionIndex);
    const subject = {
      schema: V2_B02_LANE_SUBJECT_SCHEMA,
      identity: finalIdentity,
      inputBindings: closure.inputBindings,
      kind,
      rawTransactionHex: closure.rawTransactionHex,
      rawTransactionSha256: closure.rawTransactionSha256,
      sourceOutputs: closure.sourceOutputs,
      transactionId: closure.transactionId,
    };
    const minedHeader = mineHeader({
      merkleRoot: closure.transactionId,
      previousBlockHash: checkpointHash,
      time: 1_700_000_000 + actionIndex,
    });
    const externalLanes = Object.fromEntries(roleNames.map(
      (roleName) => {
        const authority = authorities.find(
          (entry) => entry.role === roleName,
        );
        let stdin;
        let stdout;
        if (roleName === 'maintainer' || roleName === 'leanbch') {
          stdin = {
            rawTransactionHex: closure.rawTransactionHex,
            schema: V2_B02_VM_INPUT_SCHEMA,
            sourceOutputs: closure.sourceOutputs.map(
              (entry) => entry.serializedHex,
            ),
          };
          stdout = externalVmStdout(closure);
        } else if (roleName === 'bchn-mempool') {
          stdin = {
            id: `${kind}-test-only-rpc`,
            jsonrpc: '2.0',
            method: 'testmempoolaccept',
            params: [[closure.rawTransactionHex], false],
          };
          stdout = {
            error: null,
            id: `${kind}-test-only-rpc`,
            jsonrpc: '2.0',
            result: [{
              allowed: true,
              fees: { base: 0, 'effective-feerate': 0 },
              size: closure.serializedBytes,
              txid: closure.transactionId,
              vsize: closure.serializedBytes,
            }],
          };
        } else {
          stdin = {
            rawTransactionHex: closure.rawTransactionHex,
            schema: V2_B02_BCHN_MINED_INPUT_SCHEMA,
          };
          stdout = {
            headerSegment: {
              rawHeadersHex: [minedHeader.hex],
              tip: {
                blockHash: minedHeader.id,
                chainwork: HEADER_WORK.toString(10),
                height: 101,
              },
            },
            nodeObservation: {
              blockHash: minedHeader.id,
              chain: 'chipnet',
              confirmations: 1,
              initialBlockDownload: false,
              transactionId: closure.transactionId,
              version: '1.0.0',
            },
            schema: V2_B02_BCHN_MINED_OUTPUT_SCHEMA,
            transactionBlock: {
              headerIndex: 0,
              merkleBranch: [],
              transactionCount: 1,
              transactionIndex: 0,
            },
          };
        }
        const machineManifest = {
          architecture: 'test-only',
          capturedAt: CAPTURED_AT,
          cpuModel: 'test-only deterministic fixture',
          kernel: 'test-only',
          machineIdSha256: hash(`${kind}-${roleName}-machine`),
          memoryBytes: '1',
          operatingSystem: 'test-only',
          schema: V2_B02_MACHINE_MANIFEST_SCHEMA,
        };
        const stderr = Buffer.alloc(0);
        const execution = {
          exitCode: 0,
          machineManifest: {
            path: `${kind}-${roleName}-machine.json`,
            sha256: hash(canonicalBytes(machineManifest)),
          },
          signal: null,
          stderr: {
            path: `${kind}-${roleName}-stderr.txt`,
            sha256: hash(stderr),
          },
          stdin: {
            path: `${kind}-${roleName}-stdin.json`,
            sha256: hash(canonicalBytes(stdin)),
          },
          stdout: {
            path: `${kind}-${roleName}-stdout.json`,
            sha256: hash(canonicalBytes(stdout)),
          },
        };
        const envelope = {
          authorityRole: roleName,
          authoritySetSha256,
          command: authority.command,
          completedAt: COMPLETED_AT,
          descriptor,
          execution,
          runId: hash(`${kind}-${roleName}-run`),
          schema: V2_B02_LANE_ENVELOPE_SCHEMA,
          signature: null,
          startedAt: STARTED_AT,
          subject,
          tool: authority.tool,
        };
        envelope.signature = {
          algorithm: 'ed25519',
          signatureBase64: signEnvelope(
            null,
            canonicalBytes({
              domain: V2_B02_LANE_ATTESTATION_DOMAIN,
              envelope: { ...envelope, signature: null },
              version: V2_B02_LANE_ATTESTATION_VERSION,
            }),
            keys.get(roleName).privateKey,
          ).toString('base64'),
        };
        const resources =
          roleName === 'maintainer' || roleName === 'leanbch'
            ? localResourceRows(closure.inputBindings)
            : [];
        return [roleName, {
          command: authority.command,
          completedAt: COMPLETED_AT,
          envelopeSha256: hash(canonicalBytes(envelope)),
          evidence: {
            envelope,
            machineManifest,
            stderrBase64: stderr.toString('base64'),
            stdin,
            stdout,
          },
          executionArtifactSha256s: {
            machineManifest: execution.machineManifest.sha256,
            stderr: execution.stderr.sha256,
            stdin: execution.stdin.sha256,
            stdout: execution.stdout.sha256,
          },
          machineManifest,
          machineManifestSha256:
            execution.machineManifest.sha256,
          resources,
          runId: envelope.runId,
          startedAt: STARTED_AT,
          subjectSha256: hash(canonicalBytes(subject)),
          tool: authority.tool,
          toolSha256: hash(canonicalBytes(authority.tool)),
        }];
      },
    ));
    return {
      externalLanes,
      hardPolicy: closure.hardPolicy,
      inputBindings: closure.inputBindings,
      inputCount: closure.inputCount,
      inputRoleLayout: closure.inputRoleLayout,
      kind,
      localLibauth: {
        evidenceSha256: hash(`${kind}-local-libauth-evidence`),
        tool: {
          name: '@bitauth/libauth',
          profileId: finalIdentity.profileId,
          profileSha256: finalIdentity.profileSha256,
          version: LIBAUTH_VERSION,
          vm: 'BCH_2026_STANDARD',
        },
      },
      localLibauthEvidenceSha256:
        hash(`${kind}-local-libauth-evidence`),
      localResources: closure.localResources,
      maximumUnlockingBytecodeBytes:
        closure.maximumUnlockingBytecodeBytes,
      narrowerTelemetry: closure.narrowerTelemetry,
      outputCount: closure.outputCount,
      outputRoleLayout: closure.outputRoleLayout,
      rawTransactionHex: closure.rawTransactionHex,
      rawTransactionSha256: closure.rawTransactionSha256,
      serializedBytes: closure.serializedBytes,
      sourceOutputSha256s: closure.sourceOutputSha256s,
      sourceOutputs: closure.sourceOutputs,
      transactionId: closure.transactionId,
    };
  });
  return {
    schema: V2_B02_RESULT_SCHEMA,
    status: 'b02-qualified-final-vm-not-production-or-release',
    b02Qualified: true,
    production: false,
    releaseQualified: false,
    ...finalIdentity,
    runtimeQualification: {
      claims: {
        ceremonyQualified: true,
        developmentKey: false,
        finalKey: true,
        production: false,
        releaseQualified: false,
      },
      eligibility: 'final-qualified',
      runtimeMaterialSha256: finalIdentity.runtimeMaterialSha256,
    },
    authoritySetSha256,
    authorityArtifactSha256: authoritySetSha256,
    laneAuthorityArtifact,
    sourceVerification: {
      commit: finalIdentity.sourceCommit,
      tree: finalIdentity.sourceTree,
      gitExecutable: '/usr/bin/git',
      gitVersion: 'git version 2.50.1',
      environment: {
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_TERMINAL_PROMPT: '0',
        HOME: '/nonexistent',
        LANG: 'C',
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
      },
      replaceObjectsDisabled: true,
    },
    transactionsManifestSha256: hash('transactions-manifest'),
    maintainerBenchmark: laneTool('maintainer'),
    hardPolicyCeilings: {
      serializedTransactionBytes: 100_000,
      everyInputUnlockingBytecodeBytes: 10_000,
      everyReportedVmResourcePercent: 100,
    },
    narrowerMargins: '90000/9500-non-blocking-risk-telemetry-only',
    transactions,
    laneEvidenceFileCount: 63,
    externalLaneRunCount: 12,
  };
}

function argv(root) {
  return [
    '--profile-core', join(root, 'profile.json'),
    '--descriptor', join(root, 'descriptor.json'),
    '--final-manifest', join(root, 'manifest.json'),
    '--release-root', 'test-only-root',
    '--transactions', join(root, 'transactions.json'),
    '--lane-evidence-dir', join(root, 'lanes'),
    '--expected-commit', 'a'.repeat(40),
    '--expected-tree', 'b'.repeat(40),
    '--output-dir', join(root, 'output'),
  ];
}

test('B-02 accepts only the exact public argument interface', () => {
  const parsed = parseV2B02Arguments(argv('/tmp/b02'));
  assert.equal(parsed.releaseRootId, 'test-only-root');
  assert.throws(
    () => parseV2B02Arguments([...argv('/tmp/b02'), '--test-only', 'true']),
    V2B02FinalVmError,
  );
  const relative = argv('/tmp/b02');
  relative[relative.indexOf('--transactions') + 1] = 'relative.json';
  assert.throws(() => parseV2B02Arguments(relative), /absolute normalized/u);
});

test('B-02 resolves the compiled release root before caller-selected inputs and writes one bound 0600 failure', async () => {
  const parent = mkdtempSync(resolve(tmpdir(), 'shieldkit-b02-test-'));
  const options = parseV2B02Arguments(argv(parent));
  try {
    await assert.rejects(
      () => runV2B02FinalVm(options),
      /no approved V2 Direct final release roots|not approved/u,
    );
    const outputStat = statSync(options.outputDirectory);
    const failurePath = join(options.outputDirectory, 'failure.json');
    const failureStat = statSync(failurePath);
    const failure = JSON.parse(readFileSync(failurePath));
    assert.equal(outputStat.mode & 0o777, 0o700);
    assert.equal(failureStat.mode & 0o777, 0o600);
    assert.equal(failure.schema, V2_B02_RESULT_SCHEMA);
    assert.equal(failure.b02Qualified, false);
    assert.equal(failure.production, false);
    assert.equal(failure.releaseQualified, false);
    assert.equal(failure.request.expectedCommit, options.expectedCommit);
    assert.doesNotMatch(failure.reason, /profile\.json|descriptor\.json/u);

    const preexisting = {
      ...options,
      outputDirectory: join(parent, 'preexisting-output'),
    };
    mkdirSync(preexisting.outputDirectory, { mode: 0o700 });
    await assert.rejects(
      () => runV2B02FinalVm(preexisting),
      /no approved V2 Direct final release roots|not approved/u,
    );
    assert.deepEqual(readdirSync(preexisting.outputDirectory), []);
  } finally {
    rmSync(parent, { force: true, recursive: true });
  }
});

test('B-02 rejects ambient loader, preload, dynamic-linker, and execArgv trust controls', () => {
  assert.equal(assertV2B02SafeRuntimeForTestOnly({}, []), true);
  for (const environment of [
    { NODE_OPTIONS: '--import=/tmp/evil.mjs' },
    { NODE_PATH: '/tmp/evil-modules' },
    { LD_PRELOAD: '/tmp/evil.so' },
    { LD_LIBRARY_PATH: '/tmp/evil-libraries' },
    { DYLD_INSERT_LIBRARIES: '/tmp/evil.dylib' },
  ]) {
    assert.throws(
      () => assertV2B02SafeRuntimeForTestOnly(environment, []),
      /ambient loader|dynamic-linker/u,
    );
  }
  assert.throws(
    () => assertV2B02SafeRuntimeForTestOnly({}, ['--import=/tmp/evil.mjs']),
    /process\.execArgv/u,
  );
});

test('B-02 hard ceilings accept exact 100000/10000 boundaries and reject either plus one', () => {
  const exactRaw = rawTransactionOfSize(100_000, 10_000);
  const exact = measureV2B02RawTransactionForTestOnly(exactRaw);
  assert.equal(exact.transaction.sizeBytes, 100_000);
  assert.equal(exact.maximumUnlockingBytecodeBytes, 10_000);
  assert.equal(
    exact.narrowerTelemetry.serializedTransactionAtOrBelow90000,
    false,
  );
  assert.equal(
    exact.narrowerTelemetry.everyInputUnlockingBytecodeAtOrBelow9500,
    false,
  );
  assert.throws(
    () => measureV2B02RawTransactionForTestOnly(
      rawTransactionOfSize(100_001, 10_000),
    ),
    /maximum is 100000/u,
  );
  assert.throws(
    () => measureV2B02RawTransactionForTestOnly(rawTransaction({
      inputCount: 1,
      outputCount: 1,
      unlockLengths: [10_001],
      outputScriptLengths: [1],
    })),
    /maximum is 10000/u,
  );

  const resourceChanged = structuralCycle();
  resourceChanged.transactions[0]
    .lanes.maintainer.resources[0].operationCost.used = '2';
  assert.throws(
    () => verifyV2B02StructuralCycleForTestOnly(resourceChanged),
    /exceeds 100 percent/u,
  );
});

test('B-02 TEST-ONLY all-lane structural cycle is complete but never qualifying', () => {
  const result = verifyV2B02StructuralCycleForTestOnly(
    structuralCycle(),
  );
  assert.equal(result.schema, V2_B02_TEST_ONLY_STRUCTURAL_SCHEMA);
  assert.equal(result.structurallyValid, true);
  assert.equal(result.transactionCount, 3);
  assert.equal(result.runCount, 12);
  assert.equal(result.b02Qualified, false);
  assert.equal(result.production, false);
  assert.equal(result.releaseQualified, false);
});

test('B-02 structural cycle rejects lane omission, mismatch, or reject outcomes', () => {
  const omitted = structuredClone(structuralCycle());
  delete omitted.transactions[0].lanes.maintainer;
  assert.throws(
    () => verifyV2B02StructuralCycleForTestOnly(omitted),
    /missing or unknown/u,
  );

  const mismatched = structuredClone(structuralCycle());
  mismatched.transactions[1].lanes.leanbch.transactionId = hash('other-tx');
  assert.throws(
    () => verifyV2B02StructuralCycleForTestOnly(mismatched),
    /acceptance, transaction, sources, or per-input/u,
  );

  const rejected = structuredClone(structuralCycle());
  rejected.transactions[2].lanes['bchn-mempool'].accepted = false;
  assert.throws(
    () => verifyV2B02StructuralCycleForTestOnly(rejected),
    /acceptance, transaction, sources, or per-input/u,
  );
});

test('B-02 structural cycle rejects raw transaction, source-output, and output-role tampering', () => {
  const rawChanged = structuredClone(structuralCycle());
  rawChanged.transactions[0].rawTransactionHex =
    `${rawChanged.transactions[0].rawTransactionHex.slice(0, -2)}01`;
  assert.throws(
    () => verifyV2B02StructuralCycleForTestOnly(rawChanged),
    /raw transaction bytes or identity differ/u,
  );

  const outputBytesChanged = structuredClone(structuralCycle());
  const depositRaw = outputBytesChanged.transactions[0].rawTransactionHex;
  outputBytesChanged.transactions[0].rawTransactionHex =
    `${depositRaw.slice(0, -10)}52${depositRaw.slice(-8)}`;
  assert.throws(
    () => verifyV2B02StructuralCycleForTestOnly(outputBytesChanged),
    /raw transaction bytes or identity differ/u,
  );

  const sourceChanged = structuredClone(structuralCycle());
  sourceChanged.transactions[1].sourceOutputSha256s[0] =
    hash('substituted-source-output');
  assert.throws(
    () => verifyV2B02StructuralCycleForTestOnly(sourceChanged),
    /acceptance, transaction, sources, or per-input/u,
  );

  const outputChanged = structuredClone(structuralCycle());
  outputChanged.transactions[2].outputRoles[0].kind = 'change';
  assert.throws(
    () => verifyV2B02StructuralCycleForTestOnly(outputChanged),
    /differs from the exact topology/u,
  );
});

test('B-02 structural cycle rejects final identity and release-root drift', () => {
  const laneDrift = structuredClone(structuralCycle());
  laneDrift.transactions[0].lanes.maintainer.identitySha256 =
    hash('other-identity');
  assert.throws(
    () => verifyV2B02StructuralCycleForTestOnly(laneDrift),
    /acceptance, transaction, sources, or per-input/u,
  );

  const rootDrift = structuredClone(structuralCycle());
  rootDrift.identity.releaseRootId = 'other-root';
  assert.throws(
    () => verifyV2B02StructuralCycleForTestOnly(rootDrift),
    /acceptance, transaction, sources, or per-input/u,
  );
});

test('B-02 structural cycle rejects unreferenced evidence files', () => {
  const changed = structuredClone(structuralCycle());
  changed.actualEvidenceFiles.push('unreferenced.json');
  changed.actualEvidenceFiles.sort();
  assert.throws(
    () => verifyV2B02StructuralCycleForTestOnly(changed),
    /missing or unreferenced file/u,
  );
});

test('B-02 standalone result replay derives the signed all-lane closure at the exact 100-percent VM boundary', () => {
  const value = standaloneResultFixture();
  const result = revalidateV2B02FinalVmResult(value);
  assert.equal(result.schema, V2_B02_RESULT_REVALIDATION_SCHEMA);
  assert.equal(result.b02Qualified, true);
  assert.equal(result.hardPolicyQualified, true);
  assert.equal(result.production, false);
  assert.equal(result.releaseQualified, false);
  assert.equal(result.transactionCount, 3);
  assert.equal(result.externalLaneRunCount, 12);
  assert.equal(result.actions.length, 3);
  assert.equal(result.actions[0].inputCount, 13);
  assert.equal(result.peakVmResourcePercentBasisPoints, 10_000);
  assert.equal(
    result.resultSha256,
    hash(canonicalBytes(value)),
  );
});

test('B-02 standalone result replay rejects raw/source/input/lane/tool/machine and hard-ceiling tampering', () => {
  const baseline = standaloneResultFixture();
  const mutations = [
    (value) => {
      value.transactions[0].rawTransactionHex =
        `${value.transactions[0].rawTransactionHex.slice(0, -8)}04000000`;
    },
    (value) => {
      value.transactions[0].sourceOutputs[0].serializedHex =
        '01000000000000000152';
    },
    (value) => {
      const metrics = value.transactions[0].inputBindings[0].metrics;
      metrics.operationCost = String(
        BigInt(metrics.maximumOperationCost) + 1n,
      );
      metrics.arithmeticCost = metrics.operationCost;
    },
    (value) => {
      value.transactions[1].externalLanes.maintainer
        .evidence.stdout.inputs[0].accepted = false;
    },
    (value) => {
      value.transactions[1].externalLanes.leanbch
        .tool.runnerSha256 = hash('tampered-tool');
    },
    (value) => {
      value.transactions[2].externalLanes['bchn-mempool']
        .machineManifest.memoryBytes = '2';
    },
    (value) => {
      value.transactions[2].externalLanes['bchn-mined']
        .evidence.stdout.transactionBlock.transactionCount = 2;
    },
    (value) => {
      value.hardPolicyCeilings.serializedTransactionBytes = 99_999;
    },
    (value) => {
      value.runtimeQualification.claims.production = true;
    },
  ];
  for (const [index, mutate] of mutations.entries()) {
    const value = structuredClone(baseline);
    mutate(value);
    assert.throws(
      () => revalidateV2B02FinalVmResult(value),
      V2B02FinalVmError,
      `standalone tamper mutation ${index} must fail`,
    );
  }
});

test('B-02 CLI usage failure is one bounded line and exposes no test seam', () => {
  const script = fileURLToPath(new URL('./v2-b02-final-vm.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script, '--test-only'], {
    encoding: 'utf8',
    env: { ...process.env, NODE_OPTIONS: undefined },
  });
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /^B-02 final VM verification failed: usage:/u);
  assert.equal(result.stderr.trimEnd().split('\n').length, 1);
});
