import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  createHash, generateKeyPairSync, sign,
} from 'node:crypto';
import {
  mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { encodeTokenPrefix } from '@bitauth/libauth';

import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  encodeDirectV2TransactionContext,
} from '../packages/action/v2/context.mjs';
import { encodeActionPacket } from '../packages/action/v2/packet.mjs';
import { encodeStateNftCommitment } from '../packages/action/v2/state.mjs';
import {
  hashIndexedNullifierLeaf, hashIndexedNullifierNode,
} from '../packages/action/v2/poseidon.mjs';
import {
  createIndexedNullifierQualificationStore,
} from '../packages/action/v2/tree-qualification-store.mjs';
import {
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  Q07_NOTE_TREE_DEPTH, appendQ07Note, auditQ07NoteAccumulator,
  createQ07NoteAccumulator,
} from '../packages/pool/v2/qualification/q07-note-accumulator.mjs';
import {
  V2_Q07_FIXED_DEPTH_COUNTER_KEYS, V2_Q07_THRESHOLDS,
} from './v2-q07-evidence.mjs';
import {
  V2_B02_TRANSACTIONS_SCHEMA,
} from './v2-b02-final-vm.mjs';
import {
  parseV2Q07FinalPerformanceArguments,
  revalidateV2Q07FinalPerformanceResultForTestOnly,
  validateV2Q07AuthorityForTestOnly,
  validateV2Q07B02FinalPinsForTestOnly,
  validateV2Q07SampleManifestForTestOnly,
  verifyV2Q07FinalHistoryForTestOnly,
  verifyV2Q07PublishedEnvelopeForTestOnly,
  V2_Q07_BENCHMARK_AUTHORITY_SCHEMA,
  V2_Q07_FINAL_PERFORMANCE_SCHEMA,
  V2_Q07_HISTORY_SCHEMA,
  V2_Q07_INVENTORY_SCHEMA,
  V2_Q07_MACHINE_ENVELOPE_SCHEMA,
  V2_Q07_MACHINE_RECEIPT_SCHEMA,
  V2_Q07_MACHINE_STATEMENT_SCHEMA,
  V2_Q07_RAW_SAMPLE_SCHEMA,
  V2_Q07_SAMPLE_INPUT_SCHEMA,
  V2_Q07_SAMPLE_MANIFEST_SCHEMA,
  V2Q07FinalPerformanceError,
} from './v2-q07-final-performance.mjs';

const HISTORY_DOMAIN =
  'ShieldKit/V2/Q07/final-descriptor-bound-history/action-transcript/v1\0';
const ENVELOPE_DOMAIN =
  'ShieldKit/V2/Q07/final-performance/published-machine-envelope/v1\0';
const HISTORY_CLASS =
  'descriptor-bound-deterministic-local-replay-not-chain-authenticated';
const PHASES = Object.freeze([
  'proof-generation',
  'incremental-apply-1k',
  'incremental-apply-100k',
  'full-recovery',
  'bottom-up-snapshot-authentication',
  'raw-fallback',
  'suffix-replay',
  'cold-sqlite-io',
]);
const PHASE_STATE_COUNTS = Object.freeze({
  'proof-generation': [100_000, 100_000],
  'incremental-apply-1k': [999, 1_000],
  'incremental-apply-100k': [99_999, 100_000],
  'full-recovery': [0, 100_000],
  'bottom-up-snapshot-authentication': [0, 100_000],
  'raw-fallback': [0, 100_000],
  'suffix-replay': [99_000, 100_000],
  'cold-sqlite-io': [100_000, 100_000],
});
const WALLS = Object.freeze({
  'proof-generation': 60_000_000_000n,
  'incremental-apply-1k': 100_000_000n,
  'incremental-apply-100k': 110_000_000n,
  'full-recovery': 900_000_000_000n,
  'bottom-up-snapshot-authentication': 1_000_000_000n,
  'raw-fallback': 1_000_000_000n,
  'suffix-replay': 1_000_000_000n,
  'cold-sqlite-io': 1_000_000_000n,
});
const RSS = Object.freeze({
  'proof-generation': BigInt(4 * 1024 ** 3),
  'incremental-apply-1k': 1n,
  'incremental-apply-100k': 1n,
  'full-recovery': BigInt(2 * 1024 ** 3),
  'bottom-up-snapshot-authentication': 1n,
  'raw-fallback': 1n,
  'suffix-replay': 1n,
  'cold-sqlite-io': 1n,
});
const canonical = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hashLabel = (label) => sha256(Buffer.from(label));
const rootHex = (value) => value.toString(16).padStart(64, '0');
const deepClone = (value) => structuredClone(value);
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
  throw new Error('test compact uint is too large');
};

function identityFixture() {
  return {
    descriptorSha256: hashLabel('descriptor'),
    finalLocksSha256: hashLabel('final-locks'),
    instanceId: hashLabel('instance'),
    manifestSha256: hashLabel('manifest'),
    profileId: hashLabel('profile'),
    profileSha256: hashLabel('profile-file'),
    releaseBootstrapSha256: hashLabel('release-bootstrap'),
    releaseRootId: 'release-root-test',
    runtimeMaterialSha256: hashLabel('runtime'),
    sourceCommit: 'a'.repeat(40),
    sourceTree: 'b'.repeat(40),
    topologyId: 'pf10-fused-test',
  };
}

function authorityFixture(publicKeyPem) {
  return {
    artifactPaths: {
      envelope: 'published-machine-envelope.json',
      history: 'history/final-history.ndjson',
      inventory: 'inventory.json',
      samplesManifest: 'samples/raw-samples.json',
    },
    authority: {
      authorityId: 'published-machine-authority',
      organization: 'Independent Benchmark Laboratory',
      publicKeyPem,
    },
    commands: PHASES.map((phase, index) => ({
      argv: ['/usr/bin/node', 'benchmark.mjs', `--phase=${phase}`],
      id: `command-${index + 1}`,
      phase,
    })),
    evidenceWindow: {
      notAfter: '2026-12-31T23:59:59.999Z',
      notBefore: '2026-01-01T00:00:00.000Z',
    },
    machinePolicy: {
      architecture: 'x86_64',
      minimumLogicalCpus: 8,
      minimumMemoryBytes: String(16 * 1024 ** 3),
      operatingSystem: 'linux',
    },
    resourcePolicy: {
      cgroupVersion: '2',
      coldIoProtocol: 'fresh-process-after-parent-closed-durable-store-no-page-cache-drop-claim',
      ioAccounting: 'proc-pid-io',
      memoryAccounting: 'cgroup-v2-memory.peak',
      sampleCount: '32',
    },
    schema: V2_Q07_BENCHMARK_AUTHORITY_SCHEMA,
  };
}

function fixedCounters() {
  return Object.fromEntries(V2_Q07_FIXED_DEPTH_COUNTER_KEYS.map((key) => [key, 1]));
}

function sampleEvidenceFixture(authority, identity) {
  const terminalStateSha256 = sha256(Buffer.from('ab'.repeat(128), 'hex'));
  const historySha256 = hashLabel('history-file');
  const checkpointCounts = [0, 999, 1_000, 99_000, 99_999, 100_000];
  const historyVerification = {
    fileSha256: historySha256,
    checkpoints: checkpointCounts.map((actionCount) => ({
      actionCount: String(actionCount),
      stateSha256: actionCount === 100_000
        ? terminalStateSha256
        : hashLabel(`checkpoint-${actionCount}`),
    })),
  };
  const checkpoints = new Map(historyVerification.checkpoints.map((entry) =>
    [entry.actionCount, entry.stateSha256]));
  const storeBytes = Buffer.from('authenticated full V2 store fixture');
  const storePath = 'store/authenticated-store.sqlite';
  const storeArtifact = { path: storePath, sha256: sha256(storeBytes) };
  const rawEntries = [];
  const artifacts = [
    {
      bytes: '123',
      classification: 'history-corpus',
      path: authority.artifactPaths.history,
      sha256: historySha256,
    },
    {
      bytes: String(storeBytes.length),
      classification: 'authenticated-store',
      path: storePath,
      sha256: storeArtifact.sha256,
    },
  ];
  rawEntries.push({
    bytes: storeBytes,
    path: storePath,
    sha256: storeArtifact.sha256,
  });
  const phases = [];
  for (const [phaseIndex, phase] of PHASES.entries()) {
    const refs = [];
    for (let ordinal = 1; ordinal <= 32; ordinal += 1) {
      const samplePath = `samples/${String(phaseIndex + 1).padStart(2, '0')}-${String(ordinal).padStart(2, '0')}.json`;
      const inputPath = `inputs/${String(phaseIndex + 1).padStart(2, '0')}-${String(ordinal).padStart(2, '0')}.json`;
      const outputPath = `receipts/${String(phaseIndex + 1).padStart(2, '0')}-${String(ordinal).padStart(2, '0')}.json`;
      const stdoutPath = `outputs/${String(phaseIndex + 1).padStart(2, '0')}-${String(ordinal).padStart(2, '0')}.stdout`;
      const stderrPath = `outputs/${String(phaseIndex + 1).padStart(2, '0')}-${String(ordinal).padStart(2, '0')}.stderr`;
      const stderr = Buffer.alloc(0);
      const wall = WALLS[phase];
      const start = 1_000_000_000_000n + BigInt(phaseIndex * 100 + ordinal) * 1_000_000_000_000n;
      const [startCount, endCount] = PHASE_STATE_COUNTS[phase];
      const value = {
        commandId: authority.commands[phaseIndex].id,
        completedAt: new Date(
          Date.parse('2026-06-01T00:00:00.000Z')
            + Number(wall / 1_000_000n),
        ).toISOString(),
        execution: {
          exitCode: 0,
          signal: null,
          stderr: { path: stderrPath, sha256: sha256(stderr) },
          stdout: { path: stdoutPath, sha256: null },
        },
        fixedDepthOperationCounts:
          ['incremental-apply-1k', 'incremental-apply-100k'].includes(phase)
            ? fixedCounters()
            : null,
        io: {
          readBytes: phase === 'cold-sqlite-io' ? '4096' : '0',
          readSyscalls: phase === 'cold-sqlite-io' ? '1' : '0',
          storeLifecycle: phase === 'cold-sqlite-io'
            ? 'fresh-process-after-parent-closed-durable-store'
            : ['incremental-apply-1k', 'incremental-apply-100k'].includes(phase)
              ? 'same-process-open-store-warm-io'
              : 'isolated-benchmark-process',
          writeBytes: '0',
          writeSyscalls: '0',
        },
        inputArtifact: null,
        monotonicEndNanoseconds: String(start + wall),
        monotonicStartNanoseconds: String(start),
        ordinal: String(ordinal),
        outputArtifact: null,
        phase,
        process: {
          bootId: '01234567-89ab-cdef-0123-456789abcdef',
          parentProcessId: '100',
          processId: String(1_000 + phaseIndex * 100 + ordinal),
          processInstanceId: `p-${phaseIndex + 1}-${ordinal}`,
          processStartTicks: String(10_000 + phaseIndex * 100 + ordinal),
        },
        rss: {
          bytes: RSS[phase].toString(),
          kind: 'cgroup-v2',
          path: `/sys/fs/cgroup/q07/published-run-one/${phaseIndex + 1}/${ordinal}`,
          source: 'memory.peak',
        },
        sampleId: `${phase}-${String(ordinal).padStart(2, '0')}`,
        schema: V2_Q07_RAW_SAMPLE_SCHEMA,
        startedAt: '2026-06-01T00:00:00.000Z',
        state: {
          endActionCount: String(endCount),
          endStateSha256: checkpoints.get(String(endCount)),
          startActionCount: String(startCount),
          startStateSha256: checkpoints.get(String(startCount)),
        },
        wallNanoseconds: wall.toString(),
      };
      const input = {
        commandId: value.commandId,
        endCheckpoint: {
          actionCount: value.state.endActionCount,
          stateSha256: value.state.endStateSha256,
        },
        historySha256,
        identity,
        phase,
        sampleId: value.sampleId,
        schema: V2_Q07_SAMPLE_INPUT_SCHEMA,
        startCheckpoint: {
          actionCount: value.state.startActionCount,
          stateSha256: value.state.startStateSha256,
        },
        storeArtifactSha256: storeArtifact.sha256,
        terminalStateSha256,
      };
      const inputBytes = canonical(input);
      value.inputArtifact = {
        path: inputPath,
        sha256: sha256(inputBytes),
      };
      const receipt = {
        commandId: value.commandId,
        completedAt: value.completedAt,
        fixedDepthOperationCounts: value.fixedDepthOperationCounts,
        historySha256,
        inputArtifactSha256: value.inputArtifact.sha256,
        io: value.io,
        monotonicEndNanoseconds: value.monotonicEndNanoseconds,
        monotonicStartNanoseconds: value.monotonicStartNanoseconds,
        ordinal: value.ordinal,
        phase,
        process: value.process,
        rss: value.rss,
        sampleId: value.sampleId,
        schema: V2_Q07_MACHINE_RECEIPT_SCHEMA,
        startedAt: value.startedAt,
        state: value.state,
        storeArtifactSha256: storeArtifact.sha256,
        terminalStateSha256,
        wallNanoseconds: value.wallNanoseconds,
      };
      const receiptBytes = canonical(receipt);
      value.outputArtifact = {
        path: outputPath,
        sha256: sha256(receiptBytes),
      };
      const stdout = receiptBytes;
      value.execution.stdout.sha256 = sha256(stdout);
      const bytes = canonical(value);
      const digest = sha256(bytes);
      refs.push({ path: samplePath, sha256: digest });
      rawEntries.push({
        path: inputPath,
        sha256: value.inputArtifact.sha256,
        value: input,
      }, {
        path: outputPath,
        sha256: value.outputArtifact.sha256,
        value: receipt,
      }, {
        bytes: stdout,
        path: stdoutPath,
        sha256: sha256(stdout),
      }, {
        bytes: stderr,
        path: stderrPath,
        sha256: sha256(stderr),
      }, {
        path: samplePath,
        sha256: digest,
        value,
      });
      artifacts.push({
        bytes: String(bytes.length),
        classification: 'raw-sample',
        path: samplePath,
        sha256: digest,
      }, {
        bytes: String(inputBytes.length),
        classification: 'sample-input',
        path: inputPath,
        sha256: value.inputArtifact.sha256,
      }, {
        bytes: String(receiptBytes.length),
        classification: 'sample-output',
        path: outputPath,
        sha256: value.outputArtifact.sha256,
      }, {
        bytes: String(stdout.length),
        classification: 'raw-command-output',
        path: stdoutPath,
        sha256: sha256(stdout),
      }, {
        bytes: String(stderr.length),
        classification: 'raw-command-output',
        path: stderrPath,
        sha256: sha256(stderr),
      });
    }
    phases.push({
      name: phase,
      reportedP95Nanoseconds: WALLS[phase].toString(),
      reportedPeakRssBytes: RSS[phase].toString(),
      samples: refs,
    });
  }
  const manifest = {
    identity,
    machineRunId: 'published-run-one',
    phases,
    sampleCount: '32',
    schema: V2_Q07_SAMPLE_MANIFEST_SCHEMA,
    storeArtifact,
    storeBytes: String(storeBytes.length),
    terminalStateSha256,
  };
  const manifestBytes = canonical(manifest);
  artifacts.push({
    bytes: String(manifestBytes.length),
    classification: 'sample-manifest',
    path: authority.artifactPaths.samplesManifest,
    sha256: sha256(manifestBytes),
  });
  artifacts.sort((left, right) => left.path.localeCompare(right.path));
  const inventory = {
    artifacts,
    schema: V2_Q07_INVENTORY_SCHEMA,
  };
  return {
    historyVerification,
    inventory,
    manifest,
    rawEntries,
    storeArtifact: {
      bytes: String(storeBytes.length),
      path: storePath,
      sha256: storeArtifact.sha256,
    },
  };
}

function rawSampleEntry(evidence, phase = 'proof-generation', ordinal = '1') {
  const entry = evidence.rawEntries.find((candidate) =>
    candidate.value?.schema === V2_Q07_RAW_SAMPLE_SCHEMA
      && candidate.value.phase === phase
      && candidate.value.ordinal === ordinal);
  assert.ok(entry);
  return entry;
}

function updateInventoryArtifact(evidence, path, bytes, digest) {
  const inventory = evidence.inventory.artifacts.find((entry) =>
    entry.path === path);
  assert.ok(inventory);
  inventory.bytes = String(bytes.length);
  inventory.sha256 = digest;
}

function refreshRawSampleEvidence(evidence, sample) {
  const bytes = canonical(sample.value);
  sample.sha256 = sha256(bytes);
  const reference = evidence.manifest.phases
    .flatMap((phase) => phase.samples)
    .find((entry) => entry.path === sample.path);
  assert.ok(reference);
  reference.sha256 = sample.sha256;
  updateInventoryArtifact(evidence, sample.path, bytes, sample.sha256);
}

function refreshReceiptEvidence(evidence, sample) {
  const receipt = evidence.rawEntries.find((entry) =>
    entry.path === sample.value.outputArtifact.path);
  assert.ok(receipt);
  for (const key of [
    'commandId', 'completedAt', 'fixedDepthOperationCounts', 'io',
    'monotonicEndNanoseconds', 'monotonicStartNanoseconds', 'ordinal', 'phase',
    'process', 'rss', 'sampleId', 'startedAt', 'state', 'wallNanoseconds',
  ]) receipt.value[key] = deepClone(sample.value[key]);
  receipt.value.inputArtifactSha256 = sample.value.inputArtifact.sha256;
  const receiptBytes = canonical(receipt.value);
  receipt.sha256 = sha256(receiptBytes);
  sample.value.outputArtifact.sha256 = receipt.sha256;
  updateInventoryArtifact(
    evidence,
    receipt.path,
    receiptBytes,
    receipt.sha256,
  );
  const stdout = evidence.rawEntries.find((entry) =>
    entry.path === sample.value.execution.stdout.path);
  assert.ok(stdout);
  stdout.bytes = receiptBytes;
  stdout.sha256 = receipt.sha256;
  sample.value.execution.stdout.sha256 = stdout.sha256;
  updateInventoryArtifact(
    evidence,
    stdout.path,
    stdout.bytes,
    stdout.sha256,
  );
  refreshRawSampleEvidence(evidence, sample);
}

function opTrueRawTransaction(actionIndex, outputCount) {
  const inputs = Array.from({ length: 4 }, (_, index) => {
    const txid = Buffer.alloc(32);
    txid.writeUInt32LE(actionIndex * 16 + index + 1);
    return Buffer.concat([
      txid,
      u32(index),
      compact(1),
      Buffer.of(0x51),
      u32(0xffff_ffff),
    ]);
  });
  const outputs = Array.from({ length: outputCount }, () => Buffer.concat([
    u64(546),
    compact(1),
    Buffer.of(0x51),
  ]));
  return Buffer.concat([
    u32(2),
    compact(inputs.length),
    ...inputs,
    compact(outputs.length),
    ...outputs,
    u32(actionIndex),
  ]).toString('hex');
}

function opTrueB02FinalPinFixture() {
  const identity = identityFixture();
  const laneAuthorityArtifact = {
    explicitTestAuthority: 'OP_TRUE rejection fixture',
  };
  const authorityArtifactSha256 = sha256(canonical(laneAuthorityArtifact));
  const transactions = ['deposit', 'transfer', 'withdrawal'].map(
    (kind, actionIndex) => {
      const rawTransactionHex = opTrueRawTransaction(
        actionIndex + 1,
        kind === 'withdrawal' ? 5 : 4,
      );
      const transaction = parseV2RawTransaction(rawTransactionHex);
      const sourceOutputs = transaction.inputs.map((input, index) => {
        const serializedHex = Buffer.concat([
          u64(546),
          compact(1),
          Buffer.of(0x51),
        ]).toString('hex');
        return {
          index,
          outpoint: { ...input.outpoint },
          serializedHex,
          sha256: sha256(Buffer.from(serializedHex, 'hex')),
        };
      });
      const inputRoleLayout = [
        { index: 0, kind: 'verifier', ordinal: 0 },
        { index: 1, kind: 'binding', ordinal: null },
        { index: 2, kind: 'state', ordinal: null },
        { index: 3, kind: 'funding', ordinal: null },
      ];
      const outputRoleLayout = [
        { index: 0, kind: 'state', ordinal: null },
        { index: 1, kind: 'verifier', ordinal: 0 },
        { index: 2, kind: 'binding', ordinal: null },
        ...(kind === 'withdrawal'
          ? [{ index: 3, kind: 'withdrawal', ordinal: null }]
          : []),
        {
          index: kind === 'withdrawal' ? 4 : 3,
          kind: 'change',
          ordinal: null,
        },
      ];
      return {
        carrierCount: 1,
        inputCount: transaction.inputs.length,
        inputRoleLayout,
        inputRoles: deepClone(inputRoleLayout),
        kind,
        outputCount: transaction.outputs.length,
        outputRoleLayout,
        outputRoles: deepClone(outputRoleLayout),
        rawTransactionHex,
        rawTransactionSha256: sha256(transaction.bytes),
        serializedBytes: transaction.sizeBytes,
        sourceOutputs,
        transactionId: transaction.txid,
      };
    },
  );
  const manifestTransactions = transactions.map((entry) => {
    const {
      inputRoleLayout, outputRoleLayout, ...manifestEntry
    } = deepClone(entry);
    return manifestEntry;
  });
  const expectedTransactionsManifest = {
    identity,
    maintainerBenchmark: {},
    schema: V2_B02_TRANSACTIONS_SCHEMA,
    transactions: manifestTransactions,
  };
  return {
    b02Result: {
      ...identity,
      authorityArtifactSha256,
      hardPolicyCeilings: {
        everyInputUnlockingBytecodeBytes: 10_000,
        everyReportedVmResourcePercent: 100,
        serializedTransactionBytes: 100_000,
      },
      laneAuthorityArtifact,
      maintainerBenchmark: {},
      narrowerMargins: '90000/9500-non-blocking-risk-telemetry-only',
      transactions,
      transactionsManifestSha256:
        sha256(canonical(expectedTransactionsManifest)),
    },
    denominationSats: '1000',
    expectedAuthorityArtifactSha256: authorityArtifactSha256,
    expectedIdentity: identity,
    expectedTransactionsManifest,
    expectedTransactionsManifestSha256:
      sha256(canonical(expectedTransactionsManifest)),
    settlementPins: {
      bindingBaseSats: '546',
      bindingLockingBytecode: Buffer.of(0x53),
      stateBaseSats: '546',
      stateLockingBytecode: Buffer.of(0x54),
      verifierCarriers: [{
        baseValueSats: '546',
        lockingBytecode: Buffer.of(0x52),
      }],
    },
  };
}

function signEnvelope(privateKey, authoritySha256, authority, identity, artifacts, overrides = {}) {
  const statement = {
    artifacts,
    commands: authority.commands,
    completedAt: '2026-06-01T01:00:00.000Z',
    hardPolicyCeilings: {
      everyInputUnlockingBytecodeBytes: 10_000,
      everyReportedVmResourcePercent: 100,
      narrowerMargins: '90000/9500-non-blocking-risk-telemetry-only',
      serializedTransactionBytes: 100_000,
    },
    identity,
    machine: {
      architecture: 'x86_64',
      benchmarkFilesystem: 'dedicated-nvme-ext4',
      bootId: '01234567-89ab-cdef-0123-456789abcdef',
      cpuModel: 'Benchmark CPU Model',
      hostname: 'benchmark-host-one',
      kernelRelease: '6.12.1',
      logicalCpus: 16,
      machineId: 'published-machine-one',
      operatingSystem: 'linux',
      totalMemoryBytes: String(32 * 1024 ** 3),
    },
    resources: {
      cgroupRoot: '/sys/fs/cgroup/q07/published-run-one',
      cgroupVersion: '2',
      coldIoProtocol: 'fresh-process-after-parent-closed-durable-store-no-page-cache-drop-claim',
      ioAccounting: 'proc-pid-io',
      isolation: 'dedicated-published-benchmark-machine',
      memoryAccounting: 'cgroup-v2-memory.peak',
    },
    runId: 'published-run-one',
    schema: V2_Q07_MACHINE_STATEMENT_SCHEMA,
    startedAt: '2026-06-01T00:00:00.000Z',
    toolchain: {
      lockfileSha256: hashLabel('lockfile'),
      nodeVersion: 'v22.17.0',
      packages: [
        {
          integritySha256: hashLabel('better-sqlite3'),
          name: 'better-sqlite3',
          version: '11.10.0',
        },
        {
          integritySha256: hashLabel('snarkjs'),
          name: 'snarkjs',
          version: '0.7.6',
        },
      ],
    },
    ...overrides,
  };
  const signature = sign(
    null,
    Buffer.concat([Buffer.from(ENVELOPE_DOMAIN), canonical(statement)]),
    privateKey,
  ).toString('base64');
  return {
    authorityArtifactSha256: authoritySha256,
    schema: V2_Q07_MACHINE_ENVELOPE_SCHEMA,
    signatureBase64: signature,
    signerId: authority.authority.authorityId,
    statement,
    statementSha256: sha256(canonical(statement)),
  };
}

function stateTokenPrefix(state, instanceId, denominationSats) {
  return Buffer.from(encodeTokenPrefix({
    amount: 0n,
    category: Uint8Array.from(Buffer.from(instanceId, 'hex').reverse()),
    nft: {
      capability: 'mutable',
      commitment: Uint8Array.from(encodeStateNftCommitment(
        state,
        { denominationSats },
      )),
    },
  }));
}

function createHistoryFixture(directory, identity, actionCount = 3) {
  const denominationSats = '10000000';
  const maximumLiveNotes = '32';
  const networkId = 2;
  const carrierCount = 10;
  const verifierCarriers = Array.from({ length: carrierCount }, (_, index) => ({
    baseValueSats: String(1_000 + index),
    lockingBytecode: Buffer.from(`52${String(index).padStart(2, '0')}ac`, 'hex'),
  }));
  const settlementPins = {
    bindingBaseSats: '2000',
    bindingLockingBytecode: Buffer.from('53aa', 'hex'),
    stateBaseSats: '3000',
    stateLockingBytecode: Buffer.from('54bb', 'hex'),
    verifierCarriers,
  };
  const noteAccumulator = createQ07NoteAccumulator();
  const nullifierStore = createIndexedNullifierQualificationStore({
    depth: Q07_NOTE_TREE_DEPTH,
    hashLeaf: hashIndexedNullifierLeaf,
    hashNode: hashIndexedNullifierNode,
    maximumInserts: actionCount - 1,
  });
  let state = {
    actionSequence: '0',
    maximumLiveNotes,
    noteCount: '0',
    noteRoot: auditQ07NoteAccumulator(noteAccumulator).rootHex,
    nullifierCount: '0',
    nullifierRoot: rootHex(nullifierStore.snapshot().root),
    profileId: identity.profileId,
    reserveSats: '0',
  };
  const initialStateBytes = encodeStateNftCommitment(
    state,
    { denominationSats },
  );
  const algorithmSources = [
    { path: 'algorithms/test-production.mjs', sha256: hashLabel('algorithm') },
  ];
  const header = {
    actionCount: String(actionCount),
    actionCounts: {
      deposit: '1',
      transfer: String(actionCount - 2),
      withdrawal: '1',
    },
    algorithmSources,
    classification: HISTORY_CLASS,
    denominationSats,
    identity,
    maximumLiveNotes,
    schema: V2_Q07_HISTORY_SCHEMA,
    type: 'header',
    version: '1',
  };
  const bodyLines = [canonical(header)];
  let transcript = createHash('sha256')
    .update(Buffer.from(HISTORY_DOMAIN)).update(canonical(header)).digest();
  const fundingP2pkh = `76a914${'11'.repeat(20)}88ac`;
  const changeP2pkh = `76a914${'22'.repeat(20)}88ac`;
  const withdrawalP2pkh = `76a914${'33'.repeat(20)}88ac`;
  for (let ordinal = 1; ordinal <= actionCount; ordinal += 1) {
    const kind = ordinal === 1
      ? 'deposit'
      : ordinal === actionCount ? 'withdrawal' : 'transfer';
    const outputNoteLeaf = kind === 'withdrawal'
      ? '0'.repeat(64)
      : BigInt(ordinal).toString(16).padStart(64, '0');
    const publicNullifier = kind === 'deposit'
      ? '0'.repeat(64)
      : BigInt(100 + ordinal).toString(16).padStart(64, '0');
    let noteRoot = state.noteRoot;
    if (kind !== 'withdrawal') {
      noteRoot = appendQ07Note(
        noteAccumulator,
        Buffer.from(outputNoteLeaf, 'hex'),
      ).postRoot.toString('hex');
    }
    let nullifierRoot = state.nullifierRoot;
    if (kind !== 'deposit') {
      nullifierRoot = rootHex(
        nullifierStore.insert(BigInt(`0x${publicNullifier}`)).root,
      );
    }
    const postState = {
      actionSequence: String(ordinal),
      maximumLiveNotes,
      noteCount: String(Number(state.noteCount) + (kind === 'withdrawal' ? 0 : 1)),
      noteRoot,
      nullifierCount: String(Number(state.nullifierCount) + (kind === 'deposit' ? 0 : 1)),
      nullifierRoot,
      profileId: identity.profileId,
      reserveSats: kind === 'deposit'
        ? denominationSats
        : kind === 'withdrawal' ? '0' : state.reserveSats,
    };
    const inputs = verifierCarriers.map((entry, index) => ({
      lockingBytecode: entry.lockingBytecode,
      outpointIndex: String(index),
      outpointTransactionHash: hashLabel(`history/${ordinal}/verifier/${index}`),
      role: { kind: 'verifier', ordinal: String(index) },
      sequence: '0',
      tokenPrefix: Buffer.alloc(0),
      valueSats: entry.baseValueSats,
    }));
    inputs.push({
      lockingBytecode: settlementPins.bindingLockingBytecode,
      outpointIndex: '0',
      outpointTransactionHash: hashLabel(`history/${ordinal}/binding`),
      role: { kind: 'binding', ordinal: '0' },
      sequence: '0',
      tokenPrefix: Buffer.alloc(0),
      valueSats: settlementPins.bindingBaseSats,
    }, {
      lockingBytecode: settlementPins.stateLockingBytecode,
      outpointIndex: '0',
      outpointTransactionHash: hashLabel(`history/${ordinal}/state`),
      role: { kind: 'state', ordinal: '0' },
      sequence: '0',
      tokenPrefix: stateTokenPrefix(state, identity.instanceId, denominationSats),
      valueSats: String(BigInt(settlementPins.stateBaseSats) + BigInt(state.reserveSats)),
    });
    const outputs = [{
      lockingBytecode: settlementPins.stateLockingBytecode,
      role: { kind: 'state', ordinal: '0' },
      tokenPrefix: stateTokenPrefix(postState, identity.instanceId, denominationSats),
      valueSats: String(BigInt(settlementPins.stateBaseSats) + BigInt(postState.reserveSats)),
    }, ...verifierCarriers.map((entry, index) => ({
      lockingBytecode: entry.lockingBytecode,
      role: { kind: 'verifier', ordinal: String(index) },
      tokenPrefix: Buffer.alloc(0),
      valueSats: entry.baseValueSats,
    })), {
      lockingBytecode: settlementPins.bindingLockingBytecode,
      role: { kind: 'binding', ordinal: '0' },
      tokenPrefix: Buffer.alloc(0),
      valueSats: settlementPins.bindingBaseSats,
    }];
    if (kind === 'withdrawal') outputs.push({
      lockingBytecode: Buffer.from(withdrawalP2pkh, 'hex'),
      role: { kind: 'withdrawal', ordinal: '0' },
      tokenPrefix: Buffer.alloc(0),
      valueSats: denominationSats,
    });
    outputs.push({
      lockingBytecode: Buffer.from(changeP2pkh, 'hex'),
      role: { kind: 'change', ordinal: '0' },
      tokenPrefix: Buffer.alloc(0),
      valueSats: '2000',
    });
    const fixedInput = inputs.reduce(
      (sum, entry) => sum + BigInt(entry.valueSats),
      0n,
    );
    const outputTotal = outputs.reduce(
      (sum, entry) => sum + BigInt(entry.valueSats),
      0n,
    );
    const fundingValue = outputTotal + 100n - fixedInput;
    assert(fundingValue > 0n);
    inputs.push({
      lockingBytecode: Buffer.from(fundingP2pkh, 'hex'),
      outpointIndex: '0',
      outpointTransactionHash: hashLabel(`history/${ordinal}/funding`),
      role: { kind: 'funding', ordinal: '0' },
      sequence: '0',
      tokenPrefix: Buffer.alloc(0),
      valueSats: fundingValue.toString(),
    });
    const contextBytes = encodeDirectV2TransactionContext({
      inputs,
      instanceId: identity.instanceId,
      kind,
      locktime: '0',
      networkId,
      outputs,
      postActionSequence: postState.actionSequence,
      preActionSequence: state.actionSequence,
      profileId: identity.profileId,
      transactionVersion: '2',
    }, { carrierCount });
    const contextSha256 = sha256(contextBytes);
    const packet = encodeActionPacket({
      encryptedRecord: kind === 'withdrawal'
        ? Buffer.alloc(128)
        : Buffer.alloc(128, ordinal),
      instanceId: identity.instanceId,
      kind,
      networkId,
      outputNoteLeaf,
      postState,
      preState: state,
      publicNullifier,
      transactionContextHash: contextSha256,
      withdrawalLockingBytecodeHash: kind === 'withdrawal'
        ? sha256(Buffer.from(withdrawalP2pkh, 'hex'))
        : '0'.repeat(64),
    }, { denominationSats });
    const payload = {
      contextHex: contextBytes.toString('hex'),
      contextSha256,
      kind,
      ordinal: String(ordinal),
      packetHex: packet.toString('hex'),
      packetSha256: sha256(packet),
      publicLockingBytecodes: {
        changeOutputHex: changeP2pkh,
        fundingInputHex: fundingP2pkh,
        withdrawalOutputHex: kind === 'withdrawal' ? withdrawalP2pkh : null,
      },
      schema: V2_Q07_HISTORY_SCHEMA,
      type: 'action',
    };
    transcript = createHash('sha256')
      .update(Buffer.from(HISTORY_DOMAIN)).update(transcript)
      .update(canonical(payload)).digest();
    const record = {
      ...payload,
      actionTranscriptSha256: transcript.toString('hex'),
    };
    bodyLines.push(canonical(record));
    state = postState;
  }
  const body = Buffer.concat(bodyLines.map((line) => Buffer.concat([line, Buffer.from('\n')])));
  const terminalStateHex = encodeStateNftCommitment(
    state,
    { denominationSats },
  ).toString('hex');
  const end = {
    actionCount: String(actionCount),
    actionCounts: header.actionCounts,
    actionTranscriptSha256: transcript.toString('hex'),
    bodySha256: sha256(body),
    recordCount: String(actionCount + 2),
    schema: V2_Q07_HISTORY_SCHEMA,
    terminal: {
      actionSequence: String(actionCount),
      liveNotes: '0',
      noteCount: String(actionCount - 1),
      noteRoot: state.noteRoot,
      nullifierCount: String(actionCount - 1),
      nullifierRoot: state.nullifierRoot,
      reserveSats: '0',
    },
    terminalStateHex,
    terminalStateSha256: sha256(Buffer.from(terminalStateHex, 'hex')),
    type: 'end',
    version: '1',
  };
  const file = Buffer.concat([body, canonical(end), Buffer.from('\n')]);
  const path = resolve(directory, 'history.ndjson');
  writeFileSync(path, file, { mode: 0o600 });
  return {
    path,
    spec: {
      algorithmSources,
      carrierCount,
      denominationSats,
      identity,
      initialStateBytes,
      maximumLiveNotes,
      networkId,
      settlementPins,
      stateContext: { denominationSats },
    },
  };
}

function stubB02Result(identity) {
  return {
    ...identity,
    completeTestEvidence: 'explicit-test-b02-evidence',
    hardPolicyCeilings: {
      everyInputUnlockingBytecodeBytes: 10_000,
      everyReportedVmResourcePercent: 100,
      serializedTransactionBytes: 100_000,
    },
    narrowerMargins: '90000/9500-non-blocking-risk-telemetry-only',
  };
}
function stubB02Revalidator(value) {
  if (value.completeTestEvidence !== 'explicit-test-b02-evidence') {
    throw new Error('test B-02 evidence is incomplete');
  }
  return {
    maximumSerializedTransactionBytes: 99_999,
    maximumUnlockingBytecodeBytes: 9_999,
    peakVmResourcePercentBasisPoints: 9_999,
    testEvidenceSha256: sha256(canonical(value)),
  };
}

function resultFixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const identity = identityFixture();
  const authority = authorityFixture(publicKeyPem);
  const authoritySha256 = sha256(canonical(authority));
  const samples = sampleEvidenceFixture(authority, identity);
  const sampleValidation = validateV2Q07SampleManifestForTestOnly(
    samples.manifest,
    {
      authorityArtifact: authority,
      expectedHistoryVerification: samples.historyVerification,
      expectedIdentity: identity,
      inventory: samples.inventory,
      rawSamples: samples.rawEntries,
    },
  );
  const embeddedSamples = sampleValidation.rawSamples;
  const sampleSet = embeddedSamples.map((entry) => ({
    inputArtifactSha256: entry.inputArtifact.sha256,
    outputArtifactSha256: entry.outputArtifact.sha256,
    path: entry.path,
    sha256: entry.sha256,
    stderrSha256: entry.value.execution.stderr.sha256,
    stdoutSha256: entry.value.execution.stdout.sha256,
  }));
  const historyVerification = {
    actionCount: '100000',
    actionCounts: { deposit: '1', transfer: '99998', withdrawal: '1' },
    actionTranscriptSha256: hashLabel('history-transcript'),
    algorithmSources: [
      { path: 'algorithms/test-production.mjs', sha256: hashLabel('algorithm') },
    ],
    bodySha256: hashLabel('history-body'),
    chainAuthenticated: false,
    checkpoints: samples.historyVerification.checkpoints,
    fileSha256: samples.historyVerification.fileSha256,
    terminal: {
      actionSequence: '100000',
      liveNotes: '0',
      noteCount: '99999',
      noteRoot: hashLabel('note-root'),
      nullifierCount: '99999',
      nullifierRoot: hashLabel('nullifier-root'),
      reserveSats: '0',
    },
    terminalStateHex: 'ab'.repeat(128),
    terminalStateSha256: sha256(Buffer.from('ab'.repeat(128), 'hex')),
  };
  const q02Verification = {
    cases: 768,
    descriptorSha256: identity.descriptorSha256,
    externalLaneRuns: 33_024,
    manifestSha256: identity.manifestSha256,
    mutations: 9_984,
    q02Qualified: true,
    releaseBootstrapSha256: identity.releaseBootstrapSha256,
    releaseRootId: identity.releaseRootId,
    schema: 'shieldkit-v2-direct-q02-final-key-corpus-v2',
  };
  const b02Result = stubB02Result(identity);
  const b02Revalidation = stubB02Revalidator(b02Result);
  const inventorySha256 = sha256(canonical(samples.inventory));
  const artifacts = {
    b02ResultSha256: sha256(canonical(b02Result)),
    b02RevalidationSha256: sha256(canonical(b02Revalidation)),
    historySha256: historyVerification.fileSha256,
    historyVerificationSha256: sha256(canonical(historyVerification)),
    inventorySha256,
    q02CorpusSha256: hashLabel('q02-corpus'),
    q02VerificationSha256: sha256(canonical(q02Verification)),
    samplesManifestSha256: sha256(canonical(samples.manifest)),
    samplesVerificationSha256: sha256(canonical({
      performance: sampleValidation.performance,
      rawSampleSetSha256: sha256(canonical(sampleSet)),
    })),
  };
  const envelope = signEnvelope(
    privateKey,
    authoritySha256,
    authority,
    identity,
    artifacts,
  );
  const result = {
    authorityArtifact: authority,
    authorityArtifactSha256: authoritySha256,
    b02Result,
    b02Revalidation,
    evidenceEnvelope: envelope,
    evidenceEnvelopeSha256: sha256(canonical(envelope)),
    evidenceInventory: samples.inventory,
    evidenceInventorySha256: inventorySha256,
    hardPolicyCeilings: {
      everyInputUnlockingBytecodeBytes: 10_000,
      everyReportedVmResourcePercent: 100,
      narrowerMargins: '90000/9500-non-blocking-risk-telemetry-only',
      serializedTransactionBytes: 100_000,
    },
    historyVerification,
    identity,
    performance: sampleValidation.performance,
    production: false,
    q02Verification,
    q07Qualified: true,
    rawSamples: embeddedSamples,
    releaseQualified: false,
    samplesManifest: samples.manifest,
    schema: V2_Q07_FINAL_PERFORMANCE_SCHEMA,
    status: 'q07-qualified-final-performance-not-production-or-release',
  };
  const expectedTrustRoots = {
    authorityArtifactSha256: authoritySha256,
    authorityPublicKeyPem: publicKeyPem,
    b02Identity: identity,
    b02ResultSha256: sha256(canonical(b02Result)),
    historySha256: historyVerification.fileSha256,
    historyVerificationSha256: sha256(canonical(historyVerification)),
    identity,
    q02CorpusSha256: artifacts.q02CorpusSha256,
    q02Verification,
    storeArtifact: samples.storeArtifact,
  };
  return {
    authority, artifacts, expectedTrustRoots, identity, privateKey, result,
  };
}

test('Q-07 CLI is exact and rejects ambiguous legacy inputs', () => {
  assert.throws(
    () => parseV2Q07FinalPerformanceArguments(['--test-only', 'yes']),
    V2Q07FinalPerformanceError,
  );
  const base = [
    '--profile-core', '/profile.json',
    '--descriptor', '/descriptor.json',
    '--final-manifest', '/manifest.json',
    '--release-root', 'release-root',
    '--q02-corpus', '/q02.json',
    '--b02-result', '/b02.json',
    '--evidence-dir', '/evidence',
    '--expected-commit', 'a'.repeat(40),
    '--expected-tree', 'b'.repeat(40),
    '--output-dir', '/out',
  ];
  assert.equal(
    parseV2Q07FinalPerformanceArguments(base).releaseRootId,
    'release-root',
  );
  assert.throws(
    () => parseV2Q07FinalPerformanceArguments(
      base.map((value) => value === 'release-root' ? '../caller-controlled' : value),
    ),
    /arguments are incomplete or expected pins are malformed/u,
  );
  assert.throws(
    () => parseV2Q07FinalPerformanceArguments([
      ...base.slice(0, -2), '--evidence-dir', '/other',
    ]),
    V2Q07FinalPerformanceError,
  );
});

test('Q-07 refuses ambient loader controls and a clean child resolves the compiled root first', () => {
  const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    key !== 'NODE_OPTIONS' && key !== 'NODE_PATH' && key !== 'NODE_TEST_CONTEXT'
    && !key.startsWith('LD_') && !key.startsWith('DYLD_')));
  const command = [
    fileURLToPath(new URL('./v2-q07-final-performance.mjs', import.meta.url)),
    '--profile-core', '/must-not-open/profile.json',
    '--descriptor', '/must-not-open/descriptor.json',
    '--final-manifest', '/must-not-open/manifest.json',
    '--release-root', 'unapproved-release-root-test',
    '--q02-corpus', '/must-not-open/q02.json',
    '--b02-result', '/must-not-open/b02.json',
    '--evidence-dir', '/must-not-open/evidence',
    '--expected-commit', 'a'.repeat(40),
    '--expected-tree', 'b'.repeat(40),
    '--output-dir', '/must-not-create/q07-output',
  ];
  const unsafeChild = spawnSync(process.execPath, command, {
    encoding: 'utf8',
    env: { ...environment, NODE_PATH: '/must-not-load' },
    maxBuffer: 1024 * 1024,
  });
  assert.equal(unsafeChild.error, undefined);
  assert.equal(unsafeChild.status, 1);
  assert.equal(unsafeChild.signal, null);
  assert.equal(unsafeChild.stdout, '');
  assert.match(
    unsafeChild.stderr,
    /refuses ambient loader, module-path, preload, or dynamic-linker controls/u,
  );

  const child = spawnSync(process.execPath, command, {
    encoding: 'utf8',
    env: environment,
    maxBuffer: 1024 * 1024,
  });
  assert.equal(child.error, undefined);
  assert.equal(child.status, 1);
  assert.equal(child.signal, null);
  assert.equal(child.stdout, '');
  assert.match(
    child.stderr,
    /no approved V2 Direct final release roots|release root id is not approved/u,
  );
  assert.doesNotMatch(
    child.stderr,
    /refuses ambient loader, module-path, preload, or dynamic-linker controls/u,
  );
});

test('Q-07 pre-final policy accepts authority/policy only and rejects post-final hashes', () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  const authority = authorityFixture(
    publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  );
  assert.equal(
    validateV2Q07AuthorityForTestOnly(authority).schema,
    V2_Q07_BENCHMARK_AUTHORITY_SCHEMA,
  );
  const invalid = { ...authority, reportSha256: hashLabel('post-final') };
  assert.throws(
    () => validateV2Q07AuthorityForTestOnly(invalid),
    V2Q07FinalPerformanceError,
  );
});

test('Q-07 validates exact raw 32-sample phases, boundary percentiles, cold I/O, resources, and inventory', () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  const authority = authorityFixture(
    publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  );
  const evidence = sampleEvidenceFixture(authority, identityFixture());
  const verified = validateV2Q07SampleManifestForTestOnly(
    evidence.manifest,
    {
      authorityArtifact: authority,
      expectedHistoryVerification: evidence.historyVerification,
      expectedIdentity: identityFixture(),
      inventory: evidence.inventory,
      rawSamples: evidence.rawEntries,
    },
  );
  assert.equal(verified.performance.proofP95Nanoseconds, '60000000000');
  assert.equal(verified.performance.warmRatioBasisPoints, '11000');
  assert.equal(
    verified.performance.storeBytes,
    evidence.manifest.storeBytes,
  );

  const tampered = deepClone(evidence.rawEntries);
  const sample = tampered.find((entry) =>
    entry.value?.schema === V2_Q07_RAW_SAMPLE_SCHEMA
      && entry.value.phase === 'proof-generation');
  sample.value.wallNanoseconds = '60000000001';
  assert.throws(
    () => validateV2Q07SampleManifestForTestOnly(evidence.manifest, {
      authorityArtifact: authority,
      expectedHistoryVerification: evidence.historyVerification,
      expectedIdentity: identityFixture(),
      inventory: evidence.inventory,
      rawSamples: tampered,
    }),
    V2Q07FinalPerformanceError,
  );

  const resourceEvidence = sampleEvidenceFixture(
    authority,
    identityFixture(),
  );
  const resourceSample = rawSampleEntry(resourceEvidence);
  resourceSample.value.rss.bytes = String(4 * 1024 ** 3 + 1);
  refreshReceiptEvidence(resourceEvidence, resourceSample);
  resourceEvidence.manifest.phases[0].reportedPeakRssBytes =
    resourceSample.value.rss.bytes;
  assert.throws(
    () => validateV2Q07SampleManifestForTestOnly(
      resourceEvidence.manifest,
      {
        authorityArtifact: authority,
        expectedHistoryVerification: resourceEvidence.historyVerification,
        expectedIdentity: identityFixture(),
        inventory: resourceEvidence.inventory,
        rawSamples: resourceEvidence.rawEntries,
      },
    ),
    /performance threshold/u,
  );

  const extraInventory = deepClone(evidence.inventory);
  extraInventory.artifacts.push({
    bytes: '1',
    classification: 'raw-command-output',
    path: 'z-extra.txt',
    sha256: hashLabel('extra'),
  });
  assert.throws(
    () => validateV2Q07SampleManifestForTestOnly(evidence.manifest, {
      authorityArtifact: authority,
      expectedHistoryVerification: evidence.historyVerification,
      expectedIdentity: identityFixture(),
      inventory: extraInventory,
      rawSamples: evidence.rawEntries,
    }),
    /missing, extra, or duplicate/u,
  );
});

test('Q-07 rejects arbitrary stdout/counters, omitted stores, and detached history checkpoints', () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  const authority = authorityFixture(
    publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  );
  const validate = (evidence) => validateV2Q07SampleManifestForTestOnly(
    evidence.manifest,
    {
      authorityArtifact: authority,
      expectedHistoryVerification: evidence.historyVerification,
      expectedIdentity: identityFixture(),
      inventory: evidence.inventory,
      rawSamples: evidence.rawEntries,
    },
  );

  const stdoutEvidence = sampleEvidenceFixture(authority, identityFixture());
  const stdoutSample = rawSampleEntry(stdoutEvidence);
  const stdout = stdoutEvidence.rawEntries.find((entry) =>
    entry.path === stdoutSample.value.execution.stdout.path);
  stdout.bytes = Buffer.from('arbitrary success text\n');
  stdout.sha256 = sha256(stdout.bytes);
  stdoutSample.value.execution.stdout.sha256 = stdout.sha256;
  updateInventoryArtifact(
    stdoutEvidence,
    stdout.path,
    stdout.bytes,
    stdout.sha256,
  );
  refreshRawSampleEvidence(stdoutEvidence, stdoutSample);
  assert.throws(
    () => validate(stdoutEvidence),
    /stdout receipt/u,
  );

  const counterEvidence = sampleEvidenceFixture(authority, identityFixture());
  const counterSample = rawSampleEntry(
    counterEvidence,
    'incremental-apply-1k',
  );
  counterSample.value.fixedDepthOperationCounts = {
    ...counterSample.value.fixedDepthOperationCounts,
    [V2_Q07_FIXED_DEPTH_COUNTER_KEYS[0]]: 999_999,
  };
  refreshRawSampleEvidence(counterEvidence, counterSample);
  assert.throws(
    () => validate(counterEvidence),
    /machine-readable receipt/u,
  );

  const missingStore = sampleEvidenceFixture(authority, identityFixture());
  missingStore.rawEntries = missingStore.rawEntries.filter((entry) =>
    entry.path !== missingStore.manifest.storeArtifact.path);
  assert.throws(
    () => validate(missingStore),
    /opaque artifact is missing/u,
  );

  const checkpointEvidence = sampleEvidenceFixture(
    authority,
    identityFixture(),
  );
  const checkpointSample = rawSampleEntry(
    checkpointEvidence,
    'incremental-apply-1k',
  );
  checkpointSample.value.state.startStateSha256 =
    hashLabel('attacker-detached-checkpoint');
  refreshRawSampleEvidence(checkpointEvidence, checkpointSample);
  assert.throws(
    () => validate(checkpointEvidence),
    /independently replayed history checkpoints/u,
  );
});

test('Q-07 rejects OP_TRUE B-02 settlements despite internally consistent raw transaction hashes', () => {
  assert.throws(
    () => validateV2Q07B02FinalPinsForTestOnly(
      opTrueB02FinalPinFixture(),
    ),
    /verifier source/u,
  );
});

test('Q-07 signed post-final envelope binds artifacts, identity, command, machine, and resources', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const authority = authorityFixture(
    publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  );
  const authoritySha256 = sha256(canonical(authority));
  const identity = identityFixture();
  const artifacts = Object.fromEntries([
    'b02ResultSha256', 'b02RevalidationSha256', 'historySha256',
    'historyVerificationSha256', 'inventorySha256', 'q02CorpusSha256',
    'q02VerificationSha256', 'samplesManifestSha256',
    'samplesVerificationSha256',
  ].map((key) => [key, hashLabel(key)]));
  const envelope = signEnvelope(
    privateKey,
    authoritySha256,
    authority,
    identity,
    artifacts,
  );
  assert.equal(
    verifyV2Q07PublishedEnvelopeForTestOnly({
      authorityArtifact: authority,
      authorityArtifactSha256: authoritySha256,
      envelope,
      expectedArtifacts: artifacts,
      expectedBootId: '01234567-89ab-cdef-0123-456789abcdef',
      expectedCgroupPaths: [
        '/sys/fs/cgroup/q07/published-run-one/sample',
      ],
      expectedEvidenceWindow: {
        end: Date.parse('2026-06-01T00:15:00.000Z'),
        start: Date.parse('2026-06-01T00:00:00.000Z'),
      },
      expectedIdentity: identity,
      expectedMachineRunId: 'published-run-one',
    }).runId,
    'published-run-one',
  );

  const badSignature = deepClone(envelope);
  badSignature.signatureBase64 =
    `${badSignature.signatureBase64[0] === 'A' ? 'B' : 'A'}${badSignature.signatureBase64.slice(1)}`;
  assert.throws(
    () => verifyV2Q07PublishedEnvelopeForTestOnly({
      authorityArtifact: authority,
      authorityArtifactSha256: authoritySha256,
      envelope: badSignature,
      expectedArtifacts: artifacts,
      expectedBootId: '01234567-89ab-cdef-0123-456789abcdef',
      expectedCgroupPaths: [
        '/sys/fs/cgroup/q07/published-run-one/sample',
      ],
      expectedEvidenceWindow: {
        end: Date.parse('2026-06-01T00:15:00.000Z'),
        start: Date.parse('2026-06-01T00:00:00.000Z'),
      },
      expectedIdentity: identity,
      expectedMachineRunId: 'published-run-one',
    }),
    /signature/u,
  );

  const resourceResign = signEnvelope(
    privateKey,
    authoritySha256,
    authority,
    identity,
    artifacts,
    {
      resources: {
        ...envelope.statement.resources,
        isolation: 'shared-benchmark-machine',
      },
    },
  );
  assert.throws(
    () => verifyV2Q07PublishedEnvelopeForTestOnly({
      authorityArtifact: authority,
      authorityArtifactSha256: authoritySha256,
      envelope: resourceResign,
      expectedArtifacts: artifacts,
      expectedBootId: '01234567-89ab-cdef-0123-456789abcdef',
      expectedCgroupPaths: [
        '/sys/fs/cgroup/q07/published-run-one/sample',
      ],
      expectedEvidenceWindow: {
        end: Date.parse('2026-06-01T00:15:00.000Z'),
        start: Date.parse('2026-06-01T00:00:00.000Z'),
      },
      expectedIdentity: identity,
      expectedMachineRunId: 'published-run-one',
    }),
    /resource policy/u,
  );
});

test('Q-07 replays descriptor-bound packet/context/tree history and rejects history or OP_TRUE tampering', () => {
  const directory = mkdtempSync(join(tmpdir(), 'shieldkit-q07-final-history-'));
  try {
    const fixture = createHistoryFixture(directory, identityFixture(), 3);
    const verified = verifyV2Q07FinalHistoryForTestOnly({
      actionCount: 3,
      path: fixture.path,
      spec: fixture.spec,
    });
    assert.deepEqual(verified.actionCounts, {
      deposit: '1',
      transfer: '1',
      withdrawal: '1',
    });
    assert.equal(verified.terminal.liveNotes, '0');
    assert.equal(verified.terminal.reserveSats, '0');

    const lines = readFileSync(fixture.path, 'utf8').trimEnd().split('\n');
    const first = JSON.parse(lines[1]);
    first.publicLockingBytecodes.fundingInputHex = '51';
    lines[1] = canonicalizeJcs(first);
    const opTruePath = resolve(directory, 'history-optrue.ndjson');
    writeFileSync(opTruePath, `${lines.join('\n')}\n`, { mode: 0o600 });
    assert.throws(
      () => verifyV2Q07FinalHistoryForTestOnly({
        actionCount: 3,
        path: opTruePath,
        spec: fixture.spec,
      }),
      /P2PKH/u,
    );

    const terminalLines = readFileSync(fixture.path, 'utf8').trimEnd().split('\n');
    const end = JSON.parse(terminalLines.at(-1));
    end.terminal.liveNotes = '1';
    terminalLines[terminalLines.length - 1] = canonicalizeJcs(end);
    const terminalPath = resolve(directory, 'history-terminal.ndjson');
    writeFileSync(terminalPath, `${terminalLines.join('\n')}\n`, { mode: 0o600 });
    assert.throws(
      () => verifyV2Q07FinalHistoryForTestOnly({
        actionCount: 3,
        path: terminalPath,
        spec: fixture.spec,
      }),
      /terminal/u,
    );
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test('Q-07 standalone result revalidator requires independent roots and rejects attacker authority, corpus, history, inventory, and B02 drift', () => {
  const fixture = resultFixture();
  const verified = revalidateV2Q07FinalPerformanceResultForTestOnly(
    fixture.result,
    {
      b02Revalidator: stubB02Revalidator,
      expectedTrustRoots: fixture.expectedTrustRoots,
    },
  );
  assert.equal(verified.performance.warmRatioBasisPoints, '11000');
  assert.throws(
    () => revalidateV2Q07FinalPerformanceResultForTestOnly(
      fixture.result,
      { b02Revalidator: stubB02Revalidator },
    ),
    /independent trust-root context/u,
  );

  const {
    privateKey: attackerPrivateKey,
    publicKey: attackerPublicKey,
  } = generateKeyPairSync('ed25519');
  const attackerAuthority = deepClone(fixture.result);
  attackerAuthority.authorityArtifact.authority.publicKeyPem =
    attackerPublicKey.export({ type: 'spki', format: 'pem' }).toString();
  attackerAuthority.authorityArtifactSha256 =
    sha256(canonical(attackerAuthority.authorityArtifact));
  attackerAuthority.evidenceEnvelope = signEnvelope(
    attackerPrivateKey,
    attackerAuthority.authorityArtifactSha256,
    attackerAuthority.authorityArtifact,
    attackerAuthority.identity,
    fixture.artifacts,
  );
  attackerAuthority.evidenceEnvelopeSha256 =
    sha256(canonical(attackerAuthority.evidenceEnvelope));
  assert.throws(
    () => revalidateV2Q07FinalPerformanceResultForTestOnly(
      attackerAuthority,
      {
        b02Revalidator: stubB02Revalidator,
        expectedTrustRoots: fixture.expectedTrustRoots,
      },
    ),
    /benchmark authority/u,
  );

  const signature = deepClone(fixture.result);
  signature.evidenceEnvelope.signatureBase64 =
    `${signature.evidenceEnvelope.signatureBase64[0] === 'A' ? 'B' : 'A'}${signature.evidenceEnvelope.signatureBase64.slice(1)}`;
  signature.evidenceEnvelopeSha256 = sha256(canonical(signature.evidenceEnvelope));
  assert.throws(
    () => revalidateV2Q07FinalPerformanceResultForTestOnly(signature, {
      b02Revalidator: stubB02Revalidator,
      expectedTrustRoots: fixture.expectedTrustRoots,
    }),
    /signature/u,
  );

  const history = deepClone(fixture.result);
  history.historyVerification.terminal.liveNotes = '1';
  assert.throws(
    () => revalidateV2Q07FinalPerformanceResultForTestOnly(history, {
      b02Revalidator: stubB02Revalidator,
      expectedTrustRoots: fixture.expectedTrustRoots,
    }),
    /terminal/u,
  );

  const detachedCheckpoint = deepClone(fixture.result);
  detachedCheckpoint.historyVerification.checkpoints[1].stateSha256 =
    hashLabel('attacker-history-prefix');
  assert.throws(
    () => revalidateV2Q07FinalPerformanceResultForTestOnly(
      detachedCheckpoint,
      {
        b02Revalidator: stubB02Revalidator,
        expectedTrustRoots: fixture.expectedTrustRoots,
      },
    ),
    /independent corpus\/replay pins/u,
  );

  const inventory = deepClone(fixture.result);
  inventory.evidenceInventory.artifacts.push({
    bytes: '1',
    classification: 'raw-command-output',
    path: 'z-extra.txt',
    sha256: hashLabel('extra-result'),
  });
  inventory.evidenceInventorySha256 = sha256(canonical(inventory.evidenceInventory));
  assert.throws(
    () => revalidateV2Q07FinalPerformanceResultForTestOnly(inventory, {
      b02Revalidator: stubB02Revalidator,
      expectedTrustRoots: fixture.expectedTrustRoots,
    }),
    /missing, extra, or duplicate/u,
  );

  const b02 = deepClone(fixture.result);
  b02.b02Result.completeTestEvidence = 'incomplete';
  assert.throws(
    () => revalidateV2Q07FinalPerformanceResultForTestOnly(b02, {
      b02Revalidator: stubB02Revalidator,
      expectedTrustRoots: fixture.expectedTrustRoots,
    }),
    /B-02 evidence is incomplete/u,
  );

  const arbitraryB02Hash = deepClone(fixture.result);
  arbitraryB02Hash.b02Result.attackerSelectedHashPayload = hashLabel(
    'attacker-selected-b02-payload',
  );
  arbitraryB02Hash.b02Revalidation = stubB02Revalidator(
    arbitraryB02Hash.b02Result,
  );
  assert.throws(
    () => revalidateV2Q07FinalPerformanceResultForTestOnly(
      arbitraryB02Hash,
      {
        b02Revalidator: stubB02Revalidator,
        expectedTrustRoots: fixture.expectedTrustRoots,
      },
    ),
    /independently supplied result hash/u,
  );

  const narrowedHardCeiling = deepClone(fixture.result);
  narrowedHardCeiling.hardPolicyCeilings.serializedTransactionBytes = 99_999;
  assert.throws(
    () => revalidateV2Q07FinalPerformanceResultForTestOnly(
      narrowedHardCeiling,
      {
        b02Revalidator: stubB02Revalidator,
        expectedTrustRoots: fixture.expectedTrustRoots,
      },
    ),
    /100000\/10000\/100% hard ceilings/u,
  );

  const q02 = deepClone(fixture.result);
  q02.q02Verification.externalLaneRuns -= 1;
  assert.throws(
    () => revalidateV2Q07FinalPerformanceResultForTestOnly(q02, {
      b02Revalidator: stubB02Revalidator,
      expectedTrustRoots: fixture.expectedTrustRoots,
    }),
    /Q-02 verification result is incomplete/u,
  );

  const detachedQ02 = deepClone(fixture.result);
  detachedQ02.q02Verification.descriptorSha256 =
    hashLabel('attacker-q02-descriptor');
  assert.throws(
    () => revalidateV2Q07FinalPerformanceResultForTestOnly(
      detachedQ02,
      {
        b02Revalidator: stubB02Revalidator,
        expectedTrustRoots: fixture.expectedTrustRoots,
      },
    ),
    /independent corpus replay/u,
  );
});
