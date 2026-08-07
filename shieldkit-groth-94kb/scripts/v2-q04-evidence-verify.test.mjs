import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createWriteStream, readFileSync } from 'node:fs';
import {
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  Q04_CHECKPOINT_PROBE_CASES,
  q04CheckpointProbeCaseDigest,
  q04CheckpointProbeResultDigest,
} from '../packages/pool/v2/qualification/q04-checkpoint-probes.mjs';
import {
  openQ04PersistentNullifierStore,
} from '../packages/pool/v2/qualification/persistent-nullifier-store.mjs';
import {
  Q04_CAMPAIGN_DEFINITION,
  Q04_CAMPAIGN_PROCESSES_SCHEMA,
  Q04_DEPTH4_SCHEMA,
  Q04_DEPTH4_CHECKER_RESULT_SCHEMA,
  Q04_DEPTH4_SCOPE,
  Q04_DEPTH4_STATUS,
  Q04_EDGE_SCHEDULE,
  Q04_EVIDENCE_SCHEMA,
  Q04_FIXED_OPERATION_COUNTS,
  Q04_FIXED_SEEDS,
  Q04_FR_MODULUS_HEX,
  Q04_HISTORY_RESULT_SCHEMA,
  Q04_KEY_DERIVATION,
  Q04_NULLIFIER_DOMAINS,
  Q04_POSEIDON_PROFILE,
  Q04_REQUIRED_PROBES,
  Q04_RESULT_SCHEMA,
  Q04_RUST_DOMAINS,
  Q04_RUST_KATS,
  Q04_RUST_KAT_SCHEMA,
  Q04_SEED_DERIVATION,
  Q04_SOURCE_DEFINITIONS,
  Q04_TRANSITION_SCHEMA,
  V2Q04EvidenceVerificationError,
  deriveQ04HistoryKeyHexes,
  deriveQ04HistoryTransitionSetSha256,
  deriveQ04SourceSetSha256,
  parseQ04EvidenceArguments,
  q04ReplayFieldHex,
  validateQ04Evidence,
  verifyQ04EvidenceFile,
} from './v2-q04-evidence-verify.mjs';
import {
  buildDepth4SymbolicCertificate,
  verifyDepth4SymbolicCertificate,
} from '../packages/pool/v2/qualification/depth4-symbolic-certificate.mjs';

/*
 * TEST-ONLY: these fixtures validate the evidence validator. They are synthetic
 * and are never Q-04 qualification or release evidence.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const workspaceRoot = path.resolve(here, '../..');
const parameterSourcePath = path.resolve(
  workspaceRoot,
  'node_modules/circomlib/circuits/poseidon_constants.circom',
);
const FR_MODULUS = BigInt(`0x${Q04_FR_MODULUS_HEX}`);
const INPUT_TRANSCRIPT_DOMAIN =
  'ShieldKit/PoolActionV2Direct/Q04/input-transcript/v1\0';
const STORE_INITIAL_DOMAIN =
  'ShieldKit/PoolActionV2Direct/Q04/persistent-store/v1\0';
const symbolicCertificateFixture = buildDepth4SymbolicCertificate();
const symbolicVerificationFixture =
  verifyDepth4SymbolicCertificate(symbolicCertificateFixture);

test('[test-only] production replay canonically encodes field bigints and bytes', () => {
  const root =
    12664281133148472406707814807810618891373839109772983981495615721629359924972n;
  const rootHex =
    '1bffbaa6bb28b38e9d7fe374d9b7ba4df4bb661c8b16aecb4ffe68a22301e6ec';
  assert.equal(q04ReplayFieldHex(root), rootHex);
  assert.equal(q04ReplayFieldHex(Buffer.from(rootHex, 'hex')), rootHex);
  assert.throws(
    () => q04ReplayFieldHex(-1n),
    /field bigint must be canonical/u,
  );
  assert.throws(
    () => q04ReplayFieldHex(FR_MODULUS),
    /field bigint must be canonical/u,
  );
  assert.throws(
    () => q04ReplayFieldHex(Buffer.alloc(31)),
    /field bytes must be exactly 32 bytes/u,
  );
});

test('[test-only] production replay crosses the real persistent-store ABI and survives aliasing plus reopen', async (t) => {
  const directory = await temporaryDirectory(t);
  const databasePath = path.join(directory, 'production-replay.sqlite');
  const historyIndex = 0;
  const seed = Buffer.from(Q04_FIXED_SEEDS[historyIndex], 'hex');
  const keyHex = deriveQ04HistoryKeyHexes(historyIndex, 1)[0];
  const inputKey = Buffer.from(keyHex, 'hex');
  let store = openQ04PersistentNullifierStore({
    path: databasePath,
    create: true,
    historyIndex,
    seed,
  });
  try {
    const before = store.state();
    const expectedRootInput = Buffer.from(before.root);
    const transition = store.insert({
      expectedCount: before.normalCount,
      expectedRoot: expectedRootInput,
      key: inputKey,
    });
    for (const field of ['preRoot', 'intermediateRoot', 'postRoot']) {
      assert.equal(typeof transition.mutation.witness[field], 'bigint');
      assert.match(
        q04ReplayFieldHex(transition.mutation.witness[field]),
        /^[0-9a-f]{64}$/u,
      );
    }
    const appendedIndex = transition.mutation.witness.append.index;
    const membership = store.membershipPath(appendedIndex);
    const returnedLeaf = store.leaf(appendedIndex);
    const after = store.state();
    const bufferSurfaces = [
      before.root,
      before.transcriptChainSha256,
      transition.writes.root,
      transition.mutation.nullifierLeaves.at(-1).key,
      membership.root,
      returnedLeaf.key,
      after.root,
      after.transcriptChainSha256,
    ];
    for (const value of bufferSurfaces) {
      assert.ok(Buffer.isBuffer(value));
      assert.equal(value.byteLength, 32);
      assert.match(q04ReplayFieldHex(value), /^[0-9a-f]{64}$/u);
    }
    assert.equal(
      q04ReplayFieldHex(transition.mutation.witness.preRoot),
      q04ReplayFieldHex(before.root),
    );
    assert.equal(
      q04ReplayFieldHex(transition.mutation.witness.postRoot),
      q04ReplayFieldHex(after.root),
    );
    const durableRootHex = q04ReplayFieldHex(after.root);
    const durableTranscriptHex =
      q04ReplayFieldHex(after.transcriptChainSha256);
    const aliasEvidence = {
      inputKey,
      expectedRootInput,
      stateRootResult: before.root,
      writeRootResult: transition.writes.root,
      mutationLeafKeyResult:
        transition.mutation.nullifierLeaves.at(-1).key,
      membershipRootResult: membership.root,
    };
    Object.values(aliasEvidence).forEach((value) => value.fill(0xff));
    assert.equal(q04ReplayFieldHex(store.audit().root), durableRootHex);
    assert.equal(
      q04ReplayFieldHex(store.state().root),
      durableRootHex,
    );
    assert.equal(q04ReplayFieldHex(store.leaf(appendedIndex).key), keyHex);
    store.close();
    store = null;
    store = openQ04PersistentNullifierStore({
      path: databasePath,
      create: false,
      historyIndex,
      seed,
    });
    assert.equal(q04ReplayFieldHex(store.state().root), durableRootHex);
    assert.equal(
      q04ReplayFieldHex(store.state().transcriptChainSha256),
      durableTranscriptHex,
    );
  } finally {
    store?.close();
  }
});

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fr(value) {
  return (BigInt(`0x${digest(value)}`) % FR_MODULUS)
    .toString(16)
    .padStart(64, '0');
}

function u32be(value) {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function bytesReference(pathname, contents) {
  const bytes = Buffer.from(contents);
  return {
    contents: bytes,
    reference: {
      path: pathname,
      bytes: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    },
  };
}

function addArtifact(artifacts, pathname, contents) {
  const item = bytesReference(pathname, contents);
  artifacts.set(pathname, item.contents);
  return item.reference;
}

function sourceEntries(artifacts, lane, definitions) {
  return definitions.map((definition, index) => {
    const extension = path.posix.extname(definition.originPath) || '.txt';
    const contents = readFileSync(
      path.resolve(workspaceRoot, definition.originPath),
    );
    return {
      role: definition.role,
      originPath: definition.originPath,
      artifact: addArtifact(
        artifacts,
        `sources/${lane}-${String(index).padStart(2, '0')}${extension}`,
        contents,
      ),
    };
  });
}

function lifecycleMeasurement(seed) {
  return {
    wallMs: 1,
    closeWallMs: 0,
    fsReadOps: seed,
    fsWriteOps: seed + 1,
    involuntaryContextSwitches: 0,
    peakRssBytes: 1_048_576 + seed,
    readBytes: seed + 2,
    systemCpuMicros: seed + 3,
    userCpuMicros: seed + 4,
    voluntaryContextSwitches: seed + 5,
    writeBytes: seed + 6,
  };
}

function openStorage(database, wal, shm) {
  return {
    fileBytes: { database, shm, wal },
    freeListCount: 0,
    journalMode: 'wal',
    pageCount: 4,
    pageSize: 4096,
    synchronous: 2,
    totalFileBytes: database + wal + shm,
  };
}

function closedStorage(database) {
  return {
    fileBytes: { database, shm: 0, wal: 0 },
    totalFileBytes: database,
  };
}

function checkpointFixture(historyIndex, checkpointIndex, root, transcript) {
  const afterEntry = (checkpointIndex + 1) * 1000;
  const processBase = 10_000 + (historyIndex * 100) + (checkpointIndex * 2);
  const preStateSha256 = digest(
    `history-${historyIndex}-checkpoint-${checkpointIndex}-state`,
  );
  const segmentMeasurement = lifecycleMeasurement(10 + checkpointIndex);
  const reopenMeasurement = lifecycleMeasurement(100 + checkpointIndex);
  const database = 1_000_000 + afterEntry + historyIndex;
  return {
    afterEntry,
    closeExitCode: 0,
    reopenExitCode: 0,
    actualRoot: root,
    oracleRoot: root,
    logicalStoreSha256: digest(
      `history-${historyIndex}-checkpoint-${checkpointIndex}-logical`,
    ),
    actualTranscriptSha256: transcript,
    oracleTranscriptSha256: transcript,
    probes: Q04_CHECKPOINT_PROBE_CASES.map((definition) => {
      const result = {
        caseId: definition.id,
        caseSha256: q04CheckpointProbeCaseDigest(definition),
        kind: definition.kind,
        expectedOutcome: definition.expectedOutcome,
        accepted: false,
        stateUnchanged: true,
        errorCode: definition.errorCode,
        inputSha256: digest(
          `history-${historyIndex}-checkpoint-${checkpointIndex}-${definition.kind}`,
        ),
        preStateSha256,
        postStateSha256: preStateSha256,
        rejection: `synthetic ${definition.kind} rejection`,
      };
      return {
        ...result,
        resultSha256: q04CheckpointProbeResultDigest(result),
      };
    }),
    discrepancies: 0,
    unexpectedAccepts: 0,
    workerPid: processBase,
    reopenPid: processBase + 1,
    writerOpenAndAuditWallMs: 1,
    reopenOpenAndAuditWallMs: 1,
    reopenParentLifecycleWallMs: 1,
    phaseMeasurement: {
      checkpointProbeAuditWallMs: 1,
      openAndStartAuditWallMs: 1,
      scheduleGenerationWallMs: 1,
      transitionLoopWallMs: 1,
    },
    segmentMeasurement,
    reopenMeasurement,
    storage: {
      segmentPreClose: openStorage(database, 128, 64),
      segmentPostClose: closedStorage(database),
      reopenPreClose: openStorage(database, 128, 64),
      reopenPostClose: closedStorage(database),
    },
  };
}

function syntheticRawMetadata(historyIndex) {
  const checkpoints = Array.from({ length: 25 }, (_, checkpointIndex) => ({
    root: fr(`synthetic-${historyIndex}-${checkpointIndex}-root`),
    transcript: digest(
      `synthetic-${historyIndex}-${checkpointIndex}-transcript`,
    ),
  }));
  const key = deriveQ04HistoryKeyHexes(historyIndex, 1)[0];
  const transitionDigestSha256 = digest(
    `synthetic-${historyIndex}-transition`,
  );
  const transcript = createHash('sha256')
    .update(
      createHash('sha256')
        .update(STORE_INITIAL_DOMAIN, 'ascii')
        .update(u32be(historyIndex))
        .update(Buffer.from(Q04_FIXED_SEEDS[historyIndex], 'hex'))
        .digest(),
    )
    .update(Buffer.from(transitionDigestSha256, 'hex'))
    .digest('hex');
  const preRoot = fr(`synthetic-${historyIndex}-pre`);
  const intermediateRoot = fr(`synthetic-${historyIndex}-intermediate`);
  const postRoot = fr(`synthetic-${historyIndex}-post`);
  const measurement = {
    wallMicros: 0,
    userCpuMicros: 0,
    systemCpuMicros: 0,
    voluntaryContextSwitches: 0,
    involuntaryContextSwitches: 0,
    rssBytes: 1,
  };
  const artifact = bytesReference(
    `raw/history-${historyIndex}-transitions.ndjson`,
    `${JSON.stringify({
      schema: Q04_TRANSITION_SCHEMA,
      historyIndex,
      ordinal: 1,
      key,
      preRoot,
      intermediateRoot,
      postRoot,
      pathDigests: {
        predecessorPathSha256: digest(`synthetic-${historyIndex}-pre-path`),
        emptyAppendPathSha256: digest(`synthetic-${historyIndex}-empty-path`),
        postMembershipPathSha256: digest(`synthetic-${historyIndex}-post-path`),
      },
      actual: {
        transitionDigestSha256,
        transcriptChainSha256: transcript,
        operationCounts: {
          productionLeafHashCalls: 3,
          productionPredecessorValidationLeafHashCalls: 1,
          productionMutationLeafHashCalls: 2,
          productionMutationNodeHashCalls: 128,
          productionLogicalPathSiblingLookups: 64,
          productionPathOverrideHits: 1,
          productionPathAdapterNodeReads: 63,
          productionRootAdapterNodeReads: 1,
          productionTotalAdapterNodeReads: 64,
          productionLeafReads: 2,
          productionOrderLookups: 2,
          productionPostMembershipNodeHashCalls: 32,
          productionPostMembershipNodeReads: 32,
        },
        measurement: { ...measurement, fsReadOps: 0, fsWriteOps: 0 },
      },
      oracle: {
        transitionDigestSha256,
        transcriptChainSha256: transcript,
        operationCounts: {
          leafHashCalls: 2,
          nodeHashCalls: 160,
          membershipPathComputations: 3,
          stateUpdatePaths: 2,
          treeDepth: 32,
        },
        measurement,
      },
      discrepancies: 0,
    })}\n`,
  );
  return {
    reference: artifact.reference,
    contents: artifact.contents,
    inputTranscriptSha256: digest(`synthetic-${historyIndex}-input`),
    checkpoints,
  };
}

function historyFixture(historyIndex, raw) {
  const checkpoints = raw.checkpoints.map((entry, checkpointIndex) =>
    checkpointFixture(
      historyIndex,
      checkpointIndex,
      entry.root,
      entry.transcript,
    )
  );
  const lifecycle = checkpoints.flatMap((checkpoint) => [
    checkpoint.segmentMeasurement,
    checkpoint.reopenMeasurement,
  ]);
  const finalCheckpoint = checkpoints.at(-1);
  const finalStorage = finalCheckpoint.storage.reopenPostClose;
  return {
    schema: Q04_HISTORY_RESULT_SCHEMA,
    configSha256: digest(`history-${historyIndex}-config`),
    qualifying: true,
    index: historyIndex,
    seed: Q04_FIXED_SEEDS[historyIndex],
    acceptedEntries: 25_000,
    inputTranscriptSha256: raw.inputTranscriptSha256,
    actualTranscriptSha256: finalCheckpoint.actualTranscriptSha256,
    oracleTranscriptSha256: finalCheckpoint.oracleTranscriptSha256,
    finalActualRoot: finalCheckpoint.actualRoot,
    finalOracleRoot: finalCheckpoint.oracleRoot,
    comparisons: {
      transitions: 25_000,
      predecessorMembershipPaths: 25_000,
      emptyAppendNonMembershipPaths: 25_000,
      postInsertionMembershipPaths: 25_000,
      discrepancies: 0,
    },
    checkpoints,
    measurements: {
      elapsedMs: 1000 + historyIndex,
      peakRssBytes:
        Math.max(...lifecycle.map((measurement) => measurement.peakRssBytes))
        + 1,
      databaseBytes: finalStorage.fileBytes.database,
      walBytes: finalStorage.fileBytes.wal,
      shmBytes: finalStorage.fileBytes.shm,
      totalFileBytes: finalStorage.totalFileBytes,
      readBytes: lifecycle.reduce(
        (total, measurement) => total + measurement.readBytes,
        0,
      ),
      writeBytes: lifecycle.reduce(
        (total, measurement) => total + measurement.writeBytes,
        0,
      ),
    },
    transitionArtifact: { ...raw.reference },
    oracleMetadata: {
      poseidon: {
        implementation:
          'independent-bigint-optimized-circomlib-poseidon-oracle-v1',
        parameterSourcePath,
        parameterSourceSha256:
          '94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee',
        supportedArities: [2, 3, 6],
      },
      tree: {
        implementation:
          'independent-treap-sparse-depth32-indexed-nullifier-oracle-v1',
        depth: 32,
        frModulusHex: Q04_FR_MODULUS_HEX,
        orderedSet: 'sha256-priority-treap',
      },
    },
  };
}

function rustKatResult() {
  return {
    schema: Q04_RUST_KAT_SCHEMA,
    status: 'kat-passed-local-only',
    metadata: {
      implementation: 'rust-light-poseidon-bn254-x5',
      lightPoseidonVersion: '0.4.0',
      arkBn254Version: '0.5.0',
      arkFfVersion: '0.5.0',
      sha2Version: '0.10.9',
      fieldModulusHex: Q04_FR_MODULUS_HEX,
      inputOrdering:
        'state=[0, domain, payload...] ; new_circom(input_count) ; canonical big-endian Fr',
      arities: [2, 3, 6],
    },
    claims: {
      independentImplementation: true,
      independentEmbeddedParameterArtifact: true,
      independentParameterGeneration: false,
      importsJavaScript: false,
      importsCircomTables: false,
      productionQualification: false,
      treeCampaign: false,
    },
    domains: Q04_RUST_DOMAINS.map((entry) => ({ ...entry })),
    knownAnswerTests: Q04_RUST_KATS.map((entry) => ({
      name: entry.name,
      arity: entry.inputs.length,
      inputs: [...entry.inputs],
      output: entry.output,
    })),
  };
}

function depth4Certificate() {
  const classes = Array.from(
    { length: 14 },
    (_, normalCount) =>
      normalCount === 0 ? 1 : normalCount * (normalCount + 1),
  );
  const nonlocalPermutationClasses = [
    0, 0, 0, 6, 20, 30, 42, 56, 72, 90, 110, 132, 156, 182,
  ];
  return {
    schema: Q04_DEPTH4_SCHEMA,
    status: 'pass',
    definition: {
      depth: 4,
      capacity: 16,
      authenticatedOccupancyDefinition:
        'all 2^16 empty/nonempty physical-leaf occupancy masks; ' +
        'sentinel-shaped leaves at 0/1 and index-distinct normal-shaped ' +
        'leaves at 2..15',
      indexedControlSkeletonDefinition:
        'one deterministic SQLite-backed control skeleton for every ' +
        'allocated count 0..13 and physically distinct valid adjacent ' +
        'predecessor/successor pair, with append at count+2; paired numeric ' +
        'embeddings and every eligible nonlocal rank permutation close, ' +
        'reopen, audit, and preserve the same normalized target trace',
      symbolicTemplateDefinition:
        'one exact shared-kernel symbolic template for each of 911 local ' +
        'control skeletons; untouched allocated leaf hashes remain free ' +
        'terms and predecessor/target/successor keys remain order-constrained ' +
        'variables',
    },
    claims: {
      productionPoseidon: true,
      independentPoseidonImplementation: true,
      authenticatedOccupancyStateSpaceExhaustive: true,
      indexedControlSkeletonsEnumerated: true,
      indexedControlSkeletonsAreStateQuotient: false,
      pairedNumericEmbeddingsUseSharedSqlite: true,
      nonlocalRankPermutationsUseSharedSqlite: true,
      everySqliteLaneReopenedAndAudited: true,
      sharedKernelSymbolicTemplatesChecked: true,
      sharedKernelSymbolicFormalTheorem: false,
      externalProofCheckerRequired: true,
      fullCapacityBoundaryCovered: true,
      terminalCapacityPrecedenceCovered: true,
      exhaustiveOverBn254Field: false,
      enumeratesAllFourteenKeyHistories: false,
      enumeratesAllDepth4IndexedHistories: false,
      largerDepthClaim: false,
    },
    occupancy: {
      statesChecked: 65_536,
      leafStateHashesChecked: 32,
      subtreeHashComparisons: 66_144,
      rootsSha256: digest('depth4-roots'),
    },
    indexed: {
      classes: 911,
      controlSkeletonIds: 911,
      setupTransitions: 9_100,
      alphaRenamedSetupTransitions: 9_100,
      targetTransitions: 911,
      alphaRenamedTargetTransitions: 911,
      alphaRenamingMismatches: 0,
      nonlocalPermutationClasses: 896,
      nonlocalPermutationSetupTransitions: 9_068,
      nonlocalPermutationTargetTransitions: 896,
      nonlocalPermutationMismatches: 0,
      sqliteScheduleLanes: 2_718,
      durableReopenChecks: 2_718,
      duplicateAttempts: 911,
      semanticDuplicateRejections: 729,
      terminalCapacityPrecedenceRejections: 182,
      failClosedDuplicateAttempts: 911,
      capacityRejected: true,
      capacityRejectedBeforeAdapterReads: true,
      allocatedCountsCovered: 14,
      minimumKeyCovered: true,
      maximumKeyCovered: true,
      productionPersistentKernel: true,
      qualificationSqliteAdapter: true,
      recordedLeafCalls: 107_694,
      recordedNodeCalls: 574_368,
      depth3: {
        definition:
          'all sum(n!, n=0..6)=874 rank permutations embedded in the first ' +
          'eight physical leaves of the fixed depth-4 production kernel; all ' +
          '873 valid next insertion gaps at counts 0..5',
        states: 874,
        setupTransitions: 5_039,
        targetTransitions: 873,
        fullStates: 720,
        sqliteStates: 874,
        durableReopenChecks: 874,
        controlTraceMismatches: 0,
        recordedLeafCalls: 17_736,
        recordedNodeCalls: 94_592,
      },
      controlTraceDigestSha256: digest('depth4-control-skeletons'),
      classBreakdown: classes.map((count, normalCount) => ({
        normalCount,
        classes: count,
        setupTransitions: count * normalCount,
        targetTransitions: count,
        nonlocalPermutationClasses:
          nonlocalPermutationClasses[normalCount],
        nonlocalPermutationSetupTransitions:
          nonlocalPermutationClasses[normalCount] * normalCount,
        nonlocalPermutationTargetTransitions:
          nonlocalPermutationClasses[normalCount],
        duplicateAttempts: count,
        semanticDuplicateRejections: normalCount === 13 ? 0 : count,
        terminalCapacityPrecedenceRejections:
          normalCount === 13 ? count : 0,
      })),
    },
    symbolic: {
      certificate: symbolicCertificateFixture,
      verification: symbolicVerificationFixture,
    },
    hashes: {
      comparisons: 748_238,
      discrepancies: 0,
      independentLeafCacheEntries: 1,
      independentNodeCacheEntries: 1,
      digestSha256: digest('depth4-hash-comparisons'),
    },
    oracle: {
      implementation:
        'independent-bigint-optimized-circomlib-poseidon-oracle-v1',
      parameterSourcePath,
      parameterSourceSha256:
        '94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee',
      supportedArities: [2, 3, 6],
    },
    discrepancies: 0,
    elapsedMs: 1,
    evidenceDigestSha256: digest('depth4-evidence'),
  };
}

function testOnlyBundle(rawMetadata = Q04_FIXED_SEEDS.map((_, index) =>
  syntheticRawMetadata(index)
)) {
  const artifacts = new Map();
  for (const raw of rawMetadata) {
    if (raw.contents !== undefined) {
      artifacts.set(raw.reference.path, Buffer.from(raw.contents));
    }
  }
  const productionSources = sourceEntries(
    artifacts,
    'production',
    Q04_SOURCE_DEFINITIONS.productionCore,
  );
  const primarySources = sourceEntries(
    artifacts,
    'primary-oracle',
    Q04_SOURCE_DEFINITIONS.primaryJsOracle,
  );
  const rustSources = sourceEntries(
    artifacts,
    'rust-kat',
    Q04_SOURCE_DEFINITIONS.rustKat,
  );
  const depth4CheckerSources = sourceEntries(
    artifacts,
    'depth4-checker',
    Q04_SOURCE_DEFINITIONS.depth4Checker,
  );
  const campaignSources = sourceEntries(
    artifacts,
    'campaign',
    Q04_SOURCE_DEFINITIONS.campaign,
  );
  const depth4Sources = sourceEntries(
    artifacts,
    'depth4',
    Q04_SOURCE_DEFINITIONS.depth4,
  );
  const source = (role, originPath, pathname) => ({
    role,
    originPath,
    artifact: addArtifact(
      artifacts,
      pathname,
      readFileSync(path.resolve(workspaceRoot, originPath)),
    ),
  });
  const rustResultReference = addArtifact(
    artifacts,
    'results/rust-kat.json',
    `${JSON.stringify(rustKatResult())}\n`,
  );
  const depth4Reference = addArtifact(
    artifacts,
    'results/depth4.json',
    `${JSON.stringify(depth4Certificate())}\n`,
  );
  const symbolicCertificateReference = addArtifact(
    artifacts,
    'results/depth4-symbolic.json',
    `${JSON.stringify(symbolicCertificateFixture)}\n`,
  );
  const binaryReference = addArtifact(
    artifacts,
    'bin/q04-poseidon-oracle',
    'TEST-ONLY Rust KAT executable bytes\n',
  );
  const checkerBinaryReference = addArtifact(
    artifacts,
    'bin/shieldkit-v2-q04-certificate',
    'TEST-ONLY Rust depth-4 checker executable bytes\n',
  );
  const checkerResultValue = {
    schema: Q04_DEPTH4_CHECKER_RESULT_SCHEMA,
    status: 'verified',
    certificateSchema: symbolicCertificateFixture.schema,
    certificateSha256: symbolicCertificateFixture.certificateSha256,
    productionSourceSha256:
      symbolicCertificateFixture.semanticCore.productionSourceSha256,
    checkerSourceSha256: depth4CheckerSources[0].artifact.sha256,
    controlSkeletons: 911,
    representedConcreteRankStateGapTransitions: '93928268313',
    proofCalculus: 'independent-rust-free-term-tree-reduction-v1',
    formalJavaScriptSemanticsClaim: false,
    stateQuotientClaim: false,
    collisionAssumptionForTermEquality: false,
  };
  const checkerResultReference = addArtifact(
    artifacts,
    'results/depth4-checker.json',
    `${JSON.stringify(checkerResultValue)}\n`,
  );
  const inputManifest = addArtifact(
    artifacts,
    'provenance/input-manifest.json',
    '{"TEST-ONLY":"input manifest"}\n',
  );
  const histories = rawMetadata.map((raw, index) =>
    historyFixture(index, raw)
  );
  const rawOutput = addArtifact(
    artifacts,
    'raw/campaign-processes.json',
    `${JSON.stringify({
      schema: Q04_CAMPAIGN_PROCESSES_SCHEMA,
      rustKat: {
        pid: 7001,
        exitCode: 0,
        signal: null,
        stdoutSha256: digest('rust-kat-stdout'),
        stderrSha256: digest('rust-kat-stderr'),
        binarySha256: binaryReference.sha256,
        buildElapsedMs: 100,
        runElapsedMs: 100,
      },
      depth4Checker: {
        pid: 7002,
        exitCode: 0,
        signal: null,
        stdoutSha256: digest('depth4-checker-stdout'),
        stderrSha256: digest('depth4-checker-stderr'),
        binarySha256: checkerBinaryReference.sha256,
        buildElapsedMs: 100,
        runElapsedMs: 100,
      },
      histories: histories.map((history, historyIndex) => ({
        historyIndex,
        pid: 7100 + historyIndex,
        exitCode: 0,
        signal: null,
        configSha256: history.configSha256,
        transitionArtifact: history.transitionArtifact,
        stdoutSha256: digest(`history-${historyIndex}-stdout`),
        stderrSha256: digest(`history-${historyIndex}-stderr`),
      })),
    })}\n`,
  );
  const resultTranscript = addArtifact(
    artifacts,
    'provenance/result-transcript.ndjson',
    '{"TEST-ONLY":"result transcript"}\n',
  );
  const evidence = {
    schema: Q04_EVIDENCE_SCHEMA,
    gate: 'Q-04',
    status: 'evidence-complete',
    subject: {
      repository: 'shieldkit-sdk-test-only',
      gitCommit: digest('test-commit').slice(0, 40),
      gitTree: digest('test-tree').slice(0, 40),
      workingTreeClean: true,
      poseidonProfile: Q04_POSEIDON_PROFILE,
      treeDepth: 32,
      frModulus: Q04_FR_MODULUS_HEX,
      nullifierDomains: { ...Q04_NULLIFIER_DOMAINS },
      sourceSetSha256: digest('source-set-placeholder'),
    },
    definition: {
      historyCount: 4,
      entriesPerHistory: 25_000,
      totalEntries: 100_000,
      checkpointInterval: 1000,
      checkpointsPerHistory: 25,
      seedDerivation: Q04_SEED_DERIVATION,
      keyDerivation: Q04_KEY_DERIVATION,
      seeds: [...Q04_FIXED_SEEDS],
      edgeSchedule: Q04_EDGE_SCHEDULE.map((entry) => ({ ...entry })),
      requiredProbeKinds: [...Q04_REQUIRED_PROBES],
    },
    implementations: {
      productionCore: {
        lane: 'per-transition-production-shared-core',
        entrypoint: 'Q04PersistentNullifierStore',
        sharedCore:
          'derivePersistentIndexedNullifierInsertion/applyPersistentIndexedNullifierMutation',
        directV2DirectStoreExercised: false,
        runtime: 'node',
        transitionComparisons: 100_000,
        treeDepth: 32,
        poseidonPackage: 'poseidon-lite@0.3.0',
        nodeVersion: process.version,
        sqliteVersion: '3.50.4',
        sources: productionSources,
      },
      primaryJsOracle: {
        lane: 'per-transition-primary-independent-oracle',
        poseidonImplementation:
          'independent-bigint-optimized-circomlib-poseidon-oracle-v1',
        treeImplementation:
          'independent-treap-sparse-depth32-indexed-nullifier-oracle-v1',
        orderedSet: 'sha256-priority-treap',
        runtime: 'node',
        transitionComparisons: 100_000,
        importsProductionCore: false,
        independentPoseidonImplementation: true,
        independentTreeImplementation: true,
        independentParameterGeneration: false,
        treeDepth: 32,
        frModulus: Q04_FR_MODULUS_HEX,
        supportedArities: [2, 3, 6],
        parameterPackage: 'circomlib@2.0.5',
        parameterSourceSha256:
          '94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee',
        nodeVersion: process.version,
        sources: primarySources,
      },
      rustKat: {
        lane: 'fixed-known-answer-cross-check-only',
        resultSchema: Q04_RUST_KAT_SCHEMA,
        implementation: 'rust-light-poseidon-bn254-x5',
        runtime: 'rust',
        transitionComparisons: 0,
        treeCampaign: false,
        productionQualification: false,
        independentImplementation: true,
        independentEmbeddedParameterArtifact: true,
        independentParameterGeneration: false,
        importsJavaScript: false,
        importsCircomTables: false,
        cargoLocked: true,
        domainsChecked: 6,
        knownAnswerTests: 10,
        packages: {
          lightPoseidon: '0.4.0',
          arkBn254: '0.5.0',
          arkFf: '0.5.0',
          sha2: '0.10.9',
        },
        rustVersion: 'rustc 1.97.1 (TEST-ONLY)',
        sources: rustSources,
        cargoManifest: source(
          'rust-kat-manifest',
          'shieldkit-groth-94kb/crates/shieldkit-v2-recovery/Cargo.toml',
          'sources/rust-kat-manifest.toml',
        ),
        cargoLock: source(
          'rust-kat-lockfile',
          'shieldkit-groth-94kb/crates/shieldkit-v2-recovery/Cargo.lock',
          'sources/rust-kat-lock.lock',
        ),
        rustToolchain: source(
          'rust-toolchain',
          'shieldkit-groth-94kb/rust-toolchain.toml',
          'sources/rust-toolchain.toml',
        ),
        binary: binaryReference,
        result: rustResultReference,
      },
      depth4Checker: {
        lane: 'independent-rust-free-term-certificate-checker',
        resultSchema: Q04_DEPTH4_CHECKER_RESULT_SCHEMA,
        runtime: 'rust',
        proofCalculus: 'independent-rust-free-term-tree-reduction-v1',
        controlSkeletons: 911,
        representedConcreteRankStateGapTransitions: '93928268313',
        formalJavaScriptSemanticsClaim: false,
        stateQuotientClaim: false,
        collisionAssumptionForTermEquality: false,
        cargoLocked: true,
        rustVersion: 'rustc 1.97.1 (TEST-ONLY)',
        sources: depth4CheckerSources,
        binary: checkerBinaryReference,
        result: checkerResultReference,
      },
    },
    operationCounts: { ...Q04_FIXED_OPERATION_COUNTS },
    hardware: {
      operatingSystem: 'TEST-ONLY Linux',
      architecture: 'x64',
      cpuModel: 'TEST-ONLY CPU',
      logicalCpuCount: 4,
      totalMemoryBytes: 8 * 1024 * 1024 * 1024,
      filesystem: 'TEST-ONLY filesystem',
    },
    runtime: {
      nodeVersion: process.version,
      rustVersion: 'rustc 1.97.1 (TEST-ONLY)',
      sqliteVersion: '3.50.4',
      startedAt: '2026-07-29T00:00:00.000Z',
      finishedAt: '2026-07-29T00:00:10.000Z',
      elapsedMs: 10_000,
      rustKatElapsedMs: 100,
      depth4CheckerElapsedMs: 100,
    },
    provenance: {
      generatedAt: '2026-07-29T00:00:11.000Z',
      commands: {
        campaign: {
          executable: 'node',
          arguments: ['shieldkit-groth-94kb/scripts/v2-q04-campaign.mjs'],
          workingDirectory: '.',
        },
        rustKatBuild: {
          executable: 'cargo',
          arguments: [
            '+1.97.1',
            'build',
            '--locked',
            '--release',
            '--bin',
            'q04-poseidon-oracle',
          ],
          workingDirectory:
            'shieldkit-groth-94kb/crates/shieldkit-v2-recovery',
        },
        rustKatRun: {
          executable: 'target/release/q04-poseidon-oracle',
          arguments: [],
          workingDirectory:
            'shieldkit-groth-94kb/crates/shieldkit-v2-recovery',
        },
        depth4CheckerBuild: {
          executable: 'cargo',
          arguments: [
            '+1.97.1',
            'build',
            '--locked',
            '--release',
            '--bin',
            'shieldkit-v2-q04-certificate',
          ],
          workingDirectory:
            'shieldkit-groth-94kb/crates/shieldkit-v2-q04-certificate',
        },
        depth4CheckerRun: {
          executable: 'bin/shieldkit-v2-q04-certificate',
          arguments: [
            'raw/depth4-symbolic-certificate.json',
            'snapshot/shieldkit-groth-94kb/packages/pool/v2/persistent-indexed-nullifier.mjs',
            'snapshot/shieldkit-groth-94kb/crates/shieldkit-v2-q04-certificate/src/main.rs',
          ],
          workingDirectory: '.',
        },
      },
      campaignSources,
      nodePackageLock: source(
        'node-lockfile',
        'package-lock.json',
        'sources/package-lock.json',
      ),
      inputManifest,
      rawOutput,
      resultTranscript,
    },
    hashes: {
      inputManifestSha256: inputManifest.sha256,
      rawOutputSha256: rawOutput.sha256,
      resultTranscriptSha256: resultTranscript.sha256,
      depth4CertificateSha256: depth4Reference.sha256,
      depth4SymbolicCertificateSha256:
        symbolicCertificateReference.sha256,
      depth4CheckerResultSha256: checkerResultReference.sha256,
      rustKatResultSha256: rustResultReference.sha256,
      sourceSetSha256: digest('source-set-placeholder'),
      historyTransitionSetSha256: digest('history-set-placeholder'),
    },
    depth4: {
      schema: Q04_DEPTH4_SCHEMA,
      status: Q04_DEPTH4_STATUS,
      scope: Q04_DEPTH4_SCOPE,
      productionQualification: true,
      sources: depth4Sources,
      symbolicCertificate: symbolicCertificateReference,
      certificate: depth4Reference,
    },
    histories,
    aggregate: {
      acceptedEntries: 100_000,
      checkpoints: 100,
      probesRun: 500,
      expectedRejections: 500,
      unexpectedAccepts: 0,
      discrepancies: 0,
      transitionComparisons: {
        productionCore: 100_000,
        primaryJsOracle: 100_000,
        rustKat: 0,
      },
      rustKatKnownAnswerTests: 10,
      rustKatDomainsChecked: 6,
    },
    claimBoundary: {
      entriesPerHistory: 25_000,
      aggregateEntries: 100_000,
      singleHistory100kMeasured: false,
      largerHistoryClaim: false,
      depth4Scope: Q04_DEPTH4_SCOPE,
      depth4EnumeratesAllKeyHistories: false,
      depth4LargerDepthClaim: false,
      depth4ProductionKernelEquivalenceProved: false,
      depth4ExternalCertificateCheckerVerified: true,
      formalJavaScriptSemanticsClaim: false,
    },
    verdict: {
      largeHistoryCampaign: 'pass',
      rustPoseidonKat: 'pass',
      depth4: 'verified-universal-template-with-nonformal-js-binding',
      q04Correctness:
        'pass-bounded-100000-and-depth4-shared-kernel',
      q07Performance: 'separate',
    },
  };
  const sourceSetSha256 = deriveQ04SourceSetSha256(evidence);
  evidence.subject.sourceSetSha256 = sourceSetSha256;
  evidence.hashes.sourceSetSha256 = sourceSetSha256;
  evidence.hashes.historyTransitionSetSha256 =
    deriveQ04HistoryTransitionSetSha256(evidence.histories);
  return { artifacts, evidence };
}

async function temporaryDirectory(t) {
  const temporaryRoot = path.join(workspaceRoot, '.tmp');
  await mkdir(temporaryRoot, { recursive: true });
  const directory = await mkdtemp(
    path.join(temporaryRoot, 'shieldkit-q04-v2-test-only-'),
  );
  t.after(async () => rm(directory, { recursive: true, force: true }));
  return directory;
}

async function writeBundle(directory, bundle) {
  for (const [pathname, contents] of bundle.artifacts) {
    const filename = path.join(directory, ...pathname.split('/'));
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, contents);
  }
  const evidencePath = path.join(directory, 'TEST-ONLY-evidence.json');
  await writeFile(evidencePath, `${JSON.stringify(bundle.evidence, null, 2)}\n`);
  return evidencePath;
}

async function generateRawHistory(directory, historyIndex) {
  const pathname = `raw/history-${historyIndex}-transitions.ndjson`;
  const filename = path.join(directory, ...pathname.split('/'));
  await mkdir(path.dirname(filename), { recursive: true });
  const output = createWriteStream(filename, { flags: 'wx', mode: 0o600 });
  const fileDigest = createHash('sha256');
  const inputTranscript = createHash('sha256')
    .update(INPUT_TRANSCRIPT_DOMAIN, 'ascii')
    .update(Buffer.from(Q04_FIXED_SEEDS[historyIndex], 'hex'));
  let storeTranscript = createHash('sha256')
    .update(STORE_INITIAL_DOMAIN, 'ascii')
    .update(u32be(historyIndex))
    .update(Buffer.from(Q04_FIXED_SEEDS[historyIndex], 'hex'))
    .digest();
  const keys = deriveQ04HistoryKeyHexes(historyIndex);
  const checkpoints = [];
  let bytes = 0;
  let preRoot = fr(`history-${historyIndex}-initial-root`);
  for (let offset = 0; offset < keys.length; offset += 1) {
    const ordinal = offset + 1;
    const key = keys[offset];
    const intermediateRoot = fr(
      `history-${historyIndex}-${ordinal}-intermediate`,
    );
    const postRoot = fr(`history-${historyIndex}-${ordinal}-post`);
    const transitionDigestSha256 = digest(
      `history-${historyIndex}-${ordinal}-transition`,
    );
    storeTranscript = createHash('sha256')
      .update(storeTranscript)
      .update(Buffer.from(transitionDigestSha256, 'hex'))
      .digest();
    const transcriptChainSha256 = storeTranscript.toString('hex');
    inputTranscript.update(Buffer.from(key, 'hex'));
    const measurement = {
      wallMicros: 0,
      userCpuMicros: 0,
      systemCpuMicros: 0,
      voluntaryContextSwitches: 0,
      involuntaryContextSwitches: 0,
      rssBytes: 1,
    };
    const line = `${JSON.stringify({
      schema: Q04_TRANSITION_SCHEMA,
      historyIndex,
      ordinal,
      key,
      preRoot,
      intermediateRoot,
      postRoot,
      pathDigests: {
        predecessorPathSha256: digest(
          `history-${historyIndex}-${ordinal}-predecessor-path`,
        ),
        emptyAppendPathSha256: digest(
          `history-${historyIndex}-${ordinal}-empty-path`,
        ),
        postMembershipPathSha256: digest(
          `history-${historyIndex}-${ordinal}-post-path`,
        ),
      },
      actual: {
        transitionDigestSha256,
        transcriptChainSha256,
        operationCounts: {
          productionLeafHashCalls: 3,
          productionPredecessorValidationLeafHashCalls: 1,
          productionMutationLeafHashCalls: 2,
          productionMutationNodeHashCalls: 128,
          productionLogicalPathSiblingLookups: 64,
          productionPathOverrideHits: 1,
          productionPathAdapterNodeReads: 63,
          productionRootAdapterNodeReads: 1,
          productionTotalAdapterNodeReads: 64,
          productionLeafReads: 2,
          productionOrderLookups: 2,
          productionPostMembershipNodeHashCalls: 32,
          productionPostMembershipNodeReads: 32,
        },
        measurement: {
          ...measurement,
          fsReadOps: 0,
          fsWriteOps: 0,
        },
      },
      oracle: {
        transitionDigestSha256,
        transcriptChainSha256,
        operationCounts: {
          leafHashCalls: 2,
          nodeHashCalls: 160,
          membershipPathComputations: 3,
          stateUpdatePaths: 2,
          treeDepth: 32,
        },
        measurement,
      },
      discrepancies: 0,
    })}\n`;
    const lineBytes = Buffer.from(line);
    fileDigest.update(lineBytes);
    bytes += lineBytes.length;
    if (!output.write(lineBytes)) await once(output, 'drain');
    preRoot = postRoot;
    if (ordinal % 1000 === 0) {
      checkpoints.push({ root: postRoot, transcript: transcriptChainSha256 });
    }
  }
  output.end();
  await once(output, 'finish');
  return {
    reference: {
      path: pathname,
      bytes,
      sha256: fileDigest.digest('hex'),
    },
    inputTranscriptSha256: inputTranscript.digest('hex'),
    checkpoints,
  };
}

test('[test-only] schema v3 binds exact lanes, checker, telemetry, source set, and replay boundary', () => {
  assert.deepEqual(Q04_CAMPAIGN_DEFINITION, {
    historyCount: 4,
    entriesPerHistory: 25_000,
    checkpointInterval: 1000,
    checkpointsPerHistory: 25,
    totalEntries: 100_000,
    treeDepth: 32,
    totalProbes: 500,
  });
  assert.ok(Object.isFrozen(Q04_CAMPAIGN_DEFINITION));
  assert.ok(Q04_SOURCE_DEFINITIONS.campaign.some((entry) =>
    entry.originPath ===
      'shieldkit-groth-94kb/scripts/v2-q04-campaign.mjs'
  ));
  const { evidence } = testOnlyBundle();
  const result = validateQ04Evidence(evidence);
  assert.equal(result.schema, Q04_RESULT_SCHEMA);
  assert.equal(result.status, 'structure-valid');
  assert.equal(result.q04GatePass, false);
  assert.equal(
    result.q04Verdict,
    'requires-file-and-cryptographic-replay',
  );
  assert.equal(result.depth4BoundedEvidenceVerified, null);
  assert.equal(result.sourceSetSha256, evidence.hashes.sourceSetSha256);
  assert.equal('profileId' in evidence.subject, false);
  assert.equal(
    evidence.operationCounts.productionLeafHashCallsPerTransition,
    3,
  );
  assert.equal(evidence.operationCounts.productionLeafHashCalls, 300_000);
});

test('[test-only] runtime lower bound accounts for four concurrent history lanes', () => {
  const { evidence } = testOnlyBundle();
  const longestHistoryElapsedMs = Math.max(
    ...evidence.histories.map((history) => history.measurements.elapsedMs),
  );
  const minimumWallElapsedMs =
    longestHistoryElapsedMs
    + evidence.runtime.rustKatElapsedMs
    + evidence.runtime.depth4CheckerElapsedMs;
  evidence.runtime.elapsedMs = minimumWallElapsedMs - 4;
  assert.doesNotThrow(() => validateQ04Evidence(evidence));
  evidence.runtime.elapsedMs = minimumWallElapsedMs - 5;
  assert.throws(
    () => validateQ04Evidence(evidence),
    /must cover the longest concurrent history/u,
  );
});

test('[test-only] structure validation rejects lane, telemetry, provenance, and overclaim drift', () => {
  const mutations = [
    ['unknown top-level field', (value) => { value.unknown = true; }],
    ['direct store string', (value) => {
      value.subject.repository = 'forbidden-V2DirectStore';
    }],
    ['node-write accounting', (value) => {
      value.operationCounts.productionNodeWrites = 1;
    }],
    ['dirty subject', (value) => { value.subject.workingTreeClean = false; }],
    ['profile dependency', (value) => {
      value.subject.profileId = `sha256:${digest('profile')}`;
    }],
    ['wrong git tree', (value) => { value.subject.gitTree = 'abc'; }],
    ['direct store exercised', (value) => {
      value.implementations.productionCore.directV2DirectStoreExercised = true;
    }],
    ['Rust transition oracle', (value) => {
      value.implementations.rustKat.transitionComparisons = 1;
    }],
    ['Rust tree campaign', (value) => {
      value.implementations.rustKat.treeCampaign = true;
    }],
    ['false production leaf count', (value) => {
      value.operationCounts.productionLeafHashCallsPerTransition = 2;
    }],
    ['old history schema', (value) => {
      value.histories[0].schema =
        'shieldkit-v2-direct/q04-history-result/v1';
    }],
    ['nonqualifying history', (value) => {
      value.histories[0].qualifying = false;
    }],
    ['reused worker PID', (value) => {
      value.histories[0].checkpoints[1].workerPid =
        value.histories[0].checkpoints[0].workerPid;
    }],
    ['nonzero close', (value) => {
      value.histories[0].checkpoints[0].closeExitCode = 1;
    }],
    ['missing phase metric', (value) => {
      delete value.histories[0].checkpoints[0]
        .phaseMeasurement.transitionLoopWallMs;
    }],
    ['final database mismatch', (value) => {
      value.histories[0].measurements.databaseBytes += 1;
      value.histories[0].measurements.totalFileBytes += 1;
    }],
    ['wrong parameter source path', (value) => {
      value.histories[0].oracleMetadata.poseidon.parameterSourcePath =
        '/tmp/unbound-parameters.circom';
    }],
    ['old Rust run executable', (value) => {
      value.provenance.commands.rustKatRun.executable =
        'q04-poseidon-oracle';
    }],
    ['wrong cargo cwd', (value) => {
      value.provenance.commands.rustKatBuild.workingDirectory = '.';
    }],
    ['missing campaign driver source', (value) => {
      value.provenance.campaignSources.splice(2, 1);
    }],
    ['depth4 qualification overclaim', (value) => {
      value.depth4.productionQualification = false;
    }],
    ['kernel equivalence overclaim', (value) => {
      value.claimBoundary.depth4ProductionKernelEquivalenceProved = true;
    }],
    ['Q-04 pass overclaim', (value) => {
      value.verdict.q04Correctness = 'pass';
    }],
    ['source set drift', (value) => {
      value.hashes.sourceSetSha256 = digest('wrong-source-set');
    }],
  ];
  for (const [label, mutate] of mutations) {
    const value = structuredClone(testOnlyBundle().evidence);
    mutate(value);
    assert.throws(
      () => validateQ04Evidence(value),
      V2Q04EvidenceVerificationError,
      label,
    );
  }
});

test('[test-only] file verifier rejects four exact-length self-consistent counterfeit histories', {
  timeout: 240_000,
}, async (t) => {
  const directory = await temporaryDirectory(t);
  const rawMetadata = [];
  for (let historyIndex = 0; historyIndex < 4; historyIndex += 1) {
    rawMetadata.push(await generateRawHistory(directory, historyIndex));
  }
  const bundle = testOnlyBundle(rawMetadata);
  const evidencePath = await writeBundle(directory, bundle);
  await assert.rejects(
    verifyQ04EvidenceFile(evidencePath),
    /independent replay/u,
  );
});

test('[test-only] exact certificate scope, record count, strict JSON, and canonical paths fail closed', async (t) => {
  assert.throws(
    () => parseQ04EvidenceArguments([]),
    V2Q04EvidenceVerificationError,
  );
  assert.throws(
    () => parseQ04EvidenceArguments(['relative/evidence.json']),
    V2Q04EvidenceVerificationError,
  );
  assert.throws(
    () => parseQ04EvidenceArguments(['/tmp/q04/../q04/evidence.json']),
    V2Q04EvidenceVerificationError,
  );

  const certificateDirectory = await temporaryDirectory(t);
  const certificateBundle = testOnlyBundle();
  const certificatePath = certificateBundle.evidence.depth4.certificate.path;
  const certificate = JSON.parse(
    certificateBundle.artifacts.get(certificatePath).toString(),
  );
  certificate.claims.enumeratesAllDepth4IndexedHistories = true;
  const replacement = bytesReference(
    certificatePath,
    `${JSON.stringify(certificate)}\n`,
  );
  certificateBundle.artifacts.set(certificatePath, replacement.contents);
  certificateBundle.evidence.depth4.certificate = replacement.reference;
  certificateBundle.evidence.hashes.depth4CertificateSha256 =
    replacement.reference.sha256;
  const certificateEvidencePath = await writeBundle(
    certificateDirectory,
    certificateBundle,
  );
  await assert.rejects(
    verifyQ04EvidenceFile(certificateEvidencePath),
    /enumeratesAllDepth4IndexedHistories/,
  );

  const processBindingDirectory = await temporaryDirectory(t);
  const processBindingBundle = testOnlyBundle();
  const processBindingPath =
    processBindingBundle.evidence.provenance.rawOutput.path;
  const processBinding = JSON.parse(
    processBindingBundle.artifacts.get(processBindingPath).toString(),
  );
  processBinding.rustKat.runElapsedMs += 1;
  const processBindingReplacement = bytesReference(
    processBindingPath,
    `${JSON.stringify(processBinding)}\n`,
  );
  processBindingBundle.artifacts.set(
    processBindingPath,
    processBindingReplacement.contents,
  );
  processBindingBundle.evidence.provenance.rawOutput =
    processBindingReplacement.reference;
  processBindingBundle.evidence.hashes.rawOutputSha256 =
    processBindingReplacement.reference.sha256;
  const processBindingEvidencePath = await writeBundle(
    processBindingDirectory,
    processBindingBundle,
  );
  await assert.rejects(
    verifyQ04EvidenceFile(processBindingEvidencePath),
    /campaign processes\.rustKat\.runElapsedMs/u,
  );

  const timingDirectory = await temporaryDirectory(t);
  const timingBundle = testOnlyBundle();
  const timingPath = timingBundle.evidence.provenance.rawOutput.path;
  const timingProcesses = JSON.parse(
    timingBundle.artifacts.get(timingPath).toString(),
  );
  timingProcesses.rustKat.buildElapsedMs =
    timingBundle.evidence.runtime.elapsedMs;
  const timingReplacement = bytesReference(
    timingPath,
    `${JSON.stringify(timingProcesses)}\n`,
  );
  timingBundle.artifacts.set(timingPath, timingReplacement.contents);
  timingBundle.evidence.provenance.rawOutput = timingReplacement.reference;
  timingBundle.evidence.hashes.rawOutputSha256 =
    timingReplacement.reference.sha256;
  const timingEvidencePath = await writeBundle(
    timingDirectory,
    timingBundle,
  );
  await assert.rejects(
    verifyQ04EvidenceFile(timingEvidencePath),
    /does not cover all serial build\/check phases/u,
  );

  const countDirectory = await temporaryDirectory(t);
  const countBundle = testOnlyBundle();
  const countEvidencePath = await writeBundle(countDirectory, countBundle);
  await assert.rejects(
    verifyQ04EvidenceFile(countEvidencePath),
    /invalid strict JSON|exactly 25000 records|execution source|independent replay/u,
  );

  const duplicateDirectory = await temporaryDirectory(t);
  const duplicatePath = path.join(duplicateDirectory, 'duplicate.json');
  await writeFile(
    duplicatePath,
    `{"schema":${JSON.stringify(Q04_EVIDENCE_SCHEMA)},"schema":${JSON.stringify(Q04_EVIDENCE_SCHEMA)}}\n`,
  );
  await assert.rejects(
    verifyQ04EvidenceFile(duplicatePath),
    /duplicate JSON object name/,
  );

  const symlinkPath = path.join(countDirectory, 'evidence-symlink.json');
  await symlink(countEvidencePath, symlinkPath);
  await assert.rejects(
    verifyQ04EvidenceFile(symlinkPath),
    /regular non-symlink file/,
  );
});
