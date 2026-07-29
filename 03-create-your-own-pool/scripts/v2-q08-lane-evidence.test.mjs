/* TEST-ONLY: ephemeral authorities and fixture chain are parser coverage, never qualification evidence. */
import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as signEnvelope,
} from 'node:crypto';
import { after, test } from 'node:test';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  createV2LocalVmEvidence,
  inspectV2LocalVmEvidence,
} from '../packages/kit/v2/vm-evidence.mjs';
import {
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  FIXTURE_INSTANCE_ID,
  FIXTURE_PROFILE_ID,
  FIXTURE_PROFILE_SHA256,
  createFixtureEvidence,
  createRollingFixtureArtifacts,
} from '../packages/kit/v2/v2-test-fixtures.mjs';
import {
  V2Q02LaneEvidenceError,
  V2_Q02_LANE_AUTHORITIES_SCHEMA,
  createV2Q02PinnedLaneAuthorityContext,
} from './v2-q02-lane-evidence.mjs';
import {
  V2Q08LaneEvidenceError,
  V2_Q08_BCHN_MINED_INPUT_SCHEMA,
  V2_Q08_BCHN_MINED_OUTPUT_SCHEMA,
  V2_Q08_LANE_ATTESTATION_DOMAIN,
  V2_Q08_LANE_ATTESTATION_VERSION,
  V2_Q08_LANE_ENVELOPE_SCHEMA,
  V2_Q08_MACHINE_MANIFEST_SCHEMA,
  V2_Q08_VM_INPUT_SCHEMA,
  V2_Q08_VM_OUTPUT_SCHEMA,
  verifyV2Q08ActionLaneEvidence,
} from './v2-q08-lane-evidence.mjs';

const root = mkdtempSync(join(tmpdir(), 'shieldkit-v2-q08-nonqualifying-'));
after(() => rmSync(root, { force: true, recursive: true }));

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hashLabel = (label) => sha256(Buffer.from(`TEST-ONLY-NONQUALIFYING:${label}`));
const jcsBytes = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');
const write = (directory, filename, bytes) => {
  const path = join(directory, filename);
  writeFileSync(path, bytes);
  return path;
};
const writeJcs = (directory, filename, value) => write(directory, filename, jcsBytes(value));
const reference = (directory, filename, value, { json = true } = {}) => {
  const bytes = json ? jcsBytes(value) : Buffer.from(value);
  write(directory, filename, bytes);
  return { path: filename, sha256: sha256(bytes) };
};
const hash256Display = (value) => createHash('sha256')
  .update(createHash('sha256').update(value).digest())
  .digest()
  .reverse()
  .toString('hex');
const u32 = (value) => {
  const result = Buffer.alloc(4);
  result.writeUInt32LE(value);
  return result;
};

const MAXIMUM_TARGET = `7fffff${'00'.repeat(29)}`;
const TARGET = BigInt(`0x${MAXIMUM_TARGET}`);
const HEADER_WORK = (1n << 256n) / (TARGET + 1n);
const TOPOLOGY_ID = 'pf10-fused-q-genesis-v1';
const STARTED_AT = '2026-07-29T00:00:00.100Z';
const COMPLETED_AT = '2026-07-29T00:00:00.200Z';
const CAPTURED_AT = '2026-07-29T00:00:00.150Z';

function mineHeader({ merkleRoot, previousBlockHash }) {
  for (let nonce = 0; nonce <= 0xffff_ffff; nonce += 1) {
    const header = Buffer.concat([
      u32(4),
      Buffer.from(previousBlockHash, 'hex').reverse(),
      Buffer.from(merkleRoot, 'hex').reverse(),
      u32(1_700_000_000),
      u32(0x207fffff),
      u32(nonce),
    ]);
    const id = hash256Display(header);
    if (BigInt(`0x${id}`) <= TARGET) return { hex: header.toString('hex'), id };
  }
  throw new Error('test-only low-difficulty header was unexpectedly not mined');
}

function makeContext({ carrierCount, transaction }) {
  const checkpointHash = hashLabel('checkpoint');
  const roles = ['maintainer', 'bchn-mempool', 'bchn-mined', 'leanbch'];
  const keys = new Map(roles.map((role) => [role, generateKeyPairSync('ed25519')]));
  const authorities = roles.map((role) => ({
    authorityId: `test-only-${role}`,
    command: {
      arguments: ['--test-only-nonqualifying'],
      executable: `shieldkit-test-only-${role}`,
    },
    organization: 'ShieldKit test-only nonqualifying fixture',
    publicKey: keys.get(role).publicKey.export({ format: 'pem', type: 'spki' }),
    role,
    tool: {
      commit: '0'.repeat(40),
      executableSha256: hashLabel(`${role}-executable`),
      lockfileSha256: hashLabel(`${role}-lockfile`),
      repositoryUrl: 'https://example.invalid/shieldkit-test-only',
      runnerSha256: hashLabel(`${role}-runner`),
      sourceSha256: hashLabel(`${role}-source`),
      tree: '1'.repeat(40),
      version: '1.0.0-test',
    },
  }));
  const pins = {
    descriptorSha256: hashLabel('descriptor'),
    finalLocksSha256: hashLabel('final-locks'),
    instanceId: FIXTURE_INSTANCE_ID,
    manifestSha256: hashLabel('manifest'),
    profileId: FIXTURE_PROFILE_ID,
    topologyId: TOPOLOGY_ID,
  };
  const artifact = {
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
    finalLocksSha256: pins.finalLocksSha256,
    instanceId: pins.instanceId,
    network: { id: 2, name: 'chipnet' },
    profileId: pins.profileId,
    schema: V2_Q02_LANE_AUTHORITIES_SCHEMA,
    topologyId: pins.topologyId,
  };
  const artifactBytes = jcsBytes(artifact);
  const context = createV2Q02PinnedLaneAuthorityContext({
    ...pins,
    artifactBytes,
    artifactSha256: sha256(artifactBytes),
  });
  const descriptor = {
    descriptorSha256: pins.descriptorSha256,
    finalLocksSha256: pins.finalLocksSha256,
    instanceId: pins.instanceId,
    manifestSha256: pins.manifestSha256,
    network: { id: 2, name: 'chipnet' },
    profileId: pins.profileId,
    topologyId: pins.topologyId,
  };
  const header = mineHeader({ merkleRoot: transaction.txid, previousBlockHash: checkpointHash });
  const mined = {
    headerSegment: {
      rawHeadersHex: [header.hex],
      tip: {
        blockHash: header.id,
        chainwork: HEADER_WORK.toString(10),
        height: 101,
      },
    },
    nodeObservation: {
      blockHash: header.id,
      chain: 'chipnet',
      confirmations: 1,
      initialBlockDownload: false,
      transactionId: transaction.txid,
      version: '1.0.0',
    },
    schema: V2_Q08_BCHN_MINED_OUTPUT_SCHEMA,
    transactionBlock: {
      headerIndex: 0,
      merkleBranch: [],
      transactionCount: 1,
      transactionIndex: 0,
    },
  };
  return { authorities, context, descriptor, keys, mined };
}

function externalVmStdin({ transaction, sourceOutputs }) {
  return {
    rawTransactionHex: transaction.rawTransactionHex,
    schema: V2_Q08_VM_INPUT_SCHEMA,
    sourceOutputs,
  };
}

function externalVmStdout({ transaction, sourceOutputs }) {
  return {
    inputCount: transaction.inputs.length,
    inputs: transaction.inputs.map((input, inputIndex) => ({
      accepted: true,
      error: null,
      hashDigestIterations: 0,
      inputIndex,
      maximumHashDigestIterations: 1,
      maximumOperationCost: 1,
      maximumSignatureCheckCount: 1,
      operationCost: 0,
      signatureCheckCount: 0,
      sourceOutputSha256: sha256(Buffer.from(sourceOutputs[inputIndex], 'hex')),
      unlockingBytecodeSha256: sha256(input.unlockingBytecode),
    })),
    rawTransactionSha256: sha256(transaction.bytes),
    schema: V2_Q08_VM_OUTPUT_SCHEMA,
    transactionId: transaction.txid,
  };
}

function mempoolRequest(transaction) {
  return {
    id: 'test-only-nonqualifying-rpc-id',
    jsonrpc: '2.0',
    method: 'testmempoolaccept',
    params: [[transaction.rawTransactionHex], false],
  };
}

function mempoolResult(transaction, allowed = true) {
  return {
    error: null,
    id: 'test-only-nonqualifying-rpc-id',
    jsonrpc: '2.0',
    result: [allowed ? {
      allowed: true,
      fees: { base: 0, 'effective-feerate': 0 },
      size: transaction.sizeBytes,
      txid: transaction.txid,
      vsize: transaction.sizeBytes,
    } : {
      allowed: false,
      'reject-reason': 'test-only nonqualifying rejection',
      txid: transaction.txid,
    }],
  };
}

function signQ08Envelope({ fixture, role, directory, stdin, stdout, subject, runId }) {
  const authority = fixture.authorities.find((entry) => entry.role === role);
  const execution = {
    exitCode: 0,
    machineManifest: reference(directory, 'machine.json', {
      architecture: 'test-only',
      capturedAt: CAPTURED_AT,
      cpuModel: 'test-only deterministic fixture',
      kernel: 'test-only',
      machineIdSha256: hashLabel(`machine-${role}`),
      memoryBytes: '1',
      operatingSystem: 'test-only',
      schema: V2_Q08_MACHINE_MANIFEST_SCHEMA,
    }),
    signal: null,
    stderr: reference(directory, 'stderr.txt', '', { json: false }),
    stdin: reference(directory, 'stdin.json', stdin),
    stdout: reference(directory, 'stdout.json', stdout),
  };
  const envelope = {
    authorityRole: role,
    authoritySetSha256: fixture.context.authoritySetSha256,
    command: authority.command,
    completedAt: COMPLETED_AT,
    descriptor: fixture.descriptor,
    execution,
    runId,
    schema: V2_Q08_LANE_ENVELOPE_SCHEMA,
    signature: null,
    startedAt: STARTED_AT,
    subject,
    tool: authority.tool,
  };
  envelope.signature = {
    algorithm: 'ed25519',
    signatureBase64: signEnvelope(null, jcsBytes({
      domain: V2_Q08_LANE_ATTESTATION_DOMAIN,
      envelope: { ...envelope, signature: null },
      version: V2_Q08_LANE_ATTESTATION_VERSION,
    }), fixture.keys.get(role).privateKey).toString('base64'),
  };
  const path = writeJcs(directory, 'envelope.json', envelope);
  return { envelope, path };
}

function makeSuite({
  localEvidenceBytes = undefined,
  mempoolAllowed = true,
  minedMutator = undefined,
  runIdByRole = {},
  subjectByRole = {},
} = {}) {
  const directory = mkdtempSync(join(root, 'suite-'));
  const artifacts = createRollingFixtureArtifacts({ carrierCount: 10 });
  const transaction = parseV2RawTransaction(artifacts.rawTransactionHex);
  const localEvidence = localEvidenceBytes ?? createFixtureEvidence({
    carrierCount: 10,
    rawTransactionHex: artifacts.rawTransactionHex,
    sourceTransactionHexes: artifacts.sourceTransactionHexes,
  });
  const inspectedLocal = inspectV2LocalVmEvidence(localEvidence);
  const fixture = makeContext({ carrierCount: 10, transaction });
  const expected = {
    action: 'deposit',
    carrierCount: 10,
    instanceId: FIXTURE_INSTANCE_ID,
    journeyStep: 'deposit',
    profileId: FIXTURE_PROFILE_ID,
    profileSha256: FIXTURE_PROFILE_SHA256,
    rawTransactionHex: transaction.rawTransactionHex,
    spentNoteId: null,
    transactionId: transaction.txid,
  };
  const subject = {
    action: expected.action,
    journeyStep: expected.journeyStep,
    rawTransactionSha256: sha256(transaction.bytes),
    schema: 'shieldkit-v2-direct-q08-action-subject-v1',
    spentNoteId: null,
    transactionId: transaction.txid,
  };
  const sourceOutputs = inspectedLocal.inputs.map((entry) => entry.sourceOutput.serializedHex);
  const mined = structuredClone(fixture.mined);
  if (minedMutator !== undefined) minedMutator(mined);
  const payloadByRole = {
    maintainer: {
      stdin: externalVmStdin({ sourceOutputs, transaction }),
      stdout: externalVmStdout({ sourceOutputs, transaction }),
    },
    'bchn-mempool': {
      stdin: mempoolRequest(transaction),
      stdout: mempoolResult(transaction, mempoolAllowed),
    },
    'bchn-mined': {
      stdin: { rawTransactionHex: transaction.rawTransactionHex, schema: V2_Q08_BCHN_MINED_INPUT_SCHEMA },
      stdout: mined,
    },
    leanbch: {
      stdin: externalVmStdin({ sourceOutputs, transaction }),
      stdout: externalVmStdout({ sourceOutputs, transaction }),
    },
  };
  const envelopes = {};
  for (const role of Object.keys(payloadByRole)) {
    const child = join(directory, role);
    // An independent child keeps each referenced stdin/stdout/stderr/machine
    // set adjacent to its signed envelope.
    mkdirSync(child);
    envelopes[role] = signQ08Envelope({
      fixture,
      role,
      directory: child,
      ...payloadByRole[role],
      subject: subjectByRole[role] ?? subject,
      runId: runIdByRole[role] ?? hashLabel(`run-${role}`),
    });
  }
  const localPath = write(directory, 'libauth.json', localEvidence);
  const laneEvidence = {
    bchn: {
      mempool: { path: 'bchn-mempool/envelope.json', sha256: sha256(readFileSync(envelopes['bchn-mempool'].path)) },
      mined: { path: 'bchn-mined/envelope.json', sha256: sha256(readFileSync(envelopes['bchn-mined'].path)) },
    },
    leanbch: { path: 'leanbch/envelope.json', sha256: sha256(readFileSync(envelopes.leanbch.path)) },
    libauth: { path: 'libauth.json', sha256: sha256(readFileSync(localPath)) },
    maintainer: { path: 'maintainer/envelope.json', sha256: sha256(readFileSync(envelopes.maintainer.path)) },
  };
  return { directory, envelopes, expected, fixture, laneEvidence, localEvidence, transaction };
}

function verify(suite) {
  return verifyV2Q08ActionLaneEvidence({
    authorityContext: suite.fixture.context,
    evidenceRoot: suite.directory,
    expected: suite.expected,
    laneEvidence: suite.laneEvidence,
  });
}

function assertRejected(operation) {
  assert.throws(operation, (error) =>
    error instanceof V2Q08LaneEvidenceError
    || error instanceof V2Q02LaneEvidenceError
    || error?.name === 'RawChainRecoveryError'
    || error?.name === 'V2VmEvidenceError');
}

test('TEST-ONLY nonqualifying Q-08 derives acceptance from a real V2 VM fixture and four signed lanes', () => {
  const suite = makeSuite();
  const result = verify(suite);
  assert.equal(result.accepted, true);
  assert.equal(result.transactionId, suite.transaction.txid);
  assert.equal(Object.keys(result.externalEnvelopeSha256).length, 4);
});

test('TEST-ONLY Q-08 rejects a real local VM evidence bound to another transaction or profile', () => {
  const original = makeSuite();
  const alternateArtifacts = createRollingFixtureArtifacts({ carrierCount: 10, feeSats: 3_000n });
  const otherTransactionEvidence = createFixtureEvidence({
    carrierCount: 10,
    rawTransactionHex: alternateArtifacts.rawTransactionHex,
    sourceTransactionHexes: alternateArtifacts.sourceTransactionHexes,
  });
  const transactionSuite = makeSuite({ localEvidenceBytes: otherTransactionEvidence });
  assertRejected(() => verify(transactionSuite));

  const inspected = inspectV2LocalVmEvidence(original.localEvidence);
  const profileDrift = createV2LocalVmEvidence({
    carrierCount: inspected.carrierCount,
    inputs: inspected.inputs.map((entry) => ({ sourceTransactionHex: entry.sourceTransaction.rawTransactionHex })),
    instanceId: inspected.instanceId,
    rawTransactionHex: inspected.transaction.rawTransactionHex,
    tool: { ...inspected.tool, profileId: hashLabel('different-profile') },
  });
  const profileSuite = makeSuite({ localEvidenceBytes: profileDrift });
  assertRejected(() => verify(profileSuite));
});

test('TEST-ONLY Q-08 rejects one-at-a-time signed external subject, hash, and signature drift', () => {
  const subjectSuite = makeSuite({
    subjectByRole: {
      maintainer: {
        action: 'deposit',
        journeyStep: 'deposit',
        rawTransactionSha256: hashLabel('other-transaction'),
        schema: 'shieldkit-v2-direct-q08-action-subject-v1',
        spentNoteId: null,
        transactionId: hashLabel('other-transaction-id'),
      },
    },
  });
  assertRejected(() => verify(subjectSuite));

  const hashSuite = makeSuite();
  hashSuite.laneEvidence.maintainer.sha256 = hashLabel('envelope-sha-drift');
  assertRejected(() => verify(hashSuite));

  const signatureSuite = makeSuite();
  const altered = JSON.parse(readFileSync(signatureSuite.envelopes.maintainer.path, 'utf8'));
  altered.signature.signatureBase64 = Buffer.alloc(64, 1).toString('base64');
  writeJcs(join(signatureSuite.directory, 'maintainer'), 'envelope.json', altered);
  signatureSuite.laneEvidence.maintainer.sha256 = sha256(readFileSync(signatureSuite.envelopes.maintainer.path));
  assertRejected(() => verify(signatureSuite));
});

test('TEST-ONLY Q-08 rejects BCHN mempool rejection, invalid mined inclusion, and repeated external run IDs', () => {
  assertRejected(() => verify(makeSuite({ mempoolAllowed: false })));
  assertRejected(() => verify(makeSuite({
    minedMutator: (mined) => {
      mined.transactionBlock.merkleBranch = [hashLabel('bad-merkle')];
      mined.transactionBlock.transactionCount = 2;
    },
  })));
  const repeated = hashLabel('repeated-run');
  assertRejected(() => verify(makeSuite({
    runIdByRole: { maintainer: repeated, leanbch: repeated },
  })));
});

test('TEST-ONLY Q-08 rejects evidence traversal and every SHA-256 reference pin mismatch', () => {
  const traversal = makeSuite();
  traversal.laneEvidence.maintainer.path = '../maintainer/envelope.json';
  assertRejected(() => verify(traversal));

  for (const mutate of [
    (evidence) => { evidence.libauth.sha256 = hashLabel('libauth-pin'); },
    (evidence) => { evidence.maintainer.sha256 = hashLabel('maintainer-pin'); },
    (evidence) => { evidence.bchn.mempool.sha256 = hashLabel('mempool-pin'); },
    (evidence) => { evidence.bchn.mined.sha256 = hashLabel('mined-pin'); },
    (evidence) => { evidence.leanbch.sha256 = hashLabel('leanbch-pin'); },
  ]) {
    const suite = makeSuite();
    mutate(suite.laneEvidence);
    assertRejected(() => verify(suite));
  }
});
