/* TEST-ONLY: ephemeral fixtures below are non-qualifying parser coverage. */
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as signEnvelope } from 'node:crypto';
import { after, test } from 'node:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import { parseV2RawTransaction } from '../packages/kit/v2/transaction-policy.mjs';
import {
  V2Q02LaneEvidenceError,
  V2_Q02_LANE_ATTESTATION_DOMAIN,
  V2_Q02_LANE_ATTESTATION_VERSION,
  V2_Q02_LANE_AUTHORITIES_SCHEMA,
  V2_Q02_LANE_ENVELOPE_SCHEMA,
  createV2Q02PinnedLaneAuthorityContext,
  verifyV2Q02LaneEvidence,
} from './v2-q02-lane-evidence.mjs';

const root = mkdtempSync(join(tmpdir(), 'shieldkit-v2-q02-nonqualifying-'));
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
  const bytes = json ? jcsBytes(value) : Buffer.from(value, 'utf8');
  write(directory, filename, bytes);
  return { path: filename, sha256: sha256(bytes) };
};
const u32 = (value) => {
  const result = Buffer.alloc(4);
  result.writeUInt32LE(value);
  return result;
};
const u64 = (value) => {
  const result = Buffer.alloc(8);
  result.writeBigUInt64LE(BigInt(value));
  return result;
};
const hash256Display = (value) => createHash('sha256')
  .update(createHash('sha256').update(value).digest())
  .digest()
  .reverse()
  .toString('hex');

const MAXIMUM_TARGET = `7fffff${'00'.repeat(29)}`;
const TARGET = BigInt(`0x${MAXIMUM_TARGET}`);
const HEADER_WORK = (1n << 256n) / (TARGET + 1n);
const SOURCE_OUTPUT = '01000000000000000151';
const TEST_ONLY_TOPOLOGY_ID = 'pf10-fused-q-genesis-v1';
const STARTED_AT = '2026-07-29T00:00:00.100Z';
const COMPLETED_AT = '2026-07-29T00:00:00.200Z';
const CAPTURED_AT = '2026-07-29T00:00:00.150Z';

function makeRawTransaction(inputCount = 13) {
  const inputs = Array.from({ length: inputCount }, (_, index) => Buffer.concat([
    Buffer.alloc(32, index + 1),
    u32(index),
    Buffer.from([1, 0x51 + (index % 2)]),
    u32(0xffff_ffff),
  ]));
  return Buffer.concat([
    u32(2),
    Buffer.from([inputCount]),
    ...inputs,
    Buffer.from([1]),
    u64(1_000),
    Buffer.from([1, 0x51]),
    u32(0),
  ]);
}

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

function makeCase(transaction, expectation = 'accept') {
  const base = {
    caseId: 'deposit-0',
    expectation,
    index: 0,
    kind: 'deposit',
    localVmEvidenceSha256: hashLabel(`local-vm-${expectation}`),
    metadataSha256: hashLabel(`metadata-${expectation}`),
    packetSha256: hashLabel(`packet-${expectation}`),
    proofSha256: hashLabel(`proof-${expectation}`),
    rawTransactionSha256: sha256(transaction.bytes),
    transactionId: transaction.txid,
  };
  return expectation === 'accept' ? { ...base, mutation: null } : {
    ...base,
    mutation: {
      baseBundleSha256: hashLabel('reject-base'),
      field: 'proof',
      mutantBundleSha256: hashLabel('reject-mutant'),
    },
  };
}

function vmStdin(transaction, sourceOutputs = undefined) {
  return {
    rawTransactionHex: transaction.rawTransactionHex,
    schema: 'shieldkit-v2-direct-q02-vm-run-input-v2',
    sourceOutputs: sourceOutputs ?? Array.from(
      { length: transaction.inputs.length },
      () => SOURCE_OUTPUT,
    ),
  };
}

function vmStdout(transaction, sourceOutputs = undefined) {
  const outputs = sourceOutputs ?? Array.from(
    { length: transaction.inputs.length },
    () => SOURCE_OUTPUT,
  );
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
      sourceOutputSha256: sha256(Buffer.from(outputs[inputIndex], 'hex')),
      unlockingBytecodeSha256: sha256(input.unlockingBytecode),
    })),
    rawTransactionSha256: sha256(transaction.bytes),
    schema: 'shieldkit-v2-direct-q02-per-input-run-v2',
    transactionId: transaction.txid,
  };
}

function mempoolRequest(transaction, params = undefined) {
  return {
    id: 'test-only-nonqualifying-rpc-id',
    jsonrpc: '2.0',
    method: 'testmempoolaccept',
    params: params ?? [[transaction.rawTransactionHex], false],
  };
}

function mempoolAccept(transaction) {
  return {
    error: null,
    id: 'test-only-nonqualifying-rpc-id',
    jsonrpc: '2.0',
    result: [{
      allowed: true,
      fees: { base: 0, 'effective-feerate': 0 },
      size: transaction.sizeBytes,
      txid: transaction.txid,
      vsize: transaction.sizeBytes,
    }],
  };
}

function mempoolReject(transaction) {
  return {
    error: null,
    id: 'test-only-nonqualifying-rpc-id',
    jsonrpc: '2.0',
    result: [{
      allowed: false,
      'reject-reason': 'test-only nonqualifying negative case',
      txid: transaction.txid,
    }],
  };
}

function buildFixture({ minimumConfirmations = 1 } = {}) {
  const directory = mkdtempSync(join(root, 'fixture-'));
  const raw = makeRawTransaction();
  const transaction = parseV2RawTransaction(raw.toString('hex'));
  const checkpointHash = hashLabel('checkpoint');
  const minedHeader = mineHeader({
    merkleRoot: transaction.txid,
    previousBlockHash: checkpointHash,
  });
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
  const contextPins = {
    descriptorSha256: hashLabel('descriptor'),
    finalLocksSha256: hashLabel('final-locks'),
    instanceId: hashLabel('instance'),
    manifestSha256: hashLabel('manifest'),
    profileId: hashLabel('profile'),
    topologyId: TEST_ONLY_TOPOLOGY_ID,
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
      minimumConfirmations,
    },
    evidenceWindow: {
      notAfter: '2027-01-01T00:00:00.000Z',
      notBefore: '2026-01-01T00:00:00.000Z',
    },
    finalLocksSha256: contextPins.finalLocksSha256,
    instanceId: contextPins.instanceId,
    network: { id: 2, name: 'chipnet' },
    profileId: contextPins.profileId,
    schema: V2_Q02_LANE_AUTHORITIES_SCHEMA,
    topologyId: TEST_ONLY_TOPOLOGY_ID,
  };
  const artifactBytes = jcsBytes(artifact);
  const context = createV2Q02PinnedLaneAuthorityContext({
    ...contextPins,
    artifactBytes,
    artifactSha256: sha256(artifactBytes),
  });
  const descriptor = {
    descriptorSha256: contextPins.descriptorSha256,
    finalLocksSha256: contextPins.finalLocksSha256,
    instanceId: contextPins.instanceId,
    manifestSha256: contextPins.manifestSha256,
    network: { id: 2, name: 'chipnet' },
    profileId: contextPins.profileId,
    topologyId: TEST_ONLY_TOPOLOGY_ID,
  };
  const mined = {
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
      transactionId: transaction.txid,
      version: '1.0.0',
    },
    schema: 'shieldkit-v2-direct-q02-bchn-mined-result-v2',
    transactionBlock: {
      headerIndex: 0,
      merkleBranch: [],
      transactionCount: 1,
      transactionIndex: 0,
    },
  };
  return { authorities, context, descriptor, directory, keys, mined, minedHeader, transaction };
}

const fixture = buildFixture();
const acceptCase = makeCase(fixture.transaction);
const rejectCase = makeCase(fixture.transaction, 'reject');

function signedEnvelope({
  fixture: activeFixture = fixture,
  role,
  expectedCase,
  stdin,
  stdout,
  envelopeMutator = undefined,
}) {
  const directory = mkdtempSync(join(activeFixture.directory, 'envelope-'));
  const authority = activeFixture.authorities.find((entry) => entry.role === role);
  const execution = {
    exitCode: 0,
    machineManifest: reference(directory, 'machine.json', {
      architecture: 'test-only',
      capturedAt: CAPTURED_AT,
      cpuModel: 'test-only deterministic fixture',
      kernel: 'test-only',
      machineIdSha256: hashLabel('machine'),
      memoryBytes: '1',
      operatingSystem: 'test-only',
      schema: 'shieldkit-v2-direct-q02-machine-manifest-v2',
    }),
    signal: null,
    stderr: reference(directory, 'stderr.txt', '', { json: false }),
    stdin: reference(directory, 'stdin.json', stdin),
    stdout: reference(directory, 'stdout.json', stdout),
  };
  const envelope = {
    authorityRole: role,
    authoritySetSha256: activeFixture.context.authoritySetSha256,
    case: expectedCase,
    command: authority.command,
    completedAt: COMPLETED_AT,
    descriptor: activeFixture.descriptor,
    execution,
    runId: hashLabel(`run-${role}-${expectedCase.expectation}`),
    schema: V2_Q02_LANE_ENVELOPE_SCHEMA,
    signature: null,
    startedAt: STARTED_AT,
    tool: authority.tool,
  };
  if (envelopeMutator !== undefined) envelopeMutator(envelope);
  envelope.signature = {
    algorithm: 'ed25519',
    signatureBase64: signEnvelope(null, jcsBytes({
      domain: V2_Q02_LANE_ATTESTATION_DOMAIN,
      envelope: { ...envelope, signature: null },
      version: V2_Q02_LANE_ATTESTATION_VERSION,
    }), activeFixture.keys.get(role).privateKey).toString('base64'),
  };
  const path = writeJcs(directory, 'envelope.json', envelope);
  return { directory, envelope, path };
}

function assertRejected(operation) {
  assert.throws(operation, (error) =>
    error instanceof V2Q02LaneEvidenceError
    || error?.name === 'RawChainRecoveryError');
}

function verify(activeFixture, path, expectedCase) {
  return verifyV2Q02LaneEvidence({
    authorityContext: activeFixture.context,
    envelopePath: path,
    expectedCase,
  });
}

test('TEST-ONLY nonqualifying maintainer and LeanBCH envelopes derive accepted outcomes', () => {
  for (const role of ['maintainer', 'leanbch']) {
    const evidence = signedEnvelope({
      role,
      expectedCase: acceptCase,
      stdin: vmStdin(fixture.transaction),
      stdout: vmStdout(fixture.transaction),
    });
    const result = verify(fixture, evidence.path, acceptCase);
    assert.equal(result.derivedOutcome, 'accepted');
    assert.equal(result.qualification, false);
    assert.equal(result.lane, role);
  }
});

test('TEST-ONLY nonqualifying real-shape BCHN testmempoolaccept accepts and rejects', () => {
  const accepted = signedEnvelope({
    role: 'bchn-mempool',
    expectedCase: acceptCase,
    stdin: mempoolRequest(fixture.transaction),
    stdout: mempoolAccept(fixture.transaction),
  });
  const rejected = signedEnvelope({
    role: 'bchn-mempool',
    expectedCase: rejectCase,
    stdin: mempoolRequest(fixture.transaction),
    stdout: mempoolReject(fixture.transaction),
  });
  assert.equal(verify(fixture, accepted.path, acceptCase).derivedOutcome, 'accepted');
  assert.equal(verify(fixture, rejected.path, rejectCase).derivedOutcome, 'rejected');
});

test('TEST-ONLY nonqualifying BCHN mined raw-header and Merkle inclusion is accepted', () => {
  const evidence = signedEnvelope({
    role: 'bchn-mined',
    expectedCase: acceptCase,
    stdin: {
      rawTransactionHex: fixture.transaction.rawTransactionHex,
      schema: 'shieldkit-v2-direct-q02-bchn-mined-input-v2',
    },
    stdout: fixture.mined,
  });
  assert.equal(verify(fixture, evidence.path, acceptCase).derivedOutcome, 'accepted');
});

test('TEST-ONLY rejects a caller-constructed authority context', () => {
  const evidence = signedEnvelope({ role: 'maintainer', expectedCase: acceptCase, stdin: vmStdin(fixture.transaction), stdout: vmStdout(fixture.transaction) });
  assertRejected(() => verifyV2Q02LaneEvidence({
    authorityContext: Object.freeze({ ...fixture.context }),
    envelopePath: evidence.path,
    expectedCase: acceptCase,
  }));
});

test('TEST-ONLY rejects authority-set binding drift even when re-signed', () => {
  const evidence = signedEnvelope({
    role: 'maintainer', expectedCase: acceptCase, stdin: vmStdin(fixture.transaction), stdout: vmStdout(fixture.transaction),
    envelopeMutator: (envelope) => { envelope.authoritySetSha256 = hashLabel('authority-set-drift'); },
  });
  assertRejected(() => verify(fixture, evidence.path, acceptCase));
});

test('TEST-ONLY rejects one-at-a-time signed envelope field tampering', () => {
  const evidence = signedEnvelope({ role: 'maintainer', expectedCase: acceptCase, stdin: vmStdin(fixture.transaction), stdout: vmStdout(fixture.transaction) });
  for (const mutate of [
    (envelope) => { envelope.execution.stdout.sha256 = hashLabel('stdout-tamper'); },
    (envelope) => { envelope.execution.machineManifest.sha256 = hashLabel('machine-tamper'); },
    (envelope) => { envelope.tool.runnerSha256 = hashLabel('tool-tamper'); },
    (envelope) => { envelope.case.metadataSha256 = hashLabel('case-tamper'); },
  ]) {
    const tampered = structuredClone(evidence.envelope);
    mutate(tampered);
    writeJcs(evidence.directory, 'envelope.json', tampered);
    assertRejected(() => verify(fixture, evidence.path, acceptCase));
  }
});

test('TEST-ONLY rejects input-count, unlocking-bytecode, and source-output mismatches', () => {
  const shortTransaction = parseV2RawTransaction(makeRawTransaction(12).toString('hex'));
  const shortCase = makeCase(shortTransaction);
  const shortEvidence = signedEnvelope({ role: 'maintainer', expectedCase: shortCase, stdin: vmStdin(shortTransaction), stdout: vmStdout(shortTransaction) });
  assertRejected(() => verify(fixture, shortEvidence.path, shortCase));

  const badUnlock = vmStdout(fixture.transaction);
  badUnlock.inputs[0].unlockingBytecodeSha256 = hashLabel('unlocking-bytecode-drift');
  const unlockEvidence = signedEnvelope({ role: 'maintainer', expectedCase: acceptCase, stdin: vmStdin(fixture.transaction), stdout: badUnlock });
  assertRejected(() => verify(fixture, unlockEvidence.path, acceptCase));

  const changedSources = vmStdin(fixture.transaction);
  changedSources.sourceOutputs[0] = '02000000000000000151';
  const sourceEvidence = signedEnvelope({ role: 'maintainer', expectedCase: acceptCase, stdin: changedSources, stdout: vmStdout(fixture.transaction) });
  assertRejected(() => verify(fixture, sourceEvidence.path, acceptCase));
});

test('TEST-ONLY rejects malformed nested BCHN RPC params and response transaction-id drift', () => {
  const badParams = signedEnvelope({
    role: 'bchn-mempool', expectedCase: acceptCase,
    stdin: mempoolRequest(fixture.transaction, [[fixture.transaction.rawTransactionHex], true]),
    stdout: mempoolAccept(fixture.transaction),
  });
  assertRejected(() => verify(fixture, badParams.path, acceptCase));

  const wrongTxid = mempoolAccept(fixture.transaction);
  wrongTxid.result[0].txid = hashLabel('wrong-rpc-txid');
  const badTxid = signedEnvelope({ role: 'bchn-mempool', expectedCase: acceptCase, stdin: mempoolRequest(fixture.transaction), stdout: wrongTxid });
  assertRejected(() => verify(fixture, badTxid.path, acceptCase));
});

test('TEST-ONLY rejects insufficient depth, header linkage, Merkle drift, and mined rejection evidence', () => {
  const deepFixture = buildFixture({ minimumConfirmations: 2 });
  const depthEvidence = signedEnvelope({
    fixture: deepFixture, role: 'bchn-mined', expectedCase: makeCase(deepFixture.transaction),
    stdin: { rawTransactionHex: deepFixture.transaction.rawTransactionHex, schema: 'shieldkit-v2-direct-q02-bchn-mined-input-v2' },
    stdout: deepFixture.mined,
  });
  assertRejected(() => verify(deepFixture, depthEvidence.path, makeCase(deepFixture.transaction)));

  const linkageHeader = mineHeader({ merkleRoot: fixture.transaction.txid, previousBlockHash: hashLabel('wrong-parent') });
  const linkage = structuredClone(fixture.mined);
  linkage.headerSegment.rawHeadersHex = [linkageHeader.hex];
  linkage.headerSegment.tip.blockHash = linkageHeader.id;
  linkage.nodeObservation.blockHash = linkageHeader.id;
  const linkageEvidence = signedEnvelope({ role: 'bchn-mined', expectedCase: acceptCase, stdin: { rawTransactionHex: fixture.transaction.rawTransactionHex, schema: 'shieldkit-v2-direct-q02-bchn-mined-input-v2' }, stdout: linkage });
  assertRejected(() => verify(fixture, linkageEvidence.path, acceptCase));

  const merkleHeader = mineHeader({ merkleRoot: hashLabel('wrong-merkle-root'), previousBlockHash: fixture.context.checkpoint.blockHash });
  const merkle = structuredClone(fixture.mined);
  merkle.headerSegment.rawHeadersHex = [merkleHeader.hex];
  merkle.headerSegment.tip.blockHash = merkleHeader.id;
  merkle.nodeObservation.blockHash = merkleHeader.id;
  const merkleEvidence = signedEnvelope({ role: 'bchn-mined', expectedCase: acceptCase, stdin: { rawTransactionHex: fixture.transaction.rawTransactionHex, schema: 'shieldkit-v2-direct-q02-bchn-mined-input-v2' }, stdout: merkle });
  assertRejected(() => verify(fixture, merkleEvidence.path, acceptCase));

  const rejectMined = signedEnvelope({ role: 'bchn-mined', expectedCase: rejectCase, stdin: { rawTransactionHex: fixture.transaction.rawTransactionHex, schema: 'shieldkit-v2-direct-q02-bchn-mined-input-v2' }, stdout: fixture.mined });
  assertRejected(() => verify(fixture, rejectMined.path, rejectCase));
});
