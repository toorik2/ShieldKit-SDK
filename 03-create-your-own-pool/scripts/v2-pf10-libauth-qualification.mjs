#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';

import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  inspectV2LocalVmEvidence,
} from '../packages/kit/v2/vm-evidence.mjs';

const SCRIPT_SCHEMA =
  'shieldkit-v2-direct-pf10-local-libauth-qualification-v2';
const EVIDENCE_SCHEMA =
  'shieldkit-v2-direct-pf10-local-libauth-evidence-v2';
const projectRoot = path.resolve(import.meta.dirname, '..');
const repositoryRoot = path.resolve(projectRoot, '..');
const testPath = path.join(
  projectRoot,
  'packages/unlock-builder/v2/pf10-withdrawal.test.mjs',
);

class QualificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'QualificationError';
  }
}

const fail = (message) => {
  throw new QualificationError(message);
};

const sha256 = (bytes) =>
  createHash('sha256').update(bytes).digest('hex');

const hash256 = (bytes) => {
  const first = createHash('sha256').update(bytes).digest();
  return createHash('sha256').update(first).digest();
};

const canonicalBytes = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');

const exactObject = (value, label) => {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
  ) {
    fail(`${label} must be an object`);
  }
  return value;
};

const exactArray = (value, label) => {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  return value;
};

const exactString = (value, expected, label) => {
  if (value !== expected) {
    fail(`${label} must equal ${JSON.stringify(expected)}`);
  }
};

const exactBoolean = (value, expected, label) => {
  if (value !== expected) {
    fail(`${label} must equal ${expected}`);
  }
};

const exactInteger = (value, label) => {
  if (!Number.isSafeInteger(value)) fail(`${label} must be a safe integer`);
  return value;
};

const parseOptions = (argv) => {
  const optionNames = Object.freeze({
    '--output': 'output',
    '--profile-core': 'profileCore',
    '--qualification-root': 'qualificationRoot',
    '--r1cs': 'r1cs',
    '--setup-metadata': 'setupMetadata',
    '--temporary-root': 'temporaryRoot',
    '--verification-key': 'verificationKey',
    '--wasm': 'wasm',
    '--zkey': 'zkey',
  });
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const key = optionNames[option];
    if (key === undefined) fail(`unknown option: ${option}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) {
      fail(`${option} requires a value`);
    }
    if (options[key] !== undefined) fail(`${option} may appear only once`);
    options[key] = value;
    index += 1;
  }
  for (const option of [
    '--output',
    '--profile-core',
    '--qualification-root',
    '--r1cs',
    '--setup-metadata',
    '--verification-key',
    '--wasm',
    '--zkey',
  ]) {
    if (options[optionNames[option]] === undefined) {
      fail(`${option} is required`);
    }
  }
  return Object.freeze({
    output: path.resolve(options.output),
    profileCore: path.resolve(options.profileCore),
    qualificationRoot: path.resolve(options.qualificationRoot),
    r1cs: path.resolve(options.r1cs),
    setupMetadata: path.resolve(options.setupMetadata),
    temporaryRoot: path.resolve(
      options.temporaryRoot
      ?? path.join(repositoryRoot, '.tmp/pf10-libauth-qualification'),
    ),
    verificationKey: path.resolve(options.verificationKey),
    wasm: path.resolve(options.wasm),
    zkey: path.resolve(options.zkey),
  });
};

const assertAbsent = async (target) => {
  try {
    await access(target);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  fail(`refusing to overwrite existing output: ${target}`);
};

const runChild = ({ evidencePath, options, temporaryDirectory }) =>
  new Promise((resolve, reject) => {
    const temporaryFiles = path.join(temporaryDirectory, 'tmp');
    const child = spawn(
      process.execPath,
      ['--test', testPath],
      {
        cwd: repositoryRoot,
        env: {
          ...process.env,
          SHIELDKIT_PF10_LIBAUTH_EVIDENCE_OUTPUT: evidencePath,
          SHIELDKIT_PF10_PROFILE_CORE: options.profileCore,
          SHIELDKIT_PF10_QUALIFICATION_ROOT: options.qualificationRoot,
          SHIELDKIT_PF10_R1CS: options.r1cs,
          SHIELDKIT_PF10_SETUP_METADATA: options.setupMetadata,
          SHIELDKIT_PF10_VERIFICATION_KEY: options.verificationKey,
          SHIELDKIT_PF10_WASM: options.wasm,
          SHIELDKIT_PF10_ZKEY: options.zkey,
          TMPDIR: temporaryFiles,
          TMP: temporaryFiles,
          TEMP: temporaryFiles,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr.on('data', (chunk) => stderr.push(Buffer.from(chunk)));
    child.once('error', reject);
    child.once('close', (code, signal) => resolve(Object.freeze({
      code,
      signal,
      stdout: Buffer.concat(stdout),
      stderr: Buffer.concat(stderr),
    })));
  });

const canonicalHex = (value, label, { allowEmpty = false } = {}) => {
  if (
    typeof value !== 'string'
    || value.length % 2 !== 0
    || (!allowEmpty && value.length === 0)
    || !/^[0-9a-f]*$/.test(value)
  ) {
    fail(`${label} must be canonical lowercase hexadecimal`);
  }
  return value;
};

const validateSourceParent = (value, label) => {
  const parent = exactObject(value, label);
  const rawTransactionHex = canonicalHex(
    parent.rawTransactionHex,
    `${label}.rawTransactionHex`,
  );
  const raw = Buffer.from(rawTransactionHex, 'hex');
  const parsed = parseV2RawTransaction(rawTransactionHex);
  exactString(
    parent.rawTransactionSha256,
    sha256(raw),
    `${label}.rawTransactionSha256`,
  );
  exactString(
    parent.transactionId,
    parsed.txid,
    `${label}.transactionId`,
  );
  return Object.freeze({ parent, parsed });
};

const validateAction = (action, expectedKind) => {
  exactObject(action, `action ${expectedKind}`);
  exactString(action.kind, expectedKind, `${expectedKind}.kind`);
  exactInteger(action.inputCount, `${expectedKind}.inputCount`);
  exactInteger(action.outputCount, `${expectedKind}.outputCount`);
  if (action.inputCount !== 13) fail(`${expectedKind} must have 13 inputs`);
  const expectedOutputs = expectedKind === 'withdrawal' ? 14 : 13;
  if (action.outputCount !== expectedOutputs) {
    fail(`${expectedKind} must have ${expectedOutputs} outputs`);
  }
  const transactionBytes = exactInteger(
    action.transactionBytes,
    `${expectedKind}.transactionBytes`,
  );
  if (transactionBytes > 100_000) {
    fail(`${expectedKind} exceeds the 100000-byte transaction ceiling`);
  }
  exactBoolean(
    action.proofVerified,
    true,
    `${expectedKind}.proofVerified`,
  );
  if (
    typeof action.rawTransactionHex !== 'string'
    || !/^(?:[0-9a-f]{2})+$/.test(action.rawTransactionHex)
  ) {
    fail(`${expectedKind}.rawTransactionHex must be canonical lowercase hex`);
  }
  const raw = Buffer.from(action.rawTransactionHex, 'hex');
  if (raw.length !== transactionBytes) {
    fail(`${expectedKind} raw transaction length mismatch`);
  }
  exactString(
    action.rawTransactionSha256,
    sha256(raw),
    `${expectedKind}.rawTransactionSha256`,
  );
  exactString(
    action.transactionId,
    Buffer.from(hash256(raw)).reverse().toString('hex'),
    `${expectedKind}.transactionId`,
  );
  const parsedTransaction = parseV2RawTransaction(
    action.rawTransactionHex,
  );
  exactString(
    parsedTransaction.txid,
    action.transactionId,
    `${expectedKind}.parsedTransaction.txid`,
  );
  if (
    parsedTransaction.inputs.length !== 13
    || parsedTransaction.inputs.some((input) => input.sequence !== 0)
  ) {
    fail(`${expectedKind} must use sequence zero on all 13 inputs`);
  }
  exactString(
    action.feeRateSatsPerByte,
    '1',
    `${expectedKind}.feeRateSatsPerByte`,
  );
  exactString(
    action.feeSats,
    transactionBytes.toString(),
    `${expectedKind}.feeSats`,
  );
  const construction = exactObject(
    action.construction,
    `${expectedKind}.construction`,
  );
  const constructionPath = exactArray(
    construction.path,
    `${expectedKind}.construction.path`,
  );
  const expectedPath = [
    'prepareV2DirectSettlement',
    'assembleV2DirectSettlement',
    'signV2DirectSettlement',
  ];
  if (
    constructionPath.length !== expectedPath.length
    || constructionPath.some(
      (entry, index) => entry !== expectedPath[index],
    )
  ) {
    fail(`${expectedKind} did not use the exact production settlement path`);
  }
  for (const field of [
    'preparedPayloadHash',
    'assemblyHash',
    'localVmEvidenceHash',
  ]) {
    canonicalHex(
      construction[field],
      `${expectedKind}.construction.${field}`,
    );
    if (construction[field].length !== 64) {
      fail(`${expectedKind}.construction.${field} must be 32 bytes`);
    }
  }
  if (construction.inputSequence !== 0) {
    fail(`${expectedKind}.construction.inputSequence must be zero`);
  }

  const sourceParents = exactObject(
    action.sourceParents,
    `${expectedKind}.sourceParents`,
  );
  const previousBundle = validateSourceParent(
    sourceParents.previousBundle,
    `${expectedKind}.sourceParents.previousBundle`,
  );
  const funding = validateSourceParent(
    sourceParents.funding,
    `${expectedKind}.sourceParents.funding`,
  );
  if (previousBundle.parsed.txid === funding.parsed.txid) {
    fail(`${expectedKind} source parents must be distinct`);
  }
  const parents = new Map([
    ['previous-bundle', previousBundle],
    ['funding', funding],
  ]);

  const inputSources = exactArray(
    action.inputSources,
    `${expectedKind}.inputSources`,
  );
  if (inputSources.length !== 13) {
    fail(`${expectedKind} must record all 13 authenticated input sources`);
  }
  const sourceOutputs = exactArray(
    action.sourceOutputs,
    `${expectedKind}.sourceOutputs`,
  );
  if (sourceOutputs.length !== 13) {
    fail(`${expectedKind} must record all 13 source outputs`);
  }
  for (const [index, sourceOutput] of sourceOutputs.entries()) {
    const inputSource = exactObject(
      inputSources[index],
      `${expectedKind}.inputSources[${index}]`,
    );
    if (inputSource.inputIndex !== index) {
      fail(`${expectedKind}.inputSources[${index}] index mismatch`);
    }
    const expectedParentKind = index === 12
      ? 'funding'
      : 'previous-bundle';
    exactString(
      inputSource.parentKind,
      expectedParentKind,
      `${expectedKind}.inputSources[${index}].parentKind`,
    );
    const parent = parents.get(expectedParentKind);
    const expectedOutputIndex = index < 10
      ? index + 1
      : index === 10
        ? 11
        : 0;
    if (inputSource.outputIndex !== expectedOutputIndex) {
      fail(`${expectedKind}.inputSources[${index}] output index mismatch`);
    }
    exactString(
      inputSource.transactionId,
      parent.parsed.txid,
      `${expectedKind}.inputSources[${index}].transactionId`,
    );
    const transactionInput = parsedTransaction.inputs[index];
    if (
      transactionInput.outpoint.txid !== parent.parsed.txid
      || transactionInput.outpoint.vout !== expectedOutputIndex
    ) {
      fail(`${expectedKind} input ${index} does not spend its recorded parent`);
    }
    const serializedOutput =
      parent.parsed.outputs[expectedOutputIndex]?.serializedHex;
    if (serializedOutput === undefined) {
      fail(`${expectedKind} input ${index} source output is absent`);
    }
    const authenticatedOutput =
      parseSerializedSourceOutput(serializedOutput);
    exactString(
      inputSource.serializedOutputSha256,
      authenticatedOutput.sha256,
      `${expectedKind}.inputSources[${index}].serializedOutputSha256`,
    );
    exactObject(sourceOutput, `${expectedKind}.sourceOutputs[${index}]`);
    if (
      typeof sourceOutput.valueSats !== 'string'
      || !/^(?:0|[1-9][0-9]*)$/.test(sourceOutput.valueSats)
    ) {
      fail(`${expectedKind}.sourceOutputs[${index}].valueSats is invalid`);
    }
    for (const field of ['lockingBytecodeHex', 'tokenPrefixHex']) {
      if (
        typeof sourceOutput[field] !== 'string'
        || !/^(?:[0-9a-f]{2})*$/.test(sourceOutput[field])
      ) {
        fail(`${expectedKind}.sourceOutputs[${index}].${field} is invalid`);
      }
    }
    exactString(
      sourceOutput.valueSats,
      authenticatedOutput.valueSatoshis.toString(),
      `${expectedKind}.sourceOutputs[${index}].valueSats`,
    );
    exactString(
      sourceOutput.lockingBytecodeHex,
      authenticatedOutput.lockingBytecodeHex,
      `${expectedKind}.sourceOutputs[${index}].lockingBytecodeHex`,
    );
    exactString(
      sourceOutput.tokenPrefixHex,
      authenticatedOutput.tokenPrefixHex,
      `${expectedKind}.sourceOutputs[${index}].tokenPrefixHex`,
    );
  }
  const localVmEvidence = exactObject(
    action.localVmEvidence,
    `${expectedKind}.localVmEvidence`,
  );
  const localVmEvidenceHex = canonicalHex(
    localVmEvidence.hex,
    `${expectedKind}.localVmEvidence.hex`,
  );
  const localVmBytes = Buffer.from(localVmEvidenceHex, 'hex');
  exactString(
    localVmEvidence.sha256,
    sha256(localVmBytes),
    `${expectedKind}.localVmEvidence.sha256`,
  );
  exactString(
    localVmEvidence.evidenceHash,
    construction.localVmEvidenceHash,
    `${expectedKind}.localVmEvidence.evidenceHash`,
  );
  const inspectedVm = inspectV2LocalVmEvidence(localVmBytes);
  exactString(
    inspectedVm.evidenceHash,
    localVmEvidence.evidenceHash,
    `${expectedKind}.localVmEvidence inspected hash`,
  );
  exactString(
    inspectedVm.transaction.rawTransactionHex,
    action.rawTransactionHex,
    `${expectedKind}.localVmEvidence transaction`,
  );
  if (
    inspectedVm.inputs.length !== 13
    || inspectedVm.inputs.some((input, index) =>
      input.sourceTransaction.rawTransactionHex
      !== parents.get(index === 12 ? 'funding' : 'previous-bundle')
        .parent.rawTransactionHex)
  ) {
    fail(`${expectedKind} local VM evidence does not bind every parent byte`);
  }
  const rows = exactArray(action.rows, `${expectedKind}.rows`);
  if (rows.length !== 13) {
    fail(`${expectedKind} must record all 13 VM evaluations`);
  }
  for (const row of rows) {
    exactObject(row, `${expectedKind}.row`);
    const unlockBytes = exactInteger(
      row.unlockBytes,
      `${expectedKind}.${row.name}.unlockBytes`,
    );
    if (unlockBytes > 10_000) {
      fail(`${expectedKind}.${row.name} exceeds the 10000-byte unlock ceiling`);
    }
    exactBoolean(
      row.hardAccepted,
      true,
      `${expectedKind}.${row.name}.hardAccepted`,
    );
    exactBoolean(
      row.semanticAccepted,
      true,
      `${expectedKind}.${row.name}.semanticAccepted`,
    );
    const operationCost = exactInteger(
      row.operationCost,
      `${expectedKind}.${row.name}.operationCost`,
    );
    const maximumOperationCost = exactInteger(
      row.maximumOperationCost,
      `${expectedKind}.${row.name}.maximumOperationCost`,
    );
    const hashDigestIterations = exactInteger(
      row.hashDigestIterations,
      `${expectedKind}.${row.name}.hashDigestIterations`,
    );
    const maximumHashDigestIterations = exactInteger(
      row.maximumHashDigestIterations,
      `${expectedKind}.${row.name}.maximumHashDigestIterations`,
    );
    const signatureCheckCount = exactInteger(
      row.signatureCheckCount,
      `${expectedKind}.${row.name}.signatureCheckCount`,
    );
    const maximumSignatureChecks = exactInteger(
      row.maximumSignatureChecks,
      `${expectedKind}.${row.name}.maximumSignatureChecks`,
    );
    if (operationCost > maximumOperationCost) {
      fail(`${expectedKind}.${row.name} exceeds its operation budget`);
    }
    if (hashDigestIterations > maximumHashDigestIterations) {
      fail(`${expectedKind}.${row.name} exceeds its hash-iteration budget`);
    }
    if (signatureCheckCount > maximumSignatureChecks) {
      fail(`${expectedKind}.${row.name} exceeds its signature-check budget`);
    }
    if (
      typeof row.operationPercent !== 'number'
      || !Number.isFinite(row.operationPercent)
      || row.operationPercent < 0
      || row.operationPercent > 100
    ) {
      fail(`${expectedKind}.${row.name}.operationPercent is invalid`);
    }
  }
  return Object.freeze({
    kind: expectedKind,
    transactionBytes,
    transactionId: action.transactionId,
    maximumUnlockBytes: Math.max(...rows.map((row) => row.unlockBytes)),
    maximumOperationPercent: Math.max(
      ...rows.map((row) => row.operationPercent),
    ),
    feeSats: action.feeSats,
    proofGenerationMs: action.proofGenerationMs,
  });
};

const validateEvidence = (value) => {
  const evidence = exactObject(value, 'evidence');
  exactString(evidence.schema, EVIDENCE_SCHEMA, 'evidence.schema');
  exactString(
    evidence.eligibility,
    'development-only',
    'evidence.eligibility',
  );
  const claims = exactObject(evidence.claims, 'evidence.claims');
  exactBoolean(claims.finalKey, false, 'claims.finalKey');
  exactBoolean(claims.production, false, 'claims.production');
  exactBoolean(claims.releaseQualified, false, 'claims.releaseQualified');
  exactBoolean(claims.libauthBch2026, true, 'claims.libauthBch2026');
  for (const claim of [
    'bchnMempool',
    'bchnMined',
    'liveChainParentProvenance',
    'leanBch',
    'unmodifiedMaintainerBenchmark',
  ]) {
    exactBoolean(claims[claim], false, `claims.${claim}`);
  }
  exactBoolean(
    claims.productionSettlementBuilderPath,
    true,
    'claims.productionSettlementBuilderPath',
  );
  exactBoolean(
    claims.authenticatedSerializedParentOutputs,
    true,
    'claims.authenticatedSerializedParentOutputs',
  );
  const qualificationScope = exactObject(
    evidence.qualificationScope,
    'evidence.qualificationScope',
  );
  exactString(
    qualificationScope.settlementPath,
    'prepareV2DirectSettlement -> assembleV2DirectSettlement -> signV2DirectSettlement -> createV2LocalVmEvidence',
    'qualificationScope.settlementPath',
  );
  exactString(
    qualificationScope.feePolicy,
    'exact signed bytes at 1 satoshi per byte',
    'qualificationScope.feePolicy',
  );
  if (qualificationScope.inputSequence !== 0) {
    fail('qualificationScope.inputSequence must be zero');
  }
  if (
    typeof qualificationScope.parentTransactions !== 'string'
    || !qualificationScope.parentTransactions.includes(
      'no live-chain provenance is claimed',
    )
  ) {
    fail('qualificationScope must disclaim live-chain parent provenance');
  }
  const limits = exactObject(evidence.hardLimits, 'evidence.hardLimits');
  if (
    limits.transactionBytes !== 100_000
    || limits.unlockingBytecodeBytes !== 10_000
    || limits.standardVmResourcePercent !== 100
  ) {
    fail('evidence must use only the full BCH hard ceilings');
  }
  const bases = exactObject(evidence.exactDustBases, 'evidence.exactDustBases');
  const verifierBases = exactArray(
    bases.verifierSats,
    'exactDustBases.verifierSats',
  );
  if (
    verifierBases.length !== 10
    || verifierBases.some((value) => value !== '1200')
    || bases.bindingSats !== '1200'
    || bases.stateSats !== '2500'
    || bases.minimumChangeSats !== '546'
  ) {
    fail('evidence does not use the current exact PF10 dust-derived bases');
  }
  const result = exactObject(
    evidence.pf10FusedQGenesisActions,
    'pf10FusedQGenesisActions',
  );
  exactString(
    result.verdict,
    'production-builder-local-standard-pass-all-actions-precomputed-fixed-lines',
    'pf10FusedQGenesisActions.verdict',
  );
  const actions = exactArray(result.actions, 'pf10FusedQGenesisActions.actions');
  if (actions.length !== 3) fail('evidence must contain exactly three actions');
  const expectedKinds = ['deposit', 'transfer', 'withdrawal'];
  const summaries = expectedKinds.map((kind, index) =>
    validateAction(actions[index], kind));
  return Object.freeze({ evidence, summaries });
};

const main = async () => {
  const options = parseOptions(process.argv.slice(2));
  await assertAbsent(options.output);
  await mkdir(path.dirname(options.output), { recursive: true, mode: 0o700 });
  await mkdir(options.temporaryRoot, { recursive: true, mode: 0o700 });
  const stage = await mkdtemp(path.join(
    options.temporaryRoot,
    '.pf10-libauth-stage-',
  ));
  await chmod(stage, 0o700);
  let published = false;
  try {
    const temporaryFiles = path.join(stage, 'tmp');
    await mkdir(temporaryFiles, { mode: 0o700 });
    const evidencePath = path.join(stage, 'libauth.json');
    const executed = await runChild({
      evidencePath,
      options,
      temporaryDirectory: stage,
    });
    await writeFile(
      path.join(stage, 'stdout.txt'),
      executed.stdout,
      { mode: 0o600 },
    );
    await writeFile(
      path.join(stage, 'stderr.txt'),
      executed.stderr,
      { mode: 0o600 },
    );
    if (executed.code !== 0 || executed.signal !== null) {
      fail(
        `PF10 Libauth qualification test failed: code=${executed.code} signal=${executed.signal}`,
      );
    }
    const parsed = JSON.parse(await readFile(evidencePath, 'utf8'));
    const validated = validateEvidence(parsed);
    const evidenceBytes = canonicalBytes(validated.evidence);
    await writeFile(evidencePath, evidenceBytes, { mode: 0o600 });
    await chmod(evidencePath, 0o600);
    const summary = Object.freeze({
      schema: SCRIPT_SCHEMA,
      eligibility: 'development-only',
      claims: validated.evidence.claims,
      identity: validated.evidence.identity,
      hardLimits: validated.evidence.hardLimits,
      exactDustBases: validated.evidence.exactDustBases,
      actions: validated.summaries,
      evidence: Object.freeze({
        path: 'libauth.json',
        bytes: evidenceBytes.length,
        sha256: sha256(evidenceBytes),
      }),
      command: Object.freeze({
        executable: process.execPath,
        arguments: Object.freeze(['--test', path.relative(
          repositoryRoot,
          testPath,
        )]),
        workingDirectory: '.',
      }),
    });
    const summaryBytes = canonicalBytes(summary);
    await writeFile(
      path.join(stage, 'qualification-summary.json'),
      summaryBytes,
      { mode: 0o600 },
    );
    await rm(temporaryFiles, { recursive: true, force: false });
    await rename(stage, options.output);
    published = true;
    process.stdout.write(`${canonicalizeJcs(Object.freeze({
      outputDirectory: options.output,
      evidenceSha256: summary.evidence.sha256,
      actions: summary.actions,
      eligibility: summary.eligibility,
    }))}\n`);
  } finally {
    if (!published) {
      await rm(stage, { recursive: true, force: true });
    }
  }
};

main().catch((error) => {
  process.stderr.write(`${error?.stack ?? error}\n`);
  process.exitCode = 1;
});
