import assert from 'node:assert/strict';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  constructDirectV2Output,
  deriveDirectV2Address,
} from '../../action/v2/notes.mjs';

import {
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  deriveV2Pf10StoreRuntimeMaterialsSha256,
} from '../../profile/v2/instance-descriptor.mjs';
import {
  createV2DirectActionLifecycle,
  inspectV2OperationProofRecord,
  V2ActionLifecycleError,
} from '@shieldkit/kit/v2';
import {
  V2_ACTION_LIFECYCLE_CRASH_STAGES as lifecycleCrashStages,
  V2ActionLifecycleCrash as LifecycleCrash,
} from './action-lifecycle.mjs';
import {
  V2_ACTION_LIFECYCLE_CRASH_STAGES as crashStages,
  V2ActionLifecycleCrash as Crash,
} from './action-lifecycle-crash.mjs';
import {
  createV2PrivateActionStore,
  V2PrivateActionStoreError,
} from './private-action-store.mjs';
import { encodeV2PrivateActionRecord } from './private-action-record.mjs';

const FIXTURE_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../..',
);
const TMP_ROOT = path.join(FIXTURE_ROOT, '.tmp');
const PROFILE_ID = '11'.repeat(32);
const INSTANCE_ID = '22'.repeat(32);
const PUBLIC_NULLIFIER = '33'.repeat(32);

const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
const rejectsPrivateActionStore = (code) => (error) =>
  error instanceof V2PrivateActionStoreError && error.code === code;

test('action lifecycle re-exports the exact lightweight crash seam identities', () => {
  assert.strictEqual(lifecycleCrashStages, crashStages);
  assert.strictEqual(LifecycleCrash, Crash);
  const injected = new LifecycleCrash(crashStages[0]);
  assert.equal(injected instanceof Crash, true);
  assert.equal(injected.stage, 'prove.after_transition');
});

function fixedRng() {
  let next = 5n;
  return {
    bytes(length) {
      assert.equal(length, 32);
      const value = Buffer.from(fr(next), 'hex');
      next += 1n;
      return value;
    },
  };
}

function output(sequence) {
  return constructDirectV2Output({
    address: deriveDirectV2Address({
      networkId: 2,
      profileId: PROFILE_ID,
      instanceId: INSTANCE_ID,
      spendSecret: fr(3),
      incomingViewSecret: fr(4),
    }),
    postActionSequence: String(sequence + 1),
    rng: fixedRng(),
  });
}

function operationId(value) {
  return `v2op:${BigInt(value).toString(16).padStart(64, '0')}`;
}

function material(sequence, id = operationId(sequence + 1)) {
  return {
    expectedActionSequence: sequence,
    kind: 'transfer',
    operationId: id,
    output: output(sequence),
    publicNullifier: PUBLIC_NULLIFIER,
  };
}

function binding(record) {
  return {
    actionMaterialSha256: record.actionMaterialSha256.toString('hex'),
    expectedActionSequence: record.expectedActionSequence,
    kind: record.kind,
    operationId: record.operationId,
    privateActionRecordSha256:
      record.privateActionRecordSha256.toString('hex'),
  };
}

function filename(directory, id) {
  return path.join(directory, `${id.slice('v2op:'.length)}.json`);
}

async function privateDirectory(t) {
  // Keep all test state under the worktree-local .tmp root. The terminal
  // directory itself is mode 0700, as required by the production store and
  // proof-workspace guards; .tmp may be traversable but is not writable.
  await mkdir(TMP_ROOT, { recursive: true, mode: 0o755 });
  const directory = await mkdtemp(path.join(TMP_ROOT, 'action-lifecycle-'));
  await chmod(directory, 0o700);
  t.after(async () => {
    await rm(directory, { recursive: true, force: true });
  });
  return directory;
}

const rejectsLifecycleInput = (error) =>
  error instanceof V2ActionLifecycleError
  && error.code === 'INVALID_LIFECYCLE_INPUT';

const exactFactoryOptions = () => ({
  allowDevelopmentOnly: false,
  descriptor: null,
  fundingWallet: null,
  loadRawTransaction: null,
  profileCore: null,
  privateActionStore: null,
  proofWorkspaceDirectory: null,
  store: null,
  synchronizeCanonicalTip: null,
});

test('action lifecycle factory rejects non-exact public option shapes before interpreting values', async () => {
  await assert.rejects(
    createV2DirectActionLifecycle(undefined),
    rejectsLifecycleInput,
  );
  await assert.rejects(
    createV2DirectActionLifecycle({}),
    rejectsLifecycleInput,
  );
  await assert.rejects(
    createV2DirectActionLifecycle({
      ...exactFactoryOptions(),
      callerSuppliedRuntime: {},
    }),
    rejectsLifecycleInput,
  );
});

test('descriptor and runtime admission reject lookalikes by validation identity', async () => {
  const lookalikeDescriptor = Object.freeze({
    schema: 'shieldkit-v2-instance-descriptor-v1',
  });
  await assert.rejects(
    deriveV2Pf10RuntimeFromValidatedDescriptor(lookalikeDescriptor),
    /descriptor validated by loadV2InstanceDescriptor/,
  );

  // The digest bridge is also the proof-record inspector's first runtime
  // admission step after profile-core validation. A copied object cannot
  // acquire the module-private validation identity of a resolved runtime.
  const clonedRuntimeResolution = Object.freeze({
    schema: 'shieldkit-v2-direct-pf10-runtime-resolution-v1',
    runtimeMaterial: Object.freeze({ materialSha256: '00'.repeat(32) }),
  });
  assert.throws(
    () => deriveV2Pf10StoreRuntimeMaterialsSha256(clonedRuntimeResolution),
    /runtime resolution returned by deriveV2Pf10RuntimeFromValidatedDescriptor/,
  );
});

test('proof-record inspector rejects non-exact public option shapes before decoding', () => {
  assert.throws(
    () => inspectV2OperationProofRecord(Buffer.alloc(0), undefined),
    rejectsLifecycleInput,
  );
  assert.throws(
    () => inspectV2OperationProofRecord(Buffer.alloc(0), {
      profileCore: null,
      runtimeResolution: null,
      callerSuppliedRuntimeDigest: '00'.repeat(32),
    }),
    rejectsLifecycleInput,
  );
});

test('private action durability survives reload and rejects stale V12 record or sequence bindings', async (t) => {
  const directory = await privateDirectory(t);
  const id = operationId(90);
  const initial = material(41, id);
  const firstStore = await createV2PrivateActionStore({ directory });
  const persisted = await firstStore.create(initial);

  // Simulate a process crash/restart: only the durable 0600 record and its
  // operation binding are available to the new coordinator instance.
  const reloadedStore = await createV2PrivateActionStore({ directory });
  assert.deepEqual(
    await reloadedStore.load(binding(persisted)),
    persisted,
    'the reloaded coordinator receives the exact persisted private material',
  );
  await assert.rejects(
    reloadedStore.load({
      ...binding(persisted),
      expectedActionSequence: initial.expectedActionSequence + 1,
    }),
    rejectsPrivateActionStore('PRIVATE_ACTION_RECORD_MISMATCH'),
    'a pre-state sequence cannot load the persisted material',
  );

  const replacementInput = material(42, id);
  const replacement = await reloadedStore.replace(replacementInput);
  await assert.rejects(
    reloadedStore.load(binding(persisted)),
    rejectsPrivateActionStore('PRIVATE_ACTION_RECORD_MISMATCH'),
    'a crash after file replacement cannot authorize the old V12 DB hash',
  );
  assert.deepEqual(
    await reloadedStore.load(binding(replacement)),
    replacement,
    'the replacement sequence and record hash reload together',
  );
});

test('private action substitution is rejected by the persisted operation identity', async (t) => {
  const directory = await privateDirectory(t);
  const first = material(41, operationId(100));
  const substituted = material(41, operationId(101));
  const store = await createV2PrivateActionStore({ directory });
  const persisted = await store.create(first);
  const foreign = encodeV2PrivateActionRecord(substituted);

  // Model an attacker or recovery bug placing a valid canonical record under
  // the target operation filename. The bytes are valid but not usable for the
  // operation that lifecycle.proveAction is resuming.
  await writeFile(filename(directory, first.operationId), foreign.bytes, {
    mode: 0o600,
  });
  await chmod(filename(directory, first.operationId), 0o600);
  await assert.rejects(
    store.load(binding(persisted)),
    rejectsPrivateActionStore('PRIVATE_ACTION_RECORD_MISMATCH'),
  );
});

test('lifecycle production boundary requires sealed material, a private workspace, and durable proving bindings', async () => {
  const source = await readFile(
    new URL('./action-lifecycle.mjs', import.meta.url),
    'utf8',
  );
  const factory = source.slice(
    source.indexOf('export async function createV2DirectActionLifecycle'),
    source.indexOf('\nexport function inspectV2OperationProofRecord'),
  );
  assert.match(factory, /'privateActionStore'/);
  assert.match(factory, /assertV2PrivateActionStore\(value\.privateActionStore\)/);
  assert.match(factory, /await assertPrivateProofWorkspace\(value\.proofWorkspaceDirectory\)/);
  assert.match(
    source,
    /metadata\.mode & 0o077\) !== 0[\s\S]*proof workspace must be current-user-owned with mode 0700 or stricter/,
  );

  const start = source.indexOf('  async proveAction({');
  const end = source.indexOf('\n  async signAction(', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const prove = source.slice(start, end);
  assert.match(prove, /operationId: id,[\s\S]*spend = null,[\s\S]*crashAt = null/);
  assert.doesNotMatch(prove.slice(0, prove.indexOf('} = {})')), /\b(?:output|publicNullifier)\b/);
  assert.match(
    prove,
    /await this\.#privateActionStore\.load\(\{[\s\S]*actionMaterialSha256:[\s\S]*expectedActionSequence:[\s\S]*kind:[\s\S]*operationId:[\s\S]*privateActionRecordSha256:/,
  );
  assert.match(
    prove,
    /const \{[\s\S]*output,[\s\S]*publicNullifier,[\s\S]*\} = privateAction/,
  );
});

test('rebase requires explicit user selection before manually retrying a conflicted operation', async () => {
  const source = await readFile(
    new URL('./action-lifecycle.mjs', import.meta.url),
    'utf8',
  );
  const start = source.indexOf('  async rebaseOperation(value = {}) {');
  const end = source.indexOf('\n  abandonOperation(', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const rebase = source.slice(start, end);
  assert.match(
    rebase,
    /'constructPrivateAction',\s*'explicitUserSelection',\s*'operationId'/,
  );
  assert.match(
    rebase,
    /typeof value\.explicitUserSelection !== 'boolean'/,
  );
  assert.match(rebase, /typeof value\.constructPrivateAction !== 'function'/);
  assert.match(
    rebase,
    /dormant\.journalState === 'conflicted'[\s\S]*value\.explicitUserSelection !== true[\s\S]*EXPLICIT_RETRY_SELECTION_REQUIRED/,
  );
  assert.match(
    rebase,
    /dormant\.journalState === 'conflicted'[\s\S]*this\.#store\.authorizeManualRetry\(\{[\s\S]*operationId: selectedId/,
  );
  assert.match(
    rebase,
    /await value\.constructPrivateAction\(freezeJson\(\{[\s\S]*expectedActionSequence: current\.actionSequence,[\s\S]*postActionSequence: current\.actionSequence \+ 1/,
  );
  assert.match(
    rebase,
    /await this\.#privateActionStore\.replace\(\{[\s\S]*expectedActionSequence: current\.actionSequence,[\s\S]*privateActionRecordSha256:[\s\S]*privateAction\.privateActionRecordSha256/,
  );
});

test('confirmAction exposes only an operation id and settles through authenticated synchronization', async () => {
  // No exported fixture supplies a validated PF10 descriptor/runtime pair, so
  // lifecycle construction would require a synthetic proof or verifier
  // substitute. Guard the public method contract directly instead.
  const source = await readFile(
    new URL('./action-lifecycle.mjs', import.meta.url),
    'utf8',
  );
  const start = source.indexOf('  async confirmAction({ operationId: id } = {}) {');
  const end = source.indexOf('\n  async resumeOperation(', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const method = source.slice(start, end);
  assert.match(
    method,
    /await this\.#refreshTip\(\{[\s\S]*phase: 'confirm'/,
  );
  assert.match(
    method,
    /settleConfirmedOperation\(\{[\s\S]*operationId: selectedId,[\s\S]*crashAt: null,/,
  );
  assert.doesNotMatch(method, /callerSupplied|confirmationDelta|stateDelta/);
});

test('signAction owns the wallet key and exposes no caller-supplied digest signer', async () => {
  const source = await readFile(
    new URL('./action-lifecycle.mjs', import.meta.url),
    'utf8',
  );
  const start = source.indexOf('  async signAction({');
  const end = source.indexOf('\n  async broadcastAction(', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const method = source.slice(start, end);
  assert.doesNotMatch(method, /signFunding,\s*(?:\r?\n)?\s*crashAt/);
  assert.doesNotMatch(method, /return signFunding\(/);
  assert.match(
    method,
    /canonicalizeJcs\(request\)[\s\S]*canonicalizeJcs\(assembled\.signingRequest\)/,
  );
  assert.match(
    method,
    /secp256k1\.signMessageHashSchnorr\([\s\S]*this\.#fundingPrivateKey/,
  );
  assert.match(
    method,
    /assertHighFeeSigningConfirmation\(/,
  );
  assert.doesNotMatch(source, /V2_FUNDING_SIGNING_REQUEST_SCHEMA/);
  assert.match(
    source,
    /'descriptor',\s*[\r\n]+\s*'fundingWallet',/,
  );
});
