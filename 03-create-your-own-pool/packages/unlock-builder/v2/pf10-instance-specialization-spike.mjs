import { createHash } from 'node:crypto';

/**
 * A deliberately fail-closed measurement seam for a prospective PF10
 * instance-specialization cache. It does not specialize, mutate, or reuse
 * runtime material. A caller must compare independently built runtimes before
 * considering any cache design.
 */
export const V2_PF10_INSTANCE_SPECIALIZATION_SPIKE_SCHEMA =
  'shieldkit-v2-direct-pf10-instance-specialization-spike-v1';

export class V2Pf10InstanceSpecializationSpikeError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'V2Pf10InstanceSpecializationSpikeError';
    this.code = code;
  }
}

const HEX_32 = /^[0-9a-f]{64}$/u;

function fail(code, message) {
  throw new V2Pf10InstanceSpecializationSpikeError(code, message);
}

function object(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('PF10_INSTANCE_SPECIALIZATION_RUNTIME_INVALID', `${label} must be an object`);
  }
  return value;
}

function exactHex(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(
      'PF10_INSTANCE_SPECIALIZATION_RUNTIME_INVALID',
      `${label} must be a lowercase 32-byte hexadecimal hash`,
    );
  }
  return value;
}

function bytesHash(value, label) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    fail('PF10_INSTANCE_SPECIALIZATION_RUNTIME_INVALID', `${label} must be bytes`);
  }
  return createHash('sha256').update(value).digest('hex');
}

function appendProgramHashes(target, prefix, program, {
  source = true,
  raw = true,
} = {}) {
  const item = object(program, prefix);
  const hashes = object(item.hashes, `${prefix}.hashes`);
  if (source) target[`${prefix}.source`] = exactHex(hashes.source, `${prefix}.hashes.source`);
  if (raw) target[`${prefix}.raw`] = exactHex(hashes.raw, `${prefix}.hashes.raw`);
  target[`${prefix}.redeem`] = exactHex(hashes.redeem, `${prefix}.hashes.redeem`);
  target[`${prefix}.lock`] = exactHex(hashes.lock, `${prefix}.hashes.lock`);
}

function frozenRecord(entries) {
  return Object.freeze(Object.fromEntries(entries));
}

/**
 * Extract every instance-dependent PF10 material byte sequence. The fixed
 * pairfold table is intentionally reported separately: it is a possible
 * immutable template input, never a permission to patch emitted bytecode.
 */
export function snapshotV2Pf10InstanceSpecializationRuntime(runtime) {
  const value = object(runtime, 'runtime');
  const instanceId = exactHex(value.instanceId, 'runtime.instanceId');
  const material = object(value.runtimeMaterial, 'runtime.runtimeMaterial');
  const structural = object(value.structural, 'runtime.structural');
  const programs = object(value.programs, 'runtime.programs');
  const changing = {
    'runtimeMaterial.materialSha256': exactHex(
      material.materialSha256,
      'runtime.runtimeMaterial.materialSha256',
    ),
    'structural.bindingRedeem': bytesHash(
      structural.bindingRedeem,
      'runtime.structural.bindingRedeem',
    ),
    'structural.bindingLock': bytesHash(
      structural.bindingLock,
      'runtime.structural.bindingLock',
    ),
    'structural.stateHelper': bytesHash(
      structural.stateHelper,
      'runtime.structural.stateHelper',
    ),
    'structural.stateUnlock': bytesHash(
      structural.stateUnlock,
      'runtime.structural.stateUnlock',
    ),
    'structural.stateLock': bytesHash(
      structural.stateLock,
      'runtime.structural.stateLock',
    ),
  };
  if (!Array.isArray(structural.verifierLocks) || structural.verifierLocks.length !== 10) {
    fail(
      'PF10_INSTANCE_SPECIALIZATION_RUNTIME_INVALID',
      'runtime.structural.verifierLocks must contain the exact ten PF10 locks',
    );
  }
  structural.verifierLocks.forEach((lock, index) => {
    changing[`structural.verifierLocks[${index}]`] = bytesHash(
      lock,
      `runtime.structural.verifierLocks[${index}]`,
    );
  });
  appendProgramHashes(changing, 'programs.terminal', programs.terminal);
  appendProgramHashes(changing, 'programs.executor', programs.executor);
  appendProgramHashes(changing, 'programs.exactFinal', programs.exactFinal);
  appendProgramHashes(changing, 'programs.miller', programs.miller);
  appendProgramHashes(changing, 'programs.fused', programs.fused, {
    source: false,
    raw: false,
  });
  if (!Array.isArray(programs.exactMsm) || programs.exactMsm.length !== 3) {
    fail(
      'PF10_INSTANCE_SPECIALIZATION_RUNTIME_INVALID',
      'runtime.programs.exactMsm must contain exactly three programs',
    );
  }
  programs.exactMsm.forEach((program, index) => {
    appendProgramHashes(changing, `programs.exactMsm[${index}]`, program);
  });

  const fixedTables = object(value.fixedTables, 'runtime.fixedTables');
  const reusable = {
    'fixedTables.remoteBlobSha256': exactHex(
      fixedTables.remoteBlobSha256,
      'runtime.fixedTables.remoteBlobSha256',
    ),
    'fixedTables.terminalTableHash256': exactHex(
      fixedTables.terminalTableHash256,
      'runtime.fixedTables.terminalTableHash256',
    ),
  };
  if (!Array.isArray(fixedTables.carrierPadsSha256)
    || !Array.isArray(fixedTables.roleTableHash256)) {
    fail(
      'PF10_INSTANCE_SPECIALIZATION_RUNTIME_INVALID',
      'runtime fixed-table hashes must be arrays',
    );
  }
  fixedTables.carrierPadsSha256.forEach((hash, index) => {
    reusable[`fixedTables.carrierPadsSha256[${index}]`] = exactHex(
      hash,
      `runtime.fixedTables.carrierPadsSha256[${index}]`,
    );
  });
  fixedTables.roleTableHash256.forEach((hash, index) => {
    reusable[`fixedTables.roleTableHash256[${index}]`] = exactHex(
      hash,
      `runtime.fixedTables.roleTableHash256[${index}]`,
    );
  });
  return Object.freeze({
    schema: V2_PF10_INSTANCE_SPECIALIZATION_SPIKE_SCHEMA,
    instanceId,
    changing: frozenRecord(Object.entries(changing)),
    reusable: frozenRecord(Object.entries(reusable)),
  });
}

/**
 * Compare two independently produced full-builder outputs. Any differing
 * emitted byte is a hard stop: no source substitution, successor-lock patch,
 * or mixed output is a valid specialization result.
 */
export function compareV2Pf10InstanceSpecializationRuntimes(left, right) {
  const before = snapshotV2Pf10InstanceSpecializationRuntime(left);
  const after = snapshotV2Pf10InstanceSpecializationRuntime(right);
  if (before.instanceId === after.instanceId) {
    fail(
      'PF10_INSTANCE_SPECIALIZATION_IDS_NOT_DISTINCT',
      'instance-specialization comparison requires distinct instance IDs',
    );
  }
  const changedPaths = Object.keys(before.changing).filter(
    (key) => before.changing[key] !== after.changing[key],
  );
  const unchangedPaths = Object.keys(before.changing).filter(
    (key) => before.changing[key] === after.changing[key],
  );
  const reusableEqualPaths = Object.keys(before.reusable).filter(
    (key) => before.reusable[key] === after.reusable[key],
  );
  return Object.freeze({
    schema: V2_PF10_INSTANCE_SPECIALIZATION_SPIKE_SCHEMA,
    status: changedPaths.length === 0
      ? 'byte-equal-requires-independent-soundness-review'
      : 'byte-divergence-no-specialization',
    specializationPermitted: changedPaths.length === 0,
    sourceInstanceId: before.instanceId,
    targetInstanceId: after.instanceId,
    changedPaths: Object.freeze(changedPaths),
    unchangedPaths: Object.freeze(unchangedPaths),
    reusableEqualPaths: Object.freeze(reusableEqualPaths),
  });
}

/** Fail closed for callers that accidentally attempt to act on divergence. */
export function assertV2Pf10InstanceSpecializationByteEquality(left, right) {
  const comparison = compareV2Pf10InstanceSpecializationRuntimes(left, right);
  if (!comparison.specializationPermitted) {
    fail(
      'PF10_INSTANCE_SPECIALIZATION_BYTE_DIVERGENCE',
      `PF10 instance specialization is blocked by ${comparison.changedPaths.length} byte-hash divergences`,
    );
  }
  return comparison;
}
