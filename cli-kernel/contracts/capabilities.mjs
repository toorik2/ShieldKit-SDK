/**
 * Capability and maturity model — CLI_ARCHITECTURE_PLAN.md § Capability and maturity model
 */

export const CAPABILITY_STATUSES = Object.freeze([
  'qualified',
  'experimental',
  'blocked',
  'unsupported',
]);

export const CAPABILITY_KEYS = Object.freeze([
  'destinationBinding',
  'wholeTransactionVm',
  'durablePreparation',
  'singleSendAdmission',
  'exactReadback',
  'syncRecovery',
  'noteRecovery',
  'createPool',
  'deposit',
  'transfer',
  'withdraw',
]);

/** These guarantees are prerequisites for every money-moving verb. */
export const MUTATION_SAFETY_GUARANTEES = Object.freeze([
  'destinationBinding',
  'wholeTransactionVm',
  'durablePreparation',
  'singleSendAdmission',
  'exactReadback',
]);

const STATUS_SET = new Set(CAPABILITY_STATUSES);
const PROFILE_ID = /^[0-9a-f]{64}$/;
const CONTENT_REFERENCE = /^sha256:[0-9a-f]{64}$/;

export function assertCapabilityStatus(value) {
  if (!STATUS_SET.has(value)) {
    throw new Error(`invalid capability status: ${value}`);
  }
  return value;
}

/**
 * @param {object} args
 * @param {string|null} args.profileId
 * @param {string} args.designId
 * @param {string} args.network
 * @param {Record<string, { status: string, evidence?: string[], blockers?: string[] }>} args.guarantees
 */
export function buildCapabilityRecord({
  designId,
  profileId = null,
  profileStatus = profileId === null ? 'unfrozen' : 'frozen',
  network,
  guarantees = {},
  overall = null,
  evidence = [],
  blockers = [],
} = {}) {
  if (typeof designId !== 'string' || designId.length === 0) {
    throw new Error('designId required');
  }
  if (profileId !== null && !PROFILE_ID.test(profileId)) {
    throw new Error('profileId must be null or 64-char lowercase hex');
  }
  if (profileId === null && !['unselected', 'unfrozen'].includes(profileStatus)) {
    throw new Error('missing profileId must be explicitly unselected or unfrozen');
  }
  if (profileId !== null && profileStatus !== 'frozen') {
    throw new Error('exact profileId must have frozen profileStatus');
  }
  const g = {};
  for (const [key, val] of Object.entries(guarantees)) {
    if (!CAPABILITY_KEYS.includes(key)) {
      throw new Error(`unknown capability guarantee: ${key}`);
    }
    if (val === null || typeof val !== 'object') {
      throw new Error(`guarantee ${key} must be an object`);
    }
    const status = assertCapabilityStatus(val.status);
    const guaranteeEvidence = [...(val.evidence || [])];
    assertContentReferences(guaranteeEvidence, `guarantee ${key} evidence`);
    if (status === 'qualified' && guaranteeEvidence.length === 0) {
      throw new Error(`qualified guarantee ${key} requires content-addressed evidence`);
    }
    g[key] = Object.freeze({
      status,
      evidence: Object.freeze(guaranteeEvidence),
      blockers: Object.freeze([...(val.blockers || [])]),
    });
  }
  const overallStatus = overall
    ? assertCapabilityStatus(overall)
    : deriveOverall(g);
  const recordEvidence = [...evidence];
  const recordBlockers = [...blockers];
  assertContentReferences(recordEvidence, 'record evidence');
  if (overallStatus === 'qualified' && profileId === null) {
    throw new Error('a design-family capability record cannot be qualified');
  }
  if (overallStatus === 'qualified' && recordBlockers.length > 0) {
    throw new Error('a qualified capability record cannot retain blockers');
  }
  return Object.freeze({
    schema: 'shieldkit-capability-record/v2',
    designId,
    profileId,
    profileStatus,
    network,
    overall: overallStatus,
    guarantees: Object.freeze(g),
    evidence: Object.freeze(recordEvidence),
    blockers: Object.freeze(recordBlockers),
    mutationAuthority: profileId === null ? 'none-design-family-only' : 'profile-specific',
  });
}

function assertContentReferences(values, label) {
  for (const value of values) {
    if (typeof value !== 'string' || !CONTENT_REFERENCE.test(value)) {
      throw new Error(`${label} entries must be sha256:<64 lowercase hex>`);
    }
  }
}

function deriveOverall(guarantees) {
  const statuses = Object.values(guarantees).map((g) => g.status);
  if (statuses.length === 0) return 'unsupported';
  if (statuses.every((s) => s === 'qualified')) return 'qualified';
  if (statuses.some((s) => s === 'blocked')) return 'blocked';
  if (statuses.some((s) => s === 'experimental')) return 'experimental';
  return 'unsupported';
}

/** True if a mutating verb may run for this capability record. */
export function isMutationAllowed(record, verb, { allowLab = false } = {}) {
  if (!record || typeof record !== 'object') return false;
  if (!PROFILE_ID.test(record.profileId || '') || record.profileStatus !== 'frozen') return false;
  if (record.overall === 'blocked' || record.overall === 'unsupported') return false;
  if ((record.blockers || []).length > 0) return false;
  const g = record.guarantees?.[verb];
  if (!g) return false;
  const verbAllowed = g.status === 'qualified'
    || (g.status === 'experimental' && allowLab === true);
  if (!verbAllowed) return false;
  if (g.status === 'qualified' && (g.evidence || []).length === 0) return false;
  return MUTATION_SAFETY_GUARANTEES.every((key) => {
    const guarantee = record.guarantees?.[key];
    return guarantee?.status === 'qualified'
      && guarantee.evidence?.length > 0
      && guarantee.blockers?.length === 0;
  });
}

export function mutationBlockReason(record, verb, { allowLab = false } = {}) {
  if (!record || typeof record !== 'object') return 'capability record missing';
  if (!PROFILE_ID.test(record.profileId || '') || record.profileStatus !== 'frozen') {
    return 'mutation requires an exact frozen profile selected from a validated home or profile package';
  }
  if (record.overall === 'blocked' || record.overall === 'unsupported') {
    return `profile support is ${record.overall}: ${(record.blockers || []).join('; ') || 'not admitted'}`;
  }
  if ((record.blockers || []).length > 0) {
    return `profile support retains blockers: ${record.blockers.join('; ')}`;
  }
  const g = record?.guarantees?.[verb];
  if (!g) return `capability ${verb} not declared for profile`;
  if (g.status === 'experimental' && !allowLab) {
    return `capability ${verb} is experimental; pass --allow-lab or home opt-in`;
  }
  if (g.status === 'blocked') {
    return `capability ${verb} blocked: ${(g.blockers || []).join('; ') || 'no evidence'}`;
  }
  const missingSafety = MUTATION_SAFETY_GUARANTEES.find((key) => {
    const guarantee = record.guarantees?.[key];
    return guarantee?.status !== 'qualified'
      || guarantee.evidence?.length === 0
      || guarantee.blockers?.length > 0;
  });
  if (missingSafety) {
    return `mutation safety guarantee ${missingSafety} is not qualified with content-addressed evidence`;
  }
  if (isMutationAllowed(record, verb, { allowLab })) return null;
  return `capability ${verb} unsupported`;
}
