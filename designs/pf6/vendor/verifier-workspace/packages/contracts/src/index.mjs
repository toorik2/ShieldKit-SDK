import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const schemas = Object.freeze({
  lane: 'verifier.cash/lane/v1',
  candidate: 'verifier.cash/candidate/v1',
  bundle: 'verifier.cash/candidate-bundle/v1',
  evidence: 'verifier.cash/evidence/v1',
});

const idPattern = /^[a-z0-9][a-z0-9._-]*$/;
const sha256Pattern = /^[a-f0-9]{64}$/;

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const requireObject = (value, path, errors) => {
  if (!isObject(value)) errors.push(`${path} must be an object`);
  return isObject(value);
};
const requireString = (value, path, errors) => {
  if (typeof value !== 'string' || value.length === 0) errors.push(`${path} must be a non-empty string`);
};
const requireId = (value, path, errors) => {
  requireString(value, path, errors);
  if (typeof value === 'string' && !idPattern.test(value)) errors.push(`${path} must match ${idPattern}`);
};
const requireRelativePath = (value, path, errors) => {
  requireString(value, path, errors);
  if (typeof value === 'string' && (value.startsWith('/') || value.includes('..') || value.includes('\\'))) {
    errors.push(`${path} must be a repository-relative POSIX path without '..'`);
  }
};
const requireInteger = (value, path, errors, minimum = 0) => {
  if (!Number.isInteger(value) || value < minimum) errors.push(`${path} must be an integer >= ${minimum}`);
};

export const canonicalize = (value) => {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
};

export const canonicalJson = (value) => `${JSON.stringify(canonicalize(value))}\n`;
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
export const hashCanonical = (value) => sha256(canonicalJson(value));
export const hashFile = (path) => sha256(readFileSync(path));
export const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));

export const validateLane = (lane) => {
  const errors = [];
  if (!requireObject(lane, 'lane', errors)) return errors;
  if (lane.schema !== schemas.lane) errors.push(`schema must be ${schemas.lane}`);
  requireId(lane.id, 'id', errors);
  requireString(lane.title, 'title', errors);
  requireRelativePath(lane.frontierCandidate, 'frontierCandidate', errors);
  for (const [field, values] of [['writeScope', lane.writeScope], ['sharedReadOnly', lane.sharedReadOnly]]) {
    if (!Array.isArray(values) || values.length === 0) errors.push(`${field} must be a non-empty array`);
    else values.forEach((value, index) => requireString(value, `${field}[${index}]`, errors));
  }
  if (!requireObject(lane.gates, 'gates', errors)) return errors;
  for (const tier of ['fast', 'qualification', 'promotion']) {
    if (!Array.isArray(lane.gates[tier]) || lane.gates[tier].length === 0) errors.push(`gates.${tier} must be a non-empty array`);
  }
  return errors;
};

export const validateCandidate = (candidate) => {
  const errors = [];
  if (!requireObject(candidate, 'candidate', errors)) return errors;
  if (candidate.schema !== schemas.candidate) errors.push(`schema must be ${schemas.candidate}`);
  requireId(candidate.id, 'id', errors);
  requireId(candidate.lane, 'lane', errors);
  if (!['research', 'measured', 'promoted'].includes(candidate.status)) errors.push('status must be research, measured, or promoted');
  if (requireObject(candidate.capability, 'capability', errors)) {
    for (const field of ['proofSystem', 'field', 'structure', 'proofBinding', 'vkBinding', 'deploymentBinding']) {
      requireString(candidate.capability[field], `capability.${field}`, errors);
    }
  }
  if (requireObject(candidate.toolchain, 'toolchain', errors)) {
    for (const field of ['cashc', 'libauth', 'leanbch', 'bch']) requireString(candidate.toolchain[field], `toolchain.${field}`, errors);
  }
  if (requireObject(candidate.build, 'build', errors)) {
    if (!['artifact-bundle', 'lane-module'].includes(candidate.build.adapter)) errors.push('build.adapter must be artifact-bundle or lane-module');
    if (candidate.build.adapter === 'artifact-bundle') {
      requireRelativePath(candidate.build.artifactRoot, 'build.artifactRoot', errors);
      if (requireObject(candidate.build.files, 'build.files', errors)) {
        for (const [role, path] of Object.entries(candidate.build.files)) {
          requireId(role, `build.files role ${role}`, errors);
          requireRelativePath(path, `build.files.${role}`, errors);
        }
      }
    }
    if (candidate.build.adapter === 'lane-module') {
      requireRelativePath(candidate.build.module, 'build.module', errors);
      for (const field of ['entrypoint', 'fixture']) {
        if (candidate.build[field] !== undefined) requireRelativePath(candidate.build[field], `build.${field}`, errors);
      }
      requireObject(candidate.build.profile, 'build.profile', errors);
    }
  }
  if (requireObject(candidate.judge, 'judge', errors)) {
    requireString(candidate.judge.profile, 'judge.profile', errors);
    requireInteger(candidate.judge.sourceValueSatoshis, 'judge.sourceValueSatoshis', errors, 1);
    requireInteger(candidate.judge.sequenceNumber, 'judge.sequenceNumber', errors, 0);
    if (candidate.judge.execution !== undefined && requireObject(candidate.judge.execution, 'judge.execution', errors)) {
      if (!['covenant-chain', 'singleton-size'].includes(candidate.judge.execution.kind)) {
        errors.push('judge.execution.kind must be covenant-chain or singleton-size');
      }
      if (candidate.judge.execution.kind === 'covenant-chain' &&
          (typeof candidate.judge.execution.category !== 'string' || !sha256Pattern.test(candidate.judge.execution.category))) {
        errors.push('judge.execution.category must be 32-byte hex');
      }
    }
    if (requireObject(candidate.judge.expected, 'judge.expected', errors)) {
      for (const field of ['scriptBytes', 'txOverheadBytes', 'score', 'inputCount']) requireInteger(candidate.judge.expected[field], `judge.expected.${field}`, errors, 1);
      if (candidate.judge.expected.transactionCount !== undefined) requireInteger(candidate.judge.expected.transactionCount, 'judge.expected.transactionCount', errors, 1);
      for (const field of ['lockingBytes', 'operationCost', 'inputsForHeaviestStep', 'proofsTested']) {
        if (candidate.judge.expected[field] !== undefined) requireInteger(candidate.judge.expected[field], `judge.expected.${field}`, errors, 1);
      }
      if (candidate.judge.expected.lockingSha256 !== undefined &&
          (typeof candidate.judge.expected.lockingSha256 !== 'string' || !sha256Pattern.test(candidate.judge.expected.lockingSha256))) {
        errors.push('judge.expected.lockingSha256 must be SHA-256');
      }
      if (candidate.judge.expected.artifactHashes !== undefined && requireObject(candidate.judge.expected.artifactHashes, 'judge.expected.artifactHashes', errors)) {
        for (const [role, digest] of Object.entries(candidate.judge.expected.artifactHashes)) {
          requireId(role, `judge.expected.artifactHashes role ${role}`, errors);
          if (typeof digest !== 'string' || !sha256Pattern.test(digest)) errors.push(`judge.expected.artifactHashes.${role} must be SHA-256`);
        }
      }
    }
  }
  if (requireObject(candidate.provenance, 'provenance', errors)) {
    requireString(candidate.provenance.sourceCommit, 'provenance.sourceCommit', errors);
    requireString(candidate.provenance.scope, 'provenance.scope', errors);
  }
  return errors;
};

export const validateBundle = (bundle) => {
  const errors = [];
  if (!requireObject(bundle, 'bundle', errors)) return errors;
  if (bundle.schema !== schemas.bundle) errors.push(`schema must be ${schemas.bundle}`);
  requireId(bundle.runId, 'runId', errors);
  requireId(bundle.candidateId, 'candidateId', errors);
  requireId(bundle.lane, 'lane', errors);
  if (!sha256Pattern.test(bundle.candidateManifestSha256 ?? '')) errors.push('candidateManifestSha256 must be SHA-256');
  requireString(bundle.sourceCommit, 'sourceCommit', errors);
  if (requireObject(bundle.files, 'files', errors)) {
    for (const [role, ref] of Object.entries(bundle.files)) {
      requireId(role, `files role ${role}`, errors);
      if (requireObject(ref, `files.${role}`, errors)) {
        requireRelativePath(ref.path, `files.${role}.path`, errors);
        if (!sha256Pattern.test(ref.sha256 ?? '')) errors.push(`files.${role}.sha256 must be SHA-256`);
        requireInteger(ref.bytes, `files.${role}.bytes`, errors, 1);
      }
    }
  }
  if (!requireObject(bundle.judge, 'judge', errors)) return errors;
  return errors;
};

export const validateEvidence = (evidence) => {
  const errors = [];
  if (!requireObject(evidence, 'evidence', errors)) return errors;
  if (evidence.schema !== schemas.evidence) errors.push(`schema must be ${schemas.evidence}`);
  requireId(evidence.runId, 'runId', errors);
  requireId(evidence.candidateId, 'candidateId', errors);
  if (!['fast', 'qualification', 'promotion'].includes(evidence.tier)) errors.push('tier must be fast, qualification, or promotion');
  if (!['green', 'red'].includes(evidence.verdict)) errors.push('verdict must be green or red');
  if (!Array.isArray(evidence.checks) || evidence.checks.length === 0) errors.push('checks must be a non-empty array');
  return errors;
};

export const assertValid = (kind, value) => {
  const validators = { lane: validateLane, candidate: validateCandidate, bundle: validateBundle, evidence: validateEvidence };
  const validator = validators[kind];
  if (!validator) throw new Error(`unknown contract kind: ${kind}`);
  const errors = validator(value);
  if (errors.length > 0) throw new Error(`${kind} validation failed:\n- ${errors.join('\n- ')}`);
  return value;
};
