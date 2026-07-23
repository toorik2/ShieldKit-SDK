import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const packageDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(packageDirectory, '../..');
const evidenceRoot = path.join(repositoryRoot, 'evidence');

export class EvidenceValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EvidenceValidationError';
  }
}

const fail = (message) => {
  throw new EvidenceValidationError(message);
};

async function sha256File(filename) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(filename)) digest.update(chunk);
  return digest.digest('hex');
}

async function findObservationFiles(directory) {
  const found = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) found.push(...await findObservationFiles(candidate));
    else if (entry.isFile() && entry.name === 'observation.json') found.push(candidate);
  }
  return found.sort();
}

function inside(parent, child) {
  return child === parent || child.startsWith(`${parent}${path.sep}`);
}

export async function createEvidenceValidator() {
  const schema = JSON.parse(await readFile(
    path.join(repositoryRoot, 'policy/evidence.schema.json'),
    'utf8',
  ));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

export async function validateEvidenceFile(filename, validateSchema) {
  const relativeRecord = path.relative(repositoryRoot, filename);
  let record;
  try {
    record = JSON.parse(await readFile(filename, 'utf8'));
  } catch (error) {
    fail(`${relativeRecord}: invalid JSON: ${error.message}`);
  }
  if (!validateSchema(record)) {
    const errors = validateSchema.errors
      .map((error) => `${error.instancePath || '/'} ${error.message}`)
      .join('; ');
    fail(`${relativeRecord}: schema validation failed: ${errors}`);
  }

  const ids = new Set();
  for (const artifact of record.artifacts) {
    if (ids.has(artifact.path)) {
      fail(`${relativeRecord}: duplicate artifact path ${artifact.path}`);
    }
    ids.add(artifact.path);
    if (path.isAbsolute(artifact.path) || artifact.path.split('/').includes('..')) {
      fail(`${relativeRecord}: artifact path must be repository-relative: ${artifact.path}`);
    }
    const candidate = path.resolve(repositoryRoot, ...artifact.path.split('/'));
    if (!inside(repositoryRoot, candidate)) {
      fail(`${relativeRecord}: artifact path escapes repository: ${artifact.path}`);
    }
    const stats = await lstat(candidate).catch(() => fail(
      `${relativeRecord}: artifact is missing: ${artifact.path}`,
    ));
    if (!stats.isFile() || stats.isSymbolicLink()) {
      fail(`${relativeRecord}: artifact must be a regular non-symlink file: ${artifact.path}`);
    }
    const resolved = await realpath(candidate);
    if (!inside(repositoryRoot, resolved) || resolved !== candidate) {
      fail(`${relativeRecord}: artifact path resolves through a symlink: ${artifact.path}`);
    }
    if (stats.size !== artifact.bytes) {
      fail(
        `${relativeRecord}: artifact byte length ${stats.size} != ${artifact.bytes}: `
        + artifact.path,
      );
    }
    const actualHash = await sha256File(resolved);
    if (actualHash !== artifact.sha256) {
      fail(
        `${relativeRecord}: artifact SHA-256 ${actualHash} != ${artifact.sha256}: `
        + artifact.path,
      );
    }
  }

  if (record.verdict === 'PASS') {
    const failed = (record.tests ?? []).filter((test) => test.pass === false);
    if (failed.length > 0) {
      fail(`${relativeRecord}: PASS record contains ${failed.length} failing test(s)`);
    }
  }
  return record;
}

export async function validateRepositoryEvidence() {
  const validateSchema = await createEvidenceValidator();
  const records = await findObservationFiles(evidenceRoot);
  if (records.length === 0) fail('no evidence observation records found');
  const validated = [];
  for (const filename of records) {
    validated.push(await validateEvidenceFile(filename, validateSchema));
  }
  return validated;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const records = await validateRepositoryEvidence();
    console.log(`evidence validation passed: ${records.length} record(s)`);
  } catch (error) {
    console.error(`evidence validation failed: ${error.message}`);
    process.exitCode = 1;
  }
}

