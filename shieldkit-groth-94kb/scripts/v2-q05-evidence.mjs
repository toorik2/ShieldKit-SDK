#!/usr/bin/env node
/* Generate a secure, commit-bound local Q-05 evidence bundle. */
import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { readFile, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../packages/profile/load.mjs';
import {
  Q05_BUNDLE_SCHEMA,
  Q05_EVIDENCE_SCHEMA,
  Q05_SOURCE_BINDING_SCHEMA,
  Q05_SOURCE_DEFINITIONS,
  Q05_VALIDATED_PROPERTIES,
  createQ05ExecutionSnapshot,
  destroyQ05ExecutionSnapshot,
  q05Git,
  q05GitExecutionBoundary,
  runQ05JsEvidenceFromSnapshot,
  runQ05RustEvidenceFromSnapshot,
  validateQ05ExecutionSnapshot,
  validateQ05TrackedIndexFlags,
  verifyQ05EvidenceBundle,
} from './v2-q05-evidence-verify.mjs';

const projectRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const repositoryRoot = resolve(projectRoot, '..');
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (message) => { throw new Error(message); };

function assertCleanCommittedCheckout() {
  if (resolve(q05Git(['rev-parse', '--show-toplevel'], 'git root').trim()) !== repositoryRoot) fail('generator workspace root is not the checkout root');
  if (q05Git(['status', '--porcelain=v1', '--untracked-files=all'], 'git status') !== '') fail('refusing real Q-05 evidence from dirty or uncommitted source');
  validateQ05TrackedIndexFlags(q05Git(['ls-files', '-v', '-z'], 'git tracked-index flags'));
  return Object.freeze({
    head: q05Git(['rev-parse', 'HEAD'], 'git HEAD').trim(),
    tree: q05Git(['rev-parse', 'HEAD^{tree}'], 'git tree').trim(),
  });
}
function gitBlobFor(path) {
  const record = q05Git(['ls-tree', 'HEAD', '--', path], `git tree entry for ${path}`).trim();
  const match = record.match(/^100644 blob ([0-9a-f]{40})\t(.+)$/);
  if (!match || match[2] !== path) fail(`required source ${path} is not a committed regular blob`);
  return match[1];
}
function ensureAbsoluteOutput(value) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) fail('output path must be an absolute normalized new directory');
  if (relative(repositoryRoot, value) === '' || !relative(repositoryRoot, value).startsWith(`..${sep}`)) fail('output directory must be outside the source checkout so it cannot dirty source binding');
  return value;
}
async function secureNewDirectory(path) {
  const parent = dirname(path);
  let parentStat;
  try { parentStat = lstatSync(parent); } catch { fail('output parent does not exist'); }
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || await realpath(parent) !== parent) fail('output parent must be a direct directory');
  try { mkdirSync(path, { mode: 0o700 }); } catch { fail('output directory already exists or cannot be created'); }
  chmodSync(path, 0o700);
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 || (typeof process.getuid === 'function' && stat.uid !== process.getuid()) || await realpath(path) !== path) fail('created output directory is not a direct user-owned mode-0700 directory');
}
function atomicSecureWrite(directory, name, value) {
  if (!/^[a-z][a-z0-9-]*\.json$/.test(name)) fail('artifact name is invalid');
  const finalPath = resolve(directory, name);
  if (relative(directory, finalPath).startsWith(`..${sep}`)) fail('artifact path escapes output directory');
  const temporaryPath = resolve(directory, `.${name}.${process.pid}.tmp`);
  const bytes = Buffer.from(canonicalJson(value));
  let descriptor;
  try {
    descriptor = openSync(temporaryPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    let written = 0;
    while (written < bytes.length) written += writeSync(descriptor, bytes, written, bytes.length - written);
    fsyncSync(descriptor);
    closeSync(descriptor); descriptor = undefined;
    chmodSync(temporaryPath, 0o600);
    renameSync(temporaryPath, finalPath);
    const stat = lstatSync(finalPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) fail(`artifact ${name} lost secure-file properties`);
    const directoryDescriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY);
    try { fsyncSync(directoryDescriptor); } finally { closeSync(directoryDescriptor); }
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { rmSync(temporaryPath, { force: true }); } catch { /* preserve original failure */ }
    throw error;
  }
  return Object.freeze({ path: name, bytes: bytes.length, sha256: digest(bytes) });
}

async function buildSourceBinding(checkout, snapshot) {
  validateQ05ExecutionSnapshot(snapshot);
  const sources = [];
  for (const definition of Q05_SOURCE_DEFINITIONS) {
    const bytes = await readFile(resolve(snapshot.repositoryRoot, definition.path));
    sources.push(Object.freeze({ role: definition.role, path: definition.path, gitBlob: gitBlobFor(definition.path), sha256: digest(bytes) }));
  }
  return Object.freeze({
    schema: Q05_SOURCE_BINDING_SCHEMA,
    sourceRoot: 'shieldkit-groth-94kb',
    git: Object.freeze({ head: checkout.head, tree: checkout.tree }),
    gitExecution: q05GitExecutionBoundary(),
    executionSnapshot: snapshot.record,
    sources,
  });
}
async function recheckSourceBinding(binding, checkout, snapshot) {
  const current = assertCleanCommittedCheckout();
  if (current.head !== checkout.head || current.tree !== checkout.tree) fail('source HEAD or tree changed during Q-05 evidence generation');
  validateQ05ExecutionSnapshot(snapshot);
  for (const source of binding.sources) {
    if (gitBlobFor(source.path) !== source.gitBlob) fail(`committed source blob changed during generation: ${source.path}`);
    if (digest(await readFile(resolve(snapshot.repositoryRoot, source.path))) !== source.sha256) fail(`exact-HEAD snapshot source changed during generation: ${source.path}`);
  }
}

export async function generateQ05EvidenceBundle(outputPath) {
  const checkout = assertCleanCommittedCheckout();
  const output = ensureAbsoluteOutput(outputPath);
  await secureNewDirectory(output);
  let snapshot;
  try {
    snapshot = createQ05ExecutionSnapshot(checkout);
    const source = await buildSourceBinding(checkout, snapshot);
    const js = runQ05JsEvidenceFromSnapshot(snapshot);
    const rust = runQ05RustEvidenceFromSnapshot(snapshot);
    await recheckSourceBinding(source, checkout, snapshot);
    const sourceArtifact = atomicSecureWrite(output, 'source-binding.json', source);
    const jsArtifact = atomicSecureWrite(output, 'js-evidence.json', js);
    const rustArtifact = atomicSecureWrite(output, 'rust-evidence.json', rust);
    const evidence = Object.freeze({
      schema: Q05_EVIDENCE_SCHEMA,
      status: 'local-evidence-only',
      sourceBindingSha256: sourceArtifact.sha256,
      jsEvidenceSha256: jsArtifact.sha256,
      rustEvidenceSha256: rustArtifact.sha256,
      validatedProperties: Q05_VALIDATED_PROPERTIES,
      boundaries: Object.freeze([
        'local evidence only; not BCH chain execution or transaction validation',
        'not an independent cryptographic audit or audit closure',
        'not final-profile, circuit, release, or qualification evidence',
        'not authenticated external evidence or a clean-host attestation',
        'does not establish global spent-randomness or reuse prevention',
        'does not establish process-memory zeroization',
        'does not authenticate a compromised parent process',
      ]),
    });
    const evidenceArtifact = atomicSecureWrite(output, 'evidence.json', evidence);
    const manifest = Object.freeze({
      schema: Q05_BUNDLE_SCHEMA,
      artifacts: Object.freeze([
        Object.freeze({ role: 'evidence', ...evidenceArtifact }),
        Object.freeze({ role: 'js-evidence', ...jsArtifact }),
        Object.freeze({ role: 'rust-evidence', ...rustArtifact }),
        Object.freeze({ role: 'source-binding', ...sourceArtifact }),
      ]),
    });
    atomicSecureWrite(output, 'manifest.json', manifest);
    destroyQ05ExecutionSnapshot(snapshot);
    snapshot = undefined;
    return verifyQ05EvidenceBundle(output);
  } catch (error) {
    // A partial bundle is not evidence. Keep removal scoped to the newly
    // created output directory only; callers receive the original failure.
    try { rmSync(output, { recursive: true, force: true }); } catch { /* preserve original failure */ }
    throw error;
  } finally {
    if (snapshot !== undefined) {
      try { destroyQ05ExecutionSnapshot(snapshot); } catch { /* preserve original result */ }
    }
  }
}

function parseArguments(argv) {
  if (argv.length !== 2 || argv[0] !== '--out') fail('usage: v2-q05-evidence.mjs --out /absolute/new-bundle-directory');
  return argv[1];
}
async function runCli() {
  try {
    const result = await generateQ05EvidenceBundle(parseArguments(process.argv.slice(2)));
    process.stdout.write(`${canonicalJson(result)}\n`);
  } catch (error) {
    process.stderr.write(`Q05 evidence generation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runCli();
}
