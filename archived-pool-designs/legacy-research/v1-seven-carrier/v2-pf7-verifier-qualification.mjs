import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import {
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  stat,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ACTIONS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const SHA256 = /^[0-9a-f]{64}$/;
const SETUP_SCHEMA = 'shieldkit-v2-pf7-verifier-qualification-setup-v1';
const ARTIFACTS_SCHEMA = 'shieldkit-v2-pf7-verifier-qualification-artifacts-v1';
const EVIDENCE_SCHEMA = 'shieldkit-v2-direct-development-groth16-qualification-v4';
const REAL_ENTRYPOINT = 'lanes/bn254-onetx/src/c7/build.ts';
const REAL_EXECUTABLE = 'harness/node_modules/.bin/tsx';
const DYNAMIC_ENVIRONMENT = Object.freeze({
  adapterPath: 'C7_SHIELD_ADAPTER_FILE',
  adapterSha256: 'C7_SHIELD_ADAPTER_SHA256',
  packetPath: 'C7_SHIELD_ACTION_PACKET_FILE',
  packetSha256: 'C7_SHIELD_ACTION_PACKET_SHA256',
});

export class V2Pf7VerifierQualificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Pf7VerifierQualificationError';
  }
}

const fail = (message) => { throw new V2Pf7VerifierQualificationError(message); };
const own = (value, key) => Object.hasOwn(value, key);

export const canonicalJson = (value) => {
  const normalize = (item) => {
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return item;
    if (typeof item === 'bigint') return item.toString();
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) fail('cannot serialize non-finite JSON number');
      return item;
    }
    if (Array.isArray(item)) return item.map(normalize);
    if (typeof item !== 'object') fail('cannot serialize non-JSON value');
    const result = Object.create(null);
    for (const key of Object.keys(item).sort()) result[key] = normalize(item[key]);
    return result;
  };
  return `${JSON.stringify(normalize(value), null, 2)}\n`;
};

export function parseV2Pf7QualificationArguments(argv, cwd = process.cwd()) {
  const options = Object.freeze({
    '--verifier-root': 'verifierRoot',
    '--qualification-evidence': 'qualificationEvidence',
    '--setup': 'setup',
    '--artifacts': 'artifacts',
    '--output': 'outputDirectory',
  });
  if (!Array.isArray(argv)) fail('CLI arguments must be an array');
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    const key = options[option];
    const value = argv[index + 1];
    if (key === undefined) fail(`unknown or positional argument: ${String(option)}`);
    if (own(parsed, key)) fail(`duplicate CLI option: ${option}`);
    if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) fail(`missing path for ${option}`);
    const resolved = path.resolve(cwd, value);
    if (!path.isAbsolute(value)) fail(`${option} must be an explicit absolute path`);
    parsed[key] = resolved;
  }
  for (const [option, key] of Object.entries(options)) if (!own(parsed, key)) fail(`missing required CLI option: ${option}`);
  return Object.freeze(parsed);
}

async function regularFile(filename, label, { allowEmpty = false } = {}) {
  if (!path.isAbsolute(filename)) fail(`${label} must be an absolute path`);
  let metadata;
  try { metadata = await lstat(filename); } catch (error) { fail(`${label} is unavailable: ${error.message}`); }
  if (!metadata.isFile() || metadata.isSymbolicLink() || (!allowEmpty && metadata.size === 0)) fail(`${label} must be a ${allowEmpty ? '' : 'nonempty '}regular non-symlink file`);
  const canonical = await realpath(filename);
  if (canonical !== filename) fail(`${label} must be canonical and not resolve through a symlink`);
  return metadata;
}

async function sha256File(filename) {
  const bytes = await readFile(filename);
  return createHash('sha256').update(bytes).digest('hex');
}

async function fileEvidence(filename, label, options) {
  const metadata = await regularFile(filename, label, options);
  return Object.freeze({ path: filename, bytes: metadata.size, sha256: await sha256File(filename) });
}

function requireObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}

async function readJson(filename, label) {
  await regularFile(filename, label);
  try { return JSON.parse(await readFile(filename, 'utf8')); } catch (error) { fail(`${label} is not valid JSON: ${error.message}`); }
}

function relativeInside(root, relative, label) {
  if (typeof relative !== 'string' || relative.length === 0 || path.isAbsolute(relative)) fail(`${label} must be a nonempty relative path`);
  const resolved = path.resolve(root, relative);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) fail(`${label} escapes verifier root`);
  return resolved;
}

async function canonicalDirectory(directory, label) {
  if (!path.isAbsolute(directory)) fail(`${label} must be an absolute path`);
  let metadata;
  try { metadata = await stat(directory); } catch (error) { fail(`${label} is unavailable: ${error.message}`); }
  if (!metadata.isDirectory()) fail(`${label} must be a directory`);
  const canonical = await realpath(directory);
  if (canonical !== directory) fail(`${label} must be canonical and not resolve through a symlink`);
  return canonical;
}

async function verifyArtifactManifest(root, artifactsPath) {
  const manifest = requireObject(await readJson(artifactsPath, 'artifacts manifest'), 'artifacts manifest');
  if (manifest.schema !== ARTIFACTS_SCHEMA || !Array.isArray(manifest.files) || manifest.files.length === 0) {
    fail(`artifacts manifest must use ${ARTIFACTS_SCHEMA} and list files`);
  }
  const files = new Map();
  for (const item of manifest.files) {
    requireObject(item, 'artifact entry');
    if (Object.keys(item).sort().join('\0') !== 'bytes\0path\0sha256' || !SHA256.test(item.sha256) || !Number.isSafeInteger(item.bytes) || item.bytes <= 0) {
      fail('artifact entry must contain path, positive bytes, and lowercase SHA-256');
    }
    const filename = relativeInside(root, item.path, 'artifact path');
    if (files.has(item.path)) fail(`artifact path is duplicated: ${item.path}`);
    const observed = await fileEvidence(filename, `artifact ${item.path}`);
    if (observed.bytes !== item.bytes || observed.sha256 !== item.sha256) fail(`artifact hash drift: ${item.path}`);
    files.set(item.path, observed);
  }
  return Object.freeze({ manifest, files });
}

function validateSetup(setup, root, artifactFiles) {
  requireObject(setup, 'setup');
  if (setup.schema !== SETUP_SCHEMA) fail(`setup.schema must be ${SETUP_SCHEMA}`);
  for (const field of ['executable', 'entrypoint', 'qualificationClass']) if (typeof setup[field] !== 'string' || setup[field].length === 0) fail(`setup.${field} must be a nonempty string`);
  if (setup.qualificationClass !== 'real-vendored-pf7' && setup.qualificationClass !== 'test-fixture') fail('setup.qualificationClass must be real-vendored-pf7 or test-fixture');
  const executable = relativeInside(root, setup.executable, 'setup.executable');
  const entrypoint = relativeInside(root, setup.entrypoint, 'setup.entrypoint');
  for (const field of [setup.executable, setup.entrypoint]) if (!artifactFiles.has(field)) fail(`artifacts manifest must pin ${field}`);
  requireObject(setup.environment, 'setup.environment');
  const environment = {};
  for (const [key, value] of Object.entries(setup.environment)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(key) || typeof value !== 'string') fail('setup.environment must map uppercase names to strings');
    if (own(DYNAMIC_ENVIRONMENT, key) || Object.values(DYNAMIC_ENVIRONMENT).includes(key) || ['C7_TMP', 'C7_GEN', 'TMPDIR'].includes(key)) fail(`setup.environment must not set runner-controlled ${key}`);
    environment[key] = value;
  }
  if (typeof environment.PATH !== 'string' || environment.PATH.length === 0) fail('setup.environment.PATH is required for an exact environment');
  if (environment.C7_STRUCTURAL_ROLE_COUNT !== '3' || environment.C7_SHIELD_ACTION_PACKET_ABI !== 'sda2-v2-direct' || environment.C7_UNLOCK_LENGTH_STABILIZE !== '1' || environment.C7_MAXTRY !== '0') {
    fail('setup must pin structuralRoleCount=3, sda2-v2-direct ABI, fixed-width unlock stabilization, and C7_MAXTRY=0');
  }
  if (setup.qualificationClass === 'real-vendored-pf7' && (setup.entrypoint !== REAL_ENTRYPOINT || setup.executable !== REAL_EXECUTABLE)) {
    fail('real-vendored-pf7 setup must invoke the frozen BN254 PairFold-7 entrypoint via its pinned tsx executable');
  }
  return Object.freeze({ executable, entrypoint, environment: Object.freeze(environment), qualificationClass: setup.qualificationClass });
}

async function validateAction(actionName, action) {
  requireObject(action, `actions.${actionName}`);
  if (action.witnessValid !== true || action.proofVerified !== true) fail(`${actionName} is not a verified real proof action`);
  if (!SHA256.test(action.packetDigest)) fail(`${actionName}.packetDigest must be SHA-256`);
  const files = requireObject(action.files, `actions.${actionName}.files`);
  const checked = {};
  for (const field of ['v2DirectGroth16Adapter', 'packet']) {
    const declared = requireObject(files[field], `actions.${actionName}.files.${field}`);
    if (!path.isAbsolute(declared.path) || !SHA256.test(declared.sha256) || !Number.isSafeInteger(declared.bytes) || declared.bytes <= 0) fail(`${actionName}.${field} evidence is malformed`);
    const observed = await fileEvidence(declared.path, `${actionName} ${field}`);
    if (observed.bytes !== declared.bytes || observed.sha256 !== declared.sha256) fail(`${actionName} ${field} hash drift`);
    checked[field] = observed;
  }
  if (checked.packet.bytes !== 552 || checked.packet.sha256 !== action.packetDigest) fail(`${actionName} packet must be exactly the declared 552-byte packet`);
  return Object.freeze(checked);
}

function runChild(executable, args, environment, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd, env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (exitCode, signal) => resolve({ exitCode, signal, stdout, stderr }));
  });
}

function inspectBuildResult(action, result) {
  requireObject(result, `${action} build result`);
  if (result.built !== true || result.gateOk !== true || result.verifierInputCount !== 7 || result.structuralRoleCount !== 3 || result.structuralRolesUnevaluated !== true) {
    fail(`${action} build did not pass the seven-role BCH-2026 verifier gate with unevaluated structural roles`);
  }
  if (!Number.isSafeInteger(result.wire) || result.wire <= 0 || !Number.isSafeInteger(result.score) || result.score <= 0) fail(`${action} build has invalid wire/scored size`);
  if (!Array.isArray(result.manual) || result.manual.length < 10) fail(`${action} build did not report all ten input roles`);
  const verifierRoles = result.manual.slice(0, 7).map((role, index) => {
    if (role?.accepts !== true || !Number.isSafeInteger(role.unlockLen) || role.unlockLen <= 0 || !Number.isFinite(role.operationCost) || role.operationCost < 0) fail(`${action} verifier role ${index} did not BCH-2026 VM-accept with measurements`);
    return Object.freeze({ index, name: typeof role.name === 'string' ? role.name : `verifier-${index}`, vmAccepted: true, unlockBytes: role.unlockLen, operationCost: role.operationCost });
  });
  const structural = result.manual.slice(7, 10).map((role, index) => Object.freeze({ index: index + 7, name: typeof role?.name === 'string' ? role.name : ['packet', 'state', 'fee'][index], status: 'unevaluated' }));
  return Object.freeze({ wireBytes: result.wire, scoredBytes: result.score, verifierRoles, structuralRoles: structural });
}

async function ensureEmptyOutput(directory) {
  if (!path.isAbsolute(directory)) fail('output directory must be an explicit absolute path');
  await mkdir(directory, { recursive: true });
  if ((await readdir(directory)).length !== 0) fail('output directory must be empty');
}

async function writeCanonical(filename, value) {
  await writeFile(filename, canonicalJson(value), { encoding: 'utf8', flag: 'wx' });
}

export async function runV2Pf7VerifierQualification(configuration) {
  const verifierRoot = await canonicalDirectory(configuration.verifierRoot, 'verifier root');
  const outputDirectory = path.resolve(configuration.outputDirectory);
  await ensureEmptyOutput(outputDirectory);
  const artifacts = await verifyArtifactManifest(verifierRoot, configuration.artifacts);
  const setupDocument = await readJson(configuration.setup, 'setup');
  const setup = validateSetup(setupDocument, verifierRoot, artifacts.files);
  await regularFile(setup.executable, 'pinned build executable');
  await regularFile(setup.entrypoint, 'pinned build entrypoint');
  const evidence = requireObject(await readJson(configuration.qualificationEvidence, 'qualification evidence'), 'qualification evidence');
  if (evidence.schema !== EVIDENCE_SCHEMA) fail(`qualification evidence schema must be ${EVIDENCE_SCHEMA}`);
  const actionNames = Object.keys(evidence.actions ?? {}).sort();
  if (actionNames.join('\0') !== [...ACTIONS].sort().join('\0')) fail('qualification evidence must contain exactly deposit, transfer, and withdrawal');
  const actions = {};
  for (const actionName of ACTIONS) {
    const actionFiles = await validateAction(actionName, evidence.actions[actionName]);
    const actionDirectory = path.join(outputDirectory, actionName);
    const buildDirectory = path.join(actionDirectory, 'build');
    const generatedDirectory = path.join(actionDirectory, 'generated');
    const temporaryDirectory = path.join(actionDirectory, 'tmp');
    await Promise.all([mkdir(buildDirectory, { recursive: true }), mkdir(generatedDirectory, { recursive: true }), mkdir(temporaryDirectory, { recursive: true })]);
    const environment = Object.freeze({
      ...setup.environment,
      C7_TMP: buildDirectory,
      C7_GEN: generatedDirectory,
      TMPDIR: temporaryDirectory,
      [DYNAMIC_ENVIRONMENT.adapterPath]: actionFiles.v2DirectGroth16Adapter.path,
      [DYNAMIC_ENVIRONMENT.adapterSha256]: actionFiles.v2DirectGroth16Adapter.sha256,
      [DYNAMIC_ENVIRONMENT.packetPath]: actionFiles.packet.path,
      [DYNAMIC_ENVIRONMENT.packetSha256]: actionFiles.packet.sha256,
    });
    const started = process.hrtime.bigint();
    const child = await runChild(setup.executable, [setup.entrypoint], environment, verifierRoot);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1_000_000;
    await writeFile(path.join(actionDirectory, 'stdout.log'), child.stdout, { encoding: 'utf8', flag: 'wx' });
    await writeFile(path.join(actionDirectory, 'stderr.log'), child.stderr, { encoding: 'utf8', flag: 'wx' });
    if (child.exitCode !== 0 || child.signal !== null) fail(`${actionName} frozen PF7 build failed (exit=${child.exitCode}, signal=${child.signal ?? 'none'})`);
    const resultPath = path.join(buildDirectory, 'result.json');
    const result = await readJson(resultPath, `${actionName} build result`);
    const measurements = inspectBuildResult(actionName, result);
    const resultCopy = path.join(actionDirectory, 'build-result.json');
    await copyFile(resultPath, resultCopy, 0);
    actions[actionName] = Object.freeze({
      v2DirectGroth16Adapter: actionFiles.v2DirectGroth16Adapter,
      packet: actionFiles.packet,
      command: Object.freeze({ executable: setup.executable, arguments: Object.freeze([setup.entrypoint]), environment }),
      elapsedMs,
      result: await fileEvidence(resultCopy, `${actionName} copied build result`),
      stdout: await fileEvidence(path.join(actionDirectory, 'stdout.log'), `${actionName} stdout`),
      stderr: await fileEvidence(path.join(actionDirectory, 'stderr.log'), `${actionName} stderr`, { allowEmpty: true }),
      ...measurements,
    });
  }
  const fixedWidths = ACTIONS[0] ? actions[ACTIONS[0]].verifierRoles.map((role) => role.unlockBytes) : [];
  for (const actionName of ACTIONS.slice(1)) {
    const observed = actions[actionName].verifierRoles.map((role) => role.unlockBytes);
    if (observed.join(',') !== fixedWidths.join(',')) fail(`fixed-width violation: ${actionName} verifier unlock lengths differ from ${ACTIONS[0]}`);
  }
  const realQualification = setup.qualificationClass === 'real-vendored-pf7';
  const manifest = Object.freeze({
    schema: 'shieldkit-v2-pf7-verifier-qualification-v1',
    qualificationStatus: realQualification ? 'qualified-seven-verifier-roles-only' : 'not-qualification-test-fixture',
    claims: Object.freeze({ bch2026SevenVerifierRoles: realQualification, packetStateFeeAccepted: false, production: false }),
    inputs: Object.freeze({
      verifierRoot,
      qualificationEvidence: await fileEvidence(configuration.qualificationEvidence, 'qualification evidence'),
      setup: await fileEvidence(configuration.setup, 'setup'),
      artifacts: await fileEvidence(configuration.artifacts, 'artifacts manifest'),
      pinnedVerifierArtifacts: Object.freeze([...artifacts.files.entries()].map(([relativePath, value]) => Object.freeze({ relativePath, ...value }))),
    }),
    frozenBuild: Object.freeze({ qualificationClass: setup.qualificationClass, executable: setup.executable, entrypoint: setup.entrypoint, environment: setup.environment, dynamicEnvironment: DYNAMIC_ENVIRONMENT, noRunnerRetries: true, fixedVerifierUnlockBytes: Object.freeze(fixedWidths) }),
    actions: Object.freeze(actions),
  });
  const manifestPath = path.join(outputDirectory, 'qualification.json');
  await writeCanonical(manifestPath, manifest);
  return Object.freeze({ manifestPath, manifest });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const result = await runV2Pf7VerifierQualification(parseV2Pf7QualificationArguments(process.argv.slice(2)));
    process.stdout.write(canonicalJson(result));
  } catch (error) {
    process.stderr.write(`V2 PF7 verifier qualification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
