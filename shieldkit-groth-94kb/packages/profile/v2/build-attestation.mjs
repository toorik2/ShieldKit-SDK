/**
 * Canonical, development-only circuit-build and Groth16 setup attestations.
 *
 * This module validates evidence and signatures only. Command execution and
 * filesystem identity checks remain in the compiler/setup callers.
 */
import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';

import {
  NPM_BUILD_CLOSURE_SCHEMA,
  verifyNpmBuildClosure,
} from './npm-closure.mjs';
import {
  canonicalizeJcs,
} from './profile-core.mjs';
import {
  parseV2RelationSourceManifest,
  verifyV2RelationSourceManifest,
} from './relation-source-manifest.mjs';

export const CIRCUIT_BUILD_ATTESTATION_SCHEMA =
  'shieldkit-v2-direct-circuit-build-attestation-v1';
export const DEVELOPMENT_SETUP_ATTESTATION_SCHEMA =
  'shieldkit-v2-direct-development-setup-attestation-v1';
export const DEVELOPMENT_ATTESTATION_SIGNER_DOMAIN =
  'shieldkit-v2-direct-development-attestation-v1';
export const DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN =
  'shield.cash/local-development-phase2-entropy/v1\0';
export const PINNED_CIRCOM2_PACKAGE_VERSION = '0.2.23';
export const PINNED_CIRCOM_COMPILER_VERSION = '2.2.3';
export const PINNED_SNARKJS_VERSION = '0.7.6';
export const V2_BUILD_SOURCE_MANIFEST_PATH =
  'relation-source-manifest.json';
export const V2_BUILD_R1CS_PATH = 'main-chipnet.r1cs';
export const V2_BUILD_SYM_PATH = 'main-chipnet.sym';
export const V2_BUILD_WASM_PATH =
  'main-chipnet_js/main-chipnet.wasm';

const HASH = /^[0-9a-f]{64}$/;
const IDENTIFIER = /^[a-z][a-z0-9-]*$/;
const PACKAGE_NAME =
  /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;
const PORTABLE_PATH_COMPONENT = /^[A-Za-z0-9._@+-]+$/;
const BANNED_KEYS = new Set([
  'clock',
  'hostname',
  'operatingsystem',
  'os',
  'pid',
  'platform',
  'processid',
  'profileid',
  'time',
  'timestamp',
]);
const CIRCOM_LOGICAL_ARGV = Object.freeze([
  'node_modules/circom2/cli.js',
  'shieldkit-groth/circuits/v2-direct/main-chipnet.circom',
  '--r1cs',
  '--wasm',
  '--sym',
  '--O1',
  '--sanity_check',
  '2',
  '--output',
  '$BUILD_OUTPUT',
]);
const SNARKJS_LOGICAL_COMMANDS = Object.freeze({
  powersOfTauVerify: Object.freeze([
    'node_modules/snarkjs/build/cli.cjs',
    'powersoftau',
    'verify',
    '$PTAU',
  ]),
  setup: Object.freeze([
    'node_modules/snarkjs/build/cli.cjs',
    'groth16',
    'setup',
    '$R1CS',
    '$PTAU',
    '$INITIAL_ZKEY',
  ]),
  contribute: Object.freeze([
    'node_modules/snarkjs/build/cli.cjs',
    'zkey',
    'contribute',
    '$INPUT_ZKEY',
    '$OUTPUT_ZKEY',
  ]),
  verifyFinalZkey: Object.freeze([
    'node_modules/snarkjs/build/cli.cjs',
    'zkey',
    'verify',
    '$R1CS',
    '$PTAU',
    '$FINAL_ZKEY',
  ]),
  exportVerificationKey: Object.freeze([
    'node_modules/snarkjs/build/cli.cjs',
    'zkey',
    'export',
    'verificationkey',
    '$FINAL_ZKEY',
    '$VERIFICATION_KEY',
  ]),
});

export class BuildAttestationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BuildAttestationError';
  }
}

const fail = (message) => {
  throw new BuildAttestationError(message);
};
const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');
const canonicalBytes = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');
const canonicalHash = (value) => sha256(canonicalBytes(value));

function exactKeys(value, label, keys) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail(`${label} must be lowercase SHA-256 hex`);
  }
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${label} must be a positive safe integer`);
  }
  return value;
}

function nonnegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${label} must be a nonnegative safe integer`);
  }
  return value;
}

function portablePath(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.startsWith('/')
    || /^[A-Za-z]:[\\/]/.test(value)
    || value.includes('\\')
  ) {
    fail(`${label} must be a portable repository-relative path`);
  }
  const components = value.split('/');
  if (
    components.some(
      (component) =>
        component === ''
        || component === '.'
        || component === '..'
        || !PORTABLE_PATH_COMPONENT.test(component),
    )
  ) {
    fail(`${label} must be a portable repository-relative path`);
  }
  return value;
}

function assertJsonTree(value, label = 'attestation', ancestors = new Set()) {
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    // Opaque, separately validated encodings may legitimately begin with `/`
    // (standard Base64 has a 1-in-64 chance). Do not misclassify those bytes
    // as host paths; their canonical decoding and cryptographic validation run
    // later in the exact signer schema.
    const opaqueSignerEncoding = label.endsWith('.signatureBase64')
      || label.endsWith('.publicKeyPem');
    if (!opaqueSignerEncoding && (
      value.startsWith('/')
      || /^[A-Za-z]:[\\/]/.test(value)
      || value.includes('\\')
    )) {
      fail(`${label} contains an absolute or platform-specific path`);
    }
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      fail(`${label} contains a non-finite number`);
    }
    return;
  }
  if (typeof value !== 'object') {
    fail(`${label} must contain JSON data only`);
  }
  if (ancestors.has(value)) fail(`${label} must not contain cycles`);
  ancestors.add(value);
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      fail(`${label} must be a JSON array`);
    }
    const names = Object.getOwnPropertyNames(value);
    if (
      names.length !== value.length + 1
      || !names.includes('length')
    ) {
      fail(`${label} array must be dense without extra properties`);
    }
    value.forEach((entry, index) =>
      assertJsonTree(entry, `${label}[${index}]`, ancestors));
  } else {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      fail(`${label} must be a plain JSON object`);
    }
    for (const key of Object.keys(value)) {
      if (BANNED_KEYS.has(key.toLowerCase())) {
        fail(`${label}.${key} is not portable attestation evidence`);
      }
      assertJsonTree(value[key], `${label}.${key}`, ancestors);
    }
  }
  ancestors.delete(value);
}

function parseCanonical(bytes, label) {
  if (!(bytes instanceof Uint8Array)) {
    fail(`${label} must be UTF-8 bytes`);
  }
  let value;
  try {
    value = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    fail(`${label} is not JSON`);
  }
  assertJsonTree(value, label);
  if (!Buffer.from(bytes).equals(canonicalBytes(value))) {
    fail(`${label} must use exact RFC8785/JCS bytes`);
  }
  return value;
}

function artifact(value, label, { allowEmpty = false } = {}) {
  exactKeys(value, label, ['bytes', 'path', 'sha256']);
  return Object.freeze({
    bytes: allowEmpty
      ? nonnegativeInteger(value.bytes, `${label}.bytes`)
      : positiveInteger(value.bytes, `${label}.bytes`),
    path: portablePath(value.path, `${label}.path`),
    sha256: hash(value.sha256, `${label}.sha256`),
  });
}

function buildClaims(value) {
  exactKeys(value, 'circuit build claims', [
    'developmentOnly',
    'production',
    'release',
  ]);
  if (
    value.developmentOnly !== true
    || value.production !== false
    || value.release !== false
  ) {
    fail('circuit build claims must remain development-only');
  }
  return Object.freeze({ ...value });
}

function setupClaims(value) {
  exactKeys(value, 'development setup claims', [
    'contributionIndependence',
    'developmentOnly',
    'externalTranscript',
    'finalCeremony',
    'production',
    'release',
  ]);
  if (
    value.developmentOnly !== true
    || value.finalCeremony !== false
    || value.externalTranscript !== false
    || value.contributionIndependence !== 'not-established'
    || value.production !== false
    || value.release !== false
  ) {
    fail(
      'development setup claims must remain local, non-independent, and non-release',
    );
  }
  return Object.freeze({ ...value });
}

function packagePathName(value) {
  const parts = value.split('/');
  const index = parts.lastIndexOf('node_modules');
  if (index < 0 || index + 1 >= parts.length) {
    fail('npm closure packagePath is invalid');
  }
  const name = parts[index + 1].startsWith('@')
    ? `${parts[index + 1]}/${parts[index + 2] ?? ''}`
    : parts[index + 1];
  if (!PACKAGE_NAME.test(name)) fail('npm closure packagePath is invalid');
  return name;
}

function npmClosure(value, label) {
  exactKeys(value, label, [
    'installedClosureSha256',
    'lockClosureSha256',
    'lockfile',
    'packages',
    'roots',
    'schema',
  ]);
  if (value.schema !== NPM_BUILD_CLOSURE_SCHEMA) {
    fail(`${label}.schema is unsupported`);
  }
  exactKeys(value.lockfile, `${label}.lockfile`, [
    'bytes',
    'lockfileVersion',
    'path',
    'sha256',
  ]);
  if (value.lockfile.lockfileVersion !== 3) {
    fail(`${label}.lockfile must use lockfileVersion 3`);
  }
  const lockfile = Object.freeze({
    bytes: positiveInteger(value.lockfile.bytes, `${label}.lockfile.bytes`),
    lockfileVersion: 3,
    path: portablePath(value.lockfile.path, `${label}.lockfile.path`),
    sha256: hash(value.lockfile.sha256, `${label}.lockfile.sha256`),
  });
  if (!Array.isArray(value.roots) || value.roots.length === 0) {
    fail(`${label}.roots must be a nonempty array`);
  }
  let previousRoot = '';
  const roots = Object.freeze(value.roots.map((root, index) => {
    const normalized = portablePath(root, `${label}.roots[${index}]`);
    packagePathName(normalized);
    if (normalized <= previousRoot) {
      fail(`${label}.roots must be sorted and unique`);
    }
    previousRoot = normalized;
    return normalized;
  }));
  if (!Array.isArray(value.packages) || value.packages.length === 0) {
    fail(`${label}.packages must be a nonempty array`);
  }
  let previousPackage = '';
  const packages = Object.freeze(value.packages.map((entry, index) => {
    const entryLabel = `${label}.packages[${index}]`;
    exactKeys(entry, entryLabel, [
      'installed',
      'lock',
      'name',
      'packagePath',
    ]);
    const packagePath = portablePath(
      entry.packagePath,
      `${entryLabel}.packagePath`,
    );
    if (
      packagePath <= previousPackage
      || entry.name !== packagePathName(packagePath)
    ) {
      fail(`${label}.packages must be path-sorted with exact package names`);
    }
    previousPackage = packagePath;
    exactKeys(entry.lock, `${entryLabel}.lock`, [
      'integrity',
      'resolved',
      'sha256',
      'version',
    ]);
    if (
      typeof entry.lock.integrity !== 'string'
      || !entry.lock.integrity.startsWith('sha512-')
      || typeof entry.lock.resolved !== 'string'
      || !entry.lock.resolved.startsWith('https://registry.npmjs.org/')
      || typeof entry.lock.version !== 'string'
      || entry.lock.version.length === 0
    ) {
      fail(`${entryLabel}.lock is not an immutable npm lock identity`);
    }
    const lock = Object.freeze({
      integrity: entry.lock.integrity,
      resolved: entry.lock.resolved,
      version: entry.lock.version,
    });
    if (
      hash(entry.lock.sha256, `${entryLabel}.lock.sha256`)
      !== canonicalHash(lock)
    ) {
      fail(`${entryLabel}.lock.sha256 is not canonical`);
    }
    exactKeys(entry.installed, `${entryLabel}.installed`, [
      'files',
      'sha256',
    ]);
    if (
      !Array.isArray(entry.installed.files)
      || entry.installed.files.length === 0
    ) {
      fail(`${entryLabel}.installed.files must be nonempty`);
    }
    let previousFile = '';
    const files = Object.freeze(entry.installed.files.map((file, fileIndex) => {
      const parsed = artifact(
        file,
        `${entryLabel}.installed.files[${fileIndex}]`,
        { allowEmpty: true },
      );
      if (parsed.path <= previousFile) {
        fail(`${entryLabel}.installed.files must be path-sorted and unique`);
      }
      previousFile = parsed.path;
      return parsed;
    }));
    if (
      hash(entry.installed.sha256, `${entryLabel}.installed.sha256`)
      !== canonicalHash(files)
    ) {
      fail(`${entryLabel}.installed.sha256 is not canonical`);
    }
    return Object.freeze({
      installed: Object.freeze({
        files,
        sha256: entry.installed.sha256,
      }),
      lock: Object.freeze({
        ...lock,
        sha256: entry.lock.sha256,
      }),
      name: entry.name,
      packagePath,
    });
  }));
  for (const root of roots) {
    if (!packages.some((entry) => entry.packagePath === root)) {
      fail(`${label} omits root package ${root}`);
    }
  }
  const lockClosure = packages.map((entry) => Object.freeze({
    lock: entry.lock,
    name: entry.name,
    packagePath: entry.packagePath,
  }));
  const installedClosure = packages.map((entry) => Object.freeze({
    installed: entry.installed,
    name: entry.name,
    packagePath: entry.packagePath,
  }));
  if (
    hash(value.lockClosureSha256, `${label}.lockClosureSha256`)
      !== canonicalHash(lockClosure)
    || hash(
      value.installedClosureSha256,
      `${label}.installedClosureSha256`,
    ) !== canonicalHash(installedClosure)
  ) {
    fail(`${label} aggregate closure hashes are not canonical`);
  }
  return Object.freeze({
    installedClosureSha256: value.installedClosureSha256,
    lockClosureSha256: value.lockClosureSha256,
    lockfile,
    packages,
    roots,
    schema: value.schema,
  });
}

function nodeRuntime(value, label) {
  exactKeys(value, label, ['modulesAbi', 'version']);
  if (
    typeof value.version !== 'string'
    || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(value.version)
    || typeof value.modulesAbi !== 'string'
    || !/^[0-9]+$/.test(value.modulesAbi)
  ) {
    fail(`${label} is invalid`);
  }
  return Object.freeze({ ...value });
}

function exactArgv(value, expected, label) {
  if (
    !Array.isArray(value)
    || value.length !== expected.length
    || value.some((entry, index) => entry !== expected[index])
  ) {
    fail(`${label} is not the exact normalized logical command`);
  }
  return Object.freeze([...value]);
}

function signingBytes(value, schema) {
  const unsigned = { ...value };
  delete unsigned.signer;
  return canonicalBytes({
    domain: DEVELOPMENT_ATTESTATION_SIGNER_DOMAIN,
    schema,
    unsignedAttestationJcs: canonicalizeJcs(unsigned),
  });
}

function signer(value, schema, trustedDevelopmentSigners, attestation) {
  if (value === undefined) return undefined;
  exactKeys(value, 'attestation signer', [
    'algorithm',
    'domain',
    'evidence',
    'keyId',
    'publicKeyPem',
    'signatureBase64',
  ]);
  if (
    value.algorithm !== 'ed25519'
    || value.domain !== DEVELOPMENT_ATTESTATION_SIGNER_DOMAIN
    || value.evidence !== 'development-only'
    || typeof value.keyId !== 'string'
    || !IDENTIFIER.test(value.keyId)
    || typeof value.publicKeyPem !== 'string'
    || typeof value.signatureBase64 !== 'string'
  ) {
    fail('attestation signer is not development-only Ed25519 evidence');
  }
  let publicKey;
  try {
    publicKey = createPublicKey(value.publicKeyPem);
  } catch {
    fail('attestation signer public key is invalid');
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    fail('attestation signer public key must be Ed25519');
  }
  if (trustedDevelopmentSigners !== undefined) {
    if (!Array.isArray(trustedDevelopmentSigners)) {
      fail('trustedDevelopmentSigners must be an array');
    }
    const trusted = trustedDevelopmentSigners.find(
      (entry) => entry?.keyId === value.keyId,
    );
    if (
      trusted === undefined
      || trusted.publicKeyPem !== value.publicKeyPem
    ) {
      fail('attestation signer is not the trusted development key');
    }
  }
  const signature = Buffer.from(value.signatureBase64, 'base64');
  if (
    signature.length !== 64
    || signature.toString('base64') !== value.signatureBase64
    || !verifySignature(
      null,
      signingBytes(attestation, schema),
      publicKey,
      signature,
    )
  ) {
    fail('attestation signer signature or domain is invalid');
  }
  return Object.freeze({ ...value });
}

function validateBuild(value, options) {
  exactKeys(value, 'circuit build attestation', [
    'artifacts',
    'claims',
    'compilation',
    'npmClosure',
    'r1csAbi',
    'schema',
    'sourceManifest',
    ...(value.signer === undefined ? [] : ['signer']),
  ]);
  if (value.schema !== CIRCUIT_BUILD_ATTESTATION_SCHEMA) {
    fail('circuit build attestation schema is unsupported');
  }
  const claims = buildClaims(value.claims);
  exactKeys(value.compilation, 'circuit build compilation', [
    'argv',
    'circomCompilerVersion',
    'circomPackageVersion',
    'cli',
    'executable',
    'node',
    'optimization',
    'packageMetadata',
    'sanityCheck',
  ]);
  if (
    value.compilation.executable !== 'process.execPath'
    || value.compilation.circomPackageVersion
      !== PINNED_CIRCOM2_PACKAGE_VERSION
    || value.compilation.circomCompilerVersion
      !== PINNED_CIRCOM_COMPILER_VERSION
    || value.compilation.optimization !== 'O1'
    || value.compilation.sanityCheck !== 2
  ) {
    fail('circuit build compiler identity or options are invalid');
  }
  const compilation = Object.freeze({
    executable: value.compilation.executable,
    node: nodeRuntime(value.compilation.node, 'circuit build Node runtime'),
    cli: artifact(value.compilation.cli, 'circuit build Circom CLI'),
    packageMetadata: artifact(
      value.compilation.packageMetadata,
      'circuit build Circom package metadata',
    ),
    circomPackageVersion: value.compilation.circomPackageVersion,
    circomCompilerVersion: value.compilation.circomCompilerVersion,
    optimization: value.compilation.optimization,
    sanityCheck: value.compilation.sanityCheck,
    argv: exactArgv(
      value.compilation.argv,
      CIRCOM_LOGICAL_ARGV,
      'circuit build compilation.argv',
    ),
  });
  const closure = npmClosure(value.npmClosure, 'circuit build npmClosure');
  if (
    closure.roots.length !== 1
    || closure.roots[0] !== 'node_modules/circom2'
  ) {
    fail('circuit build npmClosure must be rooted exactly at circom2');
  }
  const cliPackage = closure.packages.find(
    (entry) => entry.packagePath === 'node_modules/circom2',
  );
  const cliFile = cliPackage.installed.files.find(
    (entry) => entry.path === 'cli.js',
  );
  const packageFile = cliPackage.installed.files.find(
    (entry) => entry.path === 'package.json',
  );
  if (
    cliPackage.lock.version !== PINNED_CIRCOM2_PACKAGE_VERSION
    || cliFile?.sha256 !== compilation.cli.sha256
    || cliFile?.bytes !== compilation.cli.bytes
    || compilation.cli.path !== 'node_modules/circom2/cli.js'
    || packageFile?.sha256 !== compilation.packageMetadata.sha256
    || packageFile?.bytes !== compilation.packageMetadata.bytes
    || compilation.packageMetadata.path
      !== 'node_modules/circom2/package.json'
  ) {
    fail('circuit build compiler files differ from the npm closure');
  }
  const sourceManifest = artifact(
    value.sourceManifest,
    'circuit build sourceManifest',
  );
  exactKeys(value.artifacts, 'circuit build artifacts', [
    'r1cs',
    'sym',
    'wasm',
  ]);
  const artifacts = Object.freeze({
    r1cs: artifact(value.artifacts.r1cs, 'circuit build artifacts.r1cs'),
    sym: artifact(value.artifacts.sym, 'circuit build artifacts.sym'),
    wasm: artifact(value.artifacts.wasm, 'circuit build artifacts.wasm'),
  });
  if (
    sourceManifest.path !== V2_BUILD_SOURCE_MANIFEST_PATH
    || artifacts.r1cs.path !== V2_BUILD_R1CS_PATH
    || artifacts.sym.path !== V2_BUILD_SYM_PATH
    || artifacts.wasm.path !== V2_BUILD_WASM_PATH
  ) {
    fail('circuit build artifact paths are not the exact V2 build layout');
  }
  exactKeys(value.r1csAbi, 'circuit build R1CS ABI', [
    'constraints',
    'field',
    'privateInputs',
    'publicInputs',
    'publicOutputs',
    'wires',
  ]);
  if (
    value.r1csAbi.field !== 'bn254'
    || value.r1csAbi.publicInputs !== 2
    || value.r1csAbi.publicOutputs !== 0
  ) {
    fail('circuit build R1CS ABI must be BN254 with two inputs and no outputs');
  }
  const r1csAbi = Object.freeze({
    field: value.r1csAbi.field,
    publicInputs: positiveInteger(
      value.r1csAbi.publicInputs,
      'circuit build R1CS ABI.publicInputs',
    ),
    publicOutputs: nonnegativeInteger(
      value.r1csAbi.publicOutputs,
      'circuit build R1CS ABI.publicOutputs',
    ),
    privateInputs: positiveInteger(
      value.r1csAbi.privateInputs,
      'circuit build R1CS ABI.privateInputs',
    ),
    constraints: positiveInteger(
      value.r1csAbi.constraints,
      'circuit build R1CS ABI.constraints',
    ),
    wires: positiveInteger(
      value.r1csAbi.wires,
      'circuit build R1CS ABI.wires',
    ),
  });
  const parsed = {
    schema: value.schema,
    claims,
    compilation,
    npmClosure: closure,
    sourceManifest,
    artifacts,
    r1csAbi,
  };
  const parsedSigner = signer(
    value.signer,
    value.schema,
    options.trustedDevelopmentSigners,
    value,
  );
  return Object.freeze(
    parsedSigner === undefined
      ? parsed
      : { ...parsed, signer: parsedSigner },
  );
}

function commandSet(value) {
  exactKeys(value, 'development setup commands', Object.keys(
    SNARKJS_LOGICAL_COMMANDS,
  ));
  return Object.freeze(Object.fromEntries(
    Object.entries(SNARKJS_LOGICAL_COMMANDS).map(([name, expected]) => [
      name,
      exactArgv(
        value[name],
        expected,
        `development setup commands.${name}`,
      ),
    ]),
  ));
}

function validateSetup(value, options) {
  exactKeys(value, 'development setup attestation', [
    'buildAttestation',
    'claims',
    'commands',
    'finalEvidence',
    'ptau',
    'r1cs',
    'schema',
    'snarkjs',
    'zkeyChain',
    ...(value.signer === undefined ? [] : ['signer']),
  ]);
  if (value.schema !== DEVELOPMENT_SETUP_ATTESTATION_SCHEMA) {
    fail('development setup attestation schema is unsupported');
  }
  const claims = setupClaims(value.claims);
  const buildAttestation = artifact(
    value.buildAttestation,
    'development setup buildAttestation',
  );
  const r1cs = artifact(value.r1cs, 'development setup r1cs');
  exactKeys(value.ptau, 'development setup PTau', [
    'artifact',
    'ceremonyPower',
    'power',
    'source',
    'verified',
  ]);
  if (
    typeof value.ptau.source !== 'string'
    || value.ptau.source.length === 0
    || value.ptau.verified !== true
  ) {
    fail('development setup PTau must have full verification evidence');
  }
  const ptau = Object.freeze({
    source: value.ptau.source,
    artifact: artifact(
      value.ptau.artifact,
      'development setup PTau.artifact',
    ),
    power: positiveInteger(value.ptau.power, 'development setup PTau.power'),
    ceremonyPower: positiveInteger(
      value.ptau.ceremonyPower,
      'development setup PTau.ceremonyPower',
    ),
    verified: true,
  });
  exactKeys(value.snarkjs, 'development setup SnarkJS', [
    'cli',
    'node',
    'npmClosure',
    'packageMetadata',
    'version',
  ]);
  if (value.snarkjs.version !== PINNED_SNARKJS_VERSION) {
    fail('development setup SnarkJS version is invalid');
  }
  const snarkjsClosure = npmClosure(
    value.snarkjs.npmClosure,
    'development setup SnarkJS npmClosure',
  );
  if (
    snarkjsClosure.roots.length !== 1
    || snarkjsClosure.roots[0] !== 'node_modules/snarkjs'
  ) {
    fail('development setup SnarkJS closure must be rooted exactly at snarkjs');
  }
  const snarkjsPackage = snarkjsClosure.packages.find(
    (entry) => entry.packagePath === 'node_modules/snarkjs',
  );
  const cli = artifact(value.snarkjs.cli, 'development setup SnarkJS CLI');
  const packageMetadata = artifact(
    value.snarkjs.packageMetadata,
    'development setup SnarkJS package metadata',
  );
  const closureCli = snarkjsPackage.installed.files.find(
    (entry) => entry.path === 'build/cli.cjs',
  );
  const closurePackage = snarkjsPackage.installed.files.find(
    (entry) => entry.path === 'package.json',
  );
  if (
    snarkjsPackage.lock.version !== PINNED_SNARKJS_VERSION
    || cli.path !== 'node_modules/snarkjs/build/cli.cjs'
    || cli.sha256 !== closureCli?.sha256
    || cli.bytes !== closureCli?.bytes
    || packageMetadata.path !== 'node_modules/snarkjs/package.json'
    || packageMetadata.sha256 !== closurePackage?.sha256
    || packageMetadata.bytes !== closurePackage?.bytes
  ) {
    fail('development setup SnarkJS files differ from the npm closure');
  }
  const snarkjs = Object.freeze({
    version: value.snarkjs.version,
    node: nodeRuntime(
      value.snarkjs.node,
      'development setup SnarkJS Node runtime',
    ),
    cli,
    packageMetadata,
    npmClosure: snarkjsClosure,
  });
  const commands = commandSet(value.commands);
  exactKeys(value.zkeyChain, 'development setup zkeyChain', [
    'contributions',
    'initial',
  ]);
  const initial = artifact(
    value.zkeyChain.initial,
    'development setup initial zkey',
  );
  if (
    !Array.isArray(value.zkeyChain.contributions)
    || value.zkeyChain.contributions.length !== 1
  ) {
    fail('development setup executes exactly one local contribution');
  }
  let previous = initial.sha256;
  const contributions = Object.freeze(
    value.zkeyChain.contributions.map((entry, index) => {
      const label = `development setup contribution ${index}`;
      exactKeys(entry, label, [
        'entropyCommitment',
        'entropyCommitmentDomain',
        'inputZkeySha256',
        'output',
        'sequence',
      ]);
      if (
        entry.sequence !== index + 1
        || hash(entry.inputZkeySha256, `${label}.inputZkeySha256`)
          !== previous
      ) {
        fail('development setup zkey contribution chain is discontinuous');
      }
      const output = artifact(entry.output, `${label}.output`);
      if (output.sha256 === previous) {
        fail('development setup contribution must change the zkey');
      }
      if (
        entry.entropyCommitmentDomain
          !== DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN
      ) {
        fail('development setup entropy commitment domain is invalid');
      }
      previous = output.sha256;
      return Object.freeze({
        sequence: entry.sequence,
        inputZkeySha256: entry.inputZkeySha256,
        output,
        entropyCommitmentDomain: entry.entropyCommitmentDomain,
        entropyCommitment: hash(
          entry.entropyCommitment,
          `${label}.entropyCommitment`,
        ),
      });
    }),
  );
  exactKeys(value.finalEvidence, 'development setup final evidence', [
    'finalZkeySha256',
    'finalZkeyVerified',
    'verificationKey',
    'verificationKeyExported',
  ]);
  if (
    value.finalEvidence.finalZkeyVerified !== true
    || value.finalEvidence.verificationKeyExported !== true
    || hash(
      value.finalEvidence.finalZkeySha256,
      'development setup final evidence.finalZkeySha256',
    ) !== previous
  ) {
    fail('development setup final zkey verification evidence is invalid');
  }
  const finalEvidence = Object.freeze({
    finalZkeySha256: value.finalEvidence.finalZkeySha256,
    finalZkeyVerified: true,
    verificationKeyExported: true,
    verificationKey: artifact(
      value.finalEvidence.verificationKey,
      'development setup verification key',
    ),
  });
  const parsed = {
    schema: value.schema,
    claims,
    buildAttestation,
    r1cs,
    ptau,
    snarkjs,
    commands,
    zkeyChain: Object.freeze({ initial, contributions }),
    finalEvidence,
  };
  const parsedSigner = signer(
    value.signer,
    value.schema,
    options.trustedDevelopmentSigners,
    value,
  );
  return Object.freeze(
    parsedSigner === undefined
      ? parsed
      : { ...parsed, signer: parsedSigner },
  );
}

export function developmentAttestationSigningBytes(value) {
  assertJsonTree(value);
  if (
    value?.schema !== CIRCUIT_BUILD_ATTESTATION_SCHEMA
    && value?.schema !== DEVELOPMENT_SETUP_ATTESTATION_SCHEMA
  ) {
    fail('attestation schema is unsupported for signing');
  }
  return signingBytes(value, value.schema);
}

export function parseCircuitBuildAttestation(bytes, options = {}) {
  return validateBuild(
    parseCanonical(bytes, 'circuit build attestation'),
    options,
  );
}

export function parseDevelopmentSetupAttestation(bytes, options = {}) {
  return validateSetup(
    parseCanonical(bytes, 'development setup attestation'),
    options,
  );
}

export function canonicalCircuitBuildAttestation(value, options = {}) {
  const bytes = canonicalBytes(value);
  const parsed = parseCircuitBuildAttestation(bytes, options);
  return Object.freeze({
    value: parsed,
    bytes,
    sha256: sha256(bytes),
  });
}

export function canonicalDevelopmentSetupAttestation(value, options = {}) {
  const bytes = canonicalBytes(value);
  const parsed = parseDevelopmentSetupAttestation(bytes, options);
  return Object.freeze({
    value: parsed,
    bytes,
    sha256: sha256(bytes),
  });
}

function enforceTrustedSigner(parsed, options, label) {
  if (options.requireTrustedSigner !== true) return;
  if (
    !Array.isArray(options.trustedDevelopmentSigners)
    || options.trustedDevelopmentSigners.length === 0
    || parsed.signer === undefined
  ) {
    fail(`${label} requires a signature from a pinned development signer`);
  }
}

/**
 * Verify canonical build-record syntax, optional signer policy, and the
 * complete live npm closure and relation source graph. This does not by itself
 * prove that the recorded artifacts were produced by those sources; consumers
 * must also run the independent reproduction verifier before authorization.
 */
export async function verifyCircuitBuildAttestationAgainstRepository(
  bytes,
  options = {},
) {
  if (
    typeof options.repositoryRoot !== 'string'
    || options.repositoryRoot.length === 0
  ) {
    fail('repositoryRoot is required to verify a circuit build attestation');
  }
  const parsed = parseCircuitBuildAttestation(bytes, options);
  enforceTrustedSigner(parsed, options, 'circuit build attestation');
  if (!(options.sourceManifestBytes instanceof Uint8Array)) {
    fail(
      'canonical sourceManifestBytes are required to verify a circuit build attestation',
    );
  }
  if (
    parsed.sourceManifest.bytes !== options.sourceManifestBytes.byteLength
    || parsed.sourceManifest.sha256 !== sha256(options.sourceManifestBytes)
  ) {
    fail('circuit build source manifest bytes differ from the attestation');
  }
  let sourceManifest;
  try {
    sourceManifest = parseV2RelationSourceManifest(
      options.sourceManifestBytes,
    );
    await verifyV2RelationSourceManifest(sourceManifest, {
      repositoryRoot: options.repositoryRoot,
    });
  } catch (error) {
    fail(
      `circuit build source manifest differs from the repository: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  try {
    await verifyNpmBuildClosure(parsed.npmClosure, {
      repositoryRoot: options.repositoryRoot,
    });
  } catch (error) {
    fail(
      `circuit build npm closure differs from the repository: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  return parsed;
}

/**
 * Verify a canonical setup/build pair and both live npm closures. This proves
 * the content-addressed build link and exact R1CS identity. Callers must still
 * independently verify the PTau/final zkey and reproduce the exported VK.
 */
export async function verifyDevelopmentSetupAttestationPair(
  setupBytes,
  {
    buildAttestationBytes,
    repositoryRoot,
    requireTrustedSigner = false,
    sourceManifestBytes,
    trustedDevelopmentSigners,
  } = {},
) {
  if (!(buildAttestationBytes instanceof Uint8Array)) {
    fail('canonical buildAttestationBytes are required for setup linkage');
  }
  const build = await verifyCircuitBuildAttestationAgainstRepository(
    buildAttestationBytes,
    {
      repositoryRoot,
      requireTrustedSigner,
      sourceManifestBytes,
      trustedDevelopmentSigners,
    },
  );
  const setup = parseDevelopmentSetupAttestation(setupBytes, {
    trustedDevelopmentSigners,
  });
  enforceTrustedSigner(setup, {
    requireTrustedSigner,
    trustedDevelopmentSigners,
  }, 'development setup attestation');
  if (
    setup.buildAttestation.bytes !== buildAttestationBytes.byteLength
    || setup.buildAttestation.sha256 !== sha256(buildAttestationBytes)
  ) {
    fail('development setup references a different build attestation');
  }
  if (
    setup.r1cs.bytes !== build.artifacts.r1cs.bytes
    || setup.r1cs.sha256 !== build.artifacts.r1cs.sha256
  ) {
    fail('development setup R1CS differs from the circuit build');
  }
  try {
    await verifyNpmBuildClosure(setup.snarkjs.npmClosure, {
      repositoryRoot,
    });
  } catch (error) {
    fail(
      `development setup npm closure differs from the repository: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  return Object.freeze({ build, setup });
}
