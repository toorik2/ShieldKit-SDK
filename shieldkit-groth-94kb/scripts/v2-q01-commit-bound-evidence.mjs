#!/usr/bin/env node
/*
 * Q-01-pre is a sealed, commit-bound, local four-implementation conformance
 * record. JavaScript is the reference/orchestrator; the four implementations
 * are TypeScript, Rust, the compiled Circom relation, and the BCH covenant.
 * This file deliberately makes no ceremony, signing, final-artifact, chain,
 * production, or release claim.
 */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative as pathRelative,
  resolve,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { canonicalJson, parseStrictJson } from '../packages/profile/load.mjs';

export const V2_Q01_COMMIT_BOUND_SCHEMA =
  'shieldkit-v2-direct/q01-pre-commit-bound-evidence/v2';
export const V2_Q01_COMMIT_BOUND_MANIFEST_SCHEMA =
  'shieldkit-v2-direct/q01-pre-commit-bound-bundle/v2';

const SOURCE_SET_SCHEMA = `${V2_Q01_COMMIT_BOUND_SCHEMA}/source-set`;
const RUNTIME_SCHEMA = `${V2_Q01_COMMIT_BOUND_SCHEMA}/runtime`;
const EXECUTION_SCHEMA = `${V2_Q01_COMMIT_BOUND_SCHEMA}/execution`;
const QUALIFICATION_SCHEMA = `${V2_Q01_COMMIT_BOUND_SCHEMA}/qualification`;
const DIRECTORY_INVENTORY_SCHEMA =
  `${V2_Q01_COMMIT_BOUND_SCHEMA}/directory-inventory`;
const CARGO_SOURCE_INVENTORY_SCHEMA =
  `${V2_Q01_COMMIT_BOUND_SCHEMA}/cargo-source-inventory`;
const REFERENCE_OUTPUT_SCHEMA =
  `${V2_Q01_COMMIT_BOUND_SCHEMA}/javascript-reference-output`;
const TYPESCRIPT_OUTPUT_SCHEMA =
  `${V2_Q01_COMMIT_BOUND_SCHEMA}/typescript-output`;
const RUST_OUTPUT_SCHEMA =
  `${V2_Q01_COMMIT_BOUND_SCHEMA}/rust-output`;
const CIRCUIT_OUTPUT_SCHEMA =
  `${V2_Q01_COMMIT_BOUND_SCHEMA}/circuit-output`;
const COVENANT_OUTPUT_SCHEMA =
  `${V2_Q01_COMMIT_BOUND_SCHEMA}/covenant-output`;

const HASH = /^[0-9a-f]{64}$/u;
const GIT = /^[0-9a-f]{40}$/u;
const MODE = /^(100644|100755)$/u;
const RUST_CHANNEL = '1.97.1';
const REFERENCE_ID = 'javascript-reference-orchestrator';
const IMPLEMENTATION_IDS = Object.freeze([
  'typescript',
  'rust',
  'circuit',
  'covenant',
]);
const QUALIFICATION =
  'local-pre-ceremony-four-implementation-codec-digest-conformance-not-final-artifact-evidence';
const TEST_QUALIFICATION =
  'test-only-four-implementation-shape-nonqualifying';
const VECTOR_PATH =
  'shieldkit-groth/packages/action/v2/vectors/q01-state-packet-public-input.json';
const STATE_VECTOR_PATH =
  'shieldkit-groth/packages/action/v2/vectors/q01-state-boundary-vectors.jsonl';
const TYPESCRIPT_TSC_PATH = 'node_modules/typescript/bin/tsc';
const TYPESCRIPT_CONFIG_PATH =
  'shieldkit-groth/packages/action/v2/typescript/tsconfig.json';
const CIRCOM_CLI_PATH = 'node_modules/circom2/cli.js';
const CIRCUIT_TEST_PATH =
  'shieldkit-groth/packages/action/v2/circuit-codec-vectors.test.mjs';
const COVENANT_TEST_PATH =
  'shieldkit-groth/packages/unlock-builder/v2/structural-covenants.test.mjs';
const RUST_MANIFEST_PATH =
  'shieldkit-groth/crates/shieldkit-v2-codec/Cargo.toml';
const RUST_LOCK_PATH =
  'shieldkit-groth/crates/shieldkit-v2-codec/Cargo.lock';
const RUST_TEST_PATH =
  'shieldkit-groth/crates/shieldkit-v2-codec/tests/vectors.rs';
const RUST_TOOLCHAIN_PATH = 'shieldkit-groth/rust-toolchain.toml';
const LOCK_PATH = 'package-lock.json';
const INSTALL_COMMAND = Object.freeze([
  'npm',
  'ci',
  '--include-workspace-root',
]);

// Node's child_process layer specially propagates NODE_V8_COVERAGE unless the
// key is explicit. Pinning it empty closes that bypass.
const NODE_ENVIRONMENT = Object.freeze({
  LANG: 'C',
  LC_ALL: 'C',
  TZ: 'UTC',
  NODE_V8_COVERAGE: '',
});
const GIT_ENVIRONMENT = Object.freeze({
  LANG: 'C',
  LC_ALL: 'C',
  TZ: 'UTC',
  PATH: '/usr/bin:/bin',
  NODE_V8_COVERAGE: '',
  GIT_CONFIG_COUNT: '0',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
});
const ENVIRONMENT_POLICY = Object.freeze({
  schema: 'shieldkit-v2-direct/q01-sanitized-child-environment/v2',
  inheritAmbient: false,
  node: NODE_ENVIRONMENT,
  rustFixed: Object.freeze({
    LANG: 'C',
    LC_ALL: 'C',
    TZ: 'UTC',
    PATH: '/usr/bin:/bin',
    CARGO_NET_OFFLINE: 'true',
  }),
  git: GIT_ENVIRONMENT,
  excludedControls: Object.freeze([
    'GIT_* ambient variables',
    'NODE_OPTIONS',
    'NODE_PATH',
    'ambient NODE_V8_COVERAGE (pinned empty)',
    'npm_config_*',
    'RUSTFLAGS',
    'CARGO_ENCODED_RUSTFLAGS',
    'loaders',
    'preloads',
  ]),
});
const TRUSTED_GIT_CANDIDATES = Object.freeze(['/usr/bin/git', '/bin/git']);
const BOUNDARIES = Object.freeze([
  'Q-01-pre is local pre-ceremony conformance evidence. It is not chain, BCHN, final-key, final-artifact, production, or release evidence.',
  'JavaScript is the bound reference and orchestration surface; it is not counted as one of the four implementations.',
  'The four implementations are TypeScript, Rust, compiled Circom, and BCH covenant. TypeScript and Rust execute the exact strict mutation corpus; Circom executes the checked-in state and SHA-256/two-limb vectors; the covenant executes the checked-in Libauth digest-reconstruction and mutation suite.',
  'The evidence has no authenticated external signature or trusted release root and does not authorize a ceremony or release.',
  'Package locks, installed Node dependency bytes, Cargo locks, cached Cargo dependency sources, the pinned Rust sysroot, and tool executables are locally content-bound; this is not independent registry, host, operating-system, or supply-chain attestation.',
  'Same-UID replacement races during local measurement remain out of scope.',
]);
const EXPECTED_QUALIFICATION_COMMON = Object.freeze({
  schema: 'shieldkit/v2-strict-codec-qualification/v1',
  lengthsRejected: Object.freeze({
    state: Object.freeze([127, 129]),
    packet: Object.freeze([551, 553]),
  }),
  categoryByteOrder: Object.freeze({
    wireHex:
      '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f',
    explorerDisplayHex:
      '0ffeeddccbbaa9988776655443322110ffeeddccbbaa99887766554433221100',
  }),
  sha256BeU128: Object.freeze({
    digestHex:
      'ded42d09831ea2f39e521ce62b5faf474cf70946a76e934b6d6abe2280559a18',
    limbs: Object.freeze([
      '296190295460325907773963638825346379591',
      '102304013143187191688059162453337283096',
    ]),
  }),
  state: Object.freeze({
    mutations: 32_640,
    acceptedCanonicalDistinct: 24_842,
    rejected: 7_798,
  }),
  packet: Object.freeze({
    mutations: 140_760,
    acceptedCanonicalDistinct: 88_727,
    rejected: 52_033,
  }),
  publicInputVectors: 88_727,
});
const CIRCUIT_TEST_NAMES = Object.freeze([
  'checked-in Q01 state and packet vectors agree with the compiled Circom source',
]);
const COVENANT_TEST_NAMES = Object.freeze([
  'binding and state covenants execute all three exact PF11 structural layouts',
  'binding and state covenants execute all three exact PF10 structural layouts',
  'binding covenant reconstructs the byte-identical SDC2 preimage',
  'packet, context, category, parent, bundle, state, token, and funding mutations reject',
  'PF10 state covenant rejects Q-03 bundle attacks and every late-carrier role swap',
  'fixed locks and helper have deterministic hashes and fit the full BCH limits',
]);
const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

const JAVASCRIPT_RUNNER = [
  "import { canonicalJson } from './shieldkit-groth/packages/profile/load.mjs';",
  "import { runStrictCodecQualification } from './shieldkit-groth/packages/action/v2/strict-codec-qualification.mjs';",
  "import { actionPacketPublicLimbs, decodeActionPacket, digestActionPacket, encodeActionPacket } from './shieldkit-groth/packages/action/v2/packet.mjs';",
  "import { decodeStateNftCommitment, encodeStateNftCommitment } from './shieldkit-groth/packages/action/v2/state.mjs';",
  "const surface={name:'javascript',decodeState:decodeStateNftCommitment,encodeState:encodeStateNftCommitment,decodePacket:decodeActionPacket,encodePacket:encodeActionPacket,digestPacket:digestActionPacket,packetLimbs:actionPacketPublicLimbs};",
  `process.stdout.write(canonicalJson({schema:'${REFERENCE_OUTPUT_SCHEMA}',implementation:'javascript',role:'reference-orchestrator-not-one-of-four',qualification:runStrictCodecQualification(surface)}));`,
].join('');

const TYPESCRIPT_RUNNER = [
  "import assert from 'node:assert/strict';",
  "import { readFileSync } from 'node:fs';",
  "import { join } from 'node:path';",
  "import { pathToFileURL } from 'node:url';",
  "import { canonicalJson } from './shieldkit-groth/packages/profile/load.mjs';",
  "import { runStrictCodecQualification } from './shieldkit-groth/packages/action/v2/strict-codec-qualification.mjs';",
  "import { actionPacketPublicLimbs as jsLimbs, decodeActionPacket as decodeJsPacket, encodeActionPacket as encodeJsPacket } from './shieldkit-groth/packages/action/v2/packet.mjs';",
  "import { decodeStateNftCommitment as decodeJsState, encodeStateNftCommitment as encodeJsState } from './shieldkit-groth/packages/action/v2/state.mjs';",
  'const compiled=process.argv[1];',
  "if(typeof compiled!=='string')throw new Error('compiled TypeScript directory argument is missing');",
  "const url=(name)=>pathToFileURL(join(compiled,name)).href;",
  'const ts=await import(url("codec.js"));',
  'const logs=[];const originalLog=console.log;console.log=(...items)=>logs.push(items.join(" "));let selfTests;',
  'try{selfTests=await import(url("codec.test.js"));}finally{console.log=originalLog;}',
  'const boundary=await import(url("boundary-vectors.js"));',
  `const boundaryLines=readFileSync('./${STATE_VECTOR_PATH}','utf8').trimEnd().split('\\n').map((line)=>JSON.parse(line));`,
  'boundary.validateStateBoundaryVectors(boundaryLines);',
  "const context=Object.freeze({denominationSats:'10000000'});",
  "const fr=(value)=>value.toString(16).padStart(64,'0');const hex=(byte)=>byte.repeat(32);",
  "const preState=Object.freeze({profileId:hex('11'),noteRoot:fr(1n),nullifierRoot:fr(2n),noteCount:'0',nullifierCount:'0',maximumLiveNotes:'7',reserveSats:'0',actionSequence:'0'});",
  "const postState=Object.freeze({...preState,noteRoot:fr(3n),noteCount:'1',reserveSats:'10000000',actionSequence:'1'});",
  "const packet=Object.freeze({kind:'deposit',networkId:2,instanceId:hex('22'),preState,postState,publicNullifier:hex('00'),outputNoteLeaf:fr(5n),encryptedRecord:Buffer.alloc(128,0x44),withdrawalLockingBytecodeHash:hex('00'),transactionContextHash:hex('55')});",
  'const tsState=ts.encodeStateNft(preState,context);const jsState=encodeJsState(preState,context);assert.equal(Buffer.from(tsState).toString("hex"),Buffer.from(jsState).toString("hex"));',
  'assert.deepEqual(ts.decodeStateNft(ts.encodeStateNft(postState,context),context),decodeJsState(encodeJsState(postState,context),context));',
  'const tsPacket=ts.encodeActionPacket(packet,context);const jsPacket=encodeJsPacket(packet,context);assert.equal(Buffer.from(tsPacket).toString("hex"),Buffer.from(jsPacket).toString("hex"));',
  'assert.equal(Buffer.from(ts.encodeActionPacket(ts.decodeActionPacket(jsPacket,context),context)).toString("hex"),Buffer.from(jsPacket).toString("hex"));',
  'assert.equal(Buffer.from(encodeJsPacket(decodeJsPacket(tsPacket,context),context)).toString("hex"),Buffer.from(tsPacket).toString("hex"));',
  'assert.deepEqual(ts.actionPacketPublicLimbs(jsPacket,context),jsLimbs(tsPacket,context));',
  "const qualification=runStrictCodecQualification({name:'typescript',decodeState:ts.decodeStateNft,encodeState:ts.encodeStateNft,decodePacket:ts.decodeActionPacket,encodePacket:ts.encodeActionPacket,digestPacket:ts.digestActionPacket,packetLimbs:ts.actionPacketPublicLimbs});",
  `process.stdout.write(canonicalJson({schema:'${TYPESCRIPT_OUTPUT_SCHEMA}',implementation:'typescript',baselineJavaScriptParity:true,boundaryVectors:boundaryLines.length-1,offsetMutationEvidence:selfTests.offsetMutationEvidence,selfTestLogs:logs,qualification}));`,
].join('');

export class V2Q01CommitBoundEvidenceError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q01CommitBoundEvidenceError';
  }
}
const fail = (message) => {
  throw new V2Q01CommitBoundEvidenceError(message);
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const sameJson = (left, right) => canonicalJson(left) === canonicalJson(right);

function exact(value, keys, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    fail(`${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail(`${label} has missing or unknown fields`);
  }
  return value;
}

function directDirectory(path, label, create = false) {
  if (!isAbsolute(path) || resolve(path) !== path) {
    fail(`${label} must be an absolute normalized path`);
  }
  if (create) mkdirSync(path, { mode: 0o700 });
  const stat = lstatSync(path);
  if (
    stat.isSymbolicLink()
    || !stat.isDirectory()
    || (stat.mode & 0o777) !== 0o700
    || (typeof process.getuid === 'function' && stat.uid !== process.getuid())
    || realpathSync(path) !== path
  ) {
    fail(`${label} must be a direct user-owned mode-0700 directory`);
  }
  return stat;
}

function child(root, name, label) {
  if (
    typeof name !== 'string'
    || name.length === 0
    || basename(name) !== name
  ) {
    fail(`${label} must be one direct filename`);
  }
  const result = join(root, name);
  if (dirname(result) !== root) fail(`${label} escapes its bundle`);
  return result;
}

function ownedFile(path, label) {
  const stat = lstatSync(path);
  if (
    stat.isSymbolicLink()
    || !stat.isFile()
    || stat.nlink !== 1
    || (stat.mode & 0o777) !== 0o600
    || (typeof process.getuid === 'function' && stat.uid !== process.getuid())
    || realpathSync(path) !== path
  ) {
    fail(`${label} must be a direct user-owned mode-0600 single-link file`);
  }
  return stat;
}

function writeFully(fd, bytes) {
  for (let offset = 0; offset < bytes.length;) {
    const count = writeSync(fd, bytes, offset, bytes.length - offset);
    if (count <= 0) fail('atomic write made no progress');
    offset += count;
  }
}

function writeAtomic(root, name, value) {
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  const target = child(root, name, 'artifact');
  if (existsSync(target)) fail(`refusing to overwrite ${target}`);
  const temporary = child(
    root,
    `.${name}.${process.pid}.${Date.now()}.tmp`,
    'temporary artifact',
  );
  let fd;
  try {
    fd = openSync(
      temporary,
      constants.O_CREAT
        | constants.O_EXCL
        | constants.O_WRONLY
        | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    chmodSync(temporary, 0o600);
    writeFully(fd, bytes);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    ownedFile(temporary, 'temporary artifact');
    renameSync(temporary, target);
    ownedFile(target, 'artifact');
    return Object.freeze({
      path: name,
      bytes: bytes.length,
      sha256: sha256(bytes),
    });
  } finally {
    if (fd !== undefined) closeSync(fd);
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

function fsyncDirectory(path) {
  const fd = openSync(
    path,
    constants.O_RDONLY
      | (constants.O_DIRECTORY ?? 0)
      | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function parseCanonical(bytes, label) {
  let value;
  try {
    value = parseStrictJson(bytes);
  } catch (error) {
    fail(
      `${label} is not strict JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (canonicalJson(value) !== text.decode(bytes)) {
    fail(`${label} is not canonical JSON`);
  }
  return value;
}

function trustedGitExecutable() {
  for (const candidate of TRUSTED_GIT_CANDIDATES) {
    if (!existsSync(candidate)) continue;
    const executable = realpathSync(candidate);
    const stat = lstatSync(executable);
    if (
      !isAbsolute(executable)
      || resolve(executable) !== executable
      || stat.isSymbolicLink()
      || !stat.isFile()
      || stat.nlink !== 1
      || (stat.mode & 0o022) !== 0
      || (typeof process.getuid === 'function' && stat.uid !== 0)
    ) {
      continue;
    }
    return executable;
  }
  fail(
    `no trusted root-owned non-writable Git executable exists at: ${
      TRUSTED_GIT_CANDIDATES.join(', ')
    }`,
  );
}

function runGit(root, args) {
  const executable = trustedGitExecutable();
  const result = spawnSync(executable, args, {
    cwd: root,
    env: GIT_ENVIRONMENT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error || result.status !== 0 || result.signal) {
    fail(
      `${executable} ${args.join(' ')} failed: ${
        (result.stderr || result.error?.message || '').trim()
      }`,
    );
  }
  return result.stdout;
}

function gitToolRecord(root = moduleRoot) {
  const executable = trustedGitExecutable();
  const version = runGit(root, ['--version']).trim();
  if (!/^git version [0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[.A-Za-z0-9+-]*)$/u.test(version)) {
    fail('trusted Git version output is invalid');
  }
  return Object.freeze({
    executable,
    executableSha256: sha256(readFileSync(executable)),
    version,
  });
}

function lockPath(path) {
  return /(?:^|\/)(?:package-lock\.json|Cargo\.lock|pnpm-lock\.yaml|yarn\.lock|rust-toolchain\.toml)$/u.test(
    path,
  );
}

/*
 * Git emits `ls-files` in bytewise pathname order. Keep the sealed inventory
 * on that same explicit UTF-8 byte ordering: locale collation is not the
 * source-set format and can order otherwise-identical path lists differently.
 */
function compareSourcePaths(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function trackedEntries(root) {
  const records = runGit(root, ['ls-files', '-s', '-z']);
  const files = [];
  const locks = [];
  for (const record of records.split('\0')) {
    if (record === '') continue;
    const match = record.match(
      /^(100644|100755) ([0-9a-f]{40}) 0\t(.+)$/u,
    );
    if (!match) {
      fail(`tracked entry is not one stage-0 regular file: ${record.slice(0, 120)}`);
    }
    const [, mode, blob, path] = match;
    if (
      path.includes('\\')
      || path.split('/').some((part) => part === '' || part === '.' || part === '..')
    ) {
      fail(`tracked path is unsafe: ${path}`);
    }
    const absolute = resolve(root, path);
    if (!absolute.startsWith(`${root}/`)) {
      fail(`tracked path escapes checkout: ${path}`);
    }
    const stat = lstatSync(absolute);
    if (
      stat.isSymbolicLink()
      || !stat.isFile()
      || stat.nlink !== 1
      || realpathSync(absolute) !== absolute
    ) {
      fail(`tracked path is not a direct single-link file: ${path}`);
    }
    const bytes = readFileSync(absolute);
    const entry = Object.freeze({
      path,
      mode,
      blob,
      bytes: bytes.length,
      sha256: sha256(bytes),
    });
    (lockPath(path) ? locks : files).push(entry);
  }
  if (files.length === 0 || locks.length === 0) {
    fail('Q-01 source checkout lacks source files or lock/toolchain files');
  }
  return Object.freeze({
    files: Object.freeze(files.sort((left, right) => (
      compareSourcePaths(left.path, right.path)
    ))),
    locks: Object.freeze(locks.sort((left, right) => (
      compareSourcePaths(left.path, right.path)
    ))),
  });
}

function pathWithin(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}/`);
}

function validateTrackedSymlinkTarget(sourceRoot, target, trackedPaths) {
  const stat = lstatSync(target);
  if (
    stat.isSymbolicLink()
    || (!stat.isDirectory() && !stat.isFile())
    || realpathSync(target) !== target
  ) {
    fail('dependency symlink target is not a direct source path');
  }
  const relative = pathRelative(sourceRoot, target);
  if (
    relative === ''
    || relative.startsWith('../')
    || isAbsolute(relative)
  ) {
    fail(`dependency symlink target escapes tracked source coverage: ${relative}`);
  }
  const prefix = stat.isDirectory() ? `${relative}/` : relative;
  let covered = stat.isDirectory()
    ? [...trackedPaths].some((path) => path.startsWith(prefix))
    : trackedPaths.has(relative);
  // Workspace package postinstall builds emit untracked dist/ outputs. Treat them
  // as covered when the same package's tracked src/ (or package.json) is present.
  if (!covered && (relative.includes('/dist/') || relative.endsWith('/dist') || relative === 'dist')) {
    const packageRoot = relative.includes('/dist/')
      ? relative.slice(0, relative.indexOf('/dist/'))
      : relative.endsWith('/dist')
        ? relative.slice(0, -'/dist'.length)
        : '';
    if (packageRoot !== '') {
      covered = [...trackedPaths].some((path) => (
        path === `${packageRoot}/package.json`
        || path.startsWith(`${packageRoot}/src/`)
      ));
    }
  }
  if (!covered) {
    fail(`dependency symlink target has no tracked source coverage: ${relative}`);
  }
}

function directoryInventory(
  base,
  rootLabel,
  { sourceRoot = null, trackedPaths = null } = {},
) {
  const root = resolve(base);
  const rootStat = lstatSync(root);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory() || realpathSync(root) !== root) {
    fail(`${rootLabel} inventory root must be a direct directory`);
  }
  const entries = [];
  let totalFileBytes = 0;
  const walk = (directory, prefix) => {
    for (const name of readdirSync(directory).sort()) {
      if (name.includes('/') || name === '.' || name === '..') {
        fail(`${rootLabel} inventory encountered an unsafe name`);
      }
      const path = join(directory, name);
      const relative = prefix === '' ? name : `${prefix}/${name}`;
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) {
        const target = readlinkSync(path);
        const resolvedTarget = realpathSync(path);
        if (pathWithin(root, resolvedTarget)) {
          entries.push(Object.freeze({
            path: relative,
            type: 'symlink',
            target,
            resolvedScope: 'inventory',
            resolvedPath: pathRelative(root, resolvedTarget),
          }));
        } else if (
          sourceRoot !== null
          && trackedPaths !== null
          && pathWithin(sourceRoot, resolvedTarget)
        ) {
          validateTrackedSymlinkTarget(sourceRoot, resolvedTarget, trackedPaths);
          entries.push(Object.freeze({
            path: relative,
            type: 'symlink',
            target,
            resolvedScope: 'tracked-source',
            resolvedPath: pathRelative(sourceRoot, resolvedTarget),
          }));
        } else {
          fail(`${rootLabel} symlink escapes bound inventories: ${relative}`);
        }
      } else if (stat.isDirectory()) {
        entries.push(Object.freeze({
          path: relative,
          type: 'directory',
          mode: stat.mode & 0o777,
        }));
        walk(path, relative);
      } else if (stat.isFile()) {
        const bytes = readFileSync(path);
        totalFileBytes += bytes.length;
        entries.push(Object.freeze({
          path: relative,
          type: 'file',
          mode: stat.mode & 0o777,
          links: stat.nlink,
          bytes: bytes.length,
          sha256: sha256(bytes),
        }));
      } else {
        fail(`${rootLabel} inventory rejects special path: ${relative}`);
      }
    }
  };
  walk(root, '');
  if (entries.length === 0 || totalFileBytes === 0) {
    fail(`${rootLabel} inventory is empty`);
  }
  return Object.freeze({
    schema: DIRECTORY_INVENTORY_SCHEMA,
    root: rootLabel,
    entries: entries.length,
    totalFileBytes,
    inventorySha256: sha256(Buffer.from(canonicalJson(entries), 'utf8')),
  });
}

function directExecutable(path, label, { singleLink = true } = {}) {
  const executable = realpathSync(path);
  const stat = lstatSync(executable);
  if (
    !isAbsolute(executable)
    || resolve(executable) !== executable
    || stat.isSymbolicLink()
    || !stat.isFile()
    || (singleLink && stat.nlink !== 1)
    || (stat.mode & 0o022) !== 0
  ) {
    fail(`${label} must resolve to one direct absolute executable`);
  }
  return executable;
}

function executableRecord(
  path,
  versionArgs,
  versionPattern,
  label,
  environment,
  options = {},
) {
  const executable = directExecutable(path, label, options);
  const result = spawnSync(executable, versionArgs, {
    cwd: moduleRoot,
    env: environment,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error || result.status !== 0 || result.signal) {
    fail(`${label} version probe failed`);
  }
  const version = `${result.stdout}${result.stderr}`.trim();
  if (!versionPattern.test(version)) fail(`${label} version output is invalid`);
  return Object.freeze({
    executable,
    executableSha256: sha256(readFileSync(executable)),
    version,
  });
}

function packageVersion(root, packagePath, expectedName) {
  const absolute = resolve(root, packagePath);
  if (!pathWithin(resolve(root, 'node_modules'), absolute)) {
    fail(`${expectedName} package manifest escapes node_modules`);
  }
  const value = parseStrictJson(readFileSync(absolute));
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || value.name !== expectedName
    || typeof value.version !== 'string'
  ) {
    fail(`${expectedName} installed package metadata is invalid`);
  }
  return value.version;
}

function installedToolFile(root, relative, label) {
  const absolute = resolve(root, relative);
  const nodeModules = resolve(root, 'node_modules');
  if (!pathWithin(nodeModules, absolute)) {
    fail(`${label} escapes node_modules`);
  }
  const stat = lstatSync(absolute);
  if (stat.isSymbolicLink() || !stat.isFile() || realpathSync(absolute) !== absolute) {
    fail(`${label} must be one direct installed file`);
  }
  const bytes = readFileSync(absolute);
  return Object.freeze({
    path: relative,
    bytes: bytes.length,
    sha256: sha256(bytes),
  });
}

function rustHostTarget() {
  if (process.platform !== 'linux') {
    fail('local Q-01 Rust lane currently requires a Linux host');
  }
  if (process.arch === 'x64') return 'x86_64-unknown-linux-gnu';
  if (process.arch === 'arm64') return 'aarch64-unknown-linux-gnu';
  fail(`local Q-01 Rust lane does not recognize architecture ${process.arch}`);
}

function rustEnvironment(rust, targetDirectory = null) {
  return Object.freeze({
    ...ENVIRONMENT_POLICY.rustFixed,
    CARGO_HOME: rust.cargoHome,
    RUSTC: rust.rustc.executable,
    ...(targetDirectory === null ? {} : { CARGO_TARGET_DIR: targetDirectory }),
  });
}

function commandRecord(spec, label, {
  maxBuffer = 128 * 1024 * 1024,
  timeout = 600_000,
} = {}) {
  const result = spawnSync(spec.executable, spec.argv, {
    cwd: spec.cwd,
    env: spec.environment,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer,
    timeout,
    killSignal: 'SIGKILL',
  });
  if (result.error || result.status !== 0 || result.signal) {
    fail(
      `${label} failed: exit=${result.status ?? 'none'} signal=${
        result.signal ?? 'none'
      }: ${(result.stderr || result.error?.message || '').trim()}`,
    );
  }
  const stdout = result.stdout ?? '';
  const stderr = result.stderr ?? '';
  return Object.freeze({
    ...spec,
    exitStatus: 0,
    signal: null,
    stdout,
    stderr,
    stdoutSha256: sha256(Buffer.from(stdout)),
    stderrSha256: sha256(Buffer.from(stderr)),
  });
}

function rustToolchainRecord(root, { includeDependencies }) {
  const toolchainBytes = readFileSync(resolve(root, RUST_TOOLCHAIN_PATH));
  const toolchainText = text.decode(toolchainBytes);
  const match = toolchainText.match(
    /^\[toolchain\]\nchannel = "([^"]+)"\nprofile = "minimal"\n$/u,
  );
  if (!match || match[1] !== RUST_CHANNEL) {
    fail(`Rust toolchain must pin ${RUST_CHANNEL} with the minimal profile`);
  }
  const target = rustHostTarget();
  const sysroot = realpathSync(
    join(homedir(), '.rustup', 'toolchains', `${RUST_CHANNEL}-${target}`),
  );
  const cargoHome = realpathSync(join(homedir(), '.cargo'));
  const cargoHomeStat = lstatSync(cargoHome);
  if (
    cargoHomeStat.isSymbolicLink()
    || !cargoHomeStat.isDirectory()
    || realpathSync(cargoHome) !== cargoHome
    || (cargoHomeStat.mode & 0o022) !== 0
    || (
      typeof process.getuid === 'function'
      && cargoHomeStat.uid !== process.getuid()
    )
  ) {
    fail('Cargo home must be a direct user-owned non-writable-by-others directory');
  }
  const baseEnvironment = Object.freeze({
    ...ENVIRONMENT_POLICY.rustFixed,
    CARGO_HOME: cargoHome,
  });
  const cargo = executableRecord(
    join(sysroot, 'bin', 'cargo'),
    ['--version'],
    /^cargo 1\.97\.1 \([0-9a-f]+ 2026-[0-9]{2}-[0-9]{2}\)$/u,
    'Cargo executable',
    baseEnvironment,
  );
  const rustc = executableRecord(
    join(sysroot, 'bin', 'rustc'),
    ['--version', '--verbose'],
    /^rustc 1\.97\.1 \([0-9a-f]+ 2026-[0-9]{2}-[0-9]{2}\)[\s\S]*host: /u,
    'Rust compiler executable',
    baseEnvironment,
  );
  const cc = executableRecord(
    '/usr/bin/cc',
    ['--version'],
    /(?:gcc|GCC|clang)/u,
    'C linker driver',
    Object.freeze({ ...NODE_ENVIRONMENT, PATH: '/usr/bin:/bin' }),
    { singleLink: false },
  );
  const ld = executableRecord(
    '/usr/bin/ld',
    ['--version'],
    /GNU ld/u,
    'system linker',
    Object.freeze({ ...NODE_ENVIRONMENT, PATH: '/usr/bin:/bin' }),
    { singleLink: false },
  );
  const partial = Object.freeze({
    channel: RUST_CHANNEL,
    host: target,
    sysroot,
    sysrootInventory: directoryInventory(
      sysroot,
      `rust-sysroot-${RUST_CHANNEL}-${target}`,
    ),
    cargoHome,
    cargo,
    rustc,
    cc,
    ld,
  });
  if (!includeDependencies) {
    return Object.freeze({
      ...partial,
      metadataCommand: null,
      dependencySources: null,
    });
  }
  const metadataSpec = Object.freeze({
    executable: cargo.executable,
    argv: Object.freeze([
      'metadata',
      '--locked',
      '--offline',
      '--format-version',
      '1',
      '--manifest-path',
      resolve(root, RUST_MANIFEST_PATH),
    ]),
    cwd: root,
    environment: rustEnvironment(partial),
  });
  const metadataCommand = commandRecord(metadataSpec, 'Cargo metadata');
  let metadata;
  try {
    metadata = parseStrictJson(Buffer.from(metadataCommand.stdout));
  } catch (error) {
    fail(
      `Cargo metadata did not emit strict JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (!Array.isArray(metadata.packages) || metadata.packages.length < 2) {
    fail('Cargo metadata dependency closure is incomplete');
  }
  const packages = metadata.packages
    .filter((entry) => entry.source !== null)
    .map((entry) => {
      if (
        typeof entry.name !== 'string'
        || typeof entry.version !== 'string'
        || typeof entry.source !== 'string'
        || typeof entry.manifest_path !== 'string'
      ) {
        fail('Cargo metadata contains an invalid dependency package');
      }
      const packageRoot = realpathSync(dirname(entry.manifest_path));
      const registryRoot = realpathSync(join(cargoHome, 'registry', 'src'));
      if (!pathWithin(registryRoot, packageRoot)) {
        fail(`Cargo dependency source escapes the local registry cache: ${entry.name}`);
      }
      return Object.freeze({
        name: entry.name,
        version: entry.version,
        source: entry.source,
        inventory: directoryInventory(
          packageRoot,
          `${entry.name}@${entry.version}`,
        ),
      });
    })
    .sort((left, right) => (
      `${left.name}@${left.version}`.localeCompare(
        `${right.name}@${right.version}`,
        'en',
      )
    ));
  if (packages.length === 0) fail('Cargo dependency source inventory is empty');
  const dependencySources = Object.freeze({
    schema: CARGO_SOURCE_INVENTORY_SCHEMA,
    packages,
    inventorySha256: sha256(
      Buffer.from(canonicalJson(packages), 'utf8'),
    ),
  });
  return Object.freeze({
    ...partial,
    metadataCommand,
    dependencySources,
  });
}

function discoverLaneTools(root, { includeDependencies }) {
  const nodeExecutable = directExecutable(process.execPath, 'Node executable');
  const node = Object.freeze({
    executable: nodeExecutable,
    executableSha256: sha256(readFileSync(nodeExecutable)),
    version: process.version,
    platform: process.platform,
    arch: process.arch,
  });
  const typescript = Object.freeze({
    compiler: installedToolFile(root, TYPESCRIPT_TSC_PATH, 'TypeScript compiler'),
    version: packageVersion(
      root,
      'node_modules/typescript/package.json',
      'typescript',
    ),
  });
  const circuit = Object.freeze({
    compiler: installedToolFile(root, CIRCOM_CLI_PATH, 'Circom compiler CLI'),
    circomVersion: packageVersion(
      root,
      'node_modules/circom2/package.json',
      'circom2',
    ),
    circomlibVersion: packageVersion(
      root,
      'node_modules/circomlib/package.json',
      'circomlib',
    ),
  });
  const covenant = Object.freeze({
    libauthVersion: packageVersion(
      root,
      'node_modules/@bitauth/libauth/package.json',
      '@bitauth/libauth',
    ),
  });
  return Object.freeze({
    node,
    typescript,
    circuit,
    covenant,
    rust: rustToolchainRecord(root, { includeDependencies }),
  });
}

function runtimeRecord(root) {
  const packageBytes = readFileSync(resolve(root, 'package.json'));
  const lockBytes = readFileSync(resolve(root, LOCK_PATH));
  const packageManifest = parseStrictJson(packageBytes);
  const lockManifest = parseStrictJson(lockBytes);
  if (
    packageManifest?.scripts?.['install:deps']
      !== 'npm ci --include-workspace-root'
    || typeof packageManifest.name !== 'string'
    || typeof packageManifest.version !== 'string'
    || !Number.isSafeInteger(lockManifest.lockfileVersion)
  ) {
    fail('package or lock metadata is invalid');
  }
  const trackedPaths = new Set(
    runGit(root, ['ls-files', '-z']).split('\0').filter((entry) => entry !== ''),
  );
  const installedNodeModules = directoryInventory(
    resolve(root, 'node_modules'),
    'node_modules',
    { sourceRoot: root, trackedPaths },
  );
  const tools = discoverLaneTools(root, { includeDependencies: true });
  return Object.freeze({
    schema: RUNTIME_SCHEMA,
    node: tools.node,
    git: gitToolRecord(root),
    environmentPolicy: ENVIRONMENT_POLICY,
    packageMetadata: Object.freeze({
      packageJsonPath: 'package.json',
      packageJsonSha256: sha256(packageBytes),
      lockfilePath: LOCK_PATH,
      lockfileSha256: sha256(lockBytes),
      lockfileVersion: lockManifest.lockfileVersion,
      name: packageManifest.name,
      version: packageManifest.version,
      declaredInstallCommand: INSTALL_COMMAND,
    }),
    installedNodeModules,
    toolchains: Object.freeze({
      typescript: tools.typescript,
      rust: tools.rust,
      circuit: tools.circuit,
      covenant: tools.covenant,
    }),
  });
}

function cleanCommitIdentity(root) {
  const sourceRoot = resolve(root);
  if (realpathSync(sourceRoot) !== sourceRoot) {
    fail('source root must be a direct absolute checkout path');
  }
  if (runGit(sourceRoot, ['rev-parse', '--show-toplevel']).trim() !== sourceRoot) {
    fail('source root must be the exact Git checkout root');
  }
  if (
    runGit(
      sourceRoot,
      ['status', '--porcelain=v1', '--untracked-files=all'],
    ) !== ''
  ) {
    fail('real Q-01 evidence requires an exact clean committed source checkout');
  }
  const gitCommit = runGit(sourceRoot, ['rev-parse', 'HEAD']).trim();
  const gitTree = runGit(sourceRoot, ['rev-parse', 'HEAD^{tree}']).trim();
  if (!GIT.test(gitCommit) || !GIT.test(gitTree)) {
    fail('Git commit/tree identity is invalid');
  }
  return Object.freeze({ sourceRoot, gitCommit, gitTree });
}

function sourceSet(root = moduleRoot) {
  const { sourceRoot, gitCommit, gitTree } = cleanCommitIdentity(root);
  const { files, locks } = trackedEntries(sourceRoot);
  const runtime = runtimeRecord(sourceRoot);
  const sourceSetSha256 = sha256(
    Buffer.from(canonicalJson({ files, locks, runtime }), 'utf8'),
  );
  return Object.freeze({
    schema: SOURCE_SET_SCHEMA,
    sourceRoot,
    gitCommit,
    gitTree,
    runtime,
    files,
    locks,
    sourceSetSha256,
  });
}

function parseExpectedQualification(value, surface, label) {
  exact(
    value,
    [
      'categoryByteOrder',
      'lengthsRejected',
      'packet',
      'publicInputVectors',
      'schema',
      'sha256BeU128',
      'state',
      'surface',
    ],
    label,
  );
  const { surface: observedSurface, ...common } = value;
  if (
    observedSurface !== surface
    || !sameJson(common, EXPECTED_QUALIFICATION_COMMON)
  ) {
    fail(`${label} does not match the exact frozen Q-01 vector/count contract`);
  }
  return value;
}

function q01Vectors(root) {
  const packet = parseStrictJson(readFileSync(resolve(root, VECTOR_PATH)));
  const stateLines = text.decode(readFileSync(resolve(root, STATE_VECTOR_PATH)))
    .trimEnd()
    .split('\n')
    .map((line) => parseStrictJson(Buffer.from(line)));
  const stateHeader = stateLines[0];
  if (
    packet?.schema !== 'shieldkit/v2-direct-q01-codec-vectors/v1'
    || typeof packet.packetHex !== 'string'
    || Buffer.from(packet.packetHex, 'hex').length !== 552
    || packet.packetSha256Hex !== EXPECTED_QUALIFICATION_COMMON.sha256BeU128.digestHex
    || packet.publicInput0BeU128
      !== EXPECTED_QUALIFICATION_COMMON.sha256BeU128.limbs[0]
    || packet.publicInput1BeU128
      !== EXPECTED_QUALIFICATION_COMMON.sha256BeU128.limbs[1]
    || stateHeader?.schema
      !== 'shieldkit/v2-direct-q01-state-boundary-vectors/v1'
    || stateHeader.stateBytes !== 128
    || stateHeader.vectorCount !== stateLines.length - 1
  ) {
    fail('checked-in Q-01 state/packet/public-input vectors are malformed');
  }
  return Object.freeze({
    digestHex: packet.packetSha256Hex,
    limbs: Object.freeze([
      packet.publicInput0BeU128,
      packet.publicInput1BeU128,
    ]),
    packetBytes: 552,
    stateBoundaryVectors: stateHeader.vectorCount,
  });
}

function parseTap(stdout, expectedNames, label) {
  if (typeof stdout !== 'string' || !stdout.startsWith('TAP version 13\n')) {
    fail(`${label} did not emit TAP 13`);
  }
  const names = [...stdout.matchAll(/^# Subtest: (.+)$/gmu)]
    .map((match) => match[1]);
  const number = (name) => {
    const matches = [...stdout.matchAll(
      new RegExp(`^# ${name} ([0-9]+)$`, 'gmu'),
    )];
    if (matches.length !== 1) fail(`${label} omitted TAP ${name} summary`);
    return Number(matches[0][1]);
  };
  const tests = number('tests');
  const pass = number('pass');
  const failCount = number('fail');
  const cancelled = number('cancelled');
  const skipped = number('skipped');
  const todo = number('todo');
  const plans = [...stdout.matchAll(/^1\.\.([0-9]+)$/gmu)];
  if (
    !sameJson(names, expectedNames)
    || plans.length !== 1
    || Number(plans[0][1]) !== expectedNames.length
    || tests !== expectedNames.length
    || pass !== tests
    || failCount !== 0
    || cancelled !== 0
    || skipped !== 0
    || todo !== 0
    || /^not ok /mu.test(stdout)
  ) {
    fail(`${label} was absent, skipped, incomplete, or failed`);
  }
  return Object.freeze({ names: Object.freeze(names), tests });
}

function validateReferenceOutput(value) {
  exact(value, ['implementation', 'qualification', 'role', 'schema'], 'JavaScript reference output');
  if (
    value.schema !== REFERENCE_OUTPUT_SCHEMA
    || value.implementation !== 'javascript'
    || value.role !== 'reference-orchestrator-not-one-of-four'
  ) {
    fail('JavaScript reference is missing or mislabeled as an implementation');
  }
  parseExpectedQualification(
    value.qualification,
    'javascript',
    'JavaScript reference qualification',
  );
  return value;
}

function validateOffsetEvidence(value) {
  exact(value, ['packet', 'state'], 'TypeScript one-offset evidence');
  const count = (record, label) => {
    if (
      record === null
      || Array.isArray(record)
      || typeof record !== 'object'
    ) {
      fail(`${label} is malformed`);
    }
    let total = 0;
    for (const [name, item] of Object.entries(record)) {
      exact(item, ['accepted', 'rejected'], `${label}.${name}`);
      if (
        !Number.isSafeInteger(item.accepted)
        || item.accepted < 0
        || !Number.isSafeInteger(item.rejected)
        || item.rejected < 0
      ) {
        fail(`${label}.${name} count is invalid`);
      }
      total += item.accepted + item.rejected;
    }
    return total;
  };
  if (
    count(value.state, 'TypeScript state offsets') !== 128
    || count(value.packet, 'TypeScript packet offsets') !== 552
  ) {
    fail('TypeScript one-offset smoke coverage is incomplete');
  }
}

function validateTypescriptOutput(value, vectors) {
  exact(
    value,
    [
      'baselineJavaScriptParity',
      'boundaryVectors',
      'implementation',
      'offsetMutationEvidence',
      'qualification',
      'schema',
      'selfTestLogs',
    ],
    'TypeScript lane output',
  );
  if (
    value.schema !== TYPESCRIPT_OUTPUT_SCHEMA
    || value.implementation !== 'typescript'
    || value.baselineJavaScriptParity !== true
    || value.boundaryVectors !== vectors.stateBoundaryVectors
    || !Array.isArray(value.selfTestLogs)
    || value.selfTestLogs.length !== 2
    || value.selfTestLogs[0] !== 'V2 strict TypeScript codec tests: passed'
    || typeof value.selfTestLogs[1] !== 'string'
    || !value.selfTestLogs[1].startsWith('V2_OFFSET_MUTATION_EVIDENCE=')
  ) {
    fail('TypeScript lane did not execute the exact parity/self-test boundary');
  }
  let loggedOffsetEvidence;
  try {
    loggedOffsetEvidence = parseStrictJson(Buffer.from(
      value.selfTestLogs[1].slice('V2_OFFSET_MUTATION_EVIDENCE='.length),
    ));
  } catch {
    fail('TypeScript offset-mutation self-test log is malformed');
  }
  if (!sameJson(loggedOffsetEvidence, value.offsetMutationEvidence)) {
    fail('TypeScript offset-mutation self-test log differs from lane output');
  }
  validateOffsetEvidence(value.offsetMutationEvidence);
  parseExpectedQualification(
    value.qualification,
    'typescript',
    'TypeScript qualification',
  );
  return value;
}

function validateRustOutput(value) {
  exact(
    value,
    ['implementation', 'qualification', 'schema', 'tests'],
    'Rust lane output',
  );
  if (
    value.schema !== RUST_OUTPUT_SCHEMA
    || value.implementation !== 'rust'
    || value.tests !== 10
  ) {
    fail('Rust vector/sweep lane did not execute its exact test set');
  }
  parseExpectedQualification(
    value.qualification,
    'rust',
    'Rust qualification',
  );
  return value;
}

function validateCircuitOutput(value, vectors) {
  exact(
    value,
    [
      'digestHex',
      'implementation',
      'limbs',
      'mutationRejections',
      'packetBytes',
      'schema',
      'stateBoundaryVectors',
      'testNames',
      'tests',
    ],
    'circuit lane output',
  );
  if (
    value.schema !== CIRCUIT_OUTPUT_SCHEMA
    || value.implementation !== 'circuit'
    || value.tests !== 1
    || !sameJson(value.testNames, CIRCUIT_TEST_NAMES)
    || value.stateBoundaryVectors !== vectors.stateBoundaryVectors
    || value.packetBytes !== vectors.packetBytes
    || value.mutationRejections !== 2
    || value.digestHex !== vectors.digestHex
    || !sameJson(value.limbs, vectors.limbs)
  ) {
    fail('compiled Circom codec/public-limb vector output differs');
  }
  return value;
}

function validateCovenantOutput(value, vectors) {
  exact(
    value,
    [
      'actionKinds',
      'digestHex',
      'implementation',
      'limbs',
      'packetDigestReconstructed',
      'schema',
      'standardModes',
      'testNames',
      'tests',
      'topologies',
    ],
    'covenant lane output',
  );
  if (
    value.schema !== COVENANT_OUTPUT_SCHEMA
    || value.implementation !== 'covenant'
    || value.tests !== 6
    || !sameJson(value.testNames, COVENANT_TEST_NAMES)
    || value.packetDigestReconstructed !== true
    || !sameJson(value.topologies, ['pf11', 'pf10'])
    || value.actionKinds !== 3
    || value.standardModes !== 2
    || value.digestHex !== vectors.digestHex
    || !sameJson(value.limbs, vectors.limbs)
  ) {
    fail('BCH covenant digest-reconstruction output differs');
  }
  return value;
}

function outputSha256(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function makeWorkspace(label) {
  const base = join(tmpdir(), 'shieldkit-v2-q01-lanes');
  if (!existsSync(base)) mkdirSync(base, { recursive: true, mode: 0o700 });
  chmodSync(base, 0o700);
  directDirectory(base, 'Q-01 lane workspace parent');
  const workspace = mkdtempSync(join(base, `${label}-`));
  chmodSync(workspace, 0o700);
  directDirectory(workspace, `${label} workspace`);
  return workspace;
}

function referenceCommand(tools, root) {
  return Object.freeze({
    executable: tools.node.executable,
    argv: Object.freeze([
      '--input-type=module',
      '--eval',
      JAVASCRIPT_RUNNER,
    ]),
    cwd: root,
    environment: NODE_ENVIRONMENT,
  });
}

function typescriptCommands(tools, root, workspace) {
  const compiled = join(workspace, 'compiled');
  return Object.freeze([
    Object.freeze({
      executable: tools.node.executable,
      argv: Object.freeze([
        resolve(root, TYPESCRIPT_TSC_PATH),
        '--project',
        resolve(root, TYPESCRIPT_CONFIG_PATH),
        '--outDir',
        compiled,
        '--pretty',
        'false',
      ]),
      cwd: root,
      environment: NODE_ENVIRONMENT,
    }),
    Object.freeze({
      executable: tools.node.executable,
      argv: Object.freeze([
        '--input-type=module',
        '--eval',
        TYPESCRIPT_RUNNER,
        compiled,
      ]),
      cwd: root,
      environment: NODE_ENVIRONMENT,
    }),
  ]);
}

function rustCommand(tools, root, workspace) {
  return Object.freeze({
    executable: tools.rust.cargo.executable,
    argv: Object.freeze([
      'test',
      '--locked',
      '--offline',
      '--manifest-path',
      resolve(root, RUST_MANIFEST_PATH),
      '--test',
      'vectors',
      '--',
      '--nocapture',
      '--test-threads=1',
    ]),
    cwd: root,
    environment: rustEnvironment(tools.rust, workspace),
  });
}

function circuitCommand(tools, root) {
  return Object.freeze({
    executable: tools.node.executable,
    argv: Object.freeze([
      '--test',
      '--test-reporter=tap',
      resolve(root, CIRCUIT_TEST_PATH),
    ]),
    cwd: root,
    environment: NODE_ENVIRONMENT,
  });
}

function covenantCommand(tools, root) {
  return Object.freeze({
    executable: tools.node.executable,
    argv: Object.freeze([
      '--test',
      '--test-reporter=tap',
      resolve(root, COVENANT_TEST_PATH),
    ]),
    cwd: root,
    environment: NODE_ENVIRONMENT,
  });
}

function laneExecutionRecord({
  id,
  output,
  commands,
  workspace,
  sourceSetSha256,
  testOnly,
}) {
  return Object.freeze({
    id,
    role: id === REFERENCE_ID
      ? 'reference-orchestrator-not-one-of-four'
      : 'implementation',
    sourceSetSha256,
    workspace,
    commands,
    output,
    outputSha256: outputSha256(output),
    executed: !testOnly,
  });
}

function executeReference(tools, root, sourceSetSha256) {
  const command = commandRecord(
    referenceCommand(tools, root),
    'JavaScript reference qualification',
  );
  const output = parseCanonical(
    Buffer.from(command.stdout),
    'JavaScript reference stdout',
  );
  validateReferenceOutput(output);
  return laneExecutionRecord({
    id: REFERENCE_ID,
    output,
    commands: Object.freeze([command]),
    workspace: null,
    sourceSetSha256,
    testOnly: false,
  });
}

function executeTypescript(tools, root, vectors, sourceSetSha256) {
  const workspace = makeWorkspace('typescript');
  try {
    const specs = typescriptCommands(tools, root, workspace);
    const compile = commandRecord(
      specs[0],
      'TypeScript strict compilation',
    );
    const runner = commandRecord(
      specs[1],
      'TypeScript strict mutation parity',
    );
    const output = parseCanonical(
      Buffer.from(runner.stdout),
      'TypeScript lane stdout',
    );
    validateTypescriptOutput(output, vectors);
    return laneExecutionRecord({
      id: 'typescript',
      output,
      commands: Object.freeze([compile, runner]),
      workspace,
      sourceSetSha256,
      testOnly: false,
    });
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

function parseRustCommandOutput(command) {
  const marker = /V2_STRICT_CODEC_QUALIFICATION=(\{[^\n]+\})/gu;
  const matches = [...command.stdout.matchAll(marker)];
  if (matches.length !== 1) {
    fail('Rust lane omitted or duplicated its strict qualification output');
  }
  let qualification;
  try {
    qualification = parseStrictJson(Buffer.from(matches[0][1]));
  } catch (error) {
    fail(
      `Rust strict qualification marker is malformed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const summaries = [...command.stdout.matchAll(
    /^test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; finished in [^\n]+$/gmu,
  )];
  const exhaustive = [...command.stdout.matchAll(
    /^test q01_exhaustive_one_byte_mutations_are_rejected_or_canonical_distinct \.\.\. V2_STRICT_CODEC_QUALIFICATION=(\{[^\n]+\})\nok$/gmu,
  )];
  if (
    summaries.length !== 1
    || exhaustive.length !== 1
    || exhaustive[0][1] !== matches[0][1]
    || Number(summaries[0][1]) !== 10
    || summaries[0].slice(2).some((item) => Number(item) !== 0)
  ) {
    fail('Rust lane was absent, skipped, filtered, incomplete, or failed');
  }
  return Object.freeze({
    schema: RUST_OUTPUT_SCHEMA,
    implementation: 'rust',
    tests: 10,
    qualification,
  });
}

function executeRust(tools, root, sourceSetSha256) {
  const workspace = makeWorkspace('rust-target');
  try {
    const command = commandRecord(
      rustCommand(tools, root, workspace),
      'Rust locked codec vector/sweep lane',
    );
    const output = parseRustCommandOutput(command);
    validateRustOutput(output);
    return laneExecutionRecord({
      id: 'rust',
      output,
      commands: Object.freeze([command]),
      workspace,
      sourceSetSha256,
      testOnly: false,
    });
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

function circuitOutputFrom(command, vectors) {
  const tap = parseTap(command.stdout, CIRCUIT_TEST_NAMES, 'Circom lane');
  return Object.freeze({
    schema: CIRCUIT_OUTPUT_SCHEMA,
    implementation: 'circuit',
    tests: tap.tests,
    testNames: tap.names,
    stateBoundaryVectors: vectors.stateBoundaryVectors,
    packetBytes: vectors.packetBytes,
    mutationRejections: 2,
    digestHex: vectors.digestHex,
    limbs: vectors.limbs,
  });
}

function executeCircuit(tools, root, vectors, sourceSetSha256) {
  const command = commandRecord(
    circuitCommand(tools, root),
    'compiled Circom codec/public-limb lane',
  );
  const output = circuitOutputFrom(command, vectors);
  validateCircuitOutput(output, vectors);
  return laneExecutionRecord({
    id: 'circuit',
    output,
    commands: Object.freeze([command]),
    workspace: null,
    sourceSetSha256,
    testOnly: false,
  });
}

function covenantOutputFrom(command, vectors) {
  const tap = parseTap(command.stdout, COVENANT_TEST_NAMES, 'covenant lane');
  return Object.freeze({
    schema: COVENANT_OUTPUT_SCHEMA,
    implementation: 'covenant',
    tests: tap.tests,
    testNames: tap.names,
    packetDigestReconstructed: true,
    topologies: Object.freeze(['pf11', 'pf10']),
    actionKinds: 3,
    standardModes: 2,
    digestHex: vectors.digestHex,
    limbs: vectors.limbs,
  });
}

function executeCovenant(tools, root, vectors, sourceSetSha256) {
  const command = commandRecord(
    covenantCommand(tools, root),
    'BCH covenant digest-reconstruction lane',
  );
  const output = covenantOutputFrom(command, vectors);
  validateCovenantOutput(output, vectors);
  return laneExecutionRecord({
    id: 'covenant',
    output,
    commands: Object.freeze([command]),
    workspace: null,
    sourceSetSha256,
    testOnly: false,
  });
}

function agreement(reference, implementations) {
  const typescript = implementations[0].output;
  const rust = implementations[1].output;
  const circuit = implementations[2].output;
  const covenant = implementations[3].output;
  return Object.freeze({
    implementations: IMPLEMENTATION_IDS,
    javascriptRole: 'reference-orchestrator-not-one-of-four',
    digestHex: reference.output.qualification.sha256BeU128.digestHex,
    limbs: reference.output.qualification.sha256BeU128.limbs,
    stateMutations: typescript.qualification.state.mutations,
    packetMutations: typescript.qualification.packet.mutations,
    publicInputVectors: typescript.qualification.publicInputVectors,
    typescriptRustStrictMutationParity:
      sameJson(
        (() => {
          const { surface, ...value } = typescript.qualification;
          void surface;
          return value;
        })(),
        (() => {
          const { surface, ...value } = rust.qualification;
          void surface;
          return value;
        })(),
      ),
    circuitDigestAndLimbsMatched:
      circuit.digestHex === reference.output.qualification.sha256BeU128.digestHex
      && sameJson(
        circuit.limbs,
        reference.output.qualification.sha256BeU128.limbs,
      ),
    covenantDigestReconstructionMatched:
      covenant.packetDigestReconstructed === true
      && covenant.digestHex
        === reference.output.qualification.sha256BeU128.digestHex
      && sameJson(
        covenant.limbs,
        reference.output.qualification.sha256BeU128.limbs,
      ),
  });
}

function validateAgreement(value, reference, implementations) {
  exact(
    value,
    [
      'circuitDigestAndLimbsMatched',
      'covenantDigestReconstructionMatched',
      'digestHex',
      'implementations',
      'javascriptRole',
      'limbs',
      'packetMutations',
      'publicInputVectors',
      'stateMutations',
      'typescriptRustStrictMutationParity',
    ],
    'four-implementation agreement',
  );
  const expected = agreement(reference, implementations);
  if (
    !sameJson(value, expected)
    || value.typescriptRustStrictMutationParity !== true
    || value.circuitDigestAndLimbsMatched !== true
    || value.covenantDigestReconstructionMatched !== true
  ) {
    fail('one or more Q-01 implementation lanes disagree');
  }
  return value;
}

function executeCycle(root, sourceSetSha256, tools) {
  const vectors = q01Vectors(root);
  const reference = executeReference(tools, root, sourceSetSha256);
  const implementations = Object.freeze([
    executeTypescript(tools, root, vectors, sourceSetSha256),
    executeRust(tools, root, sourceSetSha256),
    executeCircuit(tools, root, vectors, sourceSetSha256),
    executeCovenant(tools, root, vectors, sourceSetSha256),
  ]);
  const agreed = agreement(reference, implementations);
  validateAgreement(agreed, reference, implementations);
  return Object.freeze({ reference, implementations, agreement: agreed });
}

function validateDirectoryInventory(value, label) {
  exact(
    value,
    ['entries', 'inventorySha256', 'root', 'schema', 'totalFileBytes'],
    label,
  );
  if (
    value.schema !== DIRECTORY_INVENTORY_SCHEMA
    || typeof value.root !== 'string'
    || value.root.length === 0
    || !Number.isSafeInteger(value.entries)
    || value.entries < 1
    || !Number.isSafeInteger(value.totalFileBytes)
    || value.totalFileBytes < 1
    || !HASH.test(value.inventorySha256)
  ) {
    fail(`${label} is invalid`);
  }
}

function validateExecutableRecord(value, label) {
  exact(value, ['executable', 'executableSha256', 'version'], label);
  if (
    typeof value.executable !== 'string'
    || !isAbsolute(value.executable)
    || resolve(value.executable) !== value.executable
    || !HASH.test(value.executableSha256)
    || typeof value.version !== 'string'
    || value.version.length === 0
  ) {
    fail(`${label} is invalid`);
  }
}

function validateToolFile(value, label) {
  exact(value, ['bytes', 'path', 'sha256'], label);
  if (
    typeof value.path !== 'string'
    || !value.path.startsWith('node_modules/')
    || !Number.isSafeInteger(value.bytes)
    || value.bytes < 1
    || !HASH.test(value.sha256)
  ) {
    fail(`${label} is invalid`);
  }
}

function validateCommand(value, label) {
  exact(
    value,
    [
      'argv',
      'cwd',
      'environment',
      'executable',
      'exitStatus',
      'signal',
      'stderr',
      'stderrSha256',
      'stdout',
      'stdoutSha256',
    ],
    label,
  );
  if (
    typeof value.executable !== 'string'
    || !isAbsolute(value.executable)
    || resolve(value.executable) !== value.executable
    || !Array.isArray(value.argv)
    || value.argv.some((item) => typeof item !== 'string')
    || typeof value.cwd !== 'string'
    || !isAbsolute(value.cwd)
    || resolve(value.cwd) !== value.cwd
    || value.environment === null
    || Array.isArray(value.environment)
    || typeof value.environment !== 'object'
    || value.exitStatus !== 0
    || value.signal !== null
    || typeof value.stdout !== 'string'
    || typeof value.stderr !== 'string'
    || value.stdoutSha256 !== sha256(Buffer.from(value.stdout))
    || value.stderrSha256 !== sha256(Buffer.from(value.stderr))
  ) {
    fail(`${label} command, transcript, or transcript hash is invalid`);
  }
  return value;
}

function validateRustToolchain(value) {
  exact(
    value,
    [
      'cargo',
      'cargoHome',
      'cc',
      'channel',
      'dependencySources',
      'host',
      'ld',
      'metadataCommand',
      'rustc',
      'sysroot',
      'sysrootInventory',
    ],
    'Rust toolchain',
  );
  if (
    value.channel !== RUST_CHANNEL
    || typeof value.host !== 'string'
    || typeof value.sysroot !== 'string'
    || !isAbsolute(value.sysroot)
    || typeof value.cargoHome !== 'string'
    || !isAbsolute(value.cargoHome)
  ) {
    fail('Rust toolchain identity is invalid');
  }
  validateDirectoryInventory(
    value.sysrootInventory,
    'Rust sysroot inventory',
  );
  for (const [label, tool] of [
    ['Cargo', value.cargo],
    ['rustc', value.rustc],
    ['cc', value.cc],
    ['ld', value.ld],
  ]) {
    validateExecutableRecord(tool, `${label} toolchain executable`);
  }
  if (value.metadataCommand === null || value.dependencySources === null) {
    fail('public Q-01 Rust dependency closure is absent');
  }
  validateCommand(value.metadataCommand, 'Cargo metadata command');
  exact(
    value.dependencySources,
    ['inventorySha256', 'packages', 'schema'],
    'Cargo dependency source inventory',
  );
  if (
    value.dependencySources.schema !== CARGO_SOURCE_INVENTORY_SCHEMA
    || !Array.isArray(value.dependencySources.packages)
    || value.dependencySources.packages.length < 1
    || !HASH.test(value.dependencySources.inventorySha256)
    || value.dependencySources.inventorySha256
      !== sha256(
        Buffer.from(
          canonicalJson(value.dependencySources.packages),
          'utf8',
        ),
      )
  ) {
    fail('Cargo dependency source inventory is invalid');
  }
  for (const [index, entry] of value.dependencySources.packages.entries()) {
    exact(
      entry,
      ['inventory', 'name', 'source', 'version'],
      `Cargo dependency source ${index}`,
    );
    if (
      typeof entry.name !== 'string'
      || typeof entry.version !== 'string'
      || typeof entry.source !== 'string'
    ) {
      fail(`Cargo dependency source ${index} identity is invalid`);
    }
    validateDirectoryInventory(
      entry.inventory,
      `Cargo dependency source ${index} inventory`,
    );
  }
}

function validateRuntime(value) {
  exact(
    value,
    [
      'environmentPolicy',
      'git',
      'installedNodeModules',
      'node',
      'packageMetadata',
      'schema',
      'toolchains',
    ],
    'runtime',
  );
  if (
    value.schema !== RUNTIME_SCHEMA
    || !sameJson(value.environmentPolicy, ENVIRONMENT_POLICY)
  ) {
    fail('runtime environment policy is invalid');
  }
  exact(
    value.node,
    ['arch', 'executable', 'executableSha256', 'platform', 'version'],
    'Node runtime',
  );
  if (
    typeof value.node.executable !== 'string'
    || !isAbsolute(value.node.executable)
    || resolve(value.node.executable) !== value.node.executable
    || !HASH.test(value.node.executableSha256)
    || !/^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/u.test(
      value.node.version,
    )
    || typeof value.node.platform !== 'string'
    || typeof value.node.arch !== 'string'
  ) {
    fail('Node runtime identity is invalid');
  }
  validateExecutableRecord(value.git, 'Git runtime');
  exact(
    value.packageMetadata,
    [
      'declaredInstallCommand',
      'lockfilePath',
      'lockfileSha256',
      'lockfileVersion',
      'name',
      'packageJsonPath',
      'packageJsonSha256',
      'version',
    ],
    'package metadata',
  );
  if (
    value.packageMetadata.packageJsonPath !== 'package.json'
    || value.packageMetadata.lockfilePath !== LOCK_PATH
    || !HASH.test(value.packageMetadata.packageJsonSha256)
    || !HASH.test(value.packageMetadata.lockfileSha256)
    || !Number.isSafeInteger(value.packageMetadata.lockfileVersion)
    || value.packageMetadata.lockfileVersion < 1
    || typeof value.packageMetadata.name !== 'string'
    || typeof value.packageMetadata.version !== 'string'
    || !sameJson(
      value.packageMetadata.declaredInstallCommand,
      INSTALL_COMMAND,
    )
  ) {
    fail('package/lock binding is invalid');
  }
  validateDirectoryInventory(
    value.installedNodeModules,
    'installed Node dependency inventory',
  );
  exact(
    value.toolchains,
    ['circuit', 'covenant', 'rust', 'typescript'],
    'lane toolchains',
  );
  exact(
    value.toolchains.typescript,
    ['compiler', 'version'],
    'TypeScript toolchain',
  );
  validateToolFile(
    value.toolchains.typescript.compiler,
    'TypeScript compiler file',
  );
  if (typeof value.toolchains.typescript.version !== 'string') {
    fail('TypeScript version is invalid');
  }
  exact(
    value.toolchains.circuit,
    ['circomVersion', 'circomlibVersion', 'compiler'],
    'circuit toolchain',
  );
  validateToolFile(
    value.toolchains.circuit.compiler,
    'Circom compiler file',
  );
  if (
    typeof value.toolchains.circuit.circomVersion !== 'string'
    || typeof value.toolchains.circuit.circomlibVersion !== 'string'
  ) {
    fail('Circom toolchain version is invalid');
  }
  exact(
    value.toolchains.covenant,
    ['libauthVersion'],
    'covenant toolchain',
  );
  if (typeof value.toolchains.covenant.libauthVersion !== 'string') {
    fail('Libauth toolchain version is invalid');
  }
  validateRustToolchain(value.toolchains.rust);
  return value;
}

function validateSourceEntries(entries, label) {
  if (!Array.isArray(entries) || entries.length < 1) {
    fail(`${label} must be a nonempty array`);
  }
  let previous = null;
  for (const [index, entry] of entries.entries()) {
    exact(
      entry,
      ['blob', 'bytes', 'mode', 'path', 'sha256'],
      `${label}[${index}]`,
    );
    if (
      typeof entry.path !== 'string'
      || entry.path.includes('\\')
      || entry.path.split('/').some(
        (part) => part === '' || part === '.' || part === '..',
      )
      || (previous !== null && compareSourcePaths(previous, entry.path) >= 0)
      || !MODE.test(entry.mode)
      || !GIT.test(entry.blob)
      || !Number.isSafeInteger(entry.bytes)
      || entry.bytes < 0
      || !HASH.test(entry.sha256)
    ) {
      fail(`${label}[${index}] is invalid or unsorted`);
    }
    previous = entry.path;
  }
}

function validateSourceRecord(value) {
  exact(
    value,
    [
      'files',
      'gitCommit',
      'gitTree',
      'locks',
      'runtime',
      'schema',
      'sourceRoot',
      'sourceSetSha256',
    ],
    'source set',
  );
  if (
    value.schema !== SOURCE_SET_SCHEMA
    || typeof value.sourceRoot !== 'string'
    || !isAbsolute(value.sourceRoot)
    || resolve(value.sourceRoot) !== value.sourceRoot
    || !GIT.test(value.gitCommit)
    || !GIT.test(value.gitTree)
  ) {
    fail('source set identity is invalid');
  }
  validateSourceEntries(value.files, 'source files');
  validateSourceEntries(value.locks, 'source locks');
  const all = [...value.files, ...value.locks];
  const paths = new Set(all.map((entry) => entry.path));
  if (
    paths.size !== all.length
    || !paths.has(LOCK_PATH)
    || !paths.has(RUST_LOCK_PATH)
    || !paths.has(RUST_TOOLCHAIN_PATH)
    || !paths.has(VECTOR_PATH)
    || !paths.has(STATE_VECTOR_PATH)
    || !paths.has(RUST_TEST_PATH)
    || !paths.has(CIRCUIT_TEST_PATH)
    || !paths.has(COVENANT_TEST_PATH)
  ) {
    fail('source set omits a required source, vector, lock, or toolchain pin');
  }
  validateRuntime(value.runtime);
  if (
    !HASH.test(value.sourceSetSha256)
    || value.sourceSetSha256
      !== sha256(
        Buffer.from(
          canonicalJson({
            files: value.files,
            locks: value.locks,
            runtime: value.runtime,
          }),
          'utf8',
        ),
      )
  ) {
    fail('source-set digest is invalid');
  }
  return value;
}

function recheckSource(source) {
  if (
    runGit(
      source.sourceRoot,
      ['status', '--porcelain=v1', '--untracked-files=all'],
    ) !== ''
    || runGit(source.sourceRoot, ['rev-parse', 'HEAD']).trim()
      !== source.gitCommit
    || runGit(source.sourceRoot, ['rev-parse', 'HEAD^{tree}']).trim()
      !== source.gitTree
  ) {
    fail('source checkout changed during Q-01 evidence generation or verification');
  }
  const current = sourceSet(source.sourceRoot);
  if (!sameJson(current, source)) {
    fail('bound Q-01 source, lock, dependency, executable, or toolchain drifted');
  }
}

function toolsFromRuntime(runtimeValue) {
  return Object.freeze({
    node: runtimeValue.node,
    typescript: runtimeValue.toolchains.typescript,
    rust: runtimeValue.toolchains.rust,
    circuit: runtimeValue.toolchains.circuit,
    covenant: runtimeValue.toolchains.covenant,
  });
}

function validateCommandShape(record, expected, label) {
  validateCommand(record, label);
  if (
    !sameJson(
      {
        executable: record.executable,
        argv: record.argv,
        cwd: record.cwd,
        environment: record.environment,
      },
      expected,
    )
  ) {
    fail(`${label} executable, argv, cwd, or environment differs`);
  }
}

function validateLaneExecution(
  value,
  expectedId,
  expectedOutput,
  source,
  vectors,
  { testOnly },
) {
  exact(
    value,
    [
      'commands',
      'executed',
      'id',
      'output',
      'outputSha256',
      'role',
      'sourceSetSha256',
      'workspace',
    ],
    `${expectedId} execution`,
  );
  if (
    value.id !== expectedId
    || value.role !== (
      expectedId === REFERENCE_ID
        ? 'reference-orchestrator-not-one-of-four'
        : 'implementation'
    )
    || value.sourceSetSha256 !== source.sourceSetSha256
    || !sameJson(value.output, expectedOutput)
    || value.outputSha256 !== outputSha256(value.output)
  ) {
    fail(`${expectedId} execution/output binding differs`);
  }
  if (testOnly) {
    if (
      value.executed !== false
      || value.workspace !== null
      || !Array.isArray(value.commands)
      || value.commands.length !== 0
    ) {
      fail('test-only lane must not fabricate an execution transcript');
    }
    return value;
  }
  if (value.executed !== true || !Array.isArray(value.commands)) {
    fail(`${expectedId} execution is absent or skipped`);
  }
  const tools = toolsFromRuntime(source.runtime);
  if (expectedId === REFERENCE_ID) {
    if (value.workspace !== null || value.commands.length !== 1) {
      fail('JavaScript reference command count differs');
    }
    validateCommandShape(
      value.commands[0],
      referenceCommand(tools, source.sourceRoot),
      'JavaScript reference command',
    );
    const output = parseCanonical(
      Buffer.from(value.commands[0].stdout),
      'JavaScript reference transcript',
    );
    validateReferenceOutput(output);
    if (!sameJson(output, value.output)) {
      fail('JavaScript reference transcript output differs');
    }
  } else if (expectedId === 'typescript') {
    if (
      typeof value.workspace !== 'string'
      || !isAbsolute(value.workspace)
      || resolve(value.workspace) !== value.workspace
      || value.commands.length !== 2
    ) {
      fail('TypeScript workspace or command count differs');
    }
    const expected = typescriptCommands(
      tools,
      source.sourceRoot,
      value.workspace,
    );
    validateCommandShape(
      value.commands[0],
      expected[0],
      'TypeScript compile command',
    );
    validateCommandShape(
      value.commands[1],
      expected[1],
      'TypeScript runner command',
    );
    const output = parseCanonical(
      Buffer.from(value.commands[1].stdout),
      'TypeScript transcript',
    );
    validateTypescriptOutput(output, vectors);
    if (!sameJson(output, value.output)) {
      fail('TypeScript transcript output differs');
    }
  } else if (expectedId === 'rust') {
    if (
      typeof value.workspace !== 'string'
      || !isAbsolute(value.workspace)
      || resolve(value.workspace) !== value.workspace
      || value.commands.length !== 1
    ) {
      fail('Rust workspace or command count differs');
    }
    validateCommandShape(
      value.commands[0],
      rustCommand(tools, source.sourceRoot, value.workspace),
      'Rust command',
    );
    const output = parseRustCommandOutput(value.commands[0]);
    validateRustOutput(output);
    if (!sameJson(output, value.output)) fail('Rust transcript output differs');
  } else if (expectedId === 'circuit') {
    if (value.workspace !== null || value.commands.length !== 1) {
      fail('circuit command count differs');
    }
    validateCommandShape(
      value.commands[0],
      circuitCommand(tools, source.sourceRoot),
      'circuit command',
    );
    const output = circuitOutputFrom(value.commands[0], vectors);
    validateCircuitOutput(output, vectors);
    if (!sameJson(output, value.output)) {
      fail('circuit transcript output differs');
    }
  } else if (expectedId === 'covenant') {
    if (value.workspace !== null || value.commands.length !== 1) {
      fail('covenant command count differs');
    }
    validateCommandShape(
      value.commands[0],
      covenantCommand(tools, source.sourceRoot),
      'covenant command',
    );
    const output = covenantOutputFrom(value.commands[0], vectors);
    validateCovenantOutput(output, vectors);
    if (!sameJson(output, value.output)) {
      fail('covenant transcript output differs');
    }
  } else {
    fail(`unknown Q-01 execution lane: ${expectedId}`);
  }
  return value;
}

function qualificationRecord(source, cycle, testOnly) {
  return Object.freeze({
    schema: QUALIFICATION_SCHEMA,
    sourceSetSha256: source.sourceSetSha256,
    localOnly: true,
    preCeremony: true,
    chainAuthenticated: false,
    signed: false,
    finalArtifacts: false,
    finalQualification: false,
    testOnly,
    qualification: testOnly ? TEST_QUALIFICATION : QUALIFICATION,
    reference: Object.freeze({
      id: cycle.reference.id,
      role: cycle.reference.role,
      output: cycle.reference.output,
      outputSha256: cycle.reference.outputSha256,
    }),
    implementations: Object.freeze(
      cycle.implementations.map((entry) => Object.freeze({
        id: entry.id,
        role: entry.role,
        output: entry.output,
        outputSha256: entry.outputSha256,
      })),
    ),
    agreement: cycle.agreement,
  });
}

function executionRecord(source, cycle, testOnly) {
  return Object.freeze({
    schema: EXECUTION_SCHEMA,
    sourceSetSha256: source.sourceSetSha256,
    runtime: source.runtime,
    reference: cycle.reference,
    implementations: cycle.implementations,
    testOnly,
    boundaries: BOUNDARIES,
  });
}

function validateQualification(value, source) {
  exact(
    value,
    [
      'agreement',
      'chainAuthenticated',
      'finalArtifacts',
      'finalQualification',
      'implementations',
      'localOnly',
      'preCeremony',
      'qualification',
      'reference',
      'schema',
      'signed',
      'sourceSetSha256',
      'testOnly',
    ],
    'qualification evidence',
  );
  if (
    value.schema !== QUALIFICATION_SCHEMA
    || value.sourceSetSha256 !== source.sourceSetSha256
    || value.localOnly !== true
    || value.preCeremony !== true
    || value.chainAuthenticated !== false
    || value.signed !== false
    || value.finalArtifacts !== false
    || value.finalQualification !== false
    || typeof value.testOnly !== 'boolean'
    || value.qualification !== (
      value.testOnly ? TEST_QUALIFICATION : QUALIFICATION
    )
  ) {
    fail('qualification claim boundary is invalid');
  }
  exact(
    value.reference,
    ['id', 'output', 'outputSha256', 'role'],
    'qualification reference',
  );
  if (
    value.reference.id !== REFERENCE_ID
    || value.reference.role !== 'reference-orchestrator-not-one-of-four'
    || value.reference.outputSha256 !== outputSha256(value.reference.output)
  ) {
    fail('JavaScript reference is absent or counted as an implementation');
  }
  validateReferenceOutput(value.reference.output);
  if (
    !Array.isArray(value.implementations)
    || value.implementations.length !== IMPLEMENTATION_IDS.length
  ) {
    fail('qualification must contain exactly four implementation lanes');
  }
  const vectors = q01VectorsForValidation(value);
  for (const [index, id] of IMPLEMENTATION_IDS.entries()) {
    const entry = value.implementations[index];
    exact(
      entry,
      ['id', 'output', 'outputSha256', 'role'],
      `qualification implementation ${index}`,
    );
    if (
      entry.id !== id
      || entry.role !== 'implementation'
      || entry.outputSha256 !== outputSha256(entry.output)
    ) {
      fail(`qualification implementation lane ${id} is absent or malformed`);
    }
    if (id === 'typescript') validateTypescriptOutput(entry.output, vectors);
    else if (id === 'rust') validateRustOutput(entry.output);
    else if (id === 'circuit') validateCircuitOutput(entry.output, vectors);
    else validateCovenantOutput(entry.output, vectors);
  }
  const reference = Object.freeze({
    id: value.reference.id,
    role: value.reference.role,
    output: value.reference.output,
    outputSha256: value.reference.outputSha256,
  });
  const implementations = value.implementations.map((entry) => Object.freeze({
    id: entry.id,
    role: entry.role,
    output: entry.output,
    outputSha256: entry.outputSha256,
  }));
  validateAgreement(value.agreement, reference, implementations);
  return value;
}

function q01VectorsForValidation(qualification) {
  const circuit = qualification.implementations?.find(
    (entry) => entry.id === 'circuit',
  )?.output;
  if (
    circuit === undefined
    || typeof circuit.stateBoundaryVectors !== 'number'
    || typeof circuit.packetBytes !== 'number'
  ) {
    fail('qualification lacks circuit vector dimensions');
  }
  return Object.freeze({
    digestHex: EXPECTED_QUALIFICATION_COMMON.sha256BeU128.digestHex,
    limbs: EXPECTED_QUALIFICATION_COMMON.sha256BeU128.limbs,
    packetBytes: 552,
    stateBoundaryVectors: 26,
  });
}

function validateExecution(value, source, qualification) {
  exact(
    value,
    [
      'boundaries',
      'implementations',
      'reference',
      'runtime',
      'schema',
      'sourceSetSha256',
      'testOnly',
    ],
    'execution evidence',
  );
  if (
    value.schema !== EXECUTION_SCHEMA
    || value.sourceSetSha256 !== source.sourceSetSha256
    || value.testOnly !== qualification.testOnly
    || !sameJson(value.boundaries, BOUNDARIES)
    || !sameJson(value.runtime, source.runtime)
    || !Array.isArray(value.implementations)
    || value.implementations.length !== 4
  ) {
    fail('execution evidence boundary or four-lane set is invalid');
  }
  const vectors = q01VectorsForValidation(qualification);
  validateLaneExecution(
    value.reference,
    REFERENCE_ID,
    qualification.reference.output,
    source,
    vectors,
    { testOnly: value.testOnly },
  );
  for (const [index, id] of IMPLEMENTATION_IDS.entries()) {
    validateLaneExecution(
      value.implementations[index],
      id,
      qualification.implementations[index].output,
      source,
      vectors,
      { testOnly: value.testOnly },
    );
  }
  return value;
}

function artifactReference(root, entry, label) {
  exact(entry, ['bytes', 'path', 'role', 'sha256'], label);
  if (
    typeof entry.role !== 'string'
    || typeof entry.path !== 'string'
    || basename(entry.path) !== entry.path
    || !Number.isSafeInteger(entry.bytes)
    || entry.bytes < 0
    || !HASH.test(entry.sha256)
  ) {
    fail(`${label} is invalid`);
  }
  const path = child(root, entry.path, label);
  const stat = ownedFile(path, label);
  const bytes = readFileSync(path);
  if (
    stat.size !== entry.bytes
    || bytes.length !== entry.bytes
    || sha256(bytes) !== entry.sha256
  ) {
    fail(`${label} hash differs`);
  }
  return Object.freeze({
    ...entry,
    absolutePath: path,
    value: parseCanonical(bytes, label),
  });
}

function verifyBundle(
  bundlePath,
  {
    verifySource = true,
    allowTestOnly = false,
    rerunQualification = true,
  } = {},
) {
  const root = resolve(bundlePath);
  directDirectory(root, 'bundle root');
  const manifestPath = child(root, 'manifest.json', 'manifest');
  ownedFile(manifestPath, 'manifest');
  const manifest = parseCanonical(readFileSync(manifestPath), 'manifest');
  exact(
    manifest,
    [
      'artifacts',
      'chainAuthenticated',
      'finalArtifacts',
      'finalQualification',
      'localOnly',
      'preCeremony',
      'schema',
      'signed',
    ],
    'manifest',
  );
  if (
    manifest.schema !== V2_Q01_COMMIT_BOUND_MANIFEST_SCHEMA
    || manifest.localOnly !== true
    || manifest.preCeremony !== true
    || manifest.chainAuthenticated !== false
    || manifest.signed !== false
    || manifest.finalArtifacts !== false
    || manifest.finalQualification !== false
    || !Array.isArray(manifest.artifacts)
    || manifest.artifacts.length !== 3
  ) {
    fail('manifest qualification boundary is invalid');
  }
  const names = new Set(['manifest.json']);
  const refs = new Map();
  for (const entry of manifest.artifacts) {
    if (refs.has(entry.role) || names.has(entry.path)) {
      fail('manifest has ambiguous artifact references');
    }
    refs.set(
      entry.role,
      artifactReference(root, entry, `artifact ${entry.role}`),
    );
    names.add(entry.path);
  }
  if (
    refs.size !== 3
    || !refs.has('source-set')
    || !refs.has('qualification')
    || !refs.has('execution')
    || !sameJson(readdirSync(root).sort(), [...names].sort())
  ) {
    fail('bundle has missing or unreferenced artifacts');
  }
  const source = validateSourceRecord(refs.get('source-set').value);
  const qualification = validateQualification(
    refs.get('qualification').value,
    source,
  );
  if (qualification.testOnly && !allowTestOnly) {
    fail('test-only Q-01 evidence is nonqualifying and rejected publicly');
  }
  if (
    verifySource
    && !qualification.testOnly
    && source.sourceRoot !== moduleRoot
  ) {
    fail('public verifier only accepts this exact module source root');
  }
  const execution = validateExecution(
    refs.get('execution').value,
    source,
    qualification,
  );
  if (verifySource && !qualification.testOnly) {
    recheckSource(source);
    if (rerunQualification) {
      const rerun = executeCycle(
        source.sourceRoot,
        source.sourceSetSha256,
        toolsFromRuntime(source.runtime),
      );
      if (
        !sameJson(rerun.reference.output, qualification.reference.output)
        || !sameJson(
          rerun.implementations.map((entry) => entry.output),
          qualification.implementations.map((entry) => entry.output),
        )
        || !sameJson(rerun.agreement, qualification.agreement)
      ) {
        fail('public Q-01 replay disagrees with sealed four-lane evidence');
      }
      recheckSource(source);
    }
  }
  return Object.freeze({
    schema: `${V2_Q01_COMMIT_BOUND_MANIFEST_SCHEMA}/verification`,
    bundlePath: root,
    status: qualification.testOnly
      ? 'verified-test-only-local-nonqualifying'
      : 'verified-local-pre-ceremony-four-implementation-conformance',
    sourceSetSha256: source.sourceSetSha256,
    gitCommit: source.gitCommit,
    gitTree: source.gitTree,
    reference: REFERENCE_ID,
    implementations: IMPLEMENTATION_IDS,
    localOnly: true,
    preCeremony: true,
    chainAuthenticated: false,
    signed: false,
    finalArtifacts: false,
    finalQualification: false,
    qualification: qualification.qualification,
    boundaries: BOUNDARIES,
    executed: execution.implementations.every((entry) => entry.executed),
  });
}

function createBundle({
  outputDirectory,
  source,
  cycle,
  testOnly,
}) {
  const parent = resolve(outputDirectory);
  directDirectory(parent, 'output directory');
  const root = join(parent, `q01-pre-commit-bound-${Date.now()}-${process.pid}`);
  if (existsSync(root)) fail('refusing to overwrite Q-01 bundle');
  directDirectory(root, 'bundle root', true);
  try {
    const checkedSource = validateSourceRecord(source);
    const qualification = qualificationRecord(checkedSource, cycle, testOnly);
    validateQualification(qualification, checkedSource);
    const execution = executionRecord(checkedSource, cycle, testOnly);
    validateExecution(execution, checkedSource, qualification);
    const sourceArtifact = writeAtomic(root, 'source-set.json', checkedSource);
    const qualificationArtifact = writeAtomic(
      root,
      'qualification.json',
      qualification,
    );
    const executionArtifact = writeAtomic(root, 'execution.json', execution);
    const manifest = Object.freeze({
      schema: V2_Q01_COMMIT_BOUND_MANIFEST_SCHEMA,
      localOnly: true,
      preCeremony: true,
      chainAuthenticated: false,
      signed: false,
      finalArtifacts: false,
      finalQualification: false,
      artifacts: Object.freeze([
        Object.freeze({ role: 'source-set', ...sourceArtifact }),
        Object.freeze({ role: 'qualification', ...qualificationArtifact }),
        Object.freeze({ role: 'execution', ...executionArtifact }),
      ]),
    });
    writeAtomic(root, 'manifest.json', manifest);
    fsyncDirectory(root);
    fsyncDirectory(parent);
    return verifyBundle(root, {
      verifySource: !testOnly,
      allowTestOnly: testOnly,
      rerunQualification: !testOnly,
    });
  } catch (error) {
    try {
      rmSync(root, { recursive: true, force: true });
    } catch {
      // Preserve the original error.
    }
    throw error;
  }
}

function fixtureInventory(label) {
  return Object.freeze({
    schema: DIRECTORY_INVENTORY_SCHEMA,
    root: label,
    entries: 1,
    totalFileBytes: 1,
    inventorySha256: '9'.repeat(64),
  });
}

function fixtureExecutable(version) {
  return Object.freeze({
    executable: process.execPath,
    executableSha256: sha256(readFileSync(process.execPath)),
    version,
  });
}

function fixtureRuntime() {
  const metadataStdout = '{}';
  const metadataStderr = '';
  const rust = Object.freeze({
    channel: RUST_CHANNEL,
    host: 'x86_64-unknown-linux-gnu',
    sysroot: '/test/rust',
    sysrootInventory: fixtureInventory(
      `rust-sysroot-${RUST_CHANNEL}-x86_64-unknown-linux-gnu`,
    ),
    cargoHome: '/test/cargo',
    cargo: fixtureExecutable('cargo 1.97.1 (fixture 2026-01-01)'),
    rustc: fixtureExecutable('rustc 1.97.1 (fixture 2026-01-01)'),
    cc: fixtureExecutable('cc fixture'),
    ld: fixtureExecutable('GNU ld fixture'),
    metadataCommand: Object.freeze({
      executable: process.execPath,
      argv: Object.freeze(['fixture-metadata']),
      cwd: '/test/q01-source',
      environment: Object.freeze({
        ...ENVIRONMENT_POLICY.rustFixed,
        CARGO_HOME: '/test/cargo',
        RUSTC: process.execPath,
      }),
      exitStatus: 0,
      signal: null,
      stdout: metadataStdout,
      stderr: metadataStderr,
      stdoutSha256: sha256(Buffer.from(metadataStdout)),
      stderrSha256: sha256(Buffer.from(metadataStderr)),
    }),
    dependencySources: Object.freeze({
      schema: CARGO_SOURCE_INVENTORY_SCHEMA,
      packages: Object.freeze([
        Object.freeze({
          name: 'fixture',
          version: '1.0.0',
          source: 'registry+fixture',
          inventory: fixtureInventory('fixture@1.0.0'),
        }),
      ]),
      inventorySha256: sha256(Buffer.from(canonicalJson([
        Object.freeze({
          name: 'fixture',
          version: '1.0.0',
          source: 'registry+fixture',
          inventory: fixtureInventory('fixture@1.0.0'),
        }),
      ]), 'utf8')),
    }),
  });
  return Object.freeze({
    schema: RUNTIME_SCHEMA,
    node: Object.freeze({
      executable: process.execPath,
      executableSha256: sha256(readFileSync(process.execPath)),
      version: process.version,
      platform: process.platform,
      arch: process.arch,
    }),
    git: fixtureExecutable('git version 2.0.0'),
    environmentPolicy: ENVIRONMENT_POLICY,
    packageMetadata: Object.freeze({
      packageJsonPath: 'package.json',
      packageJsonSha256: '1'.repeat(64),
      lockfilePath: LOCK_PATH,
      lockfileSha256: '2'.repeat(64),
      lockfileVersion: 3,
      name: 'shieldkit-test',
      version: '0.0.0',
      declaredInstallCommand: INSTALL_COMMAND,
    }),
    installedNodeModules: fixtureInventory('node_modules'),
    toolchains: Object.freeze({
      typescript: Object.freeze({
        compiler: Object.freeze({
          path: TYPESCRIPT_TSC_PATH,
          bytes: 1,
          sha256: '3'.repeat(64),
        }),
        version: '5.9.3',
      }),
      rust,
      circuit: Object.freeze({
        compiler: Object.freeze({
          path: CIRCOM_CLI_PATH,
          bytes: 1,
          sha256: '4'.repeat(64),
        }),
        circomVersion: '0.2.23',
        circomlibVersion: '2.0.5',
      }),
      covenant: Object.freeze({ libauthVersion: '3.1.0-next.8' }),
    }),
  });
}

function fixtureEntry(path, lock = false) {
  return Object.freeze({
    path,
    mode: '100644',
    blob: (lock ? 'b' : 'a').repeat(40),
    bytes: 1,
    sha256: (lock ? '6' : '5').repeat(64),
  });
}

function fixtureSource() {
  const runtime = fixtureRuntime();
  const requiredFiles = [
    COVENANT_TEST_PATH,
    CIRCUIT_TEST_PATH,
    RUST_TEST_PATH,
    STATE_VECTOR_PATH,
    VECTOR_PATH,
  ].sort(compareSourcePaths);
  const requiredLocks = [
    RUST_LOCK_PATH,
    RUST_TOOLCHAIN_PATH,
    LOCK_PATH,
  ].sort(compareSourcePaths);
  const files = Object.freeze(requiredFiles.map((path) => fixtureEntry(path)));
  const locks = Object.freeze(
    requiredLocks.map((path) => fixtureEntry(path, true)),
  );
  return Object.freeze({
    schema: SOURCE_SET_SCHEMA,
    sourceRoot: '/test/q01-source',
    gitCommit: '7'.repeat(40),
    gitTree: '8'.repeat(40),
    runtime,
    files,
    locks,
    sourceSetSha256: sha256(
      Buffer.from(canonicalJson({ files, locks, runtime }), 'utf8'),
    ),
  });
}

function fixtureTypescriptOutput(vectors) {
  const offsetMutationEvidence = Object.freeze({
    state: Object.freeze({
      all: Object.freeze({ accepted: 128, rejected: 0 }),
    }),
    packet: Object.freeze({
      all: Object.freeze({ accepted: 552, rejected: 0 }),
    }),
  });
  return Object.freeze({
    schema: TYPESCRIPT_OUTPUT_SCHEMA,
    implementation: 'typescript',
    baselineJavaScriptParity: true,
    boundaryVectors: vectors.stateBoundaryVectors,
    offsetMutationEvidence,
    selfTestLogs: Object.freeze([
      'V2 strict TypeScript codec tests: passed',
      `V2_OFFSET_MUTATION_EVIDENCE=${JSON.stringify(offsetMutationEvidence)}`,
    ]),
    qualification: Object.freeze({
      ...EXPECTED_QUALIFICATION_COMMON,
      surface: 'typescript',
    }),
  });
}

function fixtureCycle(source) {
  const vectors = Object.freeze({
    digestHex: EXPECTED_QUALIFICATION_COMMON.sha256BeU128.digestHex,
    limbs: EXPECTED_QUALIFICATION_COMMON.sha256BeU128.limbs,
    packetBytes: 552,
    stateBoundaryVectors: 26,
  });
  const referenceOutput = Object.freeze({
    schema: REFERENCE_OUTPUT_SCHEMA,
    implementation: 'javascript',
    role: 'reference-orchestrator-not-one-of-four',
    qualification: Object.freeze({
      ...EXPECTED_QUALIFICATION_COMMON,
      surface: 'javascript',
    }),
  });
  const outputs = Object.freeze([
    fixtureTypescriptOutput(vectors),
    Object.freeze({
      schema: RUST_OUTPUT_SCHEMA,
      implementation: 'rust',
      tests: 10,
      qualification: Object.freeze({
        ...EXPECTED_QUALIFICATION_COMMON,
        surface: 'rust',
      }),
    }),
    Object.freeze({
      schema: CIRCUIT_OUTPUT_SCHEMA,
      implementation: 'circuit',
      tests: 1,
      testNames: CIRCUIT_TEST_NAMES,
      stateBoundaryVectors: 26,
      packetBytes: 552,
      mutationRejections: 2,
      digestHex: vectors.digestHex,
      limbs: vectors.limbs,
    }),
    Object.freeze({
      schema: COVENANT_OUTPUT_SCHEMA,
      implementation: 'covenant',
      tests: 6,
      testNames: COVENANT_TEST_NAMES,
      packetDigestReconstructed: true,
      topologies: Object.freeze(['pf11', 'pf10']),
      actionKinds: 3,
      standardModes: 2,
      digestHex: vectors.digestHex,
      limbs: vectors.limbs,
    }),
  ]);
  const reference = laneExecutionRecord({
    id: REFERENCE_ID,
    output: referenceOutput,
    commands: Object.freeze([]),
    workspace: null,
    sourceSetSha256: source.sourceSetSha256,
    testOnly: true,
  });
  const implementations = Object.freeze(
    IMPLEMENTATION_IDS.map((id, index) => laneExecutionRecord({
      id,
      output: outputs[index],
      commands: Object.freeze([]),
      workspace: null,
      sourceSetSha256: source.sourceSetSha256,
      testOnly: true,
    })),
  );
  return Object.freeze({
    reference,
    implementations,
    agreement: agreement(reference, implementations),
  });
}

export function q01TestFixtures() {
  const source = fixtureSource();
  return Object.freeze({ source, cycle: fixtureCycle(source) });
}

export async function runV2Q01CommitBoundEvidence(options = {}) {
  if (
    options === null
    || Array.isArray(options)
    || typeof options !== 'object'
    || Object.keys(options).some((key) => key !== 'outputDirectory')
  ) {
    fail(
      'public Q-01 generator accepts only outputDirectory and rejects injected source, runtime, toolchain, transcript, or lane seams',
    );
  }
  const parent = resolve(options.outputDirectory);
  directDirectory(parent, 'output directory');
  if (parent === moduleRoot || parent.startsWith(`${moduleRoot}/`)) {
    fail('public Q-01 output directory must be outside the bound source checkout');
  }
  const source = sourceSet(moduleRoot);
  const cycle = executeCycle(
    moduleRoot,
    source.sourceSetSha256,
    toolsFromRuntime(source.runtime),
  );
  recheckSource(source);
  return createBundle({
    outputDirectory: parent,
    source,
    cycle,
    testOnly: false,
  });
}

/** TEST-ONLY: fixture records are visibly nonqualifying and never replayed publicly. */
export async function runV2Q01CommitBoundEvidenceForTest({
  outputDirectory,
  source,
  cycle,
} = {}) {
  return createBundle({
    outputDirectory,
    source: validateSourceRecord(source),
    cycle,
    testOnly: true,
  });
}

/** TEST-ONLY: executes every real lane once without creating public evidence. */
export function runV2Q01FourImplementationCycleForTest() {
  const tools = discoverLaneTools(moduleRoot, { includeDependencies: false });
  const cycle = executeCycle(moduleRoot, '0'.repeat(64), tools);
  return Object.freeze({
    reference: cycle.reference,
    implementations: cycle.implementations,
    agreement: cycle.agreement,
  });
}

/** TEST-ONLY: exercises the full dependency/toolchain content binding. */
export function probeV2Q01RuntimeBindingForTest() {
  const runtime = runtimeRecord(moduleRoot);
  validateRuntime(runtime);
  return Object.freeze({
    nodeInventoryEntries: runtime.installedNodeModules.entries,
    nodeInventorySha256: runtime.installedNodeModules.inventorySha256,
    cargoDependencyPackages:
      runtime.toolchains.rust.dependencySources.packages.length,
    cargoDependencyInventorySha256:
      runtime.toolchains.rust.dependencySources.inventorySha256,
    node: runtime.node,
    git: runtime.git,
    toolchains: runtime.toolchains,
    environmentPolicy: runtime.environmentPolicy,
  });
}

/** TEST-ONLY: snapshots the same complete tracked-source contract used publicly. */
export function snapshotV2Q01TrackedSourcesForTest(root = moduleRoot) {
  return trackedEntries(resolve(root));
}

/** TEST-ONLY: validates the actual serialized source-inventory ordering. */
export function assertV2Q01TrackedSourceInventoryForTest(root = moduleRoot) {
  const inventory = trackedEntries(resolve(root));
  validateSourceEntries(inventory.files, 'source files');
  validateSourceEntries(inventory.locks, 'source locks');
  return inventory;
}

/** TEST-ONLY: exercises the exact clean committed checkout gate used publicly. */
export function assertV2Q01CleanCommittedCheckoutForTest(root) {
  return cleanCommitIdentity(resolve(root));
}

/** TEST-ONLY: detects live source drift without requiring a public bundle. */
export function assertV2Q01TrackedSourcesUnchangedForTest(root, expected) {
  const current = trackedEntries(resolve(root));
  if (!sameJson(current, expected)) {
    fail('bound Q-01 tracked source drifted');
  }
  return true;
}

/** TEST-ONLY: exercises absolute trusted Git and sanitized Node primitives. */
export function probeV2Q01SanitizedChildrenForTest() {
  const nodeExecutable = directExecutable(process.execPath, 'Node executable');
  const probe = [
    'const controls=Object.keys(process.env).filter((key)=>',
    "/^(?:GIT_|NODE_|npm_config_|RUST|CARGO)/u.test(key)&&process.env[key]!=='' ).sort();",
    'process.stdout.write(JSON.stringify({controls,environment:process.env}));',
  ].join('');
  const result = spawnSync(
    nodeExecutable,
    ['--input-type=module', '--eval', probe],
    {
      cwd: moduleRoot,
      env: NODE_ENVIRONMENT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  if (result.error || result.status !== 0 || result.signal) {
    fail(
      `sanitized Node probe failed: ${
        (result.stderr || result.error?.message || '').trim()
      }`,
    );
  }
  const node = parseStrictJson(Buffer.from(result.stdout));
  if (!sameJson(node, { controls: [], environment: NODE_ENVIRONMENT })) {
    fail('sanitized Node probe inherited an ambient control');
  }
  return Object.freeze({
    git: gitToolRecord(),
    node,
    environmentPolicy: ENVIRONMENT_POLICY,
  });
}

export function verifyV2Q01CommitBoundBundle(bundlePath) {
  return verifyBundle(bundlePath);
}

/** TEST-ONLY: validates the visibly nonqualifying fixture boundary. */
export function verifyV2Q01CommitBoundBundleForTest(bundlePath) {
  return verifyBundle(bundlePath, {
    verifySource: false,
    allowTestOnly: true,
    rerunQualification: false,
  });
}

export function parseV2Q01CommitBoundArguments(argv, cwd = process.cwd()) {
  if (
    !Array.isArray(argv)
    || argv.length !== 2
    || !['--output-directory', '--verify'].includes(argv[0])
    || typeof argv[1] !== 'string'
    || argv[1].startsWith('--')
  ) {
    fail(
      'usage: v2-q01-commit-bound-evidence.mjs --output-directory <existing-mode-0700-directory> | --verify <bundle>',
    );
  }
  return Object.freeze(
    argv[0] === '--verify'
      ? { mode: 'verify', bundlePath: resolve(cwd, argv[1]) }
      : { mode: 'run', outputDirectory: resolve(cwd, argv[1]) },
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const args = parseV2Q01CommitBoundArguments(process.argv.slice(2));
    const result = args.mode === 'verify'
      ? verifyV2Q01CommitBoundBundle(args.bundlePath)
      : await runV2Q01CommitBoundEvidence({
        outputDirectory: args.outputDirectory,
      });
    process.stdout.write(`${canonicalJson(result)}\n`);
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.stack : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}
