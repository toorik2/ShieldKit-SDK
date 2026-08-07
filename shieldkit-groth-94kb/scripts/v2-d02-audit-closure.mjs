#!/usr/bin/env node
/*
 * D-02 verifies independently produced final audit material.  The signed
 * final manifest authorizes only the audit policy: reports and evidence are
 * deliberately post-final inputs, so they cannot create a D01 -> Q* -> D02
 * manifest cycle.
 */
import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey, verify } from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readdirSync, readFileSync, realpathSync, renameSync, writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import { resolveV2FinalReleaseRoot, verifyV2FinalReleaseProfileCore } from '../packages/profile/v2/release-bootstrap.mjs';
import { deriveV2ManifestArtifactFromValidatedDescriptor, deriveV2Pf10RuntimeFromValidatedDescriptor, loadV2InstanceDescriptor } from '../packages/profile/v2/instance-descriptor.mjs';

const ROLES = Object.freeze(['protocol', 'circuit', 'covenants', 'wallet']);
const CLASSIFICATIONS = new Set(['reproducible-final', 'raw-vm-lane', 'raw-proof', 'raw-command', 'raw-test', 'maintainer-bench', 'leanbch']);
const HASH = /^[0-9a-f]{64}$/u;
const SHA1 = /^[0-9a-f]{40}$/u;
const ID = /^[a-z][a-z0-9-]*$/u;
const DNS = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u;
const SAFE_RELATIVE = /^(?!\/)(?!.*\\)(?!.*(?:^|\/)\.{1,2}(?:\/|$))[A-Za-z0-9][A-Za-z0-9._/-]*$/u;
const STABLE = Object.freeze(['dev', 'ino', 'size', 'mode', 'nlink', 'uid', 'mtimeNs', 'ctimeNs']);
const SIGNING_DOMAIN = 'shieldkit-v2-direct-d02-audit-signature-v1\0';
const workspace = resolve(dirname(new URL(import.meta.url).pathname), '../..');

export const V2_D02_POLICY_SCHEMA = 'shieldkit-v2-direct-d02-audit-policy-v2';
export const V2_D02_REPORT_SCHEMA = 'shieldkit-v2-direct-d02-final-audit-report-v2';
export const V2_D02_INVENTORY_SCHEMA = 'shieldkit-v2-direct-d02-evidence-inventory-v2';
export const V2_D02_ENVELOPE_SCHEMA = 'shieldkit-v2-direct-d02-signed-audit-envelope-v2';
export const V2_D02_RESULT_SCHEMA = 'shieldkit-v2-direct-d02-audit-closure-v2';
export const V2_D02_FAILURE_SCHEMA = 'shieldkit-v2-direct-d02-audit-closure-failure-v1';

export class V2D02AuditClosureError extends Error {
  constructor(message) { super(message); this.name = 'V2D02AuditClosureError'; }
}
const fail = (message) => { throw new V2D02AuditClosureError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonical = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');

function plain(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail(`${label} must be a plain object`);
  return value;
}
function exact(value, keys, label) {
  plain(value, label);
  const got = Object.keys(value).sort(); const wanted = [...keys].sort();
  if (got.length !== wanted.length || got.some((key, index) => key !== wanted[index])) fail(`${label} has missing or unknown properties`);
  return value;
}
function absolute(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) fail(`${label} must be an absolute normalized path`);
  return value;
}
function safeRelative(value, label) {
  if (typeof value !== 'string' || !SAFE_RELATIVE.test(value) || value.endsWith('/') || relative('/', `/${value}`).startsWith('..')) fail(`${label} must be a safe relative path`);
  return value;
}
function stableIdentity(left, right) { return STABLE.every((field) => left[field] === right[field]); }
function directDirectory(pathname, label) {
  absolute(pathname, label);
  const entry = lstatSync(pathname, { bigint: true, throwIfNoEntry: false });
  if (!entry?.isDirectory() || entry.isSymbolicLink() || realpathSync(pathname) !== pathname) fail(`${label} must be a direct canonical directory`);
  return pathname;
}
function stableBytes(filename, label) {
  absolute(filename, label);
  const pathname = lstatSync(filename, { bigint: true, throwIfNoEntry: false });
  if (!pathname?.isFile() || pathname.isSymbolicLink() || pathname.nlink !== 1n || realpathSync(filename) !== filename) fail(`${label} must be a direct single-link regular file`);
  let fd;
  try {
    fd = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(fd, { bigint: true });
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const finalPath = lstatSync(filename, { bigint: true, throwIfNoEntry: false });
    if (!before.isFile() || before.nlink !== 1n || !after.isFile() || after.nlink !== 1n || !finalPath?.isFile() || finalPath.isSymbolicLink() || finalPath.nlink !== 1n || !stableIdentity(pathname, before) || !stableIdentity(before, after) || !stableIdentity(after, finalPath)) fail(`${label} changed while it was read`);
    return Buffer.from(bytes);
  } finally { if (fd !== undefined) closeSync(fd); }
}
function canonicalFile(pathname, label) {
  const bytes = stableBytes(pathname, label); let value;
  try { value = JSON.parse(bytes); } catch { fail(`${label} is not JSON`); }
  if (!bytes.equals(canonical(value))) fail(`${label} must use exact RFC8785/JCS bytes`);
  return Object.freeze({ bytes, value, sha256: sha256(bytes) });
}
function inside(root, relativePath, label) {
  safeRelative(relativePath, label);
  const filename = resolve(root, relativePath);
  if (!filename.startsWith(`${root}${sep}`)) fail(`${label} escapes its root`);
  return filename;
}
function physicalFiles(root, label) {
  directDirectory(root, label);
  const files = [];
  const walk = (directory, prefix) => {
    const directoryEntry = lstatSync(directory, { bigint: true, throwIfNoEntry: false });
    if (!directoryEntry?.isDirectory() || directoryEntry.isSymbolicLink() || realpathSync(directory) !== directory) fail(`${label} contains an unsafe directory`);
    for (const name of readdirSync(directory).sort()) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(name)) fail(`${label} contains an unsafe filename`);
      const path = join(directory, name); const rel = prefix === '' ? name : `${prefix}/${name}`;
      const entry = lstatSync(path, { bigint: true });
      if (entry.isSymbolicLink()) fail(`${label} contains a symlink`);
      if (entry.isDirectory()) walk(path, rel);
      else if (entry.isFile() && entry.nlink === 1n && realpathSync(path) === path) files.push(rel);
      else fail(`${label} contains a special or multiply linked file`);
    }
  };
  walk(root, '');
  return Object.freeze(files.sort());
}
/** TEST-ONLY filesystem probes; these grant no qualification authority. */
export function readV2D02StableFileForTestOnly(filename) {
  return stableBytes(filename, 'D02 test stable file');
}
export function listV2D02PhysicalFilesForTestOnly(root) {
  return physicalFiles(root, 'D02 test physical root');
}
function exactPaths(actual, expected, label) {
  if (actual.length !== expected.length || actual.some((entry, index) => entry !== expected[index])) fail(`${label} does not exactly cover its physical files`);
}
function assertHash(value, label) { if (typeof value !== 'string' || !HASH.test(value)) fail(`${label} must be SHA-256`); return value; }
function sixHashes(value, label) {
  exact(value, ['commit', 'descriptorSha256', 'manifestSha256', 'profileId', 'runtimeMaterialSha256', 'tree'], label);
  if (!SHA1.test(value.commit) || !SHA1.test(value.tree)) fail(`${label} Git hashes are invalid`);
  for (const field of ['profileId', 'descriptorSha256', 'manifestSha256', 'runtimeMaterialSha256']) assertHash(value[field], `${label}.${field}`);
  return value;
}
function authority(value, label) {
  exact(value, ['emailDomain', 'organizationId', 'publicKeyPem', 'role', 'signerId'], label);
  if (!ROLES.includes(value.role) || !ID.test(value.signerId) || !ID.test(value.organizationId) || typeof value.emailDomain !== 'string' || !DNS.test(value.emailDomain)) fail(`${label} identity is invalid`);
  let key; try { key = createPublicKey(value.publicKeyPem); } catch { fail(`${label} public key is invalid`); }
  const canonicalPem = key.export({ type: 'spki', format: 'pem' }).toString();
  if (key.asymmetricKeyType !== 'ed25519' || canonicalPem !== value.publicKeyPem) fail(`${label} requires canonical Ed25519 SPKI PEM`);
  return Object.freeze({ ...value, key, keySha256: sha256(key.export({ type: 'spki', format: 'der' })) });
}
function verifySignature(encoded, signer, role, statement) {
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9+/]{86}==$/u.test(encoded)) fail('D02 signature is not canonical base64');
  const signature = Buffer.from(encoded, 'base64');
  const message = Buffer.concat([Buffer.from(SIGNING_DOMAIN), Buffer.from(role), Buffer.from([0]), canonical(statement)]);
  if (signature.length !== 64 || signature.toString('base64') !== encoded || !verify(null, message, signer.key, signature)) fail('D02 signature is invalid');
}
function policyStructure(value) {
  exact(value, ['authorities', 'reports', 'schema'], 'D02 policy');
  if (value.schema !== V2_D02_POLICY_SCHEMA || !Array.isArray(value.authorities) || value.authorities.length !== 4 || !Array.isArray(value.reports) || value.reports.length !== 4) fail('D02 policy must have exactly four roles');
  const authorities = new Map(); const signerIds = new Set(); const keys = new Set(); const organizations = new Set(); const domains = new Set();
  for (const entry of value.authorities) {
    const parsed = authority(entry, 'D02 authority');
    if (authorities.has(parsed.role) || signerIds.has(parsed.signerId) || keys.has(parsed.keySha256) || organizations.has(parsed.organizationId) || domains.has(parsed.emailDomain)) fail('D02 authorities are not independent');
    authorities.set(parsed.role, parsed); signerIds.add(parsed.signerId); keys.add(parsed.keySha256); organizations.add(parsed.organizationId); domains.add(parsed.emailDomain);
  }
  const reports = new Map(); const paths = new Set();
  for (const entry of value.reports) {
    exact(entry, ['evidenceInventoryPath', 'mandatoryTests', 'reportPath', 'role'], 'D02 policy report');
    if (!ROLES.includes(entry.role) || reports.has(entry.role)) fail('D02 policy report role is duplicate or invalid');
    safeRelative(entry.reportPath, 'D02 policy reportPath'); safeRelative(entry.evidenceInventoryPath, 'D02 policy evidenceInventoryPath');
    if (entry.reportPath === entry.evidenceInventoryPath || paths.has(entry.reportPath) || paths.has(entry.evidenceInventoryPath) || !Array.isArray(entry.mandatoryTests) || entry.mandatoryTests.length === 0 || new Set(entry.mandatoryTests).size !== entry.mandatoryTests.length || entry.mandatoryTests.some((id) => !ID.test(id))) fail('D02 policy report paths or mandatory tests are invalid');
    paths.add(entry.reportPath); paths.add(entry.evidenceInventoryPath); reports.set(entry.role, Object.freeze({ ...entry, mandatoryTests: Object.freeze([...entry.mandatoryTests]) }));
  }
  if (ROLES.some((role) => !authorities.has(role) || !reports.has(role))) fail('D02 policy lacks exact role coverage');
  return Object.freeze({ authorities, reports });
}
function inventory(value, label) {
  exact(value, ['artifacts', 'schema'], label);
  if (value.schema !== V2_D02_INVENTORY_SCHEMA || !Array.isArray(value.artifacts) || value.artifacts.length === 0) fail(`${label} must contain nonempty real evidence`);
  const ids = new Set(); const paths = new Set();
  for (const entry of value.artifacts) {
    exact(entry, ['artifactId', 'classification', 'path', 'sha256'], `${label} artifact`);
    if (!ID.test(entry.artifactId) || !CLASSIFICATIONS.has(entry.classification) || !safeRelative(entry.path, `${label} artifact path`) || !HASH.test(entry.sha256) || ids.has(entry.artifactId) || paths.has(entry.path)) fail(`${label} artifact is invalid`);
    ids.add(entry.artifactId); paths.add(entry.path);
  }
  return value;
}
function findings(statement, requiredTests, artifactIds) {
  if (!Array.isArray(statement.mandatoryTests) || statement.mandatoryTests.length !== requiredTests.length) fail('D02 mandatory test coverage is incomplete');
  const tests = new Set();
  for (const entry of statement.mandatoryTests) {
    exact(entry, ['id', 'status'], 'D02 mandatory test');
    if (!requiredTests.includes(entry.id) || tests.has(entry.id) || entry.status !== 'passed') fail('D02 mandatory test is skipped, unavailable, duplicate, or unknown');
    tests.add(entry.id);
  }
  if (!Array.isArray(statement.findings)) fail('D02 findings must be an array');
  const ids = new Set();
  for (const finding of statement.findings) {
    exact(finding, ['applicable', 'evidenceArtifactId', 'id', 'remediationArtifactId', 'severity', 'status'], 'D02 finding');
    if (!ID.test(finding.id) || ids.has(finding.id) || typeof finding.applicable !== 'boolean' || !['critical', 'high', 'medium', 'low', 'info'].includes(finding.severity) || !['open', 'closed', 'not-applicable'].includes(finding.status) || !artifactIds.has(finding.evidenceArtifactId) || (finding.remediationArtifactId !== null && (!ID.test(finding.remediationArtifactId) || !artifactIds.has(finding.remediationArtifactId)))) fail('D02 finding is malformed or references unavailable evidence');
    ids.add(finding.id);
    if ((finding.severity === 'critical' || finding.severity === 'high') && (!finding.applicable || finding.status !== 'closed' || finding.remediationArtifactId === null)) fail('D02 critical/high finding is unresolved or waived');
    if (finding.severity === 'medium' && finding.applicable && (finding.status !== 'closed' || finding.remediationArtifactId === null)) fail('D02 applicable medium finding is unresolved');
    if (finding.severity === 'medium' && !finding.applicable && (finding.status !== 'not-applicable' || finding.remediationArtifactId !== null)) fail('D02 nonapplicable medium finding is invalid');
  }
}
function statement(value, role, expectedHashes, requiredTests, inventoryValue) {
  exact(value, ['evidenceInventorySha256', 'findings', 'hashes', 'mandatoryTests', 'role', 'schema', 'scope'], 'D02 report statement');
  if (value.schema !== V2_D02_REPORT_SCHEMA || value.role !== role || !Array.isArray(value.scope) || value.scope.length === 0 || new Set(value.scope).size !== value.scope.length || value.scope.some((entry) => !ID.test(entry)) || canonical(value.hashes).compare(canonical(expectedHashes)) !== 0 || value.evidenceInventorySha256 !== sha256(canonical(inventoryValue))) fail('D02 report statement binding drifts');
  findings(value, requiredTests, new Set(inventoryValue.artifacts.map((entry) => entry.artifactId)));
  return value;
}
function setEntries(value, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  const paths = new Set(); const normalized = [];
  for (const entry of value) {
    exact(entry, ['path', 'sha256'], `${label} entry`); safeRelative(entry.path, `${label} path`); assertHash(entry.sha256, `${label} sha256`);
    if (paths.has(entry.path)) fail(`${label} has duplicate paths`); paths.add(entry.path); normalized.push({ path: entry.path, sha256: entry.sha256 });
  }
  normalized.sort((left, right) => left.path.localeCompare(right.path));
  if (normalized.some((entry, index) => entry.path !== value[index].path || entry.sha256 !== value[index].sha256)) fail(`${label} must be path-sorted`);
  return normalized;
}
function expectSet(actual, expected, label) {
  if (actual.length !== expected.length || actual.some((entry, index) => entry.path !== expected[index].path || entry.sha256 !== expected[index].sha256)) fail(`${label} differs from exact referenced set`);
}

/** Revalidates an emitted closure without trusting its qualification booleans. */
export function revalidateV2D02AuditClosure(value) {
  exact(value, ['auditSet', 'auditSetSha256', 'd02Qualified', 'evidenceInventories', 'evidenceSet', 'evidenceSetSha256', 'expectedFinalHashes', 'policy', 'policySha256', 'production', 'releaseQualified', 'reports', 'schema', 'status'], 'D02 closure');
  if (value.schema !== V2_D02_RESULT_SCHEMA || value.status !== 'd02-qualified-audit-closure-not-production-or-release' || value.d02Qualified !== true || value.production !== false || value.releaseQualified !== false) fail('D02 closure cannot claim production or release qualification');
  sixHashes(value.expectedFinalHashes, 'D02 expected final hashes');
  if (sha256(canonical(value.policy)) !== value.policySha256) fail('D02 policy hash drifts');
  const policy = policyStructure(value.policy);
  if (!Array.isArray(value.evidenceInventories) || value.evidenceInventories.length !== 4 || !Array.isArray(value.reports) || value.reports.length !== 4) fail('D02 closure needs exactly four reports and inventories');
  const inventories = new Map();
  for (const entry of value.evidenceInventories) {
    exact(entry, ['role', 'sha256', 'value'], 'D02 closure inventory');
    if (!ROLES.includes(entry.role) || inventories.has(entry.role)) fail('D02 closure inventory role is invalid');
    const parsed = inventory(entry.value, `D02 ${entry.role} inventory`);
    if (entry.sha256 !== sha256(canonical(parsed))) fail('D02 inventory hash drifts');
    inventories.set(entry.role, parsed);
  }
  if (ROLES.some((role) => !inventories.has(role))) fail('D02 inventory role coverage is incomplete');
  const reports = new Map();
  for (const envelope of value.reports) {
    exact(envelope, ['role', 'schema', 'signatureBase64', 'signerId', 'statement', 'statementSha256'], 'D02 report envelope');
    const signer = policy.authorities.get(envelope.role); const required = policy.reports.get(envelope.role); const inv = inventories.get(envelope.role);
    if (!signer || !required || !inv || reports.has(envelope.role) || envelope.schema !== V2_D02_ENVELOPE_SCHEMA || envelope.signerId !== signer.signerId || envelope.statementSha256 !== sha256(canonical(envelope.statement))) fail('D02 report envelope binding is invalid');
    statement(envelope.statement, envelope.role, value.expectedFinalHashes, required.mandatoryTests, inv);
    verifySignature(envelope.signatureBase64, signer, envelope.role, envelope.statement);
    reports.set(envelope.role, envelope);
  }
  if (ROLES.some((role) => !reports.has(role))) fail('D02 report role coverage is incomplete');
  const wantedAudit = ROLES.flatMap((role) => {
    const spec = policy.reports.get(role); return [
      { path: spec.reportPath, sha256: sha256(canonical(reports.get(role))) },
      { path: spec.evidenceInventoryPath, sha256: sha256(canonical(inventories.get(role))) },
    ];
  }).sort((left, right) => left.path.localeCompare(right.path));
  const auditSet = setEntries(value.auditSet, 'D02 audit set');
  expectSet(auditSet, wantedAudit, 'D02 audit set');
  if (value.auditSetSha256 !== sha256(canonical(auditSet))) fail('D02 audit set hash drifts');
  const evidenceByPath = new Map(); const evidenceById = new Map();
  for (const role of ROLES) for (const artifact of inventories.get(role).artifacts) {
    const priorPath = evidenceByPath.get(artifact.path); const priorId = evidenceById.get(artifact.artifactId);
    const same = (prior) => prior !== undefined && prior.path === artifact.path && prior.sha256 === artifact.sha256 && prior.classification === artifact.classification && prior.artifactId === artifact.artifactId;
    if ((priorPath !== undefined && !same(priorPath)) || (priorId !== undefined && !same(priorId))) fail('D02 evidence inventories contain conflicting aliases');
    evidenceByPath.set(artifact.path, artifact); evidenceById.set(artifact.artifactId, artifact);
  }
  const wantedEvidence = [...evidenceByPath.values()].map(({ path, sha256: digest }) => ({ path, sha256: digest })).sort((left, right) => left.path.localeCompare(right.path));
  const evidenceSet = setEntries(value.evidenceSet, 'D02 evidence set');
  expectSet(evidenceSet, wantedEvidence, 'D02 evidence set');
  if (value.evidenceSetSha256 !== sha256(canonical(evidenceSet))) fail('D02 evidence set hash drifts');
  return Object.freeze({ policy: value.policy, reports: value.reports, evidenceInventories: value.evidenceInventories, expectedFinalHashes: value.expectedFinalHashes, auditSet: value.auditSet, evidenceSet: value.evidenceSet });
}

function safeRuntime() {
  if (process.execArgv.length !== 0 || Object.keys(process.env).some((key) => key === 'NODE_OPTIONS' || key === 'NODE_PATH' || key.startsWith('LD_') || key.startsWith('DYLD_'))) fail('D02 refuses ambient loader or dynamic-linker controls');
}
function trustedGit() {
  for (const candidate of ['/usr/bin/git', '/bin/git']) {
    const entry = lstatSync(candidate, { throwIfNoEntry: false });
    if (entry?.isFile() && !entry.isSymbolicLink() && entry.uid === 0 && (entry.mode & 0o022) === 0 && realpathSync(candidate) === candidate) return candidate;
  }
  fail('D02 requires a root-owned non-writable absolute Git executable');
}
function gitState(git) {
  const run = (args) => {
    const result = spawnSync(git, ['--no-replace-objects', '--literal-pathspecs', '-c', 'core.hooksPath=/dev/null', '-c', 'include.path=/dev/null', '-c', 'core.fsmonitor=false', ...args], { cwd: workspace, env: { GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_NO_REPLACE_OBJECTS: '1', GIT_TERMINAL_PROMPT: '0', HOME: '/nonexistent', PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    if (result.error || result.status !== 0 || result.signal !== null || result.stderr !== '') fail('D02 sanitized trusted Git query failed');
    return result.stdout;
  };
  const root = run(['rev-parse', '--show-toplevel']).trim(); const commit = run(['rev-parse', 'HEAD^{commit}']).trim(); const tree = run(['rev-parse', 'HEAD^{tree}']).trim(); const status = run(['status', '--porcelain=v1', '--untracked-files=all']);
  if (root !== workspace || !SHA1.test(commit) || !SHA1.test(tree) || status !== '') fail('D02 requires the exact clean compiled source checkout');
  for (const row of run(['ls-files', '-v', '-z']).split('\0')) if (row !== '' && !row.startsWith('H ')) fail('D02 rejects non-normal Git index flags');
  return Object.freeze({ commit, tree });
}
export function parseV2D02Arguments(argv) {
  const names = new Set(['--profile-core', '--descriptor', '--final-manifest', '--release-root', '--audit-dir', '--evidence-root', '--expected-commit', '--expected-tree', '--output-dir']);
  if (!Array.isArray(argv) || argv.length !== names.size * 2) fail('usage: v2-d02-audit-closure.mjs --profile-core <absolute> --descriptor <absolute> --final-manifest <absolute> --release-root <compiled-root-id> --audit-dir <absolute-directory> --evidence-root <absolute-directory> --expected-commit <sha1> --expected-tree <sha1> --output-dir <absolute-new-directory>');
  const fields = new Map();
  for (let index = 0; index < argv.length; index += 2) { if (!names.has(argv[index]) || fields.has(argv[index]) || typeof argv[index + 1] !== 'string' || argv[index + 1] === '') fail('D02 arguments are malformed'); fields.set(argv[index], argv[index + 1]); }
  if ([...names].some((name) => !fields.has(name)) || !ID.test(fields.get('--release-root')) || !SHA1.test(fields.get('--expected-commit')) || !SHA1.test(fields.get('--expected-tree'))) fail('D02 release root or expected Git pins are malformed');
  return Object.freeze({ profileCorePath: absolute(fields.get('--profile-core'), 'D02 profile core'), descriptorPath: absolute(fields.get('--descriptor'), 'D02 descriptor'), finalManifestPath: absolute(fields.get('--final-manifest'), 'D02 final manifest'), releaseRootId: fields.get('--release-root'), auditDirectory: absolute(fields.get('--audit-dir'), 'D02 audit directory'), evidenceRoot: absolute(fields.get('--evidence-root'), 'D02 evidence root'), expectedCommit: fields.get('--expected-commit'), expectedTree: fields.get('--expected-tree'), outputDirectory: absolute(fields.get('--output-dir'), 'D02 output directory') });
}
function writeResult(directory, filename, value) {
  if (existsSync(directory)) fail('D02 output directory already exists');
  const parent = dirname(directory); directDirectory(parent, 'D02 output parent');
  mkdirSync(directory, { mode: 0o700 }); chmodSync(directory, 0o700);
  const directoryEntry = lstatSync(directory, { bigint: true });
  if (!directoryEntry.isDirectory() || directoryEntry.isSymbolicLink() || directoryEntry.uid !== BigInt(process.getuid()) || (directoryEntry.mode & 0o777n) !== 0o700n || realpathSync(directory) !== directory) fail('D02 output directory is unsafe');
  const temporary = join(directory, '.writing'); const target = join(directory, filename); let fd;
  try { fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600); writeSync(fd, canonical(value)); fsyncSync(fd); } finally { if (fd !== undefined) closeSync(fd); }
  chmodSync(temporary, 0o600); renameSync(temporary, target);
  const entry = lstatSync(target, { bigint: true });
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1n || entry.uid !== BigInt(process.getuid()) || (entry.mode & 0o777n) !== 0o600n || realpathSync(target) !== target) fail('D02 output file is unsafe');
  const dirFd = openSync(directory, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0)); try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
}
function failure(options, error) {
  if (options && typeof options.outputDirectory === 'string' && isAbsolute(options.outputDirectory) && resolve(options.outputDirectory) === options.outputDirectory && !existsSync(options.outputDirectory)) {
    try { writeResult(options.outputDirectory, 'failure.json', { schema: V2_D02_FAILURE_SCHEMA, status: 'd02-not-qualified', d02Qualified: false, production: false, releaseQualified: false, reason: error instanceof Error ? error.message : String(error) }); } catch { /* preserve the original failure */ }
  }
}
export async function verifyV2D02AuditClosure(options) {
  try {
    exact(options, ['auditDirectory', 'descriptorPath', 'evidenceRoot', 'expectedCommit', 'expectedTree', 'finalManifestPath', 'outputDirectory', 'profileCorePath', 'releaseRootId'], 'D02 options');
    safeRuntime();
    // Compiled release-root authorization is resolved before any caller path.
    const releaseRoot = resolveV2FinalReleaseRoot(options.releaseRootId);
    const git = gitState(trustedGit());
    if (git.commit !== options.expectedCommit || git.tree !== options.expectedTree) fail('D02 expected source pins differ from the clean checkout');
    directDirectory(options.auditDirectory, 'D02 audit directory'); directDirectory(options.evidenceRoot, 'D02 evidence root');
    const profile = canonicalFile(options.profileCorePath, 'D02 profile core');
    const release = verifyV2FinalReleaseProfileCore(releaseRoot, profile.bytes, profile.value);
    const descriptor = await loadV2InstanceDescriptor({ descriptorPath: options.descriptorPath, profileCore: profile.value, trustedSigners: release.descriptorSigners });
    const manifest = canonicalFile(options.finalManifestPath, 'D02 final manifest');
    if (descriptor.manifest.filename !== options.finalManifestPath || descriptor.manifest.sha256 !== manifest.sha256) fail('D02 final manifest differs from the validated descriptor');
    const runtime = await deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor);
    if (runtime.eligibility !== 'final-qualified' || runtime.claims.finalKey !== true || runtime.claims.developmentKey !== false || runtime.claims.ceremonyQualified !== true || runtime.claims.production !== false || runtime.claims.releaseQualified !== false) fail('D02 final runtime claims are not exact');
    const policyArtifact = deriveV2ManifestArtifactFromValidatedDescriptor(descriptor, 'd02-audit-policy');
    const policyFile = canonicalFile(policyArtifact.path, 'D02 signed audit policy');
    if (policyFile.sha256 !== policyArtifact.sha256) fail('D02 signed audit policy hash drifts');
    const policy = policyStructure(policyFile.value);
    const auditPaths = ROLES.flatMap((role) => [policy.reports.get(role).reportPath, policy.reports.get(role).evidenceInventoryPath]).sort();
    exactPaths(physicalFiles(options.auditDirectory, 'D02 audit directory'), auditPaths, 'D02 audit directory');
    const inventories = []; const reports = []; const auditSet = [];
    for (const role of ROLES) {
      const spec = policy.reports.get(role);
      const report = canonicalFile(inside(options.auditDirectory, spec.reportPath, 'D02 report path'), `D02 ${role} report`);
      const inv = canonicalFile(inside(options.auditDirectory, spec.evidenceInventoryPath, 'D02 inventory path'), `D02 ${role} inventory`);
      reports.push(report.value); inventories.push({ role, sha256: inv.sha256, value: inv.value }); auditSet.push({ path: spec.reportPath, sha256: report.sha256 }, { path: spec.evidenceInventoryPath, sha256: inv.sha256 });
    }
    const evidencePhysical = physicalFiles(options.evidenceRoot, 'D02 evidence root');
    const evidenceByPath = new Map(); const evidenceById = new Map();
    for (const entry of inventories) for (const artifact of inventory(entry.value, `D02 ${entry.role} inventory`).artifacts) {
      const priorPath = evidenceByPath.get(artifact.path); const priorId = evidenceById.get(artifact.artifactId);
      const same = (prior) => prior !== undefined && prior.path === artifact.path && prior.sha256 === artifact.sha256 && prior.classification === artifact.classification && prior.artifactId === artifact.artifactId;
      if ((priorPath !== undefined && !same(priorPath)) || (priorId !== undefined && !same(priorId))) fail('D02 evidence inventories contain conflicting aliases');
      evidenceByPath.set(artifact.path, artifact); evidenceById.set(artifact.artifactId, artifact);
    }
    const evidenceSet = [...evidenceByPath.values()].map(({ path, sha256: digest }) => ({ path, sha256: digest })).sort((left, right) => left.path.localeCompare(right.path));
    exactPaths(evidencePhysical, evidenceSet.map((entry) => entry.path), 'D02 evidence root');
    for (const entry of evidenceSet) if (sha256(stableBytes(inside(options.evidenceRoot, entry.path, 'D02 evidence path'), `D02 evidence ${entry.path}`)) !== entry.sha256) fail(`D02 evidence hash drifts: ${entry.path}`);
    const closure = { schema: V2_D02_RESULT_SCHEMA, status: 'd02-qualified-audit-closure-not-production-or-release', d02Qualified: true, production: false, releaseQualified: false, policy: policyFile.value, policySha256: policyFile.sha256, reports, evidenceInventories: inventories, expectedFinalHashes: { commit: git.commit, tree: git.tree, profileId: descriptor.profileId, descriptorSha256: descriptor.descriptor.sha256, manifestSha256: descriptor.manifest.sha256, runtimeMaterialSha256: runtime.runtimeMaterial.materialSha256 }, auditSet: auditSet.sort((left, right) => left.path.localeCompare(right.path)), auditSetSha256: '', evidenceSet, evidenceSetSha256: '' };
    closure.auditSetSha256 = sha256(canonical(closure.auditSet)); closure.evidenceSetSha256 = sha256(canonical(closure.evidenceSet));
    revalidateV2D02AuditClosure(closure); writeResult(options.outputDirectory, 'audit-closure.json', closure); return Object.freeze(closure);
  } catch (error) { failure(options, error); throw error; }
}
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { process.stdout.write(`${JSON.stringify(await verifyV2D02AuditClosure(parseV2D02Arguments(process.argv.slice(2))))}\n`); } catch (error) { process.stderr.write(`D02 audit closure failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; }
}
