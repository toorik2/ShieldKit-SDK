import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import { listV2D02PhysicalFilesForTestOnly, parseV2D02Arguments, readV2D02StableFileForTestOnly, revalidateV2D02AuditClosure, verifyV2D02AuditClosure, V2_D02_ENVELOPE_SCHEMA, V2_D02_INVENTORY_SCHEMA, V2_D02_POLICY_SCHEMA, V2_D02_REPORT_SCHEMA, V2_D02_RESULT_SCHEMA, V2D02AuditClosureError } from './v2-d02-audit-closure.mjs';

const roles = ['protocol', 'circuit', 'covenants', 'wallet'];
const hash = (value) => createHash('sha256').update(value).digest('hex');
const bytes = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');
const hashes = { commit: 'a'.repeat(40), tree: 'b'.repeat(40), profileId: 'c'.repeat(64), descriptorSha256: 'd'.repeat(64), manifestSha256: 'e'.repeat(64), runtimeMaterialSha256: 'f'.repeat(64) };
function signature(key, role, statement) { return sign(null, Buffer.concat([Buffer.from('shieldkit-v2-direct-d02-audit-signature-v1\0'), Buffer.from(role), Buffer.from([0]), bytes(statement)]), key).toString('base64'); }
function build() {
  const keys = roles.map((role, index) => ({ role, signerId: `signer-${index}`, organizationId: `org-${index}`, emailDomain: `audit-${index}.example.org`, ...generateKeyPairSync('ed25519') }));
  const policy = { schema: V2_D02_POLICY_SCHEMA, authorities: keys.map((key) => ({ role: key.role, signerId: key.signerId, organizationId: key.organizationId, emailDomain: key.emailDomain, publicKeyPem: key.publicKey.export({ type: 'spki', format: 'pem' }).toString() })), reports: keys.map((key) => ({ role: key.role, reportPath: `reports/${key.role}.json`, evidenceInventoryPath: `inventories/${key.role}.json`, mandatoryTests: [`test-${key.role}`] })) };
  const evidenceInventories = keys.map((key) => { const value = { schema: V2_D02_INVENTORY_SCHEMA, artifacts: [{ artifactId: `evidence-${key.role}`, classification: 'raw-vm-lane', path: `evidence/${key.role}.txt`, sha256: hash(key.role) }, { artifactId: `fix-${key.role}`, classification: 'raw-command', path: `evidence/${key.role}-fix.txt`, sha256: hash(`${key.role}-fix`) }] }; return { role: key.role, value, sha256: hash(bytes(value)) }; });
  const reports = keys.map((key) => { const inv = evidenceInventories.find((entry) => entry.role === key.role); const statement = { schema: V2_D02_REPORT_SCHEMA, role: key.role, scope: ['final-v2-direct'], hashes, evidenceInventorySha256: inv.sha256, mandatoryTests: [{ id: `test-${key.role}`, status: 'passed' }], findings: [{ id: `finding-${key.role}`, severity: 'high', applicable: true, status: 'closed', evidenceArtifactId: `evidence-${key.role}`, remediationArtifactId: `fix-${key.role}` }] }; return { role: key.role, schema: V2_D02_ENVELOPE_SCHEMA, signerId: key.signerId, statement, statementSha256: hash(bytes(statement)), signatureBase64: signature(key.privateKey, key.role, statement) }; });
  const auditSet = roles.flatMap((role) => { const policyEntry = policy.reports.find((entry) => entry.role === role); const report = reports.find((entry) => entry.role === role); const inv = evidenceInventories.find((entry) => entry.role === role); return [{ path: policyEntry.reportPath, sha256: hash(bytes(report)) }, { path: policyEntry.evidenceInventoryPath, sha256: inv.sha256 }]; }).sort((a, b) => a.path.localeCompare(b.path));
  const evidenceSet = evidenceInventories.flatMap((entry) => entry.value.artifacts.map((artifact) => ({ path: artifact.path, sha256: artifact.sha256 }))).sort((a, b) => a.path.localeCompare(b.path));
  const closure = { schema: V2_D02_RESULT_SCHEMA, status: 'd02-qualified-audit-closure-not-production-or-release', d02Qualified: true, production: false, releaseQualified: false, policy, policySha256: hash(bytes(policy)), reports, evidenceInventories, expectedFinalHashes: hashes, auditSet, auditSetSha256: hash(bytes(auditSet)), evidenceSet, evidenceSetSha256: hash(bytes(evidenceSet)) };
  Object.defineProperty(closure, 'keys', { value: keys });
  return closure;
}
function resign(closure, index = 0) { const report = closure.reports[index]; report.statementSha256 = hash(bytes(report.statement)); report.signatureBase64 = signature(closure.keys[index].privateKey, report.role, report.statement); closure.auditSet.find((entry) => entry.path === closure.policy.reports[index].reportPath).sha256 = hash(bytes(report)); closure.auditSetSha256 = hash(bytes(closure.auditSet)); }
function reject(mutate) { const closure = build(); mutate(closure); assert.throws(() => revalidateV2D02AuditClosure(closure), V2D02AuditClosureError); }

test('D02 standalone closure accepts four real Ed25519 audit authorities', () => { const closure = build(); assert.equal(revalidateV2D02AuditClosure(closure).reports.length, 4); });
test('D02 accepts closed high and applicable medium plus nonapplicable medium when re-signed', () => { const closure = build(); closure.reports[0].statement.findings.push({ id: 'medium-closed', severity: 'medium', applicable: true, status: 'closed', evidenceArtifactId: 'evidence-protocol', remediationArtifactId: 'fix-protocol' }); closure.reports[0].statement.findings.push({ id: 'medium-na', severity: 'medium', applicable: false, status: 'not-applicable', evidenceArtifactId: 'evidence-protocol', remediationArtifactId: null }); resign(closure); assert.equal(revalidateV2D02AuditClosure(closure).reports.length, 4); });
test('D02 rejects unresolved material findings and missing references', () => {
  reject((x) => { x.reports[0].statement.findings[0].status = 'open'; resign(x); });
  reject((x) => { x.reports[0].statement.findings[0] = { ...x.reports[0].statement.findings[0], severity: 'medium', status: 'open' }; resign(x); });
  reject((x) => { x.reports[0].statement.findings[0].evidenceArtifactId = 'missing'; resign(x); });
  reject((x) => { x.reports[0].statement.findings[0].remediationArtifactId = 'missing'; resign(x); });
});
test('D02 rejects signature, identity, mandatory-test, path, and set drift', () => {
  reject((x) => { x.reports[0].signatureBase64 = 'A'.repeat(88); });
  reject((x) => { x.policy.authorities[1].emailDomain = x.policy.authorities[0].emailDomain; x.policySha256 = hash(bytes(x.policy)); });
  reject((x) => { x.reports[0].statement.mandatoryTests.push({ id: 'test-protocol', status: 'passed' }); resign(x); });
  reject((x) => { x.policy.reports[1].reportPath = x.policy.reports[0].reportPath; x.policySha256 = hash(bytes(x.policy)); });
  reject((x) => { x.auditSetSha256 = '0'.repeat(64); });
  reject((x) => { x.evidenceSet[0].sha256 = '0'.repeat(64); x.evidenceSetSha256 = hash(bytes(x.evidenceSet)); });
});
test('D02 parser requires the exact arguments and resolves release root before caller paths', async () => {
  assert.throws(() => parseV2D02Arguments(['--profile-core', '/a']), V2D02AuditClosureError);
  await assert.rejects(() => verifyV2D02AuditClosure({ profileCorePath: '/must-not-open/p', descriptorPath: '/must-not-open/d', finalManifestPath: '/must-not-open/m', releaseRootId: '../bad', auditDirectory: '/must-not-open/a', evidenceRoot: '/must-not-open/e', expectedCommit: 'a'.repeat(40), expectedTree: 'b'.repeat(40), outputDirectory: '/must-not-create/o' }), /root id is malformed/u);
});
test('D02 stable reader and recursive physical-set guards reject symlinks and extra files', () => {
  const root = mkdtempSync(join(tmpdir(), 'd02-test-')); const audit = join(root, 'audit'); const evidence = join(root, 'evidence'); mkdirSync(join(audit, 'reports'), { recursive: true }); mkdirSync(join(audit, 'inventories'), { recursive: true }); mkdirSync(join(evidence, 'evidence'), { recursive: true });
  const closure = build();
  for (const entry of closure.auditSet) { const file = join(audit, entry.path); mkdirSync(join(file, '..'), { recursive: true }); const value = entry.path.startsWith('reports/') ? closure.reports.find((report) => `reports/${report.role}.json` === entry.path) : closure.evidenceInventories.find((inv) => `inventories/${inv.role}.json` === entry.path).value; writeFileSync(file, bytes(value)); }
  for (const entry of closure.evidenceSet) { const file = join(evidence, entry.path); mkdirSync(join(file, '..'), { recursive: true }); writeFileSync(file, entry.path.includes('-fix') ? entry.path.split('/').at(-1).replace('.txt', '') : entry.path.split('/').at(-1).replace('.txt', '')); }
  assert.deepEqual(listV2D02PhysicalFilesForTestOnly(audit), closure.auditSet.map((entry) => entry.path));
  assert.deepEqual(readV2D02StableFileForTestOnly(join(audit, 'reports', 'protocol.json')), bytes(closure.reports[0]));
  assert.equal(revalidateV2D02AuditClosure(closure).auditSet.length, 8);
  symlinkSync(join(audit, 'reports', 'protocol.json'), join(audit, 'reports', 'link.json'));
  assert.throws(() => listV2D02PhysicalFilesForTestOnly(audit), V2D02AuditClosureError);
  chmodSync(root, 0o700);
});
