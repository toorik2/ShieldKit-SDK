// Fail-closed production release gate for FRI-STARK55.
//
// This is deliberately not a manifest template. A real-money release must
// supply a concrete production_manifest.json produced by the application owner
// and backed by independently verifiable evidence. Missing or test-looking
// values are a hard failure; the research fixture must never be mistaken for a
// funded deployment.
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { collectLocalModuleClosure } from './source_closure.mjs';

const here = new URL('.', import.meta.url);
const path = (name) => new URL(name, here);
const fail = (message) => { console.error(`FRI-STARK55 RELEASE BLOCKED: ${message}`); process.exitCode = 1; };

const manifestUrl = path('./production_manifest.json');
const hash256Hex = (value) => {
  const first = createHash('sha256').update(value).digest();
  return createHash('sha256').update(first).digest('hex');
};
if (!existsSync(manifestUrl)) {
  fail('production_manifest.json is absent; the current artifact has no real application statement, security target, genesis category, or funded UTXO set');
  process.exit();
}

let manifest;
try {
  manifest = JSON.parse(readFileSync(manifestUrl, 'utf8'));
} catch (error) {
  fail(`production_manifest.json is not valid JSON: ${error.message}`);
  process.exit();
}
if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
  fail('production_manifest.json root must be a JSON object');
  process.exit();
}

const errors = [];
const sourceRoot = new URL('../', here);
const repositoryRoot = fileURLToPath(sourceRoot);
const isRepoRelativePath = (value) => {
  if (typeof value !== 'string' || value.trim() === '' || value.includes('\0') || value.startsWith('/')) return false;
  const resolved = resolve(repositoryRoot, value);
  return resolved === repositoryRoot || resolved.startsWith(`${repositoryRoot}/`);
};
const text = (value, name) => {
  if (typeof value !== 'string' || value.trim() === '') errors.push(`${name} must be a non-empty string`);
  return typeof value === 'string' ? value : '';
};
const hex = (value, name) => {
  const v = text(value, name);
  if (!/^[0-9a-f]{64}$/i.test(v)) errors.push(`${name} must be a 32-byte hex value`);
};
const list = (value, name, minimum) => {
  if (!Array.isArray(value) || value.length < minimum) errors.push(`${name} must contain at least ${minimum} independently checkable entries`);
};
const containsFixtureLanguage = (value) => /(?:^|[^a-z])(toy|demo(?:nstrator)?|mock|placeholder|synthetic|fixture|test deployment)(?:[^a-z]|$)/i.test(String(value));
const MAX_TOKEN_AMOUNT = 9_223_372_036_854_775_807n;
const isTokenAmount = (value) => {
  if (!/^\d+$/.test(String(value ?? ''))) return false;
  try { return BigInt(String(value)) <= MAX_TOKEN_AMOUNT; } catch { return false; }
};

const statementId = text(manifest.statementId, 'statementId');
const statementDescription = text(manifest.statementDescription, 'statementDescription');
const statementSpecSha256 = manifest.statementSpecSha256;
if (!/^[0-9a-f]{64}$/i.test(String(statementSpecSha256 ?? ''))) errors.push('statementSpecSha256 must be a 32-byte hex digest');
if (!/^[0-9a-f]{64}$/i.test(String(manifest.genesisCategory ?? '')) || /^0+$/.test(String(manifest.genesisCategory ?? ''))) errors.push('genesisCategory must be a non-zero 32-byte category ID');
if (String(manifest.genesisCategory ?? '').toLowerCase() === hash256Hex('verifier.cash/fri-stark55/category/v1')) errors.push('genesisCategory is the checked-in deterministic fixture category');
if (containsFixtureLanguage(statementId) || containsFixtureLanguage(statementDescription)) {
  errors.push('statement metadata contains research-fixture language');
}

if (manifest.network !== 'mainnet') errors.push('network must be exactly mainnet for a real-money release');
if (manifest.proofSystem !== 'FRI-STARK') errors.push('proofSystem must be exactly FRI-STARK');
if (manifest.soundnessModel !== 'provable') errors.push('soundnessModel must be exactly provable');
if (!Number.isInteger(manifest.securityTargetBits) || manifest.securityTargetBits < 128) {
  errors.push('securityTargetBits must be an explicit value of at least 128');
}
if (!Number.isInteger(manifest.soundnessBoundBits) || manifest.soundnessBoundBits < (manifest.securityTargetBits ?? 129)) errors.push('soundnessBoundBits must cover securityTargetBits');
if (!Number.isInteger(manifest.challengeFieldBits) || manifest.challengeFieldBits < (manifest.securityTargetBits ?? 129)) errors.push('challengeFieldBits must cover securityTargetBits');
if (!Number.isInteger(manifest.queryCount) || manifest.queryCount < 1) errors.push('queryCount must be explicit and positive');
if (manifest.maxTotalBytes !== 45_000) errors.push('maxTotalBytes must equal the hard 45,000-byte crown cap');
if (manifest.proofBinding !== 'runtime') errors.push('proofBinding must be exactly runtime');
if (!Array.isArray(manifest.verifierSourcePaths) || manifest.verifierSourcePaths.length < 1) errors.push('verifierSourcePaths must identify the production verifier source');
if (typeof manifest.adapterModule !== 'string' || manifest.adapterModule.trim() === '') errors.push('adapterModule must identify the production bench adapter');
else if (!isRepoRelativePath(manifest.adapterModule)) errors.push('adapterModule must be a repository-relative path');
if (typeof manifest.independentReferenceModule !== 'string' || manifest.independentReferenceModule.trim() === '') errors.push('independentReferenceModule must identify the independent reference verifier');
else if (!isRepoRelativePath(manifest.independentReferenceModule)) errors.push('independentReferenceModule must be a repository-relative path');
if (manifest.independentReferenceModule === manifest.adapterModule) errors.push('independentReferenceModule must differ from adapterModule');
if (!manifest.verifierSourceSha256 || typeof manifest.verifierSourceSha256 !== 'object' || Array.isArray(manifest.verifierSourceSha256)) {
  errors.push('verifierSourceSha256 must map every production source path to a digest');
}
hex(manifest.genesisCategory, 'genesisCategory');
hex(manifest.genesisTxid, 'genesisTxid');
if (/^0+$/.test(String(manifest.genesisTxid ?? ''))) errors.push('genesisTxid must be non-zero');
if (manifest.genesisInputIndex !== 0) errors.push('genesisInputIndex must be 0 for a CashToken category genesis');
hex(manifest.reproducibleBuildSha256, 'reproducibleBuildSha256');
hex(manifest.vectorSha256, 'vectorSha256');
hex(manifest.securityCertificateSha256, 'securityCertificateSha256');
hex(manifest.dependencyLockSha256, 'dependencyLockSha256');
list(manifest.fundingTxids, 'fundingTxids', 1);
const fundingTxidList = Array.isArray(manifest.fundingTxids) ? manifest.fundingTxids : [];
const fundingTxids = new Set(fundingTxidList.map((txid) => String(txid).toLowerCase()));
if (fundingTxids.size !== fundingTxidList.length) errors.push('fundingTxids must be unique');
for (const [i, txid] of fundingTxidList.entries()) {
  hex(txid, `fundingTxids[${i}]`);
  if (/^0+$/.test(String(txid))) errors.push(`fundingTxids[${i}] must be non-zero`);
}
const fundingUtxoList = Array.isArray(manifest.fundingUtxos) ? manifest.fundingUtxos : [];
if (fundingUtxoList.length < 1) errors.push('fundingUtxos must contain real funded UTXOs');
const fundingUtxoKeys = new Set();
let applicationUtxoCount = 0;
if (typeof manifest.genesisTxid === 'string' && !fundingTxids.has(manifest.genesisTxid.toLowerCase())) {
  errors.push('fundingTxids must include genesisTxid so category provenance is linked to the funded set');
}
for (const [i, utxo] of fundingUtxoList.entries()) {
  if (!utxo || !/^[0-9a-f]{64}$/i.test(String(utxo.txid ?? '')) || /^0+$/.test(String(utxo?.txid ?? '')) || !Number.isInteger(utxo.vout) || utxo.vout < 0) errors.push(`fundingUtxos[${i}] needs non-zero txid/vout`);
  if (!/^[1-9]\d*$/.test(String(utxo?.valueSatoshis ?? ''))) errors.push(`fundingUtxos[${i}] valueSatoshis must be a positive integer`);
  if (!/^[0-9a-f]{64}$/i.test(String(utxo?.lockingBytecodeSha256 ?? ''))) errors.push(`fundingUtxos[${i}] lockingBytecodeSha256 must be a 32-byte digest`);
  const key = `${String(utxo?.txid ?? '').toLowerCase()}:${utxo?.vout}`;
  if (fundingUtxoKeys.has(key)) errors.push(`fundingUtxos[${i}] duplicates another funded outpoint`);
  fundingUtxoKeys.add(key);
  if (utxo?.txid && !fundingTxids.has(String(utxo.txid).toLowerCase())) errors.push(`fundingUtxos[${i}] txid is not listed in fundingTxids`);
  const role = utxo?.role ?? 'application';
  if (role !== 'application' && role !== 'library') errors.push(`fundingUtxos[${i}] role must be application or library`);
  if (role === 'application') {
    applicationUtxoCount++;
    if (utxo?.category !== manifest.genesisCategory) errors.push(`fundingUtxos[${i}] category mismatch`);
    if (utxo?.capability !== 'mutable') errors.push(`fundingUtxos[${i}] capability must be mutable`);
    if (!isTokenAmount(utxo?.tokenAmount)) errors.push(`fundingUtxos[${i}] tokenAmount exceeds the BCH-2026 maximum or is not a decimal integer`);
    if (!/^[0-9a-f]{64}$/i.test(String(utxo?.nftCommitmentSha256 ?? ''))) errors.push(`fundingUtxos[${i}] nftCommitmentSha256 must be a 32-byte digest`);
  } else if (utxo?.category !== undefined || utxo?.capability !== undefined || utxo?.tokenAmount !== undefined || utxo?.nftCommitmentSha256 !== undefined) {
    errors.push(`fundingUtxos[${i}] library role must be tokenless (omit token fields)`);
  }
}
if (applicationUtxoCount < 1) errors.push('fundingUtxos must contain at least one application-token UTXO');
const artifactList = (value, name, minimum) => {
  if (!Array.isArray(value) || value.length < minimum) { errors.push(`${name} must contain at least ${minimum} hashed artifacts`); return; }
  const seen = new Set();
  const seenDigests = new Set();
  for (const [i, item] of value.entries()) {
    if (!item || typeof item.path !== 'string' || !/^[0-9a-f]{64}$/i.test(String(item.sha256 ?? ''))) {
      errors.push(`${name}[${i}] needs path + sha256`); continue;
    }
    if (!isRepoRelativePath(item.path)) {
      errors.push(`${name}[${i}] path must stay inside the repository`);
      continue;
    }
    const identity = `${item.path}\0${item.sha256.toLowerCase()}`;
    if (seen.has(identity)) errors.push(`${name}[${i}] duplicates another evidence entry`);
    seen.add(identity);
    if (seenDigests.has(item.sha256.toLowerCase())) errors.push(`${name}[${i}] reuses another artifact digest`);
    seenDigests.add(item.sha256.toLowerCase());
    try {
      const actual = createHash('sha256').update(readFileSync(new URL(item.path, sourceRoot))).digest('hex');
      if (actual !== item.sha256.toLowerCase()) errors.push(`${name}[${i}] sha256 mismatch`);
    } catch (error) { errors.push(`${name}[${i}] missing: ${error.message}`); }
  }
};
artifactList(manifest.distinctValidProofArtifacts, 'distinctValidProofArtifacts', 2);
artifactList(manifest.independentVerifierArtifacts, 'independentVerifierArtifacts', 2);
artifactList(manifest.fullNodeEvidence, 'fullNodeEvidence', 2);
artifactList(manifest.auditReferences, 'auditReferences', 1);
artifactList(manifest.applicationTests, 'applicationTests', 1);
const checkFileDigest = (pathName, digestName) => {
  if (!isRepoRelativePath(manifest[pathName]) || !/^[0-9a-f]{64}$/i.test(String(manifest[digestName] ?? ''))) {
    errors.push(`${pathName}/${digestName} must identify a hashed file`); return;
  }
  try {
    const actual = createHash('sha256').update(readFileSync(new URL(manifest[pathName], sourceRoot))).digest('hex');
    if (actual !== manifest[digestName].toLowerCase()) errors.push(`${pathName} sha256 mismatch`);
  } catch (error) { errors.push(`${pathName} missing: ${error.message}`); }
};
checkFileDigest('statementSpecPath', 'statementSpecSha256');
checkFileDigest('reproducibleBuildPath', 'reproducibleBuildSha256');
checkFileDigest('vectorPath', 'vectorSha256');
checkFileDigest('securityCertificatePath', 'securityCertificateSha256');
checkFileDigest('dependencyLockPath', 'dependencyLockSha256');
if (typeof manifest.dependencyLockPath !== 'string' ||
  !/(^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(manifest.dependencyLockPath)) {
  errors.push('dependencyLockPath must name a recognized package-manager lockfile');
}
if (isRepoRelativePath(manifest.securityCertificatePath)) {
  try {
    const certificate = JSON.parse(readFileSync(new URL(manifest.securityCertificatePath, sourceRoot), 'utf8'));
    if (certificate.statementId !== statementId) errors.push('security certificate statementId does not match manifest');
    if (certificate.soundnessModel !== 'provable') errors.push('security certificate must use the provable soundness model');
    if (!Number.isInteger(certificate.securityTargetBits) || certificate.securityTargetBits !== manifest.securityTargetBits) errors.push('security certificate target does not match manifest');
    if (!Number.isInteger(certificate.soundnessBoundBits) || certificate.soundnessBoundBits < manifest.securityTargetBits) errors.push('security certificate bound does not cover the manifest target');
    if (!Number.isInteger(certificate.challengeFieldBits) || certificate.challengeFieldBits < manifest.securityTargetBits) errors.push('security certificate challenge field does not cover the manifest target');
    if (!Number.isInteger(certificate.queryCount) || certificate.queryCount !== manifest.queryCount) errors.push('security certificate query count does not match manifest');
    if (typeof certificate.derivation !== 'string' || certificate.derivation.trim() === '') errors.push('security certificate lacks a reproducible bound derivation');
    if (certificate.independent !== true) errors.push('security certificate must be independently reviewed');
  } catch (error) { errors.push(`security certificate is not valid JSON: ${error.message}`); }
}
const sourceNames = Array.isArray(manifest.verifierSourcePaths)
  ? manifest.verifierSourcePaths
  : ['fri_stark/qstark.mjs', 'fri_stark55/common.mjs', 'fri_stark55/build.mjs'];
const sourceNameSet = new Set();
for (const [i, sourceName] of sourceNames.entries()) {
  if (!isRepoRelativePath(sourceName)) errors.push(`verifierSourcePaths[${i}] must be a repository-relative path`);
  if (sourceNameSet.has(sourceName)) errors.push(`verifierSourcePaths[${i}] duplicates another source path`);
  sourceNameSet.add(sourceName);
}
if (typeof manifest.adapterModule === 'string' && !sourceNames.includes(manifest.adapterModule)) {
  errors.push('verifierSourcePaths must include adapterModule so the production adapter is covered by the source audit');
}
if (typeof manifest.independentReferenceModule === 'string' && !sourceNames.includes(manifest.independentReferenceModule)) {
  errors.push('verifierSourcePaths must include independentReferenceModule so the executable differential is covered by the source audit');
}
const closureRoots = [
  ...sourceNames.filter(isRepoRelativePath),
  ...(typeof manifest.adapterModule === 'string' && isRepoRelativePath(manifest.adapterModule) ? [manifest.adapterModule] : []),
  ...(typeof manifest.independentReferenceModule === 'string' && isRepoRelativePath(manifest.independentReferenceModule) ? [manifest.independentReferenceModule] : []),
];
const closure = collectLocalModuleClosure(repositoryRoot, closureRoots);
for (const missing of closure.missing) errors.push(`local verifier import missing: ${missing}`);
for (const outside of closure.outside) errors.push(`local verifier import escapes repository: ${outside}`);
const declaredSources = new Set(sourceNames);
for (const file of closure.files) {
  const relativeName = closure.relative(file);
  if (!declaredSources.has(relativeName)) errors.push(`verifierSourcePaths omits reachable local source ${relativeName}`);
}
const closureNameSet = new Set(closure.files.map((file) => closure.relative(file)));
for (const sourceName of sourceNames) {
  if (isRepoRelativePath(sourceName) && !closureNameSet.has(sourceName)) errors.push(`verifierSourcePaths contains unreachable source ${sourceName}`);
}
if (isRepoRelativePath(manifest.adapterModule) && isRepoRelativePath(manifest.independentReferenceModule)) {
  const adapterPath = resolve(repositoryRoot, manifest.adapterModule);
  const referenceClosure = collectLocalModuleClosure(repositoryRoot, [manifest.independentReferenceModule]);
  if (referenceClosure.files.includes(adapterPath)) errors.push('independentReferenceModule must not import adapterModule');
}
const source = closure.files.map((file) => {
  try { return readFileSync(file, 'utf8'); }
  catch (error) { errors.push(`cannot read reachable verifier source ${file}: ${error.message}`); return ''; }
}).join('\n');
const sourceHashMap = manifest.verifierSourceSha256;
const closureNames = new Set(closure.files.map((file) => closure.relative(file)));
if (sourceHashMap && typeof sourceHashMap === 'object' && !Array.isArray(sourceHashMap)) {
  const missingHashes = [];
  const mismatchedHashes = [];
  for (const file of closure.files) {
    const relativeName = closure.relative(file);
    const expected = sourceHashMap[relativeName];
    if (!/^[0-9a-f]{64}$/i.test(String(expected ?? ''))) missingHashes.push(relativeName);
    else {
      try {
        const actual = createHash('sha256').update(readFileSync(file)).digest('hex');
        if (actual !== expected.toLowerCase()) mismatchedHashes.push(relativeName);
      } catch { mismatchedHashes.push(relativeName); }
    }
  }
  const extraHashes = Object.keys(sourceHashMap).filter((name) => !closureNames.has(name));
  if (missingHashes.length > 0) errors.push(`verifierSourceSha256 missing entries: ${missingHashes.join(', ')}`);
  if (mismatchedHashes.length > 0) errors.push(`verifierSourceSha256 mismatches: ${mismatchedHashes.join(', ')}`);
  if (extraHashes.length > 0) errors.push(`verifierSourceSha256 has extra entries: ${extraHashes.join(', ')}`);
}
const forbiddenSourcePatterns = [
  [/verifier\.cash\/fri-stark55\/category\/v1/, 'deterministic test category'],
  [/fibTrace|Fibonacci|Fib\(/, 'toy Fibonacci relation'],
  [/new Uint8Array\(32\)\.fill\(i \+ 1\)/, 'synthetic outpoint hashes'],
  [/new Uint8Array\(20\)\.fill\(0x55\)/, 'dummy recipient output'],
  [/valueSatoshis:\s*1_000n|valueSatoshis:\s*900n/, 'fixture satoshi values'],
  [/NUM_QUERIES\s*=\s*[1-9]\b|(?:three|five) FRI queries/i, 'tiny-query demonstrator parameter'],
  [/Math\.random\s*\(|Date\.now\s*\(|process\.env\b/, 'non-reproducible or environment-selected verifier behavior'],
  [/\b(?:import|require)\s*\(\s*(?!['"])/, 'non-literal dynamic module loading outside the pinned source closure'],
  [/sharedWitness|shared-witness/i, 'experimental shared-witness path is not production-audited'],
  [/loopFold|P3_LOOPFOLD/i, 'experimental fold-loop path is not production-audited'],
  [/\beval\s*\(|new\s+Function\s*\(|https?:\/\//i, 'dynamic/network-loaded verifier behavior'],
  [/(?:^|[^a-z])(toy|demo(?:nstrator)?|mock|placeholder|synthetic|fixture)(?:[^a-z]|$)/i, 'research-fixture language in production source'],
];
for (const [pattern, label] of forbiddenSourcePatterns) if (pattern.test(source)) errors.push(`release source still contains ${label}`);

const allManifestText = JSON.stringify(manifest);
if (containsFixtureLanguage(allManifestText)) errors.push('manifest contains fixture/mock language');

// The manifest's adapter path is not sufficient identity.  Load the exact
// adapter named by the manifest and require an explicit production declaration
// bound to the same statement.  This closes the label-only promotion path even
// when this release gate is invoked without verifier-bench.mjs.
try {
  const adapterUrl = pathToFileURL(resolve(repositoryRoot, manifest.adapterModule)).href;
  const adapter = await import(adapterUrl);
  if (typeof adapter.loadVerifierBench !== 'function') {
    errors.push('adapterModule must export loadVerifierBench()');
  } else {
    const candidate = await adapter.loadVerifierBench();
    const identityText = [
      candidate?.kind,
      candidate?.deploymentStatus,
      candidate?.statementId,
      candidate?.statementSpecSha256,
      candidate?.statementDescription,
    ].filter((value) => value !== undefined).join('\n');
    if (!candidate || typeof candidate !== 'object' ||
      candidate.kind !== 'production-adapter' ||
      candidate.deploymentStatus !== 'production' ||
      candidate.statementId !== statementId ||
      candidate.statementSpecSha256 !== statementSpecSha256 ||
      candidate.statementDescription !== statementDescription ||
      !/^[0-9a-f]{64}$/i.test(String(candidate.statementSpecSha256 ?? '')) ||
      candidate.queryCount !== manifest.queryCount ||
      candidate.securityTargetBits !== manifest.securityTargetBits ||
      candidate.soundnessModel !== manifest.soundnessModel ||
      candidate.proofBinding !== manifest.proofBinding ||
      containsFixtureLanguage(identityText)) {
      errors.push('adapter must declare production identity plus exact statement and security/binding parameters without fixture language');
    }
    if (!candidate || typeof candidate.valid !== 'object' || candidate.valid === null) {
      errors.push('adapter loadVerifierBench() must return a real valid bundle');
    }
    if (candidate?.reproducible !== true) errors.push('adapter must attest reproducible regeneration');
    if (!Array.isArray(candidate?.extraValid) || candidate.extraValid.length < 2) errors.push('adapter must provide at least two extra valid runtime proofs');
    if (!Array.isArray(candidate?.soundnessCases) || candidate.soundnessCases.length < 8) errors.push('adapter must provide at least eight soundness cases');
    if (!Array.isArray(candidate?.mutationCases) || candidate.mutationCases.length < 12) errors.push('adapter must provide at least twelve mutation cases');
    if (candidate?.reference?.validAccepted !== true || candidate?.reference?.invalidRejected !== true) {
      errors.push('adapter must report an independent valid/invalid differential');
    }
  }
} catch (error) {
  errors.push(`adapterModule failed to load for identity check: ${error instanceof Error ? error.message : String(error)}`);
}

if (errors.length > 0) {
  console.error('FRI-STARK55 RELEASE BLOCKED:');
  for (const error of errors) console.error(`- ${error}`);
  process.exitCode = 1;
  process.exit();
}

const digest = createHash('sha256').update(readFileSync(manifestUrl)).digest('hex');
console.log(`FRI-STARK55 RELEASE GATE PASS: manifest sha256=${digest}`);
