import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, open, readdir, realpath, rename, rm } from 'node:fs/promises';
import path from 'node:path';

import { canonicalizeJcs, deriveProfileId, validateProfileCore } from './profile-core.mjs';
import { verifyV2Pf10BetaRuntime } from '../../../scripts/v2-pf10-beta-runtime.mjs';
import { resolveV2BetaSingleContributorHistoricalCeremony } from '../../../scripts/v2-beta-single-contributor-ceremony.mjs';
import { consumeV2NativeGroth16ProverInstallation, loadV2NativeGroth16ProverInstallation } from '../../prove/v2/native-groth16-prover-installation.mjs';

export const V2_BETA_PRODUCT_ARTIFACT_INSTALLATION_SCHEMA = 'shieldkit-v2-beta-product-artifact-installation-v2';
export const V2_BETA_PRODUCT_ARTIFACT_RECEIPT = 'receipt.json';
const DESTINATION = 'v2-beta-product-artifacts';
const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const RECEIPT_IDENTITY_FIELDS = Object.freeze([
  'birthtimeNs', 'ctimeNs', 'dev', 'gid', 'ino',
  'mode', 'mtimeNs', 'nlink', 'size', 'uid',
]);
const BRANDS = new WeakMap();
const LINKED_TEMPLATE_BRANDS = new WeakMap();
export class V2BetaProductArtifactInstallationError extends Error { constructor(code, message, options = undefined) { super(message, options?.cause === undefined ? undefined : { cause: options.cause }); this.name = 'V2BetaProductArtifactInstallationError'; this.code = code; } }
const fail = (code, message, options = undefined) => { throw new V2BetaProductArtifactInstallationError(code, message, options); };
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
function exact(v, keys, label) { if (v === null || Array.isArray(v) || typeof v !== 'object' || Object.getPrototypeOf(v) !== Object.prototype) fail('BETA_ARTIFACT_INSTALL_INVALID', `${label} must be a plain object`); const a = Object.keys(v).sort(); const e = [...keys].sort(); if (a.length !== e.length || a.some((x, i) => x !== e[i])) fail('BETA_ARTIFACT_INSTALL_INVALID', `${label} has missing or unknown properties`); return v; }
function absolute(v, label) { if (typeof v !== 'string' || !path.isAbsolute(v) || path.normalize(v) !== v || v.includes('\0')) fail('BETA_ARTIFACT_INSTALL_INVALID', `${label} must be a normalized absolute path`); return v; }
async function privateDir(v, label) { const p = absolute(v, label); const s = await lstat(p, { bigint: true }).catch(e => fail('BETA_ARTIFACT_INSTALL_UNAVAILABLE', `${label} is unavailable`, { cause: e })); if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o777n) !== 0o700n || (process.getuid && s.uid !== BigInt(process.getuid())) || await realpath(p) !== p) fail('BETA_ARTIFACT_INSTALL_UNSAFE_PATH', `${label} must be a private canonical 0700 directory`); return p; }
function rel(root, file) { const r = path.relative(root, file); if (r === '' || r === '..' || r.startsWith(`..${path.sep}`) || path.isAbsolute(r)) fail('BETA_ARTIFACT_INSTALL_UNSAFE_PATH', 'artifact escapes its declared root'); return r.split(path.sep).join('/'); }
function identity(s) { return Object.freeze({ dev: s.dev.toString(), ino: s.ino.toString(), size: s.size.toString(), mode: s.mode.toString(), uid: s.uid.toString(), gid: s.gid.toString(), nlink: s.nlink.toString(), mtimeNs: s.mtimeNs.toString(), ctimeNs: s.ctimeNs.toString(), birthtimeNs: s.birthtimeNs.toString() }); }
function same(a,b) { return Object.keys(a).every(k => a[k] === b[k]); }
function receiptIdentity(value, label) {
  exact(value, RECEIPT_IDENTITY_FIELDS, label);
  if (RECEIPT_IDENTITY_FIELDS.some((field) => typeof value[field] !== 'string'
    || !DECIMAL.test(value[field]))) {
    fail('BETA_ARTIFACT_INSTALL_INVALID', `${label} must contain exact unsigned decimal fields`);
  }
  return value;
}

function updateFingerprintFrame(digest, tag, bytes) {
  const body = Buffer.from(bytes);
  digest.update(Buffer.from(`${tag}:${body.length}:`, 'utf8')).update(body);
}

function updateLinkedTemplateFingerprint(digest, value) {
  if (value instanceof Uint8Array) {
    updateFingerprintFrame(digest, 'bytes', value);
    return;
  }
  if (Array.isArray(value)) {
    updateFingerprintFrame(digest, 'array', Buffer.from(String(value.length), 'utf8'));
    for (const item of value) updateLinkedTemplateFingerprint(digest, item);
    return;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    updateFingerprintFrame(digest, 'object', Buffer.from(String(keys.length), 'utf8'));
    for (const key of keys) {
      updateFingerprintFrame(digest, 'key', Buffer.from(key, 'utf8'));
      updateLinkedTemplateFingerprint(digest, value[key]);
    }
    return;
  }
  if (value === null) {
    updateFingerprintFrame(digest, 'null', Buffer.alloc(0));
    return;
  }
  if (!['boolean', 'number', 'string'].includes(typeof value)) {
    fail('BETA_ARTIFACT_INSTALL_TEMPLATE_INVALID', 'linked runtime template contains an unsupported value');
  }
  updateFingerprintFrame(digest, typeof value, Buffer.from(String(value), 'utf8'));
}

function linkedTemplateFingerprint(value) {
  const digest = createHash('sha256');
  updateLinkedTemplateFingerprint(digest, value);
  return digest.digest('hex');
}
async function readPrivateMode(filename, label, mode) {
  const before = await lstat(filename, { bigint: true }).catch((error) => fail(
    'BETA_ARTIFACT_INSTALL_UNAVAILABLE',
    `${label} is unavailable`,
    { cause: error },
  ));
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
    || (before.mode & 0o777n) !== BigInt(mode) || await realpath(filename) !== filename) {
    fail(
      'BETA_ARTIFACT_INSTALL_UNSAFE_PATH',
      `${label} must be a private canonical ${mode.toString(8).padStart(4, '0')} single-link file`,
    );
  }
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = await handle.stat({ bigint: true });
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const named = await lstat(filename, { bigint: true });
    if (!same(identity(before), identity(opened))
      || !same(identity(opened), identity(after))
      || !same(identity(opened), identity(named))) {
      fail('BETA_ARTIFACT_INSTALL_RACE', `${label} changed while read`);
    }
    return { bytes, identity: identity(opened) };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}
const readPrivate = (filename, label) => readPrivateMode(filename, label, 0o600);
const readPrivateExecutable = (filename, label) => readPrivateMode(filename, label, 0o700);
async function syncRegularFile(filename, label) {
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const stat = await handle.stat({ bigint: true });
    if (!stat.isFile()) fail('BETA_ARTIFACT_INSTALL_UNSAFE_PATH', `${label} is not a regular file`);
    await handle.sync();
  } finally { await handle?.close().catch(() => undefined); }
}
async function syncDirectoryHierarchy(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) await syncDirectoryHierarchy(path.join(directory, entry.name));
  }
  const handle = await open(directory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}
async function files(root, prefix = '') { const out=[]; for (const entry of await readdir(root,{withFileTypes:true})) { const p=path.join(root,entry.name); const r=prefix?`${prefix}/${entry.name}`:entry.name; const s=await lstat(p,{bigint:true}); if(entry.isDirectory()) { if(s.isSymbolicLink()||await realpath(p)!==p) fail('BETA_ARTIFACT_INSTALL_UNSAFE_PATH',`unsafe source directory ${r}`); out.push(...await files(p,r)); } else if(entry.isFile()) { if(s.isSymbolicLink()||s.nlink!==1n||await realpath(p)!==p) fail('BETA_ARTIFACT_INSTALL_UNSAFE_PATH',`unsafe source file ${r}`); out.push(r); } else fail('BETA_ARTIFACT_INSTALL_UNSAFE_PATH',`unsafe entry ${r}`); } return out.sort(); }
function installedFileMode(section, relative) {
  return section === 'native' && relative === 'bin/prover' ? 0o700 : 0o600;
}

async function copyTree(source, destination, receipt, section) {
  await mkdir(destination, { mode: 0o700 });
  await chmod(destination, 0o700);
  for (const relative of await files(source)) {
    const from = path.join(source, ...relative.split('/'));
    const to = path.join(destination, ...relative.split('/'));
    const parent = path.dirname(to);
    await mkdir(parent, { recursive: true, mode: 0o700 });
    await chmod(parent, 0o700);
    const sourceStat = await lstat(from, { bigint: true });
    const mode = installedFileMode(section, relative);
    if ((sourceStat.mode & 0o777n) !== BigInt(mode)) {
      fail(
        'BETA_ARTIFACT_INSTALL_UNSAFE_PATH',
        `${section}/${relative} must have exact source mode ${mode.toString(8).padStart(4, '0')}`,
      );
    }
    await copyFile(from, to, fsConstants.COPYFILE_FICLONE);
    await chmod(to, mode);
    const copied = mode === 0o600
      ? await readPrivate(to, `copied ${relative}`)
      : await readPrivateExecutable(to, `copied ${relative}`);
    let sourceHandle;
    let sourceBytes;
    try {
      sourceHandle = await open(from, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      sourceBytes = await sourceHandle.readFile();
    } finally {
      await sourceHandle?.close().catch(() => undefined);
    }
    if (copied.bytes.length !== Number(sourceStat.size)
      || hash(copied.bytes) !== hash(sourceBytes)) {
      fail('BETA_ARTIFACT_INSTALL_COPY_REJECTED', `copied ${relative} differs from source`);
    }
    await syncRegularFile(to, `copied ${section}/${relative}`);
    receipt.push(Object.freeze({
      section,
      path: `${section}/${relative}`,
      bytes: copied.bytes.length,
      sha256: hash(copied.bytes),
      identity: copied.identity,
    }));
  }
}
async function writeReceipt(filename, value) { const bytes=Buffer.from(canonicalizeJcs(value),'utf8'); const tmp=`${filename}.${process.pid}.${randomUUID()}.tmp`; let h; try { h=await open(tmp,'wx',0o600); await h.writeFile(bytes); await h.chmod(0o600); await h.sync(); await h.close(); h=undefined; await rename(tmp,filename); const d=await open(path.dirname(filename),'r'); try{await d.sync();}finally{await d.close();} } finally { await h?.close().catch(()=>undefined); await rm(tmp,{force:true}).catch(()=>undefined); } }
async function productionVerify(input) { let runtimeManifest; const temporaryRoot=await mkdtemp(path.join(input.productDataDirectory,'.beta-artifact-verify-')); await chmod(temporaryRoot,0o700); try { const runtime=await verifyV2Pf10BetaRuntime({allowedOutputRoot:input.sourceRuntimeDirectory,outputDirectory:input.sourceRuntimeDirectory,temporaryRoot,onVerifiedRuntime:async ({manifest})=>{runtimeManifest=manifest;}}); const ceremony=await resolveV2BetaSingleContributorHistoricalCeremony({ceremonyDirectory:input.ceremonyDirectory}); const raw=(v)=>typeof v==='string'&&v.startsWith('sha256:')?v.slice(7):undefined; if(runtimeManifest?.profile?.ceremonyResultSha256!==ceremony.resultSha256||runtimeManifest?.proofArtifacts?.r1cs?.sha256!==raw(ceremony.artifacts.r1cs.sha256)||runtimeManifest?.proofArtifacts?.provingKey?.sha256!==raw(ceremony.artifacts.betaProvingKey.sha256)||runtimeManifest?.proofArtifacts?.verificationKey?.sha256!==raw(ceremony.artifacts.verificationKey.sha256)) fail('BETA_ARTIFACT_INSTALL_BINDING_REJECTED','runtime profile, circuit, proving-key, or verification-key binding differs from the resolved historical ceremony'); const native=await loadV2NativeGroth16ProverInstallation({installationDirectory:input.nativeProverInstallationDirectory}); const binary=await consumeV2NativeGroth16ProverInstallation(native); return {runtime,ceremony,native,binary}; } finally { await rm(temporaryRoot,{recursive:true,force:true}); } }
async function install(input, verify) { const productDataDirectory=await privateDir(input.productDataDirectory,'productDataDirectory'); const sourceRuntimeDirectory=await privateDir(input.sourceRuntimeDirectory,'sourceRuntimeDirectory'); const ceremonyDirectory=await privateDir(input.ceremonyDirectory,'ceremonyDirectory'); const nativeProverInstallationDirectory=await privateDir(input.nativeProverInstallationDirectory,'nativeProverInstallationDirectory'); const destination=path.join(productDataDirectory,DESTINATION); try { await lstat(destination); fail('BETA_ARTIFACT_INSTALL_EXISTS','product artifact destination already exists'); } catch(e) { if(e instanceof V2BetaProductArtifactInstallationError) throw e; if(e?.code!=='ENOENT') throw e; } const verified=await verify({productDataDirectory,sourceRuntimeDirectory,ceremonyDirectory,nativeProverInstallationDirectory}); const stage=await mkdtemp(path.join(productDataDirectory,'.beta-artifact-stage-')); await chmod(stage,0o700); try { const inventory=[]; await copyTree(sourceRuntimeDirectory,path.join(stage,'runtime'),inventory,'runtime'); await copyTree(ceremonyDirectory,path.join(stage,'ceremony'),inventory,'ceremony'); await copyTree(nativeProverInstallationDirectory,path.join(stage,'native'),inventory,'native'); const receipt=Object.freeze({schema:V2_BETA_PRODUCT_ARTIFACT_INSTALLATION_SCHEMA,status:'installed-beta-unqualified',runtime:verified.runtime,ceremony:{ceremonyId:verified.ceremony.ceremonyId,resultSha256:verified.ceremony.resultSha256,betaProvingKeySha256:verified.ceremony.betaProvingKeySha256,verificationKeySha256:verified.ceremony.verificationKeySha256},native:{manifestSha256:verified.native.manifestSha256,binarySha256:verified.binary.sha256},inventory:Object.freeze(inventory)}); await writeReceipt(path.join(stage,V2_BETA_PRODUCT_ARTIFACT_RECEIPT),receipt); await syncDirectoryHierarchy(stage); await rename(stage,destination); const d=await open(productDataDirectory,fsConstants.O_RDONLY|fsConstants.O_DIRECTORY|fsConstants.O_NOFOLLOW);try{await d.sync();}finally{await d.close();} return Object.freeze({installationDirectory:destination,receiptSha256:hash(Buffer.from(canonicalizeJcs(receipt),'utf8')),bytes:inventory.reduce((n,e)=>n+e.bytes,0)}); } catch(e) { await rm(stage,{recursive:true,force:true}).catch(()=>undefined); throw e; } }
export async function installV2BetaProductArtifacts(value) { exact(value,['ceremonyDirectory','nativeProverInstallationDirectory','productDataDirectory','sourceRuntimeDirectory'],'beta product artifact install input'); return install(value,productionVerify); }
export async function installV2BetaProductArtifactsForTest(value, dependencies) { exact(value,['ceremonyDirectory','nativeProverInstallationDirectory','productDataDirectory','sourceRuntimeDirectory'],'beta product artifact test install input'); exact(dependencies,['verify'],'beta product artifact test dependencies'); if(typeof dependencies.verify!=='function') fail('BETA_ARTIFACT_INSTALL_INVALID','test verify must be a function'); return install(value,dependencies.verify); }
export async function loadV2BetaProductArtifactInstallation({ productDataDirectory } = {}) {
  const root = await privateDir(productDataDirectory, 'productDataDirectory');
  const directory = await privateDir(path.join(root, DESTINATION), 'artifact installation');
  const receipt = await readPrivate(
    path.join(directory, V2_BETA_PRODUCT_ARTIFACT_RECEIPT),
    'artifact receipt',
  );
  let value;
  try {
    value = JSON.parse(receipt.bytes);
    if (!receipt.bytes.equals(Buffer.from(canonicalizeJcs(value), 'utf8'))) {
      fail('BETA_ARTIFACT_INSTALL_INVALID', 'artifact receipt must use exact JCS');
    }
  } catch (error) {
    if (error instanceof V2BetaProductArtifactInstallationError) throw error;
    fail('BETA_ARTIFACT_INSTALL_INVALID', 'artifact receipt is invalid', { cause: error });
  }
  exact(value, ['ceremony', 'inventory', 'native', 'runtime', 'schema', 'status'], 'artifact receipt');
  if (value.schema !== V2_BETA_PRODUCT_ARTIFACT_INSTALLATION_SCHEMA
    || value.status !== 'installed-beta-unqualified'
    || !Array.isArray(value.inventory)) {
    fail('BETA_ARTIFACT_INSTALL_INVALID', 'artifact receipt boundary is invalid');
  }
  const seen = new Set();
  for (const entry of value.inventory) {
    exact(entry, ['bytes', 'identity', 'path', 'section', 'sha256'], 'artifact receipt inventory entry');
    if (!HASH.test(entry.sha256) || !Number.isSafeInteger(entry.bytes) || entry.bytes <= 0
      || !['runtime', 'ceremony', 'native'].includes(entry.section)
      || typeof entry.path !== 'string' || entry.path.includes('\\')) {
      fail('BETA_ARTIFACT_INSTALL_INVALID', 'artifact receipt inventory entry is invalid');
    }
    const parts = entry.path.split('/');
    if (parts.length < 2 || parts[0] !== entry.section
      || parts.some((part) => part === '' || part === '.' || part === '..')
      || seen.has(entry.path)) {
      fail('BETA_ARTIFACT_INSTALL_INVALID', 'artifact receipt inventory path is unsafe or duplicated');
    }
    seen.add(entry.path);
    const relative = parts.slice(1).join('/');
    const expectedMode = installedFileMode(entry.section, relative);
    const storedIdentity = receiptIdentity(
      entry.identity,
      `artifact receipt identity for ${entry.path}`,
    );
    if ((BigInt(storedIdentity.mode) & 0o777n) !== BigInt(expectedMode)
      || BigInt(storedIdentity.size) !== BigInt(entry.bytes)
      || BigInt(storedIdentity.nlink) !== 1n) {
      fail('BETA_ARTIFACT_INSTALL_INVALID', `artifact receipt mode is invalid for ${entry.path}`);
    }
    const filename = path.join(directory, ...parts);
    const stat = await lstat(filename, { bigint: true }).catch((error) => fail(
      'BETA_ARTIFACT_INSTALL_UNAVAILABLE',
      `installed artifact ${entry.path} is unavailable`,
      { cause: error },
    ));
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
      || (stat.mode & 0o777n) !== BigInt(expectedMode)
      || await realpath(filename) !== filename) {
      fail('BETA_ARTIFACT_INSTALL_UNSAFE_PATH', `installed artifact ${entry.path} is unsafe`);
    }
    if (!same(storedIdentity, identity(stat))) {
      fail(
        'BETA_ARTIFACT_INSTALL_RACE',
        `installed artifact ${entry.path} identity differs; reinstallation is required`,
      );
    }
  }
  if (!seen.has('native/bin/prover') || !seen.has('native/manifest.json')) {
    fail('BETA_ARTIFACT_INSTALL_INVALID', 'artifact receipt lacks the exact native prover payload');
  }
  exact(value.native, ['binarySha256', 'manifestSha256'], 'artifact receipt.native');
  if (!HASH.test(value.native.binarySha256) || !HASH.test(value.native.manifestSha256)) {
    fail('BETA_ARTIFACT_INSTALL_INVALID', 'artifact receipt native hashes are invalid');
  }
  const nativeManifest = value.inventory.find((entry) => entry.path === 'native/manifest.json');
  const nativeBinary = value.inventory.find((entry) => entry.path === 'native/bin/prover');
  if (nativeManifest?.sha256 !== value.native.manifestSha256
    || nativeBinary?.sha256 !== value.native.binarySha256) {
    fail('BETA_ARTIFACT_INSTALL_INVALID', 'artifact receipt native hashes are not bound to its exact inventory');
  }
  const capability = Object.freeze({
    schema: value.schema,
    installationDirectory: directory,
    receiptSha256: hash(receipt.bytes),
    runtimeDirectory: path.join(directory, 'runtime'),
    ceremonyDirectory: path.join(directory, 'ceremony'),
    nativeProverInstallationDirectory: path.join(directory, 'native'),
  });
  BRANDS.set(capability, Object.freeze({ receipt: value }));
  return capability;
}
export function assertV2BetaProductArtifactInstallationCapability(value) { if(!BRANDS.has(value)) fail('BETA_ARTIFACT_INSTALL_CAPABILITY_REQUIRED','a locally loaded beta product artifact installation capability is required'); return value; }

/**
 * Return native-prover metadata only from a receipt-authenticated installation
 * capability. The records remain unavailable to structural lookalikes; the
 * native module performs its own canonical private identity checks before
 * creating its separate proving capability.
 */
export function deriveV2BetaProductNativeProverReceipt(value) {
  assertV2BetaProductArtifactInstallationCapability(value);
  const metadata = BRANDS.get(value);
  const manifest = metadata.receipt.inventory.find((entry) => entry.path === 'native/manifest.json');
  const binary = metadata.receipt.inventory.find((entry) => entry.path === 'native/bin/prover');
  if (manifest === undefined || binary === undefined
    || manifest.sha256 !== metadata.receipt.native.manifestSha256
    || binary.sha256 !== metadata.receipt.native.binarySha256) {
    fail('BETA_ARTIFACT_INSTALL_CAPABILITY_REQUIRED', 'artifact installation lacks receipt-bound native prover metadata');
  }
  return Object.freeze({
    installationDirectory: value.nativeProverInstallationDirectory,
    receiptSha256: value.receiptSha256,
    manifest: Object.freeze({
      path: path.join(value.installationDirectory, 'native', 'manifest.json'),
      bytes: manifest.bytes,
      sha256: manifest.sha256,
      identity: Object.freeze({ ...manifest.identity }),
    }),
    binary: Object.freeze({
      path: path.join(value.installationDirectory, 'native', 'bin', 'prover'),
      bytes: binary.bytes,
      sha256: binary.sha256,
      identity: Object.freeze({ ...binary.identity }),
    }),
  });
}

const LINKED_RUNTIME_FILES = {
  runtimeManifest: 'runtime/beta-runtime-manifest.json',
  runtimeMaterial: 'runtime/runtime/beta-runtime-material.json',
  profileCore: 'runtime/profile/profile-core.json',
  verificationKey: 'runtime/proof/verification_key.json',
  executorBody: 'runtime/runtime/executorBody.bin',
  fusedRedeem: 'runtime/runtime/fusedRedeem.bin',
  terminalRedeem: 'runtime/runtime/terminalRedeem.bin',
  bindingLock: 'runtime/structural/bindingLock.bin',
  bindingRedeem: 'runtime/structural/bindingRedeem.bin',
  stateHelper: 'runtime/structural/stateHelper.bin',
  stateLock: 'runtime/structural/stateLock.bin',
  stateUnlock: 'runtime/structural/stateUnlock.bin',
  exactFinalSource: 'runtime/reproducibility/exactFinal.cash',
  exactFinalRaw: 'runtime/reproducibility/exactFinal.raw.bin',
  exactFinalRedeem: 'runtime/reproducibility/exactFinal.redeem.bin',
  millerSource: 'runtime/reproducibility/miller.cash',
  millerRaw: 'runtime/reproducibility/miller.raw.bin',
  millerRedeem: 'runtime/reproducibility/miller.redeem.bin',
  executorSource: 'runtime/reproducibility/executor.cash',
  executorRaw: 'runtime/reproducibility/executor.raw.bin',
  terminalSource: 'runtime/reproducibility/terminal.cash',
  terminalRaw: 'runtime/reproducibility/terminal.raw.bin',
};
for (let index = 0; index < 3; index += 1) {
  LINKED_RUNTIME_FILES[`exactMsm${index}Redeem`] = `runtime/runtime/exact-msm-${index}.bin`;
  LINKED_RUNTIME_FILES[`exactMsm${index}Source`] = `runtime/reproducibility/exactMsm-${index}.cash`;
  LINKED_RUNTIME_FILES[`exactMsm${index}Raw`] = `runtime/reproducibility/exactMsm-${index}.raw.bin`;
  LINKED_RUNTIME_FILES[`exactMsm${index}Redeem`] = `runtime/runtime/exact-msm-${index}.bin`;
  LINKED_RUNTIME_FILES[`fixedCarrierPad${index}`] = `runtime/runtime/fixed-carrier-pad-${index}.bin`;
}
for (let index = 0; index < 10; index += 1) {
  LINKED_RUNTIME_FILES[`verifierLock${index}`] = `runtime/structural/verifier-lock-${index}.bin`;
}
Object.freeze(LINKED_RUNTIME_FILES);

function receiptEntry(metadata, relative, label) {
  const entry = metadata.receipt.inventory.find((candidate) => candidate.path === relative);
  if (entry === undefined || entry.section !== 'runtime') {
    fail('BETA_ARTIFACT_INSTALL_TEMPLATE_UNAVAILABLE', `linked runtime template requires retained ${label}`);
  }
  return entry;
}

async function readReceiptPinnedRuntimeFile(value, metadata, relative, label) {
  const entry = receiptEntry(metadata, relative, label);
  const filename = path.join(value.installationDirectory, ...relative.split('/'));
  const inspected = await readPrivate(filename, `linked runtime template ${label}`);
  if (inspected.bytes.length !== entry.bytes || hash(inspected.bytes) !== entry.sha256
    || !same(inspected.identity, entry.identity)) {
    fail('BETA_ARTIFACT_INSTALL_RACE', `linked runtime template ${label} differs from its receipt`);
  }
  return Object.freeze({ bytes: Buffer.from(inspected.bytes), entry: Object.freeze({ bytes: entry.bytes, path: entry.path, sha256: entry.sha256 }) });
}

/**
 * Read the fixed, receipt-authenticated sub-200 KB linker template. This is
 * intentionally a fixed allow-list: no manifest path can select an adjacent
 * artifact, and proving key/R1CS/WASM are never opened here.
 */
export async function deriveV2BetaProductLinkedRuntimeTemplate(value) {
  const metadata = BRANDS.get(value);
  if (metadata === undefined) fail('BETA_ARTIFACT_INSTALL_CAPABILITY_REQUIRED', 'linked runtime template requires a loaded product artifact capability');
  const files = Object.fromEntries(await Promise.all(Object.entries(LINKED_RUNTIME_FILES).map(async ([name, relative]) => [name, await readReceiptPinnedRuntimeFile(value, metadata, relative, name)])));
  let manifest; let material; let profileCore;
  try {
    manifest = JSON.parse(files.runtimeManifest.bytes.toString('utf8'));
    material = JSON.parse(files.runtimeMaterial.bytes.toString('utf8'));
    profileCore = JSON.parse(files.profileCore.bytes.toString('utf8'));
  } catch (error) { fail('BETA_ARTIFACT_INSTALL_TEMPLATE_INVALID', 'linked runtime template JSON is invalid', { cause: error }); }
  validateProfileCore(profileCore);
  const profileId = deriveProfileId(profileCore);
  if (manifest?.identity?.maximumLiveNotes !== '100000'
    || typeof manifest?.identity?.instanceId !== 'string' || !HASH.test(manifest.identity.instanceId)
    || manifest?.profile?.profileId !== profileId
    || material?.instanceId !== manifest.identity.instanceId
    || material?.profileId !== profileId
    || material?.materialSha256 !== manifest?.runtime?.materialSha256) {
    fail('BETA_ARTIFACT_INSTALL_TEMPLATE_INVALID', 'linked runtime template identity is not receipt-bound beta-100000 material');
  }
  const proofArtifacts = Object.freeze(Object.fromEntries([
    ['provingKey', 'runtime/proof/beta.zkey'],
    ['r1cs', 'runtime/proof/main-chipnet.r1cs'],
    ['verificationKey', 'runtime/proof/verification_key.json'],
    ['wasm', 'runtime/proof/main-chipnet.wasm'],
  ].map(([name, relative]) => {
    const entry = receiptEntry(metadata, relative, `proof ${name}`);
    if (material?.proofArtifactHashes?.[name] !== entry.sha256) fail('BETA_ARTIFACT_INSTALL_TEMPLATE_INVALID', `linked runtime template proof ${name} differs from its receipt`);
    return [name, Object.freeze({ bytes: entry.bytes, path: entry.path, sha256: entry.sha256, identity: Object.freeze({ ...entry.identity }) })];
  })));
  const bytes = (name) => files[name].bytes;
  const program = (name, redeemName = `${name}Redeem`) => Object.freeze({ source: bytes(`${name}Source`).toString('utf8'), raw: bytes(`${name}Raw`), redeem: bytes(redeemName) });
  const { materialSha256: _materialSha256, ...runtimeMaterialInputBase } = material;
  const linkedTemplate = Object.freeze({
    installationReceiptSha256: value.receiptSha256,
    templateRuntimeManifestSha256: files.runtimeManifest.entry.sha256,
    identity: Object.freeze({ instanceId: manifest.identity.instanceId, profileId, maximumLiveNotes: '100000', denominationSats: '10000000' }),
    profileCore: Object.freeze(JSON.parse(canonicalizeJcs(profileCore))),
    proofArtifacts,
    // This is deliberately the exact retained input shape expected by the
    // native linker. exactFinal/miller canonical redeems are not invented by
    // this profile layer; the native capability must supply/assert them.
    template: Object.freeze({
      instanceId: manifest.identity.instanceId,
      layout: Object.freeze({ ...manifest.runtime.layout }),
      fixedTables: Object.freeze({ ...manifest.runtime.fixedTables }),
      runtimeMaterial: Object.freeze({ ...material }),
      runtimeMaterialInput: Object.freeze({
        ...runtimeMaterialInputBase,
        verificationKeyBytes: bytes('verificationKey'), executorBody: bytes('executorBody'),
        exactMsmRedeems: Object.freeze([bytes('exactMsm0Redeem'), bytes('exactMsm1Redeem'), bytes('exactMsm2Redeem')]),
        fixedCarrierPads: Object.freeze([bytes('fixedCarrierPad0'), bytes('fixedCarrierPad1'), bytes('fixedCarrierPad2')]),
        fusedRedeem: bytes('fusedRedeem'), terminalRedeem: bytes('terminalRedeem'),
        stateUnlockingBytecode: bytes('stateUnlock'), bindingRedeemBytecode: bytes('bindingRedeem'), bindingLockingBytecode: bytes('bindingLock'),
        verifierLockingBytecodes: Object.freeze([...Array(10).keys()].map((index) => bytes(`verifierLock${index}`))),
      }),
      structural: Object.freeze({ bindingLock: bytes('bindingLock'), bindingRedeem: bytes('bindingRedeem'), stateHelper: bytes('stateHelper'), stateLock: bytes('stateLock'), stateUnlock: bytes('stateUnlock'), verifierLocks: Object.freeze([...Array(10).keys()].map((index) => bytes(`verifierLock${index}`))) }),
      programs: Object.freeze({ terminal: program('terminal'), executor: program('executor', 'executorBody'), exactFinal: program('exactFinal'), miller: program('miller'), exactMsm: Object.freeze([program('exactMsm0'), program('exactMsm1'), program('exactMsm2')]) }),
    }),
  });
  LINKED_TEMPLATE_BRANDS.set(linkedTemplate, Object.freeze({
    fingerprint: linkedTemplateFingerprint(linkedTemplate),
  }));
  return linkedTemplate;
}

/**
 * Reject serialized lookalikes and mutable-buffer drift. This capability is
 * issued only after the fixed linker allow-list has been matched to the
 * once-verified installation receipt.
 */
export function assertV2BetaProductLinkedRuntimeTemplateCapability(value) {
  const record = LINKED_TEMPLATE_BRANDS.get(value);
  if (record === undefined) {
    fail(
      'BETA_ARTIFACT_INSTALL_TEMPLATE_CAPABILITY_REQUIRED',
      'a receipt-authenticated linked runtime template capability is required',
    );
  }
  if (linkedTemplateFingerprint(value) !== record.fingerprint) {
    fail(
      'BETA_ARTIFACT_INSTALL_TEMPLATE_CAPABILITY_STALE',
      'linked runtime template bytes changed after receipt authentication',
    );
  }
  return value;
}
