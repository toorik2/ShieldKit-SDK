import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

import { canonicalJson, parseStrictJson } from "../packages/profile/load.mjs";
import { V2_Q07_DATASET_SCHEMA } from "./v2-q07-dataset.mjs";
import { V2_Q07_REFERENCE_MACHINE_SCHEMA } from "./v2-q07-performance-harness.mjs";
import { Q04_RESULT_SCHEMA } from "./v2-q04-evidence-verify.mjs";
import { verifyQ07Evidence } from "./v2-q07-evidence.mjs";

export const Q07_BUNDLE_SCHEMA = "shieldkit-v2-direct/q07-evidence-bundle/v1";
export const Q07_BUNDLE_RESULT_SCHEMA = "shieldkit-v2-direct/q07-evidence-bundle-result/v1";
const HASH = /^[0-9a-f]{64}$/;
export class Q07BundleVerifyError extends Error { constructor(message) { super(message); this.name = "Q07BundleVerifyError"; } }
const fail = (m) => { throw new Q07BundleVerifyError(m); };
const exact = (v, keys, label) => { if (!v || Array.isArray(v) || typeof v !== "object") fail(`${label} must be an object`); const a = Object.keys(v).sort(), e = [...keys].sort(); if (a.length !== e.length || a.some((x, i) => x !== e[i])) fail(`${label} has missing or unknown fields`); return v; };
const hash = (b) => createHash("sha256").update(b).digest("hex");
const h = (v, l) => { if (typeof v !== "string" || !HASH.test(v)) fail(`${l} must be SHA-256 hex`); return v; };
function file(root, path, label) {
  if (typeof path !== "string" || path.length === 0 || isAbsolute(path) || path.includes("\\") || path.split("/").some((p) => p === "" || p === "." || p === "..")) fail(`${label} path is not a contained relative path`);
  const absolute = resolve(root, path);
  if (relative(root, absolute).startsWith(`..${sep}`) || relative(root, absolute) === "") fail(`${label} escapes bundle root`);
  let s; try { s = lstatSync(absolute); } catch { fail(`${label} is missing`); }
  if (
    !s.isFile() || s.isSymbolicLink() || s.nlink !== 1 ||
    realpathSync(absolute) !== absolute || (s.mode & 0o777) !== 0o600 ||
    (typeof process.getuid === "function" && s.uid !== process.getuid())
  ) fail(`${label} must be a direct single-link user-owned mode-0600 regular file`);
  return absolute;
}
function readDirect(path, label) {
  const named = lstatSync(path);
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const initial = fstatSync(descriptor);
    if (
      initial.dev !== named.dev || initial.ino !== named.ino ||
      initial.nlink !== 1 || (initial.mode & 0o777) !== 0o600 ||
      (typeof process.getuid === "function" && initial.uid !== process.getuid())
    ) fail(`${label} changed before it was opened`);
    const bytes = readFileSync(descriptor);
    const final = fstatSync(descriptor);
    if (
      final.dev !== initial.dev || final.ino !== initial.ino ||
      final.size !== initial.size || final.mtimeMs !== initial.mtimeMs ||
      final.ctimeMs !== initial.ctimeMs || final.nlink !== 1
    ) fail(`${label} changed while it was read`);
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}
function json(bytes, label, canonical = false) { let v; try { v = parseStrictJson(bytes); } catch (e) { fail(`${label} is not strict JSON: ${e.message}`); } if (canonical && Buffer.from(canonicalJson(v)).compare(Buffer.from(bytes)) !== 0) fail(`${label} is not canonical JSON`); return v; }
function walk(root, cursor = "") { const found = []; for (const name of readdirSync(resolve(root, cursor))) { const rel = cursor ? `${cursor}/${name}` : name; const p = resolve(root, rel); const s = lstatSync(p); if (s.isSymbolicLink()) fail(`bundle contains symlink ${rel}`); if (s.isDirectory()) found.push(...walk(root, rel)); else if (s.isFile()) { if (s.nlink !== 1) fail(`bundle contains hardlinked file ${rel}`); found.push(rel); } else fail(`bundle contains non-regular entry ${rel}`); } return found; }
function dataset(v, evidence) { exact(v, ["count", "edgeEvidence", "mainCount", "qualification", "qualifyingShape", "schema", "sha256", "transcriptSha256", "warmSampleOrdinal"], "dataset verification"); exact(v.edgeEvidence, ["frMinusOneKey", "frMinusOneOrdinal", "zeroKey", "zeroOrdinal"], "dataset edge evidence"); if (v.schema !== V2_Q07_DATASET_SCHEMA || v.mainCount !== 100000 || v.count !== 100001 || v.warmSampleOrdinal !== 100001 || v.edgeEvidence.zeroOrdinal !== 1 || v.edgeEvidence.zeroKey !== "00".repeat(32) || v.edgeEvidence.frMinusOneOrdinal !== 2 || v.edgeEvidence.frMinusOneKey !== "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000") fail("dataset verification has wrong full-history shape"); if (v.sha256 !== evidence.dataset.rawKeyStreamSha256 || v.transcriptSha256 !== evidence.dataset.transcriptSha256) fail("dataset verification does not bind evidence hashes"); }
function q04(v) { exact(v, ["gate", "q04GatePass", "q04Verdict", "schema", "status"], "Q04 verification"); if (v.schema !== Q04_RESULT_SCHEMA || v.gate !== "Q-04" || v.status !== "verified" || v.q04GatePass !== true || v.q04Verdict !== "pass-bounded-100000-and-depth4-shared-kernel") fail("Q04 verification is not exact green v3 evidence"); }
function reference(v, evidence) { exact(v, ["attestation", "hardware", "hostName", "operatingSystem", "runtime", "schema", "sha256"], "reference machine"); if (v.schema !== V2_Q07_REFERENCE_MACHINE_SCHEMA) fail("reference machine schema differs"); const unsigned = { schema: v.schema, attestation: v.attestation, hostName: v.hostName, runtime: v.runtime, operatingSystem: v.operatingSystem, hardware: v.hardware }; if (hash(Buffer.from(JSON.stringify(unsigned))) !== v.sha256 || v.sha256 !== evidence.referenceMachine.manifestSha256) fail("reference machine self-hash differs"); }
function pf10(v, evidence) { exact(v, ["actions", "eligibility", "instanceId", "profileId", "runtimeMaterialSha256", "schema"], "PF10 binding"); if (v.schema !== "shieldkit-v2-direct/q07-pf10-binding/v1" || v.eligibility !== evidence.finalPf10.eligibility || v.profileId !== evidence.subject.profileId || v.instanceId !== evidence.subject.instanceId || v.runtimeMaterialSha256 !== evidence.subject.runtimeMaterialSha256 || canonicalJson(v.actions) !== canonicalJson(evidence.finalPf10.actions)) fail("PF10 artifact does not bind evidence action rows or subject"); }

export function verifyQ07EvidenceBundle(bundlePath) {
  if (typeof bundlePath !== "string" || !isAbsolute(bundlePath) || resolve(bundlePath) !== bundlePath) fail("bundle path must be absolute normalized");
  const root = bundlePath; const rootStat = lstatSync(root); if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || realpathSync(root) !== root || (rootStat.mode & 0o777) !== 0o700 || (typeof process.getuid === "function" && rootStat.uid !== process.getuid())) fail("bundle root must be a direct user-owned mode-0700 directory");
  const manifestPath = file(root, "manifest.json", "manifest"); const manifestBytes = readDirect(manifestPath, "manifest"); const manifest = json(manifestBytes, "manifest", true);
  exact(manifest, ["artifacts", "schema"], "manifest"); if (manifest.schema !== Q07_BUNDLE_SCHEMA || !Array.isArray(manifest.artifacts) || manifest.artifacts.length < 5) fail("manifest schema or artifacts differ");
  const paths = new Set(), hashes = new Set(), roles = new Set(), artifacts = new Map();
  for (const entry of manifest.artifacts) { exact(entry, ["bytes", "path", "role", "sha256"], "manifest artifact"); if (!Number.isSafeInteger(entry.bytes) || entry.bytes < 1 || typeof entry.role !== "string" || !/^[a-z][a-z0-9-]*$/.test(entry.role) || paths.has(entry.path) || hashes.has(h(entry.sha256, "artifact.sha256")) || roles.has(entry.role)) fail("manifest artifact path, hash, or role is ambiguous"); const p = file(root, entry.path, `artifact ${entry.role}`); const b = readDirect(p, `artifact ${entry.role}`); if (b.length !== entry.bytes || hash(b) !== entry.sha256) fail(`artifact ${entry.role} byte count or hash differs`); paths.add(entry.path); hashes.add(entry.sha256); roles.add(entry.role); artifacts.set(entry.role, { ...entry, declaredBytes: entry.bytes, bytes: b, absolute: p }); }
  const actual = new Set(walk(root)); for (const p of actual) if (p !== "manifest.json" && !paths.has(p)) fail(`bundle has unreferenced file ${p}`);
  for (const p of paths) if (!actual.has(p)) fail(`manifest artifact disappeared ${p}`);
  for (const role of ["evidence", "q04-verification", "q07-dataset-verification", "reference-machine", "pf10"]) if (!artifacts.has(role)) fail(`manifest lacks ${role}`);
  const evidenceArtifact = artifacts.get("evidence"); const rereadEvidence = readDirect(evidenceArtifact.absolute, "evidence"); if (rereadEvidence.length !== evidenceArtifact.declaredBytes || hash(rereadEvidence) !== evidenceArtifact.sha256) fail("evidence changed after manifest verification"); const evidence = json(rereadEvidence, "evidence"); const evidenceResult = verifyQ07Evidence(evidence);
  q04(json(artifacts.get("q04-verification").bytes, "Q04 verification")); dataset(json(artifacts.get("q07-dataset-verification").bytes, "dataset verification"), evidence); reference(json(artifacts.get("reference-machine").bytes, "reference machine"), evidence); pf10(json(artifacts.get("pf10").bytes, "PF10 binding"), evidence);
  const requireHashRole = (sha, role) => { const a = artifacts.get(role); if (!a || a.sha256 !== sha) fail(`evidence reference does not resolve to manifest role ${role}`); };
  requireHashRole(evidence.dataset.verificationArtifactSha256, "q07-dataset-verification"); requireHashRole(evidence.dataset.q04VerificationArtifactSha256, "q04-verification"); requireHashRole(evidence.finalPf10.evidenceArtifactSha256, "pf10");
  for (const [key, ref] of Object.entries(evidence.prerequisites)) if (ref.status === "verified") requireHashRole(ref.sha256, key === "q04Verification" ? "q04-verification" : key === "finalPf10" ? "pf10" : key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`));
  if (evidence.actionHistory.status !== "unavailable" || evidence.proofGeneration.status !== "unavailable" || evidence.store.status !== "unavailable" || Object.values(evidence.phases).some((p) => p.status !== "unavailable")) fail("unsupported measured or verified phase artifacts are rejected");
  if (evidenceResult.q07Qualified) fail("qualified evidence cannot pass without supported phase artifacts");
  return Object.freeze({ schema: Q07_BUNDLE_RESULT_SCHEMA, status: evidenceResult.status, q07Qualified: false, artifactCount: artifacts.size, profileId: evidenceResult.profileId, instanceId: evidenceResult.instanceId });
}
