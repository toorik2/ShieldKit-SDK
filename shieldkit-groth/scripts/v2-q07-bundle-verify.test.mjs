import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, linkSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson } from "../packages/profile/load.mjs";
import { Q04_RESULT_SCHEMA } from "./v2-q04-evidence-verify.mjs";
import { V2_Q07_DATASET_SCHEMA } from "./v2-q07-dataset.mjs";
import { V2_Q07_REFERENCE_MACHINE_SCHEMA } from "./v2-q07-performance-harness.mjs";
import { Q07_BUNDLE_SCHEMA, verifyQ07EvidenceBundle } from "./v2-q07-bundle-verify.mjs";

const hash = (v) => createHash("sha256").update(v).digest("hex");
const d = (c = "a") => c.repeat(64); const git = (c = "b") => c.repeat(40);
const unavailable = () => ({ status: "unavailable", reason: "external prerequisite unavailable", evidence: null });
function write(root, path, value) { const bytes = Buffer.from(canonicalJson(value)); writeFileSync(join(root, path), bytes, { mode: 0o600 }); chmodSync(join(root, path), 0o600); return { path, bytes: bytes.length, sha256: hash(bytes) }; }
function build(root, tweak = undefined) {
  const q04 = write(root, "q04.json", { schema: Q04_RESULT_SCHEMA, status: "verified", gate: "Q-04", q04GatePass: true, q04Verdict: "pass-bounded-100000-and-depth4-shared-kernel" });
  const dataset = write(root, "dataset.json", { schema: V2_Q07_DATASET_SCHEMA, mainCount: 100000, count: 100001, warmSampleOrdinal: 100001, sha256: d("1"), transcriptSha256: d("2"), edgeEvidence: { zeroOrdinal: 1, zeroKey: "00".repeat(32), frMinusOneOrdinal: 2, frMinusOneKey: "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000" }, qualifyingShape: true, qualification: "dataset-shape-only-not-q07-performance-qualified" });
  const refUnsigned = { schema: V2_Q07_REFERENCE_MACHINE_SCHEMA, attestation: "local-unattested", hostName: "test", runtime: { node: "x", v8: "x", sqlite: null }, operatingSystem: { architecture: "x", platform: "x", release: "x" }, hardware: { cpuModels: ["x"], logicalCores: 1, totalMemoryBytes: 1 } };
  const referenceHashMaterial = { ...refUnsigned, runtime: { node: "x", sqlite: null, v8: "x" } };
  const referenceValue = { ...refUnsigned, sha256: hash(Buffer.from(JSON.stringify(referenceHashMaterial))) };
  const reference = write(root, "machine.json", referenceValue);
  const subject = { eligibility: "development-only", profileId: d("3"), instanceId: d("4"), runtimeMaterialSha256: d("5"), sourceSetSha256: d("6"), gitCommit: git(), gitTree: git("c") };
  const input = (inputIndex) => ({ inputIndex, accepted: true, unlockBytes: 1, operationCost: 0, maximumOperationCost: 1, hashDigestIterations: 0, maximumHashDigestIterations: 1, signatureCheckCount: 0, maximumSignatureChecks: 1 });
  const actions = ["deposit", "transfer", "withdrawal"].map((kind) => ({ kind, transactionBytes: 1, inputCount: 13, inputs: Array.from({ length: 13 }, (_, inputIndex) => input(inputIndex)) }));
  const pf10 = write(root, "pf10.json", { schema: "shieldkit-v2-direct/q07-pf10-binding/v1", eligibility: subject.eligibility, profileId: subject.profileId, instanceId: subject.instanceId, runtimeMaterialSha256: subject.runtimeMaterialSha256, actions });
  const evidence = { schema: "shieldkit-v2-direct/q07-performance-qualification/v1", verdict: { status: "blocked-external-prerequisites", reasons: ["external finalization unavailable"] }, subject, actionHistory: { status: "unavailable", reason: "no final corpus", evidence: null }, prerequisites: { q04Verification: { status: "verified", sha256: q04.sha256, reason: null }, finalProfile: { status: "unavailable", sha256: null, reason: "unavailable" }, finalCeremony: { status: "unavailable", sha256: null, reason: "unavailable" }, finalKey: { status: "unavailable", sha256: null, reason: "unavailable" }, finalPf10: { status: "unavailable", sha256: null, reason: "unavailable" } }, referenceMachine: { attestation: "local-unattested", cgroupV2: false, manifestSha256: referenceValue.sha256 }, dataset: { historyCount: 1, historyActions: 100000, mainCount: 100000, keyCount: 100001, warmSampleOrdinal: 100001, zeroEdgeOrdinal: 1, frMinusOneEdgeOrdinal: 2, rawKeyStreamSha256: d("1"), transcriptSha256: d("2"), verificationArtifactSha256: dataset.sha256, q04VerificationArtifactSha256: q04.sha256, q04VerificationStatus: "verified", q04GatePass: true }, proofGeneration: unavailable(), store: unavailable(), phases: { bottomUpSnapshotAuthentication: unavailable(), rawFallback: unavailable(), suffixReplay: unavailable(), warmUpdate: unavailable(), coldIo: unavailable() }, finalPf10: { eligibility: subject.eligibility, profileId: subject.profileId, instanceId: subject.instanceId, runtimeMaterialSha256: subject.runtimeMaterialSha256, sourceSetSha256: subject.sourceSetSha256, gitCommit: subject.gitCommit, gitTree: subject.gitTree, evidenceArtifactSha256: pf10.sha256, actions } };
  if (tweak) tweak({ evidence, q04, dataset, reference, pf10 });
  const evidenceRef = write(root, "evidence.json", evidence);
  const artifacts = [["evidence", evidenceRef], ["q04-verification", q04], ["q07-dataset-verification", dataset], ["reference-machine", reference], ["pf10", pf10]].map(([role, a]) => ({ role, ...a }));
  write(root, "manifest.json", { schema: Q07_BUNDLE_SCHEMA, artifacts });
}
function root() { const p = mkdtempSync(join(tmpdir(), "q07-bundle-")); chmodSync(p, 0o700); return p; }
function rejects(p, _re) { assert.throws(() => verifyQ07EvidenceBundle(p)); }

test("Q07 bundle verifier accepts only a fully pinned blocked bundle", () => { const p = root(); try { build(p); const out = verifyQ07EvidenceBundle(p); assert.equal(out.q07Qualified, false); assert.equal(out.artifactCount, 5); } finally { rmSync(p, { recursive: true, force: true }); } });
test("Q07 bundle verifier rejects tamper, path, extra, symlink, and hardlink tricks", () => { for (const kind of ["tamper", "path", "extra", "symlink", "hardlink"]) { const p = root(); try { build(p); if (kind === "tamper") writeFileSync(join(p, "q04.json"), "x"); if (kind === "path") writeFileSync(join(p, "manifest.json"), canonicalJson({ schema: Q07_BUNDLE_SCHEMA, artifacts: [{ role: "evidence", path: "../x", bytes: 1, sha256: d() }] })); if (kind === "extra") writeFileSync(join(p, "extra"), "x"); if (kind === "symlink") { writeFileSync(join(p, "junk"), "x"); symlinkSync(join(p, "junk"), join(p, "linked")); } if (kind === "hardlink") { linkSync(join(p, "q04.json"), join(p, "linked")); } rejects(p, /differs|path|unreferenced|symlink|hardlink|missing/i); } finally { rmSync(p, { recursive: true, force: true }); } } });
test("Q07 bundle verifier rejects Q04, reference, and unsupported measured phase drift", () => { for (const kind of ["q04", "reference", "phase"]) { const p = root(); try { build(p, ({ evidence }) => { if (kind === "phase") evidence.phases.rawFallback = { status: "measured", reason: null, evidence: {} }; }); if (kind === "q04") { const x = JSON.parse(readFileSync(join(p, "q04.json"))); x.q04GatePass = false; writeFileSync(join(p, "q04.json"), canonicalJson(x)); } if (kind === "reference") { const x = JSON.parse(readFileSync(join(p, "machine.json"))); x.hostName = "drift"; writeFileSync(join(p, "machine.json"), canonicalJson(x)); } rejects(p, /differs|green|reference|measured|invalid/i); } finally { rmSync(p, { recursive: true, force: true }); } } });
