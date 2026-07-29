import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildDepth4SymbolicCertificate,
} from "./depth4-symbolic-certificate.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const workspace = resolve(here, "../../../../..");
const manifest = resolve(
  workspace,
  "03-create-your-own-pool/crates/shieldkit-v2-q04-certificate/Cargo.toml",
);
const productionSource = resolve(
  workspace,
  "03-create-your-own-pool/packages/pool/v2/persistent-indexed-nullifier.mjs",
);
const checkerSource = resolve(
  workspace,
  "03-create-your-own-pool/crates/shieldkit-v2-q04-certificate/src/main.rs",
);

const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
};
const digest = (domain, value) =>
  createHash("sha256")
    .update(domain, "ascii")
    .update(JSON.stringify(canonical(value)), "utf8")
    .digest("hex");
const rehashCase = (certificate, index) => {
  const target = certificate.cases[index];
  const { statementSha256: _oldStatement, ...statement } = target;
  target.statementSha256 = digest(
    "ShieldKit/Q04/symbolic-statement/v2\0",
    statement,
  );
};
const rehashCertificate = (certificate) => {
  certificate.casesSha256 = digest(
    "ShieldKit/Q04/depth4-symbolic-cases/v2\0",
    certificate.cases,
  );
  const {
    certificateSha256: _oldCertificate,
    ...withoutCertificateDigest
  } = certificate;
  certificate.certificateSha256 = digest(
    "ShieldKit/Q04/depth4-symbolic-certificate/v2\0",
    withoutCertificateDigest,
  );
};

function runChecker(certificate) {
  return spawnSync("cargo", [
    "+1.97.1",
    "run",
    "--locked",
    "--release",
    "--manifest-path",
    manifest,
    "--",
    "-",
    productionSource,
    checkerSource,
  ], {
    cwd: workspace,
    env: {
      ...process.env,
      MISE_RUST_VERSION: "1.97.1",
      RUSTUP_TOOLCHAIN: "1.97.1",
    },
    input: JSON.stringify(certificate),
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 120_000,
  });
}

test("independent Rust checker accepts only the exact independently audited certificate schema", {
  timeout: 180_000,
}, () => {
  const certificate = buildDepth4SymbolicCertificate();
  const accepted = runChecker(certificate);
  assert.equal(
    accepted.status,
    0,
    `checker failed:\n${accepted.stderr}`,
  );
  const result = JSON.parse(accepted.stdout);
  assert.deepEqual(
    {
      status: result.status,
      controlSkeletons: result.controlSkeletons,
      represented: result.representedConcreteRankStateGapTransitions,
      quotient: result.stateQuotientClaim,
      formalJs: result.formalJavaScriptSemanticsClaim,
    },
    {
      status: "verified",
      controlSkeletons: 911,
      represented: "93928268313",
      quotient: false,
      formalJs: false,
    },
  );

  const tampered = structuredClone(certificate);
  const target = tampered.cases[0];
  target.proof.production.root = {
    kind: "free-hash",
    name: "FORGED_POST_ROOT",
  };
  target.productionProofSha256 = digest(
    "ShieldKit/Q04/symbolic-production-proof/v1\0",
    target.proof.production,
  );
  rehashCase(tampered, 0);
  rehashCertificate(tampered);
  const rejected = runChecker(tampered);
  assert.notEqual(rejected.status, 0);
  assert.match(
    rejected.stderr,
    /cases\[0\]\.proof\.production differs/u,
  );

  const forgedDiagnostics = structuredClone(certificate);
  forgedDiagnostics.cases[0].mutationSha256 = "ab".repeat(32);
  forgedDiagnostics.cases[0].traceSha256 = "cd".repeat(32);
  rehashCase(forgedDiagnostics, 0);
  rehashCertificate(forgedDiagnostics);
  const diagnosticsRejected = runChecker(forgedDiagnostics);
  assert.notEqual(diagnosticsRejected.status, 0);
  assert.match(diagnosticsRejected.stderr, /cases\[0\] keys differ/u);

  const forgedCheckerClaim = structuredClone(certificate);
  forgedCheckerClaim.checker = {
    implementation: "forged-checker-claim",
    sourceSha256: "00".repeat(32),
    formalTheoremClaim: true,
    externalProofCheckerRequiredForFormalClaim: false,
  };
  rehashCertificate(forgedCheckerClaim);
  const checkerClaimRejected = runChecker(forgedCheckerClaim);
  assert.notEqual(checkerClaimRejected.status, 0);
  assert.match(checkerClaimRejected.stderr, /certificate keys differ/u);
});
