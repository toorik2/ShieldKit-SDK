#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  rmdirSync,
} from 'node:fs';
import path from 'node:path';
import { chmod, mkdtemp, open, rm } from 'node:fs/promises';
import { availableParallelism, tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  DIRECT_V2_PF10_RUNTIME_SCHEMA,
  validateDirectV2Pf10RuntimeMaterial,
} from '../packages/unlock-builder/v2/pf10-action-witness.mjs';
import {
  buildDirectV2BindingLock,
  buildDirectV2BindingRedeem,
  buildDirectV2StateHelper,
  buildDirectV2StateTrampolineLock,
  buildDirectV2StateTrampolineUnlock,
} from '../packages/unlock-builder/v2/structural-covenants.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  validateProfileCore,
} from '../packages/profile/v2/profile-core.mjs';
import {
  verifyV2DevelopmentProfilePackage,
} from '../packages/profile/v2/development-profile.mjs';
import {
  deriveV2RollingBaseSats,
} from '../packages/action/v2/dust-policy.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../packages/action/v2/topology.mjs';

const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const EXTERNAL_FIXTURE_TESTS = new Map([
  // Registry of fixture-gated paths (files may live outside the PF10 product tree).
  ['packages/action/assemble.profile-v2.test.mjs', 'authenticated profile-v2 bundle'],
  ['packages/action/witness.test.mjs', 'authenticated prover bundle/WASM/generator'],
  ['packages/kit/desktop.test.mjs', 'authenticated desktop profile bundle'],
  ['packages/kit/kit.test.mjs', 'local authenticated playground profile bundle'],
  ['packages/kit/pool-act-fail-closed.test.mjs', 'ticket10 live pool and wallet fixtures'],
  ['packages/profile/instance.test.mjs', 'local playground-matching profile bundle'],
  ['packages/prove/lab/verifier-generator.test.mjs', 'local hash-pinned seven-carrier provenance archive'],
  // V1 seven-carrier Chipnet fixtures relocated to archived-pool-designs/legacy-research/v1-seven-carrier/.
  ['packages/pool/tip-rebuild-history.test.mjs', 'legacy seven-carrier recover fixtures'],
  ['packages/recover/raw-chain-recovery.test.mjs', 'legacy seven-carrier recover fixtures'],
  ['packages/recover/raw-settlement-history.test.mjs', 'legacy seven-carrier recover fixtures'],
]);
const SCRIPT_STYLE_TESTS = new Set([
  'packages/action/v2/typescript/parity.test.mjs',
]);
// These are deterministic, local-only campaigns. They deliberately remain
// runnable from a clean source checkout, but are opt-in rather than part of
// the portable CI latency budget. Their classification is explicit so they
// cannot be silently omitted or mistaken for an external/release gate.
const LOCAL_CAMPAIGN_TESTS = new Map([
  [
    'packages/action/v2/strict-codec-qualification.test.mjs',
    'exhaustively mutates all 128 state bytes and all 552 packet bytes',
  ],
  [
    'packages/action/v2/typescript/parity.test.mjs',
    'compiles the independent TypeScript codec and repeats the strict codec mutation corpus',
  ],
  [
    'packages/action/v2/tree-qualification-depth4.test.mjs',
    'runs the bounded 13,700-trace / 82,201-store-replay depth-4 structural campaign',
  ],
  [
    'packages/pool/v2/qualification/depth4-production-state-space.test.mjs',
    'exhaustively checks the production Poseidon depth-4 state space, including durable SQLite replay',
  ],
]);
// Q-03 support tests define the exact 219-case attack matrix and the
// fail-closed verifier for its signed three-lane evidence closure. Keep this
// list exhaustive so new Q-03 tests cannot silently inherit a generic class.
const Q03_PORTABLE_SUPPORT_TESTS = new Map([
  ['scripts/v2-q03-attack-matrix.test.mjs', 'Q-03 exact attack-matrix support test'],
  ['scripts/v2-q03-final-lock-attacks.test.mjs', 'Q-03 final-lock evidence verifier support test'],
]);
// Q-07 support tests exercise evidence schemas, dataset integrity, worker
// boundaries, and the explicitly non-qualifying small-fixture harness. They
// are mandatory portable tests, but are named separately so a later 100k
// measurement driver cannot be mistaken for (or silently folded into) them.
// Keep this list exhaustive: an unregistered `v2-q07-*.test.mjs` fails test
// discovery rather than inheriting the generic portable classification.
const Q07_PORTABLE_SUPPORT_TESTS = new Map([
  ['scripts/v2-q07-bundle-verify.test.mjs', 'Q-07 hash-bound bundle verifier support test'],
  ['scripts/v2-q07-dataset.test.mjs', 'Q-07 deterministic dataset integrity support test'],
  ['scripts/v2-q07-evidence.test.mjs', 'Q-07 evidence-contract support test'],
  ['scripts/v2-q07-final-performance.test.mjs', 'Q-07 final-performance verifier fail-closed support test'],
  ['scripts/v2-q07-indexed-microbenchmark.test.mjs', 'Q-07 indexed-store microbenchmark boundary support test'],
  ['scripts/v2-q07-lifecycle-corpus.test.mjs', 'Q-07 non-chain lifecycle corpus integrity support test'],
  ['scripts/v2-q07-local-lifecycle-run.test.mjs', 'Q-07 exact local lifecycle runner integrity support test'],
  ['scripts/v2-q07-local-blocked-evidence.test.mjs', 'Q-07 honest blocked-evidence adapter support test'],
  ['scripts/v2-q07-performance-harness.test.mjs', 'Q-07 small-fixture harness boundary support test'],
  ['scripts/v2-q07-store-worker.test.mjs', 'Q-07 store-worker boundary support test'],
]);
// Product CLI, receipt, offline-installer, and native-prover tests use only
// generated private fixtures. They are explicitly listed so a new product
// security test cannot silently fall through a future suite change: it must
// be registered here and remains mandatory in both `npm test` and the focused
// immutable CI job.
const BETA_PRODUCT_PORTABLE_SECURITY_TESTS = new Map([
  ['packages/kit/v2/beta-product-action-lifecycle.test.mjs', 'product action lifecycle security test'],
  ['packages/kit/v2/beta-product-cli.test.mjs', 'product CLI boundary test'],
  ['packages/kit/v2/beta-product-commands.test.mjs', 'product command boundary test'],
  ['packages/kit/v2/beta-product-config.test.mjs', 'product private configuration test'],
  ['packages/kit/v2/beta-product-context.test.mjs', 'product receipt-bound context test'],
  ['packages/kit/v2/beta-product-funding-add.test.mjs', 'product authenticated funding admission test'],
  ['packages/kit/v2/beta-product-pool-create-action-store.test.mjs', 'product pool-create action-store test'],
  ['packages/kit/v2/beta-product-pool-create-journal.test.mjs', 'product pool-create journal test'],
  ['packages/kit/v2/beta-product-pool-create.test.mjs', 'product pool-create test'],
  ['packages/kit/v2/beta-product-pool-funding.test.mjs', 'product pool funding test'],
  ['packages/kit/v2/performance-source-reservations.test.mjs', 'product fresh-pool performance source reservation security test'],
  ['packages/kit/v2/operator-source-registry.test.mjs', 'operator-owned canonical source registry test'],
  ['packages/kit/v2/operator-fanout.test.mjs', 'operator multi-input fanout and recovery boundary test'],
  ['packages/kit/v2/beta-product-runtime-refresh.test.mjs', 'product explicit runtime refresh security test'],
  ['packages/kit/v2/beta-product-session.test.mjs', 'product session lifecycle test'],
  ['packages/kit/v2/beta-product-wallet.test.mjs', 'product wallet test'],
  ['packages/kit/v2/beta-qualification-evidence.test.mjs', 'product evidence redaction/schema test'],
  ['packages/kit/v2/beta-zero-conf-admission.test.mjs', 'product zero-conf admission test'],
  ['packages/profile/v2/beta-chipnet-runtime-cache.test.mjs', 'product runtime-cache receipt test'],
  ['packages/profile/v2/beta-product-artifact-installation.test.mjs', 'product artifact-install receipt test'],
  ['packages/profile/v2/beta-product-offline-bootstrap.test.mjs', 'product offline-installer restart/security test'],
  ['packages/profile/v2/beta-product-offline-bundle-packer.test.mjs', 'product offline-bundle packing/security test'],
  ['packages/prove/v2/native-groth16-proof-child.test.mjs', 'product native proof child boundary test'],
  ['packages/prove/v2/native-groth16-proof-worker.test.mjs', 'product native proof workspace security test'],
  ['packages/prove/v2/native-groth16-prover-installation.test.mjs', 'product native prover receipt/cache test'],
  ['scripts/v2-beta-live-action-evidence.test.mjs', 'product live-action evidence validator test'],
  ['scripts/v2-beta-live-action-chain-attestation.test.mjs', 'product independent BCHN action-attestation test'],
  ['scripts/v2-beta-live-evidence-bundle-verify.test.mjs', 'product independent live evidence-bundle verifier test'],
  ['scripts/v2-beta-live-pool-create-performance.test.mjs', 'product fresh pool-create performance evidence test'],
]);
const BETA_RUNTIME_QUALIFICATION_TESTS = new Map([
  ['packages/profile/v2/beta-chipnet-runtime.test.mjs', 'requires an explicitly supplied private beta runtime fixture and fails closed when it is absent'],
  ['packages/unlock-builder/v2/pf10-beta-runtime-qualification.test.mjs', 'requires an explicitly supplied private PF10 beta runtime artifact closure and fails closed when it is absent'],
]);
const CLEAN_SOURCE_TESTS = new Map([
  [
    'scripts/v2-beta-single-contributor-ceremony.test.mjs',
    'binds ceremony preparation and contribution to an exact clean committed source checkout',
  ],
]);
// These tests have correctness-sensitive local resource boundaries which are
// not independent of a saturated process table. The native-child contract
// samples a short-lived subprocess via `/proc/<pid>`. The circuit-model test
// compiles the full pinned circuit and calculates its complete witness corpus
// under its own unchanged 120-second semantic timeout; it completes in about
// 42 seconds alone on the reference host but demonstrably exceeds that timeout
// when competing with nineteen other CPU-heavy files. Run each after the
// all-core pool rather than weakening either test or its timeout.
const EXCLUSIVE_DOMAIN_TEST_FILES = new Set([
  'packages/action/v2/circuit-model.test.mjs',
  'packages/prove/v2/native-groth16-proof-child.test.mjs',
  // Requires a clean Git worktree for the entire file; concurrent domain tests
  // can write untracked artifacts and trip BETA_IMPLEMENTATION_DIRTY.
  'scripts/v2-beta-single-contributor-ceremony.test.mjs',
]);
// `node:test` gives the full production depth-4 state-space check five minutes.
// The process supervisor must permit that declared test timeout plus TAP/SQLite
// teardown; a blanket 180-second supervisor limit would kill a healthy test
// before node:test can report its own result. This is a test-class policy, not
// an opt-out: the corresponding CI job invokes the entire campaign suite.
const FILE_TIMEOUT_MS_BY_CLASSIFICATION = Object.freeze({
  'local-depth4-campaign': 360_000,
});
const FILE_TIMEOUT_MS_BY_PATH = new Map([
  [
    'packages/unlock-builder/v2/pf10-runtime-bundle-coherence.test.mjs',
    900_000,
  ],
  // Packaged genesis binding + VM-accepted genesis matrix is CPU-heavy; alone
  // it is ~2 minutes and can exceed the 180s default supervisor under a full
  // all-core portable pool without any assertion failure.
  [
    'packages/profile/v2/genesis.test.mjs',
    360_000,
  ],
  [
    'packages/recover/scale-history-conformance.test.mjs',
    360_000,
  ],
  // Q-05 deliberately proves clean-checkout behavior several times: each
  // relevant case performs a fresh immutable npm install and selected cases
  // also compile/run the Rust lane in a fresh target. Keep it mandatory in
  // the portable suite, but give the process supervisor enough time for the
  // cold work rather than killing a healthy test at the generic deadline.
  [
    'scripts/v2-q05-evidence-verify.test.mjs',
    600_000,
  ],
  // This exact qualification creates a detached clean local clone, performs an
  // immutable install, copies the multi-gigabyte authenticated proof/runtime
  // closure into private single-link files, generates/replays public Q-01
  // evidence, and independently verifies B-01 before and after its mutation
  // matrix. Hosted two-core runners need a bounded heavyweight supervisor
  // without weakening any inner assertion.
  [
    'scripts/v2-b01-pre-freeze-e2e.test.mjs',
    7_200_000,
  ],
]);
const VENDORED_VERIFIER_LANE_TEST_ROOT = 'packages/unlock-builder/vendor/verifier/lanes/bn254-onetx/test';
const VENDORED_VERIFIER_EXTERNAL_TESTS = new Set([
  `${VENDORED_VERIFIER_LANE_TEST_ROOT}/legacy-c7-config.test.mjs`,
  `${VENDORED_VERIFIER_LANE_TEST_ROOT}/pairfold-8-plan.test.mjs`,
  `${VENDORED_VERIFIER_LANE_TEST_ROOT}/pf6-terminal-profile.test.mjs`,
  `${VENDORED_VERIFIER_LANE_TEST_ROOT}/shortlist-architectures.test.mjs`,
]);
const MATERIALIZED_UNLOCK_TOOLCHAIN = Object.freeze([
  'packages/unlock-builder/vendor/verifier/vendor/cashc-resched/packages/cashc/dist/index.js',
]);
const DEVELOPMENT_ARTIFACT_ROOTS = Object.freeze([
  '../.codex-build/v2-circuit-model',
  '../.codex-build/v2-dev-groth16',
  '../.codex-build/v2-dev-proof-qualification',
  '../.codex-build/v2-dev-ptau',
  '../.codex-build/v2-development-profile',
  '../.codex-build/v2-pf10-libauth-qualification',
  '../.codex-build/v2-pf10-libauth-tmp',
  '../.codex-build/v2-pf10-development-runtime',
  '../.codex-build/v2-pf10-runtime-tmp',
]);
const DEVELOPMENT_TRANSIENT_ROOTS = Object.freeze([
  '../.codex-build/v2-pf10-libauth-tmp',
  '../.codex-build/v2-pf10-runtime-tmp',
]);
const LOCAL_VERIFIER_COMPLETION_ARTIFACTS = Object.freeze([
  '../.codex-build/v2-pf10-libauth-qualification/libauth.json',
  '../.codex-build/v2-pf10-libauth-qualification/publication-complete.json',
  '../.codex-build/v2-pf10-libauth-qualification/qualification-summary.json',
  '../.codex-build/v2-pf10-development-runtime/runtime-build-manifest.json',
  '../.codex-build/v2-pf10-development-runtime/runtime/pf10-runtime-material.json',
  '../.codex-build/v2-pf10-development-runtime/qualification/pf10-libauth-evidence.json',
]);
const ARTIFACT_QUALIFICATION_TESTS = new Map([
  ['scripts/v2-b01-pre-freeze-e2e.test.mjs', Object.freeze([
    '../.codex-build/v2-circuit-model/main-chipnet.r1cs',
    '../.codex-build/v2-circuit-model/main-chipnet.sym',
    '../.codex-build/v2-circuit-model/main-chipnet_js/main-chipnet.wasm',
    '../.codex-build/v2-dev-groth16/final.zkey',
    '../.codex-build/v2-dev-groth16/initial.zkey',
    '../.codex-build/v2-dev-groth16/verification_key.json',
    '../.codex-build/v2-dev-ptau/pot19_final.ptau',
    '../.codex-build/v2-development-profile/profile-core.json',
    '../.codex-build/v2-development-profile/profile-package.json',
    '../.codex-build/v2-pf10-libauth-qualification/libauth.json',
    '../.codex-build/v2-pf10-libauth-qualification/publication-complete.json',
    '../.codex-build/v2-pf10-libauth-qualification/qualification-summary.json',
    '../.codex-build/v2-pf10-development-runtime/runtime-build-manifest.json',
    '../.codex-build/v2-pf10-development-runtime/runtime/pf10-runtime-material.json',
  ])],
  ['packages/unlock-builder/v2/pf10-fused-q-genesis.test.mjs', Object.freeze([
    '../.codex-build/v2-dev-groth16/verification_key.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/proof.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/public.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/packet.bin',
  ])],
  ['packages/unlock-builder/v2/pf10-withdrawal.test.mjs', Object.freeze([
    '../.codex-build/v2-circuit-model/main-chipnet.r1cs',
    '../.codex-build/v2-dev-groth16/verification_key.json',
    '../.codex-build/v2-dev-groth16/final.zkey',
    '../.codex-build/v2-dev-groth16/setup-metadata.json',
    '../.codex-build/v2-circuit-model/main-chipnet_js/main-chipnet.wasm',
    '../.codex-build/v2-dev-proof-qualification/qualification-evidence.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/packet.bin',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/input.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/proof.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/public.json',
  ])],
  ['packages/unlock-builder/v2/total-pairfold.test.mjs', Object.freeze([
    '../.codex-build/v2-circuit-model/main-chipnet.r1cs',
    '../.codex-build/v2-dev-groth16/verification_key.json',
    '../.codex-build/v2-dev-groth16/final.zkey',
    '../.codex-build/v2-dev-groth16/setup-metadata.json',
    '../.codex-build/v2-circuit-model/main-chipnet_js/main-chipnet.wasm',
    '../.codex-build/v2-dev-proof-qualification/qualification-evidence.json',
    '../.codex-build/v2-dev-proof-qualification/deposit/packet.bin',
    '../.codex-build/v2-dev-proof-qualification/deposit/input.json',
    '../.codex-build/v2-dev-proof-qualification/deposit/proof.json',
    '../.codex-build/v2-dev-proof-qualification/deposit/public.json',
  ])],
  ['packages/unlock-builder/v2/pf10-runtime-bundle-coherence.test.mjs', Object.freeze([
    '../.codex-build/v2-dev-proof-qualification/qualification-evidence.json',
    '../.codex-build/v2-development-profile/profile-core.json',
    '../.codex-build/v2-development-profile/profile-package.json',
    '../.codex-build/v2-pf10-libauth-qualification/libauth.json',
    '../.codex-build/v2-pf10-libauth-qualification/publication-complete.json',
    '../.codex-build/v2-pf10-libauth-qualification/qualification-summary.json',
    '../.codex-build/v2-pf10-development-runtime/runtime-build-manifest.json',
    '../.codex-build/v2-pf10-development-runtime/runtime/pf10-runtime-material.json',
    '../.codex-build/v2-pf10-development-runtime/qualification/pf10-libauth-evidence.json',
  ])],
  ['scripts/v2-pf10-development-runtime.test.mjs', Object.freeze([
    '../.codex-build/v2-circuit-model/main-chipnet.r1cs',
    '../.codex-build/v2-circuit-model/main-chipnet_js/main-chipnet.wasm',
    '../.codex-build/v2-dev-groth16/final.zkey',
    '../.codex-build/v2-dev-groth16/verification_key.json',
    '../.codex-build/v2-development-profile/profile-core.json',
    '../.codex-build/v2-development-profile/profile-package.json',
    '../.codex-build/v2-pf10-libauth-qualification/libauth.json',
  ])],
]);
const DEVELOPMENT_SETUP_SCHEMA = 'shield.cash/local-development-setup/v1';
const DEVELOPMENT_PROOF_EVIDENCE_SCHEMA =
  'shieldkit-v2-direct-development-groth16-qualification-v4';
const DEVELOPMENT_PROOF_EVIDENCE_CLASS =
  'deterministic-development-key-proof-test-evidence';
const V2_MINIMUM_CHANGE_SATS = '546';
const PF10_LIBAUTH_QUALIFICATION_SCHEMA =
  'shieldkit-v2-direct-pf10-local-libauth-qualification-v2';
const PF10_LIBAUTH_PUBLICATION_SCHEMA =
  'shieldkit-v2-direct-pf10-libauth-publication-v1';
const PF10_LIBAUTH_PUBLICATION_FILE = 'publication-complete.json';
const PF10_LIBAUTH_PUBLICATION_FILES = Object.freeze([
  'libauth.json',
  'qualification-summary.json',
  'stderr.txt',
  'stdout.txt',
]);
const PF10_DEVELOPMENT_RUNTIME_BUNDLE_SCHEMA =
  'shieldkit-v2-direct-pf10-development-runtime-bundle-v2';
const V2_ARTIFACT_MANIFEST_SCHEMA =
  'shieldkit-artifact-manifest-v2-direct';
const PF10_DEVELOPMENT_RUNTIME_ARTIFACT_COUNT = 57;
const PF10_REPRODUCIBILITY_ARTIFACT_IDS = Object.freeze([
  'repro-executor-raw',
  'repro-executor-source',
  'repro-exactfinal-raw',
  'repro-exactfinal-source',
  'repro-miller-raw',
  'repro-miller-source',
  'repro-terminal-raw',
  'repro-terminal-source',
  ...Array.from({ length: 3 }, (_, index) => [
    `repro-exact-msm-${index}-raw`,
    `repro-exact-msm-${index}-source`,
  ]).flat(),
]);
const PF10_RUNTIME_CONSUMED_ARTIFACT_IDS = new Set([
  'binding-lock',
  'binding-redeem',
  'development-profile-package',
  'pf10-executor-body',
  'pf10-fused-redeem',
  'pf10-libauth-evidence',
  'pf10-qualification-evidence',
  'pf10-qualification-raw-evidence',
  'pf10-runtime-material',
  'pf10-terminal-redeem',
  'profile-core',
  'proof-verification-key',
  'state-helper',
  'state-helper-unlock',
  'state-lock',
  ...Array.from({ length: 3 }, (_, index) =>
    `pf10-exact-msm-redeem-${index}`),
  ...Array.from({ length: 3 }, (_, index) =>
    `pf10-fixed-carrier-pad-${index}`),
  ...Array.from({ length: 10 }, (_, index) =>
    `verifier-lock-${index}`),
  ...PF10_REPRODUCIBILITY_ARTIFACT_IDS,
]);
const DEVELOPMENT_ACTIONS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const SHA256 = /^[0-9a-f]{64}$/;
const compareAscii = (left, right) =>
  left < right ? -1 : left > right ? 1 : 0;
const SUITES = new Set([
  'portable',
  'external-fixtures',
  'external-verifier-source',
  'local-covenants',
  'local-verifier-lane',
  'local-strict-codec-campaign',
  'local-depth4-campaign',
  'q03-portable-support',
  'q07-portable-support',
  'beta-product-security',
  'beta-runtime-qualification',
  'clean-source',
]);
const SKIP_OR_TODO_SOURCE = /(?:\b(?:test|it|describe|suite|t)\s*\.\s*(?:skip|todo)\s*\(|\b(?:skip|todo)\s*:)/;
const NODE_TEST_DECLARATION = /\b(?:test|it|describe|suite)\s*\(/;
const DOMAIN_TEST_TEMP_PREFIX = 'domain-test-run-';
const managedDomainTestTemporaryDirectories = new Map();
let pf10DevelopmentRuntimeBuilderModule;
let v2InstanceDescriptorModule;

export class DomainTestRunnerError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DomainTestRunnerError';
  }
}
const fail = (message) => { throw new DomainTestRunnerError(message); };
const posix = (value) => value.split(path.sep).join('/');

async function loadPf10DevelopmentRuntimeBuilder() {
  pf10DevelopmentRuntimeBuilderModule ??= import(
    '../packages/unlock-builder/v2/pf10-development-runtime-builder.mjs'
  );
  return pf10DevelopmentRuntimeBuilderModule;
}

async function loadV2InstanceDescriptor() {
  v2InstanceDescriptorModule ??= import(
    '../packages/profile/v2/instance-descriptor.mjs'
  );
  return v2InstanceDescriptorModule;
}

function requiredObject(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  return value;
}

function requiredHash(value, label, { prefixed = false } = {}) {
  const expression = prefixed ? /^sha256:([0-9a-f]{64})$/ : SHA256;
  const match = typeof value === 'string' ? value.match(expression) : null;
  if (match === null) fail(`${label} must be a lowercase SHA-256 hash`);
  return prefixed ? match[1] : value;
}

function requiredBoolean(value, label) {
  if (typeof value !== 'boolean') fail(`${label} must be boolean`);
  return value;
}

function requiredPublicInputs(value, label) {
  if (
    !Array.isArray(value)
    || value.length !== 2
    || value.some((entry) => typeof entry !== 'string' || !/^(0|[1-9][0-9]*)$/.test(entry))
  ) {
    fail(`${label} must be exactly two canonical decimal public inputs`);
  }
  return value;
}

function readJson(filename, label) {
  let metadata;
  try {
    metadata = lstatSync(filename);
  } catch {
    fail(`${label} is missing`);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0) {
    fail(`${label} must be a nonempty regular non-symlink file`);
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(filename, 'utf8'));
  } catch (error) {
    fail(`${label} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  return requiredObject(parsed, label);
}

function artifactPathSet(projectRoot, overrides) {
  if (overrides !== undefined) {
    const expectedKeys = [
      'evidence',
      'evidenceRoot',
      'r1cs',
      'setupMetadata',
      'verificationKey',
      'wasm',
      'zkey',
    ];
    const actualKeys = Object.keys(requiredObject(
      overrides,
      'local verifier artifact path overrides',
    )).sort();
    if (
      actualKeys.length !== expectedKeys.length
      || actualKeys.some((key, index) => key !== expectedKeys[index])
    ) {
      fail('local verifier artifact path overrides have missing or unknown properties');
    }
    for (const key of expectedKeys) {
      if (
        typeof overrides[key] !== 'string'
        || !path.isAbsolute(overrides[key])
        || path.normalize(overrides[key]) !== overrides[key]
      ) {
        fail(`local verifier artifact path override ${key} must be an absolute normalized path`);
      }
    }
    return Object.freeze({
      r1cs: overrides.r1cs,
      wasm: overrides.wasm,
      setupMetadata: overrides.setupMetadata,
      zkey: overrides.zkey,
      verificationKey: overrides.verificationKey,
      evidence: overrides.evidence,
      action: (name, filename) => path.join(
        overrides.evidenceRoot,
        name,
        filename,
      ),
    });
  }
  const root = path.resolve(projectRoot, '..', '.codex-build');
  const model = path.join(root, 'v2-circuit-model');
  const setup = path.join(root, 'v2-dev-groth16');
  const evidence = path.join(root, 'v2-dev-proof-qualification');
  return Object.freeze({
    r1cs: path.join(model, 'main-chipnet.r1cs'),
    wasm: path.join(model, 'main-chipnet_js', 'main-chipnet.wasm'),
    setupMetadata: path.join(setup, 'setup-metadata.json'),
    zkey: path.join(setup, 'final.zkey'),
    verificationKey: path.join(setup, 'verification_key.json'),
    evidence: path.join(evidence, 'qualification-evidence.json'),
    action: (name, filename) => path.join(evidence, name, filename),
  });
}

async function sha256RegularFile(
  filename,
  label,
  { allowEmpty = false, includeData = false } = {},
) {
  let pathBefore;
  let canonicalBefore;
  try {
    pathBefore = lstatSync(filename, { bigint: true });
    canonicalBefore = realpathSync(filename);
  } catch {
    fail(`${label} is missing`);
  }
  if (
    !pathBefore.isFile()
    || pathBefore.isSymbolicLink()
    || (!allowEmpty && pathBefore.size === 0n)
    || canonicalBefore !== filename
  ) {
    fail(`${label} must be a nonempty regular non-symlink file`);
  }
  let handle;
  try {
    handle = await open(filename, 'r');
    const before = await handle.stat({ bigint: true });
    if (
      before.dev !== pathBefore.dev
      || before.ino !== pathBefore.ino
      || before.size !== pathBefore.size
      || before.mtimeNs !== pathBefore.mtimeNs
      || before.ctimeNs !== pathBefore.ctimeNs
    ) {
      fail(`${label} changed before it could be opened safely`);
    }
    const hash = createHash('sha256');
    const chunks = [];
    let bytes = 0n;
    for await (const chunk of handle.createReadStream({
      autoClose: false,
      highWaterMark: 64 * 1024,
    })) {
      hash.update(chunk);
      bytes += BigInt(chunk.length);
      if (includeData) chunks.push(Buffer.from(chunk));
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = lstatSync(filename, { bigint: true });
    const canonicalAfter = realpathSync(filename);
    if (
      before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
      || before.dev !== pathAfter.dev
      || before.ino !== pathAfter.ino
      || before.size !== pathAfter.size
      || before.mtimeNs !== pathAfter.mtimeNs
      || before.ctimeNs !== pathAfter.ctimeNs
      || bytes !== before.size
      || canonicalAfter !== filename
    ) {
      fail(`${label} changed while it was hashed`);
    }
    if (before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(`${label} exceeds the safe evidence byte range`);
    }
    return Object.freeze({
      bytes: Number(before.size),
      sha256: hash.digest('hex'),
      ...(includeData ? { data: Buffer.concat(chunks) } : {}),
    });
  } catch (error) {
    if (error instanceof DomainTestRunnerError) throw error;
    fail(`${label} cannot be hashed`);
  } finally {
    await handle?.close();
  }
}

async function readCanonicalJsonRegularFile(filename, label) {
  const source = await sha256RegularFile(filename, label, {
    includeData: true,
  });
  let value;
  try {
    value = JSON.parse(source.data.toString('utf8'));
  } catch (error) {
    fail(
      `${label} is not valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || !source.data.equals(Buffer.from(canonicalizeJcs(value), 'utf8'))
  ) {
    fail(`${label} must be an exact canonical JCS object`);
  }
  return Object.freeze({ ...source, value });
}

async function assertEvidenceFile(filename, evidence, label) {
  const source = requiredObject(evidence, label);
  const expected = requiredHash(source.sha256, `${label}.sha256`);
  if (!Number.isSafeInteger(source.bytes) || source.bytes <= 0) {
    fail(`${label}.bytes must be a positive safe integer`);
  }
  const actual = await sha256RegularFile(filename, label);
  if (actual.bytes !== source.bytes || actual.sha256 !== expected) {
    fail(`${label} differs from the qualification evidence`);
  }
  return actual;
}

/**
 * Bind every artifact consumed by the local verifier lane to one current
 * circuit/setup/proof evidence set. This intentionally does not regenerate:
 * stale or partial generated state is BLOCKED for a clean explicit rebuild.
 */
async function inspectLocalVerifierArtifactCoherence({
  projectRoot = project,
  artifactPaths,
} = {}) {
  const files = artifactPathSet(projectRoot, artifactPaths);
  const [r1cs, wasm, zkey, verificationKey] = await Promise.all([
    sha256RegularFile(files.r1cs, 'local verifier R1CS'),
    sha256RegularFile(files.wasm, 'local verifier witness WASM'),
    sha256RegularFile(files.zkey, 'local verifier proving key'),
    sha256RegularFile(files.verificationKey, 'local verifier verification key'),
  ]);
  const setup = readJson(files.setupMetadata, 'local verifier setup metadata');
  if (setup.schema !== DEVELOPMENT_SETUP_SCHEMA || setup.mode !== 'development-only') {
    fail('local verifier setup metadata schema or mode is unsupported');
  }
  const setupR1cs = requiredObject(setup.inputs, 'local verifier setup metadata.inputs').r1cs;
  const setupOutputs = requiredObject(setup.outputs, 'local verifier setup metadata.outputs');
  if (
    requiredHash(requiredObject(setupR1cs, 'local verifier setup metadata.inputs.r1cs').sha256,
      'local verifier setup metadata.inputs.r1cs.sha256', { prefixed: true }) !== r1cs.sha256
    || requiredHash(requiredObject(setupOutputs.provingKey, 'local verifier setup metadata.outputs.provingKey').sha256,
      'local verifier setup metadata.outputs.provingKey.sha256', { prefixed: true }) !== zkey.sha256
    || requiredHash(requiredObject(setupOutputs.verificationKey, 'local verifier setup metadata.outputs.verificationKey').sha256,
      'local verifier setup metadata.outputs.verificationKey.sha256', { prefixed: true }) !== verificationKey.sha256
  ) {
    fail('local verifier setup metadata does not bind the current R1CS, zkey, and verification key');
  }
  const setupPhase2 = requiredObject(
    requiredObject(setup.setup, 'local verifier setup metadata.setup').material,
    'local verifier setup metadata.setup.material',
  ).phase2;
  if (
    requiredHash(requiredObject(setupPhase2, 'local verifier setup metadata.setup.material.phase2').finalZkeySha256,
      'local verifier setup metadata.setup.material.phase2.finalZkeySha256', { prefixed: true }) !== zkey.sha256
  ) {
    fail('local verifier setup phase2 record does not bind the current zkey');
  }

  const evidenceFile = await sha256RegularFile(
    files.evidence,
    'local verifier qualification evidence',
    { includeData: true },
  );
  let evidence;
  try {
    evidence = JSON.parse(evidenceFile.data.toString('utf8'));
  } catch {
    fail('local verifier qualification evidence is not valid JSON');
  }
  if (
    evidence.schema !== DEVELOPMENT_PROOF_EVIDENCE_SCHEMA
    || evidence.evidenceClass !== DEVELOPMENT_PROOF_EVIDENCE_CLASS
  ) {
    fail('local verifier qualification evidence schema is unsupported; clean regeneration is required');
  }
  const source = requiredObject(evidence.sourceArtifacts, 'local verifier qualification evidence.sourceArtifacts');
  const identity = requiredObject(
    evidence.identity,
    'local verifier qualification evidence.identity',
  );
  if (
    !SHA256.test(identity.profileId)
    || !SHA256.test(identity.instanceId)
  ) {
    fail('local verifier qualification evidence identity is invalid');
  }
  const expectedSources = Object.freeze({
    r1cs,
    wasm,
    developmentZkey: zkey,
    verificationKey,
  });
  for (const [name, actual] of Object.entries(expectedSources)) {
    await assertEvidenceFile(files[name === 'developmentZkey' ? 'zkey' : name], source[name],
      `local verifier qualification evidence.sourceArtifacts.${name}`);
    if (source[name].sha256 !== actual.sha256 || source[name].bytes !== actual.bytes) {
      fail(`local verifier qualification evidence source ${name} is incoherent`);
    }
  }
  const claims = requiredObject(evidence.claims, 'local verifier qualification evidence.claims');
  if (
    requiredBoolean(claims.developmentKey, 'local verifier qualification evidence.claims.developmentKey') !== true
    || requiredBoolean(claims.finalKey, 'local verifier qualification evidence.claims.finalKey') !== false
    || requiredBoolean(claims.bchVm, 'local verifier qualification evidence.claims.bchVm') !== false
    || requiredBoolean(claims.production, 'local verifier qualification evidence.claims.production') !== false
  ) {
    fail('local verifier qualification evidence claims are unsupported');
  }
  const actions = requiredObject(evidence.actions, 'local verifier qualification evidence.actions');
  if (
    Object.keys(actions).sort().join(',') !== DEVELOPMENT_ACTIONS.join(',')
  ) {
    fail('local verifier qualification evidence actions are incomplete');
  }
  for (const name of DEVELOPMENT_ACTIONS) {
    const action = requiredObject(actions[name], `local verifier qualification evidence.actions.${name}`);
    if (
      requiredBoolean(action.witnessValid, `local verifier qualification evidence.actions.${name}.witnessValid`) !== true
      || requiredBoolean(action.proofVerified, `local verifier qualification evidence.actions.${name}.proofVerified`) !== true
    ) {
      fail(`local verifier qualification evidence action ${name} is not verified`);
    }
    const publicInputs = requiredPublicInputs(action.publicInputs,
      `local verifier qualification evidence.actions.${name}.publicInputs`);
    const actionFiles = requiredObject(action.files,
      `local verifier qualification evidence.actions.${name}.files`);
    for (const [field, filename] of Object.entries({
      packet: 'packet.bin', input: 'input.json', witness: 'witness.wtns',
      proof: 'proof.json', publicSignals: 'public.json', v2DirectGroth16Adapter: 'v2-direct-groth16-adapter.json',
    })) {
      await assertEvidenceFile(files.action(name, filename), actionFiles[field],
        `local verifier qualification evidence.actions.${name}.files.${field}`);
    }
    if (actionFiles.packet.bytes !== 552) {
      fail(`local verifier qualification evidence action ${name} packet has the wrong byte length`);
    }
    if (requiredHash(action.packetDigest,
      `local verifier qualification evidence.actions.${name}.packetDigest`)
      !== actionFiles.packet.sha256) {
      fail(`local verifier qualification evidence action ${name} packet digest is incoherent`);
    }
    let input;
    let publicSignals;
    try {
      input = JSON.parse(readFileSync(files.action(name, 'input.json'), 'utf8'));
      publicSignals = JSON.parse(readFileSync(files.action(name, 'public.json'), 'utf8'));
    } catch {
      fail(`local verifier qualification action ${name} input/public JSON is invalid`);
    }
    if (
      !Array.isArray(publicSignals)
      || publicSignals.length !== 2
      || publicSignals.some((value, index) => String(value) !== publicInputs[index])
      || String(input?.publicInput0) !== publicInputs[0]
      || String(input?.publicInput1) !== publicInputs[1]
    ) {
      fail(`local verifier qualification action ${name} verifier inputs differ from the evidence`);
    }
  }
  return Object.freeze({
    profileId: identity.profileId,
    instanceId: identity.instanceId,
    evidenceBytes: evidenceFile.bytes,
    evidenceSha256: evidenceFile.sha256,
    r1cs: r1cs.sha256,
    wasm: wasm.sha256,
    zkey: zkey.sha256,
    verificationKey: verificationKey.sha256,
  });
}

export async function assertLocalVerifierArtifactCoherence(options = {}) {
  try {
    return await inspectLocalVerifierArtifactCoherence(options);
  } catch (error) {
    if (error instanceof DomainTestRunnerError) {
      fail(
        `local verifier artifact coherence is BLOCKED: ${error.message}. `
        + 'Cleanly regenerate the complete circuit/setup/proof evidence set; do not mix artifacts.',
      );
    }
    throw error;
  }
}

function canonicalNonSymlinkDirectory(filename, label) {
  const resolved = path.resolve(filename);
  let metadata;
  try {
    metadata = lstatSync(resolved);
  } catch {
    fail(`${label} is missing`);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail(`${label} must be a non-symlink directory`);
  }
  let canonical;
  try {
    canonical = realpathSync(resolved);
  } catch {
    fail(`${label} cannot be resolved`);
  }
  if (canonical !== resolved) {
    fail(`${label} must be canonical`);
  }
  return canonical;
}

function safeRuntimeArtifactPath(runtimeRoot, value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.includes('\\')
    || path.posix.normalize(value) !== value
    || path.posix.isAbsolute(value)
    || value === '..'
    || value.startsWith('../')
  ) {
    fail(`${label} must be a normalized repository-relative POSIX path`);
  }
  const filename = path.resolve(runtimeRoot, ...value.split('/'));
  const relative = path.relative(runtimeRoot, filename);
  if (
    relative.length === 0
    || relative === '..'
    || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)
  ) {
    fail(`${label} escapes the runtime bundle`);
  }
  let canonical;
  try {
    canonical = realpathSync(filename);
  } catch {
    fail(`${label} is missing`);
  }
  if (canonical !== filename) {
    fail(`${label} traverses a symlink or non-canonical parent`);
  }
  return filename;
}

function assertExactRuntimeBundleEntries(runtimeRoot, artifactPaths) {
  const expectedFiles = new Set([
    'runtime-build-manifest.json',
    ...artifactPaths,
  ]);
  const expectedDirectories = new Set();
  for (const filename of expectedFiles) {
    const components = filename.split('/');
    for (let index = 1; index < components.length; index += 1) {
      expectedDirectories.add(components.slice(0, index).join('/'));
    }
  }
  const seenFiles = new Set();
  const seenDirectories = new Set();
  const walk = (directory, relativeDirectory = '') => {
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true })
        .sort((left, right) => compareAscii(left.name, right.name));
    } catch {
      fail('local verifier PF10 runtime bundle cannot be enumerated');
    }
    for (const entry of entries) {
      const relative = relativeDirectory.length === 0
        ? entry.name
        : `${relativeDirectory}/${entry.name}`;
      const filename = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        fail(`local verifier PF10 runtime bundle contains a symlink: ${relative}`);
      }
      if (entry.isDirectory()) {
        if (!expectedDirectories.has(relative)) {
          fail(
            `local verifier PF10 runtime bundle contains an unmanifested directory: ${relative}`,
          );
        }
        seenDirectories.add(relative);
        walk(filename, relative);
      } else if (entry.isFile()) {
        if (!expectedFiles.has(relative)) {
          fail(
            `local verifier PF10 runtime bundle contains an unmanifested file: ${relative}`,
          );
        }
        seenFiles.add(relative);
      } else {
        fail(
          `local verifier PF10 runtime bundle contains an unsupported entry: ${relative}`,
        );
      }
    }
  };
  walk(runtimeRoot);
  if (
    seenFiles.size !== expectedFiles.size
    || [...expectedFiles].some((entry) => !seenFiles.has(entry))
    || seenDirectories.size !== expectedDirectories.size
    || [...expectedDirectories].some((entry) => !seenDirectories.has(entry))
  ) {
    fail('local verifier PF10 runtime bundle is missing a manifest-bound entry');
  }
}

function exactKeySet(value, expected, label) {
  const record = requiredObject(value, label);
  const actual = Object.keys(record).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length
    || actual.some((key, index) => key !== sortedExpected[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
  return record;
}

function readPinnedRuntimeArtifactBytes(record, label) {
  if (record === undefined) {
    fail(`${label} is missing`);
  }
  const bytes = record.data;
  if (
    !Buffer.isBuffer(bytes)
    || bytes.length !== record.bytes
    || createHash('sha256').update(bytes).digest('hex') !== record.sha256
  ) {
    fail(`${label} was not retained from its authenticated file handle`);
  }
  return Buffer.from(bytes);
}

function parseCanonicalRuntimeJsonArtifact(record, label) {
  const bytes = readPinnedRuntimeArtifactBytes(record, label);
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(`${label} is not JSON`);
  }
  if (!bytes.equals(Buffer.from(canonicalizeJcs(value), 'utf8'))) {
    fail(`${label} is not canonical JCS`);
  }
  return Object.freeze({ bytes, value });
}

function requiredRuntimeBytes(value, label) {
  if (!(value instanceof Uint8Array) || value.byteLength === 0) {
    fail(`${label} must be nonempty bytes`);
  }
  return Buffer.from(value);
}

/**
 * Reconstruct the identity-bound binding covenant and all three structural
 * state artifacts. A manifest hash proves only that a file was counted; this
 * check proves that the counted bytes are exactly the covenant the profile and
 * instance require.
 */
export function validateExactDirectV2Pf10StructuralArtifacts(value) {
  const input = exactKeySet(value, [
    'binding',
    'instanceId',
    'profileCore',
    'profileId',
    'state',
    'topologyId',
    'verifierRoles',
    'verifiers',
  ], 'local verifier PF10 structural artifact input');
  if (
    !SHA256.test(input.profileId)
    || !SHA256.test(input.instanceId)
    || input.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !Array.isArray(input.verifierRoles)
    || input.verifierRoles.length
      !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || input.verifierRoles.some(
      (role, index) =>
        role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index],
    )
  ) {
    fail('local verifier PF10 structural identity is invalid');
  }
  try {
    validateProfileCore(input.profileCore);
  } catch (error) {
    fail(
      `local verifier PF10 structural profile core is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (deriveProfileId(input.profileCore) !== input.profileId) {
    fail('local verifier PF10 structural profile ID is invalid');
  }
  const binding = exactKeySet(input.binding, [
    'baseSats',
    'lockingBytecode',
    'redeemBytecode',
  ], 'local verifier PF10 structural binding');
  const state = exactKeySet(input.state, [
    'baseSats',
    'helperBytecode',
    'helperUnlockingBytecode',
    'lockingBytecode',
  ], 'local verifier PF10 structural state');
  if (
    !Array.isArray(input.verifiers)
    || input.verifiers.length !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
  ) {
    fail('local verifier PF10 structural verifier set is invalid');
  }
  const verifierRecords = input.verifiers.map((entry, index) => {
    const record = exactKeySet(entry, [
      'baseSats',
      'lockingBytecode',
      'role',
    ], `local verifier PF10 structural verifier ${index}`);
    if (
      record.role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index]
      || typeof record.baseSats !== 'string'
      || !/^(0|[1-9][0-9]*)$/.test(record.baseSats)
    ) {
      fail(`local verifier PF10 structural verifier ${index} is invalid`);
    }
    return Object.freeze({
      ...record,
      lockingBytecode: requiredRuntimeBytes(
        record.lockingBytecode,
        `local verifier PF10 structural verifier ${index} lock`,
      ),
    });
  });
  if (
    typeof binding.baseSats !== 'string'
    || !/^(0|[1-9][0-9]*)$/.test(binding.baseSats)
    || typeof state.baseSats !== 'string'
    || !/^(0|[1-9][0-9]*)$/.test(state.baseSats)
  ) {
    fail('local verifier PF10 structural base values are invalid');
  }
  const actualBindingRedeem = requiredRuntimeBytes(
    binding.redeemBytecode,
    'local verifier PF10 structural binding redeem',
  );
  const actualBindingLock = requiredRuntimeBytes(
    binding.lockingBytecode,
    'local verifier PF10 structural binding lock',
  );
  const actualHelper = requiredRuntimeBytes(
    state.helperBytecode,
    'local verifier PF10 structural state helper',
  );
  const actualHelperUnlock = requiredRuntimeBytes(
    state.helperUnlockingBytecode,
    'local verifier PF10 structural state helper unlock',
  );
  const actualStateLock = requiredRuntimeBytes(
    state.lockingBytecode,
    'local verifier PF10 structural state lock',
  );
  let expectedBindingRedeem;
  let expectedBindingLock;
  let expectedHelper;
  let expectedHelperUnlock;
  let expectedStateLock;
  try {
    const bindingOptions = Object.freeze({
      networkId: input.profileCore.network.id,
      profileId: input.profileId,
      stateCategory: input.instanceId,
      denominationSats: input.profileCore.denominationSats,
      topologyId: input.topologyId,
      verifierRoles: input.verifierRoles,
    });
    expectedBindingRedeem = Buffer.from(
      buildDirectV2BindingRedeem(bindingOptions),
    );
    expectedBindingLock = Buffer.from(
      buildDirectV2BindingLock(bindingOptions),
    );
    expectedHelper = Buffer.from(buildDirectV2StateHelper({
      bindingLock: expectedBindingLock,
      verifierLocks: verifierRecords.map((record) =>
        record.lockingBytecode),
      verifierBaseValues: verifierRecords.map((record) => record.baseSats),
      bindingBaseValueSats: binding.baseSats,
      stateBaseValueSats: state.baseSats,
      denominationSats: input.profileCore.denominationSats,
      stateCategory: input.instanceId,
      minimumChangeSats: V2_MINIMUM_CHANGE_SATS,
      topologyId: input.topologyId,
      verifierRoles: input.verifierRoles,
    }));
    expectedHelperUnlock = Buffer.from(
      buildDirectV2StateTrampolineUnlock(expectedHelper),
    );
    expectedStateLock = Buffer.from(buildDirectV2StateTrampolineLock({
      helper: expectedHelper,
      bindingLock: expectedBindingLock,
      topologyId: input.topologyId,
      verifierRoles: input.verifierRoles,
    }));
  } catch (error) {
    fail(
      `local verifier PF10 structural artifacts cannot be reconstructed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    !actualBindingRedeem.equals(expectedBindingRedeem)
    || !actualBindingLock.equals(expectedBindingLock)
  ) {
    fail('local verifier PF10 binding artifacts are not exact for the profile and instance');
  }
  if (!actualHelper.equals(expectedHelper)) {
    fail('local verifier PF10 state helper is not the exact structural helper');
  }
  if (!actualHelperUnlock.equals(expectedHelperUnlock)) {
    fail('local verifier PF10 state helper unlock is not canonical');
  }
  if (!actualStateLock.equals(expectedStateLock)) {
    fail('local verifier PF10 state lock is not the exact structural trampoline');
  }
  const derivedVerifierBases = verifierRecords.map((record) =>
    deriveV2RollingBaseSats({
      lockingBytecode: record.lockingBytecode,
    }).toString());
  if (
    derivedVerifierBases.some(
      (baseSats, index) => baseSats !== verifierRecords[index].baseSats,
    )
    || deriveV2RollingBaseSats({
      lockingBytecode: actualBindingLock,
    }).toString() !== binding.baseSats
    || deriveV2RollingBaseSats({
      lockingBytecode: actualStateLock,
      token: {
        category: Buffer.from(input.instanceId, 'hex'),
        amount: 0n,
        nft: {
          capability: 'mutable',
          commitment: Buffer.alloc(128),
        },
      },
    }).toString() !== state.baseSats
  ) {
    fail('local verifier PF10 structural base values are not exact dust values');
  }
  return Object.freeze({
    bindingLockSha256:
      createHash('sha256').update(actualBindingLock).digest('hex'),
    stateHelperSha256:
      createHash('sha256').update(actualHelper).digest('hex'),
    stateLockSha256:
      createHash('sha256').update(actualStateLock).digest('hex'),
  });
}

async function validateBundledDevelopmentProfile({
  artifacts,
  expectedProofIds,
  manifest,
  profileRoot,
  projectRoot,
  runtimeReferences,
}) {
  const canonicalProfileRoot = canonicalNonSymlinkDirectory(
    profileRoot,
    'local verifier V2 development profile root',
  );
  const profileCoreId =
    runtimeReferences.references.profileArtifacts.profileCore;
  const profilePackageId =
    runtimeReferences.references.profileArtifacts.profilePackage;
  const parsedCore = parseCanonicalRuntimeJsonArtifact(
    artifacts.get(profileCoreId),
    'local verifier PF10 bundled profile core',
  );
  const parsedPackage = parseCanonicalRuntimeJsonArtifact(
    artifacts.get(profilePackageId),
    'local verifier PF10 bundled development profile package',
  );
  let verifiedPackage;
  try {
    validateProfileCore(parsedCore.value);
    if (deriveProfileId(parsedCore.value) !== manifest.profileId) {
      fail('local verifier PF10 bundled profile identity is invalid');
    }
    verifiedPackage = await verifyV2DevelopmentProfilePackage(
      parsedPackage.value,
      {
        directory: canonicalProfileRoot,
        repositoryRoot: path.resolve(projectRoot, '..'),
      },
    );
  } catch (error) {
    fail(
      `local verifier PF10 bundled development profile is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    verifiedPackage.profileId !== manifest.profileId
    || verifiedPackage.profileCoreSha256
      !== artifacts.get(profileCoreId).sha256
  ) {
    fail('local verifier PF10 bundled profile identity is invalid');
  }
  const generatedIds = Object.freeze({
    baseVerifierManifest:
      runtimeReferences.references.profileArtifacts.baseVerifierManifest,
    circuitBuildAttestation:
      runtimeReferences.references.attestationArtifacts
        .circuitBuildAttestation,
    developmentSetupAttestation:
      runtimeReferences.references.attestationArtifacts
        .developmentSetupAttestation,
    profileCore: profileCoreId,
    relationManifest:
      runtimeReferences.references.attestationArtifacts.relationManifest,
    toolchainManifest:
      runtimeReferences.references.profileArtifacts.toolchainManifest,
    topologySpec:
      runtimeReferences.references.profileArtifacts.topologySpec,
  });
  for (const [name, artifactId] of Object.entries(generatedIds)) {
    const record = verifiedPackage.generatedArtifacts[name];
    const artifact = artifacts.get(artifactId);
    if (
      record === undefined
      || artifact === undefined
      || record.bytes !== artifact.bytes
      || record.sha256 !== artifact.sha256
    ) {
      fail(
        `local verifier PF10 bundled profile generated artifact ${name} is not source-bound`,
      );
    }
  }
  for (const [name, artifactId] of Object.entries(expectedProofIds)) {
    const record = verifiedPackage.proofArtifacts[name];
    const artifact = artifacts.get(artifactId);
    if (
      record === undefined
      || artifact === undefined
      || record.bytes !== artifact.bytes
      || record.sha256 !== artifact.sha256
    ) {
      fail(
        `local verifier PF10 bundled profile proof artifact ${name} is not source-bound`,
      );
    }
  }
  if (
    parsedCore.value.proof.r1csSha256
      !== artifacts.get(expectedProofIds.r1cs).sha256
    || parsedCore.value.proof.verificationKeySha256
      !== artifacts.get(expectedProofIds.verificationKey).sha256
    || parsedCore.value.proof.witnessWasmSha256
      !== artifacts.get(expectedProofIds.witnessWasm).sha256
  ) {
    fail('local verifier PF10 bundled profile proof hashes are incoherent');
  }
  return Object.freeze({
    profileCore: parsedCore.value,
    profilePackage: verifiedPackage,
  });
}

function candidateRuntimeReferenceIds(value) {
  try {
    return [
      ...Object.values(requiredObject(
        value.profileArtifacts,
        'PF10 runtime artifact.profileArtifacts',
      )),
      ...Object.values(requiredObject(
        value.attestationArtifacts,
        'PF10 runtime artifact.attestationArtifacts',
      )),
      ...Object.values(requiredObject(
        value.setupArtifacts,
        'PF10 runtime artifact.setupArtifacts',
      )),
      ...Object.values(requiredObject(
        value.proofArtifacts,
        'PF10 runtime artifact.proofArtifacts',
      )),
      value.unlockArtifacts.executorBodyArtifactId,
      ...value.unlockArtifacts.exactMsmRedeemArtifactIds,
      ...value.unlockArtifacts.fixedCarrierPadArtifactIds,
      value.unlockArtifacts.fusedRedeemArtifactId,
      value.unlockArtifacts.terminalRedeemArtifactId,
      value.qualificationEvidenceArtifactId,
      value.rawQualificationEvidenceArtifactId,
      value.libauthEvidenceArtifactId,
    ];
  } catch (error) {
    if (error instanceof DomainTestRunnerError) throw error;
    fail(
      `PF10 runtime artifact reference structure is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

function validatePf10FinalLockReferences(value, artifacts) {
  const finalLocks = exactKeySet(
    value,
    ['binding', 'state', 'topologyId', 'verifiers'],
    'local verifier PF10 runtime finalLocks',
  );
  if (
    finalLocks.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !Array.isArray(finalLocks.verifiers)
    || finalLocks.verifiers.length
      !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
  ) {
    fail('local verifier PF10 runtime finalLocks topology is invalid');
  }
  const ids = [];
  for (
    let index = 0;
    index < DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length;
    index += 1
  ) {
    const record = exactKeySet(
      finalLocks.verifiers[index],
      ['baseSats', 'lockingArtifactId', 'role'],
      `local verifier PF10 runtime finalLocks.verifiers[${index}]`,
    );
    if (
      record.baseSats !== '1200'
      || record.role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index]
      || record.lockingArtifactId !== `verifier-lock-${index}`
      || !artifacts.has(record.lockingArtifactId)
    ) {
      fail('local verifier PF10 runtime verifier final lock is invalid');
    }
    ids.push(record.lockingArtifactId);
  }
  const binding = exactKeySet(
    finalLocks.binding,
    ['baseSats', 'lockingArtifactId', 'redeemArtifactId'],
    'local verifier PF10 runtime finalLocks.binding',
  );
  if (
    binding.baseSats !== '1200'
    || binding.lockingArtifactId !== 'binding-lock'
    || binding.redeemArtifactId !== 'binding-redeem'
    || !artifacts.has(binding.lockingArtifactId)
    || !artifacts.has(binding.redeemArtifactId)
  ) {
    fail('local verifier PF10 runtime binding final lock is invalid');
  }
  ids.push(binding.lockingArtifactId, binding.redeemArtifactId);
  const state = exactKeySet(
    finalLocks.state,
    [
      'baseSats',
      'helperArtifactId',
      'helperUnlockArtifactId',
      'lockingArtifactId',
    ],
    'local verifier PF10 runtime finalLocks.state',
  );
  if (
    state.baseSats !== '2500'
    || state.helperArtifactId !== 'state-helper'
    || state.helperUnlockArtifactId !== 'state-helper-unlock'
    || state.lockingArtifactId !== 'state-lock'
    || !artifacts.has(state.helperArtifactId)
    || !artifacts.has(state.helperUnlockArtifactId)
    || !artifacts.has(state.lockingArtifactId)
  ) {
    fail('local verifier PF10 runtime state final lock is invalid');
  }
  ids.push(
    state.helperArtifactId,
    state.helperUnlockArtifactId,
    state.lockingArtifactId,
  );
  if (new Set(ids).size !== ids.length) {
    fail('local verifier PF10 runtime final lock artifacts are duplicated');
  }
  return Object.freeze({
    ids: Object.freeze(ids),
    binding,
    state,
    verifiers: Object.freeze(finalLocks.verifiers),
  });
}

function exactManifestArtifactReference(value, artifacts, expectedId, label) {
  const reference = exactKeySet(
    value,
    ['bytes', 'id', 'path', 'sha256'],
    label,
  );
  const artifact = artifacts.get(expectedId);
  if (
    artifact === undefined
    || reference.id !== expectedId
    || reference.path !== artifact.path
    || reference.sha256 !== artifact.sha256
    || reference.bytes !== artifact.bytes
  ) {
    fail(`${label} does not bind the emitted runtime artifact`);
  }
  return artifact;
}

async function validatePf10LibauthPublication(libauthRoot) {
  const completion = await readCanonicalJsonRegularFile(
    path.join(libauthRoot, PF10_LIBAUTH_PUBLICATION_FILE),
    'local verifier PF10 Libauth publication completion record',
  );
  const value = exactKeySet(
    completion.value,
    ['files', 'schema'],
    'local verifier PF10 Libauth publication completion record',
  );
  if (
    value.schema !== PF10_LIBAUTH_PUBLICATION_SCHEMA
    || !Array.isArray(value.files)
    || value.files.length !== PF10_LIBAUTH_PUBLICATION_FILES.length
  ) {
    fail('local verifier PF10 Libauth publication completion record is invalid');
  }
  const records = new Map();
  for (let index = 0; index < value.files.length; index += 1) {
    const expectedPath = PF10_LIBAUTH_PUBLICATION_FILES[index];
    const record = exactKeySet(
      value.files[index],
      ['bytes', 'path', 'sha256'],
      `local verifier PF10 Libauth publication file ${index}`,
    );
    if (
      record.path !== expectedPath
      || !Number.isSafeInteger(record.bytes)
      || record.bytes < 0
      || records.has(record.path)
    ) {
      fail('local verifier PF10 Libauth publication file set is invalid');
    }
    const filename = safeRuntimeArtifactPath(
      libauthRoot,
      record.path,
      `local verifier PF10 Libauth publication file ${record.path}`,
    );
    const actual = await sha256RegularFile(
      filename,
      `local verifier PF10 Libauth publication file ${record.path}`,
      {
        allowEmpty: record.path === 'stderr.txt'
          || record.path === 'stdout.txt',
        includeData: true,
      },
    );
    if (
      actual.bytes !== record.bytes
      || actual.sha256 !== requiredHash(
        record.sha256,
        `local verifier PF10 Libauth publication file ${record.path}.sha256`,
      )
    ) {
      fail(
        `local verifier PF10 Libauth publication file ${record.path} differs from its completion record`,
      );
    }
    records.set(record.path, Object.freeze({ ...actual, filename }));
  }
  return Object.freeze({ completion, records });
}

/**
 * Authenticate the completed PF10 runtime bundle, including every artifact
 * named by its manifest and the independently generated Libauth source
 * evidence. Existence alone is insufficient: a stale or tampered runtime must
 * never unlock the local verifier lane.
 */
async function inspectLocalVerifierRuntimeCoherence({
  projectRoot = project,
  runtimeRoot: runtimeRootOverride,
  libauthRoot: libauthRootOverride,
  profileRoot: profileRootOverride,
  qualificationEvidenceSha256: expectedQualificationEvidenceSha256,
} = {}) {
  const artifactRoot = path.resolve(projectRoot, '..', '.codex-build');
  const runtimeRoot = canonicalNonSymlinkDirectory(
    runtimeRootOverride
      ?? path.join(artifactRoot, 'v2-pf10-development-runtime'),
    'local verifier PF10 runtime root',
  );
  const libauthRoot = canonicalNonSymlinkDirectory(
    libauthRootOverride
      ?? path.join(artifactRoot, 'v2-pf10-libauth-qualification'),
    'local verifier PF10 Libauth qualification root',
  );
  const profileRoot = profileRootOverride
    ?? path.join(artifactRoot, 'v2-development-profile');
  const manifestSource = await readCanonicalJsonRegularFile(
    path.join(runtimeRoot, 'runtime-build-manifest.json'),
    'local verifier PF10 runtime build manifest',
  );
  const manifest = exactKeySet(manifestSource.value, [
    'artifactManifestTemplate',
    'build',
    'determinism',
    'eligibility',
    'finalLocks',
    'instanceId',
    'libauthEvidence',
    'prerequisites',
    'profileCore',
    'profileId',
    'profilePackage',
    'proofArtifacts',
    'qualification',
    'runtimeMaterialSha256',
    'schema',
    'topologyId',
    'verifierRoles',
  ], 'local verifier PF10 runtime build manifest');
  if (
    manifest.schema !== PF10_DEVELOPMENT_RUNTIME_BUNDLE_SCHEMA
    || manifest.eligibility !== 'development-only'
    || !SHA256.test(manifest.profileId)
    || !SHA256.test(manifest.instanceId)
    || manifest.topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !Array.isArray(manifest.verifierRoles)
    || manifest.verifierRoles.length
      !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length
    || manifest.verifierRoles.some(
      (role, index) =>
        role !== DIRECT_V2_PF10_FUSED_VERIFIER_ROLES[index],
    )
  ) {
    fail('local verifier PF10 runtime build manifest identity is unsupported');
  }
  const {
    validateDirectV2Pf10LibauthEvidence,
    validateDirectV2Pf10Reproducibility,
  } = await loadPf10DevelopmentRuntimeBuilder();
  const {
    PF10_UNSIGNED_RUNTIME_REFERENCE_COUNT,
    validateV2DevelopmentPf10QualificationArtifacts,
    validateV2UnsignedPf10RuntimeArtifactReferences,
  } = await loadV2InstanceDescriptor();
  const template = exactKeySet(
    manifest.artifactManifestTemplate,
    ['artifacts', 'instanceId', 'profileId', 'schema'],
    'local verifier PF10 runtime artifact manifest',
  );
  if (
    template.schema !== V2_ARTIFACT_MANIFEST_SCHEMA
    || template.profileId !== manifest.profileId
    || template.instanceId !== manifest.instanceId
    || !Array.isArray(template.artifacts)
    || template.artifacts.length === 0
  ) {
    fail('local verifier PF10 runtime artifact manifest is invalid');
  }
  const artifacts = new Map();
  const artifactPaths = new Set();
  let previousArtifactId;
  for (let index = 0; index < template.artifacts.length; index += 1) {
    const label = `local verifier PF10 runtime artifact[${index}]`;
    const record = exactKeySet(
      template.artifacts[index],
      ['id', 'path', 'sha256'],
      label,
    );
    if (
      typeof record.id !== 'string'
      || !/^[a-z0-9][a-z0-9-]*$/.test(record.id)
      || artifacts.has(record.id)
      || (
        previousArtifactId !== undefined
        && compareAscii(previousArtifactId, record.id) >= 0
      )
    ) {
      fail(`${label}.id is invalid, duplicated, or out of order`);
    }
    previousArtifactId = record.id;
    const expectedSha256 = requiredHash(record.sha256, `${label}.sha256`);
    const filename = safeRuntimeArtifactPath(
      runtimeRoot,
      record.path,
      `${label}.path`,
    );
    if (artifactPaths.has(record.path)) {
      fail(`${label}.path aliases another runtime artifact`);
    }
    artifactPaths.add(record.path);
    const actual = await sha256RegularFile(filename, label, {
      includeData: PF10_RUNTIME_CONSUMED_ARTIFACT_IDS.has(record.id),
    });
    if (actual.sha256 !== expectedSha256) {
      fail(`${label} differs from the runtime artifact manifest`);
    }
    artifacts.set(record.id, Object.freeze({
      ...record,
      bytes: actual.bytes,
      ...(actual.data === undefined ? {} : { data: actual.data }),
      filename,
    }));
  }
  assertExactRuntimeBundleEntries(runtimeRoot, artifactPaths);

  const runtimeArtifactRecord = artifacts.get('pf10-runtime-material');
  if (runtimeArtifactRecord === undefined) {
    fail('local verifier PF10 runtime omits pf10-runtime-material');
  }
  const parsedRuntimeArtifact = parseCanonicalRuntimeJsonArtifact(
    runtimeArtifactRecord,
    'local verifier PF10 runtime material artifact',
  );
  const runtimeArtifact = parsedRuntimeArtifact.value;
  const candidateReferenceIds = candidateRuntimeReferenceIds(runtimeArtifact);
  const candidateEntries = {};
  for (const id of candidateReferenceIds) {
    const artifact = artifacts.get(id);
    if (artifact !== undefined) {
      candidateEntries[id] = Object.freeze({
        id,
        sha256: artifact.sha256,
      });
    }
  }
  let runtimeReferences;
  try {
    runtimeReferences = validateV2UnsignedPf10RuntimeArtifactReferences({
      artifactEntries: candidateEntries,
      instanceId: manifest.instanceId,
      profileId: manifest.profileId,
      runtimeArtifact,
    });
  } catch (error) {
    fail(
      `local verifier PF10 runtime reference topology is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    runtimeReferences.referencedArtifactCount
      !== PF10_UNSIGNED_RUNTIME_REFERENCE_COUNT
  ) {
    fail('local verifier PF10 runtime reference count is invalid');
  }
  const finalLocks = validatePf10FinalLockReferences(
    manifest.finalLocks,
    artifacts,
  );
  const expectedArtifactIds = new Set([
    ...runtimeReferences.referencedArtifactIds,
    ...finalLocks.ids,
    ...PF10_REPRODUCIBILITY_ARTIFACT_IDS,
    'pf10-runtime-material',
  ]);
  const actualArtifactIds = [...artifacts.keys()].sort(compareAscii);
  const expectedSortedIds = [...expectedArtifactIds].sort(compareAscii);
  if (
    expectedArtifactIds.size !== PF10_DEVELOPMENT_RUNTIME_ARTIFACT_COUNT
    || actualArtifactIds.length !== PF10_DEVELOPMENT_RUNTIME_ARTIFACT_COUNT
    || actualArtifactIds.some(
      (id, index) => id !== expectedSortedIds[index],
    )
  ) {
    fail(
      `local verifier PF10 runtime must contain the exact ${
        PF10_DEVELOPMENT_RUNTIME_ARTIFACT_COUNT
      }-artifact bundle`,
    );
  }
  const proofArtifacts = exactKeySet(
    manifest.proofArtifacts,
    [
      'circuitSymbols',
      'initialProvingKey',
      'powersOfTau',
      'provingKey',
      'r1cs',
      'verificationKey',
      'witnessWasm',
    ],
    'local verifier PF10 runtime build manifest.proofArtifacts',
  );
  const expectedProofIds = Object.freeze({
    circuitSymbols: runtimeReferences.references.setupArtifacts.circuitSymbols,
    initialProvingKey:
      runtimeReferences.references.setupArtifacts.initialProvingKey,
    powersOfTau: runtimeReferences.references.setupArtifacts.powersOfTau,
    provingKey: runtimeReferences.references.proofArtifacts.provingKey,
    r1cs: runtimeReferences.references.proofArtifacts.r1cs,
    verificationKey:
      runtimeReferences.references.proofArtifacts.verificationKey,
    witnessWasm: runtimeReferences.references.proofArtifacts.wasm,
  });
  const proofArtifactHashes = {};
  for (const [name, expectedId] of Object.entries(expectedProofIds)) {
    const label =
      `local verifier PF10 runtime build manifest.proofArtifacts.${name}`;
    const artifact = exactManifestArtifactReference(
      proofArtifacts[name],
      artifacts,
      expectedId,
      label,
    );
    proofArtifactHashes[name] = artifact.sha256;
  }
  exactManifestArtifactReference(
    manifest.profileCore,
    artifacts,
    runtimeReferences.references.profileArtifacts.profileCore,
    'local verifier PF10 runtime build manifest.profileCore',
  );
  exactManifestArtifactReference(
    manifest.profilePackage,
    artifacts,
    runtimeReferences.references.profileArtifacts.profilePackage,
    'local verifier PF10 runtime build manifest.profilePackage',
  );
  const prerequisites = exactKeySet(
    manifest.prerequisites,
    [
      'baseVerifierSourceManifest',
      'circuitBuildAttestation',
      'developmentSetupAttestation',
      'relationSourceManifest',
      'semantics',
      'toolchainManifest',
      'topologySpec',
    ],
    'local verifier PF10 runtime build manifest.prerequisites',
  );
  for (const [name, expectedId] of Object.entries({
    baseVerifierSourceManifest:
      runtimeReferences.references.profileArtifacts.baseVerifierManifest,
    circuitBuildAttestation:
      runtimeReferences.references.attestationArtifacts
        .circuitBuildAttestation,
    developmentSetupAttestation:
      runtimeReferences.references.attestationArtifacts
        .developmentSetupAttestation,
    relationSourceManifest:
      runtimeReferences.references.attestationArtifacts.relationManifest,
    toolchainManifest:
      runtimeReferences.references.profileArtifacts.toolchainManifest,
    topologySpec:
      runtimeReferences.references.profileArtifacts.topologySpec,
  })) {
    exactManifestArtifactReference(
      prerequisites[name],
      artifacts,
      expectedId,
      `local verifier PF10 runtime build manifest.prerequisites.${name}`,
    );
  }
  const parsedBundledProfileCore = parseCanonicalRuntimeJsonArtifact(
    artifacts.get(
      runtimeReferences.references.profileArtifacts.profileCore,
    ),
    'local verifier PF10 bundled profile core',
  );
  let bundledProfileCore;
  try {
    bundledProfileCore = validateProfileCore(
      parsedBundledProfileCore.value,
    );
    if (deriveProfileId(bundledProfileCore) !== manifest.profileId) {
      fail('local verifier PF10 bundled profile identity is invalid');
    }
  } catch (error) {
    fail(
      `local verifier PF10 bundled development profile is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    typeof prerequisites.semantics !== 'string'
    || prerequisites.semantics.length === 0
  ) {
    fail('local verifier PF10 runtime prerequisite semantics are missing');
  }
  const qualification = exactKeySet(
    manifest.qualification,
    [
      'canonicalRecord',
      'canonicalRecordSchema',
      'rawEvidence',
      'rawTelemetryIncluded',
    ],
    'local verifier PF10 runtime build manifest.qualification',
  );
  const canonicalQualificationArtifact = exactManifestArtifactReference(
    qualification.canonicalRecord,
    artifacts,
    runtimeReferences.references.qualificationEvidenceArtifactId,
    'local verifier PF10 runtime qualification canonical record',
  );
  const rawQualificationArtifact = exactManifestArtifactReference(
    qualification.rawEvidence,
    artifacts,
    runtimeReferences.references.rawQualificationEvidenceArtifactId,
    'local verifier PF10 runtime qualification raw evidence',
  );
  if (
    qualification.canonicalRecordSchema
      !== 'shieldkit-v2-direct-pf10-canonical-qualification-record-v1'
    || qualification.rawTelemetryIncluded !== true
  ) {
    fail('local verifier PF10 runtime qualification metadata is invalid');
  }
  let validatedQualification;
  try {
    validatedQualification =
      validateV2DevelopmentPf10QualificationArtifacts({
        canonicalRecordBytes: readPinnedRuntimeArtifactBytes(
          canonicalQualificationArtifact,
          'local verifier PF10 canonical qualification record',
        ),
        rawEvidenceBytes: readPinnedRuntimeArtifactBytes(
          rawQualificationArtifact,
          'local verifier PF10 raw qualification evidence',
        ),
        profileId: manifest.profileId,
        instanceId: manifest.instanceId,
        maximumLiveNotes: '32',
        denominationSats: bundledProfileCore.denominationSats,
        profileCoreSha256: artifacts.get(
          runtimeReferences.references.profileArtifacts.profileCore,
        ).sha256,
        proofArtifactHashes: Object.freeze({
          provingKey: proofArtifactHashes.provingKey,
          r1cs: proofArtifactHashes.r1cs,
          verificationKey: proofArtifactHashes.verificationKey,
          wasm: proofArtifactHashes.witnessWasm,
        }),
      });
  } catch (error) {
    fail(
      `local verifier PF10 qualification artifacts are semantically invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    expectedQualificationEvidenceSha256 !== undefined
    && (
      !SHA256.test(expectedQualificationEvidenceSha256)
      || validatedQualification.rawEvidenceSha256
        !== expectedQualificationEvidenceSha256
    )
  ) {
    fail(
      'local verifier PF10 runtime does not byte-bind the current qualification evidence',
    );
  }
  exactKeySet(
    manifest.determinism,
    ['qualificationTelemetry', 'runtimeMaterial'],
    'local verifier PF10 runtime build manifest.determinism',
  );
  const build = exactKeySet(
    manifest.build,
    ['fixedTables', 'layout', 'programs', 'toolchain'],
    'local verifier PF10 runtime build manifest.build',
  );
  requiredObject(
    build.fixedTables,
    'local verifier PF10 runtime build fixedTables',
  );
  requiredObject(build.layout, 'local verifier PF10 runtime build layout');
  requiredObject(build.toolchain, 'local verifier PF10 runtime build toolchain');
  const programs = exactKeySet(
    build.programs,
    ['exactFinal', 'exactMsm', 'executor', 'fused', 'miller', 'terminal'],
    'local verifier PF10 runtime build programs',
  );
  const reproducibilityPrograms = [
    ['executor', programs.executor, 'repro-executor'],
    ['exactFinal', programs.exactFinal, 'repro-exactfinal'],
    ['miller', programs.miller, 'repro-miller'],
    ['terminal', programs.terminal, 'repro-terminal'],
  ];
  if (!Array.isArray(programs.exactMsm) || programs.exactMsm.length !== 3) {
    fail('local verifier PF10 runtime exact-MSM reproducibility metadata is invalid');
  }
  programs.exactMsm.forEach((program, index) => {
    reproducibilityPrograms.push([
      `exactMsm[${index}]`,
      program,
      `repro-exact-msm-${index}`,
    ]);
  });
  const reproducibilityInputs = new Map();
  for (const [name, programValue, artifactPrefix] of reproducibilityPrograms) {
    const program = exactKeySet(
      programValue,
      ['lock', 'raw', 'redeem', 'source'],
      `local verifier PF10 runtime build programs.${name}`,
    );
    const retained = {};
    for (const kind of ['raw', 'source']) {
      const artifact = artifacts.get(`${artifactPrefix}-${kind}`);
      if (
        artifact === undefined
        || program[kind] !== artifact.sha256
      ) {
        fail(
          `local verifier PF10 runtime build programs.${name}.${kind} `
          + 'does not bind its reproducibility artifact',
        );
      }
      retained[kind] = readPinnedRuntimeArtifactBytes(
        artifact,
        `local verifier PF10 runtime reproducibility ${name}.${kind}`,
      );
    }
    reproducibilityInputs.set(name, Object.freeze(retained));
  }
  const fusedProgram = exactKeySet(
    programs.fused,
    ['lock', 'redeem'],
    'local verifier PF10 runtime build programs.fused',
  );
  const validateRuntimeReproducibility = async () => {
    const reproducibilityTemporaryRoot = mkdtempSync(path.join(
      artifactRoot,
      'v2-pf10-repro-check-',
    ));
    chmodSync(reproducibilityTemporaryRoot, 0o700);
    let reproduced;
    try {
      reproduced = await validateDirectV2Pf10Reproducibility({
        repositoryRoot: path.resolve(projectRoot, '..'),
        temporaryRoot: reproducibilityTemporaryRoot,
        programs: Object.freeze({
          executor: reproducibilityInputs.get('executor'),
          exactFinal: reproducibilityInputs.get('exactFinal'),
          exactMsm: Object.freeze(Array.from(
            { length: 3 },
            (_, index) => reproducibilityInputs.get(`exactMsm[${index}]`),
          )),
          miller: reproducibilityInputs.get('miller'),
          terminal: reproducibilityInputs.get('terminal'),
        }),
        runtimeArtifacts: Object.freeze({
          executorBody: readPinnedRuntimeArtifactBytes(
            artifacts.get('pf10-executor-body'),
            'local verifier PF10 executor body',
          ),
          exactMsmRedeems: Object.freeze(Array.from(
            { length: 3 },
            (_, index) => readPinnedRuntimeArtifactBytes(
              artifacts.get(`pf10-exact-msm-redeem-${index}`),
              `local verifier PF10 exact-MSM redeem ${index}`,
            ),
          )),
          fusedRedeem: readPinnedRuntimeArtifactBytes(
            artifacts.get('pf10-fused-redeem'),
            'local verifier PF10 fused redeem',
          ),
          terminalRedeem: readPinnedRuntimeArtifactBytes(
            artifacts.get('pf10-terminal-redeem'),
            'local verifier PF10 terminal redeem',
          ),
        }),
      });
    } catch (error) {
      fail(
        `local verifier PF10 reproducibility validation failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    } finally {
      rmSync(reproducibilityTemporaryRoot, {
        recursive: true,
        force: false,
      });
    }
    for (const name of ['executor', 'exactFinal', 'miller', 'terminal']) {
      if (
        canonicalizeJcs(programs[name])
          !== canonicalizeJcs(reproduced.programs[name])
      ) {
        fail(
          `local verifier PF10 runtime build program ${name} is not exactly reproducible`,
        );
      }
    }
    for (let index = 0; index < 3; index += 1) {
      if (
        canonicalizeJcs(programs.exactMsm[index])
          !== canonicalizeJcs(reproduced.programs.exactMsm[index])
      ) {
        fail(
          `local verifier PF10 runtime build exact-MSM program ${index} is not exactly reproducible`,
        );
      }
    }
    if (
      canonicalizeJcs(fusedProgram)
        !== canonicalizeJcs(reproduced.programs.fused)
    ) {
      fail(
        'local verifier PF10 runtime build fused program is not exactly reproducible',
      );
    }
    return reproduced;
  };

  const bindingRedeemBytecode = readPinnedRuntimeArtifactBytes(
    artifacts.get(finalLocks.binding.redeemArtifactId),
    'local verifier PF10 binding redeem',
  );
  const bindingLockingBytecode = readPinnedRuntimeArtifactBytes(
    artifacts.get(finalLocks.binding.lockingArtifactId),
    'local verifier PF10 binding lock',
  );
  const verifierLockingBytecodes = finalLocks.verifiers.map(
    (record, index) => readPinnedRuntimeArtifactBytes(
      artifacts.get(record.lockingArtifactId),
      `local verifier PF10 verifier lock ${index}`,
    ),
  );
  const stateHelperBytecode = readPinnedRuntimeArtifactBytes(
    artifacts.get(finalLocks.state.helperArtifactId),
    'local verifier PF10 state helper',
  );
  const stateHelperUnlockingBytecode = readPinnedRuntimeArtifactBytes(
    artifacts.get(finalLocks.state.helperUnlockArtifactId),
    'local verifier PF10 state helper unlock',
  );
  const stateLockingBytecode = readPinnedRuntimeArtifactBytes(
    artifacts.get(finalLocks.state.lockingArtifactId),
    'local verifier PF10 state lock',
  );
  validateExactDirectV2Pf10StructuralArtifacts({
    profileCore: bundledProfileCore,
    profileId: manifest.profileId,
    instanceId: manifest.instanceId,
    topologyId: manifest.topologyId,
    verifierRoles: manifest.verifierRoles,
    binding: {
      baseSats: finalLocks.binding.baseSats,
      lockingBytecode: bindingLockingBytecode,
      redeemBytecode: bindingRedeemBytecode,
    },
    state: {
      baseSats: finalLocks.state.baseSats,
      helperBytecode: stateHelperBytecode,
      helperUnlockingBytecode: stateHelperUnlockingBytecode,
      lockingBytecode: stateLockingBytecode,
    },
    verifiers: finalLocks.verifiers.map((record, index) => ({
      baseSats: record.baseSats,
      lockingBytecode: verifierLockingBytecodes[index],
      role: record.role,
    })),
  });

  let validatedRuntimeMaterial;
  try {
    validatedRuntimeMaterial = validateDirectV2Pf10RuntimeMaterial({
      schema: DIRECT_V2_PF10_RUNTIME_SCHEMA,
      eligibility: manifest.eligibility,
      profileId: manifest.profileId,
      instanceId: manifest.instanceId,
      topologyId: manifest.topologyId,
      verifierRoles: manifest.verifierRoles,
      proofArtifactHashes: Object.freeze({
        provingKey: proofArtifactHashes.provingKey,
        r1cs: proofArtifactHashes.r1cs,
        verificationKey: proofArtifactHashes.verificationKey,
        wasm: proofArtifactHashes.witnessWasm,
      }),
      verificationKeyBytes: readPinnedRuntimeArtifactBytes(
        artifacts.get(expectedProofIds.verificationKey),
        'local verifier PF10 verification key',
      ),
      executorBody: readPinnedRuntimeArtifactBytes(
        artifacts.get(
          runtimeReferences.references.unlockArtifacts.executorBody,
        ),
        'local verifier PF10 executor body',
      ),
      exactMsmRedeems:
        runtimeReferences.references.unlockArtifacts.exactMsmRedeems.map(
          (id, index) => readPinnedRuntimeArtifactBytes(
            artifacts.get(id),
            `local verifier PF10 exact-MSM redeem ${index}`,
          ),
        ),
      fixedCarrierPads:
        runtimeReferences.references.unlockArtifacts.fixedCarrierPads.map(
          (id, index) => readPinnedRuntimeArtifactBytes(
            artifacts.get(id),
            `local verifier PF10 fixed carrier pad ${index}`,
          ),
        ),
      fusedRedeem: readPinnedRuntimeArtifactBytes(
        artifacts.get(
          runtimeReferences.references.unlockArtifacts.fusedRedeem,
        ),
        'local verifier PF10 fused redeem',
      ),
      terminalRedeem: readPinnedRuntimeArtifactBytes(
        artifacts.get(
          runtimeReferences.references.unlockArtifacts.terminalRedeem,
        ),
        'local verifier PF10 terminal redeem',
      ),
      stateUnlockingBytecode: stateHelperUnlockingBytecode,
      bindingRedeemBytecode,
      bindingLockingBytecode,
      verifierLockingBytecodes,
    });
  } catch (error) {
    fail(
      `local verifier PF10 runtime material is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const runtimeMaterialSha256 = requiredHash(
    manifest.runtimeMaterialSha256,
    'local verifier PF10 runtime build manifest.runtimeMaterialSha256',
  );
  if (validatedRuntimeMaterial.materialSha256 !== runtimeMaterialSha256) {
    fail('local verifier PF10 runtime material commitment is invalid');
  }

  const libauthPublication = await validatePf10LibauthPublication(libauthRoot);
  const summarySource =
    libauthPublication.records.get('qualification-summary.json');
  let summary;
  try {
    summary = JSON.parse(summarySource.data.toString('utf8'));
  } catch (error) {
    fail(
      `local verifier PF10 Libauth qualification summary is not JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    !summarySource.data.equals(
      Buffer.from(canonicalizeJcs(summary), 'utf8'),
    )
  ) {
    fail('local verifier PF10 Libauth qualification summary is not canonical JCS');
  }
  requiredObject(summary, 'local verifier PF10 Libauth qualification summary');
  const summaryEvidence = requiredObject(
    summary.evidence,
    'local verifier PF10 Libauth qualification summary.evidence',
  );
  if (
    summary.schema !== PF10_LIBAUTH_QUALIFICATION_SCHEMA
    || summary.eligibility !== 'development-only'
    || summaryEvidence.path !== 'libauth.json'
    || !Number.isSafeInteger(summaryEvidence.bytes)
    || summaryEvidence.bytes <= 0
  ) {
    fail('local verifier PF10 Libauth qualification summary is invalid');
  }
  const sourceEvidenceFile = libauthPublication.records.get('libauth.json');
  if (
    sourceEvidenceFile.bytes !== summaryEvidence.bytes
    || sourceEvidenceFile.sha256 !== requiredHash(
      summaryEvidence.sha256,
      'local verifier PF10 Libauth qualification summary.evidence.sha256',
    )
  ) {
    fail('local verifier PF10 Libauth source evidence differs from its summary');
  }
  const bundledLibauth = artifacts.get('pf10-libauth-evidence');
  if (
    bundledLibauth.sha256 !== sourceEvidenceFile.sha256
    || bundledLibauth.bytes !== sourceEvidenceFile.bytes
  ) {
    fail('local verifier PF10 runtime does not byte-bind its Libauth source evidence');
  }
  const bundledLibauthBytes = readPinnedRuntimeArtifactBytes(
    bundledLibauth,
    'local verifier PF10 bundled Libauth evidence',
  );
  let validatedLibauth;
  try {
    validatedLibauth = validateDirectV2Pf10LibauthEvidence({
      bytes: bundledLibauthBytes,
      expectedTerminalProgramBytes: Object.freeze({
        raw: artifacts.get('repro-terminal-raw').bytes,
        redeem: artifacts.get(
          runtimeReferences.references.unlockArtifacts.terminalRedeem,
        ).bytes,
      }),
      profileId: manifest.profileId,
      instanceId: manifest.instanceId,
      proofArtifactHashes: Object.freeze({
        provingKey: proofArtifactHashes.provingKey,
        r1cs: proofArtifactHashes.r1cs,
        verificationKey: proofArtifactHashes.verificationKey,
        wasm: proofArtifactHashes.witnessWasm,
      }),
      runtimeMaterialSha256,
    });
  } catch (error) {
    fail(
      `local verifier PF10 Libauth evidence is semantically invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const manifestLibauth = exactKeySet(
    manifest.libauthEvidence,
    ['artifact', 'schema', 'semantics'],
    'local verifier PF10 runtime build manifest.libauthEvidence',
  );
  const manifestLibauthArtifact = exactKeySet(
    manifestLibauth.artifact,
    ['bytes', 'id', 'path', 'sha256'],
    'local verifier PF10 runtime build manifest.libauthEvidence.artifact',
  );
  if (
    manifestLibauth.schema !== validatedLibauth.schema
    || typeof manifestLibauth.semantics !== 'string'
    || manifestLibauth.semantics.length === 0
    || manifestLibauthArtifact.id !== bundledLibauth.id
    || manifestLibauthArtifact.path !== bundledLibauth.path
    || manifestLibauthArtifact.sha256 !== bundledLibauth.sha256
    || manifestLibauthArtifact.bytes !== bundledLibauth.bytes
  ) {
    fail('local verifier PF10 runtime Libauth manifest binding is invalid');
  }
  await validateRuntimeReproducibility();
  await validateBundledDevelopmentProfile({
    artifacts,
    expectedProofIds,
    manifest,
    profileRoot,
    projectRoot,
    runtimeReferences,
  });
  return Object.freeze({
    profileId: manifest.profileId,
    instanceId: manifest.instanceId,
    runtimeArtifactCount: artifacts.size,
    libauthEvidenceSha256: validatedLibauth.sha256,
    qualificationEvidenceSha256:
      validatedQualification.canonicalRecordSha256,
    rawQualificationEvidenceSha256:
      validatedQualification.rawEvidenceSha256,
    runtimeMaterialSha256: validatedLibauth.runtimeMaterialSha256,
    proofArtifacts: Object.freeze(proofArtifactHashes),
  });
}

export async function assertLocalVerifierRuntimeCoherence(options = {}) {
  try {
    return await inspectLocalVerifierRuntimeCoherence(options);
  } catch (error) {
    if (error instanceof DomainTestRunnerError) {
      fail(
        `local verifier runtime coherence is BLOCKED: ${error.message}. `
        + 'Cleanly regenerate the complete Libauth/runtime bundle; do not reuse partial state.',
      );
    }
    throw error;
  }
}

function classify(relativePath) {
  const cleanSourceReason = CLEAN_SOURCE_TESTS.get(relativePath);
  if (cleanSourceReason !== undefined) {
    return Object.freeze({
      classification: 'clean-source',
      reason: `${cleanSourceReason}; mandatory via test:clean-source and the clean-checkout CI job`,
    });
  }
  const betaRuntimeQualificationReason = BETA_RUNTIME_QUALIFICATION_TESTS.get(relativePath);
  if (betaRuntimeQualificationReason !== undefined) {
    return Object.freeze({
      classification: 'beta-runtime-qualification',
      reason: `${betaRuntimeQualificationReason}; run only via test:qualification:beta-runtime with the fixture environment required by that test`,
    });
  }
  const betaProductReason = BETA_PRODUCT_PORTABLE_SECURITY_TESTS.get(relativePath);
  if (betaProductReason !== undefined) {
    return Object.freeze({
      classification: 'beta-product-portable-security',
      reason: `${betaProductReason}; mandatory via npm test and test:beta-product:security`,
    });
  }
  if ((relativePath.startsWith('packages/kit/v2/beta-product-')
    || relativePath.startsWith('packages/profile/v2/beta-product-')
    || relativePath.startsWith('packages/prove/v2/native-groth16-'))
    && relativePath.endsWith('.test.mjs')) {
    fail(`${relativePath} must be explicitly registered as mandatory beta-product portable security coverage`);
  }
  const externalReason = EXTERNAL_FIXTURE_TESTS.get(relativePath);
  if (externalReason !== undefined) {
    return Object.freeze({
      classification: 'external-fixture',
      reason: `${externalReason}; run only via test:external:fixtures`,
    });
  }
  if (relativePath.startsWith('packages/prove/internal/covenants/')) {
    return Object.freeze({
      classification: 'local-covenant-qualification',
      reason: 'requires the explicitly materialized vendored qualification toolchain',
    });
  }
  if (VENDORED_VERIFIER_EXTERNAL_TESTS.has(relativePath)) {
    return Object.freeze({
      classification: 'external-verifier-source-qualification',
      reason: 'requires the omitted full verifier packages/build or packages/contracts source snapshot; test:external:verifier-source fails closed until that source is restored',
    });
  }
  if (relativePath.startsWith(`${VENDORED_VERIFIER_LANE_TEST_ROOT}/`)) {
    return Object.freeze({
      classification: 'local-verifier-lane-qualification',
      reason: 'tracked pinned BN254 verifier-lane test; requires the explicitly materialized vendored qualification toolchain',
    });
  }
  if (ARTIFACT_QUALIFICATION_TESTS.has(relativePath)) {
    return Object.freeze({
      classification: 'local-verifier-lane-qualification',
      reason: 'artifact-dependent local verifier qualification; requires the materialized vendored toolchain and explicit .codex-build proof artifacts',
    });
  }
  const campaignReason = LOCAL_CAMPAIGN_TESTS.get(relativePath);
  if (campaignReason !== undefined) {
    const classification = relativePath.includes('depth4')
      ? 'local-depth4-campaign'
      : 'local-strict-codec-campaign';
    return Object.freeze({
      classification,
      reason: `${campaignReason}; run via its explicit local campaign command and the mandatory matching CI campaign job`,
    });
  }
  const q03SupportReason = Q03_PORTABLE_SUPPORT_TESTS.get(relativePath);
  if (q03SupportReason !== undefined) {
    return Object.freeze({
      classification: 'q03-portable-support',
      reason: `${q03SupportReason}; mandatory via npm test and test:v2:q03:support; it is not external qualification evidence`,
    });
  }
  if (relativePath.startsWith('scripts/v2-q03-') && relativePath.endsWith('.test.mjs')) {
    fail(`${relativePath} must be explicitly registered as Q-03 portable support`);
  }
  const q07SupportReason = Q07_PORTABLE_SUPPORT_TESTS.get(relativePath);
  if (q07SupportReason !== undefined) {
    return Object.freeze({
      classification: 'q07-portable-support',
      reason: `${q07SupportReason}; mandatory via npm test and test:v2:q07:support; it is not a 100k performance qualification run`,
    });
  }
  if (relativePath.startsWith('scripts/v2-q07-') && relativePath.endsWith('.test.mjs')) {
    fail(`${relativePath} must be explicitly registered as Q-07 portable support or an explicit non-portable campaign`);
  }
  return Object.freeze({
    classification: 'portable',
    reason: 'mandatory clean-clone unit/integration/security test',
  });
}

export async function assertQualificationPrerequisites(
  selected,
  { projectRoot = project, suite = 'portable' } = {},
) {
  if (!['local-covenants', 'local-verifier-lane'].includes(suite)) return;
  const required = new Set(MATERIALIZED_UNLOCK_TOOLCHAIN);
  for (const record of selected) {
    for (const artifact of ARTIFACT_QUALIFICATION_TESTS.get(record.relativePath) ?? []) {
      required.add(artifact);
    }
  }
  if (suite === 'local-verifier-lane') {
    for (const artifact of LOCAL_VERIFIER_COMPLETION_ARTIFACTS) {
      required.add(artifact);
    }
  }
  const missing = [...required].filter((relativePath) => !existsSync(
    path.join(projectRoot, relativePath),
  ));
  if (missing.length > 0) {
    fail(
      `qualification suite ${suite} is BLOCKED: required local artifacts are unavailable: ${JSON.stringify(missing)}. `
      + 'Do not treat this as portable coverage or a skipped qualification gate.',
    );
  }
  if (suite === 'local-verifier-lane') {
    const qualified = await assertLocalVerifierArtifactCoherence({
      projectRoot,
    });
    const runtime = await assertLocalVerifierRuntimeCoherence({
      projectRoot,
      qualificationEvidenceSha256: qualified.evidenceSha256,
    });
    if (
      runtime.profileId !== qualified.profileId
      || runtime.instanceId !== qualified.instanceId
      || runtime.rawQualificationEvidenceSha256
        !== qualified.evidenceSha256
      || runtime.proofArtifacts.r1cs !== qualified.r1cs
      || runtime.proofArtifacts.witnessWasm !== qualified.wasm
      || runtime.proofArtifacts.provingKey !== qualified.zkey
      || runtime.proofArtifacts.verificationKey !== qualified.verificationKey
    ) {
      fail(
        'local verifier runtime coherence is BLOCKED: the completed PF10 '
        + 'runtime does not bind the current qualification identity and proof '
        + 'artifacts. Cleanly regenerate the complete artifact set.',
      );
    }
  }
}

function missingQualificationPrerequisites(selected, projectRoot) {
  const required = new Set(MATERIALIZED_UNLOCK_TOOLCHAIN);
  for (const record of selected) {
    for (const artifact of ARTIFACT_QUALIFICATION_TESTS.get(record.relativePath) ?? []) {
      required.add(artifact);
    }
  }
  for (const artifact of LOCAL_VERIFIER_COMPLETION_ARTIFACTS) {
    required.add(artifact);
  }
  return [...required].filter((relativePath) => !existsSync(
    path.join(projectRoot, relativePath),
  ));
}

function runProvisionCommand(command, args, { cwd, input } = {}) {
  const result = spawnSync(command, args, {
    cwd,
    input,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error || result.status !== 0 || result.signal !== null) {
    fail(
      `local verifier artifact provisioning failed: ${command} ${args.join(' ')} `
      + `(exit=${result.status ?? 'none'} signal=${result.signal ?? 'none'}): `
      + `${result.error?.message ?? 'command failed'}`,
    );
  }
}

function assertNoPartialDevelopmentArtifacts(projectRoot) {
  const present = DEVELOPMENT_ARTIFACT_ROOTS.filter((relativePath) => existsSync(
    path.join(projectRoot, relativePath),
  ));
  if (present.length > 0) {
    fail(
      `local verifier artifact provisioning is BLOCKED by incomplete generated state: ${JSON.stringify(present)}. `
      + 'Refuse to mix a partial development circuit/proof set with a new qualification run.',
    );
  }
}

function assertNoResidualDevelopmentTransientRoots(projectRoot) {
  const present = DEVELOPMENT_TRANSIENT_ROOTS.filter((relativePath) =>
    existsSync(path.join(projectRoot, relativePath)));
  if (present.length > 0) {
    fail(
      `local verifier artifact provisioning is BLOCKED by residual private `
      + `temporary state: ${JSON.stringify(present)}. Inspect the prior failed `
      + 'run; do not silently reuse its completed outputs.',
    );
  }
}

/**
 * Serialize the expensive local verifier provisioner with a private,
 * repository-local mkdir lock. A crashed process intentionally leaves a
 * fail-closed lock that must be inspected before manual removal.
 */
export async function withLocalVerifierProvisionLock(
  consume,
  { repositoryRoot = path.resolve(project, '..') } = {},
) {
  if (typeof consume !== 'function') {
    fail('local verifier provision lock consumer must be a function');
  }
  const repository = canonicalNonSymlinkDirectory(
    repositoryRoot,
    'local verifier provision repository root',
  );
  const artifactRoot = path.join(repository, '.codex-build');
  try {
    mkdirSync(artifactRoot, { recursive: false, mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  const canonicalArtifactRoot = canonicalNonSymlinkDirectory(
    artifactRoot,
    'local verifier provision artifact root',
  );
  const artifactRootMetadata = lstatSync(canonicalArtifactRoot);
  if ((artifactRootMetadata.mode & 0o777) !== 0o700) {
    fail('local verifier provision artifact root must have mode 0700');
  }
  const lockDirectory = path.join(
    canonicalArtifactRoot,
    'v2-local-verifier-provision.lock',
  );
  try {
    mkdirSync(lockDirectory, { recursive: false, mode: 0o700 });
  } catch (error) {
    if (error?.code === 'EEXIST') {
      fail(
        'local verifier artifact provisioning is BLOCKED: another provisioner '
        + 'is active or left a stale lock; inspect '
        + posix(path.relative(repository, lockDirectory)),
      );
    }
    throw error;
  }
  let operationError;
  try {
    return await consume(Object.freeze({ lockDirectory }));
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      rmdirSync(lockDirectory);
    } catch (cleanupError) {
      const message =
        'local verifier provision lock cleanup failed; the stale lock remains '
        + `at ${posix(path.relative(repository, lockDirectory))}`;
      if (operationError !== undefined) {
        throw new AggregateError(
          [operationError, cleanupError],
          message,
          { cause: operationError },
        );
      }
      fail(message);
    }
  }
}

/**
 * Supply development setup entropy from one private, caller-owned fd. The
 * setup module accepts only stdin or a private fd; the entropy file is always
 * closed and removed before this helper resolves or rejects.
 */
export async function withPrivateSetupEntropyFd(
  consume,
  {
    directoryPrefix = path.join(tmpdir(), 'shieldkit-local-verifier-entropy-'),
    filesystem = { chmod, mkdtemp, open, rm },
    random = randomBytes,
  } = {},
) {
  if (typeof consume !== 'function') fail('private entropy consumer must be a function');
  const directory = await filesystem.mkdtemp(directoryPrefix);
  const filename = path.join(directory, 'phase2-entropy');
  let writer;
  let reader;
  let entropy;
  try {
    await filesystem.chmod(directory, 0o700);
    writer = await filesystem.open(filename, 'wx', 0o600);
    await filesystem.chmod(filename, 0o600);
    entropy = Buffer.from(random(64).toString('hex'), 'ascii');
    await writer.writeFile(entropy);
    await writer.sync();
    entropy.fill(0);
    entropy = undefined;
    await writer.close();
    writer = undefined;
    reader = await filesystem.open(filename, 'r');
    return await consume(Object.freeze({ kind: 'fd', fd: reader.fd }));
  } finally {
    if (entropy !== undefined) entropy.fill(0);
    try {
      if (reader !== undefined) await reader.close();
    } finally {
      try {
        if (writer !== undefined) await writer.close();
      } finally {
        await filesystem.rm(directory, { recursive: true, force: true, maxRetries: 1 });
      }
    }
  }
}

export function developmentProofQualificationArguments(
  projectRoot,
  { profileCore, instanceId, maximumLiveNotes },
) {
  return Object.freeze([
    path.join(projectRoot, 'scripts/v2-development-proof-qualification.mjs'),
    '--single-thread',
    '--profile-core', profileCore,
    '--r1cs', '../.codex-build/v2-circuit-model/main-chipnet.r1cs',
    '--wasm', '../.codex-build/v2-circuit-model/main-chipnet_js/main-chipnet.wasm',
    '--zkey', '../.codex-build/v2-dev-groth16/final.zkey',
    '--verification-key', '../.codex-build/v2-dev-groth16/verification_key.json',
    '--instance-id', instanceId,
    '--maximum-live-notes', maximumLiveNotes,
    '--output', '../.codex-build/v2-dev-proof-qualification',
  ]);
}

export function pf10LibauthQualificationArguments(
  projectRoot,
  {
    output,
    profileCore,
    qualificationRoot,
    r1cs,
    setupMetadata,
    temporaryRoot,
    verificationKey,
    wasm,
    zkey,
  },
) {
  return Object.freeze([
    path.join(projectRoot, 'scripts/v2-pf10-libauth-qualification.mjs'),
    '--output', output,
    '--profile-core', profileCore,
    '--qualification-root', qualificationRoot,
    '--r1cs', r1cs,
    '--setup-metadata', setupMetadata,
    '--temporary-root', temporaryRoot,
    '--verification-key', verificationKey,
    '--wasm', wasm,
    '--zkey', zkey,
  ]);
}

export function pf10DevelopmentRuntimeArguments(
  projectRoot,
  {
    instanceId,
    output,
    profileCore,
    profilePackage,
    qualificationEvidence,
    libauthEvidence,
    temporaryRoot,
  },
) {
  return Object.freeze([
    path.join(projectRoot, 'scripts/v2-pf10-development-runtime.mjs'),
    '--instance-id', instanceId,
    '--output', output,
    '--profile-core', profileCore,
    '--profile-package', profilePackage,
    '--qualification-evidence', qualificationEvidence,
    '--libauth-evidence', libauthEvidence,
    '--temporary-root', temporaryRoot,
  ]);
}

async function provisionMissingLocalVerifierArtifacts({ projectRoot, selected }) {
  const repositoryRoot = path.resolve(projectRoot, '..');
  return withLocalVerifierProvisionLock(async () => {
    const initialMissing = missingQualificationPrerequisites(
      selected,
      projectRoot,
    );
    if (initialMissing.length === 0) {
      assertNoResidualDevelopmentTransientRoots(projectRoot);
      return Object.freeze({ provisioned: false, missing: [] });
    }
    assertNoPartialDevelopmentArtifacts(projectRoot);
  runProvisionCommand('npm', ['run', 'unlock-builder:setup'], { cwd: path.resolve(projectRoot, '..') });
  runProvisionCommand(process.execPath, [
    path.join(projectRoot, 'scripts/v2-circuit-model.mjs'),
  ], { cwd: projectRoot });

  const artifactRoot = path.resolve(projectRoot, '..', '.codex-build');
  const ptauDirectory = path.join(artifactRoot, 'v2-dev-ptau');
  const pot0 = path.join(ptauDirectory, 'pot19_0000.ptau');
  const pot1 = path.join(ptauDirectory, 'pot19_0001.ptau');
  const ptau = path.join(ptauDirectory, 'pot19_final.ptau');
  const snarkjsCli = path.join(
    repositoryRoot,
    'node_modules/snarkjs/build/cli.cjs',
  );
  mkdirSync(ptauDirectory, { recursive: true, mode: 0o700 });
  runProvisionCommand(process.execPath, [
    snarkjsCli, 'powersoftau', 'new', 'bn128', '19', pot0,
  ], {
    cwd: projectRoot,
  });
  runProvisionCommand(process.execPath, [
    snarkjsCli, 'powersoftau', 'contribute', pot0, pot1,
  ], { cwd: projectRoot, input: `${randomBytes(64).toString('hex')}\n` });
  runProvisionCommand(process.execPath, [
    snarkjsCli, 'powersoftau', 'prepare', 'phase2', pot1, ptau,
  ], { cwd: projectRoot });

  const setup = await import('../packages/profile/setup/development.mjs');
  const circuitBuild = path.join(artifactRoot, 'v2-circuit-model');
  const setupDirectory = path.join(artifactRoot, 'v2-dev-groth16');
  const profileDirectory = path.join(artifactRoot, 'v2-development-profile');
  const qualificationDirectory = path.join(
    artifactRoot,
    'v2-dev-proof-qualification',
  );
  const r1cs = path.join(circuitBuild, 'main-chipnet.r1cs');
  const wasm = path.join(circuitBuild, 'main-chipnet_js/main-chipnet.wasm');
  const circuitSymbols = path.join(circuitBuild, 'main-chipnet.sym');
  const buildAttestationPath = path.join(
    circuitBuild,
    'circuit-build-attestation.json',
  );
  const sourceManifestPath = path.join(
    circuitBuild,
    'relation-source-manifest.json',
  );
  const r1csSha256 = await setup.hashFileStreaming(r1cs);
  const ptauSha256 = await setup.hashFileStreaming(ptau);
  const pinnedSnarkjs = await setup.getPinnedSnarkjsInfo();
  await withPrivateSetupEntropyFd(async (entropySource) => {
    await setup.initializeDevelopmentGroth16({
      repositoryRoot: repositoryRoot,
      buildAttestationPath: buildAttestationPath,
      sourceManifestPath: sourceManifestPath,
      destination: setupDirectory,
      r1csPath: r1cs,
      ptauPath: ptau,
      ptauSource: 'locally generated development-only Powers of Tau transcript with non-production entropy',
      expectedR1csSha256: r1csSha256,
      expectedPtauSha256: ptauSha256,
      expectedPtauPower: 19,
      expectedSnarkjs: pinnedSnarkjs,
      entropySource,
      verifyPtau: true,
    });
  });
  runProvisionCommand(process.execPath, [
    path.join(projectRoot, 'scripts/v2-development-profile.mjs'),
    '--build-attestation', buildAttestationPath,
    '--circuit-symbols', circuitSymbols,
    '--initial-proving-key', path.join(setupDirectory, 'initial.zkey'),
    '--ptau', ptau,
    '--proving-key', path.join(setupDirectory, 'final.zkey'),
    '--r1cs', r1cs,
    '--setup-attestation', path.join(
      setupDirectory,
      'development-setup-attestation.json',
    ),
    '--verification-key', path.join(setupDirectory, 'verification_key.json'),
    '--wasm', wasm,
    '--output', profileDirectory,
  ], { cwd: projectRoot });
  const instanceId = createHash('sha256')
    .update('shieldkit-v2-direct-local-verifier-development-instance/v1')
    .digest('hex');
  const maximumLiveNotes = '32';
  const profileCore = path.join(profileDirectory, 'profile-core.json');
  const libauthQualificationDirectory = path.join(
    artifactRoot,
    'v2-pf10-libauth-qualification',
  );
  const libauthTemporaryRoot = path.join(
    artifactRoot,
    'v2-pf10-libauth-tmp',
  );
  const runtimeTemporaryRoot = path.join(
    artifactRoot,
    'v2-pf10-runtime-tmp',
  );
  runProvisionCommand(
    process.execPath,
    developmentProofQualificationArguments(projectRoot, {
      profileCore,
      instanceId,
      maximumLiveNotes,
    }),
    { cwd: projectRoot },
  );
  runProvisionCommand(
    process.execPath,
    pf10LibauthQualificationArguments(projectRoot, {
      output: libauthQualificationDirectory,
      profileCore,
      qualificationRoot: qualificationDirectory,
      r1cs,
      setupMetadata: path.join(setupDirectory, 'setup-metadata.json'),
      temporaryRoot: libauthTemporaryRoot,
      verificationKey: path.join(setupDirectory, 'verification_key.json'),
      wasm,
      zkey: path.join(setupDirectory, 'final.zkey'),
    }),
    { cwd: projectRoot },
  );
  rmSync(libauthTemporaryRoot, { recursive: true, force: false });
  runProvisionCommand(
    process.execPath,
    pf10DevelopmentRuntimeArguments(projectRoot, {
      instanceId,
      output: path.join(artifactRoot, 'v2-pf10-development-runtime'),
      profileCore,
      profilePackage: path.join(profileDirectory, 'profile-package.json'),
      qualificationEvidence: path.join(
        qualificationDirectory,
        'qualification-evidence.json',
      ),
      libauthEvidence: path.join(
        libauthQualificationDirectory,
        'libauth.json',
      ),
      temporaryRoot: runtimeTemporaryRoot,
    }),
    { cwd: projectRoot },
  );
  rmSync(runtimeTemporaryRoot, { recursive: true, force: false });
  return Object.freeze({ provisioned: true, missing: initialMissing });
  }, { repositoryRoot });
}

export async function ensureLocalVerifierQualificationArtifacts(
  selected,
  { projectRoot = project, provision = provisionMissingLocalVerifierArtifacts } = {},
) {
  const result = await provision({ projectRoot, selected });
  await assertQualificationPrerequisites(selected, { projectRoot, suite: 'local-verifier-lane' });
  return result;
}

export function discoverDomainTests({ projectRoot = project } = {}) {
  const roots = [
    Object.freeze({ relativeRoot: 'packages', excludeVendor: true, required: true }),
    Object.freeze({ relativeRoot: 'scripts', excludeVendor: true, required: true }),
    Object.freeze({
      relativeRoot: VENDORED_VERIFIER_LANE_TEST_ROOT,
      excludeVendor: false,
      required: false,
    }),
  ];
  const records = [];
  const typecheckAssets = [];
  for (const { relativeRoot, excludeVendor, required } of roots) {
    const root = path.join(projectRoot, relativeRoot);
    if (!existsSync(root)) {
      if (required) fail(`test discovery root is missing: ${relativeRoot}`);
      continue;
    }
    const visit = (directory) => {
      const entries = readdirSync(directory, { withFileTypes: true })
        .sort((left, right) => left.name.localeCompare(right.name, 'en'));
      for (const entry of entries) {
        if (
          entry.name === 'node_modules'
          || (excludeVendor && entry.name === 'vendor')
          || entry.name.startsWith('.')
        ) continue;
        const full = path.join(directory, entry.name);
        if (entry.isDirectory()) {
          visit(full);
          continue;
        }
        const relativePath = posix(path.relative(projectRoot, full));
        if (entry.isFile() && entry.name.endsWith('.test.mjs')) {
          records.push(Object.freeze({
            path: full,
            relativePath,
            ...classify(relativePath),
          }));
        } else if (entry.isFile() && entry.name.endsWith('.test.ts')) {
          typecheckAssets.push(Object.freeze({
            path: full,
            relativePath,
            classification: 'typescript-compile-asset',
            reason: 'compiled by check:type:v2 and exercised by the JavaScript parity test',
          }));
        }
      }
    };
    visit(root);
  }
  records.sort((left, right) => left.relativePath.localeCompare(right.relativePath, 'en'));
  typecheckAssets.sort((left, right) => left.relativePath.localeCompare(right.relativePath, 'en'));
  if (records.length === 0) fail('no domain test files discovered');
  return Object.freeze({
    tests: Object.freeze(records),
    typecheckAssets: Object.freeze(typecheckAssets),
    ignoredScopes: Object.freeze([
      Object.freeze({
        scope: 'packages/**/vendor/**',
        exception: `${VENDORED_VERIFIER_LANE_TEST_ROOT}/**/*.test.mjs`,
        classification: 'third-party-vendor-excluded',
        reason: 'bulk third-party trees and generated dependency/build caches are outside ShieldKit tests; the tracked pinned BN254 lane tests are explicitly discovered',
      }),
    ]),
  });
}

export function selectDomainTests(discovery, suite = 'portable') {
  if (!SUITES.has(suite)) fail(`unknown test suite: ${suite}`);
  const classifications = {
    portable: new Set(['portable', 'q03-portable-support', 'q07-portable-support', 'beta-product-portable-security']),
    'external-fixtures': new Set(['external-fixture']),
    'external-verifier-source': new Set(['external-verifier-source-qualification']),
    'local-covenants': new Set(['local-covenant-qualification']),
    'local-verifier-lane': new Set(['local-verifier-lane-qualification']),
    'local-strict-codec-campaign': new Set(['local-strict-codec-campaign']),
    'local-depth4-campaign': new Set(['local-depth4-campaign']),
    'q03-portable-support': new Set(['q03-portable-support']),
    'q07-portable-support': new Set(['q07-portable-support']),
    'beta-product-security': new Set(['beta-product-portable-security']),
    'beta-runtime-qualification': new Set(['beta-runtime-qualification']),
    'clean-source': new Set(['clean-source']),
  }[suite];
  const selected = discovery.tests.filter((record) => classifications.has(record.classification));
  if (selected.length === 0) fail(`test suite ${suite} selected no files`);
  return Object.freeze(selected);
}

export function assertCompleteSelection(discovery, selected, suite = 'portable') {
  const expected = selectDomainTests(discovery, suite).map((record) => record.relativePath);
  const actual = selected.map((record) => record.relativePath);
  if (
    actual.length !== expected.length
    || actual.some((relativePath, index) => relativePath !== expected[index])
  ) {
    const actualSet = new Set(actual);
    const expectedSet = new Set(expected);
    const omitted = expected.filter((relativePath) => !actualSet.has(relativePath));
    const unexpected = actual.filter((relativePath) => !expectedSet.has(relativePath));
    fail(`test selection is incomplete or contaminated: omitted=${JSON.stringify(omitted)} unexpected=${JSON.stringify(unexpected)}`);
  }
}

export function preflightTestSources(selected, { allowClassifiedFixtureGates = false } = {}) {
  for (const record of selected) {
    const source = readFileSync(record.path, 'utf8');
    const classifiedFixtureGate = allowClassifiedFixtureGates
      && record.classification === 'external-fixture';
    if (SKIP_OR_TODO_SOURCE.test(source) && !classifiedFixtureGate) {
      fail(`${record.relativePath} contains skip/todo fixture gating; move it to an explicit external suite`);
    }
    if (!source.includes('node:test')) {
      if (!SCRIPT_STYLE_TESTS.has(record.relativePath)) {
        fail(`${record.relativePath} is an empty or unregistered script-style test`);
      }
    } else if (!NODE_TEST_DECLARATION.test(source)) {
      fail(`${record.relativePath} imports node:test but declares no tests`);
    }
  }
}

function tapSummary(output) {
  const field = (name) => {
    const matches = [...output.matchAll(new RegExp(`^# ${name} (\\d+)$`, 'gm'))];
    return matches.length === 0 ? undefined : Number(matches.at(-1)[1]);
  };
  return Object.freeze({
    tests: field('tests'),
    pass: field('pass'),
    fail: field('fail'),
    cancelled: field('cancelled'),
    skipped: field('skipped'),
    todo: field('todo'),
  });
}

function domainTestTemporaryBuildRoot(cwd) {
  if (typeof cwd !== 'string' || !path.isAbsolute(cwd)) {
    fail('domain test cwd must be an absolute path');
  }
  const root = path.resolve(cwd, '..', '.codex-build');
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const metadata = lstatSync(root);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('domain test temporary build root must be a directory and not a symlink');
  }
  if (realpathSync(root) !== root) {
    fail('domain test temporary build root must be canonical');
  }
  return root;
}

function assertManagedDomainTestTemporaryDirectory(temporary) {
  if (temporary === null || typeof temporary !== 'object') {
    fail('domain test temporary directory must be an object');
  }
  const { root, directory } = temporary;
  if (
    typeof root !== 'string'
    || typeof directory !== 'string'
    || managedDomainTestTemporaryDirectories.get(directory) !== root
    || path.dirname(directory) !== root
    || !path.basename(directory).startsWith(DOMAIN_TEST_TEMP_PREFIX)
  ) {
    fail('refusing unmanaged domain test temporary directory');
  }
  const rootMetadata = lstatSync(root);
  const directoryMetadata = lstatSync(directory);
  if (
    !rootMetadata.isDirectory()
    || rootMetadata.isSymbolicLink()
    || !directoryMetadata.isDirectory()
    || directoryMetadata.isSymbolicLink()
    || realpathSync(root) !== root
    || realpathSync(directory) !== directory
    || (directoryMetadata.mode & 0o777) !== 0o700
  ) {
    fail('refusing unsafe domain test temporary directory');
  }
}

/** Create one private, repo-local temporary root for child domain-test processes. */
export function createDomainTestTemporaryDirectory(cwd = project) {
  const root = domainTestTemporaryBuildRoot(cwd);
  const directory = mkdtempSync(path.join(root, DOMAIN_TEST_TEMP_PREFIX));
  try {
    chmodSync(directory, 0o700);
    const temporary = Object.freeze({ root, directory });
    managedDomainTestTemporaryDirectories.set(directory, root);
    assertManagedDomainTestTemporaryDirectory(temporary);
    return temporary;
  } catch (error) {
    if (managedDomainTestTemporaryDirectories.get(directory) === root) {
      managedDomainTestTemporaryDirectories.delete(directory);
      rmSync(directory, { recursive: true, force: false });
    }
    throw error;
  }
}

/** Remove only the exact private directory created by this module. */
export function removeDomainTestTemporaryDirectory(temporary) {
  assertManagedDomainTestTemporaryDirectory(temporary);
  rmSync(temporary.directory, { recursive: true, force: false });
  managedDomainTestTemporaryDirectories.delete(temporary.directory);
}

/**
 * Return the process-supervisor deadline for one classified test file.
 *
 * The portable default deliberately remains short. Slow qualification tests
 * must be registered by exact path or explicit classification and selected by
 * a mandatory qualification suite before they receive a longer deadline.
 */
export function fileTimeoutForDomainTest(record, { defaultTimeoutMs = 180_000 } = {}) {
  if (!Number.isSafeInteger(defaultTimeoutMs) || defaultTimeoutMs <= 0) {
    fail(`invalid default per-file timeout: ${defaultTimeoutMs}`);
  }
  if (record === null || typeof record !== 'object' || typeof record.classification !== 'string') {
    fail('test record must have a classification');
  }
  return FILE_TIMEOUT_MS_BY_PATH.get(record.relativePath)
    ?? FILE_TIMEOUT_MS_BY_CLASSIFICATION[record.classification]
    ?? defaultTimeoutMs;
}

/**
 * Determine a bounded worker count for independent test files. The override
 * exists only on this exported test seam; the CLI always consumes every core
 * reported by Node's scheduler-aware availableParallelism().
 */
export function domainTestParallelism(selectedCount, { testParallelism = undefined } = {}) {
  if (!Number.isSafeInteger(selectedCount) || selectedCount <= 0) {
    fail(`invalid selected test count: ${selectedCount}`);
  }
  const available = availableParallelism();
  if (!Number.isSafeInteger(available) || available <= 0) {
    fail(`invalid available parallelism: ${available}`);
  }
  if (testParallelism !== undefined
    && (!Number.isSafeInteger(testParallelism) || testParallelism <= 0)) {
    fail(`invalid test-only parallelism override: ${testParallelism}`);
  }
  return Math.min(selectedCount, testParallelism ?? available);
}

export function isExclusiveDomainTestFile(record) {
  return record !== null
    && typeof record === 'object'
    && EXCLUSIVE_DOMAIN_TEST_FILES.has(record.relativePath);
}

function startDomainTestFile(record, {
  cwd,
  environment,
  timeoutMs,
}) {
  const temporary = createDomainTestTemporaryDirectory(cwd);
  const childEnvironment = { ...environment };
  delete childEnvironment.NODE_TEST_CONTEXT;
  childEnvironment.TMPDIR = temporary.directory;
  childEnvironment.TMP = temporary.directory;
  childEnvironment.TEMP = temporary.directory;
  let child;
  let timeout = undefined;
  let cancellationRequested = false;
  let timedOut = false;
  let settled = false;
  const promise = new Promise((resolve) => {
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      if (timeout !== undefined) clearTimeout(timeout);
      let cleanupError;
      try {
        removeDomainTestTemporaryDirectory(temporary);
      } catch (error) {
        cleanupError = error;
      }
      resolve(Object.freeze({
        record,
        temporaryDirectory: temporary.directory,
        ...outcome,
        cancellationRequested,
        timedOut,
        cleanupError,
      }));
    };
    try {
      child = spawn(process.execPath, [
        '--test',
        '--test-reporter=tap',
        '--test-concurrency=1',
        record.path,
      ], {
        cwd,
        env: childEnvironment,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      finish({ error, signal: null, status: null, stderr: '', stdout: '' });
      return;
    }
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', (error) => {
      finish({ error, signal: null, status: null, stderr, stdout });
    });
    child.once('close', (status, signal) => {
      finish({ error: undefined, signal, status, stderr, stdout });
    });
    timeout = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);
  });
  return Object.freeze({
    promise,
    cancel() {
      cancellationRequested = true;
      if (child !== undefined && !settled) child.kill('SIGKILL');
    },
  });
}

function domainTestResultError(result) {
  const { record, timeoutMs } = result;
  if (result.cleanupError !== undefined) {
    return `${record.relativePath}: domain test temporary cleanup failed: ${result.cleanupError.message}`;
  }
  if (result.timedOut) {
    return `${record.relativePath}: node test runner timed out after ${timeoutMs}ms`;
  }
  if (result.error !== undefined) {
    return `${record.relativePath}: node test runner could not start: ${result.error.message}`;
  }
  if (result.cancellationRequested) {
    return `${record.relativePath}: node test runner cancelled after another test-file failure`;
  }
  const summary = tapSummary(`${result.stdout ?? ''}\n${result.stderr ?? ''}`);
  if (result.status !== 0 || result.signal !== null) {
    return `${record.relativePath}: node test runner failed: exit=${result.status ?? 'none'} signal=${result.signal ?? 'none'}`;
  }
  for (const field of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    if (!Number.isSafeInteger(summary[field])) {
      return `${record.relativePath}: node test runner omitted TAP summary field ${field}`;
    }
  }
  if (summary.fail !== 0 || summary.cancelled !== 0 || summary.skipped !== 0 || summary.todo !== 0) {
    return `${record.relativePath}: node test runner was not fully executed: ${JSON.stringify(summary)}`;
  }
  if (summary.tests === 0 || summary.pass === 0) {
    return `${record.relativePath}: node test runner reported an empty suite`;
  }
  return undefined;
}

export async function runSelectedDomainTests(
  selected,
  {
    cwd = project,
    environment = process.env,
    fileTimeoutMs = 180_000,
    // This is deliberately unavailable from CLI/environment configuration.
    // Tests use it to assert bounded scheduling deterministically.
    testParallelism = undefined,
  } = {},
) {
  if (!Number.isSafeInteger(fileTimeoutMs) || fileTimeoutMs <= 0) {
    fail(`invalid per-file timeout: ${fileTimeoutMs}`);
  }
  if (!Array.isArray(selected) || selected.length === 0) {
    fail('selected domain tests must be a nonempty array');
  }
  const parallelIndices = selected
    .map((record, index) => ({ record, index }))
    .filter(({ record }) => !isExclusiveDomainTestFile(record))
    .map(({ index }) => index);
  const exclusiveIndices = selected
    .map((record, index) => ({ record, index }))
    .filter(({ record }) => isExclusiveDomainTestFile(record))
    .map(({ index }) => index);
  const parallelism = parallelIndices.length === 0
    ? 1
    : domainTestParallelism(parallelIndices.length, { testParallelism });
  const aggregate = {
    files: selected.length,
    tests: 0,
    pass: 0,
    fail: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0,
  };
  const results = Array(selected.length);
  const active = new Map();
  let nextParallel = 0;
  let cancellationStarted = false;
  const launch = (index) => {
    const record = selected[index];
      const timeoutMs = fileTimeoutForDomainTest(record, {
        defaultTimeoutMs: fileTimeoutMs,
      });
    const worker = startDomainTestFile(record, { cwd, environment, timeoutMs });
    const outcome = worker.promise.then((result) => Object.freeze({ index, result: Object.freeze({ ...result, timeoutMs }) }));
    active.set(index, Object.freeze({ worker, outcome }));
  };
  while (nextParallel < parallelIndices.length && active.size < parallelism) {
    launch(parallelIndices[nextParallel++]);
  }
  while (active.size > 0) {
    const { index, result } = await Promise.race([...active.values()].map(({ outcome }) => outcome));
    active.delete(index);
    results[index] = result;
    if (domainTestResultError(result) !== undefined && !cancellationStarted) {
      cancellationStarted = true;
      for (const { worker } of active.values()) worker.cancel();
    }
    if (!cancellationStarted && nextParallel < parallelIndices.length) {
      launch(parallelIndices[nextParallel++]);
    }
  }
  if (!cancellationStarted) {
    for (const index of exclusiveIndices) {
      const record = selected[index];
      const timeoutMs = fileTimeoutForDomainTest(record, {
        defaultTimeoutMs: fileTimeoutMs,
      });
      const worker = startDomainTestFile(record, { cwd, environment, timeoutMs });
      const result = await worker.promise;
      results[index] = Object.freeze({ ...result, timeoutMs });
      if (domainTestResultError(results[index]) !== undefined) {
        cancellationStarted = true;
        break;
      }
    }
  }
  const failed = results.find((result) => result !== undefined
    && !result.cancellationRequested
    && domainTestResultError(result) !== undefined);
  const completed = results.filter((result) => result !== undefined);
  for (const result of completed) {
    const index = selected.indexOf(result.record);
    process.stderr.write(`${JSON.stringify({
      phase: 'test-file',
      index: index + 1,
      total: selected.length,
      file: result.record.relativePath,
      timeoutMs: result.timeoutMs,
      parallelism,
    })}\n`);
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
  }
  if (failed !== undefined) {
    const notStarted = selected
      .filter((_, index) => results[index] === undefined)
      .map((record) => record.relativePath);
    if (notStarted.length > 0) {
      process.stderr.write(`${JSON.stringify({
        phase: 'test-cancelled-before-start',
        files: notStarted,
        cause: failed.record.relativePath,
      })}\n`);
    }
    fail(domainTestResultError(failed));
  }
  for (const result of completed) {
    const summary = tapSummary(`${result.stdout}\n${result.stderr}`);
    for (const field of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
      aggregate[field] += summary[field];
    }
  }
  process.stderr.write(`${JSON.stringify({
    phase: 'test-complete',
    parallelism,
    exclusiveFiles: exclusiveIndices.length,
    ...aggregate,
  })}\n`);
  return Object.freeze(aggregate);
}

function parse(argv) {
  if (argv.length === 0) return Object.freeze({ suite: 'portable', provisionOnly: false });
  if (argv.length === 1 && argv[0] === '--provision-local-verifier-artifacts') {
    return Object.freeze({ suite: 'local-verifier-lane', provisionOnly: true });
  }
  if (argv.length === 2 && argv[0] === '--suite' && SUITES.has(argv[1])) {
    return Object.freeze({ suite: argv[1], provisionOnly: false });
  }
  fail('usage: node run-domain-tests.mjs [--suite portable|external-fixtures|external-verifier-source|local-covenants|local-verifier-lane|local-strict-codec-campaign|local-depth4-campaign|q03-portable-support|q07-portable-support|beta-product-security|beta-runtime-qualification|clean-source] | --provision-local-verifier-artifacts');
}

export async function runDomainTests({ suite = 'portable', projectRoot = project, provisionOnly = false } = {}) {
  const discovery = discoverDomainTests({ projectRoot });
  const selected = selectDomainTests(discovery, suite);
  assertCompleteSelection(discovery, selected, suite);
  if (suite === 'local-verifier-lane') {
    await ensureLocalVerifierQualificationArtifacts(selected, { projectRoot });
    if (provisionOnly) return Object.freeze({ discovery, selected, summary: null });
  } else {
    await assertQualificationPrerequisites(selected, { projectRoot, suite });
  }
  preflightTestSources(selected, {
    allowClassifiedFixtureGates: suite === 'external-fixtures',
  });
  const selectedSet = new Set(selected.map((record) => record.relativePath));
  const excluded = discovery.tests
    .filter((record) => !selectedSet.has(record.relativePath))
    .map(({ relativePath, classification, reason }) => ({ file: relativePath, classification, reason }));
  process.stderr.write(`${JSON.stringify({
    phase: 'test-discovery',
    suite,
    selectedCount: selected.length,
    selected: selected.map((record) => record.relativePath),
    excludedCount: excluded.length + discovery.typecheckAssets.length,
    excluded: [
      ...excluded,
      ...discovery.typecheckAssets.map(({ relativePath, classification, reason }) => ({
        file: relativePath,
        classification,
        reason,
      })),
    ],
    ignoredScopes: discovery.ignoredScopes,
  }, null, 2)}\n`);
  return Object.freeze({
    discovery,
    selected,
    summary: await runSelectedDomainTests(selected, { cwd: projectRoot }),
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const parsed = parse(process.argv.slice(2));
    await runDomainTests(parsed);
  } catch (error) {
    process.stderr.write(`mandatory domain test runner failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
