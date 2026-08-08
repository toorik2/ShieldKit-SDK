/**
 * Explicit local maintenance lane for a committed V2 beta pool's immutable
 * linked runtime cache. This is deliberately separate from warm actions: it
 * does not construct an action session, open a wallet/store/journal, contact
 * public Chipnet providers, prove, or send a transaction.
 */
import { performance } from 'node:perf_hooks';
import path from 'node:path';

import {
  assertV2BetaChipnetCommittedGenesisCapability,
  loadV2BetaChipnetCommittedGenesis,
} from '../../profile/v2/beta-chipnet-deployment.mjs';
import {
  assertV2BetaChipnetRuntimeResolution,
  installV2BetaProductLinkedRuntimeCache,
  loadV2BetaProductLinkedRuntimeCache,
  loadV2BetaProductLinkedRuntimeTemplate,
} from '../../profile/v2/beta-chipnet-runtime.mjs';
import {
  loadV2BetaProductArtifactInstallation,
} from '../../profile/v2/beta-product-artifact-installation.mjs';
import {
  assertV2BetaPoolCreateRuntimeWork,
  observeV2BetaRuntimeWork,
} from '../../profile/v2/beta-runtime-work-observer.mjs';
import {
  loadV2BetaProductConfig,
} from './beta-product-config.mjs';
import {
  authenticateV2Pf10ReceiptLinkedRuntimeTemplate,
  relocateV2Pf10BetaRuntime,
} from '../../unlock-builder/v2/pf10-instance-specializer.mjs';

export const V2_BETA_PRODUCT_RUNTIME_REFRESH_RESULT_SCHEMA =
  'shieldkit-v2-beta-product-runtime-refresh-result-v1';

const HASH = /^[0-9a-f]{64}$/u;
const REPOSITORY_ROOT = path.resolve(import.meta.dirname, '../../../../..');
const V2_BETA_PRODUCT_CAPACITY = '100000';
const FALSE_CLAIMS = Object.freeze({
  broadcasted: false,
  confirmed: false,
  mined: false,
  productionQualified: false,
});

export class V2BetaProductRuntimeRefreshError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaProductRuntimeRefreshError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaProductRuntimeRefreshError(code, message, options);
};

const now = () => performance.now();

function exactOptional(value, allowed, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).some((key) => !allowed.includes(key))) {
    fail('BETA_RUNTIME_REFRESH_INVALID', `${label} has unknown properties or is not a plain object`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('BETA_RUNTIME_REFRESH_REJECTED', `${label} is not an exact lowercase SHA-256`);
  }
  return value;
}

function assertGenesisIdentity(value) {
  if (value === null || typeof value !== 'object'
    || !HASH.test(value.profileId) || !HASH.test(value.instanceId)
    || !HASH.test(value.zeroConfEvidenceSha256)
    || !HASH.test(value.genesisOutpoint?.txid) || value.genesisOutpoint?.vout !== 0) {
    fail('BETA_RUNTIME_REFRESH_REJECTED', 'committed genesis capability has an invalid public identity');
  }
  return value;
}

function assertRuntimeGenesisAgreement(runtime, genesis) {
  if (runtime === null || typeof runtime !== 'object'
    || runtime.identity?.profileId !== genesis.profileId
    || runtime.identity?.instanceId !== genesis.instanceId
    || runtime.identity?.maximumLiveNotes !== V2_BETA_PRODUCT_CAPACITY
    || runtime.identity?.denominationSats !== '10000000'
    || !HASH.test(runtime.runtimeManifestSha256)
    || !HASH.test(runtime.runtimeMaterialSha256)) {
    fail('BETA_RUNTIME_REFRESH_REJECTED', 'reloaded linked runtime differs from the committed pool identity');
  }
  return runtime;
}

function timingsValue(timings, started) {
  const value = Object.freeze({ ...timings, commandTotal: now() - started });
  if (!Object.values(value).every((entry) => typeof entry === 'number'
    && Number.isFinite(entry) && entry >= 0)) {
    fail('BETA_RUNTIME_REFRESH_REJECTED', 'runtime refresh timings are invalid');
  }
  return value;
}

function testDependencies(value) {
  const names = [
    'assertGenesis', 'assertRuntime', 'attestTemplate', 'installRuntime',
    'loadArtifactInstallation', 'loadConfig', 'loadCommittedGenesis',
    'loadRuntime', 'loadTemplate', 'specializeRuntime',
  ];
  exactOptional(value, names, 'beta runtime refresh test dependencies');
  if (Object.keys(value).length !== names.length
    || names.some((name) => typeof value[name] !== 'function')) {
    fail('BETA_RUNTIME_REFRESH_INVALID', 'beta runtime refresh test dependencies are incomplete');
  }
  return Object.freeze({ ...value });
}

async function refresh(value, dependencies) {
  exactOptional(value, ['dataHome'], 'beta runtime refresh options');
  if (value.dataHome !== undefined && (typeof value.dataHome !== 'string'
    || !path.isAbsolute(value.dataHome) || path.normalize(value.dataHome) !== value.dataHome
    || value.dataHome.includes('\0'))) {
    fail('BETA_RUNTIME_REFRESH_INVALID', 'dataHome must be a normalized absolute path when supplied');
  }
  const started = now();
  const timings = {
    artifactLoad: 0,
    committedGenesisLoad: 0,
    instanceSpecialization: 0,
    runtimeCacheInstall: 0,
    runtimeLoad: 0,
    templateLoad: 0,
    templateReceiptAttestation: 0,
  };
  let config;
  try {
    config = (await dependencies.loadConfig(value.dataHome === undefined ? {} : { dataHome: value.dataHome })).config;
  } catch (error) {
    fail('BETA_RUNTIME_REFRESH_CONFIG_REQUIRED', 'an existing private beta product configuration is required', { cause: error });
  }
  const genesisStarted = now();
  let genesis;
  try {
    genesis = dependencies.assertGenesis(dependencies.loadCommittedGenesis({
      deploymentDirectory: config.deploymentDirectory,
    }));
    assertGenesisIdentity(genesis);
  } catch (error) {
    if (error instanceof V2BetaProductRuntimeRefreshError) throw error;
    fail('BETA_RUNTIME_REFRESH_COMMITTED_POOL_REQUIRED', 'a committed zero-conf beta pool is required before refreshing its runtime', { cause: error });
  } finally {
    timings.committedGenesisLoad = now() - genesisStarted;
  }
  const artifactsStarted = now();
  let artifactInstallation;
  try {
    artifactInstallation = await dependencies.loadArtifactInstallation({
      productDataDirectory: config.dataDirectory,
    });
  } catch (error) {
    fail('BETA_RUNTIME_REFRESH_ARTIFACT_INSTALLATION_REQUIRED', 'the once-verified pinned beta artifacts are unavailable or changed', { cause: error });
  } finally {
    timings.artifactLoad = now() - artifactsStarted;
  }
  const observed = await observeV2BetaRuntimeWork(async () => {
    const load = async () => {
      const loadStarted = now();
      try {
        return await dependencies.loadRuntime({
          artifactInstallation,
          cacheRoot: config.runtimeCacheRoot,
          instanceId: genesis.instanceId,
        });
      } finally {
        timings.runtimeLoad += now() - loadStarted;
      }
    };
    let runtime;
    let linkedDuringCommand = false;
    let installed = Object.freeze({ installed: false, alreadyPresent: true });
    try {
      runtime = await load();
    } catch (error) {
      // Invalid, stale, or ambiguous generations are terminal. Only an exact
      // absence may authorize specialization and an immutable cache write.
      if (error?.code !== 'BETA_LINKED_RUNTIME_CACHE_UNAVAILABLE') throw error;
      linkedDuringCommand = true;
    }

    if (linkedDuringCommand) {
      const templateStarted = now();
      let template;
      try {
        template = await dependencies.loadTemplate({ artifactInstallation });
      } catch (error) {
        fail('BETA_RUNTIME_REFRESH_REJECTED', 'the receipt-authenticated linker template is unavailable', { cause: error });
      } finally {
        timings.templateLoad = now() - templateStarted;
      }
      const attestationStarted = now();
      let templateCapability;
      try {
        templateCapability = await dependencies.attestTemplate({ linkedTemplate: template });
      } catch (error) {
        fail('BETA_RUNTIME_REFRESH_REJECTED', 'the retained PF10 linker template failed exact source attestation', { cause: error });
      } finally {
        timings.templateReceiptAttestation = now() - attestationStarted;
      }
      const specializationStarted = now();
      let specializedRuntime;
      try {
        specializedRuntime = await dependencies.specializeRuntime({
          instanceId: genesis.instanceId,
          templateCapability,
        });
      } catch (error) {
        fail('BETA_RUNTIME_REFRESH_REJECTED', 'exact PF10 specialization for the committed pool failed', { cause: error });
      } finally {
        timings.instanceSpecialization = now() - specializationStarted;
      }
      const installStarted = now();
      let installError;
      let installFailed = false;
      try {
        installed = await dependencies.installRuntime({
          artifactInstallation,
          cacheRoot: config.runtimeCacheRoot,
          specializedRuntime,
        });
      } catch (error) {
        installError = error;
        installFailed = true;
      } finally {
        // This stage covers only the atomic immutable-cache publication. Exact
        // reload time is accounted separately by load().
        timings.runtimeCacheInstall = now() - installStarted;
      }
      if (installFailed) {
        // An immutable generation may have been published by a concurrent
        // refresher after our specialization. Only a complete exact reload can
        // classify that as the safe idempotent race outcome.
        try {
          runtime = await load();
          installed = Object.freeze({ installed: false, raced: true });
        } catch (loadError) {
          fail('BETA_RUNTIME_REFRESH_REJECTED', 'the exact linked runtime cache could not be installed and reloaded', {
            cause: new AggregateError([installError, loadError], 'runtime refresh install and exact reload failed'),
          });
        }
      } else {
        try {
          runtime = await load();
        } catch (error) {
          fail('BETA_RUNTIME_REFRESH_REJECTED', 'the newly installed linked runtime cache failed exact reload', { cause: error });
        }
      }
    }
    try {
      dependencies.assertRuntime(runtime);
      assertRuntimeGenesisAgreement(runtime, genesis);
    } catch (error) {
      if (error instanceof V2BetaProductRuntimeRefreshError) throw error;
      fail('BETA_RUNTIME_REFRESH_REJECTED', 'the reloaded linked runtime failed its exact committed-pool binding', { cause: error });
    }
    return Object.freeze({ installed, linkedDuringCommand, runtime });
  });
  let runtimeWork;
  try {
    runtimeWork = assertV2BetaPoolCreateRuntimeWork(observed.observation, {
      linkedDuringCommand: observed.value.linkedDuringCommand,
    });
  } catch (error) {
    fail('BETA_RUNTIME_REFRESH_REJECTED', 'runtime refresh performed work outside the fixed specialization and exact-load boundary', { cause: error });
  }
  const { installed, runtime } = observed.value;
  return Object.freeze({
    schema: V2_BETA_PRODUCT_RUNTIME_REFRESH_RESULT_SCHEMA,
    command: 'pool-refresh-runtime',
    status: 'linked-runtime-refreshed-beta-unqualified',
    claims: FALSE_CLAIMS,
    profileId: genesis.profileId,
    instanceId: genesis.instanceId,
    genesisTransactionId: genesis.genesisOutpoint.txid,
    runtimeManifestSha256: hash(runtime.runtimeManifestSha256, 'runtime manifest hash'),
    runtimeMaterialSha256: hash(runtime.runtimeMaterialSha256, 'runtime material hash'),
    cacheInstalled: installed?.installed === true,
    runtimeWork,
    timingsMs: timingsValue(timings, started),
  });
}

function productionDependencies() {
  return Object.freeze({
    assertGenesis: assertV2BetaChipnetCommittedGenesisCapability,
    assertRuntime: assertV2BetaChipnetRuntimeResolution,
    attestTemplate: ({ linkedTemplate }) => authenticateV2Pf10ReceiptLinkedRuntimeTemplate({
      repositoryRoot: REPOSITORY_ROOT,
      linkedTemplate,
    }),
    installRuntime: installV2BetaProductLinkedRuntimeCache,
    loadArtifactInstallation: loadV2BetaProductArtifactInstallation,
    loadCommittedGenesis: loadV2BetaChipnetCommittedGenesis,
    loadConfig: loadV2BetaProductConfig,
    loadRuntime: loadV2BetaProductLinkedRuntimeCache,
    loadTemplate: loadV2BetaProductLinkedRuntimeTemplate,
    specializeRuntime: ({ instanceId, templateCapability }) => relocateV2Pf10BetaRuntime({
      repositoryRoot: REPOSITORY_ROOT,
      instanceId,
      templateCapability,
    }),
  });
}

/** Refresh an immutable local cache generation; no network or private action state is touched. */
export async function refreshV2BetaProductRuntime(value = {}) {
  return refresh(value, productionDependencies());
}

/** Isolated test seam; production never accepts injected dependencies. */
export async function refreshV2BetaProductRuntimeForTest(value, dependencies) {
  return refresh(value, testDependencies(dependencies));
}
