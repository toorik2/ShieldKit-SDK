import { join } from 'node:path';

const flag = (environment, name) => environment[name] === '1';
const number = (environment, name, fallback) => Number(environment[name] ?? fallback);
const optionalNumber = (environment, name) => environment[name] === undefined
  ? undefined
  : Number(environment[name]);

const freezeSections = (configuration) => Object.freeze(Object.fromEntries(
  Object.entries(configuration).map(([name, value]) => [name, Object.freeze(value)]),
));

/**
 * Establish the generator switches historically forced by c7_merge.ts.
 *
 * This function remains separate from parsing because imported generators read
 * these values directly. The compatibility adapter can disappear once those
 * generators accept explicit configuration.
 */
export const normalizeLegacyC7Environment = (environment) => {
  environment.SZ_ALLAFF = '1';
  environment.L17SEL = '1';
  environment.SEAMNARROW ||= '1';
  environment.KSPEC ||= '1';
  environment.SIBLING_READ = '1';
  return environment;
};

/**
 * Convert the legacy process environment into the lane's typed build input.
 * Reading configuration is pure: only normalizeLegacyC7Environment mutates the
 * compatibility environment.
 */
export const readLegacyC7Config = (environment, { here, repoRoot }) => {
  if (!here || !repoRoot) throw new Error('legacy C7 configuration requires here and repoRoot');

  const windowSize = number(environment, 'KWIN', 7);
  if (!Number.isInteger(windowSize) || windowSize < 7 || windowSize > 13) {
    throw new Error('KWIN must be an integer in [7,13]');
  }

  const maxTry = number(environment, 'C7_MAXTRY', 8);
  if (!Number.isInteger(maxTry) || maxTry < 0) {
    throw new Error('C7_MAXTRY must be a non-negative integer');
  }

  const stripedFragments = optionalNumber(environment, 'STRIPED_FRAGS');
  if (stripedFragments !== undefined && (!Number.isInteger(stripedFragments) || stripedFragments < 1)) {
    throw new Error('STRIPED_FRAGS must be a positive integer');
  }

  const proofInstance = environment.ELIG_INSTANCE;
  const proofFile = environment.ELIG_FILE;
  const shieldAdapterFile = environment.C7_SHIELD_ADAPTER_FILE;
  const shieldAdapterSha256 = environment.C7_SHIELD_ADAPTER_SHA256;
  const structuralRoleCount = number(environment, 'C7_STRUCTURAL_ROLE_COUNT', 0);
  const actionPacketFile = environment.C7_SHIELD_ACTION_PACKET_FILE;
  const actionPacketSha256 = environment.C7_SHIELD_ACTION_PACKET_SHA256;
  if (proofInstance === 'file' && !proofFile) {
    throw new Error('ELIG_FILE is required when ELIG_INSTANCE=file');
  }
  if ((shieldAdapterFile === undefined) !== (shieldAdapterSha256 === undefined)) {
    throw new Error('C7_SHIELD_ADAPTER_FILE and C7_SHIELD_ADAPTER_SHA256 must be supplied together');
  }
  if (structuralRoleCount !== 0 && structuralRoleCount !== 3) {
    throw new Error('C7_STRUCTURAL_ROLE_COUNT must be 0 or 3');
  }
  if ((actionPacketFile === undefined) !== (actionPacketSha256 === undefined)) {
    throw new Error('C7_SHIELD_ACTION_PACKET_FILE and C7_SHIELD_ACTION_PACKET_SHA256 must be supplied together');
  }
  if (structuralRoleCount === 3 && actionPacketFile === undefined) {
    throw new Error('C7_STRUCTURAL_ROLE_COUNT=3 requires a pinned shield action packet');
  }
  if (structuralRoleCount !== 3 && actionPacketFile !== undefined) {
    throw new Error('pinned shield action packet requires C7_STRUCTURAL_ROLE_COUNT=3');
  }
  const eligSelectors = ['ELIG_INSTANCE', 'ELIG_FILE', 'ELIG_IDX'].filter((name) => environment[name] !== undefined);
  if (shieldAdapterFile !== undefined && eligSelectors.length !== 0) {
    throw new Error(`C7_SHIELD_ADAPTER_FILE owns VK/proof/public signals and cannot be combined with ${eligSelectors.join(', ')}`);
  }

  return freezeSections({
    paths: {
      generated: environment.C7_GEN || join(here, 'generated'),
      tool: environment.C7_TOOL || join(repoRoot, 'tools/singleton-artifact'),
      temp: environment.C7_TMP || join(environment.TMPDIR || '/tmp', 'verifier-cash-c7'),
    },
    mode: {
      directPort: flag(environment, 'DP'),
      striped: flag(environment, 'STRIPED'),
      stripeBoundary: flag(environment, 'STRIPE_BOUNDARY'),
      directFinalizeState: flag(environment, 'DIRECT_FINALIZE_STATE'),
      strictDeployment: flag(environment, 'STRICT_DEPLOYMENT'),
      publicBenchContext: flag(environment, 'PUBLIC_BENCH_CONTEXT'),
      driverPackDerived: flag(environment, 'DRIVER_PACK_DERIVED'),
      driverWindowDerived: flag(environment, 'DRIVER_WINDOW_DERIVED'),
      structuralRoleCount,
    },
    proofSelection: {
      instance: proofInstance,
      file: proofFile,
      shieldAdapter: shieldAdapterFile === undefined ? undefined : Object.freeze({ path: shieldAdapterFile, sha256: shieldAdapterSha256 }),
      index: number(environment, 'ELIG_IDX', 1),
      rawIndex: environment.ELIG_IDX,
    },
    shieldAction: {
      packet: actionPacketFile === undefined
        ? undefined
        : Object.freeze({ path: actionPacketFile, sha256: actionPacketSha256 }),
    },
    layout: {
      windowSize,
      stripedFragments,
      stripedNoDriver: flag(environment, 'STRIPED_NO_DRIVER'),
      stripedNoHash: flag(environment, 'STRIPED_NO_HASH'),
    },
    optimization: {
      foldOnly: flag(environment, 'C7_FOLDONLY'),
      disableFold: flag(environment, 'C7_NOFOLD'),
      disableOptimize: flag(environment, 'C7_NOOPT'),
      disableStrip: flag(environment, 'C7_NOSTRIP'),
      disableConstantSeed: flag(environment, 'C7_NOCSEED'),
      disableH1: flag(environment, 'C7_NOH1'),
      disableParameterAlias: flag(environment, 'C7_NOPALIAS'),
      disableMultiplyByOne: flag(environment, 'C7_NOMUL1'),
      keepNodeBake: flag(environment, 'DP_NODEBAKE'),
      maxTry,
      stub: environment.C7_STUB,
    },
    diagnostics: {
      debug: flag(environment, 'C7_DBG'),
    },
  });
};
