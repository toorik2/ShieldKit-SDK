export const profileSchema = 'verifier.cash/bn254-onetx-c7-profile/v1';

const generatorFields = [
  'allAffine',
  'selectL17',
  'narrowSeam',
  'specializeK',
  'siblingRead',
  'fixedWitnessData',
  'dynamicPacking',
  'deriveMode',
  'rescheduleStacks',
];
const modeFields = [
  'directPort',
  'striped',
  'stripeBoundary',
  'directFinalizeState',
  'strictDeployment',
  'publicBenchContext',
  'driverPackDerived',
  'driverWindowDerived',
];
const packingBooleanFields = [
  'retainConsensusData',
  'retainWitnessData',
  'enforceInputExhaustion',
  'stripedNoForward',
  'stripedNoWindow',
  'stripedWindowTest',
  'stripedNoDriver',
  'stripedNoHash',
];
const optimizationBooleanFields = [
  'foldOnly',
  'disableFold',
  'disableOptimize',
  'disableStrip',
  'disableConstantSeed',
  'disableH1',
  'disableParameterAlias',
  'disableMultiplyByOne',
  'keepNodeBake',
];

const requireObject = (value, path) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${path} must be an object`);
  return value;
};

const requireExactKeys = (value, fields, path) => {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.join('\0') !== expected.join('\0')) {
    throw new Error(`${path} must define exactly: ${expected.join(', ')}`);
  }
};

const requireBooleans = (value, fields, path) => {
  requireExactKeys(value, fields, path);
  for (const field of fields) {
    if (typeof value[field] !== 'boolean') throw new Error(`${path}.${field} must be boolean`);
  }
};

const requireInteger = (value, path, { minimum, maximum } = {}) => {
  if (!Number.isInteger(value)) throw new Error(`${path} must be an integer`);
  if (minimum !== undefined && value < minimum) throw new Error(`${path} must be >= ${minimum}`);
  if (maximum !== undefined && value > maximum) throw new Error(`${path} must be <= ${maximum}`);
};

const deepFreeze = (value) => {
  for (const child of Object.values(value)) {
    if (child !== null && typeof child === 'object') deepFreeze(child);
  }
  return Object.freeze(value);
};

export const readBuildProfile = (input) => {
  const profile = structuredClone(requireObject(input, 'build.profile'));
  requireExactKeys(profile, ['schema', 'generator', 'mode', 'layout', 'packing', 'optimization'], 'build.profile');
  if (profile.schema !== profileSchema) throw new Error(`build.profile.schema must be ${profileSchema}`);

  requireBooleans(requireObject(profile.generator, 'build.profile.generator'), generatorFields, 'build.profile.generator');
  requireBooleans(requireObject(profile.mode, 'build.profile.mode'), modeFields, 'build.profile.mode');

  const layout = requireObject(profile.layout, 'build.profile.layout');
  requireExactKeys(layout, ['windowSize', 'stripedFragments'], 'build.profile.layout');
  // K=13 is the bounded five-executor research layout. The build still has to
  // prove every executor and both boundary inputs fit consensus limits.
  requireInteger(layout.windowSize, 'build.profile.layout.windowSize', { minimum: 7, maximum: 13 });
  requireInteger(layout.stripedFragments, 'build.profile.layout.stripedFragments', { minimum: 1 });

  const packing = requireObject(profile.packing, 'build.profile.packing');
  requireExactKeys(packing, [
    ...packingBooleanFields,
    'stateWidth',
    'consensusNarrowLimbs',
    'consensusWidth',
    'narrowWitnessLimbs',
    'witnessWidth',
    'wideWitnessPositions',
    'finalPadding',
  ], 'build.profile.packing');
  for (const field of packingBooleanFields) {
    if (typeof packing[field] !== 'boolean') throw new Error(`build.profile.packing.${field} must be boolean`);
  }
  requireInteger(packing.stateWidth, 'build.profile.packing.stateWidth', { minimum: 1 });
  requireInteger(packing.consensusNarrowLimbs, 'build.profile.packing.consensusNarrowLimbs', { minimum: 0, maximum: 8 });
  requireInteger(packing.consensusWidth, 'build.profile.packing.consensusWidth', { minimum: 1, maximum: 40 });
  requireInteger(packing.narrowWitnessLimbs, 'build.profile.packing.narrowWitnessLimbs', { minimum: 0, maximum: 16 });
  requireInteger(packing.witnessWidth, 'build.profile.packing.witnessWidth', { minimum: 1, maximum: 40 });
  for (const field of ['wideWitnessPositions', 'finalPadding']) {
    if (!Array.isArray(packing[field])) throw new Error(`build.profile.packing.${field} must be an array`);
    packing[field].forEach((value, index) => requireInteger(value, `build.profile.packing.${field}[${index}]`, { minimum: 0 }));
  }

  const optimization = requireObject(profile.optimization, 'build.profile.optimization');
  requireExactKeys(optimization, [...optimizationBooleanFields, 'maxTry'], 'build.profile.optimization');
  for (const field of optimizationBooleanFields) {
    if (typeof optimization[field] !== 'boolean') throw new Error(`build.profile.optimization.${field} must be boolean`);
  }
  requireInteger(optimization.maxTry, 'build.profile.optimization.maxTry', { minimum: 0 });

  return deepFreeze(profile);
};

const setFlag = (environment, name, value) => {
  if (value) environment[name] = '1';
};

export const toLegacyEnvironment = (profileInput, fixture) => {
  const profile = readBuildProfile(profileInput);
  const environment = {
    ELIG_INSTANCE: 'file',
    ELIG_FILE: fixture,
    KWIN: String(profile.layout.windowSize),
    STRIPED_FRAGS: String(profile.layout.stripedFragments),
    SW: String(profile.packing.stateWidth),
    CDNW: String(profile.packing.consensusNarrowLimbs),
    CDWIDTH: String(profile.packing.consensusWidth),
    UNW: String(profile.packing.narrowWitnessLimbs),
    WDWIDTH: String(profile.packing.witnessWidth),
    WIDE_POS: profile.packing.wideWitnessPositions.join(','),
    FIN_PAD: profile.packing.finalPadding.join(','),
    C7_MAXTRY: String(profile.optimization.maxTry),
    NITS: profile.packing.enforceInputExhaustion ? '1' : '0',
    RESCHEDULE: profile.generator.rescheduleStacks ? 'on' : 'off',
  };

  for (const [name, value] of [
    ['SZ_ALLAFF', profile.generator.allAffine],
    ['L17SEL', profile.generator.selectL17],
    ['SEAMNARROW', profile.generator.narrowSeam],
    ['KSPEC', profile.generator.specializeK],
    ['SIBLING_READ', profile.generator.siblingRead],
    ['FIXED_WDAT', profile.generator.fixedWitnessData],
    ['DYN_PACK', profile.generator.dynamicPacking],
    ['DERIVE_MODE', profile.generator.deriveMode],
    ['DP', profile.mode.directPort],
    ['STRIPED', profile.mode.striped],
    ['STRIPE_BOUNDARY', profile.mode.stripeBoundary],
    ['DIRECT_FINALIZE_STATE', profile.mode.directFinalizeState],
    ['STRICT_DEPLOYMENT', profile.mode.strictDeployment],
    ['PUBLIC_BENCH_CONTEXT', profile.mode.publicBenchContext],
    ['DRIVER_PACK_DERIVED', profile.mode.driverPackDerived],
    ['DRIVER_WINDOW_DERIVED', profile.mode.driverWindowDerived],
    ['RETAIN_CDAT', profile.packing.retainConsensusData],
    ['RETAIN_WDAT', profile.packing.retainWitnessData],
    ['STRIPED_NO_FORWARD', profile.packing.stripedNoForward],
    ['STRIPED_NO_WINDOW', profile.packing.stripedNoWindow],
    ['STRIPED_WINDOW_TEST', profile.packing.stripedWindowTest],
    ['STRIPED_NO_DRIVER', profile.packing.stripedNoDriver],
    ['STRIPED_NO_HASH', profile.packing.stripedNoHash],
    ['C7_FOLDONLY', profile.optimization.foldOnly],
    ['C7_NOFOLD', profile.optimization.disableFold],
    ['C7_NOOPT', profile.optimization.disableOptimize],
    ['C7_NOSTRIP', profile.optimization.disableStrip],
    ['C7_NOCSEED', profile.optimization.disableConstantSeed],
    ['C7_NOH1', profile.optimization.disableH1],
    ['C7_NOPALIAS', profile.optimization.disableParameterAlias],
    ['C7_NOMUL1', profile.optimization.disableMultiplyByOne],
    ['DP_NODEBAKE', profile.optimization.keepNodeBake],
  ]) setFlag(environment, name, value);

  return environment;
};

export const legacyEnvironmentKeys = Object.freeze([
  'C7_DBG', 'C7_DIRECT_LOCKS', 'C7_DIRECT_LOCKS_RAW', 'C7_DIRECT_TERMINAL_LOCK', 'C7_FOLDONLY', 'C7_GEN', 'C7_MAXTRY', 'C7_NOCSEED', 'C7_NOFOLD', 'C7_NOH1',
  'C7_PROJECTED_BQ_7', 'C7_STRUCTURAL_ROLE_COUNT', 'C7_TERMINAL_OMIT_BQ_PROBE',
  'C7_SCALAR_BQ_NO_FUEL', 'C7_SCALAR_BQ_RESERVE', 'C7_SCALAR_TERM_DENS_DROP',
  'C7_NOMUL1', 'C7_NOOPT', 'C7_NOPALIAS', 'C7_NOSTRIP', 'C7_STUB', 'C7_TMP', 'C7_TOOL',
  'CASHC_ROOT', 'CDNW', 'CDWIDTH', 'DERIVE_MODE', 'DIRECT_FINALIZE_STATE', 'DP', 'DP_NODEBAKE',
  'DRIVER_PACK_DERIVED', 'DRIVER_WINDOW_DERIVED', 'DYN_PACK', 'ELIG_FILE', 'ELIG_IDX', 'C7_SHIELD_ADAPTER_FILE', 'C7_SHIELD_ADAPTER_SHA256',
  'C7_SHIELD_ACTION_PACKET_FILE', 'C7_SHIELD_ACTION_PACKET_SHA256',
  'ELIG_INSTANCE', 'FIN_PAD', 'FIXED_WDAT', 'KSPEC', 'KWIN', 'L17SEL', 'LEANBCH_ROOT', 'NITS',
  'NO_TAIL', 'PAD_HASH', 'PUBLIC_BENCH_CONTEXT', 'RESCHEDULE', 'RETAIN_CDAT', 'RETAIN_WDAT',
  'SEAMNARROW', 'SIBLING_READ', 'SR_DROP', 'STRICT_DEPLOYMENT', 'STRIPED', 'STRIPED_FRAGS',
  'STRIPED_NO_DRIVER', 'STRIPED_NO_FORWARD', 'STRIPED_NO_HASH', 'STRIPED_NO_WINDOW',
  'STRIPED_WINDOW_TEST', 'STRIPE_BOUNDARY', 'SW', 'SZ_ALLAFF', 'T7', 'UNW', 'VKX_NOFR',
  'TERMINAL_BIND_WSEL', 'TERMINAL_FROB_FUSE', 'TERMINAL_W_FASTPATH', 'TERMINAL_W_SELECTOR', 'TERMINAL_W_SPARSE',
  'WDWIDTH', 'WIDE_POS', 'XOR_BIND', 'DEFER_MOD_VARIANT',
]);

export const sanitizeLegacyEnvironment = (source) => {
  const environment = { ...source };
  for (const key of legacyEnvironmentKeys) delete environment[key];
  return environment;
};
