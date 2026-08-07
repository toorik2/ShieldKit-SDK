/**
 * Unified front controller — one binary, one grammar.
 */

import path from 'node:path';
import os from 'node:os';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from 'node:fs';

import { parseArgv, formatHelp, DEPRECATION_WINDOW } from './parser.mjs';
import { buildResultEnvelope, printEnvelope, RESULT_SCHEMA } from './contracts/envelopes.mjs';
import { CliError, ERROR_CODES } from './contracts/errors.mjs';
import {
  listDesignsDataOnly,
  showDesign,
  loadClosedCatalog,
  catalogContentHash,
  capabilitiesForDesign,
} from './registry/designs.mjs';
import { resolveHomeContext, migrateFromLegacyDataHome } from './home/resolve.mjs';
import { buildDemoCatalog, isUnavailableDemoCatalog, verifyDemoCatalog } from './demo/catalog.mjs';

const PACKAGE_VERSION = readPackageVersion();

export async function dispatch(argv = process.argv.slice(2), { stdout = process.stdout, env = process.env } = {}) {
  let parsed;
  try {
    parsed = parseArgv(argv);
  } catch (error) {
    const envelope = buildResultEnvelope({
      ok: false,
      code: error.code || ERROR_CODES.USAGE,
      error: error.message,
      command: null,
    });
    printEnvelope(envelope, { stream: stdout });
    return { envelope, exitCode: error.exitCode ?? 2 };
  }

  if (parsed.group === 'help' || (parsed.flags.help && !parsed.command)) {
    if (parsed.flags.json) {
      const envelope = buildResultEnvelope({
        ok: true,
        command: 'help',
        result: {
          grammar: formatHelp({ group: parsed.group === 'help' ? null : parsed.group }).split('\n'),
          deprecation: DEPRECATION_WINDOW,
          resultSchema: RESULT_SCHEMA,
        },
      });
      printEnvelope(envelope, { stream: stdout });
      return { envelope, exitCode: 0 };
    }
    stdout.write(`${formatHelp({ group: parsed.group === 'help' ? null : parsed.group })}\n`);
    return { envelope: { ok: true, command: 'help' }, exitCode: 0 };
  }

  if (parsed.group === 'version') {
    if (parsed.flags.json) {
      const envelope = buildResultEnvelope({ ok: true, command: 'version', result: { package: 'shieldkit', version: PACKAGE_VERSION } });
      printEnvelope(envelope, { stream: stdout });
      return { envelope, exitCode: 0 };
    }
    stdout.write(`shieldkit ${PACKAGE_VERSION}\n`);
    return { envelope: { ok: true, command: 'version', result: { version: PACKAGE_VERSION } }, exitCode: 0 };
  }

  if (parsed.flags.help) {
    if (parsed.flags.json) {
      const envelope = buildResultEnvelope({
        ok: true,
        command: `${parsed.group} ${parsed.command}`,
        result: { grammar: formatHelp({ group: parsed.group, command: parsed.command }).split('\n') },
      });
      printEnvelope(envelope, { stream: stdout });
      return { envelope, exitCode: 0 };
    }
    stdout.write(`${formatHelp({ group: parsed.group, command: parsed.command })}\n`);
    return { envelope: { ok: true, command: 'help' }, exitCode: 0 };
  }

  try {
    const envelope = await runCommand(parsed, { env });
    printEnvelope(envelope, { stream: stdout });
    return { envelope, exitCode: envelope.ok ? 0 : 2 };
  } catch (error) {
    if (error instanceof CliError) {
      const envelope = buildResultEnvelope({
        ok: false,
        code: error.code,
        error: error.message,
        command: `${parsed.group} ${parsed.command || ''}`.trim(),
        result: error.details,
        deprecation: parsed.deprecation,
      });
      printEnvelope(envelope, { stream: stdout });
      return { envelope, exitCode: error.exitCode ?? 2 };
    }
    const envelope = buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.INTERNAL,
      error: error instanceof Error ? error.message : String(error),
      command: `${parsed.group} ${parsed.command || ''}`.trim(),
    });
    printEnvelope(envelope, { stream: stdout });
    return { envelope, exitCode: 2 };
  }
}

async function runCommand(parsed, { env }) {
  const { group, command, flags, deprecation } = parsed;

  // --- design (read-only, data-only catalog) ---
  if (group === 'design') {
    if (command === 'list' || (flags.help && !command)) {
      if (flags.help && !command) {
        return buildResultEnvelope({
          ok: true,
          command: 'design help',
          result: { commands: ['list', 'show', 'doctor', 'verify'] },
        });
      }
      const designs = listDesignsDataOnly();
      return buildResultEnvelope({
        ok: true,
        command: 'design list',
        result: {
          designs,
          catalogHash: catalogContentHash(),
          backendModuleLoaded: false,
          note: 'closed catalog; listing does not execute backend modules',
        },
      });
    }
    if (command === 'show') {
      const id = parsed.positionals[0] || flags.design || flags.profile;
      if (!id) {
        return buildResultEnvelope({
          ok: false,
          code: ERROR_CODES.USAGE,
          error: 'design show requires a design alias or an exact registered profile id',
          command: 'design show',
        });
      }
      const d = showDesign(id);
      if (!d) {
        return buildResultEnvelope({
          ok: false,
          code: ERROR_CODES.UNKNOWN_ALIAS,
          error: `unknown design: ${id}`,
          command: 'design show',
        });
      }
      return buildResultEnvelope({
        ok: true,
        command: 'design show',
        identity: {
          backendId: d.backendId,
          ...(typeof d.profileId === 'string' ? { profileId: d.profileId } : {}),
          profileStatus: typeof d.profileId === 'string' ? 'frozen' : (d.profileStatus || 'unselected'),
          network: d.network,
        },
        result: d,
      });
    }
    if (command === 'verify') {
      const catalog = loadClosedCatalog();
      const hash = catalogContentHash();
      const profiles = catalog.designs.map((design) => {
        const capabilities = capabilitiesForDesign(design);
        return Object.freeze({
          designId: design.id,
          profileId: design.profileId,
          profileStatus: design.profileStatus,
          exactProfileVerified: false,
          supportStatus: capabilities.overall,
          mutationAuthority: capabilities.mutationAuthority,
          blockers: capabilities.blockers,
        });
      });
      return buildResultEnvelope({
        ok: true,
        command: 'design verify',
        result: {
          verificationScope: 'embedded-catalog-structure-only',
          designCount: catalog.designs.length,
          catalogHash: hash,
          exactProfilesVerified: 0,
          releaseReady: false,
          profiles,
          backendModuleLoaded: false,
          note: 'no exact profile package is pinned by the catalog; profile verification occurs when a validated home or package is opened',
        },
      });
    }
    if (command === 'doctor') {
      const ctx = buildCtx(parsed, env);
      return doctorFor(ctx, 'design doctor');
    }
  }

  // --- demo ---
  if (group === 'demo') {
    if (command === 'list') {
      const catalog = buildDemoCatalog();
      return buildResultEnvelope({
        ok: true,
        command: 'demo list',
        result: {
          catalog,
          verified: verifyDemoCatalog(catalog),
          unavailableStateValid: isUnavailableDemoCatalog(catalog),
          authenticity: 'unavailable',
          mutableSharedPoolDefault: false,
        },
      });
    }
    if (command === 'status') {
      const catalog = buildDemoCatalog();
      return buildResultEnvelope({
        ok: true,
        command: 'demo status',
        result: {
          readOnly: true,
          verified: verifyDemoCatalog(catalog),
          unavailableStateValid: isUnavailableDemoCatalog(catalog),
          authenticity: 'unavailable',
          entryCount: catalog.entries.length,
          policy: 'no demo descriptor catalog is bundled; no authenticity or funded-action claim exists',
        },
      });
    }
  }

  // --- pool import / migration ---
  if (group === 'pool' && command === 'import') {
    const from = flags.fromDataHome || flags.dataHome;
    if (!from) {
      return buildResultEnvelope({
        ok: false,
        code: ERROR_CODES.MIGRATION_REQUIRED,
        error: 'pool import requires --from-data-home <legacy-pf10-data-home>',
        command: 'pool import',
      });
    }
    const designAlias = flags.design || flags.profile;
    if (!designAlias) {
      return buildResultEnvelope({
        ok: false,
        code: ERROR_CODES.USAGE,
        error: 'pool import requires --design pf10 or an exact registered PF10 profile id',
        command: 'pool import',
      });
    }
    const design = showDesign(designAlias);
    if (!design) {
      return buildResultEnvelope({
        ok: false,
        code: ERROR_CODES.UNKNOWN_ALIAS,
        error: `unknown design ${designAlias}`,
        command: 'pool import',
      });
    }
    const migrated = await migrateFromLegacyDataHome({
      dataHome: from,
      destHome: flags.home,
      design,
      dryRun: flags.dryRun,
    });
    return buildResultEnvelope({
      ok: true,
      command: 'pool import',
      identity: migrated.home
        ? {
          backendId: migrated.home.backendId,
          profileId: migrated.home.profileId,
          profileStatus: 'frozen',
          instanceId: migrated.home.instanceId,
          homeId: migrated.home.homeId,
          network: migrated.home.network,
        }
        : {
          backendId: design.backendId,
          ...(typeof design.profileId === 'string' ? { profileId: design.profileId } : {}),
          profileStatus: typeof design.profileId === 'string' ? 'frozen' : (design.profileStatus || 'unselected'),
          network: design.network,
        },
      result: migrated,
      deprecation,
    });
  }

  // Context for remaining commands
  const ctx = buildCtx(parsed, env);

  if (group === 'pool') {
    if (command === 'doctor') return doctorFor(ctx, 'pool doctor');
    if (command === 'status') return statusFor(ctx);
    if (command === 'create') return createFor(ctx);
    if (command === 'sync') {
      return poolSyncFor(ctx, env);
    }
  }

  if (group === 'action') {
    return actionFor(ctx, command);
  }

  if (group === 'operation') {
    if ((command === 'inspect' || command === 'rebroadcast') && !flags.operationId) {
      return buildResultEnvelope({
        ok: false,
        code: ERROR_CODES.USAGE,
        error: `operation ${command} requires --operation-id`,
        command: `operation ${command}`,
        identity: identityFromCtx(ctx),
      });
    }
    if (command === 'rebroadcast') {
      if (!flags.acknowledgeRebroadcast) {
        return buildResultEnvelope({
          ok: false,
          code: ERROR_CODES.REBROADCAST_ACK_REQUIRED,
          error: 'operation rebroadcast requires --acknowledge-rebroadcast (never automatic)',
          command: 'operation rebroadcast',
          identity: identityFromCtx(ctx),
        });
      }
      if (!flags.casToken) {
        return buildResultEnvelope({
          ok: false,
          code: ERROR_CODES.REBROADCAST_CAS_REQUIRED,
          error: 'operation rebroadcast requires the current --cas-token',
          command: 'operation rebroadcast',
          identity: identityFromCtx(ctx),
        });
      }
    }
    // PF10: delegate recover inspect/rebroadcast to complete product lifecycle
    const design = requireDesign(ctx, `operation ${command}`);
    ctx.design = design;
    const adapter = await adapterFor(design);
    if (adapter?.pf10Operation) {
      if (command === 'inspect' || command === 'rebroadcast') {
        return adapter.pf10Operation(ctx, command);
      }
    }
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.CAPABILITY_BLOCKED,
      error: `operation ${command} is not available for ${ctx.design?.id || 'the selected backend'}`,
      command: `operation ${command}`,
      identity: identityFromCtx(ctx),
      result: ctx.design ? { capabilities: capabilitiesForDesign(ctx.design) } : null,
    });
  }

  return buildResultEnvelope({
    ok: false,
    code: ERROR_CODES.UNKNOWN_COMMAND,
    error: `unhandled ${group} ${command}`,
    command: `${group} ${command}`,
  });
}

function buildCtx(parsed, env) {
  const flags = { ...parsed.flags };
  if (flags.profile && !/^[0-9a-f]{64}$/u.test(flags.profile)) {
    throw new CliError(ERROR_CODES.USAGE, '--profile must be an exact lowercase 64-hex registered profile id', { exitCode: 64 });
  }
  const config = readOwnerConfig(env);
  // Selector precedence applies to the selector pair. Supplying either CLI
  // selector suppresses both config selectors, so an explicit profile is never
  // accidentally combined with an ambient default design (and vice versa).
  const explicitSelector = Boolean(flags.design || flags.profile);
  const selectedDesign = flags.design
    || (explicitSelector ? null : (config.design || env.SHIELDKIT_DESIGN || null));
  const selectedProfile = flags.profile
    || (explicitSelector ? null : (config.profile || null));
  const explicitDesign = selectedDesign ? showDesign(selectedDesign) : null;
  if (selectedDesign && !explicitDesign) {
    throw new CliError(ERROR_CODES.UNKNOWN_ALIAS, `unknown design: ${selectedDesign}`, { exitCode: 64 });
  }
  const registeredProfile = selectedProfile ? showDesign(selectedProfile) : null;
  // Config is owned by the local user; explicit flags always win. There is no ambient product default.
  const defaultHome = config.home || env.SHIELDKIT_HOME || env.SHIELDKIT_DEFAULT_HOME || null;
  const homePath = flags.home || defaultHome;
  let ctxBase = {
    flags,
    deprecation: parsed.deprecation,
    home: null,
    design: null,
    homeWins: false,
    env,
  };

  // For create/import-less commands, resolve home if present
  try {
    const resolved = resolveHomeContext({
      homePath,
      design: selectedDesign,
      profile: selectedProfile,
      defaultHome,
      requireHome: false,
    });
    ctxBase = {
      ...ctxBase,
      home: resolved.home,
      design: resolved.design,
      homeWins: resolved.homeWins,
      env,
    };
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw error;
  }

  // An exact profile may be asserted against a validated existing home even
  // when it is not globally registered. Without a home, only a closed-catalog
  // exact profile may select a backend.
  if (selectedProfile && !ctxBase.home && !registeredProfile) {
    throw new CliError(ERROR_CODES.PROFILE_NOT_REGISTERED, `profile is not registered and no bound home supplies it: ${selectedProfile}`, { exitCode: 64 });
  }
  if (explicitDesign && registeredProfile && explicitDesign.id !== registeredProfile.id) {
    throw new CliError(ERROR_CODES.HOME_PROFILE_MISMATCH, '--design and --profile select different designs', { exitCode: 64 });
  }

  // Default design for read-only design doctor when nothing specified: none auto from count
  if (!ctxBase.design && (selectedDesign || selectedProfile)) {
    ctxBase.design = explicitDesign || registeredProfile;
  }
  if (!ctxBase.design && !ctxBase.home) {
    // product default alias only when creating would apply — for doctor allow explicit pf10 default via flag absence only for design doctor listing?
    // Plan: no automatic default based on number of installed backends.
    // For doctor without design, require explicit alias.
  }
  return ctxBase;
}

function identityFromCtx(ctx) {
  if (!ctx.design && !ctx.home) return null;
  const identity = {
    backendId: ctx.home?.backendId || ctx.design?.backendId,
    instanceId: ctx.home?.instanceId ?? null,
    homeId: ctx.home?.homeId ?? null,
    network: ctx.home?.network || ctx.design?.network,
  };
  const profileId = ctx.home?.profileId || ctx.design?.profileId;
  if (typeof profileId === 'string') {
    identity.profileId = profileId;
    identity.profileStatus = 'frozen';
  } else {
    identity.profileStatus = ctx.design?.profileStatus || 'unselected';
  }
  return identity;
}

async function adapterFor(design) {
  if (design.id === 'pf10' || design.alias === 'pf10') return import('./adapters/pf10.mjs');
  if (design.id === 'pf6-a3-direct-v1' || design.alias === 'pf6') return import('./adapters/pf6.mjs');
  if (design.id === 'fri-stark-96kb' || design.alias === 'fri') return import('./adapters/fri.mjs');
  return null;
}

function readOwnerConfig(env) {
  const configuredRoot = env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  if (!path.isAbsolute(configuredRoot)) {
    throw new CliError(ERROR_CODES.AMBIENT_CONFIG_FORBIDDEN, 'XDG_CONFIG_HOME must be an absolute owner-controlled path', { exitCode: 64 });
  }
  const configPath = path.join(configuredRoot, 'shieldkit', 'config.json');
  if (!existsSync(configPath)) return Object.freeze({});
  assertNoSymlinkPath(configPath);
  const link = lstatSync(configPath);
  if (!link.isFile() || link.isSymbolicLink() || link.nlink !== 1 || (link.mode & 0o022) !== 0
    || (typeof process.getuid === 'function' && link.uid !== process.getuid())) {
    throw new CliError(ERROR_CODES.AMBIENT_CONFIG_FORBIDDEN, `refusing unsafe ShieldKit config: ${configPath}`, { exitCode: 64 });
  }
  let value;
  let fd;
  try {
    fd = openSync(configPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.ino !== link.ino || opened.dev !== link.dev
      || (opened.mode & 0o022) !== 0
      || (typeof process.getuid === 'function' && opened.uid !== process.getuid())) {
      throw new Error('config changed while opening');
    }
    value = JSON.parse(readFileSync(fd, 'utf8'));
  } catch {
    throw new CliError(ERROR_CODES.AMBIENT_CONFIG_FORBIDDEN, `invalid JSON in ShieldKit config: ${configPath}`, { exitCode: 64 });
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new CliError(ERROR_CODES.AMBIENT_CONFIG_FORBIDDEN, `ShieldKit config must be an object: ${configPath}`, { exitCode: 64 });
  }
  const allowed = new Set(['home', 'design', 'profile']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key) || (value[key] !== null && typeof value[key] !== 'string')) {
      throw new CliError(ERROR_CODES.AMBIENT_CONFIG_FORBIDDEN, `unsupported ShieldKit config field: ${key}`, { exitCode: 64 });
    }
  }
  return Object.freeze({ home: value.home || null, design: value.design || null, profile: value.profile || null });
}

function assertNoSymlinkPath(filename) {
  const absolute = path.resolve(filename);
  const root = path.parse(absolute).root;
  let current = root;
  for (const part of absolute.slice(root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    if (!existsSync(current)) break;
    if (lstatSync(current).isSymbolicLink()) {
      throw new CliError(ERROR_CODES.AMBIENT_CONFIG_FORBIDDEN, `refusing symlinked ShieldKit config path: ${current}`, { exitCode: 64 });
    }
  }
}

function readPackageVersion() {
  try {
    const value = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    return typeof value.version === 'string' ? value.version : 'unknown';
  } catch {
    return 'unknown';
  }
}

function requireDesign(ctx, command) {
  if (ctx.design) return ctx.design;
  // existing home always provides design binding
  if (ctx.home) {
    const d = showDesign(ctx.home.designId || ctx.home.backendId);
    if (d) return d;
  }
  throw new CliError(
    ERROR_CODES.UNKNOWN_ALIAS,
    `${command} requires --design/--profile or an existing --home`,
  );
}

async function doctorFor(ctx, command) {
  const design = requireDesign(ctx, command);
  ctx.design = design;
  if (command === 'pool doctor' && !ctx.home) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.HOME_NOT_FOUND,
      error: 'pool doctor requires a validated --home; use design doctor for a no-instance wiring check',
      command,
      identity: identityFromCtx(ctx),
      result: { instanceObserved: false },
    });
  }
  const adapter = await adapterFor(design);
  if (adapter?.pf10Doctor) return adapter.pf10Doctor(ctx, command);
  if (adapter?.pf6Doctor) return adapter.pf6Doctor(ctx, command);
  if (adapter?.friDoctor) return adapter.friDoctor(ctx, command);
  return buildResultEnvelope({
    ok: false,
    code: ERROR_CODES.UNKNOWN_ALIAS,
    error: `no doctor adapter for ${design.id}`,
    command,
  });
}

async function statusFor(ctx) {
  const design = requireDesign(ctx, 'pool status');
  ctx.design = design;
  if (!ctx.home) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.HOME_NOT_FOUND,
      error: 'pool status requires a validated instance --home',
      command: 'pool status',
      identity: identityFromCtx(ctx),
      result: { instanceObserved: false },
    });
  }
  const adapter = await adapterFor(design);
  if (adapter?.pf10PoolStatus) return adapter.pf10PoolStatus(ctx);
  return buildResultEnvelope({
    ok: false,
    code: ERROR_CODES.CAPABILITY_BLOCKED,
    error: `pool status for ${design.id} requires qualified sync capability`,
    command: 'pool status',
    identity: identityFromCtx(ctx),
    result: { capabilities: capabilitiesForDesign(design) },
  });
}

async function createFor(ctx) {
  const design = requireDesign(ctx, 'pool create');
  ctx.design = design;
  const adapter = await adapterFor(design);
  if (adapter?.pf10PoolCreate) return adapter.pf10PoolCreate(ctx);
  return buildResultEnvelope({
    ok: false,
    code: ERROR_CODES.CAPABILITY_BLOCKED,
    error: `pool create for ${design.id} is blocked until an exact profile and the complete safe lifecycle are qualified`,
    command: 'pool create',
    identity: identityFromCtx(ctx),
    result: { capabilities: capabilitiesForDesign(design), emulated: false },
  });
}

async function actionFor(ctx, kind) {
  const design = requireDesign(ctx, `action ${kind}`);
  ctx.design = design;
  const adapter = await adapterFor(design);
  if (adapter?.pf10Action) return adapter.pf10Action(ctx, kind);
  if (adapter?.pf6Action) return adapter.pf6Action(ctx, kind);
  if (adapter?.friAction) return adapter.friAction(ctx, kind);
  return buildResultEnvelope({
    ok: false,
    code: ERROR_CODES.UNKNOWN_ALIAS,
    error: `no action adapter for ${design.id}`,
    command: `action ${kind}`,
  });
}

/**
 * pool sync — reconstruct history via branded ChainReader.
 * No implementation is exposed until canonical lineage verification exists.
 */
async function poolSyncFor(ctx, env) {
  const design = ctx.design || (ctx.home ? showDesign(ctx.home.designId || ctx.home.backendId) : null);
  if (!ctx.home) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.HOME_NOT_FOUND,
      error: 'pool sync requires a validated instance --home',
      command: 'pool sync',
      identity: identityFromCtx({ ...ctx, design }),
      result: { instanceObserved: false },
    });
  }
  // Product path: never maintainer SSH
  if (env.SHIELDKIT_MAINTAINER_SSH || env.SHIELDKIT_PF6_SSH_HOST) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.MAINTAINER_PATH_FORBIDDEN,
      error: 'pool sync rejects maintainer SSH transports',
      command: 'pool sync',
      identity: identityFromCtx(ctx),
    });
  }

  return buildResultEnvelope({
    ok: false,
    code: ERROR_CODES.CAPABILITY_BLOCKED,
    error: 'pool sync has no qualified canonical-lineage implementation in the unified CLI yet; no mock reconstruction is exposed',
    command: 'pool sync',
    identity: identityFromCtx({ ...ctx, design }),
    result: {
      requires: ['qualified ChainReader', 'home network identity', 'canonical lineage verification'],
    },
  });
}
