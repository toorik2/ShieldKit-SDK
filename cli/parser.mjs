/** Canonical, deliberately small ShieldKit CLI grammar. */

import { ERROR_CODES, CliError } from './contracts/errors.mjs';

export const GROUPS = Object.freeze(['design', 'pool', 'action', 'operation', 'demo', 'help']);

export const COMMANDS = Object.freeze({
  design: Object.freeze(['list', 'show', 'doctor', 'verify']),
  pool: Object.freeze(['create', 'import', 'status', 'sync', 'doctor']),
  action: Object.freeze(['deposit', 'transfer', 'withdraw']),
  operation: Object.freeze(['inspect', 'rebroadcast']),
  demo: Object.freeze(['list', 'status']),
});

export const DEPRECATION_WINDOW = Object.freeze({
  schema: 'shieldkit-cli-deprecation/v1',
  announced: '2026-08-07',
  ends: '2026-11-07',
  message: 'Legacy PF10 pool deposit|transfer|withdraw and dual Lab router are deprecated; use action * and the unified shieldkit grammar. Shims end 2026-11-07.',
});

const VALUE_FLAGS = Object.freeze(new Set([
  'home', 'profile', 'design', 'data-home', 'from-data-home', 'to', 'note',
  'cas-token', 'funding-wallet', 'funding-utxo', 'operation-id',
]));
const BOOLEAN_FLAGS = Object.freeze(new Set([
  'json', 'help', 'version', 'allow-lab', 'acknowledge-rebroadcast', 'dry-run', 'resume',
]));

/** Parse argv without accepting an ambient or silent second grammar. */
export function parseArgv(argv) {
  const flags = {
    home: null, profile: null, design: null, json: false, help: false, version: false,
    allowLab: false, dataHome: null, fromDataHome: null, to: null, note: null,
    acknowledgeRebroadcast: false, casToken: null, dryRun: false, fundingWallet: null,
    fundingUtxo: null, operationId: null, resume: false,
  };
  const positionals = [];
  const seen = new Set();

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--') {
      throw new CliError(ERROR_CODES.USAGE, '`--` is not supported; ShieldKit has no free-form positional arguments', { exitCode: 64 });
    }
    if (!token.startsWith('--') && token !== '-h') {
      positionals.push(token);
      continue;
    }
    const name = token === '-h' ? 'help' : token.slice(2);
    if (!VALUE_FLAGS.has(name) && !BOOLEAN_FLAGS.has(name)) {
      throw new CliError(ERROR_CODES.USAGE, `unknown option: ${token}`, { exitCode: 64 });
    }
    if (seen.has(name)) {
      throw new CliError(ERROR_CODES.USAGE, `option may be supplied only once: --${name}`, { exitCode: 64 });
    }
    seen.add(name);
    if (BOOLEAN_FLAGS.has(name)) {
      flags[camel(name)] = true;
      continue;
    }
    const value = argv[++i];
    if (value === undefined || value.startsWith('--')) {
      throw new CliError(ERROR_CODES.OPTION_VALUE_REQUIRED, `--${name} requires a value`, { exitCode: 64 });
    }
    flags[camel(name)] = value;
  }

  if (flags.version) {
    if (positionals.length !== 0 || seen.size > 2 || (seen.size === 2 && !flags.json)) {
      throw new CliError(ERROR_CODES.USAGE, '--version accepts only the optional --json flag', { exitCode: 64 });
    }
    return Object.freeze({ group: 'version', command: null, flags: Object.freeze(flags), positionals: Object.freeze([]), deprecation: null });
  }

  let group = positionals[0] || null;
  let command = positionals[1] || null;
  let deprecation = null;
  if (group === 'pool' && ['deposit', 'transfer', 'withdraw'].includes(command)) {
    deprecation = Object.freeze({ ...DEPRECATION_WINDOW, legacy: `pool ${command}`, canonical: `action ${command}` });
    group = 'action';
  }
  if (flags.dataHome && !flags.home) {
    deprecation = deprecation || Object.freeze({ ...DEPRECATION_WINDOW, legacy: '--data-home', canonical: '--home after explicit pool import' });
  }

  if (!group) {
    if (flags.help) {
      validateHelpOnlyFlags(seen);
      return Object.freeze({ group: 'help', command: null, flags: Object.freeze(flags), positionals: Object.freeze([]), deprecation });
    }
    throw new CliError(ERROR_CODES.USAGE, 'missing group; try: shieldkit --help', { exitCode: 64 });
  }
  if (group === 'help') {
    if (positionals.length !== 1) throw new CliError(ERROR_CODES.USAGE, 'help takes no additional arguments', { exitCode: 64 });
    validateHelpOnlyFlags(seen);
    return Object.freeze({ group: 'help', command: null, flags: Object.freeze(flags), positionals: Object.freeze([]), deprecation });
  }
  if (!GROUPS.includes(group)) {
    throw new CliError(ERROR_CODES.UNKNOWN_COMMAND, `unknown group: ${group}`, { exitCode: 64, details: { groups: GROUPS } });
  }
  if (!command) {
    if (flags.help) {
      validateHelpOnlyFlags(seen);
      return Object.freeze({ group, command: null, flags: Object.freeze(flags), positionals: Object.freeze([]), deprecation });
    }
    throw new CliError(ERROR_CODES.USAGE, `missing command for group ${group}`, { exitCode: 64, details: { commands: COMMANDS[group] } });
  }
  if (!COMMANDS[group]?.includes(command)) {
    throw new CliError(ERROR_CODES.UNKNOWN_COMMAND, `unknown command: ${group} ${command}`, { exitCode: 64, details: { commands: COMMANDS[group] } });
  }

  validateFlagPlacement(seen, group, command);

  const trailing = positionals.slice(2);
  if (group === 'design' && command === 'show') {
    if (trailing.length > 1) throw new CliError(ERROR_CODES.USAGE, 'design show accepts at most one design/profile selector', { exitCode: 64 });
  } else if (trailing.length !== 0) {
    throw new CliError(ERROR_CODES.USAGE, `unexpected positional argument: ${trailing[0]}`, { exitCode: 64 });
  }
  return Object.freeze({ group, command, flags: Object.freeze(flags), positionals: Object.freeze(trailing), deprecation });
}

function camel(name) {
  return name.replace(/-([a-z])/gu, (_all, letter) => letter.toUpperCase());
}

function validateHelpOnlyFlags(seen) {
  for (const name of seen) {
    if (!['help', 'json'].includes(name)) {
      throw new CliError(ERROR_CODES.USAGE, `--${name} is not valid for standalone/group help`, { exitCode: 64 });
    }
  }
}

function validateFlagPlacement(seen, group, command) {
  const global = new Set(['home', 'design', 'profile', 'json', 'help']);
  const allowed = {
    'design list': [],
    'design show': [],
    'design doctor': [],
    'design verify': [],
    'pool create': ['data-home', 'funding-wallet', 'funding-utxo', 'resume'],
    'pool import': ['data-home', 'from-data-home', 'dry-run'],
    'pool status': [],
    'pool sync': [],
    'pool doctor': [],
    'action deposit': ['operation-id', 'allow-lab'],
    'action transfer': ['note', 'operation-id', 'allow-lab'],
    'action withdraw': ['note', 'to', 'operation-id', 'allow-lab'],
    'operation inspect': ['operation-id'],
    'operation rebroadcast': ['operation-id', 'cas-token', 'acknowledge-rebroadcast'],
    'demo list': [], 'demo status': [],
  }[`${group} ${command}`] || [];
  const permitted = new Set([...global, ...allowed]);
  for (const name of seen) {
    if (!permitted.has(name)) {
      throw new CliError(ERROR_CODES.USAGE, `--${name} is not valid for ${group} ${command}`, { exitCode: 64 });
    }
  }
}

export function formatHelp({ group = null, command = null } = {}) {
  if (group && !command) {
    return [
      `ShieldKit ${group} commands`,
      '',
      `usage: shieldkit [global flags] ${group} <command> [command flags]`,
      `commands: ${(COMMANDS[group] || []).join(', ')}`,
      '',
      'global flags: --home <path> --design <alias> --profile <64-hex-profile-id> --json --help',
      'A home is an explicit instance binding; --design/--profile asserts a match against it.',
      ...(group === 'operation'
        ? ['PF10 supports read-only inspection and exact acknowledged rebroadcast.']
        : []),
    ].join('\n');
  }
  if (group && command) {
    const specifics = {
      'pool create': '--funding-wallet <absolute path> --funding-utxo <txid:vout> [--data-home <legacy PF10 path>] | --resume',
      'pool import': '--from-data-home <legacy PF10 path> --home <new bound home> --design <pf10>',
      'action deposit': '--home <bound home> [--operation-id <id>]',
      'action transfer': '--home <bound home> --note <owned note id> [--operation-id <id>]',
      'action withdraw': '--home <bound home> --note <owned note id> --to <bchtest address> [--operation-id <id>]',
      'operation inspect': '--home <bound home> --operation-id <id>',
      'operation rebroadcast': '--home <bound home> --operation-id <id> --cas-token <uuid> --acknowledge-rebroadcast',
    };
    return [
      `ShieldKit ${group} ${command}`,
      '',
      `usage: shieldkit [global flags] ${group} ${command} ${specifics[`${group} ${command}`] || ''}`.trim(),
      '',
      'Unknown flags and extra positionals are rejected. Lab mutation verbs are currently blocked.',
    ].join('\n');
  }
  return [
    'ShieldKit — unified CLI', '',
    'usage: shieldkit [--home <path>] [--design <alias>|--profile <64-hex-profile-id>] <group> <command> [flags]', '',
    'groups:',
    '  design     list | show | doctor | verify',
    '  pool       create | import | status | sync | doctor',
    '  action     deposit | transfer | withdraw',
    '  operation  inspect | rebroadcast',
    '  demo       list | status', '',
    'Use "shieldkit <group> --help" or "shieldkit <group> <command> --help" for contextual help.',
    'Existing homes bind exact profile identity. Lab mutations are blocked until a qualified backend exists.',
    'Developer and benchmark tools use explicit npm scripts; unimplemented command groups are not advertised.',
    `Deprecation window ends ${DEPRECATION_WINDOW.ends}: legacy pool deposit|transfer|withdraw aliases.`,
  ].join('\n');
}
