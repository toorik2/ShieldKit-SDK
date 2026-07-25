#!/usr/bin/env node
import { resolve } from 'node:path';

import { assertValid, readJson } from '../../contracts/src/index.mjs';
import { arenaStatus, checkArena, closeArena, createArena, finalizeArena } from './arena.mjs';
import { buildCandidateBundle } from './bundle.mjs';
import { gcControlPlane } from './gc.mjs';
import { runIsolated } from './isolated-exec.mjs';
import { checkCurrentAssignment } from './ownership.mjs';
import { judgeBundle } from './judge.mjs';
import { parseOptions, resolveRepoPath } from './repo.mjs';

const usage = `verifier.cash control plane

Usage:
  vc validate FILE
  vc build CANDIDATE [--run-id ID] [--out REPO_RELATIVE_DIR]
  vc judge BUNDLE [--tier fast|qualification|promotion] [--out FILE]
  vc verify CANDIDATE [--tier fast|qualification|promotion] [--run-id ID] [--out REPO_RELATIVE_DIR]
  vc arena create RUN_ID --workers worker-a,worker-b (--target-lane LANE | --scope PATHS) [--base REF] [--dry-run]
  vc arena status RUN_ID
  vc arena check RUN_ID [WORKER]
  vc arena close RUN_ID --yes
  vc arena finalize RUN_ID --integrated-into REF [--allow-local] --yes
  vc scope-check
  vc exec [--run-id ID] -- COMMAND [ARGS...]
  vc gc [--yes]
`;

const main = async () => {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === 'help' || command === '--help') {
    console.log(usage);
    return;
  }
  if (command === 'exec') {
    const separator = rest.indexOf('--');
    if (separator === -1) throw new Error('exec requires -- before the command');
    const { options } = parseOptions(rest.slice(0, separator));
    const [executable, ...args] = rest.slice(separator + 1);
    console.log(JSON.stringify(runIsolated({ command: executable, args, runId: options['run-id'] }), null, 2));
    return;
  }
  const { positionals, options } = parseOptions(rest);
  if (command === 'validate') {
    const path = positionals[0];
    if (!path) throw new Error('validate requires a file');
    const value = readJson(resolveRepoPath(path));
    const kinds = {
      'verifier.cash/lane/v1': 'lane',
      'verifier.cash/candidate/v1': 'candidate',
      'verifier.cash/candidate-bundle/v1': 'bundle',
      'verifier.cash/evidence/v1': 'evidence',
    };
    const kind = kinds[value.schema];
    if (!kind) throw new Error(`unknown schema: ${value.schema}`);
    assertValid(kind, value);
    console.log(`${kind} valid: ${path}`);
    return;
  }
  if (command === 'build') {
    const candidate = positionals[0];
    if (!candidate) throw new Error('build requires a candidate manifest');
    const built = await buildCandidateBundle(candidate, { runId: options['run-id'], out: options.out });
    console.log(JSON.stringify({ runId: built.bundle.runId, candidate: built.bundle.candidateId, bundle: built.bundlePath }, null, 2));
    return;
  }
  if (command === 'judge') {
    const bundle = positionals[0];
    if (!bundle) throw new Error('judge requires a bundle');
    judgeBundle(resolve(bundle), { tier: options.tier, out: options.out });
    return;
  }
  if (command === 'verify') {
    const candidate = positionals[0];
    if (!candidate) throw new Error('verify requires a candidate manifest');
    const built = await buildCandidateBundle(candidate, { runId: options['run-id'], out: options.out });
    judgeBundle(built.bundlePath, { tier: options.tier ?? 'fast' });
    return;
  }
  if (command === 'arena') {
    const [subcommand, runId] = positionals;
    if (!subcommand || !runId) throw new Error('arena requires create|status|close and a run id');
    if (subcommand === 'create') {
      const workers = String(options.workers ?? options.lanes ?? '').split(',').filter(Boolean);
      const scopes = String(options.scope ?? '').split(',').filter(Boolean);
      console.log(JSON.stringify(createArena({
        runId,
        workers,
        targetLane: options['target-lane'],
        scopes,
        base: options.base,
        dryRun: options['dry-run'] === true,
      }), null, 2));
      return;
    }
    if (subcommand === 'status') {
      console.log(JSON.stringify(arenaStatus(runId), null, 2));
      return;
    }
    if (subcommand === 'check') {
      console.log(JSON.stringify(checkArena({ runId, worker: positionals[2] }), null, 2));
      return;
    }
    if (subcommand === 'close') {
      console.log(JSON.stringify(closeArena({ runId, yes: options.yes === true }), null, 2));
      return;
    }
    if (subcommand === 'finalize') {
      console.log(JSON.stringify(finalizeArena({
        runId,
        integratedInto: options['integrated-into'],
        allowLocal: options['allow-local'] === true,
        yes: options.yes === true,
      }), null, 2));
      return;
    }
    throw new Error(`unknown arena subcommand: ${subcommand}`);
  }
  if (command === 'gc') {
    console.log(JSON.stringify(gcControlPlane({ yes: options.yes === true }), null, 2));
    return;
  }
  if (command === 'scope-check') {
    console.log(JSON.stringify(checkCurrentAssignment(), null, 2));
    return;
  }
  throw new Error(`unknown command: ${command}\n\n${usage}`);
};

main().catch((error) => {
  console.error(error?.stack ?? String(error));
  process.exitCode = 1;
});
