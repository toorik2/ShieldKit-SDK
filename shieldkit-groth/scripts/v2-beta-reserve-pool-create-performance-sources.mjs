#!/usr/bin/env node
/**
 * Create the private immutable bootstrap-source ledger immediately before the
 * twenty fresh V2 beta pool-create performance samples. This command has no
 * wallet argument and cannot sign or broadcast a transaction. It claims the
 * fixed canonical operator registry; caller-supplied historical ledgers are
 * intentionally not an input surface.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  reserveV2BetaPerformanceSources,
} from '../packages/kit/v2/performance-source-reservations.mjs';
import { validateV2BetaPinnedInstall } from './v2-beta-live-qualification.mjs';

function usage() {
  throw new Error(
    'usage: v2-beta-reserve-pool-create-performance-sources.mjs --operator-root <private-0700-dir> --run-id <identifier> --plan <private-canonical-plan.json> --reservation-dir <private-dir>',
  );
}

function parseArguments(tokens) {
  const value = {};
  for (let index = 0; index < tokens.length; index += 2) {
    const flag = tokens[index]; const argument = tokens[index + 1];
    if (argument === undefined) usage();
    if (flag === '--plan' && value.planPath === undefined) value.planPath = argument;
    else if (flag === '--reservation-dir' && value.reservationDirectory === undefined) value.reservationDirectory = argument;
    else if (flag === '--operator-root' && value.operatorRoot === undefined) value.operatorRoot = argument;
    else if (flag === '--run-id' && value.runId === undefined) value.runId = argument;
    else usage();
  }
  if (value.planPath === undefined || value.reservationDirectory === undefined || value.operatorRoot === undefined || value.runId === undefined) usage();
  return Object.freeze(value);
}

if (import.meta.main === true || (process.argv[1] !== undefined
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))) {
  if (process.version !== 'v22.23.1') {
    throw new Error(`PERFORMANCE_SOURCE_NODE_VERSION_REQUIRED: expected Node v22.23.1, received ${process.version}`);
  }
  const result = await reserveV2BetaPerformanceSources(
    parseArguments(process.argv.slice(2)),
    { validateInstall: validateV2BetaPinnedInstall },
  );
  // Deliberately exclude paths and raw outpoints: the ledger is private local
  // operational state, not public qualification evidence.
  process.stdout.write(`${JSON.stringify({ sourceCount: result.sourceCount, release: result.release, leaseId: result.leaseId, runId: result.runId, ledgerSha256: result.ledgerSha256 })}\n`);
}
