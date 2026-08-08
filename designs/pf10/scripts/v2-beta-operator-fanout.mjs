#!/usr/bin/env node
/** Operator-only funding fanout lifecycle. It never accepts private keys on argv. */
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  broadcastPreparedV2BetaOperatorFanout, prepareV2BetaOperatorFanout,
  provisionV2BetaOperatorFanoutDestinations, recoverV2BetaOperatorFanout,
} from '../packages/kit/v2/operator-fanout.mjs';

function usage() { throw new Error('usage: v2-beta-operator-fanout.mjs provision --operator-root <private-0700-dir> | prepare --operator-root <private-0700-dir> --run-id <id> --source-wallet <private-0600-wallet.json> --inventory <private-0600-canonical-inventory.json> | broadcast --execute-live --operator-root <private-0700-dir> --run-id <id> | recover --operator-root <private-0700-dir> --run-id <id>'); }
function options(tokens, required) { const value = {}; for (let index = 0; index < tokens.length; index += 2) { const flag = tokens[index]; const argument = tokens[index + 1]; if (argument === undefined || !required.includes(flag) || value[flag] !== undefined) usage(); value[flag] = argument; } if (Object.keys(value).length !== required.length || required.some((flag) => value[flag] === undefined)) usage(); return value; }

if (import.meta.main === true || (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))) {
  if (process.version !== 'v22.23.1') throw new Error(`OPERATOR_FANOUT_NODE_VERSION_REQUIRED: expected Node v22.23.1, received ${process.version}`);
  const [command, ...tokens] = process.argv.slice(2); let result;
  if (command === 'provision') { const value = options(tokens, ['--operator-root']); result = await provisionV2BetaOperatorFanoutDestinations({ operatorRoot: value['--operator-root'] }); result = { recipientCount: result.recipientCount, wallets: result.wallets.map((entry) => ({ ordinal: entry.ordinal, lockingBytecodeHex: entry.lockingBytecodeHex, cashAddress: entry.cashAddress })) }; }
  else if (command === 'prepare') { const value = options(tokens, ['--operator-root', '--run-id', '--source-wallet', '--inventory']); result = await prepareV2BetaOperatorFanout({ operatorRoot: value['--operator-root'], runId: value['--run-id'], sourceWalletPath: value['--source-wallet'], inventoryPath: value['--inventory'] }); }
  else if (command === 'broadcast') { if (tokens[0] !== '--execute-live') usage(); const value = options(tokens.slice(1), ['--operator-root', '--run-id']); result = await broadcastPreparedV2BetaOperatorFanout({ operatorRoot: value['--operator-root'], runId: value['--run-id'] }); }
  else if (command === 'recover') { const value = options(tokens, ['--operator-root', '--run-id']); result = await recoverV2BetaOperatorFanout({ operatorRoot: value['--operator-root'], runId: value['--run-id'] }); }
  else usage();
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
