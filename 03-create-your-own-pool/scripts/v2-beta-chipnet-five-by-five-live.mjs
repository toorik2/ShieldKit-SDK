#!/usr/bin/env node

/**
 * Explicitly unqualified live Chipnet driver for the fixed 5-deposit/5-withdrawal
 * beta story. This entrypoint never prints wallet secrets and keeps offline build
 * and network broadcast as separate commands.
 */
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';

import { createLayer1BchnChipnetRpc } from '../packages/kit/chipnet-rpc.mjs';
import { loadPendingOperation } from '../packages/kit/transaction-coordinator.mjs';
import {
  deriveV2BetaChipnetDeploymentBinding,
} from '../packages/profile/v2/beta-chipnet-deployment.mjs';
import {
  bindV2BetaChipnetRuntimeResolution,
  loadV2BetaChipnetRuntime,
} from '../packages/profile/v2/beta-chipnet-runtime.mjs';
import {
  broadcastV2BetaChipnetFiveByFiveStory,
  buildV2BetaChipnetFiveByFiveStory,
  V2_BETA_FIVE_BY_FIVE_ACKNOWLEDGEMENT,
} from '../packages/profile/v2/beta-chipnet-five-by-five-story.mjs';

function usage() {
  throw new Error(
    'usage: v2-beta-chipnet-five-by-five-live.mjs build <deployment-dir> <story-dir> <wallet-json> | broadcast <story-dir>',
  );
}

async function privateWallet(filename) {
  const resolved = path.resolve(filename);
  const metadata = await stat(resolved);
  if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) {
    throw new Error('funding wallet must be a private regular file');
  }
  return JSON.parse(await readFile(resolved, 'utf8'));
}

async function build(deploymentArgument, storyArgument, walletArgument) {
  if (walletArgument === undefined) usage();
  const deploymentDirectory = path.resolve(deploymentArgument);
  const storyDirectory = path.resolve(storyArgument);
  const [profileCore, bootstrap, finalized, fundingWallet] = await Promise.all([
    readFile(path.join(deploymentDirectory, 'runtime/profile/profile-core.json'), 'utf8').then(JSON.parse),
    readFile(path.join(deploymentDirectory, 'bootstrap-funding.json'), 'utf8').then(JSON.parse),
    readFile(path.join(deploymentDirectory, 'finalized-genesis.json'), 'utf8').then(JSON.parse),
    privateWallet(walletArgument),
  ]);
  const startedAt = Date.now();
  const loadedRuntime = await loadV2BetaChipnetRuntime({
    runtimeDirectory: path.join(deploymentDirectory, 'runtime'),
    temporaryRoot: path.join(storyDirectory, 'runtime-verify-tmp'),
  });
  const deploymentBinding = deriveV2BetaChipnetDeploymentBinding({ deploymentDirectory });
  const runtimeResolution = bindV2BetaChipnetRuntimeResolution(loadedRuntime, {
    descriptorSha256: deploymentBinding.zeroConfEvidenceSha256,
    manifestSha256: loadedRuntime.runtimeManifestSha256,
  });
  const hotWallet = fundingWallet.hot ?? fundingWallet;
  const result = await buildV2BetaChipnetFiveByFiveStory({
    acknowledgement: V2_BETA_FIVE_BY_FIVE_ACKNOWLEDGEMENT,
    bootstrapSourceTransactionHex: bootstrap.funding.rawTransactionHex,
    deploymentBinding,
    funding: {
      privateKeyHex: hotWallet.privateKeyHex,
      lockingBytecode: hotWallet.lockingBytecodeHex,
    },
    genesisRawTransactionHex: finalized.genesis.rawTransactionHex,
    maximumLiveNotes: '100000',
    profileCore,
    runtimeResolution,
    storyDirectory,
    withdrawalLockingBytecode: hotWallet.lockingBytecodeHex,
  });
  const pending = loadPendingOperation(storyDirectory);
  return {
    status: result.record.status,
    operationId: result.operationId,
    elapsedSeconds: Math.round((Date.now() - startedAt) / 100) / 10,
    terminalStateSha256: result.record.terminalStateSha256,
    transactions: pending.journal.transactions.map((entry, index) => ({
      ordinal: index + 1,
      role: entry.role,
      txid: entry.txid,
      bytes: entry.hex.length / 2,
    })),
  };
}

async function broadcast(storyArgument) {
  if (storyArgument === undefined) usage();
  const storyDirectory = path.resolve(storyArgument);
  const rpc = await createLayer1BchnChipnetRpc();
  const startedAt = Date.now();
  const result = await broadcastV2BetaChipnetFiveByFiveStory({
    acknowledgement: V2_BETA_FIVE_BY_FIVE_ACKNOWLEDGEMENT,
    rpc,
    storyDirectory,
  });
  const pending = loadPendingOperation(storyDirectory);
  return {
    status: result.record.status,
    operationId: result.operationId,
    backend: result.rpcBackend,
    elapsedSeconds: Math.round((Date.now() - startedAt) / 100) / 10,
    transactions: pending.journal.transactions.map((entry, index) => ({
      ordinal: index + 1,
      role: entry.role,
      txid: entry.txid,
      bytes: entry.hex.length / 2,
      status: entry.status,
    })),
  };
}

const [command, ...arguments_] = process.argv.slice(2);
const result = command === 'build'
  ? await build(...arguments_)
  : command === 'broadcast'
    ? await broadcast(...arguments_)
    : usage();
process.stdout.write(`${JSON.stringify(result)}\n`);
