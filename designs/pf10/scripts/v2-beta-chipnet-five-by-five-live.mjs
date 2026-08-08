#!/usr/bin/env node

/**
 * Explicitly unqualified live Chipnet driver for the fixed 5-deposit/5-withdrawal
 * beta story. This entrypoint never prints wallet secrets and keeps offline build
 * and network broadcast as separate commands.
 *
 * Payout must be a dedicated wallet, never the funding/fee hot wallet.
 */
import { randomBytes } from 'node:crypto';
import { chmod, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { createLayer1BchnChipnetRpc } from '../packages/kit/chipnet-rpc.mjs';
import { loadPendingOperation } from '../packages/kit/transaction-coordinator.mjs';
import {
  deriveV2ChipnetFundingWallet,
} from '../packages/kit/v2/funding-wallet.mjs';
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
    'usage: v2-beta-chipnet-five-by-five-live.mjs build <deployment-dir> <story-dir> <funding-wallet-json> [payout-wallet-json] | broadcast <story-dir>',
  );
}

async function privateWallet(filename, label) {
  const resolved = path.resolve(filename);
  const metadata = await stat(resolved);
  if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) {
    throw new Error(`${label} must be a private regular file`);
  }
  return JSON.parse(await readFile(resolved, 'utf8'));
}

function freshPayoutWallet() {
  for (let attempt = 0; attempt < 64; attempt += 1) {
    try {
      return deriveV2ChipnetFundingWallet({
        privateKeyHex: randomBytes(32).toString('hex'),
      });
    } catch {
      // invalid scalar; resample
    }
  }
  throw new Error('could not sample a payout wallet');
}

async function loadOrCreatePayoutWallet(storyDirectory, payoutArgument, fundingLockHex) {
  const payoutPath = payoutArgument === undefined
    ? path.join(storyDirectory, 'payout-wallet.json')
    : path.resolve(payoutArgument);
  let wallet;
  try {
    await stat(payoutPath);
    wallet = await privateWallet(payoutPath, 'payout wallet');
  } catch (error) {
    if (payoutArgument !== undefined) throw error;
    wallet = freshPayoutWallet();
    await writeFile(payoutPath, `${JSON.stringify(wallet, null, 2)}\n`, { mode: 0o600 });
    await chmod(payoutPath, 0o600);
  }
  const payout = wallet.hot ?? wallet;
  const lock = payout.lockingBytecodeHex ?? payout.lockingBytecode;
  if (typeof lock !== 'string' || !/^[0-9a-f]+$/u.test(lock)) {
    throw new Error('payout wallet must expose lockingBytecodeHex');
  }
  if (lock === fundingLockHex) {
    throw new Error(
      'payout wallet must not equal the funding fee wallet; pass a dedicated payout-wallet-json',
    );
  }
  return Object.freeze({
    lockingBytecodeHex: lock,
    cashAddress: payout.cashAddress,
    path: payoutPath,
  });
}

async function build(deploymentArgument, storyArgument, walletArgument, payoutArgument) {
  if (walletArgument === undefined) usage();
  const deploymentDirectory = path.resolve(deploymentArgument);
  const storyDirectory = path.resolve(storyArgument);
  const [profileCore, bootstrap, finalized, fundingWallet] = await Promise.all([
    readFile(path.join(deploymentDirectory, 'runtime/profile/profile-core.json'), 'utf8').then(JSON.parse),
    readFile(path.join(deploymentDirectory, 'bootstrap-funding.json'), 'utf8').then(JSON.parse),
    readFile(path.join(deploymentDirectory, 'finalized-genesis.json'), 'utf8').then(JSON.parse),
    privateWallet(walletArgument, 'funding wallet'),
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
  const payout = await loadOrCreatePayoutWallet(
    storyDirectory,
    payoutArgument,
    hotWallet.lockingBytecodeHex,
  );
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
    withdrawalLockingBytecode: payout.lockingBytecodeHex,
  });
  const pending = loadPendingOperation(storyDirectory);
  return {
    status: result.record.status,
    operationId: result.operationId,
    elapsedSeconds: Math.round((Date.now() - startedAt) / 100) / 10,
    terminalStateSha256: result.record.terminalStateSha256,
    payoutCashAddress: payout.cashAddress,
    payoutWalletPath: payout.path,
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
