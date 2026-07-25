#!/usr/bin/env node
/**
 * Scaffold a local pool directory from a pinned development profile bundle.
 *
 * Full on-chain genesis still needs a category UTXO + broadcast (see --with-genesis).
 * This gives operators a product-shaped pool dir without sibling verifier.cash.
 *
 * Usage:
 *   node create-your-own-pool/scripts/create-pool.mjs \
 *     --out ./my-pool \
 *     [--bundle .cache/profile-build-live/profile-bundle]
 */
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadVerifierProfileBundle } from '../packages/profile/load.mjs';
import { resolveUnlockRoot, resolveLeanRoot, PIN_LENS } from '../packages/unlock-builder/index.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}

async function main() {
  const out = path.resolve(arg('out', path.join(ROOT, '.cache/my-pool')));
  const bundleSrc = path.resolve(arg('bundle', path.join(ROOT, '.cache/profile-build-live/profile-bundle')));
  if (!existsSync(bundleSrc)) {
    throw new Error(`profile bundle missing: ${bundleSrc}`);
  }
  if (existsSync(out)) {
    throw new Error(`out already exists: ${out}`);
  }

  const unlockRoot = resolveUnlockRoot();
  const leanRoot = resolveLeanRoot();
  const loaded = await loadVerifierProfileBundle(bundleSrc);

  mkdirSync(out, { recursive: true });
  cpSync(bundleSrc, path.join(out, 'bundle'), { recursive: true });
  mkdirSync(path.join(out, 'notes'), { recursive: true });
  mkdirSync(path.join(out, 'runs'), { recursive: true });

  const instance = {
    schema: 'shieldkit/pool-instance/v1',
    role: 'custom',
    network: loaded.manifest.network || 'chipnet',
    profileId: loaded.manifest.identity.profileId,
    instanceId: loaded.manifest.genesis.instanceId,
    bundleDirectory: 'bundle',
    unlockPinLens: PIN_LENS,
    unlockRootNote: 'resolved at runtime via @shieldkit/unlock-builder',
    createdAt: new Date().toISOString(),
  };
  writeFileSync(path.join(out, 'instance.json'), JSON.stringify(instance, null, 2));
  writeFileSync(path.join(out, 'state.json'), JSON.stringify({
    stateTxid: loaded.manifest.genesis?.transactionId
      || loaded.manifest.genesis?.txid
      || null,
    feeUtxos: [],
    history: [],
  }, null, 2));
  writeFileSync(path.join(out, 'README.md'), `# Pool

- profileId: \`${instance.profileId}\`
- instanceId: \`${instance.instanceId}\`
- unlock pin: \`${JSON.stringify(PIN_LENS)}\`

Act with:
\`\`\`
node create-your-own-pool/scripts/standalone-e2e-chipnet.mjs --bundle ${path.join(out, 'bundle')}
\`\`\`
`);

  console.log(JSON.stringify({
    ok: true,
    out,
    profileId: instance.profileId,
    instanceId: instance.instanceId,
    unlockRoot,
    leanRoot,
    pinLens: PIN_LENS,
  }, null, 2));
}

main().catch((e) => {
  console.error('FAIL', e.message || e);
  process.exit(1);
});
