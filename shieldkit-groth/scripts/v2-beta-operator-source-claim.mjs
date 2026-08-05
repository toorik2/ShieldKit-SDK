#!/usr/bin/env node
/** Explicit, one-source semantic-evidence claim in the canonical registry. */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { claimV2BetaSemanticSource, createV2BetaOperatorSourceLeaseId, registerV2BetaOperatorSemanticSource } from '../packages/kit/v2/operator-source-registry.mjs';
import { createPublicChipnetFulcrumRpc } from '../packages/kit/chipnet-rpc.mjs';
import { parseSerializedSourceOutput, parseV2RawTransaction } from '../packages/kit/v2/transaction-policy.mjs';

function usage() { throw new Error('usage: v2-beta-operator-source-claim.mjs --operator-root <private-0700-dir> --run-id <id> --outpoint <txid:vout> --wallet-locking-bytecode <p2pkh-hex> --value-sats <decimal> --data-home <private-0700-dir> --installation-receipt-sha256 <sha256> --release-id <id> --release-manifest-sha256 <sha256> --semantic-evidence-sha256 <sha256>'); }
function parse(tokens) { const expected = new Set(['--operator-root', '--run-id', '--outpoint', '--wallet-locking-bytecode', '--value-sats', '--data-home', '--installation-receipt-sha256', '--release-id', '--release-manifest-sha256', '--semantic-evidence-sha256']); const value = {}; for (let index = 0; index < tokens.length; index += 2) { const flag = tokens[index]; const argument = tokens[index + 1]; if (argument === undefined || !expected.has(flag) || value[flag] !== undefined) usage(); value[flag] = argument; } if (Object.keys(value).length !== expected.size) usage(); return value; }
function outpoint(value) { const match = /^([0-9a-f]{64}):(0|[1-9][0-9]*)$/u.exec(value); if (match === null) throw new Error('semantic outpoint must be canonical txid:vout'); return { txid: match[1], vout: Number(match[2]) }; }
async function authenticateSemanticSource(value) {
  const source = outpoint(value['--outpoint']); const rpc = await createPublicChipnetFulcrumRpc();
  try {
    const [raw, live] = await Promise.all([rpc.getrawtransaction(source.txid, false), rpc.gettxout(source.txid, source.vout)]);
    if (typeof raw !== 'string' || live === null) throw new Error('semantic source must be an unspent public-Chipnet-visible output before it is claimed');
    const transaction = parseV2RawTransaction(raw); const output = transaction.outputs[source.vout] === undefined ? null : parseSerializedSourceOutput(transaction.outputs[source.vout].serializedHex); const observed = typeof live?.valueSatoshis === 'string' ? live.valueSatoshis : String(Math.round(Number(live?.value) * 100_000_000));
    if (transaction.txid !== source.txid || output === null || output.token !== null || output.lockingBytecodeHex !== value['--wallet-locking-bytecode'] || output.valueSatoshis.toString() !== value['--value-sats'] || live?.scriptPubKey?.hex !== value['--wallet-locking-bytecode'] || observed !== value['--value-sats'] || live?.tokenData !== undefined && live.tokenData !== null || live?.token !== undefined && live.token !== null) throw new Error('semantic source raw transaction and public Chipnet UTXO readback do not bind the supplied tokenless P2PKH source');
  } finally { try { await rpc.close?.(); } catch {} }
}
if (import.meta.main === true || (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))) {
  if (process.version !== 'v22.23.1') throw new Error(`OPERATOR_SOURCE_CLAIM_NODE_VERSION_REQUIRED: expected Node v22.23.1, received ${process.version}`);
  const value = parse(process.argv.slice(2)); await authenticateSemanticSource(value);
  registerV2BetaOperatorSemanticSource({ operatorRoot: value['--operator-root'], source: { outpoint: value['--outpoint'], lockingBytecodeHex: value['--wallet-locking-bytecode'], valueSats: value['--value-sats'] } });
  const result = claimV2BetaSemanticSource({ operatorRoot: value['--operator-root'], claim: { release: { releaseId: value['--release-id'], releaseManifestSha256: value['--release-manifest-sha256'] }, runId: value['--run-id'], leaseId: createV2BetaOperatorSourceLeaseId(), evidenceSha256: value['--semantic-evidence-sha256'], sources: [{ outpoint: value['--outpoint'], dataHome: value['--data-home'], installationReceiptSha256: value['--installation-receipt-sha256'] }] } });
  process.stdout.write(`${JSON.stringify({ sourceCount: result.sourceCount, leaseId: result.leaseId, runId: result.runId })}\n`);
}
