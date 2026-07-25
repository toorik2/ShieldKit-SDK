import { writeFileSync } from 'node:fs';
import {
  LOGN,
  LOG_BLOWUP,
  NUM_QUERIES,
  init,
  buildBundle,
  evaluateBundle,
  metrics,
  assertStandard,
  allAccepted,
} from './common.mjs';
import { qStarkProve } from '../fri_stark/qstark.mjs';
import { binToHex } from '../node_modules/@bitauth/libauth/build/index.js';

await init();
const prove = qStarkProve(LOGN, LOG_BLOWUP, NUM_QUERIES);
const bundle = buildBundle(prove);
const states = evaluateBundle(bundle, true);
const measured = metrics(bundle, states);
if (!allAccepted(states)) throw new Error(`honest standard transaction rejected: ${measured.rows.map((r) => r.error ?? 'OK').join(' | ')}`);

console.log(JSON.stringify({
  deploymentStatus: 'research-fixture-not-production',
  parameters: { logn: LOGN, logBlowup: LOG_BLOWUP, n: 1 << LOGN, N: 1 << (LOGN + LOG_BLOWUP), queries: NUM_QUERIES },
  soundnessRegime: 'QM31 challenge path; five FRI queries; demonstrator, not 128-bit',
  scriptBytes: measured.scriptBytes,
  serializedTransactionBytes: measured.serializedTransactionBytes,
  maxUnlockingBytes: measured.maxUnlockingBytes,
  maxRedeemBytes: measured.maxRedeemBytes,
  maxOperationCost: measured.maxOperationCost,
  inputs: measured.rows,
}, null, 2));

// A compact, self-contained vector artifact containing the real P2SH scripts
// and transaction witnesses used by the standard-VM measurement.
const vectors = {
  deploymentStatus: 'research-fixture-not-production',
  parameters: { logn: LOGN, logBlowup: LOG_BLOWUP, queries: NUM_QUERIES },
  lockings: bundle.lockings.map(binToHex),
  unlockings: bundle.unlockings.map(binToHex),
  transaction: binToHex(bundle.serializedTransaction),
  metrics: measured,
};
writeFileSync(new URL('./vectors.json', import.meta.url), `${JSON.stringify(vectors, null, 2)}\n`);
console.error('wrote fri_stark55/vectors.json');

// Write the honest research vector before the strict crown assertion so an
// over-cap measurement cannot leave a stale lower-query artifact behind.  The
// command still fails closed below; emitting an over-cap research vector is
// evidence, not a release pass.
assertStandard(measured);
