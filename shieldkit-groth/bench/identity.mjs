/**
 * What this bench is measuring — product, version, design, verifier, network.
 * Embedded in every pipeline / cold-start report so results are self-describing.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { DESIGN_PF10_BASELINE } from './scorecard.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** On-chain / unlock path for the shipped PF10 product. */
export const VERIFIER_PF10 = 'DIRECT_V2_PF10';

/** Product family label (operator-facing). */
export const PRODUCT_NAME = 'ShieldKit-Groth';

/** CLI / envelope product id (matches live CLI `product` field). */
export const PRODUCT_ID = 'shieldkit-v2-beta-chipnet';

/** Network this beta product targets. */
export const NETWORK = 'chipnet';

function readPackageVersion() {
  try {
    const pkg = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    if (typeof pkg.version === 'string' && pkg.version.length > 0) return pkg.version;
  } catch {
    // fall through
  }
  return 'unknown';
}

/**
 * Stable subject block for scorecards and tables.
 * @param {{ design?: string, commit?: string|null, network?: string }} [opts]
 */
export function resolveBenchSubject({
  design = DESIGN_PF10_BASELINE,
  commit = null,
  network = NETWORK,
} = {}) {
  return Object.freeze({
    product: PRODUCT_NAME,
    productId: PRODUCT_ID,
    version: readPackageVersion(),
    design: typeof design === 'string' && design.length > 0 ? design : DESIGN_PF10_BASELINE,
    verifier: VERIFIER_PF10,
    verifierLabel: 'PF10 Groth16 (BN254) on-chain unlock',
    network: typeof network === 'string' && network.length > 0 ? network : NETWORK,
    commit: typeof commit === 'string' && commit.length > 0 ? commit : null,
  });
}

/** One-line header for human tables. */
export function formatSubjectHeader(subject) {
  const s = subject && typeof subject === 'object' ? subject : resolveBenchSubject();
  const commit = s.commit ?? 'n/a';
  return [
    `${s.product} ${s.version}  (${s.productId})`,
    `design=${s.design}  verifier=${s.verifier}  (${s.verifierLabel})  network=${s.network}`,
    `commit=${commit}`,
  ].join('\n');
}
