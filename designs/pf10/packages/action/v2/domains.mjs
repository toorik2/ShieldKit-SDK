import { createHash } from 'node:crypto';

export const BN254_SCALAR_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const DOMAIN_DERIVATION_PREFIX =
  'ShieldKit/PoolActionV2Direct/domain/v1/';

const definitions = [
  ['ADDRESS', 3, '174c18c76e6b8e7e9035476f0419293d25aabb87220e613924e58345d11914df'],
  ['RHO', 0, '0d166c9d3f0e891e85bb4a502a6ec7303938d7bfc56f1b6e6e443fa8793f8a82'],
  ['NOTE', 1, '194fd66837e146a0a8dddfcc309eb8bc1a51deb31924e089b8960ae102c7c349'],
  ['NULLIFIER', 1, '23358847ffca5391ad471ef321c12099073bff6145a867d14700e8e976377460'],
  ['RECORD_MASK_RHO', 1, '0ddef22b3c03788145c0aed1bfba5a211f13466c813c0a5d9ed2e92ab173f966'],
  ['RECORD_MASK_R', 3, '1af24bc8a85aa4b05369756d4f60843ff6dc26f886999d215ed61e38a4ae2db0'],
  ['RECORD_TAG', 2, '03db9f4bbae24de0b96466001641dc5753651feaa55a8541ededbcaf2bb2da7e'],
  ['NOTE_LEAF', 1, '0765f493bd374585f9ab5c4a1efe55f4d400a1bc1c876506ef8c7644145f370a'],
  ['NOTE_TREE_EMPTY', 9, '28fda61e6a38f74d91d7d8c4e279ba8e7b437a707948b9476bcfd650f5a60dad'],
  ['NOTE_TREE_NODE', 9, '06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153'],
  ['NULLIFIER_TREE_LEAF', 5, '21e0792dda012608a23ccef2acfb69f6a5d8ea940de6399bdd1094d68e4ffce2'],
  ['NULLIFIER_TREE_EMPTY', 3, '2633488611f1ffb2708b6ebb8994794c45c27f56b5d0d87d67a841123e3f0acb'],
  ['NULLIFIER_TREE_NODE', 0, '241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4'],
];

export const V2_DOMAIN_SEPARATORS = Object.freeze(Object.fromEntries(
  definitions.map(([name, counter, hex]) => [
    name,
    Object.freeze({
      counter,
      hex,
      value: BigInt(`0x${hex}`),
    }),
  ]),
));

export class V2DomainError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2DomainError';
  }
}

export function deriveV2DomainSeparator(label) {
  if (typeof label !== 'string' || !/^[A-Z][A-Z0-9_]*$/.test(label)) {
    throw new V2DomainError('domain label must be canonical uppercase ASCII');
  }
  for (let counter = 0; counter <= 0xffff_ffff; counter += 1) {
    const encodedCounter = Buffer.alloc(4);
    encodedCounter.writeUInt32BE(counter);
    const digest = createHash('sha256')
      .update(DOMAIN_DERIVATION_PREFIX, 'ascii')
      .update(label, 'ascii')
      .update(encodedCounter)
      .digest();
    const value = BigInt(`0x${digest.toString('hex')}`);
    if (value > 0n && value < BN254_SCALAR_FIELD_MODULUS) {
      return Object.freeze({
        counter,
        hex: digest.toString('hex'),
        value,
      });
    }
  }
  throw new V2DomainError('domain derivation exhausted u32 counter space');
}

export function verifyPinnedV2DomainSeparators() {
  const seen = new Set();
  for (const [label, expected] of Object.entries(V2_DOMAIN_SEPARATORS)) {
    const derived = deriveV2DomainSeparator(label);
    if (
      derived.counter !== expected.counter
      || derived.hex !== expected.hex
      || derived.value !== expected.value
    ) {
      throw new V2DomainError(`pinned ${label} domain separator does not match derivation`);
    }
    if (seen.has(derived.hex)) {
      throw new V2DomainError(`duplicate V2 domain separator: ${label}`);
    }
    seen.add(derived.hex);
  }
  return true;
}
