export const STATE_NFT_COMMITMENT_BYTES = 80;
export const STATE_NFT_COMMITMENT_LIMIT_BYTES = 120;
export const STATE_NFT_VERSION = 1;
export const CHIPNET_NETWORK_ID = 2;

const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;

export class StateNftError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StateNftError';
  }
}

const fail = (message) => {
  throw new StateNftError(message);
};

function exactKeys(value, label, expected) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
}

function hex32(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return Buffer.from(value, 'hex');
}

function u64(value, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > MAX_U64) fail(`${label} exceeds u64`);
  return parsed;
}

export function encodeStateNftCommitment(value) {
  exactKeys(value, 'state NFT commitment', [
    'actionSequence',
    'instanceId',
    'networkId',
    'stateCommitment',
  ]);
  if (value.networkId !== CHIPNET_NETWORK_ID) {
    fail('state NFT network is unsupported');
  }
  const commitment = Buffer.alloc(STATE_NFT_COMMITMENT_BYTES);
  Buffer.from('SHST', 'ascii').copy(commitment, 0);
  commitment[4] = STATE_NFT_VERSION;
  commitment[5] = value.networkId;
  hex32(value.instanceId, 'instanceId').copy(commitment, 8);
  hex32(value.stateCommitment, 'stateCommitment').copy(commitment, 40);
  commitment.writeBigUInt64LE(u64(value.actionSequence, 'actionSequence'), 72);
  return commitment;
}

export function decodeStateNftCommitment(value) {
  if (!(value instanceof Uint8Array) || value.length !== STATE_NFT_COMMITMENT_BYTES) {
    fail(`state NFT commitment must contain exactly ${STATE_NFT_COMMITMENT_BYTES} bytes`);
  }
  const bytes = Buffer.from(value);
  if (!bytes.subarray(0, 4).equals(Buffer.from('SHST', 'ascii'))) {
    fail('state NFT commitment magic is invalid');
  }
  if (bytes[4] !== STATE_NFT_VERSION) {
    fail('state NFT commitment version is unsupported');
  }
  if (bytes[5] !== CHIPNET_NETWORK_ID) {
    fail('state NFT commitment network is unsupported');
  }
  if (bytes[6] !== 0 || bytes[7] !== 0) {
    fail('state NFT commitment reserved bytes must be zero');
  }
  return Object.freeze({
    networkId: bytes[5],
    instanceId: bytes.subarray(8, 40).toString('hex'),
    stateCommitment: bytes.subarray(40, 72).toString('hex'),
    actionSequence: bytes.readBigUInt64LE(72).toString(),
  });
}
