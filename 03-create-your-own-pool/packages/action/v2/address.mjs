import { isSupportedDirectV2NetworkId } from './network.mjs';
import {
  validateDirectV2Address,
  DIRECT_V2_ADDRESS_SCHEMA,
} from './notes.mjs';

export const DIRECT_V2_ADDRESS_BYTES = 168;
export const DIRECT_V2_ADDRESS_OFFSETS = Object.freeze({
  magic: 0,
  networkId: 4,
  flags: 5,
  profileId: 8,
  instanceId: 40,
  spendPublicKey: 72,
  incomingViewPublicKey: 104,
  authority: 136,
  end: 168,
});

export class DirectV2AddressCodecError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2AddressCodecError';
  }
}

const fail = (message) => {
  throw new DirectV2AddressCodecError(message);
};

function exactBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(`${label} must contain exactly ${length} bytes`);
  }
  return Buffer.from(value);
}

function validated(value) {
  try {
    return validateDirectV2Address(value);
  } catch (error) {
    fail(`address is invalid: ${error.message}`);
  }
}

export function encodeDirectV2Address(value) {
  const address = validated(value);
  const bytes = Buffer.alloc(DIRECT_V2_ADDRESS_BYTES);
  Buffer.from('SKA2', 'ascii').copy(bytes, DIRECT_V2_ADDRESS_OFFSETS.magic);
  bytes[DIRECT_V2_ADDRESS_OFFSETS.networkId] = address.networkId;
  Buffer.from(address.profileId, 'hex').copy(bytes, DIRECT_V2_ADDRESS_OFFSETS.profileId);
  Buffer.from(address.instanceId, 'hex').copy(bytes, DIRECT_V2_ADDRESS_OFFSETS.instanceId);
  Buffer.from(address.spendPublicKey, 'hex').copy(bytes, DIRECT_V2_ADDRESS_OFFSETS.spendPublicKey);
  Buffer.from(address.incomingViewPublicKey, 'hex')
    .copy(bytes, DIRECT_V2_ADDRESS_OFFSETS.incomingViewPublicKey);
  Buffer.from(address.authority, 'hex').copy(bytes, DIRECT_V2_ADDRESS_OFFSETS.authority);
  return bytes;
}

export function decodeDirectV2Address(value) {
  const bytes = exactBytes(value, DIRECT_V2_ADDRESS_BYTES, 'V2 address');
  if (!bytes.subarray(0, 4).equals(Buffer.from('SKA2', 'ascii'))) {
    fail('address magic is invalid');
  }
  if (!isSupportedDirectV2NetworkId(bytes[DIRECT_V2_ADDRESS_OFFSETS.networkId])) {
    fail('address network is unsupported');
  }
  if (!bytes.subarray(5, 8).equals(Buffer.alloc(3))) {
    fail('address flags must be zero');
  }
  return validated({
    schema: DIRECT_V2_ADDRESS_SCHEMA,
    networkId: bytes[DIRECT_V2_ADDRESS_OFFSETS.networkId],
    profileId: bytes.subarray(8, 40).toString('hex'),
    instanceId: bytes.subarray(40, 72).toString('hex'),
    spendPublicKey: bytes.subarray(72, 104).toString('hex'),
    incomingViewPublicKey: bytes.subarray(104, 136).toString('hex'),
    authority: bytes.subarray(136, 168).toString('hex'),
  });
}
