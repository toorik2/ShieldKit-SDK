// Canonical, local-only G2 transaction-context commitment encoder. It neither
// creates unlocks/proofs/signatures nor constructs, broadcasts, or submits BCH.
import { createHash } from 'node:crypto';
import { encodeTokenPrefix } from '@bitauth/libauth';

export const INPUT_ROLES = Object.freeze(['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal', 'binding', 'state', 'fee']);
const kindCodes = Object.freeze({ deposit: 1, transfer: 2, withdrawal: 3 });
const outputRoles = Object.freeze({ state: 0, change: 1, withdrawal: 2 });
const maxU32 = 0xffffffffn;
const maxU64 = 0xffffffffffffffffn;
const maxTokenAmount = 9223372036854775807n;
const hex = /^[0-9a-f]*$/;

export class SettlementContextError extends Error { constructor(message) { super(message); this.name = 'SettlementContextError'; } }
const fail = message => { throw new SettlementContextError(message); };
const exactKeys = (value, label, expected) => { if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`); const actual = Object.keys(value).sort(), wanted = [...expected].sort(); if (actual.length !== wanted.length || actual.some((key, i) => key !== wanted[i])) fail(`${label} has missing or unknown properties`); };
const decimal = (value, maximum, label) => { if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) fail(`${label} must be a canonical unsigned decimal string`); const parsed = BigInt(value); if (parsed > maximum) fail(`${label} exceeds its range`); return parsed; };
const hexBytes = (value, length, label) => { if (typeof value !== 'string' || !hex.test(value) || value.length % 2 !== 0 || (length !== undefined && value.length !== length * 2)) fail(`${label} must be canonical lowercase hexadecimal`); return Uint8Array.from(Buffer.from(value, 'hex')); };
const u16le = value => { const out = Buffer.alloc(2); out.writeUInt16LE(value); return out; };
const u32le = value => { const out = Buffer.alloc(4); out.writeUInt32LE(Number(value)); return out; };
const u64le = value => { const out = Buffer.alloc(8); out.writeBigUInt64LE(value); return out; };
const sha256 = bytes => createHash('sha256').update(bytes).digest();
const hashHex = bytes => sha256(bytes).toString('hex');

function parseToken(value, label) {
  if (value === null) return undefined;
  exactKeys(value, label, ['amount', 'category', 'nft']);
  const amount = decimal(value.amount, maxTokenAmount, `${label}.amount`);
  const category = hexBytes(value.category, 32, `${label}.category`);
  let nft;
  if (value.nft !== null) {
    exactKeys(value.nft, `${label}.nft`, ['capability', 'commitment']);
    if (!['none', 'mutable', 'minting'].includes(value.nft.capability)) fail(`${label}.nft.capability is invalid`);
    const commitment = hexBytes(value.nft.commitment, undefined, `${label}.nft.commitment`);
    if (commitment.length > 128) fail(`${label}.nft.commitment exceeds BCH-2026 consensus limit`);
    nft = { capability: value.nft.capability, commitment };
  }
  if (amount === 0n && nft === undefined) fail(`${label} must use null for no-token`);
  return { amount, category, ...(nft === undefined ? {} : { nft }) };
}

function parseOutput(value, label) {
  exactKeys(value, label, ['lockingBytecode', 'token', 'valueSatoshis']);
  return { valueSatoshis: decimal(value.valueSatoshis, maxU64, `${label}.valueSatoshis`), lockingBytecode: hexBytes(value.lockingBytecode, undefined, `${label}.lockingBytecode`), token: parseToken(value.token, `${label}.token`) };
}

function parseInput(value, label) {
  exactKeys(value, label, ['outpointIndex', 'outpointTransactionHashWire', 'sequenceNumber']);
  return { outpointTransactionHashWire: hexBytes(value.outpointTransactionHashWire, 32, `${label}.outpointTransactionHashWire`), outpointIndex: decimal(value.outpointIndex, maxU32, `${label}.outpointIndex`), sequenceNumber: decimal(value.sequenceNumber, maxU32, `${label}.sequenceNumber`) };
}

function expectedOutputRoles(kind) { return kind === 'withdrawal' ? [outputRoles.state, outputRoles.withdrawal, outputRoles.change] : [outputRoles.state, outputRoles.change]; }

function parseMaterials(value) {
  exactKeys(value, 'materials', ['instanceId', 'kind', 'profileId', 'sourceOutputs', 'transaction']);
  if (!(value.kind in kindCodes)) fail('kind is invalid');
  const profileId = hexBytes(value.profileId, 32, 'profileId'); const instanceId = hexBytes(value.instanceId, 32, 'instanceId');
  exactKeys(value.transaction, 'transaction', ['inputs', 'locktime', 'outputs', 'version']);
  const version = decimal(value.transaction.version, maxU32, 'transaction.version'); const locktime = decimal(value.transaction.locktime, maxU32, 'transaction.locktime');
  if (version !== 2n || locktime !== 0n) fail('transaction must use version 2 and locktime 0');
  if (!Array.isArray(value.transaction.inputs) || value.transaction.inputs.length !== INPUT_ROLES.length) fail('transaction must contain exactly the ten ordered inputs');
  if (!Array.isArray(value.sourceOutputs) || value.sourceOutputs.length !== INPUT_ROLES.length) fail('sourceOutputs must contain exactly ten entries');
  const inputs = value.transaction.inputs.map((input, index) => { const parsed = parseInput(input, `transaction.inputs[${index}]`); if (parsed.sequenceNumber !== 0n) fail(`transaction.inputs[${index}].sequenceNumber must be 0`); return parsed; });
  const roles = expectedOutputRoles(value.kind);
  if (!Array.isArray(value.transaction.outputs) || value.transaction.outputs.length !== roles.length) fail(`${value.kind} requires exactly ${roles.length} canonical outputs`);
  return { kind: value.kind, profileId, instanceId, version, locktime, inputs, sourceOutputs: value.sourceOutputs.map((output, index) => parseOutput(output, `sourceOutputs[${index}]`)), outputs: value.transaction.outputs.map((output, index) => parseOutput(output, `transaction.outputs[${index}]`)), roles };
}

/** Return exact CashTokens prefix bytes; no-token is explicitly the empty prefix. */
export function canonicalTokenPrefix(token) { return Uint8Array.from(encodeTokenPrefix(token)); }

export function encodeSettlementContext(materials) {
  const parsed = parseMaterials(materials);
  const fields = [Buffer.from('SCCT'), Buffer.of(1, 2, kindCodes[parsed.kind], 0), Buffer.from(parsed.profileId), Buffer.from(parsed.instanceId), u16le(INPUT_ROLES.length), u16le(parsed.outputs.length)];
  for (let index = 0; index < INPUT_ROLES.length; index += 1) {
    const input = parsed.inputs[index], source = parsed.sourceOutputs[index];
    fields.push(Buffer.of(index), Buffer.from(input.outpointTransactionHashWire), u32le(input.outpointIndex), u32le(input.sequenceNumber), u64le(source.valueSatoshis), sha256(source.lockingBytecode), sha256(canonicalTokenPrefix(source.token)));
  }
  for (let index = 0; index < parsed.outputs.length; index += 1) {
    const output = parsed.outputs[index];
    fields.push(Buffer.of(parsed.roles[index]), u64le(output.valueSatoshis), sha256(output.lockingBytecode), sha256(canonicalTokenPrefix(output.token)));
  }
  const preimage = Buffer.concat(fields); const expectedLength = parsed.kind === 'withdrawal' ? 1425 : 1352;
  if (preimage.length !== expectedLength) fail(`internal context length ${preimage.length} != ${expectedLength}`);
  const digest = sha256(preimage);
  return Object.freeze({ schema: 'shield.cash/settlement-context/v1', kind: parsed.kind, inputRoles: INPUT_ROLES, outputRoles: Object.freeze([...parsed.roles]), preimage, preimageHex: preimage.toString('hex'), digestHex: digest.toString('hex'), publicInputLimbs: Object.freeze([BigInt(`0x${digest.subarray(0, 16).toString('hex')}`).toString(), BigInt(`0x${digest.subarray(16, 32).toString('hex')}`).toString()]) });
}

/** Recompute from raw transaction/source outputs; expected hashes cannot bypass derivation. */
export function validateSettlementContext(expected, materials) {
  exactKeys(expected, 'expected context', ['digestHex', 'preimageHex', 'publicInputLimbs']);
  const actual = encodeSettlementContext(materials);
  if (expected.preimageHex !== actual.preimageHex || expected.digestHex !== actual.digestHex || !Array.isArray(expected.publicInputLimbs) || expected.publicInputLimbs.length !== 2 || expected.publicInputLimbs.some((limb, index) => limb !== actual.publicInputLimbs[index])) fail('expected context does not match transaction and source outputs');
  return actual;
}
