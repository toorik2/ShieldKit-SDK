/**
 * SFC1 — transaction-context serialization for state@0 bind.
 * Normative layout: FRI_STARK_REPLACEMENT_PLAN.md (product fixed-topology profile).
 *
 * Product topology: input/output 0 = state NFT; 1..roleCount = tokenless role carriers;
 * optional funding input last. Unlocking bytecodes excluded (no proof/fee circularity).
 */
import { createHash } from 'node:crypto';

export const SFC1_MAGIC = Buffer.from('SFC1');
export const SFC1_VERSION = 1;

function u8(n) {
  return Buffer.from([Number(n) & 0xff]);
}
function u16le(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(Number(n) >>> 0, 0);
  return b;
}
function u32le(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(Number(n) >>> 0, 0);
  return b;
}
function u64le(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n), 0);
  return b;
}
function hex32(h, label = 'hex32') {
  if (typeof h !== 'string' || !/^[0-9a-f]{64}$/i.test(h)) {
    throw new Error(`bad 32-byte hex ${label}`);
  }
  return Buffer.from(h.toLowerCase(), 'hex');
}

/**
 * Canonical CashTokens data for a mutable NFT with 128-byte commitment (no fungible amount).
 * bitfield: hasAmount=0, hasNFT=1, hasCommitment=1, capability=mutable(01) → simplified product form:
 * category(32) || capability(1) || commitmentLen(1)=128 || commitment(128)
 * (Matches what OP_UTXOTOKENCATEGORY / COMMITMENT expose for continuity checks.)
 */
export function encodeStateTokenData({ categoryHex, commitmentHex, capability = 0x01 }) {
  const cat = hex32(categoryHex, 'category');
  const commit = Buffer.from(commitmentHex, 'hex');
  if (commit.length !== 128) throw new Error('state commitment must be 128 bytes');
  return Buffer.concat([cat, Buffer.from([capability & 0xff, 128]), commit]);
}

/**
 * @param {object} model
 * @param {number} model.networkId
 * @param {number} model.action - 1 deposit, 2 transfer, 3 withdraw
 * @param {number} model.txVersion
 * @param {number} model.locktime
 * @param {Array<{role:number, outpointTxidHex:string, outpointIndex:number, sequence:number, valueSats:bigint|number|string, lockingBytecodeHex:string, tokenDataHex?:string}>} model.inputs
 * @param {Array<{role:number, valueSats:bigint|number|string, lockingBytecodeHex:string, tokenDataHex?:string}>} model.outputs
 */
export function encodeSfc1(model) {
  const networkId = Number(model.networkId);
  const action = Number(model.action);
  const flags = 0;
  if (![1, 2].includes(networkId)) throw new Error('bad networkId');
  if (![1, 2, 3].includes(action)) throw new Error('bad action');
  const inputs = model.inputs || [];
  const outputs = model.outputs || [];
  if (inputs.length < 1 || inputs.length > 40) throw new Error('bad inputCount');
  if (outputs.length < 1 || outputs.length > 40) throw new Error('bad outputCount');

  const parts = [
    SFC1_MAGIC,
    u8(networkId),
    u8(SFC1_VERSION),
    u8(action),
    u8(flags),
    u32le(model.txVersion ?? 2),
    u32le(model.locktime ?? 0),
    u8(inputs.length),
  ];
  for (const inp of inputs) {
    const lock = Buffer.from(inp.lockingBytecodeHex, 'hex');
    const lockHash = createHash('sha256').update(lock).digest();
    const token = inp.tokenDataHex
      ? Buffer.from(inp.tokenDataHex, 'hex')
      : Buffer.alloc(0);
    parts.push(
      u8(inp.role),
      hex32(inp.outpointTxidHex, 'outpointTxid'),
      u32le(inp.outpointIndex),
      u32le(inp.sequence ?? 0xffffffff),
      u64le(inp.valueSats),
      lockHash,
      u16le(token.length),
      token,
    );
  }
  parts.push(u8(outputs.length));
  for (const out of outputs) {
    const lock = Buffer.from(out.lockingBytecodeHex, 'hex');
    const lockHash = createHash('sha256').update(lock).digest();
    const token = out.tokenDataHex
      ? Buffer.from(out.tokenDataHex, 'hex')
      : Buffer.alloc(0);
    parts.push(
      u8(out.role),
      u64le(out.valueSats),
      u16le(lock.length + token.length),
      // product: token prefix bytes (if any) then locking bytecode — length is total serialized output body
      token,
      lock,
    );
  }
  return Buffer.concat(parts);
}

export function hashSfc1(modelOrBytes) {
  const buf = Buffer.isBuffer(modelOrBytes) ? modelOrBytes : encodeSfc1(modelOrBytes);
  return createHash('sha256').update(buf).digest();
}

export function hashSfc1Hex(modelOrBytes) {
  return hashSfc1(modelOrBytes).toString('hex');
}

/**
 * Build SFC1 model for product pool action topology from Libauth-style tx pieces.
 */
export function sfc1ModelFromProductTx({
  networkId = 2,
  action,
  txVersion = 2,
  locktime = 0,
  categoryHex,
  preCommitmentHex,
  postCommitmentHex,
  stateLockingHex,
  roleLockingHexes,
  stateValueIn,
  stateValueOut,
  roleValue = 1000n,
  funding = null,
}) {
  const roles = roleLockingHexes || [];
  const roleCount = roles.length;
  const stateTokenIn = encodeStateTokenData({
    categoryHex,
    commitmentHex: preCommitmentHex,
  }).toString('hex');
  const stateTokenOut = encodeStateTokenData({
    categoryHex,
    commitmentHex: postCommitmentHex,
  }).toString('hex');
  const z32 = '00'.repeat(32);
  const inputs = [
    {
      role: 0,
      outpointTxidHex: z32,
      outpointIndex: 0,
      sequence: 0xffffffff,
      valueSats: stateValueIn,
      lockingBytecodeHex: stateLockingHex,
      tokenDataHex: stateTokenIn,
    },
  ];
  for (let i = 0; i < roleCount; i += 1) {
    inputs.push({
      role: i + 1,
      outpointTxidHex: z32,
      outpointIndex: i + 1,
      sequence: 0xffffffff,
      valueSats: roleValue,
      lockingBytecodeHex: roles[i],
    });
  }
  if (funding) {
    inputs.push({
      role: 255,
      outpointTxidHex: funding.outpointTxidHex || z32,
      outpointIndex: funding.outpointIndex ?? 0,
      sequence: 0xffffffff,
      valueSats: funding.valueSats,
      lockingBytecodeHex: funding.lockingBytecodeHex,
    });
  }
  const outputs = [
    {
      role: 0,
      valueSats: stateValueOut,
      lockingBytecodeHex: stateLockingHex,
      tokenDataHex: stateTokenOut,
    },
  ];
  for (let i = 0; i < roleCount; i += 1) {
    outputs.push({
      role: i + 1,
      valueSats: roleValue,
      lockingBytecodeHex: roles[i],
    });
  }
  return {
    networkId,
    action,
    txVersion,
    locktime,
    inputs,
    outputs,
  };
}
