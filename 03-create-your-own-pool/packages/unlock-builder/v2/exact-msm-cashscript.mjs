import { createHash } from 'node:crypto';

import {
  BN254_BASE_FIELD,
  DIRECT_V2_MSM_WINDOWS,
  directV2VerificationKeyPoints,
} from './exact-msm.mjs';

const HEX_35 = /^[0-9a-f]{70}$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const HEX_BYTES = /^(?:[0-9a-f]{2})+$/;

export class DirectV2ExactMsmCashScriptError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2ExactMsmCashScriptError';
  }
}

const fail = (message) => {
  throw new DirectV2ExactMsmCashScriptError(message);
};

const sha256d = (value) => {
  const first = createHash('sha256').update(value).digest();
  return createHash('sha256').update(first).digest('hex');
};

const pointBranch = (point, enabled) => {
  if (point === null) return 'aX = 0; aY = 0; doAdd = 0;';
  return `aX = ${point.x}; aY = ${point.y}; doAdd = ${enabled};`;
};

const commonFunctions = (key) => {
  const p = BN254_BASE_FIELD;
  return `function addFp(int x, int y) returns (int) { return (x + y) % ${p}; }
function subFp(int x, int y) returns (int) { return (x - y + ${p}) % ${p}; }
function mulFp(int x, int y) returns (int) { return (x * y) % ${p}; }
function sqrFp(int x) returns (int) { return (x * x) % ${p}; }
function jacDouble(int x, int y, int z) returns (int, int, int) {
    int a = sqrFp(x); int b = sqrFp(y); int c = sqrFp(b);
    int d = mulFp(2, subFp(subFp(sqrFp(addFp(x, b)), a), c));
    int e = mulFp(3, a); int f = sqrFp(e);
    int nx = subFp(f, mulFp(2, d));
    int ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c));
    int nz = mulFp(2, mulFp(y, z));
    return nx, ny, nz;
}
function jacAdd(int aX, int aY, int aZ, int bX, int bY) returns (int, int, int) {
    int rx = bX; int ry = bY; int rz = 1;
    if (aZ != 0) {
        int z1z1 = sqrFp(aZ);
        int u1 = aX; int u2 = mulFp(bX, z1z1);
        int s1 = aY; int s2 = mulFp(mulFp(bY, aZ), z1z1);
        if (u1 == u2) {
            if (s1 == s2) {
                (int dx, int dy, int dz) = jacDouble(aX, aY, aZ);
                rx = dx; ry = dy; rz = dz;
            } else {
                rx = 0; ry = 1; rz = 0;
            }
        } else {
            int h = subFp(u2, u1); int i2 = sqrFp(mulFp(2, h));
            int jj = mulFp(h, i2); int rr = mulFp(2, subFp(s2, s1));
            int vv = mulFp(u1, i2);
            int nx = subFp(subFp(sqrFp(rr), jj), mulFp(2, vv));
            int ny = subFp(mulFp(rr, subFp(vv, nx)), mulFp(2, mulFp(s1, jj)));
            int nz = mulFp(subFp(subFp(sqrFp(addFp(aZ, h)), z1z1), sqrFp(h)), 1);
            rx = nx; ry = ny; rz = nz;
        }
    }
    return rx, ry, rz;
}
function selectPoint(int b0, int b1) returns (int, int, int) {
    int aX = 0; int aY = 0; int doAdd = 0;
    if (b0 == 1 && b1 == 1) { ${pointBranch(key.ic12, 1)} }
    else {
        if (b0 == 1) { ${pointBranch(key.ic1, 1)} }
        else { if (b1 == 1) { ${pointBranch(key.ic2, 1)} } }
    }
    return aX, aY, doAdd;
}`;
};

const parseState = () => `        require(state.length == 128);
        bytes rXb, bytes state1 = state.split(32);
        bytes rYb, bytes state2 = state1.split(32);
        bytes rZb, bytes state3 = state2.split(32);
        bytes in0b, bytes in1b = state3.split(16);
        require(in1b.length == 16);
        int rX = int(rXb.reverse() + 0x00);
        int rY = int(rYb.reverse() + 0x00);
        int rZ = int(rZb.reverse() + 0x00);
        int input0 = int(in0b.reverse() + 0x00);
        int input1 = int(in1b.reverse() + 0x00);
        require(rX >= 0 && rX < ${BN254_BASE_FIELD});
        require(rY >= 0 && rY < ${BN254_BASE_FIELD});
        require(rZ >= 0 && rZ < ${BN254_BASE_FIELD});
        require(
            (rZ == 0 && rX == 0 && rY == 1)
            || (
                rZ != 0
                && !(rX == 0 && rY == 1)
                && sqrFp(rY) == addFp(mulFp(mulFp(rX, rX), rX), mulFp(3, mulFp(sqrFp(rZ), sqrFp(sqrFp(rZ)))))
            )
        );`;

const projectionChecks = (packetInputIndex) => `        require(projectionSignalCarrier.length == 480);
        bytes projectionContext, bytes actionDigest = projectionSignalCarrier.split(448);
        require(actionDigest.length == 32);
        bytes actionDigestHi, bytes actionDigestLo = actionDigest.split(16);
        require(actionDigestLo.length == 16);
        require(int(actionDigestHi.reverse() + 0x00) == input0);
        require(int(actionDigestLo.reverse() + 0x00) == input1);
        bytes packetUnlock = tx.inputs[${packetInputIndex}].unlockingBytecode;
        require(packetUnlock.length > 555);
        bytes packetPush, bytes bindingRedeemPush = packetUnlock.split(555);
        require(bindingRedeemPush.length > 0);
        bytes packetPushHeader, bytes packet = packetPush.split(3);
        require(packetPushHeader == 0x4d2802);
        require(packet.length == 552);
        require(sha256(packet) == actionDigest);
        bytes context0, bytes contextAfter0 = projectionContext.split(128);
        require(context0.length == 128);
        bytes Qxb, bytes contextAfterQx = contextAfter0.split(32);
        bytes Qyb, bytes contextTail = contextAfterQx.split(32);
        require(contextTail.length == 256);`;

/**
 * Render one exact fixed-window MSM role. This component proves only the
 * public-input MSM and its sibling-carried state. It deliberately contains no
 * Miller-genesis body and therefore is not a complete PF11 verifier.
 */
export function renderDirectV2ExactMsmRole({
  verificationKey,
  windowIndex,
  inputIndex,
  successorInputIndex,
  successorLockingBytecodeHex,
  successorStatePayloadOffset,
  stateInputIndex = 12,
  stateCategoryHex,
  expectedInputCount = 14,
  packetInputIndex = 11,
  packetLockingBytecodeHex,
  fixedWidthZInverse = false,
  zeroPaddingBytes,
  densityCarrierBytes,
}) {
  if (
    !Number.isInteger(windowIndex)
    || windowIndex < 0
    || windowIndex >= DIRECT_V2_MSM_WINDOWS.length
  ) {
    fail('windowIndex must select one of the four fixed MSM windows');
  }
  for (const [value, label] of [
    [inputIndex, 'inputIndex'],
    [successorInputIndex, 'successorInputIndex'],
    [successorStatePayloadOffset, 'successorStatePayloadOffset'],
    [expectedInputCount, 'expectedInputCount'],
    [packetInputIndex, 'packetInputIndex'],
    [stateInputIndex, 'stateInputIndex'],
    [zeroPaddingBytes, 'zeroPaddingBytes'],
  ]) {
    if (!Number.isInteger(value) || value < 0) fail(`${label} must be a nonnegative integer`);
  }
  if (!HEX_35.test(successorLockingBytecodeHex)) {
    fail('successorLockingBytecodeHex must contain exactly 35 lowercase hexadecimal bytes');
  }
  if (
    typeof packetLockingBytecodeHex !== 'string'
    || !HEX_BYTES.test(packetLockingBytecodeHex)
    || packetLockingBytecodeHex.length > 20_000
  ) {
    fail('packetLockingBytecodeHex must contain 1 to 10000 lowercase hexadecimal bytes');
  }
  if (!HEX_32.test(stateCategoryHex)) {
    fail('stateCategoryHex must contain exactly 32 lowercase hexadecimal bytes');
  }
  if (zeroPaddingBytes < 256 || zeroPaddingBytes > 9_000) {
    fail('zeroPaddingBytes must be from 256 to 9000');
  }
  if (
    densityCarrierBytes !== undefined
    && (
      !(densityCarrierBytes instanceof Uint8Array)
      || densityCarrierBytes.length !== zeroPaddingBytes
    )
  ) {
    fail('densityCarrierBytes must match zeroPaddingBytes exactly');
  }
  if (typeof fixedWidthZInverse !== 'boolean') {
    fail('fixedWidthZInverse must be boolean');
  }
  const key = directV2VerificationKeyPoints(verificationKey);
  const window = DIRECT_V2_MSM_WINDOWS[windowIndex];
  const final = windowIndex === DIRECT_V2_MSM_WINDOWS.length - 1;
  if (!final && successorStatePayloadOffset < 2) {
    fail('non-final successorStatePayloadOffset must include the two-byte canonical state push header');
  }
  const paddingHash = sha256d(
    densityCarrierBytes ?? Buffer.alloc(zeroPaddingBytes),
  );
  const packetLockingBytecodeSha256 = createHash('sha256')
    .update(Buffer.from(packetLockingBytecodeHex, 'hex'))
    .digest('hex');
  const signature = final
    ? `bytes unused zeroPadding, ${fixedWidthZInverse ? 'bytes zInverseBE' : 'int zInverse'}, bytes state, bytes projectionSignalCarrier`
    : 'bytes unused zeroPadding, int zInverse, bytes state';
  const source = [];
  source.push('pragma cashscript ^0.14.0;');
  source.push(`// ShieldKit V2 Direct exact-MSM window [${window.start},${window.end}); component-only, final=${final}.`);
  source.push(commonFunctions(key));
  source.push('contract DirectV2ExactMsmRole() {');
  source.push(`    function spend(${signature}) {`);
  source.push(`        require(this.activeInputIndex == ${inputIndex});`);
  source.push(`        require(tx.inputs.length == ${expectedInputCount});`);
  source.push(`        require(tx.inputs[${inputIndex}].outpointIndex == ${inputIndex + 1});`);
  source.push(`        require(tx.inputs[${successorInputIndex}].outpointIndex == ${successorInputIndex + 1});`);
  source.push(`        require(tx.inputs[${stateInputIndex}].outpointIndex == 0);`);
  source.push(`        require(tx.inputs[${packetInputIndex}].outpointIndex == ${packetInputIndex + 1});`);
  source.push(`        require(tx.inputs[${inputIndex}].outpointTransactionHash == tx.inputs[${successorInputIndex}].outpointTransactionHash);`);
  source.push(`        require(tx.inputs[${inputIndex}].outpointTransactionHash == tx.inputs[${stateInputIndex}].outpointTransactionHash);`);
  source.push(`        require(tx.inputs[${inputIndex}].outpointTransactionHash == tx.inputs[${packetInputIndex}].outpointTransactionHash);`);
  source.push(`        require(tx.inputs[${successorInputIndex}].lockingBytecode == 0x${successorLockingBytecodeHex});`);
  source.push(`        require(sha256(tx.inputs[${packetInputIndex}].lockingBytecode) == 0x${packetLockingBytecodeSha256});`);
  source.push(`        require(tx.inputs[${stateInputIndex}].tokenCategory == 0x${stateCategoryHex}01);`);
  source.push(`        require(tx.inputs[${stateInputIndex}].nftCommitment.length == 128);`);
  source.push(`        require(tx.inputs[${stateInputIndex}].tokenAmount == 0);`);
  source.push(`        require(zeroPadding.length == ${zeroPaddingBytes});`);
  source.push(`        require(hash256(zeroPadding) == 0x${paddingHash});`);
  source.push(`        bytes ownUnlock = tx.inputs[${inputIndex}].unlockingBytecode;`);
  if (final) {
    source.push('        bytes ownProjectionHeader, bytes ownAfterProjectionHeader = ownUnlock.split(3);');
    source.push('        require(ownProjectionHeader == 0x4de001);');
    source.push('        bytes ownProjection, bytes ownAfterProjection = ownAfterProjectionHeader.split(480);');
    source.push('        require(ownProjection == projectionSignalCarrier);');
    source.push('        bytes ownStateHeader, bytes ownAfterStateHeader = ownAfterProjection.split(2);');
    source.push('        require(ownStateHeader == 0x4c80);');
    source.push('        bytes ownState, bytes ownAfterState = ownAfterStateHeader.split(128);');
    source.push('        require(ownState == state && ownAfterState.length > 0);');
  } else {
    source.push('        bytes ownStateHeader, bytes ownAfterStateHeader = ownUnlock.split(2);');
    source.push('        require(ownStateHeader == 0x4c80);');
    source.push('        bytes ownState, bytes ownAfterState = ownAfterStateHeader.split(128);');
    source.push('        require(ownState == state && ownAfterState.length > 0);');
  }
  source.push(parseState());
  if (windowIndex === 0) {
    source.push('        require(rX == 0 && rY == 1 && rZ == 0);');
  }
  source.push(`        for (int round = 0; round < ${window.end - window.start}; round = round + 1) {`);
  source.push(`            int bit = ${127 - window.start} - round;`);
  source.push('            if (rZ != 0) { (int dx, int dy, int dz) = jacDouble(rX, rY, rZ); rX = dx; rY = dy; rZ = dz; }');
  source.push('            int b0 = (input0 >> bit) % 2;');
  source.push('            int b1 = (input1 >> bit) % 2;');
  source.push('            (int aX, int aY, int doAdd) = selectPoint(b0, b1);');
  source.push('            if (doAdd == 1) { (int ax, int ay, int az) = jacAdd(rX, rY, rZ, aX, aY); rX = ax; rY = ay; rZ = az; }');
  source.push('        }');
  source.push('        if (rZ == 0) { rX = 0; rY = 1; }');
  if (!final) {
    source.push('        require(zInverse == 0);');
    source.push('        bytes nextState = toPaddedBytes(rX, 32).reverse() + toPaddedBytes(rY, 32).reverse() + toPaddedBytes(rZ, 32).reverse() + in0b + in1b;');
    source.push(`        bytes successorUnlock = tx.inputs[${successorInputIndex}].unlockingBytecode;`);
    source.push(`        bytes successorBeforeStateHeader, bytes successorFromStateHeader = successorUnlock.split(${successorStatePayloadOffset - 2});`);
    source.push('        bytes successorStateHeader, bytes successorAfterStateHeader = successorFromStateHeader.split(2);');
    source.push('        require(successorStateHeader == 0x4c80);');
    source.push(`        bytes successorPrefix, bytes successorTail = successorUnlock.split(${successorStatePayloadOffset});`);
    source.push('        bytes successorState, bytes successorRemainder = successorTail.split(128);');
    source.push(`        require(successorBeforeStateHeader.length == ${successorStatePayloadOffset - 2});`);
    source.push('        require(successorAfterStateHeader.length > 128);');
    source.push(`        require(successorPrefix.length == ${successorStatePayloadOffset});`);
    source.push('        require(successorRemainder.length > 0);');
    source.push('        require(successorState == nextState);');
  } else {
    if (key.ic0 !== null) {
      source.push(`        (int qx, int qy, int qz) = jacAdd(rX, rY, rZ, ${key.ic0.x}, ${key.ic0.y});`);
      source.push('        rX = qx; rY = qy; rZ = qz;');
    }
    if (fixedWidthZInverse) {
      source.push('        require(zInverseBE.length == 32);');
      source.push('        int zInverse = int(zInverseBE.reverse() + 0x00);');
    }
    source.push(`        require(zInverse >= 0 && zInverse < ${BN254_BASE_FIELD});`);
    source.push('        int Qx = 0; int Qy = 0;');
    source.push('        if (rZ == 0) { require(zInverse == 0); }');
    source.push('        else {');
    source.push('            require(mulFp(rZ, zInverse) == 1);');
    source.push('            int zInverse2 = sqrFp(zInverse);');
    source.push('            int zInverse3 = mulFp(zInverse2, zInverse);');
    source.push('            Qx = mulFp(rX, zInverse2);');
    source.push('            Qy = mulFp(rY, zInverse3);');
    source.push('            require(mulFp(Qy, Qy) == addFp(mulFp(mulFp(Qx, Qx), Qx), 3));');
    source.push('        }');
    source.push(projectionChecks(packetInputIndex));
    source.push('        require(int(Qxb) == Qx);');
    source.push('        require(int(Qyb) == Qy);');
  }
  source.push('    }');
  source.push('}');
  return `${source.join('\n')}\n`;
}
