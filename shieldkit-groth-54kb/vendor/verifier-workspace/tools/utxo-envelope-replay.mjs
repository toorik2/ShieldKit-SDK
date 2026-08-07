// Concrete UTXO-envelope replay for the c7 BN254 candidate.
// The verifier sourceOutputs used below are resolved from a serialized parent tx
// referenced by every spending outpoint. No detached source-output array is used
// as VM input after the byte-exact parent-output equality check.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  binToHex,
  decodeTransactionBch,
  decodeTransactionOutputs,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  encodeTransaction,
  encodeTransactionOutputs,
  hash256,
  hexToBin,
  createVirtualMachineBch2026,
  verifyTransactionTokens,
} from '@bitauth/libauth';

const ROOT = process.env.ROOT || '/tmp/verifier-cash-81665-repair-build-3';
const OUT = process.env.OUT || '/tmp/verifier-cash-81665-parent-envelope';
const LEAN_ROOT = process.env.LEANBCH_ROOT || new URL('../LeanBCH/', import.meta.url).pathname.replace(/\/$/, '');
const XCHECK = `${LEAN_ROOT}/.lake/build/bin/xcheck_idxN`;
const VMBCONF = `${LEAN_ROOT}/.lake/build/bin/vmbconf`;
mkdirSync(OUT, { recursive: true });

const readHex = (path) => hexToBin(readFileSync(path, 'utf8').trim());
const bytes = (x) => Uint8Array.from(x);
const copyBytes = (x) => bytes(x);
const copyOutput = (o) => ({
  ...o,
  lockingBytecode: copyBytes(o.lockingBytecode),
  ...(o.token ? {
    token: {
      ...o.token,
      category: copyBytes(o.token.category),
      ...(o.token.nft ? { nft: { ...o.token.nft, commitment: copyBytes(o.token.nft.commitment) } } : {}),
    },
  } : {}),
});
const copyTx = (tx) => ({
  ...tx,
  inputs: tx.inputs.map((i) => ({
    ...i,
    outpointTransactionHash: copyBytes(i.outpointTransactionHash),
    unlockingBytecode: copyBytes(i.unlockingBytecode),
  })),
  outputs: tx.outputs.map(copyOutput),
});
const accept = (state) => state.error === undefined
  && state.stack.length === 1
  && state.stack[0]?.length === 1
  && state.stack[0][0] === 1;
const digest = (hex) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const sum = (xs) => xs.reduce((n, x) => n + BigInt(x.valueSatoshis), 0n);

const candidateTx = decodeTransactionBch(readHex(`${ROOT}/c7_candidate_tx.hex`));
const candidateSourceOutputs = decodeTransactionOutputs(readHex(`${ROOT}/c7_candidate_srcouts.hex`));
if (typeof candidateTx === 'string' || typeof candidateSourceOutputs === 'string') {
  throw new Error('candidate wire decode failed');
}
if (candidateTx.inputs.length !== 10 || candidateSourceOutputs.length !== 10) {
  throw new Error(`expected 10x10 candidate topology; got inputs=${candidateTx.inputs.length} sourceOutputs=${candidateSourceOutputs.length}`);
}

// Parent funding fixture: a nonzero external outpoint and a valid P2SH32 redeem
// path. It funds the exact candidate source-output sum plus a relay-fee margin.
// This fixture is only the antecedent transaction context; it is not verifier data.
const fundingRedeem = bytes([0x51]);
const parentFeeSatoshis = BigInt(process.env.PARENT_FEE_SATS ?? '1508');
if (parentFeeSatoshis < 0n) throw new Error('PARENT_FEE_SATS must be nonnegative');
const fundingSource = {
  lockingBytecode: encodeLockingBytecodeP2sh32(hash256(fundingRedeem)),
  valueSatoshis: sum(candidateSourceOutputs) + parentFeeSatoshis,
};
const parentTx = {
  version: 2,
  inputs: [{
    outpointTransactionHash: bytes(new Uint8Array(32).fill(0x55)),
    outpointIndex: 0,
    sequenceNumber: 0xffffffff,
    unlockingBytecode: encodeDataPush(fundingRedeem),
  }],
  outputs: candidateSourceOutputs.map(copyOutput),
  locktime: 0,
};
const parentWire = encodeTransaction(parentTx);
const parentHash = hash256(parentWire);
const parentOutputsWire = encodeTransactionOutputs(parentTx.outputs);
const candidateOutputsWire = encodeTransactionOutputs(candidateSourceOutputs);
if (binToHex(parentOutputsWire) !== binToHex(candidateOutputsWire)) {
  throw new Error('parent outputs are not byte-identical to candidate source outputs');
}

// The spending wire now contains actual outpoints: one parent tx hash, indices 0..9.
const spendTx = copyTx(candidateTx);
spendTx.inputs = spendTx.inputs.map((input, index) => ({
  ...input,
  outpointTransactionHash: copyBytes(parentHash),
  outpointIndex: index,
}));
const utxoSet = new Map([[binToHex(parentHash), parentTx.outputs]]);
const resolvedSourceOutputs = spendTx.inputs.map((input, index) => {
  const parentOutputs = utxoSet.get(binToHex(input.outpointTransactionHash));
  const output = parentOutputs?.[input.outpointIndex];
  if (!output) throw new Error(`unresolved UTXO input[${index}] ${binToHex(input.outpointTransactionHash)}:${input.outpointIndex}`);
  return output;
});
if (binToHex(encodeTransactionOutputs(resolvedSourceOutputs)) !== binToHex(parentOutputsWire)) {
  throw new Error('resolved UTXO outputs changed during source resolution');
}

const spendWire = encodeTransaction(spendTx);
const resolvedWire = encodeTransactionOutputs(resolvedSourceOutputs);
writeFileSync(`${OUT}/funding_srcout.hex`, binToHex(encodeTransactionOutputs([fundingSource])));
writeFileSync(`${OUT}/parent_tx.hex`, binToHex(parentWire));
writeFileSync(`${OUT}/parent_srcouts.hex`, binToHex(encodeTransactionOutputs([fundingSource])));
writeFileSync(`${OUT}/spend_tx.hex`, binToHex(spendWire));
writeFileSync(`${OUT}/spend_srcouts.hex`, binToHex(resolvedWire));

const consensusVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);
const verifyWholeTx = (vm, transaction, sourceOutputs) => {
  const verdict = vm.verify({ transaction, sourceOutputs });
  return { accept: verdict === true, error: verdict === true ? '' : String(verdict) };
};
const evalOne = (vm, tx, sourceOutputs, inputIndex) => {
  const state = vm.evaluate({ inputIndex, sourceOutputs, transaction: tx });
  return {
    accept: accept(state),
    error: state.error ?? '',
    opCost: state.metrics.operationCost,
    instructions: state.metrics.evaluatedInstructionCount,
  };
};
const parentConsensus = evalOne(consensusVm, parentTx, [fundingSource], 0);
const parentStandard = evalOne(standardVm, parentTx, [fundingSource], 0);
const parentConsensusWholeTx = verifyWholeTx(consensusVm, parentTx, [fundingSource]);
const parentStandardWholeTx = verifyWholeTx(standardVm, parentTx, [fundingSource]);
const parentTokenValid = verifyTransactionTokens(parentTx, [fundingSource], { maximumTokenCommitmentLength: 128 }) === true;
const spendConsensus = spendTx.inputs.map((_, i) => evalOne(consensusVm, spendTx, resolvedSourceOutputs, i));
const spendStandard = spendTx.inputs.map((_, i) => evalOne(standardVm, spendTx, resolvedSourceOutputs, i));
const spendConsensusWholeTx = verifyWholeTx(consensusVm, spendTx, resolvedSourceOutputs);
const spendStandardWholeTx = verifyWholeTx(standardVm, spendTx, resolvedSourceOutputs);
const spendTokenValid = verifyTransactionTokens(spendTx, resolvedSourceOutputs, { maximumTokenCommitmentLength: 128 }) === true;
const spendMonetaryValid = spendTx.inputs.length === resolvedSourceOutputs.length
  && sum(spendTx.outputs) <= sum(resolvedSourceOutputs);
const parentMonetaryValid = parentTx.inputs.length === 1
  && parentTx.outputs.length === 10
  && sum(parentTx.outputs) <= sum([fundingSource]);

const parseXcheck = (raw) => {
  const m = raw.match(/IDX=(\d+) leanVerifyInput=(true|false) txValid=(true|false) verifyTokens=(true|false) leanStandard=(true|false)/)
    || raw.match(/IDX=(\d+) leanVerifyInput=(true|false).*?txValid=(true|false).*?verifyTokens=(true|false).*?leanFullOpCost=(\d+)/);
  if (!m) return { raw: raw.slice(-500), parsed: false };
  return {
    raw: raw.slice(-500),
    parsed: true,
    index: Number(m[1]),
    accept: m[2] === 'true',
    txValid: m[3] === 'true',
    tokenValid: m[4] === 'true',
    ...(m[5] && /^\d+$/.test(m[5]) ? { leanOpCost: Number(m[5]) } : {}),
  };
};
const xcheck = [];
for (let i = 0; i < spendTx.inputs.length; i++) {
  const p = spawnSync(XCHECK, [`${OUT}/spend`, String(i)], {
    cwd: LEAN_ROOT,
    encoding: 'utf8',
    timeout: 180000,
    maxBuffer: 1000000,
  });
  xcheck.push({ index: i, exit: p.status, ...parseXcheck(`${p.stdout ?? ''}${p.stderr ?? ''}`.trim()) });
}
const parentX = spawnSync(XCHECK, [`${OUT}/parent`, '0'], {
  cwd: LEAN_ROOT,
  encoding: 'utf8',
  timeout: 180000,
  maxBuffer: 1000000,
});
const parentXcheck = { exit: parentX.status, ...parseXcheck(`${parentX.stdout ?? ''}${parentX.stderr ?? ''}`.trim()) };
const parentOpCostParity = parentXcheck.parsed && parentXcheck.leanOpCost === parentConsensus.opCost;

const vmbLines = [
  `1 parent ${binToHex(parentWire)} ${binToHex(encodeTransactionOutputs([fundingSource]))} 0`,
  ...Array.from({ length: 10 }, (_, i) => `1 spend-${i} ${binToHex(spendWire)} ${binToHex(resolvedWire)} ${i}`),
].join('\n');
const vmb = spawnSync(VMBCONF, [], {
  cwd: LEAN_ROOT,
  input: `${vmbLines}\n`,
  encoding: 'utf8',
  timeout: 300000,
  maxBuffer: 1000000,
});
const vmbRaw = `${vmb.stdout ?? ''}${vmb.stderr ?? ''}`.trim();
const vmbMatch = vmbRaw.match(/PASS (\d+) \/ (\d+)[\s\S]*?REJECTED-VALID (\d+):[\s\S]*?ACCEPTED-INVALID (\d+):[\s\S]*?STD-TRUE (\d+) STD-FALSE (\d+)/);
const vmbconf = vmbMatch ? {
  pass: Number(vmbMatch[1]), total: Number(vmbMatch[2]),
  rejectedValid: Number(vmbMatch[3]), acceptedInvalid: Number(vmbMatch[4]),
  standardTrue: Number(vmbMatch[5]), standardFalse: Number(vmbMatch[6]),
  raw: vmbRaw,
} : { parsed: false, raw: vmbRaw };
const spendOpCostParity = xcheck.length === spendConsensus.length
  && xcheck.every((x, i) => x.parsed && x.leanOpCost === spendConsensus[i].opCost);

const manifest = {
  schema: 'verifier.cash/utxo-envelope-replay/v1',
  generatedAt: new Date().toISOString(),
  candidateRoot: ROOT,
  candidateWire: {
    txSha256: digest(binToHex(encodeTransaction(candidateTx))),
    sourceOutputsSha256: digest(binToHex(candidateOutputsWire)),
  },
  parent: {
    txSha256: digest(binToHex(parentWire)),
    internalTxid: binToHex(parentHash),
    inputOutpoint: `${binToHex(parentTx.inputs[0].outpointTransactionHash)}:0`,
    outputCount: parentTx.outputs.length,
    outputValues: parentTx.outputs.map((o) => String(o.valueSatoshis)),
    wireBytes: parentWire.length,
    sourceResolution: 'spend outpoints -> parent txid map -> parent outputs; no detached source array',
    outputWireExact: true,
    monetaryValid: parentMonetaryValid,
    consensus: parentConsensus,
    standard: parentStandard,
    consensusWholeTx: parentConsensusWholeTx,
    standardWholeTx: parentStandardWholeTx,
    tokenValid: parentTokenValid,
    lean: parentXcheck,
  },
  spend: {
    txSha256: digest(binToHex(spendWire)),
    sourceOutputsSha256: digest(binToHex(resolvedWire)),
    inputCount: spendTx.inputs.length,
    outpointParentTxid: [...new Set(spendTx.inputs.map((i) => binToHex(i.outpointTransactionHash)))],
    outpointIndices: spendTx.inputs.map((i) => i.outpointIndex),
    monetaryValid: spendMonetaryValid,
    consensusAll: spendConsensus.every((x) => x.accept),
    standardAll: spendStandard.every((x) => x.accept),
    consensusWholeTx: spendConsensusWholeTx,
    standardWholeTx: spendStandardWholeTx,
    tokenValid: spendTokenValid,
    consensus: spendConsensus,
    standard: spendStandard,
    lean: xcheck,
  },
  vmbconf,
  gates: {
    parentConsensusAccept: parentConsensus.accept,
    parentStandardAccept: parentStandard.accept,
    parentConsensusWholeTxAccept: parentConsensusWholeTx.accept,
    parentStandardWholeTxAccept: parentStandardWholeTx.accept,
    parentLeanAccept: parentXcheck.accept === true,
    parentLeanTxValid: parentXcheck.txValid === true,
    parentLeanTokenValid: parentXcheck.tokenValid === true,
    parentOpCostParity,
    spendConsensusAll: spendConsensus.every((x) => x.accept),
    spendStandardAll: spendStandard.every((x) => x.accept),
    spendConsensusWholeTxAccept: spendConsensusWholeTx.accept,
    spendStandardWholeTxAccept: spendStandardWholeTx.accept,
    spendLeanAll: xcheck.length === 10 && xcheck.every((x) => x.parsed && x.accept && x.txValid && x.tokenValid),
    spendOpCostParity,
    vmbconfAll: vmbconf.pass === 11 && vmbconf.total === 11 && vmbconf.rejectedValid === 0 && vmbconf.acceptedInvalid === 0,
    sourceResolutionExact: true,
  },
};
writeFileSync(`${OUT}/manifest.json`, JSON.stringify(manifest, null, 2));
console.log(JSON.stringify({
  parentTxid: manifest.parent.internalTxid,
  parentBytes: manifest.parent.wireBytes,
  parent: manifest.gates.parentConsensusWholeTxAccept && manifest.gates.parentStandardWholeTxAccept && manifest.gates.parentLeanAccept,
  parentStandardWholeTx: manifest.gates.parentStandardWholeTxAccept,
  spendConsensusAll: manifest.gates.spendConsensusAll,
  spendStandardAll: manifest.gates.spendStandardAll,
  spendStandardWholeTx: manifest.gates.spendStandardWholeTxAccept,
  spendLeanAll: manifest.gates.spendLeanAll,
  vmbconf: manifest.vmbconf,
  sourceResolutionExact: manifest.gates.sourceResolutionExact,
  out: OUT,
}, null, 2));
