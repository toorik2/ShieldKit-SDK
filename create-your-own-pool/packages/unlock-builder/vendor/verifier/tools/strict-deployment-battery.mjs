// Concrete deployment-profile battery. Every case rebuilds parent txids and
// resolves spending source outputs through parent-hash:index maps before VM.
// This is distinct from detached A1 mutation testing.
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import {
  binToHex,
  createVirtualMachineBch2026,
  decodeTransactionBch,
  decodeTransactionOutputs,
  encodeTransaction,
  hexToBin,
  hash256,
  verifyTransactionTokens,
} from '@bitauth/libauth';

const PARENT_DIR = process.env.PARENT || '/tmp/verifier-cash-81665-strict-envelope';
const OUT = process.env.OUT || '/tmp/verifier-cash-81665-strict-deployment-battery';
const PUBLIC_BENCH_CONTEXT = process.env.PUBLIC_BENCH_CONTEXT === '1';
const SEQUENCE_MUTATION = PUBLIC_BENCH_CONTEXT ? 1 : 0;
mkdirSync(OUT, { recursive: true });
const read = (name) => hexToBin(readFileSync(`${PARENT_DIR}/${name}`, 'utf8').trim());
const cloneBytes = (x) => Uint8Array.from(x);
const cloneOutput = (o) => ({
  ...o,
  lockingBytecode: cloneBytes(o.lockingBytecode),
  ...(o.token ? {
    token: {
      ...o.token,
      category: cloneBytes(o.token.category),
      ...(o.token.nft ? { nft: { ...o.token.nft, commitment: cloneBytes(o.token.nft.commitment) } } : {}),
    },
  } : {}),
});
const cloneTx = (tx) => ({
  ...tx,
  inputs: tx.inputs.map((i) => ({
    ...i,
    outpointTransactionHash: cloneBytes(i.outpointTransactionHash),
    unlockingBytecode: cloneBytes(i.unlockingBytecode),
  })),
  outputs: tx.outputs.map(cloneOutput),
});
const accept = (state) => state.error === undefined
  && state.stack.length === 1
  && state.stack[0]?.length === 1
  && state.stack[0][0] === 1;
const txValidShape = (tx, sourceOutputs) => {
  if (tx.inputs.length !== sourceOutputs.length || ![1, 2].includes(tx.version) || !tx.inputs.length || !tx.outputs.length) return false;
  const seen = new Set();
  for (const input of tx.inputs) {
    const key = `${binToHex(input.outpointTransactionHash)}:${input.outpointIndex}`;
    if (seen.has(key) || (input.outpointIndex === 0xffffffff && input.outpointTransactionHash.every((x) => x === 0))) return false;
    seen.add(key);
  }
  const inValue = sourceOutputs.reduce((n, o) => n + BigInt(o.valueSatoshis), 0n);
  const outValue = tx.outputs.reduce((n, o) => n + BigInt(o.valueSatoshis), 0n);
  return outValue <= inValue;
};

const baseSpend = decodeTransactionBch(read('spend_tx.hex'));
const baseParent = decodeTransactionBch(read('parent_tx.hex'));
const fundingSource = decodeTransactionOutputs(read('parent_srcouts.hex'));
if (typeof baseSpend === 'string' || typeof baseParent === 'string' || typeof fundingSource === 'string') throw new Error('envelope decode failed');
const baseSpendWire = encodeTransaction(baseSpend);
const baseParentWire = encodeTransaction(baseParent);

const makeCase = (id, mutate) => {
  const parent = cloneTx(baseParent);
  const altParent = cloneTx(baseParent);
  const spend = cloneTx(baseSpend);
  const spec = { id, parent, altParent, spend, useAltInput0: false };
  const result = mutate(spec);
  if (result?.useAltInput0) spec.useAltInput0 = true;
  const parentHash = hash256(encodeTransaction(parent));
  const altHash = hash256(encodeTransaction(altParent));
  const mutationChanged = binToHex(encodeTransaction(parent)) !== binToHex(baseParentWire)
    || binToHex(encodeTransaction(altParent)) !== binToHex(baseParentWire)
    || binToHex(encodeTransaction(spend)) !== binToHex(baseSpendWire);
  const outputsByHash = new Map([
    [binToHex(parentHash), parent.outputs],
    [binToHex(altHash), altParent.outputs],
  ]);
  spend.inputs = spend.inputs.map((input, i) => ({
    ...input,
    outpointTransactionHash: cloneBytes(spec.useAltInput0 && i === 0 ? altHash : parentHash),
    outpointIndex: i,
  }));
  const sourceOutputs = spend.inputs.map((input, i) => {
    const outputs = outputsByHash.get(binToHex(input.outpointTransactionHash));
    const output = outputs?.[input.outpointIndex];
    if (!output) throw new Error(`${id}: unresolved input[${i}]`);
    return cloneOutput(output);
  });
  const vm = createVirtualMachineBch2026(false);
  const stdVm = createVirtualMachineBch2026(true);
  const consensus = spend.inputs.map((_, i) => vm.evaluate({ inputIndex: i, sourceOutputs, transaction: spend })).map((state) => ({ accept: accept(state), error: state.error ?? '', opCost: state.metrics.operationCost }));
  const standard = spend.inputs.map((_, i) => stdVm.evaluate({ inputIndex: i, sourceOutputs, transaction: spend })).map((state) => ({ accept: accept(state), error: state.error ?? '', opCost: state.metrics.operationCost }));
  const consensusWholeTx = vm.verify({ transaction: spend, sourceOutputs });
  const standardWholeTx = stdVm.verify({ transaction: spend, sourceOutputs });
  const txValid = txValidShape(spend, sourceOutputs);
  const tokenValid = verifyTransactionTokens(spend, sourceOutputs, { maximumTokenCommitmentLength: 128 }) === true;
  return {
    id,
    parentTxid: binToHex(parentHash),
    alternateParentTxid: binToHex(altHash),
    noOp: !mutationChanged,
    useAltInput0: spec.useAltInput0,
    txValid,
    tokenValid,
    consensusWholeTx: { accept: consensusWholeTx === true, error: consensusWholeTx === true ? '' : String(consensusWholeTx) },
    standardWholeTx: { accept: standardWholeTx === true, error: standardWholeTx === true ? '' : String(standardWholeTx) },
    consensus,
    standard,
    globalAccept: mutationChanged && txValid && tokenValid && consensusWholeTx === true && consensus.every((x) => x.accept),
    standardGlobalAccept: mutationChanged && txValid && tokenValid && standardWholeTx === true && standard.every((x) => x.accept),
  };
};

const cases = [
  makeCase('source-value-0', ({ parent }) => { parent.outputs[0].valueSatoshis = 999n; }),
  makeCase('source-value-9', ({ parent }) => { parent.outputs[9].valueSatoshis = 999n; }),
  makeCase('output-value', ({ spend }) => { spend.outputs[0].valueSatoshis = 999n; }),
  makeCase('output-lock', ({ spend }) => { spend.outputs[0].lockingBytecode = Uint8Array.from([0x51]); }),
  makeCase('output-count', ({ spend }) => { spend.outputs.push({ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1n }); }),
  makeCase(`sequence-0-to-${SEQUENCE_MUTATION}`, ({ spend }) => { spend.inputs[0].sequenceNumber = SEQUENCE_MUTATION; }),
  makeCase(`sequence-9-to-${SEQUENCE_MUTATION}`, ({ spend }) => { spend.inputs[9].sequenceNumber = SEQUENCE_MUTATION; }),
  makeCase('tx-version', ({ spend }) => { spend.version = 1; }),
  makeCase('tx-locktime', ({ spend }) => { spend.locktime = 1; }),
  makeCase('split-parent-outpoint-hash', ({ altParent, spend }) => {
    // Keep the same known funding outpoint but alter the valid parent
    // serialization, yielding a distinct parent txid without a phantom UTXO.
    altParent.inputs[0].sequenceNumber = 0xfffffffe;
    spend.inputs[0].outpointTransactionHash = cloneBytes(altParent.inputs[0].outpointTransactionHash);
    // The post-mutation parent txids are recomputed below; input 0 resolves to
    // a distinct, physically valid parent with the same candidate output set.
    spend.inputs[0].outpointIndex = 0;
    return { useAltInput0: true };
  }),
  makeCase('root-source-lock-6', ({ parent }) => { parent.outputs[6].lockingBytecode = cloneBytes(parent.outputs[7].lockingBytecode); }),
  makeCase('root-source-lock-7', ({ parent }) => { parent.outputs[7].lockingBytecode = cloneBytes(parent.outputs[0].lockingBytecode); }),
];

const output = {
  schema: 'verifier.cash/strict-deployment-battery/v1',
  context: PUBLIC_BENCH_CONTEXT ? 'public-bench value=1000 sequence=0' : 'strict value=10000 sequence=0xffffffff',
  parent: PARENT_DIR,
  total: cases.length,
  globalAccepts: cases.filter((x) => x.globalAccept && !x.noOp).map((x) => x.id),
  standardGlobalAccepts: cases.filter((x) => x.standardGlobalAccept && !x.noOp).map((x) => x.id),
  noOps: cases.filter((x) => x.noOp).map((x) => x.id),
  cases,
};
writeFileSync(`${OUT}/strict-deployment-battery.json`, JSON.stringify(output, null, 2));
if (output.noOps.length !== 0) {
  console.error(JSON.stringify({ error: 'deployment battery contains no-op mutations', noOps: output.noOps }, null, 2));
  process.exitCode = 1;
}
console.log(JSON.stringify({ total: output.total, globalAccepts: output.globalAccepts, standardGlobalAccepts: output.standardGlobalAccepts, out: `${OUT}/strict-deployment-battery.json` }, null, 2));
