// LeanBCH second-oracle export for covenant-thread-escape.
// Wraps the REAL covIn/covOut chunk in P2SH32 (as the deployed scheme does), then emits
// wire-format tx + source-outputs for a chosen scenario so xcheck.lean can independently
// verify accept/reject + token consensus. Also prints libauth's verdict for direct compare.
import { writeFileSync } from 'node:fs';
import { covIn, covOut, commitBin, CATEGORY, compileBytecodeRaw, decl } from './_millermath.mjs';
import {
  binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush,
  encodeTransaction, encodeTransactionOutputs, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const scenario = process.env.SCENARIO ?? 'honest';

const names = ['a', 'b'];
const src =
  'pragma cashscript ^0.14.0;\n' +
  'contract Thread(){\n' +
  `    function spend(${decl(names)}, bytes unused zeroPadding){\n` +
  covIn(names) + '\n' + covOut(names) + '\n' +
  '    }\n}\n';
const redeem = Uint8Array.from([...compileBytecodeRaw(src)]);
const rpush = encodeDataPush(redeem);
const locking = encodeLockingBytecodeP2sh32(hash256(redeem)); // P2SH32 of the chunk

const a = 12345678901234567890n % P, b = 98765432109876543210n % P;
const inCommit = commitBin([a, b]);
const outCommit = commitBin([a % P, b % P]);

// unlocking = [padding push][b push][a push][redeem push]  (args reversed, then redeem)
const argb = Uint8Array.from([...[a, b]].reverse().flatMap((c) => [...pushInt(c)]));
// pad so the 'bytes zeroPadding' param exists (small fixed pad push)
const padPush = encodeDataPush(new Uint8Array(8));
const unlocking = Uint8Array.from([...padPush, ...argb, ...rpush]);

const tok = (commitment, cap = 'mutable', cat = CATEGORY) => ({ amount: 0n, category: cat, nft: { capability: cap, commitment } });

// choose output[0] locking per scenario
let out0lock = locking;                      // honest: perpetuate same P2SH32
if (scenario === 'escape_op1') out0lock = Uint8Array.from([0x51]);          // OP_1 successor
if (scenario === 'escape_p2sh') out0lock = encodeLockingBytecodeP2sh32(new Uint8Array(32).fill(0x11)); // attacker P2SH32
let outputs = [{ lockingBytecode: out0lock, valueSatoshis: 1000n, token: tok(outCommit) }];
if (scenario === 'escape_extra') {
  out0lock = Uint8Array.from([0x51]);
  outputs = [
    { lockingBytecode: out0lock, valueSatoshis: 1000n, token: tok(outCommit) },
    { lockingBytecode: Uint8Array.from([0x76,0xa9,0x14,...new Uint8Array(20).fill(0xab),0x88,0xac]), valueSatoshis: 1000n },
  ];
}

const program = {
  inputIndex: 0,
  sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
  transaction: {
    version: 2,
    inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
    outputs, locktime: 0,
  },
};
const st = realVm.evaluate(program);
const top = st.stack[st.stack.length - 1];
const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
console.log(`[libauth] scenario=${scenario} accepted=${accepted} opCost=${st.metrics.operationCost} err=${st.error ?? 'none'}`);

const txHex = binToHex(encodeTransaction(program.transaction));
const soHex = binToHex(encodeTransactionOutputs(program.sourceOutputs));
writeFileSync('/tmp/xcheck_tx.hex', txHex);
writeFileSync('/tmp/xcheck_srcouts.hex', soHex);
console.log('wrote /tmp/xcheck_tx.hex + /tmp/xcheck_srcouts.hex; txBytes=', txHex.length/2, 'soBytes=', soHex.length/2);
