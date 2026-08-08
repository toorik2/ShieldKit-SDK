// HP8 helper: compile ONE redeem CashAssembly (read from a file, so multi-KB redeems bypass the OS arg-length
// limit) to its P2SH32 commitment on the real libauth toolchain, and report {hex, len} where hex =
// hash256(redeem_bin) (the exact value p2sh_multi_input.mjs bakes into the P2SH32 locking, line 25) and len =
// redeem_bin.length (R). The blob@0 count-anchor (HP8) reads a terminal input's scriptSig via OP_INPUTBYTECODE,
// splits off the trailing R bytes (= redeem_bin, since scriptSig = witness ++ PUSH(redeem)), OP_HASH256s them,
// and EQUALVERIFYs against this hex -> presence+content binding of the otherwise-unread terminal covenants.
// Usage: node compile_hash.mjs <asm-file>  ->  prints {"hex":"..","len":N}. No mock (TEST_RULES).
import { readFileSync } from 'fs';
import { cashAssemblyToBin, hash256, binToHex } from '@bitauth/libauth';

const bin = cashAssemblyToBin(readFileSync(process.argv[2], 'utf8').replace(/\n/g, ' ').trim());
if (typeof bin === 'string') { console.error(bin); process.exit(1); }
console.log(JSON.stringify({ hex: binToHex(hash256(bin)) }));
