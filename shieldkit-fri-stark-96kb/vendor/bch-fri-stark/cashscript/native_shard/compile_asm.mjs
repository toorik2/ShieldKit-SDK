// Test helper: compile one CashAssembly string to its locking-bytecode hex on the real libauth toolchain
// (used to bake an exact contract "address" for OP_UTXOBYTECODE contract-pins -- never hand-computed).
// Usage: node compile_asm.mjs "<asm>"  ->  prints the compiled bytecode as hex. No mock (TEST_RULES).
import { cashAssemblyToBin, binToHex } from '@bitauth/libauth';

const bin = cashAssemblyToBin(String(process.argv[2] ?? '').replace(/\n/g, ' ').trim());
if (typeof bin === 'string') { console.error(bin); process.exit(1); }
console.log(binToHex(bin));
