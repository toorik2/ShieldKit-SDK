import { compileString, utils } from 'cashc';
const { asmToBytecode } = utils;
const src = `pragma cashscript ^0.14.0;
contract T() {
  function f(int x) {
    require(hash256(toPaddedBytes(x, 40)) == 0x0000000000000000000000000000000000000000000000000000000000000000);
  }
}`;
const c = compileString(src);
console.log("ASM:", c.bytecode);
console.log("HEX:", Buffer.from(asmToBytecode(c.bytecode)).toString('hex'));
