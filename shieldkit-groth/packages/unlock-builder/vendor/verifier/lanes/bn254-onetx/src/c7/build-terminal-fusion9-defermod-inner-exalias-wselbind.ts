// Lane-local soundness repair: retain the exact deferred-inner/EC-EX profile,
// make the compact genesis selector canonical at unlocking byte zero, and bind
// that byte to the terminal residue class.
process.env.TERMINAL_BIND_WSEL = '1';
await import('./build-terminal-fusion9-defermod-inner-exalias.ts');
