// Lane-local composition probe: retain the exact deferred-inner candidate and
// remove only the six proven EC/EX duplicate coefficient aliases.
process.env.EX_ALIAS = '1';
process.env.DEFER_MOD_VARIANT = 'inner';
await import('./build-terminal-fusion9.ts');
