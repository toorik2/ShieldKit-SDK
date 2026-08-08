// Lane-local opt-in integration of the validated deferred inner MOD fold.
// The public/default terminal-fusion9 entrypoint remains unchanged.
process.env.DEFER_MOD_VARIANT = 'inner';
await import('./build-terminal-fusion9.ts');
