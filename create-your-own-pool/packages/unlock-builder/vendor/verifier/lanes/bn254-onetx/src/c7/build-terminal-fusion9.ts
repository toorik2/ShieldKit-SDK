// Opt-in lane entrypoint. The baseline source-public-r25 entrypoint remains
// unchanged and continues to build the reproducible 10-input profile.
process.env.TERMINAL_FUSION9 = '1';
// Terminal compression track: all transforms are proof-independent and
// preserve the existing guards and fixed carrier topology.
process.env.TERMINAL_REUSE_ZPOWERS = '1';
process.env.TERMINAL_CANON_ZPROLOGUE = '1';
process.env.TERMINAL_BYTE_GUARDS = '1';
process.env.TERMINAL_GROUP_ROLE_CACHE = 'raw-lock';
process.env.TERMINAL_GROUP_ROLE_LIMIT = '7';
await import('./build.ts');
