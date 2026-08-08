#!/usr/bin/env node

/** Internal benchmark bridge; deliberately not exposed as a product CLI. */
import { runPf6ProfileCommand } from '../../../designs/pf6/src/lifecycle-profile.mjs';

await runPf6ProfileCommand(process.argv.slice(2));
