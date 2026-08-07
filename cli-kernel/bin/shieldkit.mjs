#!/usr/bin/env node
/**
 * ShieldKit unified CLI entry — CLI_ARCHITECTURE_PLAN.md
 * One binary, one canonical lifecycle grammar.
 */
import { pathToFileURL } from 'node:url';
import { dispatch } from '../front-controller.mjs';

const { exitCode } = await dispatch(process.argv.slice(2));
process.exitCode = exitCode;
