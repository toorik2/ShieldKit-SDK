/**
 * PF6 Lab adapter — capability honesty; no maintainer SSH/evidence authority.
 */

import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildResultEnvelope } from '../contracts/envelopes.mjs';
import { ERROR_CODES } from '../contracts/errors.mjs';
import { capabilitiesForDesign } from '../registry/designs.mjs';
import { isMutationAllowed, mutationBlockReason } from '../contracts/capabilities.mjs';

const SDK_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const FORBIDDEN_ROOTS = [
  path.join(SDK_ROOT, 'designs/pf6', 'evidence'),
  path.join(SDK_ROOT, '.codex-artifacts'),
];

export function assertNoMaintainerPaths(ctx) {
  const home = ctx.flags?.home || ctx.home?.path;
  if (home) {
    const abs = path.resolve(home);
    for (const bad of FORBIDDEN_ROOTS) {
      if (abs === bad || abs.startsWith(`${bad}${path.sep}`)) {
        return buildResultEnvelope({
          ok: false,
          code: ERROR_CODES.MAINTAINER_PATH_FORBIDDEN,
          error: `home must not be repository evidence/maintainer path: ${abs}`,
          command: ctx.commandLabel || 'pf6',
        });
      }
    }
  }
  // Reject ambient SSH env for product mutations
  const env = ctx.env || process.env;
  if (env.SHIELDKIT_PF6_SSH_HOST || env.SHIELDKIT_MAINTAINER_SSH) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.MAINTAINER_PATH_FORBIDDEN,
      error: 'maintainer SSH env is not a supported product path for PF6',
      command: ctx.commandLabel || 'pf6',
    });
  }
  return null;
}

export function pf6Doctor(ctx, command = 'design doctor') {
  const forbidden = assertNoMaintainerPaths({ ...ctx, commandLabel: command });
  if (forbidden) return forbidden;
  const caps = capabilitiesForDesign(ctx.design);
  const designRoot = path.join(SDK_ROOT, ctx.design.designRoot || 'designs/pf6');
  return buildResultEnvelope({
    ok: true,
    command,
    identity: {
      backendId: ctx.design.backendId,
      ...(typeof (ctx.home?.profileId || ctx.design.profileId) === 'string'
        ? { profileId: ctx.home?.profileId || ctx.design.profileId } : {}),
      profileStatus: typeof (ctx.home?.profileId || ctx.design.profileId) === 'string' ? 'frozen' : (ctx.design.profileStatus || 'unfrozen'),
      network: ctx.design.network,
      homeId: ctx.home?.homeId ?? null,
      instanceId: ctx.home?.instanceId ?? null,
    },
    result: {
      maturity: 'lab',
      designRootExists: existsSync(designRoot),
      capabilities: caps,
      maintainerPaths: 'forbidden',
      notes: 'PF6 Lab: all mutations are blocked; acknowledgement cannot replace missing profile and safety guarantees',
    },
  });
}

export function pf6Action(ctx, kind) {
  const forbidden = assertNoMaintainerPaths({ ...ctx, commandLabel: `action ${kind}` });
  if (forbidden) return forbidden;

  const caps = capabilitiesForDesign(ctx.design);
  const allowLab = ctx.flags.allowLab === true || ctx.home?.labOptIn === true;
  if (!isMutationAllowed(caps, kind, { allowLab })) {
    const reason = mutationBlockReason(caps, kind, { allowLab });
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.CAPABILITY_BLOCKED,
      error: reason,
      command: `action ${kind}`,
      identity: {
        backendId: ctx.design.backendId,
        ...(typeof (ctx.home?.profileId || ctx.design.profileId) === 'string'
          ? { profileId: ctx.home?.profileId || ctx.design.profileId } : {}),
        profileStatus: typeof (ctx.home?.profileId || ctx.design.profileId) === 'string' ? 'frozen' : (ctx.design.profileStatus || 'unfrozen'),
        network: ctx.design.network,
      },
      result: {
        capability: caps.guarantees[kind] || null,
        emulated: false,
      },
    });
  }

  // Defensive unreachable fallback: the current support record blocks every
  // mutation. Do not emulate a lifecycle against evidence fixtures.
  return buildResultEnvelope({
    ok: false,
    code: ERROR_CODES.CAPABILITY_BLOCKED,
    error: `PF6 ${kind} is experimental Lab: provision a private home and product path; `
      + 'repository evidence fixtures are not authority (no silent evidence-root lifecycle)',
    command: `action ${kind}`,
    identity: {
      backendId: ctx.design.backendId,
      ...(typeof (ctx.home?.profileId || ctx.design.profileId) === 'string'
        ? { profileId: ctx.home?.profileId || ctx.design.profileId } : {}),
      profileStatus: typeof (ctx.home?.profileId || ctx.design.profileId) === 'string' ? 'frozen' : (ctx.design.profileStatus || 'unfrozen'),
      network: ctx.design.network,
      homeId: ctx.home?.homeId ?? null,
    },
    result: {
      capability: caps.guarantees[kind],
      emulated: false,
      parallelSendPath: false,
    },
  });
}
