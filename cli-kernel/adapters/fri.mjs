/**
 * FRI Lab adapter — incomplete verbs and unfrozen identity are blocked.
 * No emulated full lifecycle.
 */

import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildResultEnvelope } from '../contracts/envelopes.mjs';
import { ERROR_CODES } from '../contracts/errors.mjs';
import { capabilitiesForDesign } from '../registry/designs.mjs';
import { isMutationAllowed, mutationBlockReason } from '../contracts/capabilities.mjs';

const SDK_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export function friDoctor(ctx, command = 'design doctor') {
  const caps = capabilitiesForDesign(ctx.design);
  const designRoot = path.join(SDK_ROOT, ctx.design.designRoot || 'shieldkit-fri-stark-96kb');
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
      notes: 'FRI: all mutations blocked until one exact profile and full lifecycle are frozen',
      maintainerSsh: 'forbidden on product paths',
    },
  });
}

export function friAction(ctx, kind) {
  const caps = capabilitiesForDesign(ctx.design);
  const allowLab = ctx.flags.allowLab === true || ctx.home?.labOptIn === true;

  // Always refuse maintainer SSH
  const env = ctx.env || process.env;
  if (env.SHIELDKIT_FRI_SSH_HOST || env.SHIELDKIT_MAINTAINER_SSH) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.MAINTAINER_PATH_FORBIDDEN,
      error: 'maintainer SSH is not a supported FRI product path',
      command: `action ${kind}`,
    });
  }

  if (!isMutationAllowed(caps, kind, { allowLab })) {
    const reason = mutationBlockReason(caps, kind, { allowLab });
    return buildResultEnvelope({
      ok: false,
      code: caps.guarantees[kind]?.status === 'blocked'
        ? ERROR_CODES.CAPABILITY_BLOCKED
        : ERROR_CODES.LAB_ACK_REQUIRED,
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
        blockedIncompleteVerb: caps.guarantees[kind]?.status === 'blocked',
      },
    });
  }

  // Defensive unreachable fallback: Lab acknowledgement never substitutes for
  // a frozen profile or complete lifecycle guarantees.
  return buildResultEnvelope({
    ok: false,
    code: ERROR_CODES.CAPABILITY_BLOCKED,
    error: `FRI ${kind} experimental Lab path requires provisioned private home and frozen profile; `
      + 'not emulating full lifecycle against repo stories',
    command: `action ${kind}`,
    identity: {
      backendId: ctx.design.backendId,
      ...(typeof (ctx.home?.profileId || ctx.design.profileId) === 'string'
        ? { profileId: ctx.home?.profileId || ctx.design.profileId } : {}),
      profileStatus: typeof (ctx.home?.profileId || ctx.design.profileId) === 'string' ? 'frozen' : (ctx.design.profileStatus || 'unfrozen'),
      network: ctx.design.network,
    },
    result: {
      capability: caps.guarantees[kind],
      emulated: false,
      parallelSendPath: false,
    },
  });
}
