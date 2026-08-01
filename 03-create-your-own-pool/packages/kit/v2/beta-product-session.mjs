/**
 * Production composition boundary for one warm V2 beta action session.
 * Opening verifies the committed deployment, durable runtime cache, native
 * prover installation, wallet/store/journal bindings, and BCHN capability
 * before the lifecycle can prepare or send anything.
 */
import {
  assertV2BetaProductContext,
  openV2BetaProductContext,
} from './beta-product-context.mjs';
import {
  createV2BetaProductActionLifecycle,
} from './beta-product-action-lifecycle.mjs';

export const V2_BETA_PRODUCT_SESSION_SCHEMA =
  'shieldkit-v2-beta-product-session-v1';

export class V2BetaProductSessionError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaProductSessionError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaProductSessionError(code, message, options);
};

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BETA_SESSION_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    fail('BETA_SESSION_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function issuedContext(value) {
  try { return assertV2BetaProductContext(value); }
  catch (error) {
    fail('BETA_SESSION_CONTEXT_REJECTED', 'a verified beta product context is required', { cause: error });
  }
}

async function compose(contextValue, createLifecycle) {
  const context = issuedContext(contextValue);
  let lifecycle;
  try {
    lifecycle = await createLifecycle({
      journal: context.journal,
      nativeProverInstallation: context.nativeProverInstallation,
      profileCore: context.profileCore,
      proofWorkspaceDirectory: context.proofWorkspaceDirectory,
      rpc: context.rpc,
      runtimeCache: context.runtime,
      store: context.store,
      wallet: context.wallet,
    });
  } catch (error) {
    try { context.close(); } catch { /* preserve the construction failure */ }
    fail('BETA_SESSION_LIFECYCLE_REJECTED', 'verified beta action lifecycle could not open', { cause: error });
  }
  let closed = false;
  return Object.freeze({
    schema: V2_BETA_PRODUCT_SESSION_SCHEMA,
    identity: context.identity,
    lifecycle,
    context,
    close() {
      if (!closed) { closed = true; context.close(); }
    },
  });
}

/** Production-only composition; it exposes no dependency injection seam. */
export async function openV2BetaProductSession(value) {
  exact(value, ['config', 'rpc'], 'beta product session options');
  const context = await openV2BetaProductContext(value);
  return compose(context, createV2BetaProductActionLifecycle);
}

/** Explicit unit-test seam; callers must still supply a factory-issued context. */
export async function composeV2BetaProductSessionForTest(context, createLifecycle) {
  if (typeof createLifecycle !== 'function') {
    fail('BETA_SESSION_INVALID', 'test lifecycle constructor must be a function');
  }
  return compose(context, createLifecycle);
}
