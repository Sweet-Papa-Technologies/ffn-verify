import {
  BusinessKinds,
  CredentialError,
  DidResolver,
  StatusChecker,
  decodeJwt,
  didWebForOrigin,
  isDidJwk,
  jwkOfDidJwk,
  sameKey,
  verifyCredential,
  verifyDelegationChainDetailed,
  type Fetch,
  type KvStore,
  type StatusReference,
  type VerifiedChain,
} from '@fofonet/door-core';
import { pinRegistryKeys } from './pin.js';
import type { RegistryAnchor } from './verify.js';

// Verifying a key-bound presentation someone handed you, with the nonce and
// audience you gave them: the check behind the headless door and the MCP
// server's verify_presentation tool. Delegations are walked to their root;
// anything else must come from an issuer the caller accepts.
//
// Trust is decided before anything is fetched: a credential's issuer is
// checked against `issuers`, and a delegation chain's root against `roots`,
// from the presentation as given, so an issuer or root you don't accept costs
// no network request at all.

export interface PresentationInput {
  presentation: string;
  /** Parent delegations, nearest first. */
  chain?: string[];
  nonce: string;
  /** The audience you asked for (your origin). */
  audience: string;
  /** Accept delegation chains rooted at these DIDs. */
  roots?: string[];
  requiredScope?: string[];
  /** Accept non-delegation credentials from these issuers. */
  issuers?: string[];
  maxAgeSeconds?: number;
}

export interface PresentationOptions {
  fetch?: Fetch;
  resolver?: DidResolver;
  store?: KvStore;
  /** Seconds since epoch (default now). For test vectors. */
  now?: number;
  /**
   * A registry whose keys to pin (its `keyThumbprints`), as verifyBusiness
   * does. The known FFN registries are pinned whether or not this is given.
   * It does not add the registry to `issuers`.
   */
  registry?: RegistryAnchor;
  /** Total time per HTTP request (connect, headers and body), in milliseconds. Default 10 000. */
  timeoutMs?: number;
  /** Aborts every request; verifyPresentation then rejects with the signal's reason. */
  signal?: AbortSignal;
}

export type PresentationResult =
  | {
      verified: true;
      subject: string;
      vct: string;
      issuer: string;
      claims: Record<string, unknown>;
      delegation?: VerifiedChain;
    }
  | { verified: false; code: string; message: string };

const STRUCTURAL = ['iss', 'iat', 'exp', 'sub', 'jti', 'vct', 'cnf', 'status', '_sd_alg'];

const publicClaims = (claims: Record<string, unknown>) =>
  Object.fromEntries(Object.entries(claims).filter(([k]) => !STRUCTURAL.includes(k)));

export async function verifyPresentation(
  input: PresentationInput,
  options: PresentationOptions = {},
): Promise<PresentationResult> {
  options.signal?.throwIfAborted();
  const fetchFn = options.fetch ?? ((i, init) => globalThis.fetch(i, init));
  const limits = {
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
  };
  const anchor = options.registry;
  const resolver = pinRegistryKeys(
    options.resolver ?? new DidResolver({ fetch: fetchFn, ...limits }),
    anchor ? (anchor.did ?? didWebForOrigin(anchor.origin)) : undefined,
    anchor?.keyThumbprints,
  );
  const nowSec = options.now ?? Math.floor(Date.now() / 1000);
  const status = new StatusChecker({
    resolver,
    fetch: fetchFn,
    ...(options.store ? { store: options.store } : {}),
    now: () => nowSec,
    ...limits,
  });
  const keyBinding = {
    nonce: input.nonce,
    audience: input.audience,
    maxAgeSeconds: input.maxAgeSeconds ?? 300,
  };
  let result: PresentationResult;
  try {
    // What the presentation claims, before any of it is checked or fetched.
    let claimed: { iss?: unknown; vct?: unknown };
    try {
      claimed = decodeJwt<{ iss?: unknown; vct?: unknown }>(
        input.presentation.split('~')[0]!,
      ).payload;
    } catch {
      throw new CredentialError('malformed credential');
    }
    if (typeof claimed.iss !== 'string' || typeof claimed.vct !== 'string')
      throw new CredentialError('credential has no issuer or type');

    if (claimed.vct === BusinessKinds.delegation) {
      if (!input.roots?.length)
        throw new CredentialError('no accepted roots given for a delegation', 'untrusted_root');
      // The chain's root is checked against `roots` before any DID is resolved.
      const { chain: delegation, leaf } = await verifyDelegationChainDetailed(
        [input.presentation, ...(input.chain ?? [])],
        {
          resolver,
          status,
          now: nowSec,
          roots: input.roots,
          keyBinding,
          ...(input.requiredScope ? { requiredScope: input.requiredScope } : {}),
        },
      );
      result = {
        verified: true,
        subject: delegation.delegate,
        vct: leaf.vct,
        issuer: leaf.iss,
        claims: publicClaims(leaf.claims),
        delegation,
      };
    } else {
      if (!input.issuers?.includes(claimed.iss))
        throw new CredentialError(`issuer ${claimed.iss} is not accepted`, 'untrusted_issuer');
      const v = await verifyCredential(input.presentation, { resolver, keyBinding, now: nowSec });
      const subject = v.claims.sub;
      if (typeof subject !== 'string') throw new CredentialError('credential has no subject');
      const holds = isDidJwk(subject)
        ? await sameKey(jwkOfDidJwk(subject), v.cnfJwk)
        : await resolver.controlsKey(subject, v.cnfJwk);
      if (!holds)
        throw new CredentialError(`${subject} does not list the presenting key`, 'wrong_holder');
      if (v.claims.status) {
        const outcome = await status.check(v.claims.status as StatusReference, v.iss);
        if (outcome.status !== 'valid')
          throw new CredentialError(
            `credential status is ${outcome.status}`,
            outcome.status === 'unknown' ? 'status_unknown' : 'revoked',
          );
      }
      result = {
        verified: true,
        subject,
        vct: v.vct,
        issuer: v.iss,
        claims: publicClaims(v.claims),
      };
    }
  } catch (err) {
    result =
      err instanceof CredentialError
        ? { verified: false, code: err.code, message: err.message }
        : { verified: false, code: 'invalid_presentation', message: (err as Error).message };
  }
  options.signal?.throwIfAborted();
  return result;
}
