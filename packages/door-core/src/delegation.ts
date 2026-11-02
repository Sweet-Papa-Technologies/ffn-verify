import { BusinessKinds, type DelegationClaims, type SubjectKind } from './business.js';
import {
  CredentialError,
  credentialHash,
  signCredential,
  verifyCredential,
  sameKey,
  type VerifiedSdJwt,
} from './credential.js';
import { isDidJwk, jwkOfDidJwk } from './did-jwk.js';
import type { DidResolver } from './did-web.js';
import { decodeJwt, type Jwk, type JwsSigner } from './jose.js';
import { issuerJwtOf } from './sdjwt.js';
import type { StatusChecker, StatusReference } from './status.js';

// Delegation, the one primitive under everything (plan, "Delegation").
//
// A delegation is a credential the delegator signs: this DID may do these
// things for me, until this date, and I can revoke it. It covers a business
// letting the registry publish its record, a business letting an agent book
// jobs, and later a person letting another person act for them. A delegate can
// pass on part of what it holds; the verifier walks the chain back to the root.

export const MAX_CHAIN_DEPTH = 5;

export interface DelegateInput {
  /** The delegator's key; its kid must be a key in the delegator's DID document. */
  signer: JwsSigner;
  delegator: string;
  delegate: { did: string; kind: SubjectKind; key: Jwk };
  scope: string[];
  /** ISO 8601. Required: a delegation never runs forever. */
  expiresAt: string;
  /** The delegation that gave the delegator this authority, when it isn't the root. */
  parent?: string;
  purpose?: string;
  /** Status entry the delegator reserved (e.g. from the registry) so it can revoke. */
  status?: StatusReference;
  jti?: string;
  /** Seconds since epoch (default now). */
  now?: number;
}

export async function signDelegation(input: DelegateInput): Promise<string> {
  if (input.scope.length === 0) throw new Error('a delegation needs a scope');
  const iat = input.now ?? Math.floor(Date.now() / 1000);
  const exp = Math.floor(Date.parse(input.expiresAt) / 1000);
  if (!(exp > iat)) throw new Error('a delegation must expire in the future');
  const claims: DelegationClaims = {
    scope: input.scope,
    delegateKind: input.delegate.kind,
    ...(input.parent ? { parent: await credentialHash(input.parent) } : {}),
    ...(input.purpose ? { purpose: input.purpose } : {}),
  };
  return signCredential({
    signer: input.signer,
    payload: {
      iss: input.delegator,
      sub: input.delegate.did,
      vct: BusinessKinds.delegation,
      iat,
      exp,
      jti: input.jti ?? globalThis.crypto.randomUUID(),
      cnf: { jwk: input.delegate.key },
      ...(input.status ? { status: input.status } : {}),
      ...claims,
    },
  });
}

/** Does `held` cover `wanted`? Exact match, or a "prefix:*" wildcard. */
export function scopeCovers(held: readonly string[], wanted: string): boolean {
  return held.some((h) => h === wanted || (h.endsWith(':*') && wanted.startsWith(h.slice(0, -1))));
}

export interface VerifiedLink {
  jti?: string;
  iss: string;
  sub: string;
  scope: string[];
  delegateKind: SubjectKind;
  expiresAt: string;
  status: 'valid' | 'unknown';
}

export interface VerifiedChain {
  /** The DID at the top of the chain, whose authority everything below borrows. */
  root: string;
  /** The DID the chain ends at (the presenter). */
  delegate: string;
  delegateKind: SubjectKind;
  /** What the delegate may do: the leaf's scope, already bounded by every parent. */
  scope: string[];
  /** Earliest expiry in the chain. */
  expiresAt: string;
  /** Leaf first. */
  links: VerifiedLink[];
}

export interface VerifyChainOptions {
  resolver: DidResolver;
  status: StatusChecker;
  now?: number;
  /** Reject unless the chain starts at one of these DIDs. */
  roots?: string[];
  /** Reject unless the delegate may do all of these. */
  requiredScope?: string[];
  /** Accept a link whose status list can't be reached (default false: fail closed). */
  allowUnknownStatus?: boolean;
  /** Key binding for the leaf, when it is being presented. */
  keyBinding?: { nonce: string; audience: string; maxAgeSeconds?: number };
}

/**
 * Verify a chain of delegations, leaf first: chain[0] names the presenter,
 * chain[chain.length - 1] is signed by the root. Each link must be signed by
 * the key its parent delegated to, stay inside its parent's scope and expiry,
 * name its parent by hash, and be unrevoked.
 *
 * Trust is decided before anything is fetched: the root link's issuer is read
 * from the undecoded chain and checked against `roots` first, then the chain
 * is walked from the root down, so every DID resolved is the root or one a
 * verified link delegated to, and a link's status list is fetched only after
 * that link's signature verified.
 */
export async function verifyDelegationChain(
  chain: string[],
  options: VerifyChainOptions,
): Promise<VerifiedChain> {
  return (await verifyDelegationChainDetailed(chain, options)).chain;
}

/** verifyDelegationChain, also returning the verified leaf credential (claims included). */
export async function verifyDelegationChainDetailed(
  chain: string[],
  options: VerifyChainOptions,
): Promise<{ chain: VerifiedChain; leaf: VerifiedSdJwt }> {
  if (chain.length === 0) throw new CredentialError('empty delegation chain', 'broken_chain');
  if (chain.length > MAX_CHAIN_DEPTH)
    throw new CredentialError('delegation chain is too long', 'broken_chain');

  // Undecoded issuers, before any network request.
  const claimed = chain.map((compact, i) => {
    try {
      const iss = decodeJwt<{ iss?: unknown }>(issuerJwtOf(compact)).payload.iss;
      if (typeof iss === 'string') return iss;
    } catch {
      // reported below
    }
    throw new CredentialError(`link ${i} is malformed`, 'broken_chain');
  });
  const claimedRoot = claimed[claimed.length - 1]!;
  if (options.roots && !options.roots.includes(claimedRoot))
    throw new CredentialError(
      `the chain starts at ${claimedRoot}, which this verifier doesn't accept`,
      'untrusted_root',
    );

  const links: VerifiedLink[] = [];
  const verified: Array<VerifiedSdJwt & { compact: string }> = [];
  for (let i = chain.length - 1; i >= 0; i--) {
    const compact = chain[i]!;
    const parent = verified[0];
    const p = parent?.claims as (Record<string, unknown> & DelegationClaims) | undefined;
    // Only the delegate above may sign the next link: checked before its DID is resolved.
    if (p && claimed[i] !== p.sub)
      throw new CredentialError(
        `link ${i} is signed by ${claimed[i]}, not the delegate above it`,
        'broken_chain',
      );
    const v = await verifyCredential(compact, {
      resolver: options.resolver,
      ...(options.now === undefined ? {} : { now: options.now }),
      ...(i === 0 && options.keyBinding ? { keyBinding: options.keyBinding } : {}),
    });
    if (v.vct !== BusinessKinds.delegation)
      throw new CredentialError(`link ${i} is not a delegation`, 'broken_chain');
    const c = v.claims as Record<string, unknown> & Partial<DelegationClaims>;
    const sub = c.sub;
    if (typeof sub !== 'string')
      throw new CredentialError(`link ${i} has no delegate`, 'broken_chain');
    if (!Array.isArray(c.scope) || c.scope.length === 0)
      throw new CredentialError(`link ${i} has no scope`, 'broken_chain');
    if (typeof c.exp !== 'number')
      throw new CredentialError(`link ${i} never expires`, 'broken_chain');

    if (parent && p) {
      if (v.iss !== p.sub)
        throw new CredentialError(
          `link ${i} is signed by ${v.iss}, not the delegate above it`,
          'broken_chain',
        );
      if (!(await sameKey(v.issuerKey, parent.cnfJwk)))
        throw new CredentialError(
          `link ${i} is signed by a key the parent didn't delegate to`,
          'broken_chain',
        );
      if (c.parent !== (await credentialHash(parent.compact)))
        throw new CredentialError(`link ${i} names a different parent`, 'broken_chain');
      const beyond = c.scope.filter((s) => !scopeCovers(p.scope, s));
      if (beyond.length > 0)
        throw new CredentialError(
          `link ${i} widens the scope (${beyond.join(', ')})`,
          'broken_chain',
        );
      if (c.exp > (p.exp as number))
        throw new CredentialError(`link ${i} outlives its parent`, 'broken_chain');
    } else if (c.parent !== undefined) {
      throw new CredentialError('the chain is missing its root', 'broken_chain');
    }

    // The delegate's DID must control the key the delegation is bound to.
    if (isDidJwk(sub)) {
      if (!(await sameKey(jwkOfDidJwk(sub), v.cnfJwk)))
        throw new CredentialError(
          `link ${i} is bound to a key ${sub} doesn't hold`,
          'broken_chain',
        );
    } else if (!(await options.resolver.controlsKey(sub, v.cnfJwk))) {
      throw new CredentialError(`link ${i} is bound to a key ${sub} doesn't list`, 'broken_chain');
    }

    // Status last: this link's signature has verified, so its status URI is the signer's word.
    let status: VerifiedLink['status'] = 'valid';
    if (c.status !== undefined) {
      const outcome = await options.status.check(c.status as StatusReference, v.iss);
      if (outcome.status === 'invalid' || outcome.status === 'suspended')
        throw new CredentialError(`link ${i} has been revoked`, 'revoked');
      if (outcome.status === 'unknown') {
        if (!options.allowUnknownStatus)
          throw new CredentialError(`link ${i} status could not be checked`, 'status_unknown');
        status = 'unknown';
      }
    }
    verified.unshift({ ...v, compact });
    links.unshift({
      ...(typeof c.jti === 'string' ? { jti: c.jti } : {}),
      iss: v.iss,
      sub,
      scope: c.scope,
      delegateKind: (c.delegateKind ?? 'agent') as SubjectKind,
      expiresAt: new Date(c.exp * 1000).toISOString(),
      status,
    });
  }

  const root = links[links.length - 1]!.iss;
  if (options.roots && !options.roots.includes(root))
    throw new CredentialError(
      `the chain starts at ${root}, which this verifier doesn't accept`,
      'untrusted_root',
    );
  const leaf = links[0]!;
  for (const wanted of options.requiredScope ?? []) {
    if (!scopeCovers(leaf.scope, wanted))
      throw new CredentialError(`the delegation doesn't cover ${wanted}`, 'insufficient_scope');
  }
  return {
    chain: {
      root,
      delegate: leaf.sub,
      delegateKind: leaf.delegateKind,
      scope: leaf.scope,
      expiresAt: links.map((l) => l.expiresAt).sort()[0]!,
      links,
    },
    leaf: verified[0]!,
  };
}
