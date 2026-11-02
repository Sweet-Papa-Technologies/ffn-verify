import { didWebForOrigin, type Fetch } from '@fofonet/door-core';
import type { TxtResolver } from './dns.js';
import { verifyPresentation, type PresentationResult } from './presentation.js';
import {
  verifyBusiness,
  type BusinessVerification,
  type Observed,
  type RegistryAnchor,
} from './verify.js';

// The agent surface's two verifications, taking the arguments exactly as agents
// send them. The MCP server's tools and the registry's /v1 HTTP endpoints both
// call these, so the same question gets the same answer either way.

export interface AgentDeps {
  /** The registry the caller already trusts; never one an argument names. */
  registry: RegistryAnchor;
  fetch?: Fetch;
  dns?: TxtResolver;
  /** Seconds since epoch, for tests. */
  now?: number;
  /** Total time per HTTP request, in milliseconds (default 10 000). */
  timeoutMs?: number;
  /** Aborts every request. */
  signal?: AbortSignal;
}

const limitsOf = (deps: AgentDeps) => ({
  ...(deps.timeoutMs !== undefined ? { timeoutMs: deps.timeoutMs } : {}),
  ...(deps.signal ? { signal: deps.signal } : {}),
});

export interface VerifyBusinessArgs {
  domain?: string;
  phone?: string;
  observed_name?: string;
  observed_phone?: string;
  observed_address?: string;
}

/** verify_business / GET /v1/verify. A domain wins when both are given. */
export function verifyBusinessFor(
  args: VerifyBusinessArgs,
  deps: AgentDeps,
): Promise<BusinessVerification> {
  if (!args.domain && !args.phone) throw new Error('Give a domain or a phone number.');
  const observed: Observed = {
    ...(args.observed_name ? { name: args.observed_name } : {}),
    ...(args.observed_phone ? { phone: args.observed_phone } : {}),
    ...(args.observed_address ? { address: args.observed_address } : {}),
  };
  return verifyBusiness(args.domain ? { domain: args.domain } : { phone: args.phone! }, {
    registry: deps.registry,
    ...(deps.fetch ? { fetch: deps.fetch } : {}),
    ...(deps.dns ? { dns: deps.dns } : {}),
    ...(deps.now !== undefined ? { now: deps.now } : {}),
    ...(Object.keys(observed).length ? { observed } : {}),
    ...limitsOf(deps),
  });
}

export interface VerifyPresentationArgs {
  presentation: string;
  chain?: string[];
  nonce: string;
  audience: string;
  roots?: string[];
  required_scope?: string[];
  issuers?: string[];
}

/** verify_presentation / POST /v1/verify-presentation. Issuers default to the registry. */
export function verifyPresentationFor(
  args: VerifyPresentationArgs,
  deps: AgentDeps,
): Promise<PresentationResult> {
  const registryDid = deps.registry.did ?? didWebForOrigin(deps.registry.origin);
  return verifyPresentation(
    {
      presentation: args.presentation,
      nonce: args.nonce,
      audience: args.audience,
      ...(args.chain ? { chain: args.chain } : {}),
      ...(args.roots ? { roots: args.roots } : {}),
      ...(args.required_scope ? { requiredScope: args.required_scope } : {}),
      issuers: args.issuers ?? [registryDid],
    },
    {
      ...(deps.fetch ? { fetch: deps.fetch } : {}),
      // A credential the registry issued counts only under a key the caller pins.
      registry: deps.registry,
      ...(deps.now !== undefined ? { now: deps.now } : {}),
      ...limitsOf(deps),
    },
  );
}

/** One plain sentence for a presentation result (the MCP tool's text). */
export function presentationSentence(r: PresentationResult): string {
  return r.verified
    ? r.delegation
      ? `Verified: ${r.subject} may ${r.delegation.scope.join(', ')} on behalf of ${r.delegation.root} until ${r.delegation.expiresAt}.`
      : `Verified: ${r.subject} presented a current credential from ${r.issuer}.`
    : `Not verified (${r.code}): ${r.message}`;
}
