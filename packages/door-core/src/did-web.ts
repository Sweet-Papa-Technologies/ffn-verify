import { isDidJwk, resolveDidJwk } from './did-jwk.js';
import { jwkThumbprint, type Jwk } from './jose.js';
import { FetchError, FetchLimits, fetchBounded } from './net.js';
import { knownRegistryPins } from './networks.js';

// did:web resolution (FFN v1 doc, "Issuer identity": verifiers resolve it with
// one HTTPS fetch). https://w3c-ccg.github.io/did-method-web/
//
// The resolver also answers did:jwk locally, so callers holding a person's or a
// key-only business's DID use the same API.

export interface DidService {
  id: string;
  type: string | string[];
  serviceEndpoint: string | string[] | Record<string, unknown>;
}

export type VerificationRelationship =
  | 'assertionMethod'
  | 'authentication'
  | 'capabilityDelegation'
  | 'capabilityInvocation';

export interface DidDocument {
  '@context'?: unknown;
  id: string;
  /** For an agent: the DID of the business or person that runs it. */
  controller?: string | string[];
  /** Other DIDs for the same subject, e.g. a business's primary domain DID on a secondary domain. */
  alsoKnownAs?: string[];
  verificationMethod?: Array<{ id: string; type: string; controller: string; publicKeyJwk?: Jwk }>;
  assertionMethod?: Array<string | { id: string }>;
  authentication?: Array<string | { id: string }>;
  capabilityDelegation?: Array<string | { id: string }>;
  capabilityInvocation?: Array<string | { id: string }>;
  service?: DidService[];
}

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

/** did:web:pass.fofo.network → https://pass.fofo.network/.well-known/did.json */
export function didWebUrl(did: string): string {
  if (!did.startsWith('did:web:')) throw new Error(`not a did:web: ${did}`);
  const [host, ...path] = did.slice('did:web:'.length).split(':');
  if (!host) throw new Error(`malformed did:web: ${did}`);
  const decoded = decodeURIComponent(host);
  // Only a port may be percent-encoded into the host; anything that changes the URL's shape is refused.
  if (/[/?#@\\\s]/.test(decoded) || path.some((p) => /[/?#@\\\s]/.test(decodeURIComponent(p))))
    throw new Error(`malformed did:web: ${did}`);
  const origin = `https://${decoded}`;
  return path.length === 0
    ? `${origin}/.well-known/did.json`
    : `${origin}/${path.map(decodeURIComponent).join('/')}/did.json`;
}

/** The host a did:web lives on (decoded), e.g. did:web:example.com:agents:booking → example.com */
export function didWebHost(did: string): string {
  if (!did.startsWith('did:web:')) throw new Error(`not a did:web: ${did}`);
  return decodeURIComponent(did.slice('did:web:'.length).split(':')[0]!.split('#')[0]!);
}

/** Inverse of didWebUrl for an origin with no path: https://pass.fofo.network → did:web:pass.fofo.network */
export function didWebForOrigin(origin: string): string {
  const url = new URL(origin);
  return `did:web:${encodeURIComponent(url.host)}`;
}

export function buildDidDocument(
  did: string,
  keys: Array<{ kid: string; publicJwk: Jwk }>,
): DidDocument {
  const methods = keys.map(({ kid, publicJwk }) => ({
    id: kid.startsWith('did:') ? kid : `${did}#${kid}`,
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyJwk: publicJwk,
  }));
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod: methods,
    assertionMethod: methods.map((m) => m.id),
  };
}

export interface DidResolverOptions {
  fetch?: Fetch;
  /** Cache lifetime in seconds (default 3600). */
  ttlSeconds?: number;
  /** Pre-resolved documents, consulted before any fetch (tests, pinned issuers). */
  documents?: Record<string, DidDocument>;
  /** Largest DID document accepted, in bytes (default 64 KiB). Business hosts are untrusted. */
  maxBytes?: number;
  /** How long past its ttl a cached document may stand in for an unreachable host (default 1 day). */
  maxStaleSeconds?: number;
  /** Total time per fetch, body included, in milliseconds (default 10 000). */
  timeoutMs?: number;
  /** Aborts every fetch this resolver makes. */
  signal?: AbortSignal;
}

/**
 * Why a DID didn't resolve. `reason` is for callers that act on it: a host
 * that answered 4xx (`not_found`) or served another DID's document
 * (`mismatch`) has given an answer; the rest are failures to get one. The
 * message never repeats what the host answered.
 */
export class DidResolutionError extends Error {
  constructor(
    readonly did: string,
    readonly reason: 'not_found' | 'mismatch' | 'invalid' | 'refused' | 'unreachable',
    detail: string,
  ) {
    super(`could not resolve ${did}: ${detail}`);
    this.name = 'DidResolutionError';
  }
}

const ids = (list: unknown) =>
  new Set(
    (Array.isArray(list) ? list : [])
      .map((m: unknown) =>
        typeof m === 'string' ? m : (m as { id?: unknown } | null | undefined)?.id,
      )
      .filter((id): id is string => typeof id === 'string'),
  );

type Method = NonNullable<DidDocument['verificationMethod']>[number];

/** The document's verification methods, ignoring anything that isn't one. */
const methodsOf = (doc: DidDocument): Method[] =>
  (Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []).filter(
    (m): m is Method =>
      typeof m === 'object' && m !== null && typeof m.id === 'string' && !!m.publicKeyJwk,
  );

/**
 * A known FFN registry DID (networks.ts) keeps only the keys pinned for it,
 * whichever resolver or API asked: a key added to its did.json by someone who
 * reached the registry's host signs nothing. Other DIDs are returned unchanged.
 */
export async function applyKnownRegistryPins(did: string, doc: DidDocument): Promise<DidDocument> {
  const pins = knownRegistryPins(did);
  if (!pins) return doc;
  const kept: Method[] = [];
  for (const m of methodsOf(doc)) {
    const pinned = await jwkThumbprint(m.publicKeyJwk!).then(
      (t) => pins.includes(t),
      () => false,
    );
    if (pinned) kept.push(m);
  }
  return { ...doc, verificationMethod: kept };
}

export class DidWebResolver {
  private readonly cache = new Map<string, { doc: DidDocument; until: number }>();
  private readonly fetchFn: Fetch;
  private readonly ttl: number;
  private readonly pinned: Record<string, DidDocument>;
  private readonly maxBytes: number;
  private readonly maxStale: number;
  private readonly timeoutMs: number | undefined;
  private readonly signal: AbortSignal | undefined;

  constructor(options: DidResolverOptions = {}) {
    this.fetchFn = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.ttl = (options.ttlSeconds ?? 3600) * 1000;
    this.pinned = options.documents ?? {};
    this.maxBytes = options.maxBytes ?? FetchLimits.didDocument;
    this.maxStale = (options.maxStaleSeconds ?? 86_400) * 1000;
    this.timeoutMs = options.timeoutMs;
    this.signal = options.signal;
  }

  async resolve(did: string): Promise<DidDocument> {
    return applyKnownRegistryPins(did, await this.document(did));
  }

  private async document(did: string): Promise<DidDocument> {
    if (isDidJwk(did)) return resolveDidJwk(did);
    const pinned = this.pinned[did];
    if (pinned) return pinned;
    const hit = this.cache.get(did);
    if (hit && hit.until > Date.now()) return hit.doc;
    let url: string;
    try {
      url = didWebUrl(did);
    } catch (err) {
      throw new DidResolutionError(did, 'invalid', (err as Error).message);
    }
    try {
      // No redirects: a did:web is the document at exactly this URL.
      const { text } = await fetchBounded(this.fetchFn, url, {
        maxBytes: this.maxBytes,
        headers: { accept: 'application/did+json, application/json' },
        ...(this.timeoutMs !== undefined ? { timeoutMs: this.timeoutMs } : {}),
        ...(this.signal ? { signal: this.signal } : {}),
      });
      let doc: DidDocument;
      try {
        doc = JSON.parse(text) as DidDocument;
      } catch {
        throw new DidResolutionError(did, 'invalid', 'the DID document is not JSON');
      }
      if (typeof doc !== 'object' || doc === null || Array.isArray(doc))
        throw new DidResolutionError(did, 'invalid', 'the DID document is not an object');
      if (doc.id !== did)
        throw new DidResolutionError(did, 'mismatch', 'the document id does not match');
      this.cache.set(did, { doc, until: Date.now() + this.ttl });
      return doc;
    } catch (err) {
      // An issuer's host being briefly down must not fail verification of
      // credentials whose key we already know (design principle 1) — for a
      // day, so a key rotated out doesn't live on while the site is down.
      if (hit && Date.now() - hit.until < this.maxStale) return hit.doc;
      if (err instanceof DidResolutionError) throw err;
      if (err instanceof FetchError) {
        if (err.reason === 'refused') throw new DidResolutionError(did, 'refused', err.message);
        if (
          err.reason === 'http' &&
          err.status !== undefined &&
          err.status >= 400 &&
          err.status < 500
        )
          throw new DidResolutionError(did, 'not_found', 'no DID document is published there');
        throw new DidResolutionError(did, 'unreachable', err.message);
      }
      throw new DidResolutionError(did, 'unreachable', 'the host could not be reached');
    }
  }

  /** Find the assertion key named by a JWS `kid` (full DID URL or bare fragment). */
  async assertionKey(did: string, kid: string | undefined): Promise<Jwk> {
    return this.keyFor(did, kid, 'assertionMethod');
  }

  /** The key named by `kid` that `did` lists under `relationship`. */
  async keyFor(
    did: string,
    kid: string | undefined,
    relationship: VerificationRelationship,
  ): Promise<Jwk> {
    if (isDidJwk(did) && kid !== undefined && !kid.startsWith('did:')) kid = `${did}#0`;
    const doc = await this.resolve(did);
    const fullKid =
      kid === undefined
        ? undefined
        : kid.startsWith('did:')
          ? kid
          : `${did}#${kid.replace(/^#/, '')}`;
    if (fullKid && !fullKid.startsWith(`${did}#`)) throw new Error('kid does not belong to issuer');
    const allowed = ids(doc[relationship]);
    const candidates = methodsOf(doc).filter(
      (m) => allowed.has(m.id) && (fullKid === undefined || m.id === fullKid),
    );
    if (candidates.length !== 1)
      throw new Error(`no unique ${relationship} key ${kid ?? ''} in ${did}`);
    return candidates[0]!.publicKeyJwk!;
  }

  /**
   * Does `did` currently list `jwk` under any of `relationships`? This is how a
   * credential bound to a key (cnf) is tied to a DID that can rotate its keys.
   */
  async controlsKey(
    did: string,
    jwk: Jwk,
    relationships: VerificationRelationship[] = ['authentication', 'assertionMethod'],
  ): Promise<boolean> {
    const doc = await this.resolve(did);
    const allowed = new Set(relationships.flatMap((r) => [...ids(doc[r])]));
    const want = await jwkThumbprint(jwk);
    for (const m of methodsOf(doc)) {
      if (!allowed.has(m.id)) continue;
      if ((await jwkThumbprint(m.publicKeyJwk!).catch(() => undefined)) === want) return true;
    }
    return false;
  }
}

/** Every DID method the Door SDK resolves: did:web over HTTPS, did:jwk locally. */
export { DidWebResolver as DidResolver };
