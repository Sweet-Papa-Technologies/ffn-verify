import {
  AttestationKinds,
  BUSINESS_RECORD_TYP,
  BusinessKindLabels,
  BusinessKinds,
  CredentialError,
  DidResolver,
  FetchError,
  FetchLimits,
  LevelNames,
  REGISTRY_SCOPES,
  StatusChecker,
  alsoKnownAsOf,
  assertFetchableUrl,
  businessKindForVct,
  decodeJwt,
  didWebForOrigin,
  didWebHost,
  fetchBounded,
  ffnTxtName,
  isDidJwk,
  jwkOfDidJwk,
  levelFor,
  nameKey,
  normalizeDomain,
  normalizePhone,
  parseFfnTxt,
  registryEntriesOf,
  sameKey,
  verifyCredential,
  verifyDelegationChain,
  verifyJwt,
  type AttestationKind,
  type BusinessLevel,
  type BusinessProfileClaims,
  type BusinessRecordPayload,
  type CheckEntry,
  type DidDocument,
  type Fetch,
  type KvStore,
  type RecordScope,
  type RevocationReason,
  type StatusReference,
} from '@fofonet/door-core';
import { dohResolver, type TxtResolver } from './dns.js';
import { pinRegistryKeys } from './pin.js';

// verifyBusiness(domain) — the wallet-free public verifier (plan, "How an
// agent verifies"):
//
//   1. Ask the registry the agent already knows, by domain. Never a registry
//      URL the site supplies: a page saying it is verified is only a claim.
//   2. Check the registry's signature on the record, the business's signature
//      on its profile and delegation, and SPT's signature on each attestation,
//      then each one's status.
//   3. Confirm the domain binding: the DID document and DNS record on the
//      domain point back to this registry entry. A lookalike fails here.
//   4. Compare what the agent sees (name, phone, address) against the record.
//   5. Report what was verified and when, in plain words.

export interface RegistryAnchor {
  /** The registry's origin, e.g. https://registry.example. Pinned in the agent's config. */
  origin: string;
  /** Its DID (default did:web of the origin's host). */
  did?: string;
  /** Who runs it, for the summary (e.g. "Sweet Papa Technologies LLC"). */
  name?: string;
  /**
   * RFC 7638 thumbprints of the registry keys to accept (FFN_BUSINESS_REGISTRY
   * pins the production registry's). Anything the registry signs with another
   * key fails, even if its did.json lists that key. Absent: no pin.
   */
  keyThumbprints?: string[];
}

export interface Observed {
  name?: string;
  phone?: string;
  /** Free text, e.g. "123 Main St, Oakland, CA 94607". */
  address?: string;
}

export interface VerifyBusinessOptions {
  /** The registry you trust. Its origin must be https: (http: only on a loopback host, for local testing). */
  registry: RegistryAnchor;
  fetch?: Fetch;
  dns?: TxtResolver;
  resolver?: DidResolver;
  /** Last-good status list cache (default in-memory). */
  store?: KvStore;
  /** Seconds since epoch (default now). For test vectors. */
  now?: number;
  observed?: Observed;
  /**
   * Total time per HTTP request the verifier makes (connect, headers and body),
   * in milliseconds. Default 10 000. Also applies through a `fetch` you supply.
   */
  timeoutMs?: number;
  /** Aborts every request; verifyBusiness then rejects with the signal's reason. */
  signal?: AbortSignal;
}

export type FactStatus = 'valid' | 'expired' | 'revoked' | 'suspended' | 'unknown' | 'invalid';

export interface VerifiedFact {
  kind: AttestationKind;
  label: string;
  status: FactStatus;
  issuer: string;
  /** The attested facts (evidence and JWT structure removed). */
  claims: Record<string, unknown>;
  checks: CheckEntry[];
  issuedAt?: string;
  expiresAt?: string;
  reason?: RevocationReason;
  /** One sentence, e.g. "CSLB license 1000003 (C-20) is active until Jan 31, 2027 (checked Nov 1, 2026)." */
  sentence: string;
}

export type BindingStatus = 'confirmed' | 'dns-only' | 'missing' | 'mismatch' | 'unreachable';

export interface BusinessVerification {
  verified: boolean;
  domain: string;
  /** The number asked about, when the query was by phone. `domain` is then the business's primary domain. */
  phone?: string;
  level: BusinessLevel;
  levelName: string;
  /** `name` is what the business calls itself; `legalName` is what SPT verified, when it did. */
  business?: {
    did: string;
    recordId: string;
    profileUrl: string;
    legalName?: string;
  } & BusinessProfileClaims;
  facts: VerifiedFact[];
  binding: {
    status: BindingStatus;
    didDocument: boolean;
    dnsTxt: boolean;
    lowerAssurance: boolean;
  };
  delegation: { valid: boolean; expiresAt?: string };
  /**
   * What the registry asserts about this business and what it never does, from
   * the signed record. `asserts` keeps only what a currently valid attestation
   * backs. Absent when the record predates the field, or verification stopped
   * before the attestations were checked.
   */
  scope?: RecordScope;
  mismatches: string[];
  /**
   * Whether what you observed (`observed` name, phone, address) matches the
   * record: true exactly when `mismatches` is empty. Always present (true when
   * nothing was observed, or verification stopped before comparing). Rely on a
   * business only when both `verified` and `observedMatches` are true.
   */
  observedMatches: boolean;
  warnings: string[];
  failure?: { code: string; message: string };
  summary: string;
  checkedAt: string;
}

class Stop extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

const STRUCTURAL = new Set([
  'iss',
  'iat',
  'nbf',
  'exp',
  'sub',
  'jti',
  'vct',
  'cnf',
  'status',
  '_sd_alg',
  'evidence',
]);

function isAttestationCredential(compact: string): boolean {
  try {
    const vct = decodeJwt<{ vct?: string }>(compact.split('~')[0]!).payload.vct;
    return (AttestationKinds as readonly string[]).includes(businessKindForVct(String(vct)) ?? '');
  } catch {
    // undecodable: reported as an invalid fact
    return true;
  }
}

const article = (word: string) => (/^[aeiou]/i.test(word) ? 'An' : 'A');

function day(iso: string | undefined): string {
  if (!iso) return 'an unknown date';
  const d = new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso);
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    timeZone: 'UTC',
  });
}

function lastChecked(checks: CheckEntry[]): string | undefined {
  return checks
    .filter((c) => c.result === 'pass' && c.checkedAt)
    .map((c) => c.checkedAt!)
    .sort()
    .pop();
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- claims were verified; shapes per kind
function sentenceFor(kind: AttestationKind, c: Record<string, any>, checks: CheckEntry[]): string {
  const when = `checked ${day(lastChecked(checks))}`;
  switch (kind) {
    case 'businessIdentity':
      return `${c.legalName} is an active ${c.entityType ? `${c.entityType} ` : ''}entity in ${c.jurisdiction}, number ${c.entityNumber} (${when}).`;
    case 'officialChannels':
      return `It controls ${[...(c.domains ?? []), ...(c.phones ?? [])].join(', ')} (${when}).`;
    case 'license': {
      const classes = (c.classes ?? []).map((k: { code: string }) => k.code).join(', ');
      return `${c.board} license ${c.licenseNumber}${classes ? ` (${classes})` : ''} is active until ${day(c.expiresOn)} (${when}).`;
    }
    case 'insurance':
      const coverage = String(c.coverageType).replace(/-/g, ' ');
      return `${coverage.charAt(0).toUpperCase()}${coverage.slice(1)} insurance with ${c.carrier} runs until ${day(c.expiresOn)} (${when}).`;
    case 'representative':
      return `A person verified with an FFN person pass is authorized to act for it as ${String(c.role).replace(/-/g, ' ')} (${when}).`;
  }
}

interface Limits {
  timeoutMs?: number;
  signal?: AbortSignal;
}

const limitsOf = (o: { timeoutMs?: number; signal?: AbortSignal }): Limits => ({
  ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}),
  ...(o.signal ? { signal: o.signal } : {}),
});

/** The registry origin must be https: (http: only on loopback, for local testing). Throws otherwise. */
function checkRegistryOrigin(anchor: RegistryAnchor): void {
  try {
    assertFetchableUrl(anchor.origin, true);
  } catch (err) {
    throw new Error(`registry origin ${anchor.origin} refused: ${(err as Error).message}`);
  }
}

/** Fetch the record for a domain or phone from the pinned registry (1 MiB at most). */
async function fetchRecord(
  anchor: RegistryAnchor,
  query: { domain?: string; phone?: string },
  fetchFn: Fetch,
  limits: Limits,
) {
  const params = new URLSearchParams(
    query.domain ? { domain: query.domain } : { phone: query.phone! },
  );
  try {
    const { text } = await fetchBounded(
      fetchFn,
      `${anchor.origin.replace(/\/$/, '')}/v1/lookup?${params}`,
      {
        maxBytes: FetchLimits.registryResponse,
        headers: { accept: 'application/ffn-business-record+jwt' },
        trustedOrigin: true,
        ...limits,
      },
    );
    return text.trim();
  } catch (err) {
    const reason = err instanceof FetchError ? err.reason : 'network';
    if (reason === 'http' && (err as FetchError).status === 404) return undefined;
    // The registry is the one host this verifier trusts, so its status may be repeated.
    if (reason === 'http')
      throw new Stop(
        'registry_unavailable',
        `the registry answered HTTP ${(err as FetchError).status}`,
      );
    throw new Stop(
      'registry_unavailable',
      reason === 'timeout'
        ? 'the registry did not answer in time'
        : reason === 'too_large'
          ? 'the registry answer was too large'
          : reason === 'redirect'
            ? 'the registry answered with a redirect, which is not followed'
            : 'the registry could not be reached',
    );
  }
}

/** Verify the registry's signature on a record. */
async function openRecord(
  jwt: string,
  registryDid: string,
  resolver: DidResolver,
  now: number,
): Promise<BusinessRecordPayload> {
  let header: Record<string, unknown>;
  try {
    ({ header } = decodeJwt(jwt));
  } catch {
    throw new Stop('bad_record', 'the registry record is malformed');
  }
  let key;
  try {
    key = await resolver.assertionKey(registryDid, header.kid as string | undefined);
  } catch (err) {
    throw new Stop(
      'bad_record',
      `the registry key could not be resolved: ${(err as Error).message}`,
    );
  }
  try {
    const { payload } = await verifyJwt<BusinessRecordPayload & Record<string, unknown>>(jwt, key, {
      typ: BUSINESS_RECORD_TYP,
      now,
    });
    if (payload.iss !== registryDid) throw new Error('issued by someone else');
    return payload;
  } catch (err) {
    throw new Stop(
      'bad_record',
      `the registry record failed verification: ${(err as Error).message}`,
    );
  }
}

export interface LookupResult {
  found: boolean;
  /** Registry-signed, but binding, profile and attestation signatures NOT yet checked. Call verifyBusiness. */
  record?: Pick<
    BusinessRecordPayload,
    'sub' | 'recordId' | 'domains' | 'phones' | 'level' | 'profileUrl' | 'updatedAt'
  > & {
    name?: string;
    /** As the record states it (not yet checked against the attestations). */
    scope?: RecordScope;
  };
}

/** Look a business up by domain or phone. Only the registry's signature is checked. */
export async function lookupBusiness(
  query: { domain?: string; phone?: string },
  options: Pick<
    VerifyBusinessOptions,
    'registry' | 'fetch' | 'resolver' | 'now' | 'timeoutMs' | 'signal'
  >,
): Promise<LookupResult> {
  checkRegistryOrigin(options.registry);
  const fetchFn = options.fetch ?? ((i, init) => globalThis.fetch(i, init));
  const limits = limitsOf(options);
  const registryDid = options.registry.did ?? didWebForOrigin(options.registry.origin);
  const resolver = pinRegistryKeys(
    options.resolver ?? new DidResolver({ fetch: fetchFn, ...limits }),
    registryDid,
    options.registry.keyThumbprints,
  );
  const q = query.domain
    ? { domain: normalizeDomain(query.domain) }
    : { phone: normalizePhone(query.phone ?? '') };
  const jwt = await fetchRecord(options.registry, q, fetchFn, limits);
  if (!jwt) return { found: false };
  const rec = await openRecord(
    jwt,
    registryDid,
    resolver,
    options.now ?? Math.floor(Date.now() / 1000),
  );
  // A record that doesn't list what was asked for is not an answer to the question.
  if (q.domain ? !rec.domains.includes(q.domain) : !rec.phones.includes(q.phone ?? ''))
    return { found: false };
  let name: string | undefined;
  try {
    name = decodeJwt<{ name?: string }>(rec.profile.split('~')[0]!).payload.name;
  } catch {
    // reported without a name
  }
  return {
    found: true,
    record: {
      sub: rec.sub,
      recordId: rec.recordId,
      domains: rec.domains,
      phones: rec.phones,
      level: rec.level,
      profileUrl: rec.profileUrl,
      updatedAt: rec.updatedAt,
      ...(name ? { name } : {}),
      ...(isScope(rec.scope) ? { scope: rec.scope } : {}),
    },
  };
}

/** What to verify: a domain, or a phone number the business published. */
export type BusinessQuery = string | { domain: string } | { phone: string };

/** The domain a record answers for by default: its profile page's, else the first it lists. */
function primaryDomain(record: BusinessRecordPayload): string {
  const domains: unknown[] = Array.isArray(record.domains) ? record.domains : [];
  const fromProfile =
    String(record.profileUrl ?? '')
      .split('/')
      .pop() ?? '';
  if (domains.includes(fromProfile)) return fromProfile;
  if (typeof domains[0] !== 'string')
    throw new Stop('domain_not_listed', 'the record lists no domain');
  return domains[0];
}

export async function verifyBusiness(
  query: BusinessQuery,
  options: VerifyBusinessOptions,
): Promise<BusinessVerification> {
  const q = typeof query === 'string' ? { domain: query } : query;
  const given = q as { domain?: unknown; phone?: unknown };
  if ((given.domain === undefined) === (given.phone === undefined))
    throw new TypeError('verifyBusiness needs a domain or a phone number, not both');
  const askedPhone = given.phone !== undefined ? (q as { phone: string }).phone : undefined;
  const askedDomain = askedPhone === undefined ? (q as { domain: string }).domain : undefined;
  const anchor = options.registry;
  checkRegistryOrigin(anchor);
  options.signal?.throwIfAborted();
  const fetchFn = options.fetch ?? ((i, init) => globalThis.fetch(i, init));
  const limits = limitsOf(options);
  const registryDid = anchor.did ?? didWebForOrigin(anchor.origin);
  const resolver = pinRegistryKeys(
    options.resolver ?? new DidResolver({ fetch: fetchFn, ttlSeconds: 300, ...limits }),
    registryDid,
    anchor.keyThumbprints,
  );
  const nowSec = options.now ?? Math.floor(Date.now() / 1000);
  const status = new StatusChecker({
    resolver,
    fetch: fetchFn,
    ...(options.store ? { store: options.store } : {}),
    now: () => nowSec,
    ...limits,
  });
  const dns = options.dns ?? dohResolver('cloudflare', fetchFn, limits);
  const registryName = anchor.name ?? 'The registry';

  const out: BusinessVerification = {
    verified: false,
    domain: askedDomain ?? '',
    ...(askedPhone !== undefined ? { phone: askedPhone } : {}),
    level: 0,
    levelName: LevelNames[0],
    facts: [],
    binding: { status: 'missing', didDocument: false, dnsTxt: false, lowerAssurance: false },
    delegation: { valid: false },
    mismatches: [],
    observedMatches: true,
    warnings: [],
    summary: '',
    checkedAt: new Date(nowSec * 1000).toISOString(),
  };

  try {
    let domain: string;
    let phone: string | undefined;
    let record: BusinessRecordPayload;
    if (askedPhone !== undefined) {
      try {
        phone = normalizePhone(askedPhone);
      } catch (err) {
        throw new Stop('bad_phone', (err as Error).message);
      }
      out.phone = phone;
      // 1–2. The record, from the registry we already trust; then its domain, as for a domain query.
      const jwt = await fetchRecord(anchor, { phone }, fetchFn, limits);
      if (!jwt) throw new Stop('not_in_registry', `${phone} is not in the registry`);
      record = await openRecord(jwt, registryDid, resolver, nowSec);
      if (!Array.isArray(record.phones) || !record.phones.includes(phone))
        throw new Stop('phone_not_listed', `the record does not list ${phone}`);
      domain = primaryDomain(record);
      out.domain = domain;
    } else {
      try {
        domain = normalizeDomain(askedDomain!);
      } catch (err) {
        throw new Stop('bad_domain', (err as Error).message);
      }
      out.domain = domain;

      // 1–2. The record, from the registry we already trust.
      const jwt = await fetchRecord(anchor, { domain }, fetchFn, limits);
      if (!jwt) throw new Stop('not_in_registry', `${domain} is not in the registry`);
      record = await openRecord(jwt, registryDid, resolver, nowSec);
      if (!Array.isArray(record.domains) || !record.domains.includes(domain))
        throw new Stop('domain_not_listed', `the record does not list ${domain}`);
    }
    const did = record.sub;

    // 3. The domain binding, first: it fetches the DID document the signatures below need,
    // so a site that is down reads as "can't check right now", not as a bad signature.
    out.binding = await checkBinding(
      domain,
      did,
      record.recordId,
      anchor,
      resolver,
      dns,
      out.warnings,
    );
    if (out.binding.status === 'mismatch' || out.binding.status === 'missing')
      throw new Stop('binding_failed', `${domain} does not point back to this registry entry`);
    if (out.binding.status === 'unreachable')
      throw new Stop(
        'binding_unreachable',
        `the binding on ${domain} could not be checked right now`,
      );

    // The business's own signature on its profile (whose issuer is checked before it is resolved).
    let profile: BusinessProfileClaims;
    try {
      if (claimedIssuer(record.profile) !== did) throw new Error('not this business’s profile');
      const v = await verifyCredential(record.profile, { resolver, now: nowSec });
      if (v.iss !== did || v.vct !== BusinessKinds.businessProfile)
        throw new Error('not this business’s profile');
      profile = v.claims as unknown as BusinessProfileClaims;
    } catch (err) {
      throw new Stop(
        'bad_profile',
        `the business profile failed verification: ${(err as Error).message}`,
      );
    }
    out.business = {
      did,
      recordId: record.recordId,
      profileUrl: record.profileUrl,
      ...pickProfile(profile),
    };
    if (!profile.domains?.includes(domain))
      out.warnings.push(`The business's own profile does not list ${domain}.`);

    // The delegation that lets the registry publish and serve this record.
    try {
      const chain = await verifyDelegationChain([record.delegation], {
        resolver,
        status,
        now: nowSec,
        roots: [did],
        requiredScope: [...REGISTRY_SCOPES],
      });
      if (chain.delegate !== registryDid) throw new Error('it delegates to someone else');
      out.delegation = { valid: true, expiresAt: chain.expiresAt };
    } catch (err) {
      throw new Stop(
        'delegation_invalid',
        `the business has not delegated publication to this registry: ${(err as Error).message}`,
      );
    }

    // SPT's attestations.
    const revocations = new Map(record.revocations.map((r) => [r.jti, r]));
    for (const compact of record.attestations) {
      if (!isAttestationCredential(compact)) {
        out.warnings.push(
          'The record carries a credential that is not an attestation; it was ignored.',
        );
        continue;
      }
      out.facts.push(
        await checkAttestation(compact, did, registryDid, resolver, status, nowSec, revocations),
      );
    }
    const valid = new Set(out.facts.filter((f) => f.status === 'valid').map((f) => f.kind));
    const channels = out.facts.find((f) => f.kind === 'officialChannels' && f.status === 'valid');
    if (channels && !(channels.claims.domains as string[] | undefined)?.includes(domain)) {
      valid.delete('officialChannels');
      out.warnings.push(`${domain} is not among the domains SPT confirmed.`);
    }
    if (channels && phone && !(channels.claims.phones as string[] | undefined)?.includes(phone)) {
      valid.delete('officialChannels');
      out.warnings.push(`${phone} is not among the phone numbers SPT confirmed.`);
    }
    for (const f of out.facts.filter((f) => f.status === 'unknown'))
      out.warnings.push(
        `The status of the ${f.label.toLowerCase()} credential could not be checked, so it is not counted.`,
      );
    out.level = levelFor(valid);
    out.levelName = LevelNames[out.level];
    const legal = out.facts.find((f) => f.kind === 'businessIdentity' && f.status === 'valid')
      ?.claims.legalName;
    if (typeof legal === 'string') {
      out.business.legalName = legal;
      if (nameKey(legal) !== nameKey(profile.name))
        out.warnings.push(
          `It calls itself "${profile.name}"; its verified legal name is "${legal}".`,
        );
    }
    if (out.level !== record.level)
      out.warnings.push(
        `The registry lists Level ${record.level}; the credentials support Level ${out.level}.`,
      );

    // 4. What the agent sees versus the record.
    if (options.observed) compare(options.observed, profile, out);

    out.verified = out.level >= 1;
    if (!out.verified)
      out.failure = { code: 'not_verified', message: 'no current attestation supports Level 1' };
    // Nothing is asserted about a business that doesn't reach Level 1 here.
    const scope = verifiedScope(record.scope, out.verified ? valid : new Set(), channels);
    if (scope) out.scope = scope;
  } catch (err) {
    if (!(err instanceof Stop)) throw err;
    out.failure = { code: err.code, message: err.message };
    out.verified = false;
    out.level = 0;
    out.levelName = LevelNames[0];
  }
  options.signal?.throwIfAborted();
  out.observedMatches = out.mismatches.length === 0;
  out.summary = summarize(out, registryName);
  return out;
}

/** The issuer a credential names, before anything is verified (undefined when unreadable). */
function claimedIssuer(compact: string): unknown {
  try {
    return decodeJwt<{ iss?: unknown }>(compact.split('~')[0]!).payload.iss;
  } catch {
    return undefined;
  }
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** A scope a record can carry: an object with a string explanation (older records have none). */
function isScope(v: unknown): v is RecordScope {
  return isObject(v) && typeof v.explanation === 'string';
}

/**
 * The record's scope, held to what verified: an assertion stays only while a
 * valid attestation of its kind counts (phone control also needs a confirmed
 * phone). The disclaimers stand as the registry signed them.
 */
function verifiedScope(
  scope: unknown,
  valid: ReadonlySet<string>,
  channels: VerifiedFact | undefined,
): RecordScope | undefined {
  if (!isScope(scope)) return undefined;
  const entries = (list: unknown) =>
    (Array.isArray(list) ? list : []).filter(
      (e): e is Record<string, string> =>
        isObject(e) && typeof e.code === 'string' && typeof e.statement === 'string',
    );
  const phones = channels?.claims.phones;
  const asserts = entries(scope.asserts)
    .filter((a) => typeof a.kind === 'string' && valid.has(a.kind))
    .filter((a) => a.code !== 'phone-control' || (Array.isArray(phones) && phones.length > 0))
    .map(({ code, kind, statement }) => ({ code, kind, statement }));
  const doesNotAssert = entries(scope.doesNotAssert).map(({ code, statement }) => ({
    code,
    statement,
  }));
  return {
    asserts,
    doesNotAssert,
    explanation: scope.explanation,
  } as RecordScope;
}

function pickProfile(p: BusinessProfileClaims): BusinessProfileClaims {
  const { name, dba, domains, phones, hours, address, serviceArea, categories } = p;
  return Object.fromEntries(
    Object.entries({ name, dba, domains, phones, hours, address, serviceArea, categories }).filter(
      ([, v]) => v !== undefined,
    ),
  ) as unknown as BusinessProfileClaims;
}

async function checkBinding(
  domain: string,
  did: string,
  recordId: string,
  anchor: RegistryAnchor,
  resolver: DidResolver,
  dns: TxtResolver,
  warnings: string[],
): Promise<BusinessVerification['binding']> {
  const registryHost = new URL(anchor.origin).host;
  const pointsHere = (entry: string) => {
    try {
      const u = new URL(entry);
      return u.host === registryHost && u.pathname.split('/').includes(recordId);
    } catch {
      return false;
    }
  };

  // DNS: _ffn.<domain> TXT naming this DID and this registry.
  let dnsTxt = false;
  let dnsMismatch = false;
  try {
    const txts = (await dns.txt(ffnTxtName(domain)))
      .map(parseFfnTxt)
      .filter((t) => t !== undefined);
    dnsTxt = txts.some((t) => t.did === did && t.registry === registryHost);
    dnsMismatch = !dnsTxt && txts.length > 0;
  } catch {
    warnings.push(`DNS for ${domain} could not be checked.`);
  }
  if (dnsMismatch)
    return { status: 'mismatch', didDocument: false, dnsTxt: false, lowerAssurance: false };

  // Key-only business: DNS is the whole binding, at lower assurance.
  if (isDidJwk(did)) {
    if (!dnsTxt)
      return { status: 'missing', didDocument: false, dnsTxt: false, lowerAssurance: true };
    warnings.push(
      'This business uses a key-only identifier; its domain binding is DNS only (lower assurance).',
    );
    return { status: 'dns-only', didDocument: false, dnsTxt: true, lowerAssurance: true };
  }

  // did:web: the DID document on the queried domain is the binding.
  let doc: DidDocument;
  try {
    doc = await resolver.resolve(`did:web:${domain}`);
  } catch (err) {
    // A missing document (4xx) or another DID's document is an answer; a failed
    // fetch (network, 5xx, redirect, timeout, too large) is not.
    const reason = (err as { reason?: unknown }).reason;
    const answered =
      typeof reason === 'string'
        ? reason === 'not_found' || reason === 'mismatch'
        : /HTTP 4\d\d|does not match/.test((err as Error).message);
    return {
      status: answered ? 'missing' : 'unreachable',
      didDocument: false,
      dnsTxt,
      lowerAssurance: false,
    };
  }
  const isPrimary = didWebHost(did) === domain;
  const sameSubject = isPrimary ? doc.id === did : alsoKnownAsOf(doc).includes(did);
  const entries = registryEntriesOf(doc);
  if (!sameSubject || entries.length === 0)
    return { status: 'missing', didDocument: false, dnsTxt, lowerAssurance: false };
  if (!entries.some(pointsHere))
    return { status: 'mismatch', didDocument: false, dnsTxt, lowerAssurance: false };
  if (!dnsTxt) warnings.push(`${domain} has no _ffn DNS record; the DID document alone binds it.`);
  return { status: 'confirmed', didDocument: true, dnsTxt, lowerAssurance: false };
}

async function checkAttestation(
  compact: string,
  did: string,
  registryDid: string,
  resolver: DidResolver,
  status: StatusChecker,
  now: number,
  revocations: Map<string, { reason: RevocationReason; status: string }>,
): Promise<VerifiedFact> {
  let payload: Record<string, unknown> = {};
  try {
    payload = decodeJwt<Record<string, unknown>>(compact.split('~')[0]!).payload;
  } catch {
    // reported as invalid below
  }
  const anyKind = businessKindForVct(String(payload.vct));
  const isAttestation = (AttestationKinds as readonly string[]).includes(anyKind ?? '');
  const kind = (isAttestation ? anyKind : 'businessIdentity') as AttestationKind;
  const base = {
    kind,
    label: BusinessKindLabels[kind] ?? 'Attestation',
    issuer: String(payload.iss ?? ''),
    claims: {} as Record<string, unknown>,
    checks: [] as CheckEntry[],
    ...(typeof payload.iat === 'number'
      ? { issuedAt: new Date(payload.iat * 1000).toISOString() }
      : {}),
    ...(typeof payload.exp === 'number'
      ? { expiresAt: new Date(payload.exp * 1000).toISOString() }
      : {}),
  };
  const invalid = (why: string): VerifiedFact => ({
    ...base,
    status: 'invalid',
    sentence: `${article(base.label)} ${base.label.toLowerCase()} credential is invalid: ${why}.`,
  });

  if (!isAttestation) return invalid('not an attestation');
  // Only the registry issues attestations: anyone else's isn't resolved at all.
  if (payload.iss !== registryDid) return invalid('issued by someone other than the registry');
  let v;
  try {
    v = await verifyCredential(compact, { resolver, now });
  } catch (err) {
    if (err instanceof CredentialError && err.code === 'expired')
      return {
        ...base,
        status: 'expired',
        sentence: `The ${base.label.toLowerCase()} credential expired on ${day(base.expiresAt)}.`,
      };
    return invalid((err as Error).message);
  }
  if (v.iss !== registryDid) return invalid('issued by someone other than the registry');
  if (v.claims.sub !== did) return invalid('issued about a different business');
  // Bound to a key the business still lists: a rotated-out key means a stale attestation.
  const bound = await (
    isDidJwk(did) ? sameKey(jwkOfDidJwk(did), v.cnfJwk) : resolver.controlsKey(did, v.cnfJwk)
  ).catch(() => false);
  if (!bound) return invalid('bound to a key the business no longer lists');

  const checks = ((v.claims.evidence as { checks?: CheckEntry[] } | undefined)?.checks ??
    []) as CheckEntry[];
  const claims = Object.fromEntries(Object.entries(v.claims).filter(([k]) => !STRUCTURAL.has(k)));
  const fact = { ...base, claims, checks };
  const outcome = await status
    .check(v.claims.status as StatusReference, registryDid)
    .catch(() => ({ status: 'unknown' as const }));
  const revoked = revocations.get(String(v.claims.jti));
  // The registry's signed record can withdraw a credential on its own; the
  // status list can too. Either one is enough.
  const listed = revoked ? (revoked.status === 'suspended' ? 'suspended' : 'invalid') : undefined;
  const effective =
    outcome.status === 'invalid' || outcome.status === 'suspended'
      ? outcome.status
      : (listed ?? outcome.status);
  if (effective === 'invalid' || effective === 'suspended') {
    const st: FactStatus = effective === 'invalid' ? 'revoked' : 'suspended';
    return {
      ...fact,
      status: st,
      ...(revoked ? { reason: revoked.reason } : {}),
      sentence: `The ${base.label.toLowerCase()} credential was ${st}${revoked ? ` (${revoked.reason.replace(/-/g, ' ')})` : ''}.`,
    };
  }
  const sentence = sentenceFor(kind, claims, checks);
  return {
    ...fact,
    status: outcome.status,
    sentence:
      outcome.status === 'unknown'
        ? `${sentence.slice(0, -1)}, but its current status could not be checked.`
        : sentence,
  };
}

function compare(observed: Observed, profile: BusinessProfileClaims, out: BusinessVerification) {
  if (observed.name) {
    const seen = nameKey(observed.name);
    const legal = out.business?.legalName;
    // Only the legal name was verified; the profile name and DBAs are the business's own words.
    const stated = [profile.name, ...(profile.dba ?? [])].map(nameKey);
    if (legal && nameKey(legal) === seen) {
      // matches what SPT verified
    } else if (stated.includes(seen)) {
      if (legal)
        out.warnings.push(
          `"${observed.name}" matches only the name the business gives itself, not its verified legal name (${legal}).`,
        );
    } else
      out.mismatches.push(
        `The name "${observed.name}" does not match the record (${legal ?? profile.name}).`,
      );
  }
  if (observed.phone) {
    let phone: string | undefined;
    try {
      phone = normalizePhone(observed.phone);
    } catch {
      out.mismatches.push(`"${observed.phone}" is not a phone number the record could match.`);
    }
    const official = out.facts.find((f) => f.kind === 'officialChannels' && f.status === 'valid')
      ?.claims.phones as string[] | undefined;
    if (phone && !(official ?? profile.phones ?? []).includes(phone))
      out.mismatches.push(`The phone ${phone} is not one of the business's verified numbers.`);
  }
  if (observed.address && profile.address) {
    const seen = observed.address.toLowerCase();
    const a = profile.address;
    const matches = [a.locality, a.postalCode]
      .filter((x): x is string => !!x)
      .every((x) => seen.includes(x.toLowerCase()));
    if (!matches)
      out.mismatches.push(
        `The address "${observed.address}" does not match the record (${a.locality}, ${a.region}).`,
      );
  }
}

function summarize(out: BusinessVerification, registryName: string): string {
  if (out.failure && out.failure.code !== 'not_verified') {
    return `${out.phone ?? out.domain} could not be verified: ${out.failure.message}. Treat what the site says about itself as unverified.`;
  }
  const b = out.business;
  const name = b?.legalName
    ? nameKey(b.legalName) === nameKey(b.name)
      ? b.legalName
      : `${b.legalName} (calling itself "${b.name}")`
    : (b?.name ?? out.domain);
  const subject = out.phone ? `${out.phone} (${out.domain})` : out.domain;
  const lines = [
    out.verified
      ? `${subject} belongs to ${name}, listed in the FFN Verified Business registry at Level ${out.level} (${out.levelName}).`
      : `${subject} belongs to ${name}, but no current attestation supports a verification level.`,
  ];
  const valid = out.facts.filter((f) => f.status === 'valid');
  if (valid.length)
    lines.push(`${registryName} verified these facts: ${valid.map((f) => f.sentence).join(' ')}`);
  const lapsed = out.facts.filter((f) => f.status !== 'valid');
  if (lapsed.length) lines.push(lapsed.map((f) => f.sentence).join(' '));
  const kinds = new Set(out.facts.map((f) => f.kind));
  const missing = (
    ['businessIdentity', 'officialChannels', 'license', 'insurance', 'representative'] as const
  ).filter((k) => !kinds.has(k));
  if (missing.length)
    lines.push(
      `Not checked: ${missing.map((k) => BusinessKindLabels[k].toLowerCase()).join(', ')}.`,
    );
  if (out.mismatches.length) lines.push(`Mismatches: ${out.mismatches.join(' ')}`);
  const phones = valid.find((f) => f.kind === 'officialChannels')?.claims.phones;
  if (Array.isArray(phones) && phones.length > 0)
    lines.push(
      'A verified phone number shows the business controls it when you call it, not that a call or text you receive comes from the business.',
    );
  lines.push('These are verified facts with dates, not a rating or a recommendation.');
  return lines.join(' ');
}
