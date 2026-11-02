import { verifyStatusListJwtClaims } from '@owf/token-status-list';
import type { CredentialStatus } from './business.js';
import type { DidResolver, Fetch } from './did-web.js';
import { b64uDecode, decodeJwt, verifyJwt } from './jose.js';
import { MemoryKvStore, type KvStore } from './kv.js';
import { FetchLimits, assertFetchableUrl, fetchBounded } from './net.js';

// IETF Token Status List checks shared by every verifier.
//
// Principle 1 (FFN v1): never block on FFN or an issuer being down. A list that
// can't be fetched falls back to the last verified copy; with none, the status
// is "unknown" and the caller decides what that means for it.
//
// Who may sign a list: only the root did:web of the host that serves it
// (https://registry.example/status/1 → did:web:registry.example, a port
// percent-encoded as did:web does). Not a path DID on that host, which anyone
// who can publish a file there could create, and not the credential's issuer
// when it lives elsewhere. The signer resolves through the caller's resolver,
// so a pinned registry's lists must be signed with a pinned key.

export interface StatusReference {
  status_list?: { idx?: number; uri?: string };
}

export interface StatusOutcome {
  status: CredentialStatus;
  /** When the list consulted was fetched. */
  checkedAt?: string;
}

interface CacheEntry {
  jwt: string;
  fetchedAt: number;
}

const NS_STATUS = 'status_cache';

export interface StatusCheckerOptions {
  resolver: DidResolver;
  fetch?: Fetch;
  /** Last-good cache; in-memory by default. */
  store?: KvStore;
  /** Refetch after this many seconds (default 3600, the list's suggested ttl). */
  maxAgeSeconds?: number;
  /** Seconds since epoch, for test vectors (default now). */
  now?: () => number;
  /** Total time per list fetch, body included, in milliseconds (default 10 000). */
  timeoutMs?: number;
  /** Aborts every fetch this checker makes. */
  signal?: AbortSignal;
}

/** The DID that must sign the status list at `uri`: the root did:web of its host. */
export function statusListSignerFor(uri: string): string {
  return `did:web:${encodeURIComponent(new URL(uri).host)}`;
}

export class StatusChecker {
  private readonly fetchFn: Fetch;
  private readonly store: KvStore;
  private readonly maxAge: number;
  private readonly now: () => number;

  constructor(private readonly options: StatusCheckerOptions) {
    this.fetchFn = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.store = options.store ?? new MemoryKvStore();
    this.maxAge = (options.maxAgeSeconds ?? 3600) * 1000;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Status of the entry `ref` points at. The list must be signed by the root
   * did:web of the host serving it (see statusListSignerFor), whoever issued
   * the credential; `_issuer` is kept for callers that pass it. A URI that
   * isn't a public https URL throws without a request.
   */
  async check(ref: StatusReference | undefined, _issuer?: string): Promise<StatusOutcome> {
    const entry = ref?.status_list;
    if (!entry || typeof entry.idx !== 'number' || typeof entry.uri !== 'string')
      throw new Error('credential has no status reference');
    const uri = entry.uri;
    try {
      assertFetchableUrl(uri);
    } catch (err) {
      throw new Error(`status list URI refused: ${(err as Error).message}`);
    }
    const cached = await this.store.get<CacheEntry>(NS_STATUS, uri);
    let token = cached && this.now() * 1000 - cached.fetchedAt < this.maxAge ? cached : undefined;
    let list: InflatedList | undefined;
    if (!token) {
      try {
        const { text } = await fetchBounded(this.fetchFn, uri, {
          maxBytes: FetchLimits.statusList,
          headers: { accept: 'application/statuslist+jwt' },
          ...(this.options.timeoutMs !== undefined ? { timeoutMs: this.options.timeoutMs } : {}),
          ...(this.options.signal ? { signal: this.options.signal } : {}),
        });
        const fresh = { jwt: text.trim(), fetchedAt: this.now() * 1000 };
        list = await this.verifyToken(fresh.jwt, uri);
        token = fresh;
        await this.store.put(NS_STATUS, uri, token, 7 * 86_400);
      } catch {
        token = cached;
      }
    }
    if (!token) return { status: 'unknown' };
    list ??= await this.verifyToken(token.jwt, uri);
    const value = statusAt(list, entry.idx);
    const status: CredentialStatus = value === 0 ? 'valid' : value === 2 ? 'suspended' : 'invalid';
    return { status, checkedAt: new Date(token.fetchedAt).toISOString() };
  }

  private async verifyToken(jwt: string, uri: string): Promise<InflatedList> {
    const { header, payload } = decodeJwt<{ iss?: string }>(jwt);
    const listIssuer = payload.iss;
    if (typeof listIssuer !== 'string') throw new Error('status list has no issuer');
    if (listIssuer !== statusListSignerFor(uri))
      throw new Error('status list is not signed by the root DID of the host serving it');
    const key = await this.options.resolver.assertionKey(
      listIssuer,
      header.kid as string | undefined,
    );
    // Lists are re-signed daily; an old signature is still a signature, so a
    // week of skew keeps last-good copies usable through an outage.
    const verified = await verifyJwt<Record<string, unknown>>(jwt, key, {
      typ: 'statuslist+jwt',
      skew: 7 * 86_400,
      now: this.now(),
    });
    // The same clock and week of skew as the signature check, so a last-good copy
    // outlives a day-long outage and test vectors replay at their own `now`.
    verifyStatusListJwtClaims(verified.payload as never, {
      uri,
      now: new Date(this.now() * 1000),
      skewSeconds: 7 * 86_400,
      checkFreshness: false,
    });
    const list = (verified.payload as { status_list?: { lst?: unknown; bits?: unknown } })
      .status_list;
    const bits = list?.bits;
    if (bits !== 1 && bits !== 2 && bits !== 4 && bits !== 8)
      throw new Error('status list bits must be 1, 2, 4 or 8');
    return { bits, bytes: await inflate(list?.lst, FetchLimits.statusListInflated) };
  }
}

interface InflatedList {
  bits: 1 | 2 | 4 | 8;
  bytes: Uint8Array;
}

/**
 * A list's `lst` inflated (zlib, or gzip as the token-status-list library also
 * accepts), refusing one that inflates past `cap` before it is inflated any
 * further: a 2 MiB list could otherwise expand a thousandfold.
 */
async function inflate(lst: unknown, cap: number): Promise<Uint8Array> {
  if (typeof lst !== 'string') throw new Error('status list has no lst');
  const compressed = b64uDecode(lst);
  const gzip = compressed[0] === 0x1f && compressed[1] === 0x8b;
  const reader = new Response(compressed)
    .body!.pipeThrough(new DecompressionStream(gzip ? 'gzip' : 'deflate'))
    .getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > cap) throw new Error('status list inflates past the size cap');
      chunks.push(value);
    }
  } finally {
    reader.cancel().catch(() => undefined);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

/**
 * The status at `idx`, read straight from the bytes (least significant bits
 * first, as the Token Status List draft packs them) rather than expanding the
 * list into one array entry per status. A non-integer index reads as no value.
 */
function statusAt(list: InflatedList, idx: number): number | undefined {
  const total = Math.floor((list.bytes.length * 8) / list.bits);
  if (idx < 0 || idx >= total) throw new Error('Index out of bounds');
  if (!Number.isInteger(idx)) return undefined;
  const bit = idx * list.bits;
  return (list.bytes[bit >> 3]! >> (bit & 7)) & ((1 << list.bits) - 1);
}
