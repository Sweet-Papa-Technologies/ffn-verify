import type { Fetch } from './did-web.js';

// Every network read a verifier makes for data a stranger chose: DID documents,
// status lists, DNS-over-HTTPS answers, registry records. Each one is bounded
// (size while reading, total time, no redirects), and a URL taken from a
// credential or a DID must be a public https URL: no IP literal outside the
// public internet and no name that only resolves inside a network.
//
// A public name that *resolves* to a private address (DNS rebinding) is not
// caught here: only the transport sees the address it connects to. Deployments
// that verify for untrusted callers belong behind an egress proxy.

/** Largest response accepted, in bytes, per kind of read. */
export const FetchLimits = {
  didDocument: 64 * 1024,
  dnsAnswer: 64 * 1024,
  registryResponse: 1024 * 1024,
  statusList: 2 * 1024 * 1024,
  /** A status list's bits once decompressed (a 2 MiB list could otherwise inflate to ~2 GiB). */
  statusListInflated: 16 * 1024 * 1024,
} as const;

/** Total time per request (connect, headers and body), in milliseconds. */
export const DEFAULT_FETCH_TIMEOUT_MS = 10_000;

type V4 = [number, number, number, number];

/** Dotted-quad IPv4 (WHATWG URL already normalizes hex, octal and short forms). */
function parseIpv4(text: string): V4 | undefined {
  const parts = text.split('.');
  if (parts.length !== 4) return undefined;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return undefined;
    const n = Number(p);
    if (n > 255) return undefined;
    out.push(n);
  }
  return out as V4;
}

/** Eight 16-bit groups, or undefined. Accepts brackets, `::`, an IPv4 tail and a zone id. */
function parseIpv6(text: string): number[] | undefined {
  let s = text.replace(/^\[|\]$/g, '');
  const zone = s.indexOf('%');
  if (zone !== -1) s = s.slice(0, zone);
  if (!s.includes(':')) return undefined;
  let tail: number[] = [];
  const lastColon = s.lastIndexOf(':');
  const last = s.slice(lastColon + 1);
  if (last.includes('.')) {
    const v4 = parseIpv4(last);
    if (!v4) return undefined;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    s = s.slice(0, lastColon + 1);
    if (!s.endsWith('::')) s = s.slice(0, -1);
  }
  const halves = s.split('::');
  if (halves.length > 2) return undefined;
  const side = (h: string): number[] | undefined => {
    if (h === '') return [];
    const gs = h.split(':').map((g) => (/^[0-9a-f]{1,4}$/i.test(g) ? parseInt(g, 16) : undefined));
    return gs.some((g) => g === undefined) ? undefined : (gs as number[]);
  };
  const head = side(halves[0] ?? '');
  const rest = halves.length === 2 ? side(halves[1] ?? '') : [];
  if (!head || !rest) return undefined;
  const given = head.length + rest.length + tail.length;
  if (halves.length === 1) return given === 8 ? [...head, ...tail] : undefined;
  if (given > 7) return undefined;
  return [...head, ...new Array<number>(8 - given).fill(0), ...rest, ...tail];
}

const inV4 = (a: V4, base: V4, bits: number): boolean => {
  const n = ((a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]) >>> 0;
  const b = ((base[0] << 24) | (base[1] << 16) | (base[2] << 8) | base[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (n & mask) === (b & mask);
};

/** IPv4 blocks that are not the public internet (IANA special-purpose registry). */
const V4_BLOCKS: Array<[V4, number, string]> = [
  [[0, 0, 0, 0], 8, 'unspecified'],
  [[10, 0, 0, 0], 8, 'private'],
  [[100, 64, 0, 0], 10, 'carrier-grade NAT'],
  [[127, 0, 0, 0], 8, 'loopback'],
  [[169, 254, 0, 0], 16, 'link-local'],
  [[172, 16, 0, 0], 12, 'private'],
  [[192, 0, 0, 0], 24, 'reserved'],
  [[192, 0, 2, 0], 24, 'reserved'],
  [[192, 88, 99, 0], 24, 'reserved'],
  [[192, 168, 0, 0], 16, 'private'],
  [[198, 18, 0, 0], 15, 'reserved'],
  [[198, 51, 100, 0], 24, 'reserved'],
  [[203, 0, 113, 0], 24, 'reserved'],
  [[224, 0, 0, 0], 4, 'multicast'],
  [[240, 0, 0, 0], 4, 'reserved'],
];

function v4Reason(a: V4): string | undefined {
  for (const [base, bits, words] of V4_BLOCKS) if (inV4(a, base, bits)) return words;
  return undefined;
}

const inV6 = (g: number[], prefix: number[], bits: number): boolean => {
  for (let i = 0; i < 8 && bits > 0; i++, bits -= 16) {
    const take = Math.min(16, bits);
    const mask = (0xffff << (16 - take)) & 0xffff;
    if (((g[i] ?? 0) & mask) !== ((prefix[i] ?? 0) & mask)) return false;
  }
  return true;
};

function v6Reason(g: number[]): string | undefined {
  // IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::a.b.c.d) reach the IPv4 address inside.
  if (inV6(g, [0, 0, 0, 0, 0, 0xffff], 96) || inV6(g, [0x64, 0xff9b], 96)) {
    const v4: V4 = [(g[6] ?? 0) >> 8, (g[6] ?? 0) & 0xff, (g[7] ?? 0) >> 8, (g[7] ?? 0) & 0xff];
    return v4Reason(v4);
  }
  if (g.every((x) => x === 0)) return 'unspecified';
  if (inV6(g, [0, 0, 0, 0, 0, 0, 0, 1], 128)) return 'loopback';
  if (inV6(g, [0xfe80], 10)) return 'link-local';
  if (inV6(g, [0xfc00], 7)) return 'private';
  if (inV6(g, [0xfec0], 10)) return 'private';
  if (inV6(g, [0xff00], 8)) return 'multicast';
  // Only 2000::/3 is global unicast; inside it, these blocks are not the public internet.
  if (!inV6(g, [0x2000], 3)) return 'reserved';
  if (inV6(g, [0x2001, 0x0db8], 32) || inV6(g, [0x3fff], 20)) return 'reserved';
  if (inV6(g, [0x2001], 23)) return 'reserved';
  if (inV6(g, [0x2002], 16)) return 'reserved';
  return undefined;
}

/** Names that only resolve inside a network. */
const PRIVATE_NAMES = ['localhost', 'local', 'internal'];

/**
 * Why a verifier will not fetch from this URL host, or undefined when it may:
 * IP literals outside the public internet, localhost, *.localhost, *.local,
 * *.internal, and single-label names. `hostname` is a URL hostname (IPv6 in
 * brackets allowed).
 */
export function refusedHostReason(hostname: string): string | undefined {
  const host = hostname.toLowerCase().replace(/\.+$/, '');
  const v4 = parseIpv4(host);
  const v6 = v4 ? undefined : parseIpv6(host);
  const reason = v4 ? v4Reason(v4) : v6 ? v6Reason(v6) : undefined;
  if (reason) return `${host} is not a public address (${reason})`;
  if (v4 || v6) return undefined;
  if (PRIVATE_NAMES.some((s) => host === s || host.endsWith(`.${s}`)))
    return `${host} only resolves inside a private network`;
  // A single label (`metadata`, `printer`) resolves through the local search
  // domains, i.e. inside the network the verifier runs in.
  if (!host.includes('.')) return `${host} is a single-label name, not a public host`;
  return undefined;
}

/** localhost, *.localhost, 127.0.0.0/8 and ::1: where http: is allowed for a local registry. */
export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.+$/, '');
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  const v4 = parseIpv4(host);
  if (v4) return v4[0] === 127;
  const v6 = parseIpv6(host);
  if (!v6) return false;
  if (inV6(v6, [0, 0, 0, 0, 0, 0, 0, 1], 128)) return true;
  return inV6(v6, [0, 0, 0, 0, 0, 0xffff], 96) && (v6[6] ?? 0) >> 8 === 127;
}

export type FetchFailure =
  | 'refused'
  | 'redirect'
  | 'http'
  | 'too_large'
  | 'timeout'
  | 'aborted'
  | 'network';

/**
 * A bounded read that failed. The message never carries what the remote host
 * answered (status or body); `status` keeps the HTTP status for callers that
 * trust the host (the pinned registry) and want to say it.
 */
export class FetchError extends Error {
  constructor(
    readonly reason: FetchFailure,
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'FetchError';
  }
}

export interface BoundedFetchOptions {
  /** Largest body accepted, in bytes; reading stops past it. */
  maxBytes: number;
  /** Total time for the request, body included (default 10 s). */
  timeoutMs?: number;
  /** Aborts the request too, combined with the timeout. */
  signal?: AbortSignal;
  headers?: Record<string, string>;
  /**
   * The caller configured this host itself (the pinned registry): skip the
   * public-host check, and allow http: on loopback hosts for local testing.
   * Everything else must be a public https URL.
   */
  trustedOrigin?: boolean;
}

/** Can `url` be fetched under these rules? Throws FetchError('refused') when not. */
export function assertFetchableUrl(url: string, trustedOrigin = false): URL {
  // The authority as written, before any parser normalizes it: parsers disagree on
  // backslashes, userinfo and Unicode, so anything that could read two ways is refused.
  const authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/.exec(url)?.[1];
  // eslint-disable-next-line no-control-regex
  if (!authority || /[@\\\s\x00-\x1f\x7f]|[^\x00-\x7f]/.test(authority))
    throw new FetchError('refused', 'not a plain URL authority');
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new FetchError('refused', 'not a valid URL');
  }
  if (trustedOrigin) {
    if (u.protocol === 'https:' || (u.protocol === 'http:' && isLoopbackHost(u.hostname))) return u;
    throw new FetchError('refused', 'the registry origin must be https (http only on loopback)');
  }
  if (u.protocol !== 'https:') throw new FetchError('refused', 'only https URLs are fetched');
  const why = refusedHostReason(u.hostname);
  if (why) throw new FetchError('refused', why);
  return u;
}

function anySignal(signals: AbortSignal[]): AbortSignal {
  const any = (AbortSignal as { any?: (s: AbortSignal[]) => AbortSignal }).any;
  if (typeof any === 'function') return any.call(AbortSignal, signals);
  const controller = new AbortController();
  for (const s of signals) {
    if (s.aborted) {
      controller.abort(s.reason);
      break;
    }
    s.addEventListener('abort', () => controller.abort(s.reason), { once: true });
  }
  return controller.signal;
}

/**
 * GET `url` through `fetchFn` within the limits: no redirects, the body read
 * in chunks and abandoned past `maxBytes`, and one deadline for the whole
 * request, enforced here too, so a caller-supplied fetch that ignores the
 * signal still can't hang the verifier. Resolves to the body of a 2xx answer.
 */
export async function fetchBounded(
  fetchFn: Fetch,
  url: string,
  options: BoundedFetchOptions,
): Promise<{ status: number; text: string }> {
  assertFetchableUrl(url, options.trustedOrigin);
  const timeout = AbortSignal.timeout(options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS);
  const signal = options.signal ? anySignal([timeout, options.signal]) : timeout;
  const stopped = () =>
    timeout.aborted
      ? new FetchError('timeout', 'the request timed out')
      : new FetchError('aborted', 'the request was aborted');
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(stopped());
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  });
  aborted.catch(() => undefined);
  try {
    let res: Response;
    try {
      res = await Promise.race([
        fetchFn(url, {
          ...(options.headers ? { headers: options.headers } : {}),
          redirect: 'manual',
          signal,
        }),
        aborted,
      ]);
    } catch (err) {
      if (err instanceof FetchError) throw err;
      if (signal.aborted) throw stopped();
      throw new FetchError('network', 'the host could not be reached');
    }
    const discard = () => res.body?.cancel().catch(() => undefined);
    if (res.type === 'opaqueredirect' || (res.status >= 300 && res.status < 400)) {
      void discard();
      throw new FetchError('redirect', 'redirects are not followed', res.status);
    }
    if (res.status < 200 || res.status > 299) {
      void discard();
      throw new FetchError('http', 'the host answered with an error', res.status);
    }
    const declared = Number(res.headers.get('content-length') ?? NaN);
    if (Number.isFinite(declared) && declared > options.maxBytes) {
      void discard();
      throw new FetchError('too_large', 'the response is too large');
    }
    if (!res.body) return { status: res.status, text: '' };
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await Promise.race([reader.read(), aborted]);
        if (done) break;
        total += value.byteLength;
        if (total > options.maxBytes)
          throw new FetchError('too_large', 'the response is too large');
        chunks.push(value);
      }
    } catch (err) {
      reader.cancel().catch(() => undefined);
      if (err instanceof FetchError) throw err;
      if (signal.aborted) throw stopped();
      throw new FetchError('network', 'the response could not be read');
    }
    const body = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      body.set(c, offset);
      offset += c.byteLength;
    }
    return { status: res.status, text: new TextDecoder().decode(body) };
  } finally {
    if (onAbort) signal.removeEventListener('abort', onAbort);
  }
}
