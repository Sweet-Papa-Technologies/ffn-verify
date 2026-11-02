import { FetchLimits, fetchBounded, type Fetch } from '@fofonet/door-core';

// TXT lookups for the domain binding. DNS-over-HTTPS works the same in Node,
// browsers and edge runtimes, so agents need no resolver library.

export interface TxtResolver {
  /** TXT strings at `name` (each record's strings joined), or [] when there are none. */
  txt(name: string): Promise<string[]>;
}

const RESOLVERS = {
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  google: 'https://dns.google/resolve',
} as const;

export interface DohOptions {
  /** Total time per lookup, body included, in milliseconds (default 10 000). */
  timeoutMs?: number;
  /** Aborts every lookup. */
  signal?: AbortSignal;
}

/** TXT lookups over DNS-over-HTTPS. Answers over 64 KiB, redirects and timeouts fail the lookup. */
export function dohResolver(
  provider: keyof typeof RESOLVERS = 'cloudflare',
  fetchFn: Fetch = (input, init) => globalThis.fetch(input, init),
  options: DohOptions = {},
): TxtResolver {
  return {
    async txt(name) {
      const url = `${RESOLVERS[provider]}?name=${encodeURIComponent(name)}&type=TXT`;
      let text: string;
      try {
        ({ text } = await fetchBounded(fetchFn, url, {
          maxBytes: FetchLimits.dnsAnswer,
          headers: { accept: 'application/dns-json' },
          ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
          ...(options.signal ? { signal: options.signal } : {}),
        }));
      } catch (err) {
        throw new Error(`DNS lookup failed: ${(err as Error).message}`);
      }
      let body: { Status?: number; Answer?: Array<{ type: number; data: string }> };
      try {
        body = JSON.parse(text) as typeof body;
      } catch {
        throw new Error('DNS lookup failed: the answer is not JSON');
      }
      // NXDOMAIN (3) is an answer: there is no record.
      if (body.Status !== 0 && body.Status !== 3)
        throw new Error(`DNS lookup failed (status ${body.Status})`);
      return (Array.isArray(body.Answer) ? body.Answer : [])
        .filter((a) => a?.type === 16 && typeof a.data === 'string')
        .map((a) => a.data.replace(/"\s*"/g, '').replace(/^"|"$/g, ''));
    },
  };
}

/** A fixed table, for tests and test vectors. */
export function staticTxt(records: Record<string, string[]>): TxtResolver {
  return { txt: async (name) => records[name.toLowerCase()] ?? [] };
}
