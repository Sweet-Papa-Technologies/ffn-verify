import { deflateSync } from 'node:zlib';
import { getListFromStatusListJWT } from '@owf/token-status-list';
import { describe, expect, it } from 'vitest';
import {
  BusinessKinds,
  DidResolutionError,
  DidResolver,
  FetchError,
  FetchLimits,
  Networks,
  StatusChecker,
  alsoKnownAsOf,
  assertFetchableUrl,
  buildDidDocument,
  fetchBounded,
  generateEs256KeyPair,
  knownRegistryPins,
  localSigner,
  refusedHostReason,
  registryEntriesOf,
  signDelegation,
  signJwt,
  verifyDelegationChain,
  type DidDocument,
  type Fetch,
} from '../src/index.js';
import { FakeWeb, party, publishStatusList } from './helpers.js';

// The pre-publication hardening rules (SPEC R1–R4, R7) at the door-core level.

const days = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString();

/** A FakeWeb that records every URL asked for. */
class CountingWeb extends FakeWeb {
  readonly asked: string[] = [];
  readonly inits: Array<RequestInit | undefined> = [];
  override fetch: Fetch = async (input, init) => {
    this.asked.push(String(input));
    this.inits.push(init);
    const hit = this.pages.get(String(input));
    return hit
      ? new Response(hit.body, { status: 200, headers: { 'content-type': hit.type } })
      : new Response('not found', { status: 404 });
  };
}

/** A body of `total` bytes streamed in `chunk`-byte pieces, counting what the reader pulled. */
function streamed(total: number, chunk = 16 * 1024) {
  const counter = { pulled: 0 };
  let left = total;
  const body = new ReadableStream<Uint8Array>({
    pull(c) {
      if (left <= 0) return c.close();
      const n = Math.min(chunk, left);
      left -= n;
      counter.pulled += n;
      c.enqueue(new Uint8Array(n).fill(32));
    },
  });
  return { body, counter };
}

describe('R1: a status list is signed by the root DID of the host serving it', () => {
  const uri = 'https://registry.test/status/1';

  it('refuses a list signed by a path DID on that host', async () => {
    const web = new FakeWeb();
    const registry = await party('did:web:registry.test');
    const rogue = await party('did:web:registry.test:rogue', 'k');
    web.publishParty(registry);
    // Someone who can publish files on the registry's host serves a DID document under a path.
    web.publishParty(rogue);
    await publishStatusList(web, rogue.signer, rogue.did, uri);
    const checker = new StatusChecker({ resolver: web.resolver(), fetch: web.fetch });
    expect(await checker.check({ status_list: { idx: 0, uri } }, registry.did)).toEqual({
      status: 'unknown',
    });
    // The same list signed by the host's root DID is accepted.
    await publishStatusList(web, registry.signer, registry.did, uri);
    expect((await checker.check({ status_list: { idx: 0, uri } }, registry.did)).status).toBe(
      'valid',
    );
  });

  it("refuses a list signed by the credential's issuer when it lives on another host", async () => {
    const web = new FakeWeb();
    const business = await party('did:web:acme-hvac.com');
    web.publishParty(business);
    await publishStatusList(web, business.signer, business.did, uri);
    const checker = new StatusChecker({ resolver: web.resolver(), fetch: web.fetch });
    expect((await checker.check({ status_list: { idx: 0, uri } }, business.did)).status).toBe(
      'unknown',
    );
  });

  it('percent-encodes a port into the root DID, as did:web does', async () => {
    const web = new FakeWeb();
    const host = await party('did:web:registry.test%3A8443');
    const portUri = 'https://registry.test:8443/status/1';
    web.pages.set('https://registry.test:8443/.well-known/did.json', {
      body: JSON.stringify(
        buildDidDocument(host.did, [{ kid: host.signer.kid, publicJwk: host.publicJwk }]),
      ),
      type: 'application/did+json',
    });
    await publishStatusList(web, host.signer, host.did, portUri);
    const checker = new StatusChecker({ resolver: web.resolver(), fetch: web.fetch });
    expect((await checker.check({ status_list: { idx: 0, uri: portUri } })).status).toBe('valid');
    // Without the port, it is another host's DID.
    const portless = await party('did:web:registry.test');
    web.publishParty(portless);
    await publishStatusList(web, portless.signer, portless.did, portUri);
    const fresh = new StatusChecker({ resolver: web.resolver(), fetch: web.fetch });
    expect((await fresh.check({ status_list: { idx: 0, uri: portUri } })).status).toBe('unknown');
  });

  it("resolves the host's DID through the pins: a known registry's list needs a pinned key", async () => {
    const web = new FakeWeb();
    const did = Networks.production.businessRegistry.did;
    const listUri = 'https://registry.fofo.network/status/1';
    const intruder = await party(did, 'records-9');
    // did.json lists the intruder's key as an assertion key; no verifier pins it.
    web.publishParty(intruder);
    await publishStatusList(web, intruder.signer, did, listUri);
    const checker = new StatusChecker({ resolver: web.resolver(), fetch: web.fetch });
    expect((await checker.check({ status_list: { idx: 0, uri: listUri } }, did)).status).toBe(
      'unknown',
    );
  });
});

describe('R2: known FFN registry DIDs resolve only to their pinned keys', () => {
  // The production registry's keys, as its did.json published them on Nov 1, 2026.
  const records1 = {
    kty: 'EC',
    crv: 'P-256',
    x: 'SR1FObPPXWDOEOqFlSiNo9pWdapbsqgj9BOV2-ZoSv0',
    y: 'tyf2DY7OVm17qrwr8Pb-mKSCKVib22Ooi42kMqQ7HEk',
  };
  const records2 = {
    kty: 'EC',
    crv: 'P-256',
    x: 'KWrBqq4DsDPM5OZGvbDETKwp8Zy-gfflNe70z373-Ik',
    y: 'KPuvr1hBhcfO-14e0t0dI5GForY_ix87Q9qufGIfRoE',
  };
  const did = 'did:web:registry.fofo.network';

  async function document(): Promise<DidDocument> {
    const intruder = await generateEs256KeyPair();
    return buildDidDocument(did, [
      { kid: 'records-1', publicJwk: records1 },
      { kid: 'records-2', publicJwk: records2 },
      { kid: 'records-9', publicJwk: intruder.publicJwk },
    ]);
  }

  it('drops every key the network does not pin, however the document arrives', async () => {
    const doc = await document();
    const web = new FakeWeb();
    web.publishDid(doc);
    for (const resolver of [
      new DidResolver({ fetch: web.fetch }),
      new DidResolver({ documents: { [did]: doc } }),
    ]) {
      const resolved = await resolver.resolve(did);
      expect(resolved.verificationMethod!.map((m) => m.id)).toEqual([
        `${did}#records-1`,
        `${did}#records-2`,
      ]);
      expect(await resolver.assertionKey(did, `${did}#records-1`)).toEqual(records1);
      await expect(resolver.assertionKey(did, `${did}#records-9`)).rejects.toThrow(/no unique/);
    }
  });

  it('covers mainnet and devnet, and nothing else', async () => {
    expect(knownRegistryPins(did)).toEqual(Networks.production.businessRegistry.keyThumbprints);
    expect(knownRegistryPins(Networks.devnet.businessRegistry.did)).toEqual(
      Networks.devnet.businessRegistry.keyThumbprints,
    );
    expect(knownRegistryPins('did:web:registry.test')).toBeUndefined();
    // Any other DID resolves to whatever its document lists.
    const other = await party('did:web:registry.test');
    const web = new FakeWeb();
    web.publishParty(other);
    expect((await web.resolver().resolve(other.did)).verificationMethod).toHaveLength(1);
  });
});

describe('R3: decide trust before fetching', () => {
  it('refuses private, loopback, link-local, CGNAT, multicast, unspecified and reserved hosts', () => {
    const host = (h: string) => new URL(`https://${h}/`).hostname;
    for (const refused of [
      '10.0.0.5',
      '172.16.3.4',
      '192.168.1.1',
      '127.0.0.1',
      '0x7f.0.0.1', // WHATWG URL normalizes to 127.0.0.1
      '0.0.0.0',
      '169.254.169.254',
      '100.64.0.1',
      '224.0.0.1',
      '240.0.0.1',
      '255.255.255.255',
      '192.0.2.10',
      '198.18.0.1',
      '[::1]',
      '[::]',
      '[fe80::1]',
      '[fc00::1]',
      '[fd12:3456::1]',
      '[ff02::1]',
      '[::ffff:10.0.0.1]',
      '[::ffff:127.0.0.1]',
      '[64:ff9b::a9fe:a9fe]',
      '[2001:db8::1]',
      'localhost',
      'LOCALHOST.',
      'api.localhost',
      'printer.local',
      'metadata.google.internal',
      'metadata',
      'printer',
      'intranet.',
    ])
      expect(refusedHostReason(host(refused)), refused).toBeDefined();
    expect(refusedHostReason('metadata')).toMatch(/single-label/);
    for (const allowed of [
      'registry.fofo.network',
      'registry.test',
      '8.8.8.8',
      '[2606:4700:4700::1111]',
      '[::ffff:8.8.8.8]',
      'localhost.example.com',
      'local.example',
    ])
      expect(refusedHostReason(host(allowed)), allowed).toBeUndefined();
  });

  it('fetches only https URLs, except http on loopback for a configured registry', () => {
    expect(() => assertFetchableUrl('http://example.com/x')).toThrow(FetchError);
    expect(() => assertFetchableUrl('https://10.0.0.5:8443/admin')).toThrow(/not a public/);
    expect(() => assertFetchableUrl('https://example.com/x')).not.toThrow();
    for (const local of ['http://localhost:8080', 'http://127.0.0.1:8080', 'http://[::1]:8080'])
      expect(() => assertFetchableUrl(local, true), local).not.toThrow();
    expect(() => assertFetchableUrl('http://registry.example', true)).toThrow(/https/);
    expect(() => assertFetchableUrl('ftp://registry.example', true)).toThrow(/https/);
  });

  it('refuses an authority parsers could read two ways', () => {
    for (const url of [
      'https://evil.example\\@registry.test/status/1',
      'https://user@registry.test/status/1',
      'https://user:pass@registry.test/status/1',
      'https:///registry.test/status/1',
      'https://registry .test/status/1',
      'https://regis\ttry.test/status/1',
      'https://bücher.example/status/1',
      'https://registry.test\u0000.evil/status/1',
      'https:/registry.test/status/1',
    ])
      expect(() => assertFetchableUrl(url), url).toThrow(/plain URL authority/);
    // The same holds for a registry origin the caller configured.
    expect(() => assertFetchableUrl('https://user@registry.test', true)).toThrow(FetchError);
    expect(() => assertFetchableUrl('https://xn--bcher-kva.example/x')).not.toThrow();
  });

  it('never requests a DID document from a refused host', async () => {
    const web = new CountingWeb();
    const resolver = new DidResolver({ fetch: web.fetch });
    for (const did of [
      'did:web:10.0.0.9%3A9443:internal:svc',
      'did:web:localhost%3A8080',
      'did:web:0x7f.0.0.1',
      'did:web:metadata.google.internal',
      'did:web:%5B%3A%3A1%5D',
      'did:web:metadata',
      'did:web:printer%3A8443:svc',
    ]) {
      const err = await resolver.resolve(did).catch((e: unknown) => e);
      expect(err, did).toBeInstanceOf(DidResolutionError);
      expect((err as DidResolutionError).reason, did).toMatch(/refused|invalid/);
    }
    expect(web.asked).toEqual([]);
  });

  it('never requests a status list that is not a public https URL', async () => {
    const web = new CountingWeb();
    const checker = new StatusChecker({ resolver: web.resolver(), fetch: web.fetch });
    for (const uri of [
      'http://registry.test/status/1',
      'https://169.254.169.254/latest/meta-data',
      'https://[::ffff:a00:5]/status/1',
      'https://status.internal/1',
      'https://metadata/computeMetadata/v1/status',
      'https://printer:8443/status/1',
    ])
      await expect(checker.check({ status_list: { idx: 0, uri } }), uri).rejects.toThrow(/refused/);
    expect(web.asked).toEqual([]);
  });

  it('does not repeat what an untrusted host answered', async () => {
    for (const status of [401, 403, 500, 503]) {
      const fetch: Fetch = async () => new Response(`secret-${status}-body`, { status });
      const err = (await new DidResolver({ fetch })
        .resolve('did:web:victim.example')
        .catch((e: unknown) => e)) as DidResolutionError;
      expect(err.message).not.toContain(String(status));
      expect(err.message).not.toContain('secret');
      expect(err.reason).toBe(status < 500 ? 'not_found' : 'unreachable');
    }
  });

  describe('delegation chains', () => {
    async function world() {
      const web = new CountingWeb();
      const registry = await party('did:web:registry.test');
      web.publishParty(registry);
      const business = await party('did:web:acme-hvac.com');
      web.publishParty(business);
      const agent = await party('did:web:acme-hvac.com:agents:booking');
      web.publishParty(agent);
      const sub = await party('did:web:sub.example');
      web.publishParty(sub);
      const statusUri = 'https://registry.test/status/1';
      await publishStatusList(web, registry.signer, registry.did, statusUri);
      const toAgent = await signDelegation({
        signer: business.signer,
        delegator: business.did,
        delegate: { did: agent.did, kind: 'agent', key: agent.publicJwk },
        scope: ['booking:*'],
        expiresAt: days(30),
        status: { status_list: { idx: 3, uri: statusUri } },
      });
      const status = new StatusChecker({ resolver: web.resolver(), fetch: web.fetch });
      return { web, business, agent, sub, statusUri, toAgent, status };
    }

    it('rejects a chain rooted at a DID the verifier does not accept without a request', async () => {
      const w = await world();
      await expect(
        verifyDelegationChain([w.toAgent], {
          resolver: w.web.resolver(),
          status: w.status,
          roots: ['did:web:someone-else.example'],
        }),
      ).rejects.toMatchObject({ code: 'untrusted_root' });
      expect(w.web.asked).toEqual([]);
    });

    it("never resolves a link's issuer that its parent didn't delegate to", async () => {
      const w = await world();
      const impostor = await party('did:web:impostor.example');
      w.web.publishParty(impostor);
      const child = await signDelegation({
        signer: impostor.signer,
        delegator: impostor.did,
        delegate: { did: w.sub.did, kind: 'agent', key: w.sub.publicJwk },
        scope: ['booking:create'],
        expiresAt: days(7),
        parent: w.toAgent,
      });
      await expect(
        verifyDelegationChain([child, w.toAgent], {
          resolver: w.web.resolver(),
          status: w.status,
          roots: [w.business.did],
        }),
      ).rejects.toThrow(/not the delegate above it/);
      expect(w.web.asked.some((u) => u.includes('impostor.example'))).toBe(false);
    });

    it("fetches a link's status list only after its signature verified", async () => {
      const w = await world();
      // The root link's payload edited after signing (a wider scope): its signature fails.
      const [h, p, s] = w.toAgent.split('~')[0]!.split('.');
      const body = JSON.parse(Buffer.from(p!, 'base64url').toString()) as Record<string, unknown>;
      body.scope = ['*'];
      const forged = `${h}.${Buffer.from(JSON.stringify(body)).toString('base64url')}.${s}~`;
      await expect(
        verifyDelegationChain([forged], {
          resolver: w.web.resolver(),
          status: w.status,
          roots: [w.business.did],
        }),
      ).rejects.toThrow();
      expect(w.web.asked).not.toContain(w.statusUri);
      // The genuine link: signature, then status.
      await verifyDelegationChain([w.toAgent], {
        resolver: w.web.resolver(),
        status: w.status,
        roots: [w.business.did],
      });
      expect(w.web.asked.indexOf(w.statusUri)).toBeGreaterThan(
        w.web.asked.indexOf('https://acme-hvac.com/.well-known/did.json'),
      );
    });

    it('reads a malformed chain as broken without fetching', async () => {
      const w = await world();
      await expect(
        verifyDelegationChain(['not-a-jwt', w.toAgent], {
          resolver: w.web.resolver(),
          status: w.status,
          roots: [w.business.did],
        }),
      ).rejects.toMatchObject({ code: 'broken_chain' });
      expect(w.web.asked).toEqual([]);
      expect(BusinessKinds.delegation).toBeTruthy();
    });
  });
});

describe('R4: bounded fetches', () => {
  it('stops reading a DID document past 64 KiB', async () => {
    const { body, counter } = streamed(256 * 1024 * 1024);
    const resolver = new DidResolver({ fetch: async () => new Response(body) });
    const err = (await resolver
      .resolve('did:web:victim-biz.example')
      .catch((e: unknown) => e)) as DidResolutionError;
    expect(err.reason).toBe('unreachable');
    expect(err.message).toMatch(/too large/);
    expect(counter.pulled).toBeLessThan(FetchLimits.didDocument + 64 * 1024);
  });

  it('stops reading a status list past 2 MiB, and reports unknown', async () => {
    const { body, counter } = streamed(64 * 1024 * 1024, 256 * 1024);
    const checker = new StatusChecker({
      resolver: new DidResolver({ fetch: async () => new Response('nf', { status: 404 }) }),
      fetch: async () => new Response(body),
    });
    expect(
      await checker.check({ status_list: { idx: 0, uri: 'https://registry.test/status/1' } }),
    ).toEqual({ status: 'unknown' });
    expect(counter.pulled).toBeLessThan(FetchLimits.statusList + 1024 * 1024);
  });

  it('refuses a declared length over the cap without reading', async () => {
    const { body, counter } = streamed(1024);
    const fetch: Fetch = async () =>
      new Response(body, { headers: { 'content-length': String(10 * 1024 * 1024) } });
    await expect(
      fetchBounded(fetch, 'https://example.com/x', { maxBytes: 1024 * 1024 }),
    ).rejects.toMatchObject({ reason: 'too_large' });
    expect(counter.pulled).toBeLessThanOrEqual(16 * 1024);
  });

  it('times out a fetch that never answers, even one that ignores the signal', async () => {
    const hang: Fetch = () => new Promise<Response>(() => undefined);
    const t = Date.now();
    await expect(
      fetchBounded(hang, 'https://example.com/x', { maxBytes: 1024, timeoutMs: 50 }),
    ).rejects.toMatchObject({ reason: 'timeout' });
    expect(Date.now() - t).toBeLessThan(2000);
  });

  it('times out a body that stalls after the headers', async () => {
    const stall: Fetch = async () =>
      new Response(
        new ReadableStream({
          start(c) {
            c.enqueue(new Uint8Array([123]));
          },
        }),
      );
    await expect(
      fetchBounded(stall, 'https://example.com/x', { maxBytes: 1024, timeoutMs: 50 }),
    ).rejects.toMatchObject({ reason: 'timeout' });
  });

  it('never follows a redirect, and hands the fetch a signal', async () => {
    const seen: Array<RequestInit | undefined> = [];
    const fetch: Fetch = async (_u, init) => {
      seen.push(init);
      return new Response(null, { status: 302, headers: { location: 'https://10.0.0.5/' } });
    };
    await expect(
      fetchBounded(fetch, 'https://example.com/x', { maxBytes: 1024 }),
    ).rejects.toMatchObject({ reason: 'redirect' });
    expect(seen[0]!.redirect).toBe('manual');
    expect(seen[0]!.signal).toBeInstanceOf(AbortSignal);
  });

  it("honors the caller's signal", async () => {
    const controller = new AbortController();
    const hang: Fetch = () => new Promise<Response>(() => undefined);
    const pending = fetchBounded(hang, 'https://example.com/x', {
      maxBytes: 1024,
      signal: controller.signal,
    });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ reason: 'aborted' });
  });

  it('keeps the HTTP status for the caller, out of the message', async () => {
    const fetch: Fetch = async () => new Response('body text', { status: 418 });
    const err = (await fetchBounded(fetch, 'https://example.com/x', { maxBytes: 1024 }).catch(
      (e: unknown) => e,
    )) as FetchError;
    expect(err).toMatchObject({ reason: 'http', status: 418 });
    expect(err.message).not.toMatch(/418|body text/);
  });
});

describe('status lists that inflate past 16 MiB', () => {
  it('are refused before they are inflated further', async () => {
    const web = new FakeWeb();
    const registry = await party('did:web:registry.test');
    web.publishParty(registry);
    const uri = 'https://registry.test/status/1';
    const now = Math.floor(Date.now() / 1000);
    const list = async (bytes: number) =>
      signJwt(
        registry.signer,
        {
          iss: registry.did,
          sub: uri,
          iat: now,
          exp: now + 86_400,
          ttl: 3600,
          status_list: { bits: 2, lst: deflateSync(Buffer.alloc(bytes)).toString('base64url') },
        },
        { typ: 'statuslist+jwt' },
      );
    const check = async (bytes: number) => {
      web.pages.set(uri, { body: await list(bytes), type: 'application/statuslist+jwt' });
      return new StatusChecker({ resolver: web.resolver(), fetch: web.fetch }).check({
        status_list: { idx: 0, uri },
      });
    };
    expect(FetchLimits.statusListInflated).toBe(16 * 1024 * 1024);
    expect((await check(FetchLimits.statusListInflated)).status).toBe('valid');
    expect((await check(FetchLimits.statusListInflated + 1)).status).toBe('unknown');
  });
});

describe('status list claims', () => {
  it('must name the URI the list was fetched from and say when it was issued', async () => {
    const web = new FakeWeb();
    const registry = await party('did:web:registry.test');
    web.publishParty(registry);
    const uri = 'https://registry.test/status/1';
    const now = Math.floor(Date.now() / 1000);
    const check = async (claims: Record<string, unknown>) => {
      const jwt = await signJwt(
        registry.signer,
        {
          iss: registry.did,
          exp: now + 86_400,
          status_list: { bits: 2, lst: deflateSync(Buffer.alloc(16)).toString('base64url') },
          ...claims,
        },
        { typ: 'statuslist+jwt' },
      );
      web.pages.set(uri, { body: jwt, type: 'application/statuslist+jwt' });
      const checker = new StatusChecker({ resolver: web.resolver(), fetch: web.fetch });
      return (await checker.check({ status_list: { idx: 0, uri } })).status;
    };
    expect(await check({ sub: uri, iat: now })).toBe('valid');
    expect(await check({ sub: 'https://registry.test/status/2', iat: now })).toBe('unknown');
    expect(await check({ iat: now })).toBe('unknown');
    expect(await check({ sub: uri })).toBe('unknown');
    expect(await check({ sub: uri, iat: String(now) })).toBe('unknown');
  });
});

describe('status values', () => {
  it('read from the inflated bytes match the token-status-list library, entry by entry', async () => {
    const web = new FakeWeb();
    const registry = await party('did:web:registry.test');
    web.publishParty(registry);
    for (const bits of [1, 2, 4, 8] as const) {
      const uri = `https://registry.test/status/${bits}`;
      const values = Array.from({ length: 203 }, (_, i) => (i * 7 + bits) % (1 << bits));
      await publishStatusList(web, registry.signer, registry.did, uri, { ...values }, bits);
      const library = getListFromStatusListJWT(web.pages.get(uri)!.body);
      const checker = new StatusChecker({ resolver: web.resolver(), fetch: web.fetch });
      for (let idx = 0; idx < 64; idx++) {
        const v = library.getStatus(idx);
        const want = v === 0 ? 'valid' : v === 2 ? 'suspended' : 'invalid';
        expect((await checker.check({ status_list: { idx, uri } })).status, `${bits}:${idx}`).toBe(
          want,
        );
      }
      await expect(checker.check({ status_list: { idx: 1 << 20, uri } })).rejects.toThrow(
        /out of bounds/,
      );
    }
  });
});

describe('R7: DID documents that are the wrong shape', () => {
  it('reads service and alsoKnownAs that are not lists as none, without throwing', async () => {
    for (const service of [
      'FfnVerifiedBusiness',
      { type: 'FfnVerifiedBusiness' },
      7,
      null,
      [null, 'x', 3],
    ])
      expect(
        registryEntriesOf({ id: 'did:web:x.example', service } as never),
        String(service),
      ).toEqual([]);
    for (const alsoKnownAs of ['did:web:a.example', { 0: 'did:web:a.example' }, 1, null])
      expect(alsoKnownAsOf({ id: 'did:web:x.example', alsoKnownAs } as never)).toEqual([]);
    expect(
      alsoKnownAsOf({ id: 'did:web:x.example', alsoKnownAs: ['did:web:a.example', 5] } as never),
    ).toEqual(['did:web:a.example']);
  });

  it('answers key lookups on a malformed document with an error, not a crash', async () => {
    const did = 'did:web:odd.example';
    const resolver = new DidResolver({
      documents: {
        [did]: { id: did, verificationMethod: { id: 'x' }, assertionMethod: 'x' } as never,
      },
    });
    await expect(resolver.assertionKey(did, undefined)).rejects.toThrow(/no unique/);
    const someKey = (await generateEs256KeyPair()).publicJwk;
    expect(await resolver.controlsKey(did, someKey)).toBe(false);
    expect(await localSigner((await generateEs256KeyPair()).privateJwk, `${did}#k`)).toBeTruthy();
  });
});
