import {
  DidResolver,
  StatusChecker,
  buildDidDocument,
  didJwkFor,
  generateEs256KeyPair,
  localSigner,
  sdJwtVc,
  sdSigner,
  signCredential,
  signDelegation,
  signJwt,
  type DidDocument,
  type Fetch,
  type Jwk,
  type JwsSigner,
} from '@fofonet/door-core';
import { StatusList, createHeaderAndPayload } from '@owf/token-status-list';
import { describe, expect, it } from 'vitest';
import {
  FFN_BUSINESS_REGISTRY,
  dohResolver,
  keyThumbprint,
  lookupBusiness,
  pinRegistryKeys,
  staticTxt,
  verifyBusiness,
  verifyPresentation,
  verifyPresentationFor,
  type BusinessVerification,
} from '../src/index.js';
import type { HttpEntry, World } from '../scripts/vector-format.js';
import { replayFetch, world } from './world.js';

// The pre-publication hardening rules (SPEC R1–R5, R7) through the public API.

const dns = staticTxt(world.dns);
const didUrl = (domain: string) => `https://${domain}/.well-known/did.json`;
const docOf = (url: string) =>
  JSON.parse((world.http[url] as Extract<HttpEntry, { body: string }>).body) as DidDocument;
const withHttp = (changes: Record<string, HttpEntry>) => ({ ...world.http, ...changes });
const jsonEntry = (body: unknown): HttpEntry => ({
  status: 200,
  contentType: 'application/json',
  body: JSON.stringify(body),
});

function run(
  query: string | { phone: string },
  opts: {
    http?: World['http'];
    asked?: string[];
    fetch?: Fetch;
    observed?: { name?: string; phone?: string; address?: string };
    timeoutMs?: number;
    signal?: AbortSignal;
    registry?: World['registry'];
  } = {},
): Promise<BusinessVerification> {
  return verifyBusiness(query, {
    registry: opts.registry ?? world.registry,
    fetch: opts.fetch ?? replayFetch(opts.http ?? world.http, opts.asked),
    dns,
    now: world.now,
    ...(opts.observed ? { observed: opts.observed } : {}),
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    ...(opts.signal ? { signal: opts.signal } : {}),
  });
}

/** A body of `total` bytes streamed in 64 KiB pieces, counting what the reader pulled. */
function streamed(total: number) {
  const counter = { pulled: 0 };
  let left = total;
  const body = new ReadableStream<Uint8Array>({
    pull(c) {
      if (left <= 0) return c.close();
      const n = Math.min(65_536, left);
      left -= n;
      counter.pulled += n;
      c.enqueue(new Uint8Array(n).fill(32));
    },
  });
  return { body, counter };
}

const nowSec = () => Math.floor(Date.now() / 1000);

async function statusListJwt(signer: JwsSigner, iss: string, uri: string): Promise<string> {
  const now = nowSec();
  const { payload } = createHeaderAndPayload(
    new StatusList([0, 0, 0, 0], 2),
    { iss, sub: uri, iat: now, exp: now + 86_400, ttl: 3600 },
    { alg: 'ES256', typ: 'statuslist+jwt' },
  );
  return signJwt(signer, payload as Record<string, unknown>, { typ: 'statuslist+jwt' });
}

describe('R1: status lists through the pinned resolver', () => {
  // The review's repro: registry.test pins key A; someone with write access to its host
  // publishes another key or a path DID and serves /status/1 saying "valid".
  const REG = 'did:web:registry.test';
  const ROGUE = 'did:web:registry.test:rogue';
  const URI = 'https://registry.test/status/1';

  async function check(listSigner: JwsSigner, iss: string, extraRegistryKey?: Jwk) {
    const a = await generateEs256KeyPair();
    const docs: Record<string, string> = {
      'https://registry.test/.well-known/did.json': JSON.stringify(
        buildDidDocument(REG, [
          { kid: 'records-1', publicJwk: a.publicJwk },
          ...(extraRegistryKey ? [{ kid: 'records-9', publicJwk: extraRegistryKey }] : []),
        ]),
      ),
      'https://registry.test/rogue/did.json': JSON.stringify(
        buildDidDocument(ROGUE, [{ kid: 'k', publicJwk: listSigner.publicJwk }]),
      ),
    };
    const list = await statusListJwt(listSigner, iss, URI);
    const fetch: Fetch = async (u) =>
      u === URI
        ? new Response(list)
        : docs[u]
          ? new Response(docs[u])
          : new Response('nf', { status: 404 });
    const pinned = pinRegistryKeys(new DidResolver({ fetch }), REG, [
      await keyThumbprint(a.publicJwk),
    ]);
    return new StatusChecker({ resolver: pinned, fetch }).check(
      { status_list: { idx: 0, uri: URI } },
      REG,
    );
  }

  it('refuses a list signed by the registry DID with a listed but unpinned key', async () => {
    const r = await generateEs256KeyPair();
    const signer = await localSigner(r.privateJwk, `${REG}#records-9`);
    expect(await check(signer, REG, r.publicJwk)).toEqual({ status: 'unknown' });
  });

  it('refuses a list signed by a path DID on the registry host', async () => {
    const r = await generateEs256KeyPair();
    const signer = await localSigner(r.privateJwk, `${ROGUE}#k`);
    expect(await check(signer, ROGUE)).toEqual({ status: 'unknown' });
  });
});

describe('R2: known registry DIDs are pinned in every API', () => {
  const MAINNET = FFN_BUSINESS_REGISTRY.did;

  async function presentationFrom(issuerDid: string) {
    const intruder = await generateEs256KeyPair();
    const holder = await generateEs256KeyPair();
    const holderDid = didJwkFor(holder.publicJwk);
    const credential = await signCredential({
      signer: await localSigner(intruder.privateJwk, `${issuerDid}#records-9`),
      payload: {
        iss: issuerDid,
        sub: holderDid,
        vct: 'https://example.test/vct/thing',
        iat: nowSec(),
        cnf: { jwk: holder.publicJwk },
      },
    });
    const presentation = await sdJwtVc({
      kbSigner: sdSigner(await localSigner(holder.privateJwk, '')),
    }).present(credential, undefined as never, {
      kb: { payload: { iat: nowSec(), aud: 'https://door.test', nonce: 'n' } },
    });
    // The issuer's did.json lists the intruder's key as an assertion key.
    const host = issuerDid.slice('did:web:'.length);
    const doc = JSON.stringify(
      buildDidDocument(issuerDid, [{ kid: 'records-9', publicJwk: intruder.publicJwk }]),
    );
    const fetch: Fetch = async (u) =>
      u === didUrl(host) ? new Response(doc) : new Response('nf', { status: 404 });
    const input = {
      presentation,
      nonce: 'n',
      audience: 'https://door.test',
      issuers: [issuerDid],
    };
    return { input, fetch };
  }

  it('verifyPresentation refuses a mainnet registry credential under an unpinned key', async () => {
    const { input, fetch } = await presentationFrom(MAINNET);
    expect(await verifyPresentation(input, { fetch })).toMatchObject({
      verified: false,
      code: 'untrusted_issuer',
    });
    // The same credential from any other issuer verifies: only the known registry is pinned.
    const other = await presentationFrom('did:web:issuer.example');
    expect((await verifyPresentation(other.input, { fetch: other.fetch })).verified).toBe(true);
  });

  it('applies pins the caller passes for a custom registry', async () => {
    const c = world.cases.find((x) => x.name === 'headless-attestation')!;
    const { type: _t, ...input } = c.input as Extract<
      World['cases'][number]['input'],
      { type: 'verifyPresentation' }
    >;
    const fetch = replayFetch(world.http);
    const opts = { fetch, now: world.now };
    expect((await verifyPresentation(input, opts)).verified).toBe(true);
    expect((await verifyPresentation(input, { ...opts, registry: world.registry })).verified).toBe(
      true,
    );
    const otherPins = { ...world.registry, keyThumbprints: ['not-this-key'] };
    expect(await verifyPresentation(input, { ...opts, registry: otherPins })).toMatchObject({
      verified: false,
    });
  });
});

describe('R3: trust is decided before fetching', () => {
  // The review's repro (harness/ssrf.mts).
  async function attacker() {
    const now = nowSec();
    const atk = await generateEs256KeyPair();
    const ATK = 'did:web:attacker.example';
    const holder = await generateEs256KeyPair();
    const holderDid = didJwkFor(holder.publicJwk);
    const holderSigner = await localSigner(holder.privateJwk, '');
    const present = (compact: string, nonce: string) =>
      sdJwtVc({ kbSigner: sdSigner(holderSigner) }).present(compact, undefined as never, {
        kb: { payload: { iat: now, aud: 'https://agent.example', nonce } },
      });
    const delegation = await signDelegation({
      signer: await localSigner(atk.privateJwk, `${ATK}#k1`),
      delegator: ATK,
      delegate: { did: holderDid, kind: 'agent', key: holder.publicJwk },
      scope: ['anything'],
      expiresAt: new Date((now + 3600) * 1000).toISOString(),
      status: { status_list: { idx: 0, uri: 'https://10.0.0.5:8443/admin/reset?all=1' } },
      now,
    });
    const internalIssuer = 'did:web:10.0.0.9%3A9443:internal:svc';
    const credential = await signCredential({
      signer: await localSigner(atk.privateJwk, `${internalIssuer}#k1`),
      payload: {
        iss: internalIssuer,
        sub: holderDid,
        vct: 'https://x/vct',
        cnf: { jwk: holder.publicJwk },
      },
    });
    const asked: string[] = [];
    let pulled = 0;
    const fetch: Fetch = async (url) => {
      asked.push(url);
      if (url === 'https://attacker.example/.well-known/did.json')
        return new Response(
          JSON.stringify(buildDidDocument(ATK, [{ kid: 'k1', publicJwk: atk.publicJwk }])),
        );
      const { body, counter } = streamed(64 * 1024 * 1024);
      pulled = counter.pulled;
      return new Response(body);
    };
    return {
      asked,
      pulled: () => pulled,
      fetch,
      delegation: await present(delegation, 'n1'),
      credential: await present(credential, 'n2'),
    };
  }

  it('a delegation rooted at a DID the caller does not accept costs no request', async () => {
    const a = await attacker();
    const r = await verifyPresentationFor(
      {
        presentation: a.delegation,
        nonce: 'n1',
        audience: 'https://agent.example',
        roots: ['did:web:registry.fofo.network'],
      },
      { registry: FFN_BUSINESS_REGISTRY, fetch: a.fetch },
    );
    expect(r).toMatchObject({ verified: false, code: 'untrusted_root' });
    expect(a.asked).toEqual([]);
    expect(a.pulled()).toBe(0);
  });

  it('a credential from an issuer the caller does not accept costs no request', async () => {
    const a = await attacker();
    const r = await verifyPresentationFor(
      { presentation: a.credential, nonce: 'n2', audience: 'https://agent.example' },
      { registry: FFN_BUSINESS_REGISTRY, fetch: a.fetch },
    );
    expect(r).toMatchObject({ verified: false, code: 'untrusted_issuer' });
    expect(a.asked).toEqual([]);
  });

  it("verifyBusiness never resolves an attestation's or profile's foreign issuer", async () => {
    const asked: string[] = [];
    const mixed = await run('mixed-issuers.example', { asked });
    expect(mixed.facts.find((f) => f.kind === 'businessIdentity')?.status).toBe('invalid');
    expect(asked).not.toContain(didUrl('rogue-issuer.test'));
    asked.length = 0;
    const borrowed = await run('borrowed-profile.example', { asked });
    expect(borrowed.failure?.code).toBe('bad_profile');
    expect(asked).not.toContain(didUrl('acme-hvac.example'));
  });

  it("does not repeat an untrusted host's status or body; does for the registry", async () => {
    const r = await run('acme-hvac.example', {
      http: withHttp({
        [didUrl('acme-hvac.example')]: {
          status: 503,
          contentType: 'text/plain',
          body: 'internal-secret-token',
        },
      }),
    });
    expect(r.failure?.code).toBe('binding_unreachable');
    expect(JSON.stringify(r)).not.toMatch(/503|internal-secret-token/);
    const reg = await run('acme-hvac.example', {
      http: withHttp({
        'https://registry.test/v1/lookup?domain=acme-hvac.example': {
          status: 503,
          contentType: 'text/plain',
          body: 'x',
        },
      }),
    });
    expect(reg.failure).toEqual({
      code: 'registry_unavailable',
      message: 'the registry answered HTTP 503',
    });
  });
});

describe('R4: bounded requests', () => {
  it('times out a business host that never answers', async () => {
    const base = replayFetch(world.http);
    const hang: Fetch = (url, init) =>
      url === didUrl('acme-hvac.example')
        ? new Promise<Response>(() => undefined)
        : base(url, init);
    const t = Date.now();
    const r = await run('acme-hvac.example', { fetch: hang, timeoutMs: 100 });
    expect(Date.now() - t).toBeLessThan(5000);
    expect(r.failure?.code).toBe('binding_unreachable');
  });

  it('stops reading a registry answer past 1 MiB', async () => {
    const { body, counter } = streamed(8 * 1024 * 1024);
    const r = await run('acme-hvac.example', { fetch: async () => new Response(body) });
    expect(r.failure).toEqual({
      code: 'registry_unavailable',
      message: 'the registry answer was too large',
    });
    expect(counter.pulled).toBeLessThan(1024 * 1024 + 256 * 1024);
  });

  it('stops reading a DNS-over-HTTPS answer past 64 KiB', async () => {
    const { body, counter } = streamed(1024 * 1024);
    await expect(
      dohResolver('cloudflare', async () => new Response(body)).txt('_ffn.acme-hvac.example'),
    ).rejects.toThrow(/too large/);
    expect(counter.pulled).toBeLessThan(256 * 1024);
  });

  it('never follows a redirect, and passes a signal on every request', async () => {
    const inits: Array<RequestInit | undefined> = [];
    const base = replayFetch(world.http);
    const fetch: Fetch = (u, init) => {
      inits.push(init);
      return base(u, init);
    };
    expect((await run('acme-hvac.example', { fetch })).verified).toBe(true);
    expect(inits.length).toBeGreaterThan(3);
    for (const init of inits) {
      expect(init?.redirect).toBe('manual');
      expect(init?.signal).toBeInstanceOf(AbortSignal);
    }
    const moved = await run('acme-hvac.example', {
      fetch: async () =>
        new Response(null, { status: 301, headers: { location: 'https://elsewhere.test/' } }),
    });
    expect(moved.failure?.code).toBe('registry_unavailable');
  });

  it('requires an https registry, except http on loopback', async () => {
    const asked: string[] = [];
    const fetch = replayFetch({}, asked);
    for (const origin of ['http://registry.test', 'ftp://registry.test', 'not a url']) {
      const registry = { ...world.registry, origin };
      await expect(run('acme-hvac.example', { fetch, registry })).rejects.toThrow(/refused/);
      await expect(
        lookupBusiness({ domain: 'acme-hvac.example' }, { registry, fetch }),
      ).rejects.toThrow(/refused/);
    }
    expect(asked).toEqual([]);
    const local = await run('acme-hvac.example', {
      fetch,
      registry: { ...world.registry, origin: 'http://localhost:8080' },
    });
    expect(local.failure?.code).toBe('not_in_registry');
    expect(asked).toEqual(['http://localhost:8080/v1/lookup?domain=acme-hvac.example']);
  });

  it("rejects with the caller's abort", async () => {
    const controller = new AbortController();
    controller.abort(new Error('caller gave up'));
    await expect(run('acme-hvac.example', { signal: controller.signal })).rejects.toThrow(
      'caller gave up',
    );
  });
});

describe('R5: observedMatches', () => {
  it('is on every result, and true exactly when there are no mismatches', async () => {
    expect((await run('acme-hvac.example')).observedMatches).toBe(true);
    const same = await run('acme-hvac.example', {
      observed: { name: 'Acme HVAC Inc', phone: '415-555-0100', address: 'Oakland, CA 94607' },
    });
    expect(same).toMatchObject({ verified: true, observedMatches: true, mismatches: [] });
    const other = await run('acme-hvac.example', { observed: { phone: '415-555-0199' } });
    expect(other).toMatchObject({ verified: true, observedMatches: false });
    expect(other.mismatches).toHaveLength(1);
    // Verification that stops before comparing has no mismatches; `verified` is what says no.
    const missing = await run('nobody.example', { observed: { name: 'Acme HVAC' } });
    expect(missing).toMatchObject({ verified: false, observedMatches: true, mismatches: [] });
  });
});

describe('R6 parity: queries by phone', () => {
  it('takes a domain or a phone number, not both and not neither', async () => {
    const fetch = replayFetch(world.http);
    const options = { registry: world.registry, fetch, dns, now: world.now };
    for (const query of [
      { domain: 'acme-hvac.example', phone: '+14155550100' },
      {},
      { domain: undefined, phone: undefined },
    ])
      await expect(verifyBusiness(query as never, options), JSON.stringify(query)).rejects.toThrow(
        TypeError,
      );
    // A key present but undefined is absent.
    const r = await verifyBusiness({ domain: undefined, phone: '+14155550100' } as never, options);
    expect(r).toMatchObject({ verified: true, domain: 'acme-hvac.example', phone: '+14155550100' });
  });
});

describe('R7: DID documents of the wrong shape', () => {
  const acme = docOf(didUrl('acme-hvac.example'));
  const heating = docOf(didUrl('acme-heating.example'));

  it('reads a service that is not a list as no registry entry', async () => {
    for (const service of ['https://registry.test/v1/businesses/rec-acme', { a: 1 }, 7, null]) {
      const r = await run('acme-hvac.example', {
        http: withHttp({ [didUrl('acme-hvac.example')]: jsonEntry({ ...acme, service }) }),
      });
      expect(r, JSON.stringify(service)).toMatchObject({
        verified: false,
        binding: { status: 'missing' },
        failure: { code: 'binding_failed' },
      });
    }
  });

  it('reads an alsoKnownAs that is not a list as naming no one', async () => {
    // A string containing the DID used to pass as a substring match.
    for (const alsoKnownAs of ['did:web:acme-hvac.example', { 0: 'did:web:acme-hvac.example' }]) {
      const r = await run('acme-heating.example', {
        http: withHttp({
          [didUrl('acme-heating.example')]: jsonEntry({ ...heating, alsoKnownAs }),
        }),
      });
      expect(r, JSON.stringify(alsoKnownAs)).toMatchObject({
        verified: false,
        binding: { status: 'missing' },
      });
    }
    // The list form still binds.
    expect((await run('acme-heating.example')).verified).toBe(true);
  });
});
