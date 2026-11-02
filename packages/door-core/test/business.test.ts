import { describe, expect, it } from 'vitest';
import {
  BusinessKinds,
  CredentialError,
  StatusChecker,
  buildDidDocument,
  businessDidDocument,
  didJwkFor,
  ffnTxtValue,
  generateEs256KeyPair,
  jwkOfDidJwk,
  levelFor,
  localSigner,
  normalizeDomain,
  normalizePhone,
  parseFfnTxt,
  registryEntriesOf,
  sdJwtVc,
  sdSigner,
  signCredential,
  signDelegation,
  typeMetadata,
  verifyCredential,
  verifyDelegationChain,
  type DidDocument,
  type Jwk,
} from '../src/index.js';
import { FakeWeb, party, publishStatusList } from './helpers.js';

const days = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString();

describe('identifiers', () => {
  it('normalizes domains to lowercase punycode and refuses non-domains', () => {
    expect(normalizeDomain(' ACME-HVAC.com. ')).toBe('acme-hvac.com');
    // Cyrillic "а": a different name, which no verified business lists.
    expect(normalizeDomain('аcme-hvac.com')).toMatch(/^xn--/);
    expect(normalizeDomain('аcme-hvac.com')).not.toBe('acme-hvac.com');
    for (const bad of ['https://acme.com', 'acme.com/x', '10.0.0.1', 'localhost', 'a b.com', ''])
      expect(() => normalizeDomain(bad)).toThrow();
  });

  it('normalizes phones to E.164, taking ten digits as NANP', () => {
    expect(normalizePhone('(415) 555-0100')).toBe('+14155550100');
    expect(normalizePhone('1-415-555-0100')).toBe('+14155550100');
    expect(normalizePhone('+44 20 7946 0958')).toBe('+442079460958');
    expect(() => normalizePhone('555-0100')).toThrow();
  });

  it('round-trips did:jwk and resolves it locally', async () => {
    const { publicJwk } = await generateEs256KeyPair();
    const did = didJwkFor({ ...publicJwk, alg: 'ES256' } as Jwk);
    expect(jwkOfDidJwk(did)).toEqual({ crv: 'P-256', kty: 'EC', x: publicJwk.x, y: publicJwk.y });
    expect(didJwkFor(jwkOfDidJwk(did))).toBe(did);
    const web = new FakeWeb();
    const key = await web.resolver().keyFor(did, '#0', 'authentication');
    expect(key.x).toBe(publicJwk.x);
  });

  it('reads FFN TXT records, quoted or split', () => {
    const value = ffnTxtValue({ did: 'did:web:acme-hvac.com', registry: 'registry.test' });
    expect(parseFfnTxt(value)).toEqual({
      v: 'ffn1',
      did: 'did:web:acme-hvac.com',
      registry: 'registry.test',
    });
    expect(
      parseFfnTxt(`"v=ffn1; did=did:web:acme-hvac.com; " "registry=registry.test"`)?.registry,
    ).toBe('registry.test');
    expect(parseFfnTxt('v=spf1 include:_spf.google.com ~all')).toBeUndefined();
  });

  it('carries an optional key thumbprint, and records without one read as before', () => {
    const value = ffnTxtValue({
      did: 'did:web:acme-hvac.com',
      registry: 'registry.test',
      key: 'abc_-1',
    });
    expect(value).toBe('v=ffn1; did=did:web:acme-hvac.com; registry=registry.test; key=abc_-1');
    expect(parseFfnTxt(value)).toEqual({
      v: 'ffn1',
      did: 'did:web:acme-hvac.com',
      registry: 'registry.test',
      key: 'abc_-1',
    });
    expect(
      parseFfnTxt('v=ffn1; did=did:web:acme-hvac.com; registry=registry.test'),
    ).not.toHaveProperty('key');
  });

  it('builds a business DID document that points back to its registry entry', async () => {
    const acme = await party('did:web:acme-hvac.com');
    const doc = businessDidDocument({
      did: acme.did,
      keys: [{ kid: acme.signer.kid, publicJwk: acme.privateJwk }],
      registryEntry: 'https://registry.test/v1/businesses/abc',
    });
    expect(registryEntriesOf(doc)).toEqual(['https://registry.test/v1/businesses/abc']);
    expect(JSON.stringify(doc)).not.toContain('"d"');
    expect(doc.authentication).toEqual([acme.signer.kid]);
  });
});

describe('levels and type metadata', () => {
  it('levels are cumulative', () => {
    expect(levelFor(new Set(['businessIdentity']))).toBe(0);
    expect(levelFor(new Set(['businessIdentity', 'officialChannels']))).toBe(1);
    expect(levelFor(new Set(['businessIdentity', 'officialChannels', 'license']))).toBe(1);
    expect(
      levelFor(new Set(['businessIdentity', 'officialChannels', 'license', 'insurance'])),
    ).toBe(2);
    expect(
      levelFor(
        new Set(['businessIdentity', 'officialChannels', 'license', 'insurance', 'representative']),
      ),
    ).toBe(3);
  });

  it('publishes metadata for every business type', () => {
    const meta = typeMetadata(BusinessKinds.license) as { claims: Array<{ path: string[] }> };
    expect(meta.claims.map((c) => c.path[0])).toContain('licenseNumber');
    expect(typeMetadata('https://example.com/unknown')).toBeUndefined();
  });
});

describe('self-signed credentials', () => {
  it('verifies a business profile against the business DID, and rejects tampering', async () => {
    const web = new FakeWeb();
    const acme = await party('did:web:acme-hvac.com');
    web.publishParty(acme);
    const profile = await signCredential({
      signer: acme.signer,
      payload: {
        iss: acme.did,
        sub: acme.did,
        vct: BusinessKinds.businessProfile,
        iat: Math.floor(Date.now() / 1000),
        cnf: { jwk: acme.publicJwk },
        name: 'Acme HVAC',
        domains: ['acme-hvac.com'],
        phones: ['+14155550100'],
      },
    });
    const v = await verifyCredential(profile, { resolver: web.resolver() });
    expect(v.claims.name).toBe('Acme HVAC');

    const [jwt] = profile.split('~');
    const [h, p, s] = jwt!.split('.');
    const forged = JSON.parse(Buffer.from(p!, 'base64url').toString());
    forged.phones = ['+14155559999'];
    const tampered = `${h}.${Buffer.from(JSON.stringify(forged)).toString('base64url')}.${s}~`;
    await expect(verifyCredential(tampered, { resolver: web.resolver() })).rejects.toThrow(
      CredentialError,
    );

    // A lookalike signing with its own key under the real DID's name gets nowhere.
    const rogue = await party('did:web:acme-hvac.com');
    const fake = await signCredential({
      signer: rogue.signer,
      payload: {
        iss: acme.did,
        vct: BusinessKinds.businessProfile,
        cnf: { jwk: rogue.publicJwk },
        name: 'Acme HVAC',
      },
    });
    await expect(verifyCredential(fake, { resolver: web.resolver() })).rejects.toThrow(
      /verification/,
    );
  });
});

// ---------------------------------------------------------------------------
// Delegation chains
// ---------------------------------------------------------------------------

async function world() {
  const web = new FakeWeb();
  const registry = await party('did:web:registry.test');
  web.publishParty(registry);
  const business = await party('did:web:acme-hvac.com');
  web.publishParty(business);
  const agent = await party('did:web:acme-hvac.com:agents:booking');
  const agentDoc: DidDocument = {
    ...buildDidDocument(agent.did, [{ kid: agent.signer.kid, publicJwk: agent.publicJwk }]),
    controller: business.did,
    authentication: [agent.signer.kid],
  };
  web.publishDid(agentDoc);
  const subKeys = await generateEs256KeyPair();
  const subDid = didJwkFor(subKeys.publicJwk);
  const sub = {
    did: subDid,
    signer: await localSigner(subKeys.privateJwk, ''),
    publicJwk: subKeys.publicJwk,
  };
  const statusUri = 'https://registry.test/status/1';
  await publishStatusList(web, registry.signer, registry.did, statusUri);

  const toAgent = await signDelegation({
    signer: business.signer,
    delegator: business.did,
    delegate: { did: agent.did, kind: 'agent', key: agent.publicJwk },
    scope: ['booking:*', 'quote:request'],
    expiresAt: days(30),
    status: { status_list: { idx: 3, uri: statusUri } },
    purpose: 'Books service calls',
  });
  // The agent signs with its own key; its kid must name a key in its DID document.
  const toSub = await signDelegation({
    signer: agent.signer,
    delegator: agent.did,
    delegate: { did: sub.did, kind: 'agent', key: sub.publicJwk },
    scope: ['booking:create'],
    expiresAt: days(7),
    parent: toAgent,
  });
  const status = () =>
    new StatusChecker({ resolver: web.resolver(), fetch: web.fetch, maxAgeSeconds: 0 });
  return { web, registry, business, agent, sub, statusUri, toAgent, toSub, status };
}

/** The leaf presented with key binding, as the headless door receives it. */
async function present(
  compact: string,
  signer: Awaited<ReturnType<typeof world>>['sub']['signer'],
  nonce: string,
) {
  const sdjwt = sdJwtVc({ kbSigner: sdSigner(signer) });
  return sdjwt.present(compact, undefined as never, {
    kb: { payload: { iat: Math.floor(Date.now() / 1000), aud: 'https://door.test', nonce } },
  });
}

describe('delegation chains', () => {
  it('walks a two-link chain to the root, bounded by every parent', async () => {
    const w = await world();
    const presented = await present(w.toSub, w.sub.signer, 'n-1');
    const chain = await verifyDelegationChain([presented, w.toAgent], {
      resolver: w.web.resolver(),
      status: w.status(),
      roots: [w.business.did],
      requiredScope: ['booking:create'],
      keyBinding: { nonce: 'n-1', audience: 'https://door.test' },
    });
    expect(chain).toMatchObject({
      root: w.business.did,
      delegate: w.sub.did,
      scope: ['booking:create'],
    });
    expect(chain.links.map((l) => l.iss)).toEqual([w.agent.did, w.business.did]);
    expect(Date.parse(chain.expiresAt)).toBeLessThan(Date.parse(days(8)));

    await expect(
      verifyDelegationChain([presented, w.toAgent], {
        resolver: w.web.resolver(),
        status: w.status(),
        requiredScope: ['quote:request'],
      }),
    ).rejects.toMatchObject({ code: 'insufficient_scope' });
    await expect(
      verifyDelegationChain([presented, w.toAgent], {
        resolver: w.web.resolver(),
        status: w.status(),
        keyBinding: { nonce: 'other', audience: 'https://door.test' },
      }),
    ).rejects.toThrow();
  });

  it('rejects a chain whose root this verifier does not accept', async () => {
    const w = await world();
    await expect(
      verifyDelegationChain([w.toSub, w.toAgent], {
        resolver: w.web.resolver(),
        status: w.status(),
        roots: ['did:web:someone-else.com'],
      }),
    ).rejects.toMatchObject({ code: 'untrusted_root' });
  });

  it('rejects broken chains', async () => {
    const w = await world();
    const opts = () => ({ resolver: w.web.resolver(), status: w.status() });
    const broken = async (chain: string[], match: RegExp | string) =>
      expect(verifyDelegationChain(chain, opts())).rejects.toThrow(match);

    // Missing the root.
    await broken([w.toSub], /missing its root/);
    // A child that widens its parent's scope.
    const wider = await signDelegation({
      signer: w.agent.signer,
      delegator: w.agent.did,
      delegate: { did: w.sub.did, kind: 'agent', key: w.sub.publicJwk },
      scope: ['payments:send'],
      expiresAt: days(7),
      parent: w.toAgent,
    });
    await broken([wider, w.toAgent], /widens the scope/);
    // A child that outlives its parent.
    const longer = await signDelegation({
      signer: w.agent.signer,
      delegator: w.agent.did,
      delegate: { did: w.sub.did, kind: 'agent', key: w.sub.publicJwk },
      scope: ['booking:create'],
      expiresAt: days(60),
      parent: w.toAgent,
    });
    await broken([longer, w.toAgent], /outlives/);
    // Spliced under a different parent than the one it names.
    const otherParent = await signDelegation({
      signer: w.business.signer,
      delegator: w.business.did,
      delegate: { did: w.agent.did, kind: 'agent', key: w.agent.publicJwk },
      scope: ['booking:*'],
      expiresAt: days(30),
    });
    await broken([w.toSub, otherParent], /different parent/);
    // Signed by the business directly, though the parent delegated to the agent's key.
    const skipped = await signDelegation({
      signer: w.business.signer,
      delegator: w.agent.did,
      delegate: { did: w.sub.did, kind: 'agent', key: w.sub.publicJwk },
      scope: ['booking:create'],
      expiresAt: days(7),
      parent: w.toAgent,
    });
    await expect(verifyDelegationChain([skipped, w.toAgent], opts())).rejects.toThrow();
    // Bound to a key the delegate's DID doesn't list.
    const stranger = await generateEs256KeyPair();
    const unbound = await signDelegation({
      signer: w.business.signer,
      delegator: w.business.did,
      delegate: { did: w.agent.did, kind: 'agent', key: stranger.publicJwk },
      scope: ['booking:*'],
      expiresAt: days(30),
    });
    await broken([unbound], /doesn't list/);
    // Order matters: root first is not a chain.
    await expect(verifyDelegationChain([w.toAgent, w.toSub], opts())).rejects.toThrow();
    // A did:jwk delegate bound to some other key.
    const notTheirs = await signDelegation({
      signer: w.agent.signer,
      delegator: w.agent.did,
      delegate: { did: w.sub.did, kind: 'agent', key: stranger.publicJwk },
      scope: ['booking:create'],
      expiresAt: days(7),
      parent: w.toAgent,
    });
    await broken([notTheirs, w.toAgent], /doesn't hold/);
  });

  it('requires each link to come from the delegate above it, with the delegated key', async () => {
    const w = await world();
    const opts = () => ({ resolver: w.web.resolver(), status: w.status() });
    // Another DID that happens to list the agent's key signs the child: right key, wrong delegate.
    const other = 'did:web:other.test';
    w.web.publishDid(
      buildDidDocument(other, [{ kid: `${other}#key-1`, publicJwk: w.agent.publicJwk }]),
    );
    const impostor = await signDelegation({
      signer: await localSigner(w.agent.privateJwk, `${other}#key-1`),
      delegator: other,
      delegate: { did: w.sub.did, kind: 'agent', key: w.sub.publicJwk },
      scope: ['booking:create'],
      expiresAt: days(7),
      parent: w.toAgent,
    });
    await expect(verifyDelegationChain([impostor, w.toAgent], opts())).rejects.toThrow(
      /not the delegate above it/,
    );

    // The right delegate, but signing with a second key the delegation wasn't bound to.
    const second = await party(w.agent.did, 'key-2');
    w.web.publishDid({
      ...buildDidDocument(w.agent.did, [
        { kid: w.agent.signer.kid, publicJwk: w.agent.publicJwk },
        { kid: second.signer.kid, publicJwk: second.publicJwk },
      ]),
      controller: w.business.did,
    });
    const wrongKey = await signDelegation({
      signer: second.signer,
      delegator: w.agent.did,
      delegate: { did: w.sub.did, kind: 'agent', key: w.sub.publicJwk },
      scope: ['booking:create'],
      expiresAt: days(7),
      parent: w.toAgent,
    });
    await expect(verifyDelegationChain([wrongKey, w.toAgent], opts())).rejects.toThrow(
      /key the parent didn't delegate to/,
    );
  });

  it('fails a revoked or suspended link, and an unreachable status list closed', async () => {
    const w = await world();
    for (const value of [1, 2]) {
      await publishStatusList(w.web, w.registry.signer, w.registry.did, w.statusUri, { 3: value });
      await expect(
        verifyDelegationChain([w.toSub, w.toAgent], {
          resolver: w.web.resolver(),
          status: w.status(),
        }),
      ).rejects.toMatchObject({ code: 'revoked' });
    }
    w.web.pages.delete(w.statusUri);
    await expect(
      verifyDelegationChain([w.toSub, w.toAgent], {
        resolver: w.web.resolver(),
        status: w.status(),
      }),
    ).rejects.toMatchObject({ code: 'status_unknown' });
    const lenient = await verifyDelegationChain([w.toSub, w.toAgent], {
      resolver: w.web.resolver(),
      status: w.status(),
      allowUnknownStatus: true,
    });
    expect(lenient.links[1]!.status).toBe('unknown');
  });

  it('accepts a status list only from the root DID of the host that serves it', async () => {
    const w = await world();
    const rogue = await party('did:web:rogue.test');
    w.web.publishParty(rogue);
    // A list at registry.test signed by rogue.test is ignored.
    await publishStatusList(w.web, rogue.signer, rogue.did, w.statusUri);
    const checked = await w
      .status()
      .check({ status_list: { idx: 3, uri: w.statusUri } }, w.business.did);
    expect(checked.status).toBe('unknown');
  });
});
