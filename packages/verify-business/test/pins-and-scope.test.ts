import { networkFromEnv, type DidDocument, type Fetch } from '@fofonet/door-core';
import { describe, expect, it } from 'vitest';
import {
  FFN_BUSINESS_REGISTRY,
  ScopeDisclaimers,
  lookupBusiness,
  staticTxt,
  verifyBusiness,
  verifyPresentationFor,
  type RegistryAnchor,
} from '../src/index.js';
import type { World } from '../scripts/vector-format.js';
import { replayFetch, world } from './world.js';

// Registry key pins (item 14) and the scope of assertion (item 16), on the
// vector world: its registry did.json lists #records-1 (signing), #records-2
// (standby, no relationship) and #records-9 (an assertion key nobody pins).

const DID_URL = 'https://registry.test/.well-known/did.json';

const fetchFrom = (http: World['http']): Fetch => replayFetch(http);
const fetch = fetchFrom(world.http);
const dns = staticTxt(world.dns);
const run = (domain: string, registry: RegistryAnchor = world.registry, f = fetch) =>
  verifyBusiness(domain, { registry, fetch: f, dns, now: world.now });

/** The world after the standby is promoted: #records-2 becomes an assertion key too. */
function promoted(): Fetch {
  const doc = JSON.parse((world.http[DID_URL] as { body: string }).body) as DidDocument;
  doc.assertionMethod = [...(doc.assertionMethod ?? []), `${world.registry.did}#records-2`];
  return fetchFrom({
    ...world.http,
    [DID_URL]: { status: 200, contentType: 'application/json', body: JSON.stringify(doc) },
  });
}

describe('registry key pins', () => {
  it('reject a key did.json lists but the verifier does not pin', async () => {
    const unpinned = { ...world.registry, keyThumbprints: undefined };
    // The registry's own document vouches for #records-9, so without pins it verifies...
    expect((await run('unpinned-key.example', unpinned)).verified).toBe(true);
    // ...and with them it doesn't, naming why.
    const pinned = await run('unpinned-key.example');
    expect(pinned).toMatchObject({ verified: false, failure: { code: 'bad_record' } });
    expect(pinned.failure!.message).toContain('not one of the registry keys this verifier pins');
    // The same key inside an otherwise good record: its attestation alone is dropped.
    const smuggled = await run('smuggled-license.example');
    expect(smuggled.facts.find((f) => f.kind === 'license')).toMatchObject({ status: 'invalid' });
    expect((await run('smuggled-license.example', unpinned)).level).toBe(2);
  });

  it('cover the standby, so a planned rotation keeps deployed verifiers working', async () => {
    // Before promotion the standby signs nothing...
    expect((await run('standby-key.example')).failure?.code).toBe('bad_record');
    // ...after it, a record it signs verifies under the same pins...
    const after = await run('standby-key.example', world.registry, promoted());
    expect(after, after.summary).toMatchObject({ verified: true, level: 2 });
    // ...and the records #records-1 signed still do.
    expect((await run('acme-hvac.example', world.registry, promoted())).verified).toBe(true);
    // A verifier that pinned only the old key would have broken.
    const oldPinsOnly = { ...world.registry, keyThumbprints: [world.registry.keyThumbprints[0]!] };
    const broken = await run('standby-key.example', oldPinsOnly, promoted());
    expect(broken.failure?.code).toBe('bad_record');
  });

  it('apply to lookups and to presentations of registry credentials', async () => {
    await expect(
      lookupBusiness(
        { domain: 'unpinned-key.example' },
        { registry: world.registry, fetch, now: world.now },
      ),
    ).rejects.toThrow(/pins/);
    const input = world.cases.find((c) => c.name === 'headless-attestation')!.input as Extract<
      World['cases'][number]['input'],
      { type: 'verifyPresentation' }
    >;
    const args = {
      presentation: input.presentation,
      nonce: input.nonce,
      audience: input.audience,
      issuers: input.issuers!,
    };
    const deps = (registry: RegistryAnchor) => ({ registry, fetch, now: world.now });
    expect(
      (await verifyPresentationFor(args, deps(world.registry))).verified,
      'signed with #records-1',
    ).toBe(true);
    const otherPins = { ...world.registry, keyThumbprints: ['not-this-key'] };
    expect(await verifyPresentationFor(args, deps(otherPins))).toMatchObject({
      verified: false,
    });
  });

  it('ship for the production registry, and stay only while the origin is its own', () => {
    expect(FFN_BUSINESS_REGISTRY).toMatchObject({
      origin: 'https://registry.fofo.network',
      did: 'did:web:registry.fofo.network',
    });
    // KMS fofo-network-mainet registry-signer v1, as live did.json served it on Nov 1, 2026.
    expect(FFN_BUSINESS_REGISTRY.keyThumbprints).toContain(
      'ha2yRH_LpeVyIJR5KvD_3m10ZQCbe1ppRqo5Swo7B6k',
    );
    const own = networkFromEnv({ PASS_NETWORK: 'production' }).businessRegistry;
    expect(own.keyThumbprints).toEqual(FFN_BUSINESS_REGISTRY.keyThumbprints);
    const same = networkFromEnv({
      PASS_NETWORK: 'production',
      BUSINESS_REGISTRY_ORIGIN: 'https://registry.fofo.network',
    }).businessRegistry;
    expect(same.keyThumbprints).toEqual(FFN_BUSINESS_REGISTRY.keyThumbprints);
    const moved = networkFromEnv({
      PASS_NETWORK: 'production',
      BUSINESS_REGISTRY_ORIGIN: 'https://registry.test',
    }).businessRegistry;
    expect(moved.keyThumbprints).toBeUndefined();
    const configured = networkFromEnv({
      PASS_NETWORK: 'devnet',
      BUSINESS_REGISTRY_ORIGIN: 'https://registry.test',
      BUSINESS_REGISTRY_KEY_THUMBPRINTS: ' a, b ,',
    }).businessRegistry;
    expect(configured.keyThumbprints).toEqual(['a', 'b']);
  });
});

describe('scope of assertion', () => {
  it('states what was verified, what never is, and where it is explained', async () => {
    const r = await run('acme-hvac.example');
    expect(r.scope!.explanation).toBe('https://registry.test/how-it-works#scope');
    expect(r.scope!.doesNotAssert.map((d) => d.code)).toEqual(ScopeDisclaimers.map((d) => d.code));
    expect(r.scope!.doesNotAssert.map((d) => d.code)).toEqual(
      expect.arrayContaining(['rating', 'ranking', 'recommendation', 'endorsement', 'quality']),
    );
    const callerId = r.scope!.doesNotAssert.find((d) => d.code === 'inbound-caller-id')!;
    expect(callerId.statement).toMatch(/when you call it/);
    expect(callerId.statement).toMatch(/never shows that a call or text you receive/);
    for (const a of r.scope!.asserts) expect(a.statement, a.code).toBeTruthy();
    expect(r.summary).toContain(
      'A verified phone number shows the business controls it when you call it, not that a call or text you receive comes from the business.',
    );
    // Nothing in the scope rates or recommends.
    expect(JSON.stringify(r.scope!.asserts)).not.toMatch(
      /\b(trusted|recommended|endorsed|rated)\b/i,
    );
  });

  it('is carried by lookups as the record states it', async () => {
    const found = await lookupBusiness(
      { domain: 'acme-hvac.example' },
      { registry: world.registry, fetch, now: world.now },
    );
    expect(found.record!.scope!.asserts.map((a) => a.code)).toContain('license-active');
    const legacy = await lookupBusiness(
      { domain: 'legacy-record.example' },
      { registry: world.registry, fetch, now: world.now },
    );
    expect(legacy.found).toBe(true);
    expect(legacy.record).not.toHaveProperty('scope');
  });
});
