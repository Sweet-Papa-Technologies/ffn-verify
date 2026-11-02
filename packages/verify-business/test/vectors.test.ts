import { describe, expect, it, vi } from 'vitest';
import {
  staticTxt,
  verifyBusiness,
  verifyPresentation,
  type BusinessVerification,
  type PresentationResult,
} from '../src/index.js';
import { replayFetch, world } from './world.js';

// Replays vectors/business/v1.json offline. The Python verifier runs the same file.
// The format, extensions included, is documented in scripts/generate-vectors.ts;
// a key this runner doesn't know fails the case, so nothing goes unchecked.

const fetch = replayFetch(world.http);
const dns = staticTxt(world.dns);

const CASE_KEYS = ['name', 'description', 'input', 'expected', 'http', 'dns'];
const FETCH_KEYS = ['fetches', 'noFetches', 'maxFetches'];
const BUSINESS_KEYS = [
  'verified',
  'level',
  'binding',
  'lowerAssurance',
  'failure',
  'mismatches',
  'facts',
  'summaryIncludes',
  'warningsInclude',
  'reasons',
  'scope',
  'observedMatches',
  'phone',
  'domain',
  'delegation',
  ...FETCH_KEYS,
];
const PRESENTATION_KEYS = [
  'verified',
  'code',
  'subject',
  'root',
  'delegate',
  'scope',
  'issuer',
  'vct',
  'messageIncludes',
  ...FETCH_KEYS,
];

const unknownKeys = (o: object, known: string[]) =>
  Object.keys(o).filter((k) => !known.includes(k));

function checkBusiness(r: BusinessVerification, e: Record<string, unknown>) {
  expect(unknownKeys(e, BUSINESS_KEYS), 'expectations this runner does not check').toEqual([]);
  if ('verified' in e) expect(r.verified, r.summary).toBe(e.verified);
  if ('level' in e) expect(r.level).toBe(e.level);
  if ('binding' in e) expect(r.binding.status).toBe(e.binding);
  if ('lowerAssurance' in e) expect(r.binding.lowerAssurance).toBe(e.lowerAssurance);
  if ('failure' in e) expect(r.failure?.code, r.summary).toBe(e.failure);
  if ('mismatches' in e)
    expect(r.mismatches, r.mismatches.join(' | ')).toHaveLength(e.mismatches as number);
  for (const [kind, status] of Object.entries((e.facts ?? {}) as Record<string, string>))
    expect(r.facts.find((f) => f.kind === kind)?.status, kind).toBe(status);
  if (e.summaryIncludes) expect(r.summary).toContain(e.summaryIncludes);
  if (e.warningsInclude) expect(r.warnings.join(' | ')).toContain(e.warningsInclude);
  for (const [kind, reason] of Object.entries((e.reasons ?? {}) as Record<string, string>))
    expect(r.facts.find((f) => f.kind === kind)?.reason).toBe(reason);
  // The assertion codes the verified scope keeps, or null for a record without one.
  if ('scope' in e) expect(r.scope ? r.scope.asserts.map((a) => a.code) : null).toEqual(e.scope);
  if ('observedMatches' in e) expect(r.observedMatches).toBe(e.observedMatches);
  if ('domain' in e) expect(r.domain).toBe(e.domain);
  if ('phone' in e) expect(r.phone).toBe(e.phone);
  if ('delegation' in e) {
    const want = e.delegation as boolean | { valid: boolean };
    expect(r.delegation.valid).toBe(typeof want === 'boolean' ? want : want.valid);
  }
  // On every result, and always in step with the mismatches.
  expect(r.observedMatches).toBe(r.mismatches.length === 0);
}

function checkPresentation(r: PresentationResult, e: Record<string, unknown>) {
  expect(unknownKeys(e, PRESENTATION_KEYS), 'expectations this runner does not check').toEqual([]);
  expect(r.verified, 'message' in r ? r.message : '').toBe(e.verified);
  if (!r.verified) {
    if ('code' in e) expect(r.code, r.message).toBe(e.code);
    if ('messageIncludes' in e) expect(r.message).toContain(e.messageIncludes);
  } else {
    if (e.subject) expect(r.subject).toBe(e.subject);
    if (e.issuer) expect(r.issuer).toBe(e.issuer);
    if (e.vct) expect(r.vct).toBe(e.vct);
    if (e.root) expect(r.delegation?.root).toBe(e.root);
    if (e.delegate) expect(r.delegation?.delegate).toBe(e.delegate);
    if (e.scope) expect(r.delegation?.scope).toEqual(e.scope);
  }
}

function checkFetches(asked: string[], e: Record<string, unknown>) {
  if ('fetches' in e) {
    if (Array.isArray(e.fetches)) expect(asked).toEqual(e.fetches);
    else expect(asked, asked.join(' ')).toHaveLength(e.fetches as number);
  }
  if (e.noFetches) expect(asked).toEqual([]);
  if ('maxFetches' in e)
    expect(asked.length, asked.join(' ')).toBeLessThanOrEqual(e.maxFetches as number);
}

describe(`test vectors (${world.cases.length})`, () => {
  for (const c of world.cases) {
    it(`${c.name}: ${c.description}`, async () => {
      expect(unknownKeys(c, CASE_KEYS), 'case keys this runner does not know').toEqual([]);
      const asked: string[] = [];
      const fetch = replayFetch({ ...world.http, ...c.http }, asked);
      const dns = staticTxt({ ...world.dns, ...c.dns });
      if (c.input.type === 'verifyBusiness') {
        const query = c.input.phone !== undefined ? { phone: c.input.phone } : c.input.domain!;
        const r = await verifyBusiness(query, {
          registry: world.registry,
          fetch,
          dns,
          now: world.now,
          ...(c.input.observed ? { observed: c.input.observed } : {}),
        });
        checkBusiness(r, c.expected);
        expect(r.summary).not.toMatch(/\b(trusted|recommended|endorsed)\b/i);
      } else {
        const { type: _type, ...input } = c.input;
        checkPresentation(await verifyPresentation(input, { fetch, now: world.now }), c.expected);
      }
      checkFetches(asked, c.expected);
    });
  }

  it('replays at the vector time, whatever the wall clock says', async () => {
    vi.useFakeTimers({ now: (world.now + 3 * 86_400) * 1000, toFake: ['Date'] });
    try {
      const r = await verifyBusiness('acme-hvac.example', {
        registry: world.registry,
        fetch,
        dns,
        now: world.now,
      });
      expect(r, r.summary).toMatchObject({ verified: true, level: 2 });
    } finally {
      vi.useRealTimers();
    }
  });

  it('the summary states facts with dates in plain words', async () => {
    const r = await verifyBusiness('acme-hvac.example', {
      registry: world.registry,
      fetch,
      dns,
      now: world.now,
    });
    expect(r.summary).toMatch(
      /^acme-hvac\.example belongs to Acme HVAC Inc\., listed in the FFN Verified Business registry at Level 2/,
    );
    expect(r.summary).toMatch(/license 1000003 \(C-20\) is active until/);
    expect(r.summary).toContain('Not checked: verified representative.');
    expect(r.summary).toContain('not a rating or a recommendation');
  });
});
