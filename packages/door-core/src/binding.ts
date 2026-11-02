import type { BusinessProfileClaims } from './business.js';
import type { DidDocument, DidService } from './did-web.js';
import type { Jwk } from './jose.js';

// Domain binding (plan, "How it works"): the registry lists the business's
// official domains, and each domain points back. A lookalike domain fails both
// directions: the registry doesn't list it, and the real domain's DID document
// and DNS record don't name it.
//
//   https://<domain>/.well-known/did.json   the business DID document, with a
//                                            service entry naming its registry record
//   _ffn.<domain>  TXT  "v=ffn1; did=<did>; registry=<registry host>[; key=<thumbprint>]"
//
// Verifiers trust the registry they already know, never what the page says.
//
// `key` is optional (added Nov 2026). A did:web stays the same when its key
// changes, so without it the TXT record agrees with any document on the site.
// With it, DNS names the one key it vouches for: the registry asks for it
// before a business moves its listing to a new key. Readers that don't know
// the field ignore it, so records without it keep working as before.

export const FFN_SERVICE_TYPE = 'FfnVerifiedBusiness';
export const FFN_TXT_PREFIX = '_ffn';

export interface BusinessDidInput {
  did: string;
  keys: Array<{ kid: string; publicJwk: Jwk }>;
  /** The registry record this business is listed under. */
  registryEntry: string;
  /** For a secondary domain: the business's primary DID. */
  alsoKnownAs?: string[];
}

export function businessDidDocument(input: BusinessDidInput): DidDocument {
  const methods = input.keys.map(({ kid, publicJwk }) => ({
    id: kid.startsWith('did:') ? kid : `${input.did}#${kid}`,
    type: 'JsonWebKey2020',
    controller: input.did,
    publicKeyJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y } as Jwk,
  }));
  const refs = methods.map((m) => m.id);
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: input.did,
    ...(input.alsoKnownAs?.length ? { alsoKnownAs: input.alsoKnownAs } : {}),
    verificationMethod: methods,
    assertionMethod: refs,
    authentication: refs,
    capabilityDelegation: refs,
    service: [
      {
        id: `${input.did}#ffn-registry`,
        type: FFN_SERVICE_TYPE,
        serviceEndpoint: input.registryEntry,
      },
    ],
  };
}

/** Registry record URLs the DID document points at (service entries of type FfnVerifiedBusiness). */
export function registryEntriesOf(doc: DidDocument): string[] {
  const out: string[] = [];
  // A document from an untrusted host: anything that isn't a list of service objects counts as none.
  const services: unknown[] = Array.isArray(doc.service) ? doc.service : [];
  for (const s of services) {
    if (typeof s !== 'object' || s === null) continue;
    const { type, serviceEndpoint } = s as Partial<DidService>;
    const types: unknown[] = Array.isArray(type) ? type : [type];
    if (!types.includes(FFN_SERVICE_TYPE)) continue;
    const ends: unknown[] = Array.isArray(serviceEndpoint) ? serviceEndpoint : [serviceEndpoint];
    for (const e of ends) if (typeof e === 'string') out.push(e);
  }
  return out;
}

/** The document's alsoKnownAs DIDs; none when it isn't a list. */
export function alsoKnownAsOf(doc: DidDocument): string[] {
  return Array.isArray(doc.alsoKnownAs)
    ? doc.alsoKnownAs.filter((d): d is string => typeof d === 'string')
    : [];
}

export interface FfnTxt {
  v: 'ffn1';
  did: string;
  /** Registry host, e.g. registry.example */
  registry: string;
  /** RFC 7638 SHA-256 thumbprint (base64url) of the business key DNS vouches for. Optional. */
  key?: string;
}

export function ffnTxtName(domain: string): string {
  return `${FFN_TXT_PREFIX}.${domain}`;
}

export function ffnTxtValue(record: Omit<FfnTxt, 'v'>): string {
  return `v=ffn1; did=${record.did}; registry=${record.registry}${record.key ? `; key=${record.key}` : ''}`;
}

export function parseFfnTxt(value: string): FfnTxt | undefined {
  // DNS answers may arrive quoted or split into 255-byte strings.
  const joined = value.replace(/"\s*"/g, '').replace(/^"|"$/g, '');
  const fields = Object.fromEntries(
    joined
      .split(';')
      .map((part) => part.trim().split('='))
      .filter((kv): kv is [string, string] => kv.length >= 2)
      .map(([k, ...rest]) => [k.trim(), rest.join('=').trim()]),
  );
  if (fields.v !== 'ffn1' || !fields.did || !fields.registry) return undefined;
  return {
    v: 'ffn1',
    did: fields.did,
    registry: fields.registry,
    ...(fields.key ? { key: fields.key } : {}),
  };
}

export interface JsonLdInput {
  profile: BusinessProfileClaims;
  did: string;
  /** The public profile page on the registry. */
  profileUrl: string;
  /** The signed record (API). */
  recordUrl: string;
}

/**
 * schema.org markup a business puts on its site, and the registry puts on the
 * public profile, so agents that only crawl still read the facts. It is a
 * pointer, not proof: a verifier confirms it against the registry.
 */
export function businessJsonLd(input: JsonLdInput): Record<string, unknown> {
  const p = input.profile;
  return {
    '@context': 'https://schema.org',
    '@type': 'LocalBusiness',
    name: p.name,
    ...(p.dba?.length ? { alternateName: p.dba } : {}),
    url: `https://${p.domains[0]}`,
    ...(p.phones[0] ? { telephone: p.phones[0] } : {}),
    ...(p.address
      ? {
          address: {
            '@type': 'PostalAddress',
            ...(p.address.streetAddress ? { streetAddress: p.address.streetAddress } : {}),
            addressLocality: p.address.locality,
            addressRegion: p.address.region,
            ...(p.address.postalCode ? { postalCode: p.address.postalCode } : {}),
            addressCountry: p.address.country,
          },
        }
      : {}),
    ...(p.hours?.length ? { openingHours: p.hours } : {}),
    ...(p.serviceArea?.length ? { areaServed: p.serviceArea } : {}),
    identifier: [
      { '@type': 'PropertyValue', propertyID: 'did', value: input.did },
      { '@type': 'PropertyValue', propertyID: 'ffn-verified-business', value: input.recordUrl },
    ],
    sameAs: [input.profileUrl],
  };
}
