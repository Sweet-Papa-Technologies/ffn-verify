import type { DidDocument } from './did-web.js';
import { b64uDecodeJson, b64uJson, type Jwk } from './jose.js';

// did:jwk (https://github.com/quartzjer/did-jwk/blob/main/spec.md): the DID is
// the public key. People get one from their wallet key, and a business that
// can't publish a DID document uses one as its key-only fallback. Nothing to
// host and no personal data in it.

const PREFIX = 'did:jwk:';

/** Members kept in the DID, in RFC 7638 order so the same key always yields the same DID. */
function canonical(jwk: Jwk): Jwk {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y)
    throw new Error('did:jwk here supports P-256 public keys only');
  return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
}

export function didJwkFor(publicJwk: Jwk): string {
  return `${PREFIX}${b64uJson(canonical(publicJwk))}`;
}

export function isDidJwk(did: string): boolean {
  return did.startsWith(PREFIX);
}

export function jwkOfDidJwk(did: string): Jwk {
  if (!isDidJwk(did)) throw new Error(`not a did:jwk: ${did}`);
  const encoded = did.slice(PREFIX.length).split('#')[0]!;
  const jwk = b64uDecodeJson<Jwk>(encoded);
  if ('d' in jwk) throw new Error('did:jwk must not carry a private key');
  const key = canonical(jwk);
  // One key, one DID: aliases with other member orders or extra members are refused.
  if (`${PREFIX}${encoded}` !== didJwkFor(key)) throw new Error('did:jwk is not in canonical form');
  return key;
}

export function resolveDidJwk(did: string): DidDocument {
  const id = did.split('#')[0]!;
  const vm = `${id}#0`;
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id,
    verificationMethod: [
      { id: vm, type: 'JsonWebKey2020', controller: id, publicKeyJwk: jwkOfDidJwk(id) },
    ],
    assertionMethod: [vm],
    authentication: [vm],
    capabilityDelegation: [vm],
    capabilityInvocation: [vm],
  };
}
