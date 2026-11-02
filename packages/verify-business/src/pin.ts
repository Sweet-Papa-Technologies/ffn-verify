import {
  DidResolver,
  applyKnownRegistryPins,
  jwkThumbprint,
  type DidDocument,
  type Jwk,
  type VerificationRelationship,
} from '@fofonet/door-core';

// Registry key pinning. A verifier that pins the registry's keys accepts only
// those keys for the registry's DID, whatever its did.json lists: a key added
// to the document by someone who got write access to the registry's host signs
// nothing a pinned verifier accepts. Records, attestations, status lists and
// the delegation's key binding all resolve through here, so one filter covers
// every registry signature.
//
// The known FFN registries (mainnet and devnet, door-core networks.ts) are
// pinned to their own keys always, even through a resolver the caller brings
// and even when no anchor pins are given.

/** RFC 7638 SHA-256 thumbprint (base64url), the pin format. */
export const keyThumbprint = (jwk: Jwk): Promise<string> => jwkThumbprint(jwk);

export class PinnedRegistryResolver extends DidResolver {
  constructor(
    private readonly inner: DidResolver,
    private readonly registryDid: string | undefined,
    private readonly thumbprints: readonly string[] | undefined,
  ) {
    super();
  }

  override async resolve(did: string): Promise<DidDocument> {
    const doc = await applyKnownRegistryPins(did, await this.inner.resolve(did));
    if (did !== this.registryDid || !this.thumbprints) return doc;
    const methods = [];
    for (const m of Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []) {
      const pinned = await keyThumbprint(m?.publicKeyJwk ?? ({} as Jwk)).then(
        (t) => this.thumbprints!.includes(t),
        () => false,
      );
      if (pinned) methods.push(m);
    }
    return { ...doc, verificationMethod: methods };
  }

  override async keyFor(
    did: string,
    kid: string | undefined,
    relationship: VerificationRelationship,
  ): Promise<Jwk> {
    try {
      return await super.keyFor(did, kid, relationship);
    } catch (err) {
      // Say so when the registry lists the key but this verifier doesn't pin it.
      if (did === this.registryDid && this.thumbprints && kid !== undefined) {
        const listed = await this.inner.keyFor(did, kid, relationship).catch(() => undefined);
        if (listed) throw new Error(`${kid} is not one of the registry keys this verifier pins`);
      }
      throw err;
    }
  }
}

/**
 * `resolver`, limited to the pinned keys for the registry's DID, and for the
 * known FFN registries to their built-in pins. With no `thumbprints`, only the
 * built-in pins apply.
 */
export function pinRegistryKeys(
  resolver: DidResolver,
  registryDid: string | undefined,
  thumbprints: readonly string[] | undefined,
): DidResolver {
  return new PinnedRegistryResolver(resolver, registryDid, thumbprints);
}
