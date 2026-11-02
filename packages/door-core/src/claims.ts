import {
  AccountTypes,
  CredentialKinds,
  IdentityClaims,
  SiteKinds,
  type CredentialKind,
} from './catalog.js';
import type { ClaimRef, ParsedClaimRef } from './types.js';

export class ClaimRefError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ClaimRefError';
  }
}

export function parseClaimRef(ref: ClaimRef | string): ParsedClaimRef {
  const required = !ref.endsWith('?');
  const body = required ? ref : ref.slice(0, -1);
  const [kind, item, ...rest] = body.split('.');
  if (rest.length > 0 || !kind) throw new ClaimRefError(`unknown claim ${ref}`);
  if (kind === 'identity') {
    if (!item || !(IdentityClaims as readonly string[]).includes(item))
      throw new ClaimRefError(`unknown claim ${ref}`);
    return { ref, kind, item, required };
  }
  if (kind === 'link') {
    if (!item || !(AccountTypes as readonly string[]).includes(item))
      throw new ClaimRefError(`unknown account type ${ref}`);
    return { ref, kind, item, required };
  }
  if ((SiteKinds as readonly string[]).includes(kind) && item === undefined) {
    return { ref, kind: kind as CredentialKind, required };
  }
  throw new ClaimRefError(`unknown claim ${ref}`);
}

/** The vct each parsed ref is satisfied by. */
export function vctOf(parsed: ParsedClaimRef): string {
  return CredentialKinds[parsed.kind];
}

/** Stable DCQL credential query id for a parsed ref. */
export function queryIdOf(parsed: ParsedClaimRef): string {
  return parsed.kind === 'link' ? `link_${parsed.item}` : parsed.kind;
}

/** "Unknown is explicit" (principle 4): ref → display name used in notChecked lists. */
export function claimName(parsed: ParsedClaimRef): string {
  return parsed.item ? `${parsed.kind}.${parsed.item}` : parsed.kind;
}
