import { CredentialError } from './credential.js';

// Flow 5: what a traveler's vouch says. The site drafts it, the voucher's
// wallet shows and signs exactly this with the holder key, and the site checks
// it again before issuing. Both sides use these rules.

// A type alias, not an interface, so it passes straight to signStatement().
export type VouchPayload = {
  type: 'travelVouch';
  /** The site's client_id. */
  aud: string;
  /** The traveler's subjectId at this site. */
  sub: string;
  tags: string[];
  /** Up to 280 characters. */
  note?: string;
};

export const VOUCH_LIMITS = { tags: 10, tagLength: 40, note: 280 } as const;

const VOUCH_FIELDS = new Set(['type', 'aud', 'sub', 'tags', 'note']);

export function vouchPayload(input: Omit<VouchPayload, 'type'>): VouchPayload {
  const payload: VouchPayload = {
    type: 'travelVouch',
    aud: input.aud,
    sub: input.sub,
    tags: input.tags,
    ...(input.note ? { note: input.note } : {}),
  };
  checkVouchContent(payload);
  return payload;
}

/** Positive tags and an optional short note: nothing else. */
export function checkVouchContent(p: {
  tags?: unknown;
  note?: unknown;
}): asserts p is Pick<VouchPayload, 'tags' | 'note'> {
  const tags = p.tags;
  if (!Array.isArray(tags) || tags.length === 0)
    throw new CredentialError('a vouch needs at least one tag', 'invalid_vouch');
  if (tags.length > VOUCH_LIMITS.tags) throw new CredentialError('too many tags', 'invalid_vouch');
  if (!tags.every((t) => typeof t === 'string' && t.trim() && t.length <= VOUCH_LIMITS.tagLength))
    throw new CredentialError('tags must be short strings', 'invalid_vouch');
  if (p.note !== undefined && (typeof p.note !== 'string' || p.note.length > VOUCH_LIMITS.note))
    throw new CredentialError('vouch note is over 280 characters', 'invalid_vouch');
}

/** A payload with exactly the vouch fields, for `aud`: what a wallet agrees to sign. */
export function checkVouchPayload(p: unknown, aud: string): asserts p is VouchPayload {
  if (!p || typeof p !== 'object') throw new CredentialError('not a vouch', 'invalid_vouch');
  const v = p as Record<string, unknown>;
  if (v.type !== 'travelVouch') throw new CredentialError('not a vouch', 'invalid_vouch');
  if (Object.keys(v).some((k) => !VOUCH_FIELDS.has(k)))
    throw new CredentialError('the vouch has fields beyond tags and a note', 'invalid_vouch');
  if (v.aud !== aud) throw new CredentialError('the vouch names another site', 'invalid_vouch');
  if (typeof v.sub !== 'string' || !v.sub)
    throw new CredentialError("the vouch doesn't say who it's for", 'invalid_vouch');
  checkVouchContent(v);
}
