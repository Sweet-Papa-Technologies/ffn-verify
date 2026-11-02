import type { LegalName, NameMatch } from './types.js';

// "Name matching is a computed fact ('matches', 'partial', 'no match'), not a
// judgment" (FFN v1 doc, Flow 2). Compares the verified legal name with the
// name an account provider (or a site's own account) gives, ignoring case,
// accents, punctuation, order and middle names.

const tokens = (s: string) =>
  s
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]/gu, ' ')
    .split(/[\s-]+/)
    .filter(Boolean);

export function matchName(
  legal: LegalName | undefined,
  providerName: string | undefined,
): NameMatch {
  if (!legal || !providerName?.trim()) return 'not-checked';
  const have = new Set(tokens(providerName));
  const given = tokens(legal.givenName);
  const family = tokens(legal.familyName);
  const givenHit = given.length > 0 && given.some((t) => have.has(t));
  const familyHit = family.length > 0 && family.every((t) => have.has(t));
  if (givenHit && familyHit) return 'match';
  if (givenHit || familyHit) return 'partial';
  return 'no-match';
}
