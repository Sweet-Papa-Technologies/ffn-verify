// Normalizing the identifiers a business is looked up by. Lookups compare
// normalized forms only, so `ACME-HVAC.example.` and `acme-hvac.example` are the same
// entry and a homoglyph (`аcme-hvac.com`, Cyrillic а) becomes its own punycode
// name that no verified business lists.

export class IdentifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdentifierError';
  }
}

const PRIVATE_SUFFIXES = [
  'internal',
  'local',
  'localhost',
  'localdomain',
  'home.arpa',
  'lan',
  'intranet',
];

/** Lowercase ASCII (punycode) host name, no trailing dot, port, path or IP address. */
export function normalizeDomain(input: string): string {
  const raw = input.trim().replace(/\.$/, '');
  if (!raw || /[\s/?#@:]/.test(raw)) throw new IdentifierError(`not a domain: ${input}`);
  let host: string;
  try {
    host = new URL(`https://${raw}/`).hostname;
  } catch {
    throw new IdentifierError(`not a domain: ${input}`);
  }
  if (/^\d+(\.\d+){3}$/.test(host) || host.startsWith('['))
    throw new IdentifierError('IP addresses are not business domains');
  const labels = host.split('.');
  if (labels.length < 2 || labels.some((l) => l.length === 0 || l.length > 63))
    throw new IdentifierError(`not a domain: ${input}`);
  // Names that only resolve inside a network (e.g. metadata.google.internal) are never a business.
  if (PRIVATE_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`)))
    throw new IdentifierError(`not a public domain: ${input}`);
  return host;
}

/**
 * E.164 form of a phone number. Ten-digit numbers are taken as US/Canada (NANP),
 * the only region v1 verifies; anything else must already carry its country code.
 */
export function normalizePhone(input: string): string {
  const trimmed = input.trim();
  const digits = trimmed.replace(/[^\d]/g, '');
  if (trimmed.startsWith('+')) {
    if (digits.length < 8 || digits.length > 15) throw new IdentifierError(`not a phone: ${input}`);
    return `+${digits}`;
  }
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith('1')) return `+${digits}`;
  throw new IdentifierError(`not a phone number with a country code: ${input}`);
}

/** Loose comparison form of a business name: case, punctuation and legal suffixes ignored. */
export function nameKey(name: string): string {
  return name
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/&/g, ' and ')
    .replace(/[^a-z0-9 ]+/g, ' ')
    .replace(/\b(inc|incorporated|llc|l l c|ltd|co|corp|corporation|company|the)\b/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}
