// The shape of vectors/business/v1.json, shared by the generator (world.ts)
// and every replayer. Pure types, so a test suite can read the file without
// the generator's dependencies. The format is documented in
// generate-vectors.ts.

export type HttpEntry =
  | { status: number; contentType: string; body: string }
  /** Raw body bytes, base64 (standard alphabet, padded): bodies that aren't plain text or are oversized. */
  | { status: number; contentType: string; bodyBase64: string }
  | { error: 'unreachable' };

export interface VectorCase {
  name: string;
  description: string;
  input:
    | {
        type: 'verifyBusiness';
        /** Exactly one of domain and phone. */
        domain?: string;
        phone?: string;
        observed?: { name?: string; phone?: string; address?: string };
      }
    | {
        type: 'verifyPresentation';
        presentation: string;
        chain?: string[];
        nonce: string;
        audience: string;
        roots?: string[];
        requiredScope?: string[];
        issuers?: string[];
      };
  expected: Record<string, unknown>;
  /** Entries that replace or add to the world's `http` table for this case only. */
  http?: Record<string, HttpEntry>;
  /** Entries that replace or add to the world's `dns` table for this case only. */
  dns?: Record<string, string[]>;
}

export interface World {
  version: 1;
  now: number;
  /** The anchor every verifyBusiness case runs with, key pins included. */
  registry: { origin: string; did: string; name: string; keyThumbprints: string[] };
  http: Record<string, HttpEntry>;
  dns: Record<string, string[]>;
  cases: VectorCase[];
}
