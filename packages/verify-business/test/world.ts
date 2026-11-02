import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Fetch } from '@fofonet/door-core';
import type { HttpEntry, World } from '../scripts/vector-format.js';

// The vector world (vectors/business/v1.json), served as its format says
// (scripts/generate-vectors.ts), for every suite that replays it.

export const world = JSON.parse(
  readFileSync(resolve(__dirname, '../../../vectors/business/v1.json'), 'utf8'),
) as World;

/** A fetch answering from `http`; every URL asked for is pushed onto `log`. */
export function replayFetch(http: Record<string, HttpEntry>, log: string[] = []): Fetch {
  return async (input) => {
    log.push(String(input));
    const hit = http[String(input)];
    if (!hit) return new Response('not found', { status: 404 });
    if ('error' in hit) throw new TypeError('fetch failed');
    const body =
      'bodyBase64' in hit ? new Uint8Array(Buffer.from(hit.bodyBase64, 'base64')) : hit.body;
    return new Response(body, { status: hit.status, headers: { 'content-type': hit.contentType } });
  };
}
