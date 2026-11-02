// Small fetch-API helpers shared by the issuer and verifier route handlers.
// Handlers take a standard Request and return a Response, so they mount in Hono,
// Express/Cloud Functions (via nodeHandler), Next.js, Workers or Deno unchanged.

export type FetchHandler = (request: Request) => Promise<Response | undefined>;

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers },
  });
}

export function oauthError(error: string, description: string, status = 400): Response {
  return json({ error, error_description: description }, status);
}

/** CORS for the hosted wallet's origin(s). The wallet runs in a browser, unlike native wallets. */
export function withCors(
  response: Response,
  request: Request,
  allowedOrigins: readonly string[],
): Response {
  const origin = request.headers.get('origin');
  if (!origin || !allowedOrigins.includes(origin)) return response;
  const headers = new Headers(response.headers);
  headers.set('access-control-allow-origin', origin);
  headers.set('vary', 'origin');
  return new Response(response.body, { status: response.status, headers });
}

export function preflight(
  request: Request,
  allowedOrigins: readonly string[],
): Response | undefined {
  if (request.method !== 'OPTIONS') return undefined;
  const origin = request.headers.get('origin');
  if (!origin || !allowedOrigins.includes(origin)) return new Response(null, { status: 403 });
  return new Response(null, {
    status: 204,
    headers: {
      'access-control-allow-origin': origin,
      'access-control-allow-methods': 'GET, POST, OPTIONS',
      'access-control-allow-headers': 'authorization, content-type, dpop',
      'access-control-max-age': '600',
      vary: 'origin',
    },
  });
}

export async function readForm(request: Request): Promise<Record<string, string>> {
  const type = request.headers.get('content-type') ?? '';
  if (type.includes('application/json')) {
    const body = (await request.json()) as Record<string, unknown>;
    return Object.fromEntries(
      Object.entries(body).map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)]),
    );
  }
  return Object.fromEntries(new URLSearchParams(await request.text()));
}

interface NodeReq {
  method?: string;
  url?: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody?: Uint8Array;
  body?: unknown;
  protocol?: string;
  on?(event: string, cb: (chunk?: unknown) => void): unknown;
}
interface NodeRes {
  statusCode: number;
  setHeader(name: string, value: string): unknown;
  end(body?: Uint8Array | string): unknown;
}

/**
 * Adapt a FetchHandler to Node/Express/Cloud Functions (req, res, next).
 * Works whether or not a body parser already ran: it prefers Cloud Functions'
 * req.rawBody, then a parsed req.body, then the raw stream.
 */
export function nodeHandler(handler: FetchHandler, options: { origin?: string } = {}) {
  return async (req: NodeReq, res: NodeRes, next?: (err?: unknown) => void) => {
    try {
      const host = (req.headers['x-forwarded-host'] ?? req.headers.host) as string;
      const proto = ((req.headers['x-forwarded-proto'] as string) ?? req.protocol ?? 'https').split(
        ',',
      )[0];
      const base = options.origin ?? `${proto}://${host}`;
      const url = new URL(req.originalUrl ?? req.url ?? '/', base);
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === 'string') headers.set(k, v);
        else if (Array.isArray(v)) headers.set(k, v.join(', '));
      }
      let body: BodyInit | undefined;
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        if (req.rawBody) body = req.rawBody as Uint8Array<ArrayBuffer>;
        else if (req.body !== undefined) {
          const type = headers.get('content-type') ?? '';
          body =
            typeof req.body === 'string'
              ? req.body
              : type.includes('application/x-www-form-urlencoded')
                ? new URLSearchParams(req.body as Record<string, string>).toString()
                : JSON.stringify(req.body);
        } else if (req.on) {
          body = await new Promise<Uint8Array<ArrayBuffer>>((resolve, reject) => {
            const chunks: Uint8Array[] = [];
            req.on!('data', (c) => chunks.push(c as Uint8Array));
            req.on!('end', () => {
              const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
              let o = 0;
              for (const c of chunks) {
                out.set(c, o);
                o += c.length;
              }
              resolve(out);
            });
            req.on!('error', reject);
          });
        }
      }
      const response = await handler(
        new Request(url, { method: req.method ?? 'GET', headers, body: body ?? null }),
      );
      if (!response) {
        if (next) return next();
        res.statusCode = 404;
        return res.end();
      }
      res.statusCode = response.status;
      response.headers.forEach((value, key) => res.setHeader(key, value));
      res.end(new Uint8Array(await response.arrayBuffer()));
    } catch (err) {
      if (next) return next(err);
      res.statusCode = 500;
      res.end();
    }
  };
}
