/**
 * The office over HTTP.
 *
 * Public, no auth, open to any origin:
 *
 *     GET  /.well-known/did.json     the body's DID document: its anchor key, and this office
 *     GET  /status/1                 the withdrawal list, a signed JWT
 *     GET  /pickup/:code             what the body will and will not say
 *     POST /pickup/:code {proof}     the vouch, about the key that signed the proof
 *     POST /collect {proof}          every live vouch about the key that signed the proof
 *
 * The registrar's desk, with `Authorization: Bearer <token>`:
 *
 *     GET  /desk/roster              every row
 *     POST /desk/roster {rows}       add or update rows
 *     POST /desk/consent {ids, consent}
 *     POST /desk/vouch {ids, periodEnd?}           pickup URLs, for QR codes
 *     POST /desk/withdraw {ids, sponsorNote?}
 *     GET  /desk/needs               the home list
 *     GET  /desk/standing            the registry entry, the nodes, the withdrawal list
 *
 * The desk is a page on another origin (the Helm, served by the body's
 * brain), so the office answers a browser from the origins it is given
 * (`deskOrigins`) and from no other. That is CORS, not a lock: every desk
 * route still wants the token, whoever asks.
 *
 * The server speaks plain HTTP on localhost by default. Put TLS in front of
 * it: the token is a bearer secret, and so is a pickup code until it is used.
 * `deploy/` has a systemd unit and a Caddy site for it, beside a brain.
 */
import { Office, OfficeError } from './office';

type Handler = (req: Request) => Promise<Response>;

const json = (body: unknown, status = 200, headers: Record<string, string> = {}): Response =>
  new Response(`${JSON.stringify(body, null, 2)}\n`, {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers },
  });

async function bodyOf(req: Request): Promise<Record<string, any>> {
  let b: unknown;
  try {
    b = await req.json();
  } catch {
    throw new OfficeError(400, 'bad_json');
  }
  if (typeof b !== 'object' || b === null || Array.isArray(b)) throw new OfficeError(400, 'bad_request', 'the body is a JSON object');
  return b as Record<string, any>;
}

/** The token from `Authorization: Bearer <token>`, '' if the header is some other thing, null if absent. */
function bearer(req: Request): string | null {
  const h = req.headers.get('authorization');
  if (h === null) return null;
  return /^Bearer ([A-Za-z0-9._~+/-]+=*)$/.exec(h)?.[1] ?? '';
}

/** The answer to a browser's preflight for a public route that takes JSON. */
const preflight = (methods: string): Response =>
  new Response(null, {
    status: 204,
    headers: { 'access-control-allow-methods': methods, 'access-control-allow-headers': 'content-type', 'access-control-max-age': '600' },
  });

function only(methods: string[], req: Request): void {
  if (!methods.includes(req.method)) throw new OfficeError(405, 'method_not_allowed', methods.join(', '));
}

const DESK = new Map<string, string[]>([
  ['roster', ['GET', 'POST']],
  ['consent', ['POST']],
  ['vouch', ['POST']],
  ['withdraw', ['POST']],
  ['needs', ['GET']],
  ['standing', ['GET']],
]);

/** What a desk route answers a GET with. */
const DESK_READS: Record<string, (office: Office) => unknown> = {
  roster: (office) => ({ rows: office.rows() }),
  needs: (office) => office.needs(),
  standing: (office) => office.standing(),
};

async function desk(office: Office, req: Request, name: string, allowed: (origin: string | null) => boolean): Promise<Response> {
  if (req.method === 'OPTIONS') {
    // A browser asks before it sends the token. Only the desk's origins are told yes.
    const origin = req.headers.get('origin');
    if (!allowed(origin)) throw new OfficeError(403, 'origin_not_allowed');
    return new Response(null, {
      status: 204,
      headers: {
        'access-control-allow-methods': DESK.get(name)!.join(', '),
        'access-control-allow-headers': 'authorization, content-type',
        'access-control-max-age': '600',
      },
    });
  }
  only(DESK.get(name)!, req);
  const token = bearer(req);
  if (token === null) throw new OfficeError(401, 'no_token');
  if (token === '' || !office.checkToken(token)) throw new OfficeError(401, 'bad_token');
  if (req.method === 'GET') return json(DESK_READS[name]!(office));
  const b = await bodyOf(req);
  switch (name) {
    case 'roster':
      return json({ rows: office.upsertRows(b.rows) });
    case 'consent':
      return json(office.setConsent(b.ids, b.consent));
    case 'vouch':
      return json(office.vouch(b.ids, b.periodEnd));
    default:
      return json(office.withdraw(b.ids, b.sponsorNote));
  }
}

async function route(office: Office, req: Request, path: string, allowed: (origin: string | null) => boolean): Promise<Response> {
  const deskName = /^\/desk\/([a-z]+)$/.exec(path)?.[1];
  if (deskName !== undefined && DESK.has(deskName)) return desk(office, req, deskName, allowed);

  if (path.endsWith('/did.json') && path === office.didDocumentPath()) {
    only(['GET'], req);
    return json(office.didDocument(), 200, { 'content-type': 'application/did+json', 'cache-control': 'no-cache' });
  }

  const status = /^\/status\/([1-9][0-9]{0,8})$/.exec(path)?.[1];
  if (status !== undefined) {
    only(['GET'], req);
    const list = office.statusList(Number(status));
    if (list === null) throw new OfficeError(404, 'not_found');
    return new Response(list, { headers: { 'content-type': 'application/vc+jwt', 'cache-control': 'no-cache' } });
  }

  const code = /^\/pickup\/([^/]+)$/.exec(path)?.[1];
  if (code !== undefined) {
    if (req.method === 'OPTIONS') return preflight('GET, POST');
    only(['GET', 'POST'], req);
    if (req.method === 'GET') return json(office.pickup(code));
    return json(office.redeem(code, (await bodyOf(req)).proof));
  }

  if (path === '/collect') {
    if (req.method === 'OPTIONS') return preflight('POST');
    only(['POST'], req);
    return json(office.collect((await bodyOf(req)).proof));
  }

  throw new OfficeError(404, 'not_found');
}

function failure(e: unknown): Response {
  if (!(e instanceof OfficeError)) {
    console.error(e);
    return json({ error: 'internal' }, 500);
  }
  const headers: Record<string, string> = {};
  if (e.status === 401) headers['www-authenticate'] = `Bearer realm="desk"${e.code === 'bad_token' ? ', error="invalid_token"' : ''}`;
  if (e.status === 405 && e.detail !== undefined) headers.allow = e.detail;
  return json({ error: e.code, ...(e.detail !== undefined && { detail: e.detail }) }, e.status, headers);
}

/** An origin, as a browser sends it: a scheme of http or https, a host and maybe a port, and nothing more. */
export function deskOrigin(origin: string): string {
  const u = URL.parse(origin);
  if (u === null || (u.protocol !== 'https:' && u.protocol !== 'http:') || u.origin !== origin) {
    throw new OfficeError(400, 'bad_desk_origin', `a desk origin is a scheme and host, such as https://brain.example.org, not ${origin}`);
  }
  return origin;
}

export interface OfficeHandlerOptions {
  /**
   * The origins the registrar's desk is served from, such as the body's
   * brain, which serves the Helm. A browser on one of them may call the desk
   * routes; it still needs the token. None by default.
   */
  deskOrigins?: readonly string[];
}

/** A fetch handler for the office: Bun.serve, a Worker, or a test calling it directly. */
export function officeHandler(office: Office, o: OfficeHandlerOptions = {}): Handler {
  const origins = new Set((o.deskOrigins ?? []).map(deskOrigin));
  const allowed = (origin: string | null) => origin !== null && origins.has(origin);
  return async (req) => {
    const path = new URL(req.url).pathname;
    let res: Response;
    try {
      res = await route(office, req, path, allowed);
    } catch (e) {
      res = failure(e);
    }
    if (!path.startsWith('/desk/')) {
      // Apps fetch the public half from their own pages.
      res.headers.set('access-control-allow-origin', '*');
    } else if (origins.size > 0) {
      // The desk is for its own origins only, and a cache must not hand one origin's answer to another.
      res.headers.set('vary', 'Origin');
      const origin = req.headers.get('origin');
      if (allowed(origin)) res.headers.set('access-control-allow-origin', origin!);
    }
    return res;
  };
}

export interface ServeOptions extends OfficeHandlerOptions {
  port: number;
  /** Defaults to 127.0.0.1: put TLS in front. */
  hostname?: string;
}

export function serveOffice(office: Office, o: ServeOptions) {
  return Bun.serve({
    port: o.port,
    hostname: o.hostname ?? '127.0.0.1',
    maxRequestBodySize: 1 << 20,
    fetch: officeHandler(office, o),
  });
}
