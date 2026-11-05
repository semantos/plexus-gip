/**
 * The office over HTTP.
 *
 * Public, no auth, open to any origin:
 *
 *     GET  /.well-known/did.json     the body's DID document: its anchor key
 *     GET  /status/1                 the withdrawal list, a signed JWT
 *     GET  /pickup/:code             what the body will and will not say
 *     POST /pickup/:code {proof}     the vouch, about the key that signed the proof
 *
 * The registrar's desk, with `Authorization: Bearer <token>`:
 *
 *     GET  /desk/roster              every row
 *     POST /desk/roster {rows}       add or update rows
 *     POST /desk/consent {ids, consent}
 *     POST /desk/vouch {ids, periodEnd?}           pickup URLs, for QR codes
 *     POST /desk/withdraw {ids, sponsorNote?}
 *     GET  /desk/needs               the home list
 *
 * The server speaks plain HTTP on localhost by default. Put TLS in front of
 * it: the token is a bearer secret, and so is a pickup code until it is used.
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

function only(methods: string[], req: Request): void {
  if (!methods.includes(req.method)) throw new OfficeError(405, 'method_not_allowed', methods.join(', '));
}

const DESK = new Map<string, string[]>([
  ['roster', ['GET', 'POST']],
  ['consent', ['POST']],
  ['vouch', ['POST']],
  ['withdraw', ['POST']],
  ['needs', ['GET']],
]);

async function desk(office: Office, req: Request, name: string): Promise<Response> {
  only(DESK.get(name)!, req);
  const token = bearer(req);
  if (token === null) throw new OfficeError(401, 'no_token');
  if (token === '' || !office.checkToken(token)) throw new OfficeError(401, 'bad_token');
  if (req.method === 'GET') return json(name === 'needs' ? office.needs() : { rows: office.rows() });
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

async function route(office: Office, req: Request, path: string): Promise<Response> {
  const deskName = /^\/desk\/([a-z]+)$/.exec(path)?.[1];
  if (deskName !== undefined && DESK.has(deskName)) return desk(office, req, deskName);

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
    if (req.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: { 'access-control-allow-methods': 'GET, POST', 'access-control-allow-headers': 'content-type', 'access-control-max-age': '600' },
      });
    }
    only(['GET', 'POST'], req);
    if (req.method === 'GET') return json(office.pickup(code));
    return json(office.redeem(code, (await bodyOf(req)).proof));
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

/** A fetch handler for the office: Bun.serve, a Worker, or a test calling it directly. */
export function officeHandler(office: Office): Handler {
  return async (req) => {
    const path = new URL(req.url).pathname;
    let res: Response;
    try {
      res = await route(office, req, path);
    } catch (e) {
      res = failure(e);
    }
    // Apps fetch the public half from their own pages; the desk is not for other origins.
    if (!path.startsWith('/desk/')) res.headers.set('access-control-allow-origin', '*');
    return res;
  };
}

export interface ServeOptions {
  port: number;
  /** Defaults to 127.0.0.1: put TLS in front. */
  hostname?: string;
}

export function serveOffice(office: Office, o: ServeOptions) {
  return Bun.serve({
    port: o.port,
    hostname: o.hostname ?? '127.0.0.1',
    maxRequestBodySize: 1 << 20,
    fetch: officeHandler(office),
  });
}
