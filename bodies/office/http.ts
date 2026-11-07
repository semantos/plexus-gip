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
 *     POST /collect {proof, extend, cosign?}
 *                                    the same, after making out to that key what a key the
 *                                    office vouches for holds (a new place; office.ts, extendNonce)
 *
 * The registrar's desk:
 *
 *     GET  /desk/whoami              who the office takes the caller to be, and whether it lets them in
 *     GET  /desk/roster              every row
 *     POST /desk/roster {rows}       add or update rows
 *     POST /desk/consent {ids, consent}
 *     POST /desk/vouch {ids, periodEnd?}           pickup URLs, for QR codes
 *     POST /desk/withdraw {ids, sponsorNote?}
 *     GET  /desk/needs               the home list
 *     GET  /desk/standing            the registry entry, the nodes, the withdrawal list
 *
 * Who may use the desk is the desk auth mode's to say:
 *
 * - `brain` (for a deploy). The registrar signs in to the body's brain in the
 *   Helm. Caddy, on the brain's host, takes `/api/v1/vouch/desk/*`, asks the
 *   brain who the Helm's bearer belongs to (`forward_auth` to
 *   `/api/v1/auth/check`), strips whatever identity headers the client sent,
 *   sets them from the brain's answer, drops the brain's credentials and
 *   passes the request here as `/desk/*`. The office takes a desk request only
 *   over loopback or its own unix socket, only with those headers, and only
 *   from the brain's operator or a member on its registrar list
 *   (`cli.ts registrars`). A request that still carries an Authorization
 *   header or a cookie is refused: the brain's credential stops at Caddy.
 * - `dev-token` (the default, for development only): `Authorization: Bearer
 *   <token>`, the token `init` printed.
 *
 * Every desk action is put down to who made it, in the office's own record.
 *
 * The desk may be a page on another origin (a Helm the brain does not
 * serve), so the office answers a browser from the origins it is given
 * (`deskOrigins`) and from no other. That is CORS, not a lock.
 *
 * The server speaks plain HTTP on localhost by default. Put TLS in front of
 * it: a pickup code is a secret until it is used. `deploy/` has a systemd unit
 * and a Caddy site for it, beside a brain.
 */
import { chmodSync } from 'node:fs';
import { CERT_ID, Office, OfficeError } from './office';
import type { DeskActor } from './state';

/** How the desk knows who is asking: through the brain, or (development only) by the office's own token. */
export type DeskAuth = 'brain' | 'dev-token';

/** The headers Caddy sets from the brain's answer (`/api/v1/auth/check`), and no one else may. */
export const STANDING_HEADER = 'x-semantos-standing';
export const CERT_ID_HEADER = 'x-semantos-cert-id';

/** Every standing the brain names. The desk takes only the operator's and a listed member's. */
const STANDINGS = new Set(['operator', 'admin', 'member', 'hat', 'device', 'agent']);

/** Where a request came from: an address, or the office's own unix socket. */
export type Peer = { address: string } | { unix: true };

type Handler = (req: Request, peer?: Peer) => Promise<Response>;

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
  ['whoami', ['GET']],
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

/** 127.0.0.0/8, ::1, or either as an IPv4-mapped address. */
export function isLoopback(address: string): boolean {
  const a = address.toLowerCase().replace(/^::ffff:/, '');
  if (a === '::1' || a === '0:0:0:0:0:0:0:1') return true;
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(a);
  return m !== null && m.slice(1).every((x) => Number(x) <= 255);
}

/** Who the caller is at the desk, and whether the office lets them in. */
interface DeskCaller {
  /** As the brain named it, or `dev-token`. */
  standing: string;
  certId?: string;
  registrar: boolean;
  /** Why not, when not. */
  why?: string;
}

/** A caller the office let in, as its record names them. */
const actorOf = (c: DeskCaller): DeskActor => ({
  standing: c.standing as DeskActor['standing'],
  ...(c.certId !== undefined && { certId: c.certId }),
});

/**
 * The caller behind the brain, from the headers Caddy set. Throws when the
 * request did not come the way Caddy sends it; answers `registrar: false`
 * for a caller the brain named but the office does not let in.
 */
function brainCaller(office: Office, req: Request, peer: Peer | undefined): DeskCaller {
  if (peer === undefined || (!('unix' in peer) && !isLoopback(peer.address))) {
    throw new OfficeError(403, 'not_through_the_brain', 'the desk is reached through the brain\'s host, from Caddy on this machine');
  }
  if (req.headers.has('authorization') || req.headers.has('cookie')) {
    throw new OfficeError(400, 'brain_credential_forwarded', 'the brain\'s credentials stop at Caddy: strip Authorization and Cookie before the office');
  }
  const standing = req.headers.get(STANDING_HEADER) ?? '';
  const certId = req.headers.get(CERT_ID_HEADER) ?? '';
  if (standing === '') throw new OfficeError(401, 'no_identity', 'no caller from the brain: sign in to the brain in the Helm');
  if (!STANDINGS.has(standing) || (certId !== '' && !CERT_ID.test(certId))) throw new OfficeError(401, 'bad_identity');
  const who = { standing, ...(certId !== '' && { certId }) };
  if (standing === 'operator' || standing === 'admin') return { ...who, registrar: true };
  if (standing !== 'member') return { ...who, registrar: false, why: `signed in with a ${standing}'s bearer: sign in to the brain with your own wallet` };
  if (certId === '') return { ...who, registrar: false, why: 'your sign-in names no identity: bind your wallet to your identity on the brain' };
  if (!office.isRegistrar(certId)) return { ...who, registrar: false, why: 'ask the school\'s operator to add you as a registrar' };
  return { ...who, registrar: true };
}

/** The caller with the development token. */
function tokenCaller(office: Office, req: Request): DeskCaller {
  const token = bearer(req);
  if (token === null) throw new OfficeError(401, 'no_token');
  if (token === '' || !office.checkToken(token)) throw new OfficeError(401, 'bad_token');
  return { standing: 'dev-token', registrar: true };
}

async function desk(
  office: Office,
  req: Request,
  name: string,
  allowed: (origin: string | null) => boolean,
  mode: DeskAuth,
  peer: Peer | undefined,
): Promise<Response> {
  if (req.method === 'OPTIONS') {
    // A browser asks before it sends its credential. Only the desk's origins are told yes.
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
  const caller = mode === 'brain' ? brainCaller(office, req, peer) : tokenCaller(office, req);
  if (name === 'whoami') return json({ mode, ...caller });
  if (!caller.registrar) throw new OfficeError(403, 'not_a_registrar', caller.why);
  if (req.method === 'GET') return json(DESK_READS[name]!(office));
  const b = await bodyOf(req);
  const by = actorOf(caller);
  switch (name) {
    case 'roster':
      return json({ rows: office.upsertRows(b.rows, by) });
    case 'consent':
      return json(office.setConsent(b.ids, b.consent, by));
    case 'vouch':
      return json(office.vouch(b.ids, b.periodEnd, by));
    default:
      return json(office.withdraw(b.ids, b.sponsorNote, by));
  }
}

async function route(
  office: Office,
  req: Request,
  path: string,
  allowed: (origin: string | null) => boolean,
  mode: DeskAuth,
  peer: Peer | undefined,
): Promise<Response> {
  const deskName = /^\/desk\/([a-z]+)$/.exec(path)?.[1];
  if (deskName !== undefined && DESK.has(deskName)) return desk(office, req, deskName, allowed, mode, peer);

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
    const b = await bodyOf(req);
    if ('guardian' in b) throw new OfficeError(400, 'bad_request', 'a guardian\'s proof goes in cosign');
    return json(office.collect(b.proof, b.extend, b.cosign));
  }

  throw new OfficeError(404, 'not_found');
}

function failure(e: unknown): Response {
  if (!(e instanceof OfficeError)) {
    console.error(e);
    return json({ error: 'internal' }, 500);
  }
  const headers: Record<string, string> = {};
  if (e.status === 401 && (e.code === 'no_token' || e.code === 'bad_token')) {
    headers['www-authenticate'] = `Bearer realm="desk"${e.code === 'bad_token' ? ', error="invalid_token"' : ''}`;
  }
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
   * The origins the registrar's desk is served from, when that is not the
   * brain's own host (a Helm the brain does not serve). A browser on one of
   * them may call the desk routes; it is still asked who it is. None by
   * default.
   */
  deskOrigins?: readonly string[];
  /** How the desk knows who is asking. `dev-token` by default, which is for development only. */
  deskAuth?: DeskAuth;
}

/** A desk auth mode, from a flag or the environment. */
export function deskAuth(mode: string): DeskAuth {
  if (mode !== 'brain' && mode !== 'dev-token') throw new OfficeError(400, 'bad_desk_auth', `the desk auth is brain or dev-token, not ${mode}`);
  return mode;
}

/**
 * A fetch handler for the office: Bun.serve, a Worker, or a test calling it
 * directly. `peer` is where the request came from; behind the brain, the desk
 * answers only loopback and the office's own socket.
 */
export function officeHandler(office: Office, o: OfficeHandlerOptions = {}): Handler {
  const origins = new Set((o.deskOrigins ?? []).map(deskOrigin));
  const allowed = (origin: string | null) => origin !== null && origins.has(origin);
  const mode = deskAuth(o.deskAuth ?? 'dev-token');
  return async (req, peer) => {
    const path = new URL(req.url).pathname;
    let res: Response;
    try {
      res = await route(office, req, path, allowed, mode, peer);
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
  /** Defaults to 127.0.0.1: put TLS in front. Behind the brain, it must be a loopback address. */
  hostname?: string;
}

export interface ServeUnixOptions extends OfficeHandlerOptions {
  /** A unix socket to listen on instead of a port, made mode 0660: only its owner and group connect. */
  unix: string;
}

export function serveOffice(office: Office, o: ServeOptions | ServeUnixOptions) {
  const handler = officeHandler(office, o);
  if ('unix' in o) {
    const server = Bun.serve({
      unix: o.unix,
      maxRequestBodySize: 1 << 20,
      fetch: (req) => handler(req, { unix: true }),
    });
    chmodSync(o.unix, 0o660);
    return server;
  }
  const hostname = o.hostname ?? '127.0.0.1';
  if (o.deskAuth === 'brain' && !isLoopback(hostname) && hostname !== 'localhost') {
    throw new OfficeError(400, 'not_loopback', `behind the brain the office listens on loopback or a unix socket, not ${hostname}`);
  }
  return Bun.serve({
    port: o.port,
    hostname,
    maxRequestBodySize: 1 << 20,
    fetch: (req, server) => {
      const ip = server.requestIP(req);
      return handler(req, ip === null ? undefined : { address: ip.address });
    },
  });
}
