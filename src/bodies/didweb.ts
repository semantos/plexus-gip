/**
 * did:web, read as the DID Web method says: where a body's DID document is,
 * and, from that document, where the body's office is. Nothing here fetches;
 * the reader does that with the URL it is given.
 *
 *     did:web:example.com                    https://example.com/.well-known/did.json
 *     did:web:example.com%3A3000:user:alice  https://example.com:3000/user/alice/did.json
 *
 * The method allows no IP address and only https. For local development and
 * tests a reader may be told to use http for localhost and 127.0.0.1, and for
 * nothing else.
 */
import { WireError } from './bytes';

/** The DID document service type naming a body's office, where holders collect their vouches. */
export const BODY_VOUCH_OFFICE = 'BodyVouchOffice';

export interface DidWebOptions {
  /** Use http for localhost and 127.0.0.1. For local development and tests only. */
  allowHttpLocal?: boolean;
}

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1']);

/** A DNS label, lowercase: the method's examples, and the registry's did:web, are lowercase. */
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/** A path segment: DID syntax's idchar, letters, digits, `.`, `-`, `_` and %-escapes. */
const SEGMENT = /^([A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+$/;

/** A host whose last label is a number is an IPv4 address to a URL parser. */
const looksIpv4 = (host: string): boolean => /^(0x[0-9a-f]*|[0-9]+)$/.test(host.slice(host.lastIndexOf('.') + 1));

interface DidWeb {
  host: string;
  /** The host, and `:port` if the did has one. */
  hostPort: string;
  /** Where the document is on the host, %-escapes kept. */
  path: string;
}

function parse(did: string): DidWeb {
  const bad = (why: string) => new WireError('bad_did', `${did}: ${why}`);
  if (!did.startsWith('did:web:')) throw bad('not a did:web');
  const [hostPort, ...path] = did.slice('did:web:'.length).split(':');
  const m = /^([^%]*)(?:%3[Aa]([1-9][0-9]{0,4}))?$/.exec(hostPort!);
  if (m === null) throw bad('a host, then optionally %3A and a port');
  const host = m[1]!;
  const port = m[2] ?? null;
  if (host === '' || !host.split('.').every((l) => LABEL.test(l))) throw bad('the host is not a lowercase domain name');
  if (looksIpv4(host) && host !== '127.0.0.1') throw bad('the method allows no IP address');
  if (port !== null && Number(port) > 65535) throw bad('the port is above 65535');
  for (const seg of path) {
    if (!SEGMENT.test(seg)) throw bad('a path segment is empty or has a character the method does not allow');
    // An escaped dot is still a dot to a URL parser, and an escaped slash may be one to a server.
    if (/^(\.|%2e){1,2}$/i.test(seg) || /%(2f|5c)/i.test(seg)) throw bad('a path segment would leave its place');
  }
  return {
    host,
    hostPort: port === null ? host : `${host}:${port}`,
    path: path.length === 0 ? '/.well-known/did.json' : `/${path.join('/')}/did.json`,
  };
}

/** The host a did:web names, with its port if it has one: `example.com:3000`. */
export const didWebHost = (did: string): string => parse(did).hostPort;

/** Where on its host a did:web's document is: `/.well-known/did.json`, or `/<path>/did.json`. */
export const didWebPath = (did: string): string => parse(did).path;

/** The URL of a did:web's DID document. Throws `bad_did` for anything the method does not allow. */
export function didWebDocumentUrl(did: string, o: DidWebOptions = {}): string {
  const { host, hostPort, path } = parse(did);
  const local = LOCAL_HOSTS.has(host) && o.allowHttpLocal === true;
  if (host === '127.0.0.1' && !local) throw new WireError('bad_did', `${did}: the method allows no IP address`);
  return `${local ? 'http' : 'https'}://${hostPort}${path}`;
}

/**
 * The body's office, from the DID document fetched for `did`: the endpoint of
 * its {@link BODY_VOUCH_OFFICE} service, with no trailing slash, so the
 * collect route is `${office}/collect`. Null if the document is for another
 * did, names no office, or names one a reader may not use: it must be https,
 * or http on localhost or 127.0.0.1 when the reader allows it.
 */
export function vouchOfficeOf(doc: unknown, did: string, o: DidWebOptions = {}): string | null {
  if (typeof doc !== 'object' || doc === null || (doc as Record<string, unknown>).id !== did) return null;
  const services = (doc as Record<string, unknown>).service;
  if (!Array.isArray(services)) return null;
  for (const s of services) {
    const type = s?.type;
    if (!(type === BODY_VOUCH_OFFICE || (Array.isArray(type) && type.includes(BODY_VOUCH_OFFICE)))) continue;
    const u = typeof s.serviceEndpoint === 'string' ? URL.parse(s.serviceEndpoint) : null;
    if (u === null || u.username !== '' || u.password !== '' || u.search !== '' || u.hash !== '') continue;
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && o.allowHttpLocal && LOCAL_HOSTS.has(u.hostname))) continue;
    return `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
  }
  return null;
}
