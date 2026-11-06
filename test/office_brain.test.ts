/**
 * The desk behind the brain (`--desk-auth brain`): the office takes a desk
 * request only over loopback or its own socket, only with the identity
 * headers Caddy sets from the brain's answer, only from the brain's operator
 * or a member on its registrar list, and puts every action down to them.
 * These tests play Caddy's part by setting the headers themselves; no brain
 * runs here.
 */
import { afterAll, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PrivateKey } from '@bsv/sdk';
import { CERT_ID_HEADER, Office, type Peer, STANDING_HEADER, fileStore, initState, isLoopback, officeHandler, serveOffice } from '../bodies/office';

const key = (label: string): PrivateKey =>
  PrivateKey.fromString(createHash('sha256').update(`gip-v2-office-brain-test/${label}`).digest('hex'), 16);
const at = (iso: string): number => Date.parse(iso) / 1000;

const NOW = at('2026-11-05T09:00:00Z');
const DID = 'did:web:hillside.example.edu.au';
const BASE = 'https://hillside.example.edu.au';
const LOOPBACK: Peer = { address: '127.0.0.1' };

/** Who the brain says is signed in: a registrar, someone else, and the operator's own login. */
const RUTH = '0123456789abcdef0123456789abcdef';
const OTHER = 'fedcba9876543210fedcba9876543210';
const OPERATOR = '00112233445566778899aabbccddeeff';

const ROSTER = [
  { id: 'HP-0042', kind: 'member', label: 'Mia Ellis', group: 'Room 3B' },
  { id: 'HP-G-0042a', kind: 'guardian', label: 'Sam Ellis', guardianOf: ['HP-0042'] },
];

const dir = mkdtempSync(join(tmpdir(), 'gip-office-brain-test-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

interface Reply {
  status: number;
  json: any;
  headers: Headers;
}

/** The identity headers, as Caddy sets them from the brain's answer. */
const as = (standing: string, certId?: string): Record<string, string> => ({
  [STANDING_HEADER]: standing,
  ...(certId !== undefined && { [CERT_ID_HEADER]: certId }),
});

function makeOffice(name: string) {
  const { state, token } = initState({
    did: DID,
    anchorSk: key('anchor'),
    stewardSk: key('steward'),
    kind: 'school',
    claims: ['member', 'guardian_of_member'],
    periodEnds: ['2026-12-31T23:59:59Z', '2027-12-31T23:59:59Z'],
    now: NOW - 86400,
  });
  const path = join(dir, `${name}.json`);
  fileStore(path).save(state);
  const office = new Office(fileStore(path), { now: () => NOW });
  const h = officeHandler(office, { deskAuth: 'brain', deskOrigins: ['https://helm.example.org'] });
  /** `peer` 'none' is a request with no peer at all. */
  const call = async (method: string, p: string, headers: Record<string, string> = {}, body?: unknown, peer: Peer | 'none' = LOOPBACK): Promise<Reply> => {
    const res = await h(
      new Request(`${BASE}${p}`, {
        method,
        headers: { ...headers, ...(body !== undefined && { 'content-type': 'application/json' }) },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
      peer === 'none' ? undefined : peer,
    );
    const text = await res.text();
    let json: any = null;
    try {
      json = JSON.parse(text);
    } catch {}
    return { status: res.status, json, headers: res.headers };
  };
  return { office, h, token, path, call };
}

const DESK: [string, string, unknown?][] = [
  ['GET', '/desk/roster'],
  ['POST', '/desk/roster', { rows: [] }],
  ['POST', '/desk/consent', { ids: [], consent: true }],
  ['POST', '/desk/vouch', { ids: [] }],
  ['POST', '/desk/withdraw', { ids: [] }],
  ['GET', '/desk/needs'],
  ['GET', '/desk/standing'],
];

describe('who the desk lets in', () => {
  const o = makeOffice('who');
  o.office.addRegistrar(RUTH, 'Ruth, the registrar');

  test('without the identity headers every desk route is 401, and says to sign in to the brain', async () => {
    for (const [method, path, body] of DESK) {
      const r = await o.call(method, path, {}, body);
      expect([r.status, r.json.error]).toEqual([401, 'no_identity']);
      expect(r.headers.get('www-authenticate')).toBeNull();
    }
  });

  test('the brain\'s operator, and an admin, are let in; a member on the list is let in', async () => {
    for (const who of [as('operator'), as('operator', OPERATOR), as('admin'), as('member', RUTH)]) {
      for (const [method, path, body] of DESK) expect((await o.call(method, path, who, body)).status).toBe(200);
    }
  });

  test('a member not on the list is refused, and told to ask the operator', async () => {
    for (const [method, path, body] of DESK) {
      const r = await o.call(method, path, as('member', OTHER), body);
      expect([r.status, r.json.error]).toEqual([403, 'not_a_registrar']);
      expect(r.json.detail).toContain('ask the school\'s operator to add you as a registrar');
    }
    const none = await o.call('GET', '/desk/needs', as('member'));
    expect([none.status, none.json.error]).toEqual([403, 'not_a_registrar']);
  });

  test('a hat, a device or an agent is not a registrar, even with a listed identity', async () => {
    for (const standing of ['hat', 'device', 'agent']) {
      const r = await o.call('GET', '/desk/needs', as(standing, RUTH));
      expect([r.status, r.json.error]).toEqual([403, 'not_a_registrar']);
    }
  });

  test('a registrar taken off the list is refused at their next request', async () => {
    const office = makeOffice('removed');
    office.office.addRegistrar(OTHER);
    expect((await office.call('GET', '/desk/needs', as('member', OTHER))).status).toBe(200);
    office.office.removeRegistrar(OTHER);
    const r = await office.call('GET', '/desk/needs', as('member', OTHER));
    expect([r.status, r.json.error]).toEqual([403, 'not_a_registrar']);
  });

  test('whoami says who the office takes the caller to be, let in or not', async () => {
    expect((await o.call('GET', '/desk/whoami', as('member', RUTH))).json).toEqual({
      mode: 'brain',
      standing: 'member',
      certId: RUTH,
      registrar: true,
    });
    const other = await o.call('GET', '/desk/whoami', as('member', OTHER));
    expect(other.status).toBe(200);
    expect(other.json).toEqual({
      mode: 'brain',
      standing: 'member',
      certId: OTHER,
      registrar: false,
      why: 'ask the school\'s operator to add you as a registrar',
    });
    expect((await o.call('GET', '/desk/whoami', as('operator'))).json).toEqual({ mode: 'brain', standing: 'operator', registrar: true });
    expect((await o.call('GET', '/desk/whoami')).status).toBe(401);
    // It names the caller and no one else: no list, no label.
    expect(JSON.stringify(other.json)).not.toContain('Ruth');
  });
});

describe('the way in', () => {
  const o = makeOffice('way-in');

  test('only over loopback or the office\'s own socket', async () => {
    for (const peer of [{ address: '203.0.113.7' }, { address: '10.0.0.2' }, { address: '::ffff:192.0.2.1' }, { address: 'fe80::1' }, 'none' as const]) {
      const r = await o.call('GET', '/desk/needs', as('operator'), undefined, peer);
      expect([r.status, r.json.error]).toEqual([403, 'not_through_the_brain']);
    }
    for (const peer of [{ address: '127.0.0.1' }, { address: '127.8.9.10' }, { address: '::1' }, { address: '::ffff:127.0.0.1' }, { unix: true } as Peer]) {
      expect((await o.call('GET', '/desk/needs', as('operator'), undefined, peer)).status).toBe(200);
    }
  });

  test('isLoopback takes 127/8 and ::1, and nothing that only looks like them', () => {
    for (const a of ['127.0.0.1', '127.255.255.255', '::1', '::FFFF:127.0.0.1', '0:0:0:0:0:0:0:1']) expect(isLoopback(a)).toBe(true);
    for (const a of ['128.0.0.1', '127.0.0.256', '127.0.0', '1.127.0.0.1', '::2', 'localhost', '127.0.0.1.evil.example', '']) {
      expect(isLoopback(a)).toBe(false);
    }
  });

  test('the public routes stay open from anywhere, with no identity', async () => {
    const r = await o.call('GET', '/.well-known/did.json', {}, undefined, { address: '203.0.113.7' });
    expect(r.status).toBe(200);
  });

  test('a preflight from a desk origin is answered without an identity', async () => {
    const r = await o.call('OPTIONS', '/desk/needs', { origin: 'https://helm.example.org' });
    expect(r.status).toBe(204);
    expect(r.headers.get('access-control-allow-origin')).toBe('https://helm.example.org');
  });
});

describe('spoofing', () => {
  const o = makeOffice('spoof');
  o.office.addRegistrar(RUTH);

  test('the development token is no way in behind the brain', async () => {
    const r = await o.call('GET', '/desk/needs', { authorization: `Bearer ${o.token}` });
    expect([r.status, r.json.error]).toEqual([400, 'brain_credential_forwarded']);
    expect((await o.call('GET', '/desk/whoami', { authorization: `Bearer ${o.token}` })).status).toBe(400);
  });

  test('a request still carrying the brain\'s bearer or a cookie is refused: Caddy must strip them', async () => {
    const extras: Record<string, string>[] = [{ authorization: `Bearer ${'ab'.repeat(32)}` }, { cookie: '__semantos_session=x' }];
    for (const extra of extras) {
      const r = await o.call('GET', '/desk/needs', { ...as('operator'), ...extra });
      expect([r.status, r.json.error]).toEqual([400, 'brain_credential_forwarded']);
    }
  });

  test('a standing the brain does not name, two of them, or a cert id that is not one, is refused', async () => {
    const bad: Record<string, string>[] = [
      as('root'),
      as('Operator'),
      as('operator, member'),
      as('member, operator', RUTH),
      as(' '),
      as('member', RUTH.toUpperCase()),
      as('member', `${RUTH}00`),
      as('member', `${RUTH}, ${OTHER}`),
      as('operator', 'not-a-cert-id'),
    ];
    for (const headers of bad) {
      const r = await o.call('GET', '/desk/needs', headers);
      expect(r.status).toBeOneOf([401]);
      expect(r.json.error).toBeOneOf(['bad_identity', 'no_identity']);
    }
  });

  test('a header that only resembles the identity header is not it', async () => {
    const r = await o.call('GET', '/desk/needs', { x_semantos_standing: 'operator', 'x-semantos-standing-': 'operator', 'x-semantos-standings': 'operator' });
    expect([r.status, r.json.error]).toEqual([401, 'no_identity']);
  });
});

describe('who did what', () => {
  const o = makeOffice('attribution');
  o.office.addRegistrar(RUTH);
  const ruth = as('member', RUTH);

  test('each desk action is put down to who made it, in the office\'s own record', async () => {
    expect((await o.call('POST', '/desk/roster', ruth, { rows: ROSTER })).status).toBe(200);
    expect((await o.call('POST', '/desk/consent', as('operator', OPERATOR), { ids: ['HP-0042', 'HP-G-0042a'], consent: true })).status).toBe(200);
    const v = await o.call('POST', '/desk/vouch', ruth, { ids: ['HP-0042', 'HP-G-0042a'] });
    expect(v.json.pickups).toHaveLength(2);
    expect((await o.call('POST', '/desk/withdraw', as('operator'), { ids: ['HP-0042'], sponsorNote: true })).status).toBe(200);

    const s = JSON.parse(readFileSync(o.path, 'utf8'));
    // Who vouched: on each pickup.
    expect(s.pickups.map((p: any) => [p.rosterId, p.vouchedBy])).toEqual([
      ['HP-0042', { standing: 'member', certId: RUTH }],
      ['HP-G-0042a', { standing: 'member', certId: RUTH }],
    ]);
    // Who withdrew: on the row.
    expect(s.roster.find((r: any) => r.id === 'HP-0042').withdrawnBy).toEqual({ standing: 'operator' });
    expect(s.roster.find((r: any) => r.id === 'HP-G-0042a').withdrawnBy).toBeUndefined();
    // And every action, in order, by row id only.
    expect(o.office.deskLog()).toEqual([
      { at: '2026-11-05T09:00:00Z', by: { standing: 'member', certId: RUTH }, action: 'roster', ids: ['HP-0042', 'HP-G-0042a'] },
      { at: '2026-11-05T09:00:00Z', by: { standing: 'operator', certId: OPERATOR }, action: 'consent', ids: ['HP-0042', 'HP-G-0042a'], consent: true },
      { at: '2026-11-05T09:00:00Z', by: { standing: 'member', certId: RUTH }, action: 'vouch', ids: ['HP-0042', 'HP-G-0042a'] },
      { at: '2026-11-05T09:00:00Z', by: { standing: 'operator' }, action: 'withdraw', ids: ['HP-0042'] },
    ]);
    expect(JSON.stringify(s.deskLog)).not.toContain('Ellis');
  });

  test('the roster the desk reads says who withdrew a row; vouching it again clears it', async () => {
    const rows = (await o.call('GET', '/desk/roster', ruth)).json.rows;
    expect(rows.find((r: any) => r.id === 'HP-0042').withdrawnBy).toEqual({ standing: 'operator' });
    await o.call('POST', '/desk/vouch', ruth, { ids: ['HP-0042'] });
    const again = (await o.call('GET', '/desk/roster', ruth)).json.rows;
    expect(again.find((r: any) => r.id === 'HP-0042').withdrawnBy).toBeUndefined();
  });

  test('a refused request records nothing', async () => {
    const before = o.office.deskLog().length;
    await o.call('POST', '/desk/withdraw', as('member', OTHER), { ids: ['HP-0042'] });
    await o.call('POST', '/desk/withdraw', {}, { ids: ['HP-0042'] });
    expect(o.office.deskLog()).toHaveLength(before);
  });

  test('with the development token, an action is put down to the token', async () => {
    const dev = makeOffice('attribution-dev');
    const h = officeHandler(dev.office);
    const res = await h(
      new Request(`${BASE}/desk/roster`, {
        method: 'POST',
        headers: { authorization: `Bearer ${dev.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ rows: ROSTER }),
      }),
    );
    expect(res.status).toBe(200);
    expect(dev.office.deskLog().map((e) => e.by)).toEqual([{ standing: 'dev-token' }]);
    const who = await h(new Request(`${BASE}/desk/whoami`, { headers: { authorization: `Bearer ${dev.token}` } }));
    expect(await who.json()).toEqual({ mode: 'dev-token', standing: 'dev-token', registrar: true });
    // And the identity headers mean nothing to it.
    const spoofed = await h(new Request(`${BASE}/desk/needs`, { headers: as('operator') }));
    expect(spoofed.status).toBe(401);
  });
});

describe('the registrar list', () => {
  test('is kept by cert id, added once, and refuses what is not a cert id', () => {
    const o = makeOffice('list');
    expect(o.office.addRegistrar(RUTH, 'Ruth').added).toBe(true);
    expect(o.office.addRegistrar(RUTH).added).toBe(false);
    expect(o.office.registrars()).toEqual([{ certId: RUTH, label: 'Ruth', addedAt: '2026-11-05T09:00:00Z' }]);
    for (const bad of ['', RUTH.toUpperCase(), `${RUTH}0`, 'ruth']) expect(() => o.office.addRegistrar(bad)).toThrow();
    expect(() => o.office.removeRegistrar(OTHER)).toThrow();
    o.office.removeRegistrar(RUTH);
    expect(o.office.registrars()).toEqual([]);
  });

  test('a state file from before the list loads with none', () => {
    const o = makeOffice('old-file');
    const s = JSON.parse(readFileSync(o.path, 'utf8'));
    delete s.registrars;
    delete s.deskLog;
    const path = join(dir, 'old-file-2.json');
    fileStore(path).save(s);
    const office = new Office(fileStore(path));
    expect(office.registrars()).toEqual([]);
    expect(office.deskLog()).toEqual([]);
  });
});

describe('the server, behind the brain', () => {
  test('over loopback HTTP, with the headers Caddy sets', async () => {
    const o = makeOffice('server-brain');
    const server = serveOffice(o.office, { port: 0, hostname: '127.0.0.1', deskAuth: 'brain' });
    try {
      const base = `http://127.0.0.1:${server.port}`;
      expect((await fetch(`${base}/desk/needs`, { headers: as('operator') })).status).toBe(200);
      expect((await fetch(`${base}/desk/needs`)).status).toBe(401);
      expect((await fetch(`${base}/desk/needs`, { headers: { authorization: `Bearer ${o.token}` } })).status).toBe(400);
    } finally {
      server.stop(true);
    }
  });

  test('over its own unix socket, mode 0660', async () => {
    const o = makeOffice('server-unix');
    const sock = join(dir, 'office.sock');
    const server = serveOffice(o.office, { unix: sock, deskAuth: 'brain' });
    try {
      expect(statSync(sock).mode & 0o777).toBe(0o660);
      const r = await fetch('http://localhost/desk/whoami', { unix: sock, headers: as('operator') } as RequestInit);
      expect(await r.json()).toEqual({ mode: 'brain', standing: 'operator', registrar: true });
    } finally {
      server.stop(true);
    }
  });

  test('refuses to listen anywhere but loopback', () => {
    const o = makeOffice('server-wide');
    for (const hostname of ['0.0.0.0', '::', '192.0.2.10']) {
      expect(() => serveOffice(o.office, { port: 0, hostname, deskAuth: 'brain' })).toThrow();
    }
  });
});

describe('the CLI', () => {
  const cli = (...args: string[]) => {
    const r = Bun.spawnSync([process.execPath, 'bodies/office/cli.ts', ...args], { cwd: join(import.meta.dir, '..') });
    return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString() };
  };

  test('registrars add, list and remove, by cert id', () => {
    const o = makeOffice('cli-registrars');
    const add = cli('registrars', 'add', RUTH, '--label', 'Ruth', '--state', o.path);
    expect(add.code).toBe(0);
    expect(add.out).toContain(`added ${RUTH}`);
    expect(cli('registrars', 'add', RUTH, '--state', o.path).out).toContain('already');
    const list = cli('registrars', 'list', '--state', o.path);
    expect(list.out).toContain(RUTH);
    expect(list.out).toContain('Ruth');
    const bad = cli('registrars', 'add', 'not-a-cert-id', '--state', o.path);
    expect(bad.code).not.toBe(0);
    expect(bad.err).toContain('bad_cert_id');
    expect(cli('registrars', 'remove', OTHER, '--state', o.path).code).not.toBe(0);
    expect(cli('registrars', 'remove', RUTH, '--state', o.path).code).toBe(0);
    expect(cli('registrars', 'list', '--state', o.path).out).toContain('no registrars');
    expect(cli('registrars', 'nonsense', '--state', o.path).code).not.toBe(0);
  });

  test('serve --desk-auth brain listens on loopback only, and says so', async () => {
    const o = makeOffice('cli-serve-brain');
    const wide = cli('serve', '--state', o.path, '--port', '0', '--desk-auth', 'brain', '--host', '0.0.0.0');
    expect(wide.code).not.toBe(0);
    expect(wide.err).toContain('not_loopback');
    const nonsense = cli('serve', '--state', o.path, '--port', '0', '--desk-auth', 'open');
    expect(nonsense.code).not.toBe(0);
    expect(nonsense.err).toContain('brain or dev-token');

    const p = Bun.spawn([process.execPath, 'bodies/office/cli.ts', 'serve', '--state', o.path, '--port', '0', '--desk-auth', 'brain'], {
      cwd: join(import.meta.dir, '..'),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    try {
      const reader = p.stdout.getReader();
      let out = '';
      while (!/ desk from .*\n/.test(out)) {
        const { value, done } = await reader.read();
        if (done) break;
        out += new TextDecoder().decode(value);
      }
      expect(out).toContain('desk auth brain');
      const base = /listening on (\S+)/.exec(out)![1]!;
      expect((await fetch(`${base}/desk/whoami`, { headers: as('operator') })).status).toBe(200);
      expect((await fetch(`${base}/desk/whoami`, { headers: { authorization: `Bearer ${o.token}` } })).status).toBe(400);
    } finally {
      p.kill();
    }
  });

  test('serve in dev-token mode says loudly that it is for development only', async () => {
    const o = makeOffice('cli-serve-dev');
    const p = Bun.spawn([process.execPath, 'bodies/office/cli.ts', 'serve', '--state', o.path, '--port', '0'], {
      cwd: join(import.meta.dir, '..'),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    try {
      const reader = p.stderr.getReader();
      let err = '';
      while (!err.includes('DEVELOPMENT ONLY')) {
        const { value, done } = await reader.read();
        if (done) break;
        err += new TextDecoder().decode(value);
      }
      expect(err).toContain('DEVELOPMENT ONLY');
    } finally {
      p.kill();
    }
  });
});
