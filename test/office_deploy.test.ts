/**
 * The office's deploy files (`bodies/office/deploy/`), beside a brain on one
 * host: the systemd unit starts the office as written, on localhost, behind
 * the brain; the office's own site serves the public routes to everyone and
 * no desk; and the desk is on the brain's host, passed to the office only
 * after the brain names the caller. With `caddy` on PATH, both are validated
 * and run: Caddy in front of the office and of a stand-in for the brain's
 * /api/v1/auth/check (not a real brain), to show what reaches the office.
 *
 * The brain's own Caddy template (semantos-core caddy_template.zig) writes the
 * desk and the office's site; `brain-desk.caddy` and `Caddyfile` are the same
 * by hand, for a brain whose site block nothing writes. With a semantos-core
 * checkout (SEMANTOS_CORE_DIR, or semantos-core beside this repository), they
 * are held line for line to the template's fixtures, and the template's whole
 * rendered block is run in front of the office as the hand copies are.
 */
import { afterAll, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PrivateKey } from '@bsv/sdk';
import { Office, fileStore, initState, serveOffice } from '../bodies/office';

const ROOT = join(import.meta.dir, '..');
const DEPLOY = join(ROOT, 'bodies/office/deploy');
const read = (name: string) => readFileSync(join(DEPLOY, name), 'utf8');

const unit = read('vouch-office@.service');
const site = read('Caddyfile');
const deskBlock = read('brain-desk.caddy');
/** The example env file, as systemd reads it: KEY=value lines. */
const env = Object.fromEntries(
  read('office.env.example')
    .split('\n')
    .filter((l) => /^[A-Z_]+=/.test(l))
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
);
const directive = (name: string): string[] => [...unit.matchAll(new RegExp(`^${name}=(.*)$`, 'gm'))].map((m) => m[1]!);

const dir = mkdtempSync(join(tmpdir(), 'gip-office-deploy-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** The brain's Caddy template's fixtures, in a semantos-core checkout, or null without one. */
const TEMPLATE = (() => {
  const core = process.env.SEMANTOS_CORE_DIR ?? join(ROOT, '..', 'semantos-core');
  const vectors = join(core, 'runtime/semantos-brain/tests/vectors/caddy-blocks');
  if (!existsSync(join(vectors, 'with-vouch-office.conf.expected'))) {
    if (process.env.SEMANTOS_CORE_DIR !== undefined) throw new Error(`SEMANTOS_CORE_DIR has no brain Caddy template fixtures at ${vectors}`);
    return null;
  }
  const fixture = (name: string) => readFileSync(join(vectors, name), 'utf8');
  return { desk: fixture('vouch-desk.caddy.expected'), site: fixture('vouch-office-site.caddy.expected'), block: fixture('with-vouch-office.conf.expected') };
})();
const NO_TEMPLATE = 'no semantos-core checkout: set SEMANTOS_CORE_DIR, or put semantos-core beside this repository';

describe('the systemd unit', () => {
  test('runs serve on localhost behind the brain, its state in its own state directory, its settings from an env file', () => {
    const [exec] = directive('ExecStart');
    expect(exec).toBe(
      '/usr/local/bin/bun --no-install run bodies/office/cli.ts serve --desk-auth brain --state /var/lib/vouch-office/%i/office.json --host 127.0.0.1 --port ${OFFICE_PORT}',
    );
    expect(directive('WorkingDirectory')).toEqual(['/opt/plexus-gip']);
    expect(directive('StateDirectory')).toEqual(['vouch-office/%i']);
    expect(directive('StateDirectoryMode')).toEqual(['0700']);
    expect(directive('EnvironmentFile')).toEqual(['/etc/vouch-office/%i.env']);
    expect(directive('User')).toEqual(['vouch-office']);
    expect(directive('ProtectSystem')).toEqual(['strict']);
    expect(directive('NoNewPrivileges')).toEqual(['true']);
  });

  test('its env file names a port, no other origin for the desk, and no secret; the desk auth is not in it', () => {
    expect(Object.keys(env).sort()).toEqual(['OFFICE_DESK_ORIGIN', 'OFFICE_PORT']);
    expect(Number.isInteger(Number(env.OFFICE_PORT))).toBe(true);
    // The Helm the brain serves is on the brain's host: no other origin.
    expect(env.OFFICE_DESK_ORIGIN).toBe('');
    expect(unit).not.toMatch(/^Environment=/m);
    expect(unit).not.toContain('OFFICE_DESK_AUTH');
  });

  test('its command line starts the office behind the brain: the desk wants the brain\'s caller, not a token', async () => {
    const key = (label: string) => PrivateKey.fromString(createHash('sha256').update(`gip-v2-deploy-test/${label}`).digest('hex'), 16);
    const year = new Date().getUTCFullYear() + 1;
    const { state } = initState({
      did: 'did:web:hillside.example.edu.au',
      anchorSk: key('anchor'),
      stewardSk: key('steward'),
      kind: 'school',
      claims: ['member', 'guardian_of_member'],
      periodEnds: [`${year}-12-31T23:59:59Z`],
      now: Math.floor(Date.now() / 1000),
    });
    const statePath = join(dir, 'office.json');
    fileStore(statePath).save(state);
    // The unit's own command line, with the instance, the port and the paths of this machine.
    const args = directive('ExecStart')[0]!
      .replaceAll('/var/lib/vouch-office/%i/office.json', statePath)
      .replaceAll('${OFFICE_PORT}', '0')
      .split(' ');
    args[0] = process.execPath;
    const p = Bun.spawn(args, { cwd: ROOT, env: { ...process.env, ...env }, stdout: 'pipe', stderr: 'pipe' });
    try {
      const reader = p.stdout.getReader();
      let out = '';
      while (!/ desk from .*\n/.test(out)) {
        const { value, done } = await reader.read();
        if (done) break;
        out += new TextDecoder().decode(value);
      }
      expect(out).toContain('desk auth brain');
      expect(out).toContain('desk from no other origin');
      const base = /listening on (http:\/\/127\.0\.0\.1:\d+)/.exec(out)![1]!;
      expect((await fetch(`${base}/desk/standing`)).status).toBe(401);
      expect((await fetch(`${base}/desk/standing`, { headers: { 'x-semantos-standing': 'operator' } })).status).toBe(200);
      expect((await fetch(`${base}/.well-known/did.json`)).status).toBe(200);
    } finally {
      p.kill();
    }
  });
});

describe('the office\'s own site', () => {
  /** The body of a named block: `@name {` or `handle @name {`, to its closing brace. */
  const block = (opening: string): string => {
    const at = site.indexOf(`${opening} {`);
    expect(at).toBeGreaterThanOrEqual(0);
    return site.slice(at, site.indexOf('\n\t}', at));
  };
  const upstream = `reverse_proxy 127.0.0.1:${env.OFFICE_PORT}`;

  test('serves exactly the public routes to everyone, from the unit\'s port', () => {
    const matcher = /^\t@public path (.*)$/m.exec(site)?.[1]?.split(' ');
    expect(matcher).toEqual(['/.well-known/did.json', '/status/*', '/pickup/*', '/collect']);
    expect(block('handle @public')).toContain(upstream);
  });

  test('passes no caller to the office, whatever a client sends', () => {
    const pub = block('handle @public');
    expect(pub).toContain('header_up -X-Semantos-Standing');
    expect(pub).toContain('header_up -X-Semantos-Cert-Id');
  });

  test('has no desk, answers 404 for anything else, and keeps no access log', () => {
    expect(site.split('\n').filter((l) => !l.trim().startsWith('#'))).not.toContainEqual(expect.stringContaining('/desk'));
    expect(site).toMatch(/\thandle \{\n\t\trespond 404\n\t\}/);
    expect(site.split('\n').filter((l) => /^\s*log\b/.test(l))).toEqual([]);
    expect(site.split('\n').filter((l) => l.includes('reverse_proxy'))).toHaveLength(1);
  });
});

describe('the desk on the brain\'s host', () => {
  /** The directives inside `route { }`, in the order Caddy runs them. */
  const steps = deskBlock
    .slice(deskBlock.indexOf('route {') + 'route {'.length)
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#') && l !== '}' && !l.startsWith('uri /') && !l.startsWith('copy_headers'));

  test('is /api/v1/vouch/desk/*, and nothing else of the brain\'s', () => {
    expect(deskBlock).toMatch(/^handle \/api\/v1\/vouch\/desk\/\* \{$/m);
    expect(deskBlock.split('\n').filter((l) => /^\S/.test(l) && !l.startsWith('#'))).toEqual(['handle /api/v1/vouch/desk/* {', '}']);
  });

  test('drops the client\'s caller, asks the brain, drops the brain\'s credentials, then passes /desk/* to the office', () => {
    expect(steps).toEqual([
      'request_header -X-Semantos-Standing',
      'request_header -X-Semantos-Cert-Id',
      '@asked not method OPTIONS',
      'forward_auth @asked 127.0.0.1:8082 {',
      'request_header -Authorization',
      'request_header -Cookie',
      'uri strip_prefix /api/v1/vouch',
      `reverse_proxy 127.0.0.1:${env.OFFICE_PORT}`,
    ]);
  });

  test('asks the brain\'s /api/v1/auth/check, and copies exactly the caller it names', () => {
    expect(deskBlock).toContain('\t\t\turi /api/v1/auth/check\n');
    expect(deskBlock).toContain('\t\t\tcopy_headers X-Semantos-Standing X-Semantos-Cert-Id\n');
  });
});

/** A Caddyfile's directives, one a line, without comments, blank lines or indentation. */
const directives = (text: string): string[] =>
  text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'));

describe.skipIf(TEMPLATE === null)(`the brain's template writes the same (skipped with ${NO_TEMPLATE})`, () => {
  test('brain-desk.caddy is the desk the template writes into a brain\'s site, line for line', () => {
    expect(directives(deskBlock)).toEqual(directives(TEMPLATE!.desk));
  });

  test('Caddyfile is the office\'s site the template writes, line for line', () => {
    expect(directives(site)).toEqual(directives(TEMPLATE!.site));
  });
});

/** Where one live run's sites and services are on this machine, and where the brain's site logs. */
type Ports = { brainSite: number; officeSite: number; brain: number; office: number; log: string };

/** caddy, if this machine has it. */
const caddy = Bun.which('caddy');
const freePort = async (): Promise<number> => {
  const s = Bun.serve({ port: 0, hostname: '127.0.0.1', fetch: () => new Response() });
  const port = s.port!;
  s.stop(true);
  return port;
};

/** One raw request, so a path is sent as written. */
const raw = (port: number, lines: string): Promise<string> =>
  new Promise((resolve, reject) => {
    const c = connect(port, '127.0.0.1', () => c.write(`${lines}\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`));
    let d = '';
    c.on('data', (b) => (d += b));
    c.on('end', () => resolve(d));
    c.on('error', reject);
  });

describe.skipIf(caddy === null)('Caddy in front (skipped without caddy on PATH)', () => {
  const RUTH = '0123456789abcdef0123456789abcdef';
  const OTHER = 'fedcba9876543210fedcba9876543210';

  test('caddy validate takes the office\'s site, and the brain\'s with the desk in it', () => {
    const file = join(dir, 'validate.Caddyfile');
    writeFileSync(file, `${site}\nbrain.hillside.example.edu.au {\n${deskBlock}\n\thandle {\n\t\treverse_proxy 127.0.0.1:8082\n\t}\n}\n`);
    const r = Bun.spawnSync([caddy!, 'validate', '--config', file, '--adapter', 'caddyfile'], { env: { ...process.env, HOME: dir, XDG_DATA_HOME: dir, XDG_CONFIG_HOME: dir } });
    expect(r.stdout.toString() + r.stderr.toString()).toContain('Valid configuration');
    expect(r.exitCode).toBe(0);
  });

  /** Caddy, on `config`'s sites, in front of a stand-in brain and the office: what reaches the office. */
  const deskBehindCaddy = async (name: string, config: (p: Ports) => string) => {
    // A stand-in for the brain, answering as runtime/semantos-brain's /api/v1/auth/check does for three bearers,
    // and everything else its own. It is not a brain.
    const asked: Headers[] = [];
    const brain = Bun.serve({
      port: 0,
      hostname: '127.0.0.1',
      fetch(req) {
        const path = new URL(req.url).pathname;
        if (path !== '/api/v1/auth/check') return new Response(`brain ${path}`);
        asked.push(req.headers);
        const callers: Record<string, Record<string, string>> = {
          'Bearer ruth': { 'x-semantos-standing': 'member', 'x-semantos-cert-id': RUTH },
          'Bearer stranger': { 'x-semantos-standing': 'member', 'x-semantos-cert-id': OTHER },
          // The brain sends the cert id even when empty: Caddy 2.6 would pass on its placeholder for one it lacks.
          'Bearer op': { 'x-semantos-standing': 'operator', 'x-semantos-cert-id': '' },
        };
        const who = callers[req.headers.get('authorization') ?? ''];
        return who === undefined ? Response.json({ error: 'unauthorised' }, { status: 401 }) : new Response(null, { status: 204, headers: who });
      },
    });
    const { state } = initState({
      did: 'did:web:hillside.example.edu.au',
      anchorSk: PrivateKey.fromString(createHash('sha256').update('gip-v2-deploy-test/caddy-anchor').digest('hex'), 16),
      stewardSk: PrivateKey.fromString(createHash('sha256').update('gip-v2-deploy-test/caddy-steward').digest('hex'), 16),
      kind: 'school',
      claims: ['member', 'guardian_of_member'],
      periodEnds: [`${new Date().getUTCFullYear() + 1}-12-31T23:59:59Z`],
      now: Math.floor(Date.now() / 1000),
    });
    const statePath = join(dir, `caddy-office-${name}.json`);
    fileStore(statePath).save(state);
    const office = new Office(fileStore(statePath));
    office.addRegistrar(RUTH);
    const served = serveOffice(office, { port: 0, hostname: '127.0.0.1', deskAuth: 'brain' });
    const [brainSite, officeSite] = [await freePort(), await freePort()];
    const log = join(dir, `caddy-${name}.access.log`);
    const sites = config({ brainSite, officeSite, brain: brain.port!, office: served.port!, log });
    // Every host and port of the deploy is this machine's now.
    for (const left of ['hillside', ':8082', `:${env.OFFICE_PORT}`, 'on_demand']) expect(sites).not.toContain(left);
    const configFile = join(dir, `run-${name}.Caddyfile`);
    writeFileSync(configFile, `{\n\tadmin off\n\tauto_https off\n}\n${sites}`);
    const p = Bun.spawn([caddy!, 'run', '--config', configFile, '--adapter', 'caddyfile'], {
      env: { ...process.env, HOME: dir, XDG_DATA_HOME: dir, XDG_CONFIG_HOME: dir },
      stdout: 'ignore',
      stderr: 'ignore',
    });
    try {
      const desk = `http://127.0.0.1:${brainSite}/api/v1/vouch/desk`;
      for (let i = 0; i < 200; i++) {
        if (await fetch(`http://127.0.0.1:${brainSite}/`).then(() => true, () => false)) break;
        await Bun.sleep(25);
      }
      const spoof = { 'x-semantos-standing': 'operator', 'x-semantos-cert-id': OTHER };

      // A registrar's bearer, with a forged caller beside it: the office sees the brain's answer.
      const ruth = await fetch(`${desk}/whoami`, { headers: { authorization: 'Bearer ruth', ...spoof } });
      expect(await ruth.json()).toEqual({ mode: 'brain', standing: 'member', certId: RUTH, registrar: true });
      // The brain was asked without the forged caller.
      expect(asked.at(-1)!.get('x-semantos-standing')).toBeNull();
      expect(asked.at(-1)!.get('x-semantos-cert-id')).toBeNull();

      // No bearer, or one the brain does not know: the brain's 401, and the office never asked.
      for (const headers of [spoof, { authorization: 'Bearer nobody', ...spoof }]) {
        const r = await fetch(`${desk}/needs`, { headers });
        expect(r.status).toBe(401);
        expect((await r.json()).error).toBe('unauthorised');
      }

      // Someone the brain knows and the office does not list.
      const stranger = await fetch(`${desk}/needs`, { headers: { authorization: 'Bearer stranger' } });
      expect([stranger.status, (await stranger.json()).error]).toEqual([403, 'not_a_registrar']);

      // The operator, with a cookie as a browser would send one: the office would refuse either credential.
      const op = await fetch(`${desk}/needs`, { headers: { authorization: 'Bearer op', cookie: '__semantos_session=abc' } });
      expect(op.status).toBe(200);
      const roster = await fetch(`${desk}/roster`, {
        method: 'POST',
        headers: { authorization: 'Bearer ruth', 'content-type': 'application/json' },
        body: JSON.stringify({ rows: [{ id: 'HP-0042', kind: 'member', label: 'Mia Ellis' }] }),
      });
      expect(roster.status).toBe(200);
      expect(office.deskLog().at(-1)!.by).toEqual({ standing: 'member', certId: RUTH });

      // The rest of the brain's host is the brain's.
      expect(await (await fetch(`http://127.0.0.1:${brainSite}/api/v1/info`)).text()).toBe('brain /api/v1/info');

      // The office's own site has no desk, even by a path that climbs out of a public one.
      const site = `http://127.0.0.1:${officeSite}`;
      expect((await fetch(`${site}/desk/needs`, { headers: spoof })).status).toBe(404);
      for (const path of ['/pickup/../desk/needs', '/pickup/%2e%2e/desk/needs', '/status/..%2fdesk/needs']) {
        const answer = await raw(officeSite, `GET ${path} HTTP/1.1\r\nX-Semantos-Standing: operator`);
        expect(answer).not.toMatch(/^HTTP\/1\.1 200/);
      }
      expect((await fetch(`${site}/.well-known/did.json`)).status).toBe(200);
    } finally {
      p.kill();
      await p.exited;
      served.stop(true);
      brain.stop(true);
    }
    // Where the brain's site keeps an access log, the desk's requests are in it and the brain's credentials are not.
    if (sites.includes(log)) {
      const kept = readFileSync(log, 'utf8');
      expect(kept).toContain('/api/v1/vouch/desk/whoami');
      expect(kept).not.toContain('Bearer ');
      expect(kept).not.toContain('__semantos_session');
    }
  };

  test('the hand copies: only the caller the brain names reaches the office, without the brain\'s credentials', () =>
    deskBehindCaddy('hand', (p) => {
      const swap = (text: string) => text.replaceAll('127.0.0.1:8082', `127.0.0.1:${p.brain}`).replaceAll(`127.0.0.1:${env.OFFICE_PORT}`, `127.0.0.1:${p.office}`);
      return (
        `${swap(site).replace('vouch.hillside.example.edu.au {', `http://127.0.0.1:${p.officeSite} {`)}\n` +
        `http://127.0.0.1:${p.brainSite} {\n${swap(deskBlock)}\n\thandle {\n\t\treverse_proxy 127.0.0.1:${p.brain}\n\t}\n}\n`
      );
    }), 30_000);

  test.skipIf(TEMPLATE === null)('the brain\'s template, its whole block: the same', () =>
    deskBehindCaddy('template', (p) =>
      TEMPLATE!.block
        // Plain HTTP on this machine's ports: no certificate, and the log in the test's directory.
        .replaceAll('    tls {\n        on_demand\n    }\n\n', '')
        .replace('brain.hillside.example.edu.au {', `http://127.0.0.1:${p.brainSite} {`)
        .replace('vouch.hillside.example.edu.au {', `http://127.0.0.1:${p.officeSite} {`)
        .replace('/var/log/caddy/brain.hillside.example.edu.au.access.log', p.log)
        .replaceAll('localhost:8082', `127.0.0.1:${p.brain}`)
        .replaceAll('127.0.0.1:8082', `127.0.0.1:${p.brain}`)
        .replaceAll(`127.0.0.1:${env.OFFICE_PORT}`, `127.0.0.1:${p.office}`),
    ), 30_000);
});
