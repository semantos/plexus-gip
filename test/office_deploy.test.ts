/**
 * The office's deploy files (`bodies/office/deploy/`), beside a brain on one
 * host: the systemd unit starts the office as written, on localhost, and the
 * Caddy site serves the public routes to everyone and the desk only to the
 * desk's origin.
 */
import { afterAll, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PrivateKey } from '@bsv/sdk';
import { fileStore, initState } from '../bodies/office';

const ROOT = join(import.meta.dir, '..');
const DEPLOY = join(ROOT, 'bodies/office/deploy');
const read = (name: string) => readFileSync(join(DEPLOY, name), 'utf8');

const unit = read('vouch-office@.service');
const site = read('Caddyfile');
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

describe('the systemd unit', () => {
  test('runs serve on localhost, its state in its own state directory, its settings from an env file', () => {
    const [exec] = directive('ExecStart');
    expect(exec).toBe(
      '/usr/local/bin/bun --no-install run bodies/office/cli.ts serve --state /var/lib/vouch-office/%i/office.json --host 127.0.0.1 --port ${OFFICE_PORT}',
    );
    expect(directive('WorkingDirectory')).toEqual(['/opt/plexus-gip']);
    expect(directive('StateDirectory')).toEqual(['vouch-office/%i']);
    expect(directive('StateDirectoryMode')).toEqual(['0700']);
    expect(directive('EnvironmentFile')).toEqual(['/etc/vouch-office/%i.env']);
    expect(directive('User')).toEqual(['vouch-office']);
    expect(directive('ProtectSystem')).toEqual(['strict']);
    expect(directive('NoNewPrivileges')).toEqual(['true']);
  });

  test('its env file names a port and the desk\'s origin, and no secret', () => {
    expect(Object.keys(env).sort()).toEqual(['OFFICE_DESK_ORIGIN', 'OFFICE_PORT']);
    expect(Number.isInteger(Number(env.OFFICE_PORT))).toBe(true);
    expect(new URL(env.OFFICE_DESK_ORIGIN!).origin).toBe(env.OFFICE_DESK_ORIGIN!);
    expect(unit).not.toMatch(/^Environment=/m);
  });

  test('its command line starts the office, which answers the desk\'s origin', async () => {
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
      expect(out).toContain(`desk from ${env.OFFICE_DESK_ORIGIN}`);
      const base = /listening on (http:\/\/127\.0\.0\.1:\d+)/.exec(out)![1]!;
      const pre = await fetch(`${base}/desk/standing`, { method: 'OPTIONS', headers: { origin: env.OFFICE_DESK_ORIGIN! } });
      expect(pre.status).toBe(204);
      expect(pre.headers.get('access-control-allow-origin')).toBe(env.OFFICE_DESK_ORIGIN!);
      expect((await fetch(`${base}/.well-known/did.json`)).status).toBe(200);
    } finally {
      p.kill();
    }
  });
});

describe('the Caddy site', () => {
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

  test('serves the desk only to the desk\'s origin', () => {
    const desk = block('@desk');
    expect(desk).toContain('path /desk/*');
    expect(desk).toContain(`header Origin ${env.OFFICE_DESK_ORIGIN}`);
    expect(block('handle @desk')).toContain(upstream);
  });

  test('answers 404 for anything else, and keeps no access log', () => {
    expect(site).toMatch(/\thandle \{\n\t\trespond 404\n\t\}/);
    expect(site.split('\n').filter((l) => /^\s*log\b/.test(l))).toEqual([]);
    // Two proxies to the office and no more: nothing else reaches it.
    expect(site.split('\n').filter((l) => l.includes('reverse_proxy'))).toHaveLength(2);
  });
});
