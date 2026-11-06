/**
 * Run a body's office.
 *
 *     bun bodies/office/cli.ts keygen <file>
 *     bun bodies/office/cli.ts init --did did:web:<host> --anchor-key <file> --entry <file>
 *     bun bodies/office/cli.ts init --did did:web:<host> --anchor-key <file> \
 *         --steward-key <file> --kind school --period-ends 2026-12-31T23:59:59Z,2027-12-31T23:59:59Z
 *     bun bodies/office/cli.ts serve [--desk-auth brain|dev-token] [--port 8080] [--host 127.0.0.1]
 *         [--unix <socket>] [--desk-origin <origin>[,<origin>]]
 *     bun bodies/office/cli.ts registrars add <cert id> [--label <name>]
 *     bun bodies/office/cli.ts registrars remove <cert id>
 *     bun bodies/office/cli.ts registrars list
 *     bun bodies/office/cli.ts token
 *     bun bodies/office/cli.ts rotate-node --anchor-key <file>
 *     bun bodies/office/cli.ts retire-node <node>
 *
 * Every command but keygen takes `--state <file>`, by default $OFFICE_STATE or
 * `.gip-v2/office.json`. `init` also takes `--url <origin>` when the office is
 * not at the did:web's host, and `--claims` (default member,guardian_of_member).
 * `serve` takes `--desk-auth`, by default $OFFICE_DESK_AUTH or `dev-token`:
 * `brain` for a deploy, where the registrar signs in to the brain and Caddy
 * passes the brain's answer on (http.ts); `dev-token` for development only,
 * with the token `init` printed. Behind the brain the office listens on
 * loopback (`--host`) or a unix socket (`--unix`, mode 0660). `--desk-origin`,
 * by default $OFFICE_DESK_ORIGIN, names the origins a browser may reach the
 * desk routes from when the Helm is not served by the brain itself.
 *
 * `registrars` keeps the members who may use the desk behind the brain,
 * besides the brain's operator, by the cert id the brain names for them (the
 * desk's Setup shows a member theirs). Taking one off refuses their next
 * request.
 *
 * The anchor key file is read once, to sign the node's delegation, and is not
 * copied into the state. Keep it offline after init, and bring it out again
 * only for rotate-node.
 *
 * rotate-node makes a new node key; the withdrawal list carries both nodes'
 * delegations, so vouches from either pass. retire-node drops an old node's
 * delegation from the list: every vouch it signed then fails at the gate.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseArgs } from 'node:util';
import { PrivateKey } from '@bsv/sdk';
import type { BodyClaim, BodyKind } from '../../src';
import { type DeskAuth, deskAuth, deskOrigin, serveOffice } from './http';
import { Office, OfficeError } from './office';
import { fileStore, initState } from './state';

const HELP = `commands:
  keygen <file>         make a key file (an anchor, or a pilot's steward), mode 600
  init                  make the office: --did --anchor-key, and --entry or --steward-key
  serve                 run it: --desk-auth (brain, or dev-token for development) --port (8080) --host (127.0.0.1)
                        --unix (a socket instead of a port) --desk-origin (the desk's origins, comma separated)
  registrars add <cert id> [--label <name>]
                        let a member use the desk behind the brain, by the cert id the brain names for them
  registrars remove <cert id>
                        stop them: their next desk request is refused
  registrars list       who may use the desk, besides the brain's operator
  token                 make a new development token (dev-token mode); the old one stops working
  rotate-node           make a new signing node: --anchor-key; the old one stays honoured until retired
  retire-node <node>    stop honouring an old node: every vouch it signed then fails
options: --state <file> (default $OFFICE_STATE or .gip-v2/office.json)`;

const STEWARD_WARNING = `
==============================================================================
WARNING: A BODY MUST NOT STEWARD ITSELF.
This registry entry was signed here, with a local steward key. That is for a
pilot only. An app that trusts this steward trusts whatever its key signs, so
the steward should be someone else: the app's operator, said plainly, or an
association of bodies, holding its own key. Past the pilot, have them sign the
entry and run init again with --entry.
==============================================================================
`;

function fail(message: string): never {
  console.error(`office: ${message}`);
  process.exit(1);
}

function readKey(path: string | undefined, what: string): PrivateKey {
  if (path === undefined) fail(`${what} is required`);
  const text = readFileSync(path, 'utf8').trim();
  if (!/^[0-9a-f]{64}$/.test(text)) fail(`${path} is not a private key in hex`);
  return PrivateKey.fromString(text, 16);
}

function keygen(path: string | undefined): void {
  if (path === undefined) fail('keygen <file>');
  if (existsSync(path)) fail(`refusing to overwrite ${path}`);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const sk = PrivateKey.fromRandom();
  writeFileSync(path, `${sk.toHex()}\n`, { mode: 0o600, flag: 'wx' });
  console.log(`key written to ${path} (mode 600)`);
  console.log(`public key: ${sk.toPublicKey().toString()}`);
}

function init(v: Record<string, string | undefined>, statePath: string): void {
  if (existsSync(statePath)) fail(`refusing to overwrite ${statePath}: a new office has a new node key and a new token`);
  if (v.did === undefined) fail('--did is required');
  const anchorSk = readKey(v['anchor-key'], '--anchor-key');
  const now = Math.floor(Date.now() / 1000);
  const base = { did: v.did, baseUrl: v.url, anchorSk, now };
  let made: ReturnType<typeof initState>;
  if (v.entry !== undefined) {
    if (v['steward-key'] !== undefined) fail('give --entry or --steward-key, not both');
    made = initState({ ...base, entry: readFileSync(v.entry, 'utf8') });
  } else if (v['steward-key'] !== undefined) {
    if (v.kind === undefined || v['period-ends'] === undefined) fail('--kind and --period-ends are required with --steward-key');
    made = initState({
      ...base,
      stewardSk: readKey(v['steward-key'], '--steward-key'),
      kind: v.kind as BodyKind,
      claims: (v.claims ?? 'member,guardian_of_member').split(',') as BodyClaim[],
      periodEnds: v['period-ends'].split(','),
    });
  } else {
    fail('give --entry <file>, an entry a steward signed, or for a pilot --steward-key <file>');
  }
  mkdirSync(dirname(statePath), { recursive: true, mode: 0o700 });
  fileStore(statePath).save(made.state);
  const info = new Office(fileStore(statePath)).info();
  console.log(`office state written to ${statePath} (mode 600)`);
  console.log(`  did            ${info.did}`);
  console.log(`  did document   ${info.didDocument}`);
  console.log(`                 (the office serves it too; if it runs elsewhere, publish a copy there)`);
  console.log(`  office         ${info.baseUrl}`);
  console.log(`  withdrawals    ${info.statusList}`);
  console.log(`  anchor         ${info.anchor}   (keep its key offline from now on)`);
  console.log(`  node           ${info.node}   (delegated for body.vouch)`);
  console.log(`  steward        ${info.steward}   (apps put this in their trusted set)`);
  console.log(`  may vouch      ${info.claims.join(', ')}, ending ${info.periodEnds.join(', ')}`);
  console.log('registrar token, for --desk-auth dev-token, development only (shown once; keep it safe):');
  console.log(`  ${made.token}`);
  console.log('behind the brain, add registrars with: registrars add <cert id>');
  if (info.pilotSteward) console.error(STEWARD_WARNING);
}

function serve(v: Record<string, string | undefined>, statePath: string): void {
  const office = new Office(fileStore(statePath));
  const info = office.info();
  if (info.pilotSteward) console.error(STEWARD_WARNING);
  let mode: DeskAuth;
  try {
    mode = deskAuth(v['desk-auth'] ?? process.env.OFFICE_DESK_AUTH ?? 'dev-token');
  } catch (e) {
    fail(`--desk-auth: ${(e as OfficeError).detail}`);
  }
  const port = Number(v.port ?? 8080);
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail('--port is a port number');
  const origins = (v['desk-origin'] ?? process.env.OFFICE_DESK_ORIGIN ?? '')
    .split(',')
    .map((o) => o.trim())
    .filter((o) => o !== '');
  for (const o of origins) {
    try {
      deskOrigin(o);
    } catch (e) {
      fail(`--desk-origin: ${(e as Error).message}`);
    }
  }
  if (v.unix !== undefined && v.host !== undefined) fail('give --unix or --host, not both');
  let server: ReturnType<typeof serveOffice>;
  try {
    server =
      v.unix !== undefined
        ? serveOffice(office, { unix: v.unix, deskOrigins: origins, deskAuth: mode })
        : serveOffice(office, { port, hostname: v.host, deskOrigins: origins, deskAuth: mode });
  } catch (e) {
    fail(e instanceof OfficeError ? `${e.code}: ${e.detail}` : (e as Error).message);
  }
  console.log(`office for ${info.did} listening on ${v.unix !== undefined ? `unix:${v.unix}` : `http://${server.hostname}:${server.port}`}`);
  console.log(`  reached at ${info.baseUrl}: put TLS in front, a pickup code is a secret until it is used`);
  if (mode === 'brain') {
    const n = office.registrars().length;
    console.log(`  desk auth brain: the brain's operator, and ${n} ${n === 1 ? 'registrar' : 'registrars'}, through Caddy on the brain's host`);
  } else {
    console.error('  desk auth dev-token: DEVELOPMENT ONLY. Anyone with the token is the registrar. Deploy with --desk-auth brain.');
  }
  console.log(origins.length === 0 ? '  desk from no other origin (--desk-origin to add one)' : `  desk from ${origins.join(', ')}`);
}

function registrars(sub: string | undefined, certId: string | undefined, v: Record<string, string | undefined>, statePath: string): void {
  const office = new Office(fileStore(statePath));
  if (sub === 'list') {
    const list = office.registrars();
    if (list.length === 0) console.log('no registrars: only the brain\'s operator may use the desk');
    for (const r of list) console.log(`${r.certId}  ${r.addedAt}${r.label === undefined ? '' : `  ${r.label}`}`);
    return;
  }
  if (sub !== 'add' && sub !== 'remove') fail('registrars add <cert id> [--label <name>] | remove <cert id> | list');
  if (certId === undefined) fail(`registrars ${sub} <cert id>`);
  try {
    if (sub === 'add') {
      const r = office.addRegistrar(certId, v.label);
      console.log(r.added ? `added ${certId}: they may use the desk from their next request` : `${certId} is already a registrar`);
    } else {
      office.removeRegistrar(certId);
      console.log(`removed ${certId}: their next desk request is refused`);
    }
  } catch (e) {
    fail(e instanceof OfficeError ? `${e.code}: ${e.detail}` : (e as Error).message);
  }
}

function token(statePath: string): void {
  const t = new Office(fileStore(statePath)).rotateToken();
  console.log('new registrar token, for --desk-auth dev-token, development only (shown once; the old one no longer works):');
  console.log(`  ${t}`);
}

function rotateNode(v: Record<string, string | undefined>, statePath: string): void {
  const anchorSk = readKey(v['anchor-key'], '--anchor-key');
  const r = new Office(fileStore(statePath)).rotateNode(anchorSk);
  console.log('new signing node, delegated for body.vouch; the withdrawal list is signed again');
  console.log(`  node           ${r.node}`);
  for (const n of r.nodes.slice(1)) console.log(`  still honoured ${n}   (retire-node ${n})`);
  console.log('Keep the anchor key offline again. Retire an old node once its vouches are');
  console.log('collected again, or at once if its key may be lost or taken.');
}

function retireNode(node: string | undefined, statePath: string): void {
  const office = new Office(fileStore(statePath));
  if (node === undefined) {
    const older = office.info().nodes.slice(1);
    fail(older.length === 0 ? 'retire-node <node>: no older node is honoured' : `retire-node <node>, one of:\n  ${older.join('\n  ')}`);
  }
  const r = office.retireNode(node);
  console.log(`retired ${r.retired}: the withdrawal list is signed again without its delegation`);
  console.log('  every vouch it signed now fails at the gate (node_not_delegated) once an app downloads the list');
  console.log(`  honoured       ${r.nodes.join(', ')}`);
}

function main(): void {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      state: { type: 'string' },
      did: { type: 'string' },
      url: { type: 'string' },
      'anchor-key': { type: 'string' },
      entry: { type: 'string' },
      'steward-key': { type: 'string' },
      kind: { type: 'string' },
      claims: { type: 'string' },
      'period-ends': { type: 'string' },
      port: { type: 'string' },
      host: { type: 'string' },
      'desk-origin': { type: 'string' },
      'desk-auth': { type: 'string' },
      unix: { type: 'string' },
      label: { type: 'string' },
      help: { type: 'boolean' },
    },
  });
  const [cmd, arg, arg2] = positionals;
  const statePath = values.state ?? process.env.OFFICE_STATE ?? '.gip-v2/office.json';
  const { help, ...v } = values;
  if (cmd === 'keygen') keygen(arg);
  else if (cmd === 'init') init(v, statePath);
  else if (cmd === 'serve') serve(v, statePath);
  else if (cmd === 'registrars') registrars(arg, arg2, v, statePath);
  else if (cmd === 'token') token(statePath);
  else if (cmd === 'rotate-node') rotateNode(v, statePath);
  else if (cmd === 'retire-node') retireNode(arg, statePath);
  else if (cmd === undefined || help) console.log(HELP);
  else fail(`unknown command: ${cmd}\n${HELP}`);
}

try {
  main();
} catch (e) {
  fail(e instanceof Error ? e.message : String(e));
}
