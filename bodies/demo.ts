/**
 * Any body as attestor: the school pilot, then a scout group, as a runnable demo.
 *
 *     bun bodies/demo.ts
 *
 * A registry steward lists Hillside Primary. The school's anchor delegates a
 * hosted node, and the delegation travels on the withdrawal list. The
 * registrar's node vouches `member` for a child and `guardian_of_member` for a
 * parent, each about a key their own wallet made for this one platform. The
 * kids' world gate checks both presentations offline. The school withdraws
 * the child and the gate refuses. The school moves to a new node and then
 * withdraws the old one, and the old node's vouch stops passing. Then a scout
 * group runs through the same function with kind `scouts` and no code change.
 *
 * Every name, record and address here is made up.
 */

import { createHash } from 'node:crypto';
import { PrivateKey } from '@bsv/sdk';
import {
  type Association,
  BODY_VOUCH_PURPOSE,
  type BodyClaim,
  type BodyKind,
  delegateSigner,
  didKeyOfSecret,
  fromB64url,
  fromUtf8,
  issueRegistryEntry,
  issueStatusList,
  issueVouch,
  present,
  readDelegation,
  readRegistryEntry,
  appPlace,
  placeKeyOf,
  verifyPresentation,
} from '../src';

/** Deterministic demo key from a label, so the output is stable and explainable. */
const key = (label: string): PrivateKey =>
  PrivateKey.fromString(createHash('sha256').update(`gip-v2-bodies-demo/${label}`).digest('hex'), 16);
const pub = (k: PrivateKey): string => k.toPublicKey().toString();
const short = (s: string): string => `${s.slice(0, 18)}…${s.slice(-4)}`;
const h = (title: string): void => console.log(`\n\x1b[1m${title}\x1b[0m`);
const ok = (b: boolean): string => (b ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m');
const payloadOf = (jwt: string) => JSON.parse(fromUtf8(fromB64url(jwt.split('.')[1]!)));
const nonce = (): string => crypto.randomUUID();

// ── time: now, and the next two 31 December period ends ─────────────────────
const now = Math.floor(Date.now() / 1000);
const yearEnd = (y: number): string => `${y}-12-31T23:59:59Z`;
let year = new Date(now * 1000).getUTCFullYear();
if (now >= Date.parse(yearEnd(year)) / 1000) year += 1;
const PERIOD_ENDS = [yearEnd(year), yearEnd(year + 1)];

// ── the registry steward and the kids' world ────────────────────────────────
const steward = key('steward'); // keeps the published list of bodies that count
const GATE = 'kids-world:gem-island'; // the relying party, and its audience id
const gateTrusts = new Set([didKeyOfSecret(steward)]);

interface Pilot {
  name: string;
  did: string;
  kind: BodyKind;
  claims: BodyClaim[];
  /** What the body's own records say. This never leaves the body. */
  records: { child: Record<string, string>; parent: Record<string, string> };
}

function runPilot(p: Pilot): void {
  const host = p.did.slice('did:web:'.length);
  const statusUrl = `https://${host}/status/1`;
  const anchor = key(`${p.did}/anchor`); // the body's Plexus page-0: delegates, never vouches
  const node = key(`${p.did}/node-1`); // the hosted signing node

  console.log(`\n\x1b[1m═══ ${p.name} (${p.kind}) ═══\x1b[0m`);

  h(`[1] The steward registers ${p.name}`);
  const entryJwt = issueRegistryEntry(steward, {
    did: p.did,
    anchor: pub(anchor),
    kind: p.kind,
    claims: p.claims,
    periodEnds: PERIOD_ENDS,
    statusList: statusUrl,
    validFrom: now - 86400,
    validUntil: PERIOD_ENDS[1]!,
  });
  const entry = readRegistryEntry(entryJwt)!;
  console.log(`  did         ${entry.did}`);
  console.log(`  anchor      ${short(entry.anchor)}`);
  console.log(`  kind        ${entry.kind}`);
  console.log(`  may vouch   ${entry.claims.join(', ')}`);
  console.log(`  expiries    ${entry.periodEnds.join(', ')}   (period ends only, never a birthday)`);
  console.log(`  withdrawals ${entry.statusList}`);
  console.log(`  signed by   ${short(entry.steward)}   (the steward, not the body)`);

  h('[2] The anchor delegates a hosted node');
  const delegation = delegateSigner(anchor, pub(node), BODY_VOUCH_PURPOSE);
  const d = readDelegation(delegation)!;
  console.log(`  anchor ${short(d.anchor)} → node ${short(d.node)}   purpose=${d.purpose}`);
  console.log('  the anchor key goes back in the safe; the node signs from here on');
  console.log('  the delegation goes on the withdrawal list, not in each vouch');

  h('[3] Each wallet makes a key for this one platform');
  const childSk = placeKeyOf(key(`${p.did}/child-root`), appPlace(GATE));
  const parentSk = placeKeyOf(key(`${p.did}/parent-root`), appPlace(GATE));
  const elsewhere = placeKeyOf(key(`${p.did}/child-root`), appPlace('homework-club:online'));
  console.log(`  child,  for ${GATE}   ${short(didKeyOfSecret(childSk))}`);
  console.log(`  parent, for ${GATE}   ${short(didKeyOfSecret(parentSk))}`);
  console.log(`  child,  for another platform   ${short(didKeyOfSecret(elsewhere))}   (a different key: no cross-platform match)`);

  h(`[4] The registrar checks the records, and the node vouches one fact each`);
  const lead = `  records (stay at ${p.name}): `;
  console.log(`${lead}${JSON.stringify(p.records.child)}`);
  console.log(`${' '.repeat(lead.length)}${JSON.stringify(p.records.parent)}`);
  const childCred = issueVouch({
    nodeSk: node,
    entry,
    subject: didKeyOfSecret(childSk),
    claim: 'member',
    statusIndex: 101,
    validFrom: now - 60,
    validUntil: PERIOD_ENDS[0]!,
  });
  const parentCred = issueVouch({
    nodeSk: node,
    entry,
    subject: didKeyOfSecret(parentSk),
    claim: 'guardian_of_member',
    statusIndex: 102,
    validFrom: now - 60,
    validUntil: PERIOD_ENDS[0]!,
  });
  const shown = payloadOf(childCred);
  console.log(`  the child's credential, as it travels (${childCred.length} bytes, no delegation inside):`);
  console.log(`    issuer            ${shown.issuer}`);
  console.log(`    credentialSubject ${JSON.stringify(shown.credentialSubject).replace(/did:key:[^"]+/, (s) => short(s))}`);
  console.log(`    validUntil        ${shown.validUntil}`);
  console.log(`    credentialStatus  index ${shown.credentialStatus.statusListIndex} of ${shown.credentialStatus.statusListCredential}`);
  const text = JSON.stringify(shown) + JSON.stringify(payloadOf(parentCred));
  const leaked = Object.values({ ...p.records.child, ...p.records.parent }).filter((v) => text.includes(v));
  console.log(`  any name, birthdate or record number inside? ${leaked.length === 0 ? 'none ' + ok(true) : leaked.join(', ') + ' ' + ok(false)}`);

  h('[5] The node publishes the withdrawal list (16 KiB of bits, fetched whole)');
  const lists = { [statusUrl]: issueStatusList(node, { issuer: p.did, delegations: [delegation], url: statusUrl, revoked: [], validFrom: now - 60 }) };
  console.log(`  ${statusUrl}   nothing withdrawn; carries the node's delegation`);

  const gate = (statusLists: Record<string, string>, require: BodyClaim, n: string) => ({
    audience: GATE,
    nonce: n,
    stewards: gateTrusts,
    registryEntries: [entryJwt],
    statusLists,
    now,
    require,
  });

  h(`[6] ${GATE} challenges each holder and checks offline`);
  const n1 = nonce();
  const v1 = verifyPresentation(present({ credentialJwt: childCred, subjectSk: childSk, audience: GATE, nonce: n1, at: now }), gate(lists, 'member', n1));
  console.log(`  child  asks in as member              → ${v1.ok ? `ok, vouched by ${v1.body.did} (${v1.body.kind})` : v1.reason} ${ok(v1.ok)}`);
  const n2 = nonce();
  const v2 = verifyPresentation(
    present({ credentialJwt: parentCred, subjectSk: parentSk, audience: GATE, nonce: n2, at: now }),
    gate(lists, 'guardian_of_member', n2),
  );
  console.log(`  parent asks in as guardian_of_member  → ${v2.ok ? `ok, vouched by ${v2.body.did} (${v2.body.kind})` : v2.reason} ${ok(v2.ok)}`);
  console.log(`  the gate contacted ${host}: never`);

  h(`[7] The child leaves; ${p.name} withdraws index 101`);
  const after = { [statusUrl]: issueStatusList(node, { issuer: p.did, delegations: [delegation], url: statusUrl, revoked: [101], validFrom: now - 30 }) };
  const n3 = nonce();
  const v3 = verifyPresentation(present({ credentialJwt: childCred, subjectSk: childSk, audience: GATE, nonce: n3, at: now }), gate(after, 'member', n3));
  console.log(`  child asks in again → ${v3.ok ? 'ok' : `refused: ${v3.reason}`} ${ok(!v3.ok)}`);

  h(`[8] ${p.name} moves to a new node, then withdraws the old one`);
  const node2 = key(`${p.did}/node-2`);
  const delegation2 = delegateSigner(anchor, pub(node2), BODY_VOUCH_PURPOSE);
  const parentCred2 = issueVouch({
    nodeSk: node2,
    entry,
    subject: didKeyOfSecret(parentSk),
    claim: 'guardian_of_member',
    statusIndex: 103,
    validFrom: now - 20,
    validUntil: PERIOD_ENDS[0]!,
  });
  const listOf = (delegations: Association[], at: number) => ({
    [statusUrl]: issueStatusList(node2, { issuer: p.did, delegations, url: statusUrl, revoked: [101], validFrom: at }),
  });
  const parentIn = (cred: string, statusLists: Record<string, string>) => {
    const n = nonce();
    return verifyPresentation(present({ credentialJwt: cred, subjectSk: parentSk, audience: GATE, nonce: n, at: now }), gate(statusLists, 'guardian_of_member', n));
  };
  const said = (v: ReturnType<typeof verifyPresentation>) => (v.ok ? 'ok' : `refused: ${v.reason}`);
  console.log('  the anchor delegates node-2; node-2 signs the list, which carries both delegations');
  const v4 = parentIn(parentCred, listOf([delegation2, delegation], now - 20));
  console.log(`  parent's vouch from node-1   → ${said(v4)} ${ok(v4.ok)}`);
  console.log('  node-1 withdrawn: its delegation comes off, and node-2 signs the list again');
  const retired = listOf([delegation2], now - 10);
  const v5 = parentIn(parentCred, retired);
  console.log(`  parent's vouch from node-1   → ${said(v5)} ${ok(!v5.ok)}`);
  const v6 = parentIn(parentCred2, retired);
  console.log(`  parent's vouch from node-2   → ${said(v6)} ${ok(v6.ok)}`);
}

runPilot({
  name: 'Hillside Primary',
  did: 'did:web:hillside.example.edu.au',
  kind: 'school',
  claims: ['member', 'guardian_of_member'],
  records: {
    child: { given: 'Mia', family: 'Ellis', birthdate: '2016-03-04', studentNumber: 'HP-0042' },
    parent: { given: 'Sam', family: 'Ellis', guardianOf: 'HP-0042' },
  },
});

runPilot({
  name: '1st Hillside Scouts',
  did: 'did:web:1st-hillside.scouts.example.org.au',
  kind: 'scouts',
  claims: ['member', 'guardian_of_member', 'helper'],
  records: {
    child: { given: 'Leo', family: 'Okafor', birthdate: '2015-08-21', memberNumber: 'SC-1187' },
    parent: { given: 'Ana', family: 'Okafor', guardianOf: 'SC-1187' },
  },
});

console.log('\n\x1b[1m═══ done — one function, two kinds of body, every step against real signatures ═══\x1b[0m');
