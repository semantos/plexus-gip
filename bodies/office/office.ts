/**
 * The office: a body's issuing service, run by or for one body.
 *
 * The registrar keeps a roster here, with names, and records each family's
 * consent. Vouching a row makes a one-time pickup code for the family to scan
 * at the office. Their app proves a key it made for one relationship and
 * collects a vouch about that key: one claim, no name. Withdrawing a row sets
 * its bits in the body's withdrawal list, and the node signs the list again.
 * The list also carries the anchor's delegation of each node the body
 * honours: a new node is added beside the old, and retiring the old one takes
 * its delegation off, so every vouch it signed stops passing.
 *
 * Names never leave. A public answer carries the body, the claim and the
 * dates, and nothing from the roster: no label, no group, no roster id.
 */
import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { PrivateKey } from '@bsv/sdk';
import {
  BODY_VOUCH_OFFICE,
  BODY_VOUCH_PURPOSE,
  type BodyClaim,
  type BodyKind,
  PRESENTATION_MAX_SKEW,
  type RegistryEntry,
  STATUS_LIST_BITS,
  WireError,
  b64url,
  delegateSigner,
  didKeyOf,
  didWebPath,
  isoSeconds,
  issueStatusList,
  issueVouch,
  parseIsoSeconds,
  readDelegation,
  readRegistryEntry,
  signJwt,
  verifyJwtByKid,
} from '../../src';
import {
  type IssuedVouch,
  type OfficeState,
  type Pickup,
  type RosterKind,
  type RosterRow,
  type Store,
  didWebOrigin,
  hashToken,
  newToken,
} from './state';

/** How long a pickup code lasts, in seconds. */

/**
 * A random free place on the withdrawal list. Places handed out in order
 * would put one person's vouches for different apps side by side, and two
 * apps comparing places could tell they hold the same person; Bitstring
 * Status List 1.0 says to choose them at random for this reason.
 */
function unusedStatusIndex(vouches: readonly { statusIndex: number }[]): number {
  const taken = new Set(vouches.map((v) => v.statusIndex));
  for (;;) {
    const i = randomInt(0, STATUS_LIST_BITS);
    if (!taken.has(i)) return i;
  }
}

export const PICKUP_TTL = 7 * 86400;

/** How many subjects one pickup serves: one per app a family uses. */
export const PICKUP_MAX_SUBJECTS = 4;

/** The JWT type of a holder's proof of its key at pickup. */
export const PICKUP_PROOF_TYP = 'openid4vci-proof+jwt';

/** What a vouch never says, for the parent's screen. It has no field for any of them. */
export const WILL_NOT_SAY = ['name', 'date of birth', 'class or group', 'record number', 'address', 'photo'] as const;

/** The claim each kind of row is vouched. */
export const CLAIM_FOR: Readonly<Record<RosterKind, BodyClaim>> = { member: 'member', guardian: 'guardian_of_member' };

export class OfficeError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail?: string,
  ) {
    super(detail ? `${code}: ${detail}` : code);
  }
}

// ── the holder's proof ───────────────────────────────────────────────────────

export interface PickupProofInput {
  /** The holder's relationship key: the subject of the vouch it collects. */
  subjectSk: PrivateKey;
  /** The body's did:web. */
  body: string;
  /** The pickup code. */
  code: string;
  /** Unix seconds. */
  at: number;
}

/** The holder's proof that it holds the key the vouch will be about. */
export function pickupProof(p: PickupProofInput): string {
  return signJwt({ aud: p.body, nonce: p.code, iat: p.at }, p.subjectSk, PICKUP_PROOF_TYP);
}

/** The did:key that signed a proof for this body and code, now. */
function proofSubject(proof: unknown, did: string, code: string, now: number): string {
  const v = typeof proof === 'string' ? verifyJwtByKid(proof, PICKUP_PROOF_TYP) : null;
  if (v === null || !Number.isSafeInteger(v.payload.iat)) throw new OfficeError(400, 'bad_proof');
  if (v.payload.aud !== did) throw new OfficeError(400, 'wrong_audience');
  if (v.payload.nonce !== code) throw new OfficeError(400, 'wrong_nonce');
  if (Math.abs(now - v.payload.iat) > PRESENTATION_MAX_SKEW) throw new OfficeError(400, 'stale');
  return v.signer;
}

// ── shapes ───────────────────────────────────────────────────────────────────

export interface OfficeInfo {
  did: string;
  baseUrl: string;
  /** Where the DID document must be found for the did:web to resolve. */
  didDocument: string;
  anchor: string;
  /** The node that signs, compressed hex. */
  node: string;
  /** Every node the withdrawal list honours, the signing node first. */
  nodes: string[];
  steward: string;
  kind: BodyKind;
  claims: readonly BodyClaim[];
  periodEnds: readonly string[];
  statusList: string;
  entryValidUntil: string;
  pilotSteward: boolean;
}

/** A pickup as the registrar's desk sees it, ready for a QR code. */
export interface PickupSlip {
  id: string;
  label: string;
  claim: BodyClaim;
  url: string;
  expiresAt: string;
  validUntil: string;
}

export type VouchRefusal = 'unknown_row' | 'no_consent' | 'claim_not_allowed' | 'left' | 'no_member';

/** A pickup as the family's phone sees it: what the body will and will not say. */
export interface PickupView {
  body: string;
  kind: BodyKind;
  claim: BodyClaim;
  validUntil: string;
  expiresAt: string;
  redemptionsLeft: number;
  willNotSay: string[];
  registryEntry: string;
}

export interface NeedsItem {
  id: string;
  kind: RosterKind;
  label: string;
  group?: string;
}

/** The registrar's home list: what needs the school. */
export interface Needs {
  at: string;
  /** The period end a vouch made now would carry, or null if none is left. */
  periodEnd: string | null;
  counts: {
    members: number;
    guardians: number;
    consented: number;
    /** Rows with a live vouch. */
    vouched: number;
    /** Rows with a code out and no live vouch yet. */
    awaitingPickup: number;
    withdrawn: number;
    liveVouches: number;
  };
  /** Consent is in, and nothing is vouched or waiting. */
  consentNotVouched: NeedsItem[];
  /** Guardians not yet vouched whose child's other guardian is. */
  secondGuardians: (NeedsItem & { consent: boolean; pickupOpen: boolean })[];
  /** Rows going, with something still to withdraw. A guardian goes when all their children do. */
  leaving: (NeedsItem & { leavingOn: string })[];
  /** Rows whose every live vouch ends at the current period end. */
  lapsing: (NeedsItem & { lapsesAt: string })[];
  /** Consent withdrawn, and a vouch still live. */
  consentWithdrawn: NeedsItem[];
}

// ── helpers ──────────────────────────────────────────────────────────────────

const CODE = /^[A-Za-z0-9_-]{22}$/;
const ROW_ID = /^[A-Za-z0-9._-]{1,64}$/;
const ROW_FIELDS = new Set(['id', 'kind', 'label', 'group', 'guardianOf', 'leavingOn']);

const codeHash = (code: string): string => createHash('sha256').update(code, 'utf8').digest('hex');
const at = (iso: string): number => parseIsoSeconds(iso)!;
const dayStart = (t: number): number => t - (t % 86400);

const isDate = (s: unknown): s is string =>
  typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s)) && new Date(s).toISOString().startsWith(s);

const isLive = (v: IssuedVouch, now: number): boolean => v.withdrawnAt === undefined && at(v.validUntil) > now;
const isOpen = (p: Pickup, now: number): boolean =>
  p.cancelledAt === undefined && at(p.expiresAt) > now && p.redeemed.length < PICKUP_MAX_SUBJECTS;

/** A row's fields in a fixed order, without empty optionals. */
function tidy(r: RosterRow): RosterRow {
  return {
    id: r.id,
    kind: r.kind,
    label: r.label,
    ...(r.group !== undefined && { group: r.group }),
    ...(r.guardianOf !== undefined && { guardianOf: r.guardianOf }),
    consent: r.consent,
    ...(r.leavingOn !== undefined && { leavingOn: r.leavingOn }),
    ...(r.withdrawnAt !== undefined && { withdrawnAt: r.withdrawnAt }),
    ...(r.sponsorNote !== undefined && { sponsorNote: r.sponsorNote }),
  };
}

function idList(ids: unknown): string[] {
  if (!Array.isArray(ids) || !ids.every((x) => typeof x === 'string')) throw new OfficeError(400, 'bad_request', 'ids must be an array of roster ids');
  return [...new Set(ids as string[])];
}

/** The rows named, all of them or an error. */
function pickRows(s: OfficeState, ids: unknown): RosterRow[] {
  const list = idList(ids);
  const byId = new Map(s.roster.map((r) => [r.id, r]));
  const unknown = list.filter((id) => !byId.has(id));
  if (unknown.length > 0) throw new OfficeError(400, 'unknown_rows', unknown.join(', '));
  return list.map((id) => byId.get(id)!);
}

/** Cancel a row's pickups still in date. Returns how many. */
function cancelPickups(s: OfficeState, rowId: string, now: number): number {
  let n = 0;
  for (const p of s.pickups) {
    if (p.rosterId === rowId && p.cancelledAt === undefined && at(p.expiresAt) > now) {
      p.cancelledAt = isoSeconds(now);
      n++;
    }
  }
  return n;
}

// ── the office ───────────────────────────────────────────────────────────────

export interface OfficeOptions {
  /** Unix seconds. */
  now?: () => number;
}

export class Office {
  private readonly now: () => number;
  private parsed: { jwt: string; entry: RegistryEntry } | null = null;

  constructor(
    private readonly store: Store,
    o: OfficeOptions = {},
  ) {
    this.now = o.now ?? (() => Math.floor(Date.now() / 1000));
  }

  private read<T>(fn: (s: OfficeState, now: number) => T): T {
    return fn(this.store.load(), this.now());
  }

  /** Load, change, save. A throw saves nothing. */
  private write<T>(fn: (s: OfficeState, now: number) => T): T {
    const s = this.store.load();
    const out = fn(s, this.now());
    this.store.save(s);
    return out;
  }

  private entry(s: OfficeState): RegistryEntry {
    if (this.parsed?.jwt !== s.registryEntry) {
      const entry = readRegistryEntry(s.registryEntry);
      if (entry === null) throw new OfficeError(500, 'bad_state', 'the registry entry does not verify');
      this.parsed = { jwt: s.registryEntry, entry };
    }
    return this.parsed.entry;
  }

  private node(s: OfficeState): PrivateKey {
    return PrivateKey.fromString(s.nodeKey, 16);
  }

  /** The nodes the delegations name, compressed hex, in the state's order. */
  private honoured(s: OfficeState): string[] {
    return s.delegations.map((d) => {
      const info = readDelegation(d);
      if (info === null) throw new OfficeError(500, 'bad_state', 'a delegation does not verify');
      return info.node;
    });
  }

  /** Sign the withdrawal list again, from the vouches withdrawn and the delegations honoured. */
  private resign(s: OfficeState, now: number): void {
    const revoked = s.vouches.filter((v) => v.withdrawnAt !== undefined).map((v) => v.statusIndex);
    s.statusList = issueStatusList(this.node(s), {
      issuer: s.did,
      delegations: s.delegations,
      url: this.entry(s).statusList,
      revoked,
      validFrom: now,
    });
  }

  info(): OfficeInfo {
    return this.read((s) => {
      const e = this.entry(s);
      return {
        did: s.did,
        baseUrl: s.baseUrl,
        didDocument: `${didWebOrigin(s.did)}${didWebPath(s.did)}`,
        anchor: s.anchor,
        node: this.node(s).toPublicKey().toString(),
        nodes: this.honoured(s),
        steward: e.steward,
        kind: e.kind,
        claims: e.claims,
        periodEnds: e.periodEnds,
        statusList: e.statusList,
        entryValidUntil: e.validUntil,
        pilotSteward: s.pilotSteward,
      };
    });
  }

  // ── public ─────────────────────────────────────────────────────────────────

  /** The path the DID document is served at. */
  didDocumentPath(): string {
    return this.read((s) => didWebPath(s.did));
  }

  /**
   * A did:web DID document with the anchor as its one key, a secp256k1
   * Multikey, and the office as a service, where holders collect their vouches.
   */
  didDocument(): Record<string, unknown> {
    return this.read((s) => {
      const vm = `${s.did}#anchor`;
      return {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
        id: s.did,
        verificationMethod: [
          { id: vm, type: 'Multikey', controller: s.did, publicKeyMultibase: didKeyOf(s.anchor).slice('did:key:'.length) },
        ],
        // The anchor signs one kind of statement, the delegation of a node.
        assertionMethod: [vm],
        capabilityDelegation: [vm],
        service: [{ id: `${s.did}#vouch-office`, type: BODY_VOUCH_OFFICE, serviceEndpoint: s.baseUrl }],
      };
    });
  }

  /** Withdrawal list `n`, if it is the one the registry entry names. */
  statusList(n: number): string | null {
    return this.read((s) => (this.entry(s).statusList === `${s.baseUrl}/status/${n}` ? s.statusList : null));
  }

  private findPickup(s: OfficeState, code: string, now: number): Pickup {
    const h = CODE.test(code) ? codeHash(code) : null;
    const p = s.pickups.find((x) => x.codeHash === h);
    if (p === undefined) throw new OfficeError(404, 'unknown_pickup');
    if (p.cancelledAt !== undefined) throw new OfficeError(410, 'cancelled');
    if (at(p.expiresAt) <= now) throw new OfficeError(410, 'expired');
    return p;
  }

  /** What the body will and will not say. Nothing from the roster. */
  pickup(code: string): PickupView {
    return this.read((s, now) => {
      const p = this.findPickup(s, code, now);
      if (p.redeemed.length >= PICKUP_MAX_SUBJECTS) throw new OfficeError(410, 'used_up');
      return {
        body: s.did,
        kind: this.entry(s).kind,
        claim: p.claim,
        validUntil: p.validUntil,
        expiresAt: p.expiresAt,
        redemptionsLeft: PICKUP_MAX_SUBJECTS - p.redeemed.length,
        willNotSay: [...WILL_NOT_SAY],
        registryEntry: s.registryEntry,
      };
    });
  }

  /**
   * The vouch, about the key that signed the proof. A subject that collected
   * with this code before gets the same vouch again, signed by the current
   * node, and uses no place.
   */
  redeem(code: string, proof: unknown): { credential: string } {
    return this.write((s, now) => {
      const p = this.findPickup(s, code, now);
      const subject = proofSubject(proof, s.did, code, now);
      const entry = this.entry(s);
      const sign = (v: IssuedVouch): string => {
        try {
          return issueVouch({
            nodeSk: this.node(s),
            entry,
            subject: v.subject,
            claim: v.claim,
            statusIndex: v.statusIndex,
            validFrom: v.validFrom,
            validUntil: v.validUntil,
          });
        } catch (e) {
          if (e instanceof WireError) throw new OfficeError(409, e.code);
          throw e;
        }
      };
      const before = p.redeemed.find((r) => r.subject === subject);
      if (before !== undefined) return { credential: sign(s.vouches.find((v) => v.statusIndex === before.statusIndex)!) };
      if (p.redeemed.length >= PICKUP_MAX_SUBJECTS) throw new OfficeError(410, 'used_up');
      // One key, one person: a parent's key cannot collect the child's vouch.
      if (s.vouches.some((v) => v.subject === subject && v.rosterId !== p.rosterId)) {
        throw new OfficeError(409, 'subject_taken', 'this key already holds a vouch for someone else');
      }
      const row = s.roster.find((r) => r.id === p.rosterId);
      if (row === undefined || !row.consent || row.withdrawnAt !== undefined) throw new OfficeError(410, 'cancelled');
      if (s.nextStatusIndex >= STATUS_LIST_BITS) throw new OfficeError(507, 'status_list_full');
      const v: IssuedVouch = {
        statusIndex: unusedStatusIndex(s.vouches),
        rosterId: p.rosterId,
        claim: p.claim,
        subject,
        validFrom: p.validFrom,
        issuedAt: isoSeconds(now),
        validUntil: p.validUntil,
      };
      const credential = sign(v);
      s.nextStatusIndex++; // how many places are taken, for status_list_full
      s.vouches.push(v);
      p.redeemed.push({ subject, statusIndex: v.statusIndex });
      return { credential };
    });
  }

  // ── registrar ──────────────────────────────────────────────────────────────

  checkToken(token: string): boolean {
    const want = Buffer.from(this.read((s) => s.tokenHash), 'hex');
    const got = Buffer.from(hashToken(token), 'hex');
    return want.length === got.length && timingSafeEqual(want, got);
  }

  /** A new registrar token. The old one stops working. */
  rotateToken(): string {
    const token = newToken();
    this.write((s) => {
      s.tokenHash = hashToken(token);
    });
    return token;
  }

  /**
   * A new signing node. The anchor delegates it and it signs the list from
   * now on. The nodes before it stay on the list, so their vouches still
   * pass, until each is retired. The anchor key is used here and not kept.
   */
  rotateNode(anchorSk: PrivateKey): { node: string; nodes: string[] } {
    return this.write((s, now) => {
      if (anchorSk.toPublicKey().toString() !== s.anchor) {
        throw new OfficeError(400, 'wrong_anchor', 'that key is not the anchor the registry entry names');
      }
      const node = PrivateKey.fromRandom();
      const pub = node.toPublicKey().toString();
      s.nodeKey = node.toHex();
      s.delegations = [delegateSigner(anchorSk, pub, BODY_VOUCH_PURPOSE), ...s.delegations];
      this.resign(s, now);
      return { node: pub, nodes: this.honoured(s) };
    });
  }

  /**
   * Stop honouring an older node: take its delegation off the list and sign
   * the list again. Every vouch that node signed fails at the gate, as
   * node_not_delegated, once the app downloads the list again.
   */
  retireNode(node: string): { retired: string; nodes: string[] } {
    return this.write((s, now) => {
      if (node === this.node(s).toPublicKey().toString()) {
        throw new OfficeError(409, 'current_node', 'this node signs the list; make a new node first');
      }
      const i = this.honoured(s).indexOf(node);
      if (i < 0) throw new OfficeError(404, 'unknown_node', `${node} is not on the list`);
      s.delegations.splice(i, 1);
      this.resign(s, now);
      return { retired: node, nodes: this.honoured(s) };
    });
  }

  rows(): RosterRow[] {
    return this.read((s) => s.roster.map(tidy));
  }

  /**
   * Add or update rows, all or none. A row without an id is added with a
   * random one. On an update, fields given replace, null clears, and the rest
   * stay. A row's kind is fixed once set. Consent goes through {@link setConsent}.
   */
  upsertRows(input: unknown): RosterRow[] {
    if (!Array.isArray(input)) throw new OfficeError(400, 'bad_request', 'rows must be an array');
    return this.write((s) => {
      const byId = new Map(s.roster.map((r) => [r.id, r]));
      const touched: string[] = [];
      input.forEach((raw: any, i) => {
        const bad = (why: string) => new OfficeError(400, 'bad_row', `rows[${i}]: ${why}`);
        if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw bad('not an object');
        for (const k of Object.keys(raw)) if (!ROW_FIELDS.has(k)) throw bad(`no field ${k}`);
        let id = raw.id;
        if (id === undefined) do id = b64url(new Uint8Array(randomBytes(9))); while (byId.has(id));
        if (typeof id !== 'string' || !ROW_ID.test(id)) throw bad('id is 1 to 64 letters, digits, dots, dashes or underscores');
        const old = byId.get(id);
        if (old === undefined && (raw.kind === undefined || raw.label === undefined)) throw bad('a new row needs a kind and a label');
        if (raw.kind !== undefined && raw.kind !== 'member' && raw.kind !== 'guardian') throw bad('kind is member or guardian');
        if (old !== undefined && raw.kind !== undefined && raw.kind !== old.kind) throw bad('a row\'s kind is fixed once set');
        const row: RosterRow = old === undefined ? { id, kind: raw.kind, label: '', consent: false } : { ...old };
        if (raw.label !== undefined) {
          if (typeof raw.label !== 'string' || raw.label.trim() === '' || raw.label.length > 200) throw bad('label is 1 to 200 characters');
          row.label = raw.label;
        }
        const optional = <K extends 'group' | 'guardianOf' | 'leavingOn'>(k: K, ok: (x: unknown) => boolean, why: string) => {
          if (raw[k] === null) delete row[k];
          else if (raw[k] !== undefined) {
            if (!ok(raw[k])) throw bad(why);
            row[k] = raw[k];
          }
        };
        optional('group', (g) => typeof g === 'string' && g.trim() !== '' && g.length <= 100, 'group is 1 to 100 characters, or null');
        optional('guardianOf', (g) => Array.isArray(g) && g.every((x) => typeof x === 'string'), 'guardianOf is a list of roster ids, or null');
        optional('leavingOn', isDate, 'leavingOn is a date, YYYY-MM-DD, or null');
        if (row.guardianOf !== undefined) row.guardianOf = [...new Set(row.guardianOf)];
        byId.set(id, row);
        touched.push(id);
      });
      // Links are checked once the whole batch is in, so a family can arrive together.
      for (const [i, id] of touched.entries()) {
        const row = byId.get(id)!;
        if (row.guardianOf === undefined) continue;
        if (row.kind !== 'guardian') throw new OfficeError(400, 'bad_row', `rows[${i}]: only a guardian has guardianOf`);
        const notMember = row.guardianOf.filter((m) => byId.get(m)?.kind !== 'member');
        if (notMember.length > 0) throw new OfficeError(400, 'bad_row', `rows[${i}]: guardianOf names no member ${notMember.join(', ')}`);
      }
      s.roster = [...byId.values()].map(tidy);
      return [...new Set(touched)].map((id) => tidy(byId.get(id)!));
    });
  }

  /** Record consent, or its withdrawal. Withdrawing it cancels any code still out. */
  setConsent(ids: unknown, consent: unknown): { updated: string[]; cancelledPickups: number } {
    if (typeof consent !== 'boolean') throw new OfficeError(400, 'bad_request', 'consent is true or false');
    return this.write((s, now) => {
      const rows = pickRows(s, ids);
      let cancelledPickups = 0;
      for (const r of rows) {
        r.consent = consent;
        if (!consent) cancelledPickups += cancelPickups(s, r.id, now);
      }
      return { updated: rows.map((r) => r.id), cancelledPickups };
    });
  }

  /**
   * A pickup for each row that may be vouched, and a reason for each that may
   * not. A new pickup replaces any code the row still has out. The vouch it
   * gives ends at `periodEnd`, by default the next of the entry's period ends,
   * and the code lasts seven days or to that end, whichever is sooner.
   */
  vouch(ids: unknown, periodEnd?: unknown): { pickups: PickupSlip[]; refused: { id: string; reason: VouchRefusal }[] } {
    return this.write((s, now) => {
      const entry = this.entry(s);
      const ahead = entry.periodEnds.filter((p) => at(p) > now).sort();
      let validUntil: string;
      if (periodEnd !== undefined) {
        if (typeof periodEnd !== 'string' || !ahead.includes(periodEnd)) {
          throw new OfficeError(400, 'not_a_period_end', `one of ${ahead.join(', ') || 'none'}`);
        }
        validUntil = periodEnd;
      } else {
        if (ahead.length === 0) throw new OfficeError(409, 'no_period_end', 'every period end in the registry entry has passed');
        validUntil = ahead[0]!;
      }
      const today = isoSeconds(now).slice(0, 10);
      const byId = new Map(s.roster.map((r) => [r.id, r]));
      const pickups: PickupSlip[] = [];
      const refused: { id: string; reason: VouchRefusal }[] = [];
      for (const id of idList(ids)) {
        const row = byId.get(id);
        const reason: VouchRefusal | null =
          row === undefined
            ? 'unknown_row'
            : !row.consent
              ? 'no_consent'
              : !entry.claims.includes(CLAIM_FOR[row.kind])
                ? 'claim_not_allowed'
                : row.leavingOn !== undefined && row.leavingOn <= today
                  ? 'left'
                  : row.kind === 'guardian' && !(row.guardianOf ?? []).some((m) => byId.get(m)?.kind === 'member')
                    ? 'no_member'
                    : null;
        if (reason !== null) {
          refused.push({ id, reason });
          continue;
        }
        const r = row!;
        cancelPickups(s, id, now);
        const code = b64url(new Uint8Array(randomBytes(16)));
        const expiresAt = isoSeconds(Math.min(now + PICKUP_TTL, at(validUntil)));
        const claim = CLAIM_FOR[r.kind];
        s.pickups.push({
          codeHash: codeHash(code),
          rosterId: id,
          claim,
          createdAt: isoSeconds(now),
          expiresAt,
          validFrom: isoSeconds(dayStart(now)),
          validUntil,
          redeemed: [],
        });
        // Vouching a withdrawn row again is the registrar's decision to take it back.
        delete r.withdrawnAt;
        delete r.sponsorNote;
        pickups.push({ id, label: r.label, claim, url: `${s.baseUrl}/pickup/${code}`, expiresAt, validUntil });
      }
      return { pickups, refused };
    });
  }

  /**
   * Withdraw every vouch issued for these rows, cancel their codes, and sign
   * the withdrawal list again. `sponsorNote` records that a guardian may
   * sponsor the child onward; it stays on the roster.
   */
  withdraw(ids: unknown, sponsorNote?: unknown): { withdrawn: { id: string; statusIndexes: number[] }[]; cancelledPickups: number } {
    if (sponsorNote !== undefined && typeof sponsorNote !== 'boolean') throw new OfficeError(400, 'bad_request', 'sponsorNote is true or false');
    return this.write((s, now) => {
      const rows = pickRows(s, ids);
      const stamp = isoSeconds(now);
      let cancelledPickups = 0;
      let changed = false;
      const withdrawn = rows.map((r) => {
        r.withdrawnAt = stamp;
        r.sponsorNote = sponsorNote === true;
        cancelledPickups += cancelPickups(s, r.id, now);
        const statusIndexes: number[] = [];
        for (const v of s.vouches) {
          if (v.rosterId === r.id && v.withdrawnAt === undefined) {
            v.withdrawnAt = stamp;
            statusIndexes.push(v.statusIndex);
            changed = true;
          }
        }
        return { id: r.id, statusIndexes };
      });
      if (changed) this.resign(s, now);
      return { withdrawn, cancelledPickups };
    });
  }

  /** The registrar's home list. Labels are allowed here: it is the registrar's own view. */
  needs(): Needs {
    return this.read((s, now) => {
      const entry = this.entry(s);
      const today = isoSeconds(now).slice(0, 10);
      const periodEnd = entry.periodEnds.filter((p) => at(p) > now).sort()[0] ?? null;
      const byId = new Map(s.roster.map((r) => [r.id, r]));
      const live = new Map<string, IssuedVouch[]>();
      for (const v of s.vouches) if (isLive(v, now)) live.set(v.rosterId, [...(live.get(v.rosterId) ?? []), v]);
      const openFor = new Map<string, Pickup[]>();
      for (const p of s.pickups) if (isOpen(p, now)) openFor.set(p.rosterId, [...(openFor.get(p.rosterId) ?? []), p]);
      const hasLive = (id: string) => live.has(id);
      const hasOpen = (id: string) => openFor.has(id);
      const current = s.roster.filter((r) => r.withdrawnAt === undefined);
      const item = (r: RosterRow): NeedsItem => ({ id: r.id, kind: r.kind, label: r.label, ...(r.group !== undefined && { group: r.group }) });

      // A guardian is going when every child of theirs is going or withdrawn.
      const goingOn = (r: RosterRow): string | null => {
        if (r.leavingOn !== undefined) return r.leavingOn;
        const kids = (r.guardianOf ?? []).map((id) => byId.get(id)).filter((k): k is RosterRow => k !== undefined);
        if (r.kind !== 'guardian' || kids.length === 0) return null;
        if (!kids.every((k) => k.withdrawnAt !== undefined || k.leavingOn !== undefined)) return null;
        return kids.map((k) => k.leavingOn).filter((d): d is string => d !== undefined).sort().at(-1) ?? today;
      };
      const going = new Map(current.map((r) => [r.id, goingOn(r)]));

      const leaving = current
        .filter((r) => going.get(r.id) !== null && (hasLive(r.id) || hasOpen(r.id)))
        .map((r) => ({ ...item(r), leavingOn: going.get(r.id)! }))
        .sort((a, b) => a.leavingOn.localeCompare(b.leavingOn));

      const fellowVouched = (g: RosterRow) =>
        (g.guardianOf ?? []).some((m) =>
          current.some((o) => o.id !== g.id && o.kind === 'guardian' && (o.guardianOf ?? []).includes(m) && hasLive(o.id)),
        );
      const secondGuardians = current
        .filter((r) => r.kind === 'guardian' && going.get(r.id) === null && !hasLive(r.id) && fellowVouched(r))
        .map((r) => ({ ...item(r), consent: r.consent, pickupOpen: hasOpen(r.id) }));
      const second = new Set(secondGuardians.map((g) => g.id));

      const consentNotVouched = current
        .filter((r) => r.consent && going.get(r.id) === null && !hasLive(r.id) && !hasOpen(r.id) && !second.has(r.id))
        .map(item);

      const lapsing =
        periodEnd === null
          ? []
          : current
              .filter((r) => {
                if (going.get(r.id) !== null) return false;
                const ends = [...(live.get(r.id) ?? []), ...(openFor.get(r.id) ?? [])].map((x) => x.validUntil);
                return (live.get(r.id) ?? []).some((v) => v.validUntil === periodEnd) && ends.every((e) => e <= periodEnd);
              })
              .map((r) => ({ ...item(r), lapsesAt: periodEnd }));

      const consentWithdrawn = current.filter((r) => !r.consent && hasLive(r.id)).map(item);

      return {
        at: isoSeconds(now),
        periodEnd,
        counts: {
          members: s.roster.filter((r) => r.kind === 'member').length,
          guardians: s.roster.filter((r) => r.kind === 'guardian').length,
          consented: s.roster.filter((r) => r.consent).length,
          vouched: current.filter((r) => hasLive(r.id)).length,
          awaitingPickup: current.filter((r) => hasOpen(r.id) && !hasLive(r.id)).length,
          withdrawn: s.roster.filter((r) => r.withdrawnAt !== undefined).length,
          liveVouches: [...live.values()].reduce((n, l) => n + l.length, 0),
        },
        consentNotVouched,
        secondGuardians,
        leaving,
        lapsing,
        consentWithdrawn,
      };
    });
  }
}
