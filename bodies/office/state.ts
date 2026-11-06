/**
 * The office's state: one JSON file, mode 0600, written whole to a temporary
 * file and renamed into place, so a crash leaves the old file or the new one.
 *
 * It holds the body's node key, so it is a secret. It holds the roster, the
 * only place the office keeps a name. The anchor's private key is never in it:
 * the anchor signs a node's delegation, at init and at each new node, and goes
 * back in the safe.
 */
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, closeSync, fsyncSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { PrivateKey } from '@bsv/sdk';
import {
  type Association,
  BODY_VOUCH_PURPOSE,
  type BodyClaim,
  type BodyKind,
  type Instant,
  WireError,
  b64url,
  delegateSigner,
  didWebHost,
  didWebPath,
  isoSeconds,
  issueRegistryEntry,
  issueStatusList,
  readRegistryEntry,
} from '../../src';

/** 2: the delegations travel on the withdrawal list, not in each vouch. */
export const OFFICE_STATE_VERSION = 2;

export type RosterKind = 'member' | 'guardian';

/**
 * Who did something at the desk. Behind the brain (`--desk-auth brain`), the
 * caller the brain named: its standing there and, for a member, the identity
 * its wallet login names (a page-0 cert id). With the development token,
 * only that the token was used.
 */
export interface DeskActor {
  standing: 'operator' | 'admin' | 'member' | 'dev-token';
  /** 32 hex, when the brain named one. */
  certId?: string;
}

/** A member the operator lets use the desk, by the identity the brain names for them. */
export interface Registrar {
  /** The member's page-0 cert id, 32 lowercase hex. */
  certId: string;
  /** The operator's name for them, for `registrars list`. Never sent anywhere. */
  label?: string;
  addedAt: string;
}

/** One desk action, as the office's own record of who did what. Row ids only: no name. */
export interface DeskEntry {
  at: string;
  by: DeskActor;
  action: 'roster' | 'consent' | 'vouch' | 'withdraw';
  ids: string[];
  /** For consent: given or taken away. */
  consent?: boolean;
}

/** One person on the body's own roster. */
export interface RosterRow {
  id: string;
  kind: RosterKind;
  /** The registrar's name for the person. It never leaves the office. */
  label: string;
  group?: string;
  /** For a guardian: the members they are guardian of. */
  guardianOf?: string[];
  consent: boolean;
  /** YYYY-MM-DD. */
  leavingOn?: string;
  /** When the registrar withdrew the row's vouches. */
  withdrawnAt?: string;
  /** The registrar's note at withdrawal: a guardian may sponsor the child onward. */
  sponsorNote?: boolean;
  /** Who withdrew the row's vouches. */
  withdrawnBy?: DeskActor;
}

/** A vouch the node signed, with enough to sign it again: byte for byte while the node is the same. */
export interface IssuedVouch {
  statusIndex: number;
  rosterId: string;
  claim: BodyClaim;
  /** The holder's did:key for one relationship. */
  subject: string;
  validFrom: string;
  issuedAt: string;
  validUntil: string;
  withdrawnAt?: string;
}

/** A one-time code the registrar hands a family. Only its hash is kept. */
export interface Pickup {
  codeHash: string;
  rosterId: string;
  claim: BodyClaim;
  createdAt: string;
  expiresAt: string;
  /** The vouch's validFrom: the start of the UTC day the registrar vouched. */
  validFrom: string;
  /** The vouch's validUntil: one of the registry entry's period ends. */
  validUntil: string;
  /** Each subject that collected a vouch with this code, and its status index. */
  redeemed: { subject: string; statusIndex: number }[];
  /** Who vouched the row. */
  vouchedBy?: DeskActor;
  cancelledAt?: string;
  /**
   * When the row was withdrawn. A pickup is also the registrar's word that
   * the row is vouched for its period, which renews the row's holders at
   * collect (a later period); a withdrawal ends that, and the row needs
   * vouching again.
   */
  withdrawnAt?: string;
}

export interface OfficeState {
  version: typeof OFFICE_STATE_VERSION;
  /** The body's did:web. */
  did: string;
  /** Where the office is reached, an origin such as https://office.example.org. */
  baseUrl: string;
  /** The anchor's public key, compressed hex. */
  anchor: string;
  /** The signing node's private key, hex. An older node's key is not kept. */
  nodeKey: string;
  /**
   * The anchor's delegations the body honours, for body.vouch: the current
   * node's first, then any older node's whose vouches are still to pass. The
   * withdrawal list carries them all, and is signed again whenever they change.
   */
  delegations: Association[];
  /** The steward-signed registry entry JWT. */
  registryEntry: string;
  /** True when the entry was signed here with a local steward key: a pilot only. */
  pilotSteward: boolean;
  /** The current withdrawal list JWT. */
  statusList: string;
  /** sha256 of the development token (`--desk-auth dev-token`), hex. */
  tokenHash: string;
  /** The members who may use the desk behind the brain, besides the operator. */
  registrars: Registrar[];
  /** Every desk action, oldest first: who did it, to which rows. */
  deskLog: DeskEntry[];
  roster: RosterRow[];
  vouches: IssuedVouch[];
  /** How many places on the withdrawal list are taken. Places are chosen at random, never in order. */
  nextStatusIndex: number;
  pickups: Pickup[];
}

// ── the file ─────────────────────────────────────────────────────────────────

export interface Store {
  load(): OfficeState;
  save(state: OfficeState): void;
}

/** Write a file whole, mode 0600, by a rename from a temporary file beside it. */
export function writeAtomic(path: string, text: string): void {
  const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
  try {
    const fd = openSync(tmp, 'wx', 0o600);
    try {
      writeFileSync(fd, text);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    chmodSync(tmp, 0o600);
    renameSync(tmp, path);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
}

function parseState(text: string): OfficeState {
  const s = JSON.parse(text);
  if (s?.version !== OFFICE_STATE_VERSION) throw new WireError('bad_state', `not an office state file, version ${OFFICE_STATE_VERSION}`);
  for (const k of ['roster', 'vouches', 'pickups', 'delegations']) if (!Array.isArray(s[k])) throw new WireError('bad_state', `${k} is missing`);
  if (s.delegations.length === 0) throw new WireError('bad_state', 'no delegation for the current node');
  // A file from before the registrar list and the desk's record has neither yet.
  s.registrars ??= [];
  s.deskLog ??= [];
  for (const k of ['registrars', 'deskLog']) if (!Array.isArray(s[k])) throw new WireError('bad_state', `${k} is not a list`);
  return s;
}

/** The state in one file. Every load reads it afresh, so `token` from the CLI takes effect at once. */
export function fileStore(path: string): Store {
  return {
    load: () => parseState(readFileSync(path, 'utf8')),
    save: (s) => writeAtomic(path, `${JSON.stringify(s, null, 2)}\n`),
  };
}

// ── tokens ───────────────────────────────────────────────────────────────────

export const hashToken = (token: string): string => createHash('sha256').update(token, 'utf8').digest('hex');

/** A development token: 256 random bits, base64url. */
export const newToken = (): string => b64url(new Uint8Array(randomBytes(32)));

// ── did:web ──────────────────────────────────────────────────────────────────

/** The https origin a did:web names. */
export const didWebOrigin = (did: string): string => `https://${didWebHost(did)}`;

function originOf(url: string): string {
  const u = URL.parse(url);
  if (u === null || (u.protocol !== 'https:' && u.protocol !== 'http:') || u.pathname !== '/' || u.search !== '' || u.hash !== '') {
    throw new WireError('bad_url', `the office URL must be an origin such as https://office.example.org, not ${url}`);
  }
  return u.origin;
}

// ── init ─────────────────────────────────────────────────────────────────────

interface InitBase {
  /** The body's did:web. */
  did: string;
  /** Where the office is reached. Defaults to the did:web's host. */
  baseUrl?: string;
  /** The body's anchor. It signs the node's delegation and nothing else. */
  anchorSk: PrivateKey;
  /** Unix seconds. */
  now: number;
}

/** A registry entry a steward elsewhere signed. */
export interface InitWithEntry extends InitBase {
  entry: string;
}

/** For a pilot: an entry signed here with a local steward key. */
export interface InitWithSteward extends InitBase {
  stewardSk: PrivateKey;
  kind: BodyKind;
  claims: readonly BodyClaim[];
  periodEnds: readonly Instant[];
  /** When the entry lapses. Defaults to the last period end. */
  validUntil?: Instant;
}

export type InitOptions = InitWithEntry | InitWithSteward;

/**
 * A new office: a fresh node key, the anchor's delegation of it, the registry
 * entry, an empty withdrawal list, no registrars, and a development token
 * (`--desk-auth dev-token`). The token is returned once and only its hash is
 * kept.
 */
export function initState(o: InitOptions): { state: OfficeState; token: string } {
  const baseUrl = originOf(o.baseUrl ?? didWebOrigin(o.did));
  didWebPath(o.did);
  const anchor = o.anchorSk.toPublicKey().toString();
  let registryEntry: string;
  if ('entry' in o) {
    registryEntry = o.entry.trim();
  } else {
    const periodEnds = o.periodEnds.map((p) => (typeof p === 'number' ? isoSeconds(p) : p)).sort();
    registryEntry = issueRegistryEntry(o.stewardSk, {
      did: o.did,
      anchor,
      kind: o.kind,
      claims: o.claims,
      periodEnds,
      statusList: `${baseUrl}/status/1`,
      validFrom: o.now,
      validUntil: o.validUntil ?? periodEnds.at(-1) ?? o.now,
    });
  }
  const entry = readRegistryEntry(registryEntry);
  if (entry === null) throw new WireError('bad_entry', 'the registry entry does not verify, or the body signed it itself');
  if (entry.did !== o.did) throw new WireError('bad_entry', `the entry is for ${entry.did}, not this did ${o.did}`);
  if (entry.anchor !== anchor) throw new WireError('bad_entry', 'the entry names another anchor');
  const list = URL.parse(entry.statusList);
  if (list?.origin !== baseUrl || !/^\/status\/[1-9][0-9]{0,8}$/.test(list.pathname) || list.search !== '') {
    throw new WireError('bad_entry', `the entry's withdrawal list ${entry.statusList} is not ${baseUrl}/status/<n>`);
  }
  if (!entry.claims.includes('member') && !entry.claims.includes('guardian_of_member')) {
    throw new WireError('bad_entry', 'the office vouches member and guardian_of_member, and the entry lists neither');
  }
  const node = PrivateKey.fromRandom();
  const delegations = [delegateSigner(o.anchorSk, node.toPublicKey().toString(), BODY_VOUCH_PURPOSE)];
  const token = newToken();
  const state: OfficeState = {
    version: OFFICE_STATE_VERSION,
    did: o.did,
    baseUrl,
    anchor,
    nodeKey: node.toHex(),
    delegations,
    registryEntry,
    pilotSteward: !('entry' in o),
    statusList: issueStatusList(node, { issuer: o.did, delegations, url: entry.statusList, revoked: [], validFrom: o.now }),
    tokenHash: hashToken(token),
    registrars: [],
    deskLog: [],
    roster: [],
    vouches: [],
    nextStatusIndex: 0,
    pickups: [],
  };
  return { state, token };
}
