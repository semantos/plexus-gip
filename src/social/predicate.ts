/**
 * Predicate attestations — the L0 rung of the ZK predicate-proof ladder.
 *
 * The design note (`docs/design/GIP-V2-PREDICATE-PROOFS.md`) lays out three
 * rungs for proving a statement about a lineage without revealing it. This is
 * the first and cheapest: a certifier that can already see the tree —
 * FamilySearch — SIGNS the computed predicate, so the holder presents a signed
 * *property* ("≥3 documented generations") and the tree stays hidden. No ZK
 * circuit, no new crypto: it is `recordAttestation`'s sibling, over a canonical
 * predicate string instead of a record hash.
 *
 * What it is and is not:
 *   - It reveals the PREDICATE and that a certifier computed it — nothing of the
 *     names, dates, or edges behind it.
 *   - The buyer trusts the certifier's *computation*, not mathematics. For a
 *     data market that already prices FamilySearch's authority, that is usually
 *     the right trade; when it is not, that is what rungs L1/L2 are for.
 *   - `vouchTier` (`./familysearch`) is how a verifier decides the certifier is
 *     trusted; this module produces and checks the attestation, and leaves the
 *     trust decision there, local to the verifier.
 *
 * ## The canonical predicate string is the interoperable unit
 *
 * A market works only if the buyer's asked predicate and the certifier's signed
 * predicate are the SAME BYTES. So a predicate has one canonical encoding —
 * `<metric>[:<qualifier>]<op><value>`, lowercase kebab tokens — and both sides
 * compare it exactly. The grammar is deliberately small: this layer transports a
 * predicate, it does not evaluate one (the certifier did that off-stage).
 */

import type { PrivateKey } from '@bsv/sdk';
import {
  ASSOCIATION_KINDS,
  type Association,
  signAssociation,
  verifyVouch,
} from '../associations';

/** The association kind a predicate attestation carries. */
export const PREDICATE_KIND: string = ASSOCIATION_KINDS.predicate;

export type PredicateOp = 'gte' | 'lte' | 'eq' | 'ne';

const OP_SYMBOL: Readonly<Record<PredicateOp, string>> = {
  gte: '>=',
  lte: '<=',
  eq: '==',
  ne: '!=',
};
const SYMBOL_OP: Readonly<Record<string, PredicateOp>> = {
  '>=': 'gte',
  '<=': 'lte',
  '==': 'eq',
  '!=': 'ne',
};

export interface Predicate {
  /** What is measured, e.g. `gen-depth`, `ancestry-region`, `born-before`. */
  readonly metric: string;
  /** Optional narrowing, e.g. `scotland-highland`. */
  readonly qualifier?: string;
  readonly op: PredicateOp;
  /** The threshold — a number or a token, e.g. `3`, `1970`, `true`. */
  readonly value: string;
}

/** Lowercase kebab tokens only, so the canonical string is unambiguous. */
const TOKEN = /^[a-z0-9-]+$/;

/**
 * Canonical predicate string. Throws on any non-conforming part — a market
 * predicate that is not byte-canonical is a predicate two parties can disagree
 * about, which defeats the point.
 */
export function encodePredicate(p: Predicate): string {
  if (!TOKEN.test(p.metric)) throw new Error(`metric must be a lowercase kebab token: ${p.metric}`);
  if (p.qualifier !== undefined && !TOKEN.test(p.qualifier)) {
    throw new Error(`qualifier must be a lowercase kebab token: ${p.qualifier}`);
  }
  if (!TOKEN.test(p.value)) throw new Error(`value must be a lowercase kebab token: ${p.value}`);
  if (OP_SYMBOL[p.op] === undefined) throw new Error(`unknown op: ${p.op}`);
  return `${p.metric}${p.qualifier !== undefined ? `:${p.qualifier}` : ''}${OP_SYMBOL[p.op]}${p.value}`;
}

const PREDICATE_RE = /^([a-z0-9-]+)(?::([a-z0-9-]+))?(>=|<=|==|!=)([a-z0-9-]+)$/;

/** Parse and validate a canonical predicate string. Null on any malformation. */
export function parsePredicate(s: string): Predicate | null {
  const m = s.match(PREDICATE_RE);
  if (m === null) return null;
  const op = SYMBOL_OP[m[3]!];
  if (op === undefined) return null;
  return m[2] === undefined
    ? { metric: m[1]!, op, value: m[4]! }
    : { metric: m[1]!, qualifier: m[2], op, value: m[4]! };
}

/** Normalise a predicate given as either a struct or an already-canonical string. */
function canonical(predicate: Predicate | string): string {
  const s = typeof predicate === 'string' ? predicate : encodePredicate(predicate);
  if (parsePredicate(s) === null) throw new Error(`malformed predicate: ${s}`);
  return s;
}

/**
 * A certifier's attestation that a predicate holds over `subjectPage0`'s lineage.
 *
 * Bound to the subject key by `signAssociation`, so it is not a bearer token.
 * `predicate` may be a struct or an already-canonical string; either way the
 * stored `display` is the canonical form, so a verifier can compare it exactly
 * against the predicate a buyer asked for.
 */
export function predicateAttestation(
  voucherSk: PrivateKey,
  subjectPage0: string,
  predicate: Predicate | string,
): Association {
  const display = canonical(predicate);
  const kind = PREDICATE_KIND;
  return {
    kind,
    display,
    vouchedBy: voucherSk.toPublicKey().toString(),
    signature: signAssociation(voucherSk, subjectPage0, kind, display),
  };
}

/** The parsed predicate if `a` is a well-formed predicate attestation, else null. */
export function readPredicateAttestation(a: Pick<Association, 'kind' | 'display'>): Predicate | null {
  if (a.kind !== PREDICATE_KIND) return null;
  return parsePredicate(a.display);
}

/**
 * Does this attestation assert `expected` about `subjectPage0`, signed by its
 * voucher? Checks the predicate string AND the signature. It does NOT decide
 * whether the voucher is a *trusted* certifier — pass the association to
 * `vouchTier` for that; keeping the two separate is the same discipline as every
 * other attestation here.
 */
export function verifyPredicateAttestation(
  a: Association,
  subjectPage0: string,
  expected: Predicate | string,
): boolean {
  if (a.kind !== PREDICATE_KIND) return false;
  if (a.display !== canonical(expected)) return false;
  return verifyVouch(a, subjectPage0);
}
