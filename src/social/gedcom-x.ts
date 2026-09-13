/**
 * GEDCOM X JSON → kinship edges — the modern-format sibling of `./gedcom` (which
 * reads legacy GEDCOM 5.5.1).
 *
 * GEDCOM X is FamilySearch's own model, and the Family Tree API serves it, so
 * this is the mapper the FS integration reads through (`docs/design/
 * GIP-V2-FS-INTEGRATION-SEAM.md` §3). It is the inverse of `record.ts`'s
 * `toGedcomX`: pull a target person's names, facts and relationships out of a
 * GEDCOM X document into a `RecordModel`, resolving relationship references to
 * page-0 keys through a caller-supplied map — with everyone not yet enrolled
 * returned as `unresolved`, never fabricated, exactly as the 5.5.1 importer does.
 *
 * Pure format mapping — no network, no FS access needed to build or test it.
 */

import { PublicKey } from '@bsv/sdk';
import { type KinRelation, KIN_RELATIONS } from './kinship';
import type { GedcomImportResult, ProvisionalRelation } from './gedcom';
import type { RecordFact, RecordName, RecordRelation } from './record';

// ── the GEDCOM X JSON subset we read ────────────────────────────────────────
export interface GedcomXNamePart { readonly type?: string; readonly value?: string }
export interface GedcomXNameForm { readonly fullText?: string; readonly parts?: readonly GedcomXNamePart[] }
export interface GedcomXName { readonly nameForms?: readonly GedcomXNameForm[] }
export interface GedcomXValue { readonly original?: string }
export interface GedcomXFact { readonly type?: string; readonly date?: GedcomXValue; readonly place?: GedcomXValue }
export interface GedcomXPerson {
  readonly id?: string;
  readonly names?: readonly GedcomXName[];
  readonly facts?: readonly GedcomXFact[];
}
export interface GedcomXResourceRef { readonly resource?: string; readonly resourceId?: string }
export interface GedcomXRelationship {
  readonly type?: string;
  readonly person1?: GedcomXResourceRef;
  readonly person2?: GedcomXResourceRef;
}
export interface GedcomXDocument {
  readonly persons?: readonly GedcomXPerson[];
  readonly relationships?: readonly GedcomXRelationship[];
}

const GEDCOMX = 'http://gedcomx.org/';
const PARENTCHILD = `${GEDCOMX}ParentChild`;
const COUPLE = `${GEDCOMX}Couple`;
const SIBLING = 'x-semantos/Sibling'; // what our own toGedcomX emits; FS uses shared-parent derivation
const GIVEN = `${GEDCOMX}Given`;
const SURNAME = `${GEDCOMX}Surname`;

/** A local `#id` fragment, an explicit `resourceId`, or a bare URI → the person id. */
function refId(ref?: GedcomXResourceRef): string | null {
  if (ref === undefined) return null;
  if (typeof ref.resourceId === 'string' && ref.resourceId !== '') return ref.resourceId;
  const r = ref.resource;
  if (typeof r !== 'string' || r === '') return null;
  return r.startsWith('#') ? r.slice(1) : r;
}

/** GEDCOM X fact URI → our short type: `http://gedcomx.org/Birth` → `birth`. */
function factType(uri?: string): string | null {
  if (typeof uri !== 'string' || uri === '') return null;
  const seg = uri.startsWith(GEDCOMX) ? uri.slice(GEDCOMX.length) : (uri.split('/').pop() ?? uri);
  return seg.toLowerCase() || null;
}

function namesOf(person: GedcomXPerson): RecordName[] {
  const out: RecordName[] = [];
  for (const nm of person.names ?? []) {
    for (const form of nm.nameForms ?? []) {
      let given: string | undefined;
      let surname: string | undefined;
      for (const part of form.parts ?? []) {
        if (part.type === GIVEN && typeof part.value === 'string') given = part.value;
        else if (part.type === SURNAME && typeof part.value === 'string') surname = part.value;
      }
      const full = typeof form.fullText === 'string' ? form.fullText : undefined;
      if (given !== undefined || surname !== undefined || full !== undefined) {
        out.push({ ...(given !== undefined ? { given } : {}), ...(surname !== undefined ? { surname } : {}), ...(full !== undefined ? { full } : {}) });
      }
    }
  }
  return out;
}

function factsOf(person: GedcomXPerson): RecordFact[] {
  const out: RecordFact[] = [];
  for (const f of person.facts ?? []) {
    const type = factType(f.type);
    if (type === null) continue;
    const date = typeof f.date?.original === 'string' ? f.date.original : undefined;
    const place = typeof f.place?.original === 'string' ? f.place.original : undefined;
    out.push({ type, ...(date !== undefined ? { date } : {}), ...(place !== undefined ? { place } : {}) });
  }
  return out;
}

/**
 * Derive a target person's atomic relations from the relationship graph.
 *
 * ParentChild(p1=parent, p2=child) gives `parent`/`child`; Couple gives `spouse`.
 * Siblings have no native GEDCOM X type, so they are derived as the other
 * children of the target's parents (and an explicit `x-semantos/Sibling`, which
 * is what our own `toGedcomX` emits, is also read directly).
 */
export function relationsForPerson(doc: GedcomXDocument, targetId: string): ProvisionalRelation[] {
  const rels: ProvisionalRelation[] = [];
  const add = (relation: KinRelation, cx: string | null): void => {
    if (cx !== null && cx !== targetId) rels.push({ relation, counterpartXref: cx });
  };
  const parents: string[] = [];

  for (const r of doc.relationships ?? []) {
    const p1 = refId(r.person1);
    const p2 = refId(r.person2);
    if (r.type === PARENTCHILD) {
      if (p2 === targetId) { add(KIN_RELATIONS.parent, p1); if (p1 !== null) parents.push(p1); }
      else if (p1 === targetId) add(KIN_RELATIONS.child, p2);
    } else if (r.type === COUPLE) {
      if (p1 === targetId) add(KIN_RELATIONS.spouse, p2);
      else if (p2 === targetId) add(KIN_RELATIONS.spouse, p1);
    } else if (r.type === SIBLING) {
      if (p1 === targetId) add(KIN_RELATIONS.sibling, p2);
      else if (p2 === targetId) add(KIN_RELATIONS.sibling, p1);
    }
  }

  if (parents.length > 0) {
    const parentSet = new Set(parents);
    for (const r of doc.relationships ?? []) {
      if (r.type !== PARENTCHILD) continue;
      if (refId(r.person1) !== null && parentSet.has(refId(r.person1) as string)) add(KIN_RELATIONS.sibling, refId(r.person2));
    }
  }

  const seen = new Set<string>();
  return rels.filter((r) => {
    const k = `${r.relation}|${r.counterpartXref}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

const normPub = (hex: string): string | null => {
  try {
    return PublicKey.fromString(hex).toString();
  } catch {
    return null;
  }
};

/**
 * Import one person from a GEDCOM X document as a `RecordModel`, resolving
 * relationship references to page-0 keys via `idToPage0`.
 *
 * `subjectPage0` is the target's page-0 key (GEDCOM X has none — it uses its own
 * person ids). Returns null on a malformed subject key or an unknown target id.
 * Counterparts not in the map — or mapped to a non-key — come back in
 * `unresolved` (who still needs to enrol), never fabricated. Feed `model` to
 * `recordToKinClaims` to bootstrap self-asserted `kin.edge` claims.
 */
export function recordFromGedcomX(
  doc: GedcomXDocument,
  targetId: string,
  subjectPage0: string,
  idToPage0: ReadonlyMap<string, string>,
): GedcomImportResult | null {
  const subject = normPub(subjectPage0);
  if (subject === null) return null;
  const person = (doc.persons ?? []).find((p) => p.id === targetId);
  if (person === undefined) return null;

  const relations: RecordRelation[] = [];
  const unresolved: ProvisionalRelation[] = [];
  for (const r of relationsForPerson(doc, targetId)) {
    const mapped = idToPage0.get(r.counterpartXref);
    const pub = mapped === undefined ? null : normPub(mapped);
    if (pub === null) unresolved.push(r);
    else relations.push({ relation: r.relation, counterpart: pub });
  }

  return { model: { subject, names: namesOf(person), facts: factsOf(person), relations, sources: [] }, unresolved };
}
