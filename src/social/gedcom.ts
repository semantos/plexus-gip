/**
 * Legacy GEDCOM 5.5.1 → kinship edges — the "bootstrap from an existing tree" path.
 *
 * `record.ts`'s `recordFromGedcom551` reads ONE individual's names and facts and
 * stops there, because relationships in legacy GEDCOM do not live on the person:
 * they live in the FAM-record graph, addressed by `@Ixref@` pointers that are
 * NOT page-0 keys. This module closes that gap. It parses the whole file into an
 * INDI/FAM graph, derives a target individual's atomic relations (parent, child,
 * sibling, spouse) from that graph, and resolves each counterpart `@xref@` to a
 * page-0 key through a caller-supplied mapping.
 *
 * ## Why a mapping, and why "unresolved" is a first-class output
 *
 * A legacy file has no keys — only xrefs. So relations can only be resolved for
 * relatives who have ALREADY enrolled (whose xref the caller can map to a
 * page-0 key). The rest are not dropped silently: they come back as `unresolved`,
 * which is precisely the list of people still to invite. That is the design the
 * GIP v2 note calls for — a tree bootstraps *self-asserted* edges as relatives
 * enrol, never a set of fabricated keys.
 *
 * The names/facts come from `recordFromGedcom551` (one parser for the INDI
 * block, no second copy to drift); this module adds only the FAM-graph walk.
 */

import { PublicKey } from '@bsv/sdk';
import { type KinRelation, KIN_RELATIONS } from './kinship';
import {
  type RecordFact,
  type RecordModel,
  type RecordName,
  type RecordRelation,
  recordFromGedcom551,
} from './record';

export interface GedcomIndividual {
  readonly xref: string;
  /** The full INDI block, handed to `recordFromGedcom551` for names/facts. */
  readonly recordText: string;
  /** Families in which this person is a CHILD (source of parents + siblings). */
  readonly famc: readonly string[];
  /** Families in which this person is a SPOUSE (source of children + spouse). */
  readonly fams: readonly string[];
}

export interface GedcomFamily {
  readonly xref: string;
  readonly husb?: string;
  readonly wife?: string;
  readonly children: readonly string[];
}

export interface GedcomTree {
  readonly individuals: ReadonlyMap<string, GedcomIndividual>;
  readonly families: ReadonlyMap<string, GedcomFamily>;
}

/** Split a GEDCOM file into level-0 records (each a group of lines). */
function splitRecords(text: string): string[][] {
  const records: string[][] = [];
  let cur: string[] | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (/^0(\s|$)/.test(line)) {
      if (cur !== null) records.push(cur);
      cur = [line];
    } else if (cur !== null) {
      cur.push(line);
    }
  }
  if (cur !== null) records.push(cur);
  return records;
}

/** Parse the whole file into an INDI/FAM graph. Unknown level-0 records are skipped. */
export function parseGedcomTree(text: string): GedcomTree {
  const individuals = new Map<string, GedcomIndividual>();
  const families = new Map<string, GedcomFamily>();

  for (const rec of splitRecords(text)) {
    const m = rec[0]!.match(/^0\s+@([^@]+)@\s+(\w+)/);
    if (m === null) continue; // HEAD / TRLR / level-0 SOUR carry no xref
    const xref = m[1]!;
    const tag = m[2]!;

    if (tag === 'INDI') {
      const famc: string[] = [];
      const fams: string[] = [];
      for (const line of rec.slice(1)) {
        const lm = line.match(/^1\s+(FAMC|FAMS)\s+@([^@]+)@/);
        if (lm !== null) (lm[1] === 'FAMC' ? famc : fams).push(lm[2]!);
      }
      individuals.set(xref, { xref, recordText: rec.join('\n'), famc, fams });
    } else if (tag === 'FAM') {
      let husb: string | undefined;
      let wife: string | undefined;
      const children: string[] = [];
      for (const line of rec.slice(1)) {
        const fm = line.match(/^1\s+(HUSB|WIFE|CHIL)\s+@([^@]+)@/);
        if (fm === null) continue;
        if (fm[1] === 'HUSB') husb = fm[2]!;
        else if (fm[1] === 'WIFE') wife = fm[2]!;
        else children.push(fm[2]!);
      }
      families.set(xref, { xref, husb, wife, children });
    }
  }
  return { individuals, families };
}

/** A relation still addressed by xref, before mapping to a page-0 key. */
export interface ProvisionalRelation {
  readonly relation: KinRelation;
  readonly counterpartXref: string;
}

/**
 * Derive a target individual's atomic relations from the FAM graph.
 *
 * From FAMC (families the target is a child of): the HUSB/WIFE are `parent`s and
 * the other CHIL are `sibling`s. From FAMS (families the target is a spouse in):
 * the CHIL are `child`ren and the other partner is a `spouse`. Half-siblings via
 * a parent's *other* family are out of scope — only same-family CHIL are
 * siblings here, which is what a single FAM record actually asserts.
 */
export function relationsForIndividual(tree: GedcomTree, xref: string): ProvisionalRelation[] {
  const indi = tree.individuals.get(xref);
  if (indi === undefined) return [];
  const rels: ProvisionalRelation[] = [];
  const add = (relation: KinRelation, cx: string): void => {
    if (cx !== xref) rels.push({ relation, counterpartXref: cx });
  };

  for (const fx of indi.famc) {
    const fam = tree.families.get(fx);
    if (fam === undefined) continue;
    if (fam.husb !== undefined) add(KIN_RELATIONS.parent, fam.husb);
    if (fam.wife !== undefined) add(KIN_RELATIONS.parent, fam.wife);
    for (const c of fam.children) add(KIN_RELATIONS.sibling, c);
  }
  for (const fx of indi.fams) {
    const fam = tree.families.get(fx);
    if (fam === undefined) continue;
    for (const c of fam.children) add(KIN_RELATIONS.child, c);
    if (fam.husb !== undefined) add(KIN_RELATIONS.spouse, fam.husb);
    if (fam.wife !== undefined) add(KIN_RELATIONS.spouse, fam.wife);
  }

  const seen = new Set<string>();
  return rels.filter((r) => {
    const k = `${r.relation}|${r.counterpartXref}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export interface GedcomImportResult {
  /** The target's record: names + facts from the INDI block, relations resolved to page-0 keys. */
  readonly model: RecordModel;
  /** Relations whose counterpart has no page-0 key yet — exactly who still needs to enrol. */
  readonly unresolved: readonly ProvisionalRelation[];
}

const normPub = (hex: string): string | null => {
  try {
    return PublicKey.fromString(hex).toString();
  } catch {
    return null;
  }
};

/**
 * Import one individual from a legacy GEDCOM file as a `RecordModel`, resolving
 * relations through `xrefToPage0`.
 *
 * `subjectPage0` is the target's page-0 key (a legacy file has none, so the
 * caller supplies it). Returns null if the subject key is malformed or the xref
 * is not in the file. Relations whose counterpart is not in the mapping — or is
 * mapped to a non-key — are returned in `unresolved`, never invented.
 *
 * Feed `result.model` to `recordToKinClaims(model, egoSk)` to turn the resolved
 * relations into self-asserted `kin.edge` claims for the target to counter-sign.
 */
export function recordFromGedcomTree(
  text: string,
  targetXref: string,
  subjectPage0: string,
  xrefToPage0: ReadonlyMap<string, string>,
): GedcomImportResult | null {
  const subject = normPub(subjectPage0);
  if (subject === null) return null;
  const tree = parseGedcomTree(text);
  const indi = tree.individuals.get(targetXref);
  if (indi === undefined) return null;

  const base = recordFromGedcom551(indi.recordText, subject);
  const names: readonly RecordName[] = base?.names ?? [];
  const facts: readonly RecordFact[] = base?.facts ?? [];

  const relations: RecordRelation[] = [];
  const unresolved: ProvisionalRelation[] = [];
  for (const r of relationsForIndividual(tree, targetXref)) {
    const mapped = xrefToPage0.get(r.counterpartXref);
    const pub = mapped === undefined ? null : normPub(mapped);
    if (pub === null) unresolved.push(r);
    else relations.push({ relation: r.relation, counterpart: pub });
  }

  return { model: { subject, names, facts, relations, sources: [] }, unresolved };
}
