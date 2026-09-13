/**
 * The read-only FamilySearch Family Tree port + a mock for the prototype.
 *
 * The bridge (`./bridge`) reads a person's GEDCOM X through THIS port and
 * nothing else, so the real client — an authenticated `GET /platform/tree/
 * persons/{id}` against FamilySearch, gated by partner access — drops in behind
 * it later without changing the bridge. `MockTreeApi` stands in until then.
 *
 * ⚠ The real implementation reads with the SUBJECT's own OIDC/authorization-code
 * token (their consent, their tree — see `GIP-V2-FS-INTEGRATION-SEAM.md` §3), not
 * a service account. The mock ignores auth entirely; it is not a stand-in for
 * that access decision, only for the shape of the data.
 */

import type { GedcomXDocument } from '../src';

export interface TreeApi {
  /**
   * The GEDCOM X for one person — the person plus the relationships that touch
   * them (and the counterpart persons), as FamilySearch's `/platform/tree/
   * persons/{id}` returns. Null when the person is not found / not accessible.
   */
  readPerson(personId: string): Promise<GedcomXDocument | null>;
}

/** A hand-loaded Tree API for the prototype. NOT a real FamilySearch client. */
export class MockTreeApi implements TreeApi {
  constructor(private readonly docsByPersonId: ReadonlyMap<string, GedcomXDocument>) {}

  readPerson(personId: string): Promise<GedcomXDocument | null> {
    return Promise.resolve(this.docsByPersonId.get(personId) ?? null);
  }
}
