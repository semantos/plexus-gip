/**
 * The known-answer file for a person's key at a place, test/fixtures/place_keys_kat.json.
 *
 * scripts/gen-place-keys-kat.ts writes it. Here it is regenerated and compared byte for byte, and checked against
 * things the generator does not compute: the bodies known-answer file's subject, invoices written by hand, and the
 * Plexus Auth approver's own formula as that code writes it.
 */
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PrivateKey } from '@bsv/sdk';
import { buildPlaceKeysKat, PLACE_KEYS_KAT_PATH } from '../scripts/gen-place-keys-kat';
import { originOf, siteKeyInvoice, siteKeyOf, WireError } from '../src';

const text = readFileSync(PLACE_KEYS_KAT_PATH, 'utf8');
const KAT = JSON.parse(text);
const BODIES_KAT = JSON.parse(readFileSync(join(import.meta.dir, 'fixtures/bodies_kat.json'), 'utf8'));

const codeOf = (f: () => unknown): string | undefined => {
  try {
    f();
    return undefined;
  } catch (e) {
    return e instanceof WireError ? e.code : `not a WireError: ${String(e)}`;
  }
};

describe('place keys known answers', () => {
  test('regenerating the file gives the same bytes', () => {
    expect(buildPlaceKeysKat()).toBe(text);
  });

  test('the bodies holder at the kids world is the bodies known-answer subject', () => {
    const holder = KAT.roots.find((r: { label: string }) => r.label === 'bodies-kat-holder');
    expect(holder.rootPublicKey).toBe(BODIES_KAT.parties.holderRoot);
    const place = holder.places.find((p: { place: string }) => p.place === BODIES_KAT.relationship.relyingParty);
    expect(place.relationshipKey.invoice).toBe(BODIES_KAT.relationship.invoice);
    expect(place.relationshipKey.didKey).toBe(BODIES_KAT.parties.subject);
  });

  test('invoices, written by hand', () => {
    expect(siteKeyInvoice('https://lessons.example')).toBe('2-admin plexus site-https://lessons.example 1');
    expect(siteKeyInvoice('http://localhost:5173', 2)).toBe('2-admin plexus site-http://localhost:5173 2');
    const lessons = KAT.roots[0].places.find((p: { place: string }) => p.place === 'https://lessons.example');
    expect(lessons.siteKey.invoice).toBe('2-admin plexus site-https://lessons.example 1');
    // sha256("https://lessons.example") begins a5b2e30ddb4d9ac9, worked out apart from the generator.
    expect(lessons.relationshipKey.invoice).toBe('relationship-a5b2e30ddb4d9ac9:1:0');
  });

  test("the approver's formula, as its code writes it, gives the file's site keys", () => {
    for (const r of KAT.roots) {
      const root = PrivateKey.fromString(r.root, 16);
      for (const p of r.places.filter((x: { siteKey?: unknown }) => x.siteKey)) {
        const approver = root.deriveChild(root.toPublicKey(), `2-admin plexus site-${p.place} ${1}`);
        expect(approver.toPublicKey().toString()).toBe(p.siteKey.publicKey);
      }
    }
  });

  test('for one web site the two derivations give different keys (decision 11)', () => {
    for (const r of KAT.roots) {
      for (const p of r.places.filter((x: { siteKey?: unknown }) => x.siteKey)) {
        expect(p.siteKey.publicKey).not.toBe(p.relationshipKey.publicKey);
      }
    }
  });

  test('origins serialise, or are refused, as the file says', () => {
    expect(KAT.origins).toEqual([
      { address: 'https://Lessons.Example:443/packs?x#y', origin: 'https://lessons.example' },
      { address: 'http://localhost:5173/', origin: 'http://localhost:5173' },
      { address: 'https://BÜCHER.example/x', origin: 'https://xn--bcher-kva.example' },
      { address: 'https://hillside.example.edu.au:8443/a', origin: 'https://hillside.example.edu.au:8443' },
      { address: 'https://[::1]:8443/', origin: 'https://[::1]:8443' },
      { address: 'not a url', refused: 'bad_origin' },
      { address: 'ws://x.example/', refused: 'not_web' },
      { address: 'blob:https://a.example/uuid', refused: 'not_web' },
      { address: 'data:text/plain,hi', refused: 'not_web' },
      { address: 'file:///etc/passwd', refused: 'not_web' },
    ]);
    for (const o of KAT.origins) {
      if (o.origin) expect(originOf(o.address)).toBe(o.origin);
      else expect(codeOf(() => originOf(o.address))).toBe(o.refused);
    }
  });

  test('a site key takes the serialised origin itself, and nothing else', () => {
    const root = PrivateKey.fromString(KAT.roots[0].root, 16);
    for (const spelling of ['https://Lessons.example', 'https://lessons.example/', 'https://lessons.example:443', 'ws://x.example', 'lessons.example']) {
      expect(codeOf(() => siteKeyOf(root, spelling))).toBe('not_an_origin');
    }
    expect(codeOf(() => siteKeyInvoice('https://lessons.example', 0))).toBe('bad_version');
    expect(codeOf(() => siteKeyInvoice('https://lessons.example', 1.5))).toBe('bad_version');
  });
});
