/**
 * The known-answer file for a person's key at a place, test/fixtures/place_keys_kat.json.
 *
 * scripts/gen-place-keys-kat.ts writes it. Here it is regenerated and compared byte for byte, and checked against
 * things the generator does not compute: the bodies known-answer file's subject, invoices written by hand, and the
 * Plexus Auth approver's own site-key formula as that code writes it.
 */
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PrivateKey } from '@bsv/sdk';
import { buildPlaceKeysKat, PLACE_KEYS_KAT_PATH } from '../scripts/gen-place-keys-kat';
import { appPlace, isPlace, originOf, placeInvoice, placeKeyOf, siteKeyOf, WireError } from '../src';

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

type Place = { place: string; invoice: string; publicKey: string; didKey: string };

describe('place keys known answers', () => {
  test('regenerating the file gives the same bytes', () => {
    expect(buildPlaceKeysKat()).toBe(text);
  });

  test("the bodies holder's key at the kids' world is the bodies known-answer subject", () => {
    const holder = KAT.roots.find((r: { label: string }) => r.label === 'bodies-kat-holder');
    expect(holder.rootPublicKey).toBe(BODIES_KAT.parties.holderRoot);
    const world = holder.places.find((p: Place) => p.place === BODIES_KAT.place.place);
    expect(world.invoice).toBe(BODIES_KAT.place.invoice);
    expect(world.didKey).toBe(BODIES_KAT.parties.subject);
  });

  test('invoices, written by hand', () => {
    expect(placeInvoice('https://lessons.example')).toBe('2-admin plexus site-https://lessons.example 1');
    expect(placeInvoice('app:kids-world:gem-island')).toBe('2-admin plexus site-app:kids-world:gem-island 1');
    expect(placeInvoice('http://localhost:5173', 2)).toBe('2-admin plexus site-http://localhost:5173 2');
    expect(appPlace('kids-world:gem-island')).toBe('app:kids-world:gem-island');
  });

  test("at a web site, the place key is the approver's site key, as its code writes it", () => {
    for (const r of KAT.roots) {
      const root = PrivateKey.fromString(r.root, 16);
      for (const p of r.places.filter((x: Place) => !x.place.startsWith('app:'))) {
        const approver = root.deriveChild(root.toPublicKey(), `2-admin plexus site-${p.place} ${1}`);
        expect(approver.toPublicKey().toString()).toBe(p.publicKey);
        expect(siteKeyOf(root, p.place).toPublicKey().toString()).toBe(p.publicKey);
      }
    }
  });

  test('the code gives every key in the file, and each root a different key at each place', () => {
    for (const r of KAT.roots) {
      const root = PrivateKey.fromString(r.root, 16);
      for (const p of r.places) expect(placeKeyOf(root, p.place).toPublicKey().toString()).toBe(p.publicKey);
      expect(new Set(r.places.map((p: Place) => p.publicKey)).size).toBe(r.places.length);
    }
  });

  test('origins and apps become places, or are refused, as the file says', () => {
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
    expect(KAT.apps).toEqual([
      { id: 'kids-world:gem-island', place: 'app:kids-world:gem-island' },
      { id: 'vedic-math-lab:app', place: 'app:vedic-math-lab:app' },
      { id: 'Kids-World:gem-island', refused: 'not_an_app' },
      { id: 'kidsworld', refused: 'not_an_app' },
      { id: 'a:b:c', refused: 'not_an_app' },
      { id: 'a:', refused: 'not_an_app' },
      { id: '', refused: 'not_an_app' },
    ]);
    for (const o of KAT.origins) {
      if (o.origin) expect(originOf(o.address)).toBe(o.origin);
      else expect(codeOf(() => originOf(o.address))).toBe(o.refused);
    }
  });

  test('a place is taken only as written: a bare app id, another spelling of a site, or a non-web scheme is not one', () => {
    const root = PrivateKey.fromString(KAT.roots[0].root, 16);
    for (const n of KAT.notPlaces) {
      expect(n.refused).toBe('not_a_place');
      expect(isPlace(n.place)).toBe(false);
      expect(codeOf(() => placeKeyOf(root, n.place))).toBe('not_a_place');
    }
    expect(KAT.notPlaces.map((n: { place: string }) => n.place)).toContain('kids-world:gem-island');
    expect(codeOf(() => siteKeyOf(root, 'app:kids-world:gem-island'))).toBe('not_an_origin');
    expect(codeOf(() => placeInvoice('https://lessons.example', 0))).toBe('bad_version');
    expect(codeOf(() => placeInvoice('https://lessons.example', 1.5))).toBe('bad_version');
  });
});
