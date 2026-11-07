/**
 * A person's key at one place: the key they sign in with there, and the key every vouch for that place names.
 *
 *   placeKeyOf(root, place) = BRC-42(root -> root, "2-admin plexus site-<place> <version>")
 *
 * One derivation for every place (semantos-core `docs/design/CLAIMS-AND-REQUIREMENTS.md`, decision 11, decided by
 * Todd on 7 November 2026). A place is one of two kinds, which cannot be confused, since an origin starts with
 * `http`:
 *
 * - a web site's WHATWG origin, `http` or `https` only (`originOf`): `https://lessons.example`. For an origin this is
 *   the key the Plexus Auth approver signs in with, `siteKeyOf` (semantos-core `PER-APP-IDENTITY-AND-RECOVERY.md`,
 *   R1).
 * - `app:<id>` for an app, where `<id>` is a seat card's app id, `[a-z0-9-]+:[a-z0-9-]+` (`appPlace`):
 *   `app:kids-world:gem-island`.
 *
 * It sits under BRC-44's `admin` protocol, so no app can ask a wallet for it, and it is a keyed derivation, so no
 * public value inverts it. It replaces the bodies' earlier `relationshipKey` (`relationship-<hash>:1:0`), under which
 * the key a person signed in with and the key their vouch named were two keys.
 *
 * `test/fixtures/place_keys_kat.json` pins it, and is canonical here: every other implementation (the approver, the
 * Plexus SDK, BitPiggy, the lab) copies it byte for byte and holds to it.
 */
import type { PrivateKey } from '@bsv/sdk';
import { WireError } from '../bodies/bytes';

/** The place key's version, the last word of its invoice. */
export const PLACE_KEY_VERSION = 1;

/**
 * The WHATWG serialisation of a web address's origin, for `http` and `https` only: scheme, lower-case host (in
 * punycode), and the port only when it is not the scheme's default.
 *
 * Refuses, as `WireError` codes:
 * - `bad_origin`: not an absolute URL;
 * - `not_web`: any scheme but `http` and `https`, including `blob`, `ws` and `file`, whose origins platforms
 *   disagree on or which are not sites;
 * - `opaque_origin`: an origin serialised as `null`.
 */
export function originOf(address: string): string {
  let url: URL;
  try {
    url = new URL(address);
  } catch {
    throw new WireError('bad_origin', 'not an absolute URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new WireError('not_web', url.protocol);
  const origin = url.origin;
  if (origin === 'null') throw new WireError('opaque_origin');
  return origin;
}

const APP_ID = /^[a-z0-9-]+:[a-z0-9-]+$/;

/** An app's id as a seat card writes it: `<a>:<b>`, each part `[a-z0-9-]+`. */
export const isAppId = (id: string): boolean => APP_ID.test(id);

/** The place for an app: `app:<id>`. Refuses anything that is not an app's id (`not_an_app`). */
export function appPlace(appId: string): string {
  if (!isAppId(appId)) throw new WireError('not_an_app', appId);
  return `app:${appId}`;
}

const isOrigin = (place: string): boolean => {
  try {
    return originOf(place) === place;
  } catch {
    return false;
  }
};

/** Whether `place` is a place as written: a serialised http(s) origin, or `app:` and an app's id. */
export function isPlace(place: string): boolean {
  if (place.startsWith('app:')) return isAppId(place.slice(4));
  return isOrigin(place);
}

/** The invoice a place key is derived under. `place` must be a place as written (`isPlace`). */
export function placeInvoice(place: string, version: number = PLACE_KEY_VERSION): string {
  if (!isPlace(place)) throw new WireError('not_a_place', place);
  if (!Number.isSafeInteger(version) || version < 1) throw new WireError('bad_version', String(version));
  return `2-admin plexus site-${place} ${version}`;
}

/**
 * The person's key at one place. `place` must be a place exactly as written: a serialised origin (a trailing slash,
 * an upper-case host or a default port is refused rather than quietly normalised, because two spellings of one site
 * would otherwise give two keys), or `app:<id>`. A bare app id, without `app:`, is refused: it is not a place.
 */
export function placeKeyOf(root: PrivateKey, place: string, version: number = PLACE_KEY_VERSION): PrivateKey {
  return root.deriveChild(root.toPublicKey(), placeInvoice(place, version));
}

/** The key at a web site: `placeKeyOf` for an origin, refusing anything else (`not_an_origin`). */
export function siteKeyOf(root: PrivateKey, origin: string, version: number = PLACE_KEY_VERSION): PrivateKey {
  if (!isOrigin(origin)) throw new WireError('not_an_origin', origin);
  return placeKeyOf(root, origin, version);
}
