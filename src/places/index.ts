/**
 * A person's key at one place: the key they sign in with there, and the key a vouch for that place names.
 *
 * Two derivations exist today. Both are BRC-42 children of the person's root, derived against the root's own public
 * key, as Plexus kdf-v1 derives. They differ only in the invoice:
 *
 * - `relationshipKey(root, place)`, in `../bodies`: invoice `relationship-<first 16 hex of sha256(place)>:1:0`. A
 *   body's vouch names this key. The kids' world, BitPiggy and the lab use it today.
 * - `siteKeyOf(root, origin)`, here: invoice `2-admin plexus site-<origin> <version>`. The Plexus Auth approver signs
 *   in to a web site with this key (semantos-core `docs/design/PER-APP-IDENTITY-AND-RECOVERY.md`, R1). It sits under
 *   BRC-44's `admin` protocol, so no app can ask a wallet for it.
 *
 * For one web site the two give different keys, so a vouch issued to the first cannot be presented by the second.
 * Which one becomes the single place key is decision 11 of semantos-core
 * `docs/design/CLAIMS-AND-REQUIREMENTS.md`. Until then both are pinned by `test/fixtures/place_keys_kat.json`.
 * That file is canonical here: every other implementation (the approver, the Plexus SDK, BitPiggy, the lab) copies
 * it byte for byte and holds to it.
 */
import type { PrivateKey } from '@bsv/sdk';
import { WireError } from '../bodies/bytes';

/** The site key's version, the last word of its invoice. */
export const SITE_KEY_VERSION = 1;

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

/** The invoice a site key is derived under. `origin` must already be serialised (`originOf`). */
export function siteKeyInvoice(origin: string, version: number = SITE_KEY_VERSION): string {
  if (!Number.isSafeInteger(version) || version < 1) throw new WireError('bad_version', String(version));
  return `2-admin plexus site-${origin} ${version}`;
}

/**
 * The person's key at one web site: `BRC-42(root -> root, "2-admin plexus site-<origin> <version>")`.
 *
 * `origin` must be the serialised origin itself, as `originOf` returns it. Anything else (a path, a trailing slash,
 * an upper-case host, a default port) is refused as `not_an_origin` rather than quietly normalised, because two
 * spellings of one site would otherwise give two keys.
 */
export function siteKeyOf(root: PrivateKey, origin: string, version: number = SITE_KEY_VERSION): PrivateKey {
  let serialised: string;
  try {
    serialised = originOf(origin);
  } catch (e) {
    throw e instanceof WireError ? new WireError('not_an_origin', e.code) : e;
  }
  if (serialised !== origin) throw new WireError('not_an_origin', `serialises as ${serialised}`);
  return root.deriveChild(root.toPublicKey(), siteKeyInvoice(origin, version));
}
