/**
 * Verifying a FamilySearch OpenID Connect id_token, so the social leaf can be
 * trusted.
 *
 * The network half of the FamilySearch OIDC provider (`social/providers.ts`),
 * mirroring `linkedin-verify.ts`: `socialCertFields` is pure and checks issuer +
 * claims from VALUES; none of that means anything until the id_token's RS256
 * SIGNATURE is checked against FamilySearch's JWKS. Same three attacks it must
 * refuse — `alg:"none"`, algorithm confusion (HS256 with the RSA public key),
 * and a token signed by a key we did not get from FamilySearch's JWKS.
 *
 * ## Two FamilySearch-specific adaptations
 *
 * 1. **Claim shape.** FamilySearch's identity scopes yield `given_name` /
 *    `family_name` (and `user_id`), not necessarily a composed `name` or a bare
 *    `sub`. This normalises the payload into the generic `SocialClaims` shape
 *    (`name` from the parts, `sub` falling back to `user_id`) before handing it
 *    to `socialCertFields` — the adapter doing its one job.
 * 2. **Audience.** FamilySearch is a `global`-subject provider, so
 *    `socialCertFields` does not gate on `aud` (that is deliberate for the REST
 *    providers). But an OIDC id_token DOES carry `aud`, and one minted for
 *    another client is not ours to read — so the audience is checked HERE,
 *    explicitly, before the leaf is accepted.
 *
 * See `docs/GIP-V2-FS-INTEGRATION-SEAM.md`.
 */

import {
  FAMILYSEARCH_DISCOVERY,
  type SocialCertResult,
  socialCertFields,
} from '../src';

/** The only algorithm accepted, regardless of what a token asks for. */
const ALG = 'RS256';
/** Confirmed against the live discovery document; used if discovery is down. */
const FALLBACK_JWKS = 'https://ident.familysearch.org/oauth2/jwks';

export type VerifyFailure =
  | 'malformed_token'
  | 'unsupported_alg'
  | 'unknown_key'
  | 'bad_signature'
  | 'jwks_unavailable';

export type VerifyResult =
  | { readonly ok: true; readonly result: SocialCertResult }
  | { readonly ok: false; readonly reason: VerifyFailure };

function b64urlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

interface Jwk { kty?: string; kid?: string; alg?: string; n?: string; e?: string; use?: string }

/**
 * FamilySearch's signing keys, read through the discovery document (so a key
 * rotation needs no release) with the confirmed JWKS URI as a fallback — a
 * discovery outage must not take verification down, only a keys outage should.
 */
export async function fetchJwks(fetchImpl: typeof fetch = fetch): Promise<Jwk[] | null> {
  let uri = FALLBACK_JWKS;
  try {
    const disco = await fetchImpl(FAMILYSEARCH_DISCOVERY);
    if (disco.ok) {
      const d = (await disco.json()) as { jwks_uri?: string };
      if (typeof d.jwks_uri === 'string' && d.jwks_uri.startsWith('https://')) uri = d.jwks_uri;
    }
  } catch { /* fall through to the constant */ }
  try {
    const r = await fetchImpl(uri);
    if (!r.ok) return null;
    const { keys } = (await r.json()) as { keys?: Jwk[] };
    return Array.isArray(keys) ? keys : null;
  } catch {
    return null;
  }
}

/** Compose the generic claim shape from FamilySearch's id_token payload. */
function normalize(payload: Record<string, unknown>): Record<string, unknown> {
  const given = typeof payload.given_name === 'string' ? payload.given_name : '';
  const family = typeof payload.family_name === 'string' ? payload.family_name : '';
  const composed = [given, family].filter((s) => s !== '').join(' ');
  return {
    ...payload,
    sub: typeof payload.sub === 'string' && payload.sub !== '' ? payload.sub : payload.user_id,
    name: typeof payload.name === 'string' && payload.name.trim() !== '' ? payload.name : composed || undefined,
  };
}

function audMatches(aud: unknown, audience: string): boolean {
  return typeof aud === 'string' ? aud === audience : Array.isArray(aud) && aud.includes(audience);
}

/**
 * Verify a FamilySearch id_token and derive the social-leaf fields.
 *
 * Signature first, then the audience, then the pure claim checks — the claim
 * checks are meaningless on an unverified token, and the audience is an OIDC
 * check `socialCertFields` (global) does not make.
 */
export async function verifyFamilySearchIdToken(
  idToken: string,
  audience: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
  deps: { readonly keys?: Jwk[]; readonly fetchImpl?: typeof fetch } = {},
): Promise<VerifyResult> {
  const parts = idToken.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'malformed_token' };
  const [h, p, s] = parts as [string, string, string];

  let header: { alg?: string; kid?: string };
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
    payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));
  } catch {
    return { ok: false, reason: 'malformed_token' };
  }

  if (header.alg !== ALG) return { ok: false, reason: 'unsupported_alg' };

  const keys = deps.keys ?? (await fetchJwks(deps.fetchImpl ?? fetch));
  if (keys === null) return { ok: false, reason: 'jwks_unavailable' };

  const jwk = keys.find(
    (k) => k.kty === 'RSA' && k.n !== undefined && k.e !== undefined
      && (header.kid === undefined || k.kid === header.kid),
  );
  if (jwk === undefined) return { ok: false, reason: 'unknown_key' };

  let verified: boolean;
  try {
    const key = await crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    verified = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', key, b64urlToBytes(s), new TextEncoder().encode(`${h}.${p}`),
    );
  } catch {
    return { ok: false, reason: 'bad_signature' };
  }
  if (!verified) return { ok: false, reason: 'bad_signature' };

  // OIDC audience — a real, signature-verified token minted for another client
  // is the realistic attack, and `socialCertFields` (global) does not catch it.
  if (!audMatches(payload.aud, audience)) {
    return { ok: true, result: { ok: false, reason: 'wrong_audience' } };
  }

  return { ok: true, result: socialCertFields('familysearch', normalize(payload), audience, nowSeconds) };
}
