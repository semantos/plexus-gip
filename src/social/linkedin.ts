/**
 * The LinkedIn identity certificate type.
 *
 * Binds a semantos cert to a LinkedIn account, so a credential page can say
 * "Validated by Jane Ellis" instead of `certid:0271db8ecf4f1062`. That hex
 * string is the weakest thing on the deployed page at `semantos.me/c/…`: a
 * stranger checking an engineer's licence learns nothing from it.
 *
 * `verifyAttestedClaim` deliberately does not bind certIds to keys — "that
 * binding is the identity layer's, and pretending to settle it here with no
 * cert store would be theatre". This is that layer, for one provider.
 *
 * Modelled on p2ppsr/socialcert-backend, which issues exactly this shape for
 * Discord, X, email and phone (`userName` + `profilePhoto`) and has no LinkedIn
 * type. The two field names are kept verbatim so a consumer that already
 * renders a SocialCert certificate renders this one unchanged.
 *
 * ## Three things LinkedIn's own documentation forces
 *
 * **1. It is NOT identity verification, and LinkedIn says so.** Their docs
 * state: Sign In with LinkedIn using OpenID Connect "does not verify user
 * identities and should not be marketed as such." So this certifies CONTROL OF
 * AN ACCOUNT — a mechanical fact a certifier actually checked — and never that
 * a real named human is behind it. That distinction is the whole reason a
 * certifier here is defensible where a competence CA is not: the claim is
 * bounded, checkable, and carries no judgment.
 *
 * **2. The subject identifier is PAIRWISE.** The discovery document declares
 * `"subject_types_supported": ["pairwise"]`, meaning `sub` is scoped to the
 * requesting `client_id` — a different opaque value per relying party for the
 * same person. Two consequences, both load-bearing:
 *
 *   - It cannot be correlated with anyone else's `sub` for that person, so it
 *     is useless for reconstructing a graph from other services. (It is also
 *     why "poach the LinkedIn graph" does not work at this layer even before
 *     the Connections API is considered.)
 *   - **Re-registering the OAuth app silently breaks every binding.** A new
 *     `client_id` yields new `sub` values, and old certificates would keep
 *     verifying while pointing at an identifier LinkedIn will never issue
 *     again. `linkedinAudience` records which `client_id` the `sub` was scoped
 *     to, so the breakage is DETECTABLE instead of silent.
 *
 * **3. There is no profile URL.** The claim set is `iss aud iat exp sub name
 * given_name family_name picture email email_verified locale` — no vanity name,
 * no `linkedin.com/in/…`. A certificate carrying a profile link would be
 * fabricating its most clickable field, so this carries none, and the page
 * shows a name it can support rather than a link it cannot.
 *
 * ## What is deliberately not here
 *
 * `email` and `email_verified` are available and excluded. They are PII that
 * would end up on a public verification page, and the binding does not need
 * them — the smallest field set that does the job is the one that cannot leak.
 */

import type { PrivateKey } from '@bsv/sdk';
import { ASSOCIATION_KINDS, type Association, signAssociation } from '../associations';

/**
 * Certificate type identifier.
 *
 * SocialCert's convention is 32 random bytes base64 ("Do not re-use type
 * identifiers"). This repo's `Brc52Cert.type` is a dotted namespace instead
 * (`plexus.identity.root`), and that convention wins here: the certificates are
 * issued into OUR cert system, no SocialCert LinkedIn type exists to be
 * compatible with, and an unknown random base64 id is no more legible to a
 * foreign wallet than a readable one. Greppable beats opaque when neither
 * interoperates.
 */
export const LINKEDIN_CERT_TYPE = 'semantos.identity.social.linkedin.v1';

/** LinkedIn's OIDC issuer. Anything else is not a LinkedIn token. */
export const LINKEDIN_ISSUER = 'https://www.linkedin.com';

/** Discovery document, whose `jwks_uri` verifies an id_token's signature. */
export const LINKEDIN_DISCOVERY = 'https://www.linkedin.com/oauth/.well-known/openid-configuration';

/**
 * LinkedIn's own words, carried so a display layer cannot soften them by
 * paraphrase. A page rendering this certificate must not imply more.
 */
export const LINKEDIN_VERIFICATION_DISCLAIMER =
  'LinkedIn states that Sign In with LinkedIn using OpenID Connect does not verify user identities.';

/** The OIDC claims this certificate is derived from. */
export interface LinkedInClaims {
  readonly iss?: string;
  readonly aud?: string | readonly string[];
  readonly sub?: string;
  readonly exp?: number;
  readonly iat?: number;
  readonly name?: string;
  readonly picture?: string;
  // `email`, `email_verified` and `locale` are intentionally unused.
}

/** The certificate's `fields`. String values only, per `Brc52Cert`. */
export interface LinkedInCertFields extends Record<string, string> {
  /** Pairwise subject id. Meaningless without `linkedinAudience`. */
  readonly linkedinSub: string;
  /** The `client_id` the pairwise `sub` is scoped to. */
  readonly linkedinAudience: string;
  /** Display name. Same key SocialCert uses. */
  readonly userName: string;
  /** Picture URL. Same key SocialCert uses. */
  readonly profilePhoto: string;
}

export type LinkedInCertResult =
  | { readonly ok: true; readonly fields: LinkedInCertFields }
  | {
      readonly ok: false;
      readonly reason:
        | 'wrong_issuer'
        | 'wrong_audience'
        | 'expired'
        | 'no_subject'
        | 'no_name';
    };

/**
 * Turn verified OIDC claims into certificate fields.
 *
 * ⚠️ **Pure — it does NOT verify the token's signature.** Call it only with
 * claims from an id_token whose RS256 signature was checked against LinkedIn's
 * JWKS, or from `/v2/userinfo` fetched with a real access token. Handed an
 * unverified JWT payload it will happily certify anything, because a JWT
 * payload is attacker-controlled text until its signature is checked. The
 * split is deliberate: the checks below are decidable from values and belong
 * where they can be tested exhaustively, and signature verification needs the
 * network.
 *
 * `audience` is required rather than optional. It is what makes a pairwise
 * `sub` meaningful, and defaulting it would let a caller mint a certificate
 * whose subject identifier is scoped to an app nobody recorded.
 */
export function linkedInCertFields(
  claims: LinkedInClaims,
  audience: string,
  nowSeconds: number,
): LinkedInCertResult {
  if (claims.iss !== LINKEDIN_ISSUER) return { ok: false, reason: 'wrong_issuer' };

  // `aud` is a string or an array; both must contain OUR client_id, or the
  // token was minted for a different relying party and its `sub` is not ours
  // to read.
  const aud = claims.aud;
  const audMatches = typeof aud === 'string' ? aud === audience : aud?.includes(audience) === true;
  if (!audMatches) return { ok: false, reason: 'wrong_audience' };

  // Absent `exp` is treated as expired, not as "never expires" — the
  // conservative direction for a token whose whole purpose is to be temporary.
  if (typeof claims.exp !== 'number' || claims.exp <= nowSeconds) {
    return { ok: false, reason: 'expired' };
  }
  if (typeof claims.sub !== 'string' || claims.sub === '') return { ok: false, reason: 'no_subject' };
  // A certificate whose entire purpose is to replace a hex string with a human
  // name is worthless without the name, so this refuses rather than issuing a
  // blank one.
  if (typeof claims.name !== 'string' || claims.name.trim() === '') {
    return { ok: false, reason: 'no_name' };
  }

  return {
    ok: true,
    fields: {
      linkedinSub: claims.sub,
      linkedinAudience: audience,
      userName: claims.name.trim(),
      profilePhoto: typeof claims.picture === 'string' ? claims.picture : '',
    },
  };
}

/**
 * Is this certificate's pairwise subject still meaningful for our app?
 *
 * False means the certificate was issued under a different `client_id`: the
 * `sub` inside it is an identifier LinkedIn will never issue to us again, so
 * the binding is stale even though every signature on it is still valid. This
 * is the check that turns the re-registration trap from silent into loud.
 */
export function linkedInBindingIsCurrent(
  fields: Pick<LinkedInCertFields, 'linkedinAudience'>,
  currentAudience: string,
): boolean {
  return fields.linkedinAudience === currentAudience;
}

/**
 * A verified LinkedIn login, as ONE signed association among many.
 *
 * The bridge that demotes LinkedIn from "the identity" to a leaf. Because the
 * HOLDER assembles their set locally, whoever ran the OAuth must SIGN — an
 * unsigned `vouchedBy` would be a field the holder types, and they could name
 * this certifier beside any handle they liked.
 *
 * `subjectPublicKey` is bound in by `signAssociation`, so the result is
 * unusable in anyone else's set.
 *
 * The pairwise `sub` and its audience stay OUT: operational bookkeeping for
 * detecting a re-registered app, not something a verifier should be handed
 * when they asked for a name.
 */
export function linkedInAssociation(
  fields: Pick<LinkedInCertFields, 'userName'>,
  voucherSk: PrivateKey,
  subjectPublicKey: string,
): Association {
  const kind = ASSOCIATION_KINDS.linkedin;
  return {
    kind,
    display: fields.userName,
    vouchedBy: voucherSk.toPublicKey().toString(),
    signature: signAssociation(voucherSk, subjectPublicKey, kind, fields.userName),
  };
}
