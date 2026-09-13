/**
 * Social login as identity-graph LEAVES — LinkedIn, GitHub, Google, Facebook, X.
 *
 * `linkedin.ts` proved one provider. This is the same move generalised: turn a
 * verified social login into ONE signed association among many, so that no
 * platform IS the identity — each is a leaf a verifier may or may not be shown,
 * and the thing worth trusting is the SET (see `humanityEvidence`).
 *
 * The split from `linkedin.ts` is deliberately preserved. Everything here is
 * PURE and network-free: it turns already-verified claims into fields. The
 * signature/token check that makes those claims trustworthy lives in the
 * cartridge, over the network, because the substrate does no I/O. Hand this
 * module an unverified JWT payload and it will certify anything, exactly as
 * `linkedInCertFields` will — a JWT payload is attacker-controlled text until
 * its signature is checked.
 *
 * ## Two subject-id regimes, and why the difference is load-bearing
 *
 * The one thing a generic social layer must NOT paper over is that providers
 * hand out subject identifiers under two incompatible contracts:
 *
 * - **pairwise** (`linkedin`, `facebook`): `sub` is scoped to the requesting
 *   `client_id` — a different opaque value per relying party for the same
 *   person. Two consequences carry through, both from `linkedin.ts`:
 *     · it cannot be correlated across services (good for privacy);
 *     · **re-registering the OAuth app silently breaks every binding** — a new
 *       `client_id` yields new `sub` values while old certificates keep
 *       verifying against ids the provider will never issue again. So the
 *       audience is recorded (`socialAudience`) and `bindingIsCurrent` makes the
 *       breakage LOUD.
 *
 * - **global** (`google`, `github`, `x`): `sub` is one durable id for the person
 *   across every app. No re-registration trap, so no audience to record — but
 *   the mirror-image caveat holds: this id IS correlatable across services, and
 *   a verifier who collects two of them has linked two accounts. That is a
 *   property to state, not a bug to hide.
 *
 * ⚠️ The regime per provider is what WE configured the OAuth app to request and
 * what the provider guarantees; treat the registry value as the default and
 * confirm it against the live discovery document at integration time. Getting
 * it wrong in the pairwise→global direction leaks correlation; in the
 * global→pairwise direction it drops the staleness check.
 *
 * ## Freshness: `exp` is not universal
 *
 * OIDC providers issue an id_token with `exp`, and it is checked. The REST
 * providers here (`github`, `x`) return a profile from an authenticated
 * `/user`-style call that carries no expiry: freshness IS the live access-token
 * fetch the cartridge just performed, which the substrate cannot see. So for a
 * `global`/REST provider this module does NOT gate on `exp` — the association
 * records a durable fact ("this key proved control of GitHub user 12345"), and
 * *how recently* is the caller's question, not a field this can fabricate.
 *
 * ## What none of this is
 *
 * Not identity verification. Every provider here certifies CONTROL OF AN
 * ACCOUNT — a mechanical fact a certifier checked — and never that a named
 * human is behind it. `disclaimer` on each descriptor carries that in the
 * provider's own framing so a display layer cannot soften it by paraphrase.
 */

import type { PrivateKey } from '@bsv/sdk';
import { ASSOCIATION_KINDS, type Association, signAssociation } from '../associations';
import { LINKEDIN_ISSUER, LINKEDIN_VERIFICATION_DISCLAIMER } from './linkedin';

/**
 * FamilySearch's OpenID Connect issuer + discovery, confirmed against the live
 * well-known document (issuer `https://ident.familysearch.org`, RS256, JWKS at
 * `/oauth2/jwks`). The verify half (`cartridges/boomspace/brain/src/credential/
 * familysearch-verify.ts`) reads discovery for the JWKS `uri`, matching the
 * LinkedIn pattern. See `docs/design/GIP-V2-FS-INTEGRATION-SEAM.md`.
 */
export const FAMILYSEARCH_ISSUER = 'https://ident.familysearch.org';
export const FAMILYSEARCH_DISCOVERY = 'https://ident.familysearch.org/.well-known/openid-configuration';

/** How a provider scopes its subject id. See the file header. */
export type SocialSubjectType = 'pairwise' | 'global';

export type SocialProviderId = 'linkedin' | 'github' | 'google' | 'facebook' | 'x' | 'familysearch';

export interface SocialProvider {
  /** Stable id, also the key into {@link SOCIAL_PROVIDERS}. */
  readonly id: SocialProviderId;
  /** Dotted cert-type namespace, versioned; changing it orphans issued certs. */
  readonly certType: string;
  /** The `ASSOCIATION_KINDS` label this provider mints. */
  readonly kind: string;
  /**
   * The `iss` an OIDC token must carry, or the API host a REST profile came
   * from. Anything else is not this provider — the first check, always.
   */
  readonly issuer: string;
  /** `pairwise` records an audience and gates staleness; `global` does neither. */
  readonly subjectType: SocialSubjectType;
  /** The provider's own words on what its login does and does not prove. */
  readonly disclaimer: string;
}

/**
 * The providers, as descriptors.
 *
 * LinkedIn reuses the constants `linkedin.ts` already pins, so there is one
 * source of truth for its issuer and disclaimer rather than a second copy that
 * can drift. `linkedInCertFields` remains the authority for LinkedIn's exact
 * field shape; this registry is the generic orchestration around all five.
 */
export const SOCIAL_PROVIDERS: Readonly<Record<SocialProviderId, SocialProvider>> = {
  linkedin: {
    id: 'linkedin',
    certType: 'semantos.identity.social.linkedin.v1',
    kind: ASSOCIATION_KINDS.linkedin,
    issuer: LINKEDIN_ISSUER,
    subjectType: 'pairwise',
    disclaimer: LINKEDIN_VERIFICATION_DISCLAIMER,
  },
  google: {
    id: 'google',
    certType: 'semantos.identity.social.google.v1',
    kind: ASSOCIATION_KINDS.google,
    issuer: 'https://accounts.google.com',
    subjectType: 'global',
    disclaimer:
      'Google confirms control of a Google account; it does not assert the account holder is a specific real-world person.',
  },
  facebook: {
    id: 'facebook',
    certType: 'semantos.identity.social.facebook.v1',
    kind: ASSOCIATION_KINDS.facebook,
    issuer: 'https://www.facebook.com',
    subjectType: 'pairwise',
    disclaimer:
      'Facebook Login confirms control of a Facebook account and returns an app-scoped id; it does not verify real-world identity.',
  },
  github: {
    id: 'github',
    certType: 'semantos.identity.social.github.v1',
    kind: ASSOCIATION_KINDS.github,
    issuer: 'https://api.github.com',
    subjectType: 'global',
    disclaimer:
      'GitHub confirms control of a GitHub account; it does not verify the account holder’s real-world identity.',
  },
  x: {
    id: 'x',
    certType: 'semantos.identity.social.x.v1',
    kind: ASSOCIATION_KINDS.x,
    issuer: 'https://api.twitter.com',
    subjectType: 'global',
    disclaimer:
      'X confirms control of an X account; it does not verify the account holder’s real-world identity.',
  },
  familysearch: {
    id: 'familysearch',
    certType: 'semantos.identity.social.familysearch.v1',
    kind: ASSOCIATION_KINDS.familysearch,
    issuer: FAMILYSEARCH_ISSUER,
    // OIDC `sub`/`user_id` is one durable id per person across relying parties —
    // global, like Google/GitHub, so no audience-scoping. Also the natural anchor
    // for the tree-data bridge: this leaf proves control of the FS account the
    // bridge then reads from (GIP-V2-FS-INTEGRATION-SEAM.md §3).
    subjectType: 'global',
    disclaimer:
      'FamilySearch confirms control of a FamilySearch account; it does not verify the account holder’s real-world identity.',
  },
} as const;

/**
 * Claims the cartridge has ALREADY VERIFIED, normalised to a common shape.
 *
 * OIDC providers fill `aud`/`exp` from the id_token. REST providers (GitHub, X)
 * map their profile response into this: `sub` from the numeric/string id, `name`
 * from the display name (falling back to the handle), `picture` from the avatar
 * — and leave `aud`/`exp` unset, because their profile carries neither.
 */
export interface SocialClaims {
  readonly iss?: string;
  readonly aud?: string | readonly string[];
  readonly sub?: string;
  readonly exp?: number;
  readonly iat?: number;
  readonly name?: string;
  readonly picture?: string;
}

/** A minted social leaf's fields. `userName`/`profilePhoto` match SocialCert. */
export interface SocialCertFields extends Record<string, string> {
  /** Which platform, so a mixed set stays legible. */
  readonly provider: SocialProviderId;
  /** The subject id. Meaningful alone only for a `global` provider. */
  readonly socialSub: string;
  /**
   * For `pairwise` providers, the `client_id` the `sub` is scoped to; empty for
   * `global` providers, which have no per-app namespace to record.
   */
  readonly socialAudience: string;
  /** Display name. Same key SocialCert uses. */
  readonly userName: string;
  /** Picture URL, or empty. Same key SocialCert uses. */
  readonly profilePhoto: string;
}

export type SocialCertResult =
  | { readonly ok: true; readonly fields: SocialCertFields }
  | {
      readonly ok: false;
      readonly reason:
        | 'unknown_provider'
        | 'wrong_issuer'
        | 'wrong_audience'
        | 'expired'
        | 'no_subject'
        | 'no_name';
    };

/**
 * Turn verified claims into a social leaf's fields.
 *
 * ⚠️ Pure — does NOT verify a token signature. Call only with claims from an
 * id_token whose signature was checked, or from an authenticated profile fetch.
 *
 * `audience` is required for a `pairwise` provider (it is what makes the `sub`
 * meaningful, and defaulting it would mint a leaf scoped to an app nobody
 * recorded) and ignored for a `global` one.
 */
export function socialCertFields(
  providerId: SocialProviderId,
  claims: SocialClaims,
  audience: string | undefined,
  nowSeconds: number,
): SocialCertResult {
  const p = SOCIAL_PROVIDERS[providerId];
  if (p === undefined) return { ok: false, reason: 'unknown_provider' };
  if (claims.iss !== p.issuer) return { ok: false, reason: 'wrong_issuer' };

  if (p.subjectType === 'pairwise') {
    // A pairwise sub without the audience that scopes it is not an identifier.
    if (typeof audience !== 'string' || audience === '') {
      return { ok: false, reason: 'wrong_audience' };
    }
    const aud = claims.aud;
    const audMatches =
      typeof aud === 'string' ? aud === audience : aud?.includes(audience) === true;
    if (!audMatches) return { ok: false, reason: 'wrong_audience' };
    // OIDC tokens are temporary; absent `exp` reads as expired, not eternal.
    if (typeof claims.exp !== 'number' || claims.exp <= nowSeconds) {
      return { ok: false, reason: 'expired' };
    }
  } else if (typeof claims.exp === 'number' && claims.exp <= nowSeconds) {
    // A `global`/REST provider carries no `exp` and is not gated on one — but if
    // a caller DID pass an expiry (e.g. Google's OIDC token), honour it rather
    // than silently ignore a real expiry the caller bothered to include.
    return { ok: false, reason: 'expired' };
  }

  if (typeof claims.sub !== 'string' || claims.sub === '') {
    return { ok: false, reason: 'no_subject' };
  }
  // A leaf whose job is to replace a hex string with a human-legible name is
  // worthless blank, so it refuses rather than issuing an empty one.
  if (typeof claims.name !== 'string' || claims.name.trim() === '') {
    return { ok: false, reason: 'no_name' };
  }

  return {
    ok: true,
    fields: {
      provider: providerId,
      socialSub: claims.sub,
      socialAudience: p.subjectType === 'pairwise' ? (audience as string) : '',
      userName: claims.name.trim(),
      profilePhoto: typeof claims.picture === 'string' ? claims.picture : '',
    },
  };
}

/**
 * Is a `pairwise` provider's binding still meaningful for our current app?
 *
 * False means the leaf was minted under a different `client_id`: its `sub` is
 * an id the provider will never issue us again, so the binding is stale even
 * though every signature on it is still valid. This is the check that turns the
 * re-registration trap from silent into loud.
 *
 * A `global` provider has no per-app namespace, so its binding never goes stale
 * this way and this returns `true`.
 */
export function bindingIsCurrent(
  fields: Pick<SocialCertFields, 'provider' | 'socialAudience'>,
  currentAudience: string,
): boolean {
  const p = SOCIAL_PROVIDERS[fields.provider];
  if (p === undefined) return false;
  if (p.subjectType === 'global') return true;
  return fields.socialAudience === currentAudience;
}

/**
 * A verified social login as ONE signed association, bound to the subject key.
 *
 * The bridge that demotes a provider from "the identity" to a leaf. Because the
 * HOLDER assembles their set locally, whoever ran the OAuth must SIGN — an
 * unsigned `vouchedBy` would be a field the holder types. The subject key is in
 * the preimage (via `signAssociation`), so the leaf is unusable in anyone
 * else's set.
 *
 * The `sub` and its audience stay OUT of the association: operational
 * bookkeeping for the staleness check, not something a verifier who asked for a
 * name should be handed.
 */
export function socialAssociation(
  fields: Pick<SocialCertFields, 'provider' | 'userName'>,
  voucherSk: PrivateKey,
  subjectPublicKey: string,
): Association {
  const kind = SOCIAL_PROVIDERS[fields.provider].kind;
  return {
    kind,
    display: fields.userName,
    vouchedBy: voucherSk.toPublicKey().toString(),
    signature: signAssociation(voucherSk, subjectPublicKey, kind, fields.userName),
  };
}

/** The set of social-provider kinds, for recognising social leaves in a set. */
const SOCIAL_KINDS: ReadonlySet<string> = new Set(
  Object.values(SOCIAL_PROVIDERS).map((p) => p.kind),
);

/**
 * Distinct social platforms vouching for a key — the "proof of human" aggregate.
 *
 * The insight the user's phrasing carries: identity is composed from edges, and
 * humanity is not any single edge but their BREADTH. One bot makes one throwaway
 * account cheaply; aged, real accounts across LinkedIn AND GitHub AND Google AND
 * X, all bound to one key at once, are expensive in a way that scales against a
 * sybil. So the evidence is the COUNT OF DISTINCT PROVIDERS, deduplicated by
 * kind — two GitHub leaves are one platform, not two.
 *
 * ⚠️ This counts, it does not judge. It presumes each leaf was already verified
 * (`readDisclosedAssociation` returned it) — it does not re-check signatures. And
 * "evidence of humanity" is not "a verified human": every provider's own
 * disclaimer still holds, and a determined attacker with real accounts still
 * clears any fixed threshold. It raises the cost of a sybil; it does not close
 * the door. Pair it with the boomspace proof-of-human subject, do not replace it.
 */
export function humanityEvidence(
  associations: readonly Pick<Association, 'kind'>[],
): { readonly distinctProviders: number; readonly kinds: readonly string[] } {
  const kinds = Array.from(
    new Set(associations.map((a) => a.kind).filter((k) => SOCIAL_KINDS.has(k))),
  );
  return { distinctProviders: kinds.length, kinds };
}

/** Does a set carry social leaves from at least `threshold` distinct platforms? */
export function meetsHumanityThreshold(
  associations: readonly Pick<Association, 'kind'>[],
  threshold: number,
): boolean {
  return humanityEvidence(associations).distinctProviders >= threshold;
}
