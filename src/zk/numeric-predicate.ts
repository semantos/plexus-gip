/**
 * Self-proven numeric predicates (L1) — the range proof, tied to the predicate
 * grammar, with NO attestor.
 *
 * @experimental UNAUDITED hand-rolled ZK (see `./range-proof` `L1_ZK_STATUS`).
 *
 * L0 (`../social/predicate`) had FamilySearch *sign* a predicate; the buyer
 * trusts the certifier's computation. This proves the SAME grammar of predicate
 * — `gen-depth>=3`, `born-before<=1970` — with a Pedersen commitment + range
 * proof, so the holder proves it *themselves* and nobody is trusted to compute
 * it. Same honest caveat as the primitive: hand-rolled ZK, unaudited (see
 * `./range-proof`).
 *
 * ## How a comparison becomes a range, and why that IS the soundness
 *
 * Commit the true value `v` as `V = v·G + γ·H`, then:
 *   - `v >= t`  ⟺  `(v − t) ∈ [0, 2^bits)`  — verifier derives `V − t·G` and range-checks it.
 *   - `v <= t`  ⟺  `(t − v) ∈ [0, 2^bits)`  — verifier derives `t·G − V` and range-checks it.
 *   - `v == t`  ⟺  both of the above.
 *
 * The prover can only *produce* the range proof when the shifted value is
 * actually ≥ 0 — `proveRange` refuses a negative — so a false predicate cannot be
 * proven. The range's upper bound `2^bits` is an artifact: `v >= t` also asserts
 * `v < t + 2^bits`, which for genealogical metrics (`bits = 16` ⇒ < 65536) is no
 * real restriction. `!=` is a NON-membership statement, not a range, and is
 * refused — it needs a different construction.
 *
 * The commitment carries no identity by itself; bind it to a subject/context at
 * the layer above (a signed association over the commitment point), exactly as
 * every other leaf here is subject-bound.
 */

import type { BigNumber } from '@bsv/sdk';
import { type Predicate, encodePredicate, parsePredicate } from '../social/predicate';
import {
  type Commitment,
  type RangeProof,
  commit,
  negateScalar,
  proveRange,
  shiftCommitment,
  upperShiftCommitment,
  verifyRange,
} from './range-proof';

/** Default range width — 16 bits covers years, ages, and generation counts. */
export const DEFAULT_PREDICATE_BITS = 16;

export interface NumericPredicateProof {
  /** The canonical predicate string proven, e.g. `gen-depth>=3`. */
  readonly predicate: string;
  /** `V = value·G + blinding·H` — the commitment to the true value. */
  readonly commitment: Commitment;
  readonly bits: number;
  /** One range proof for `>=`/`<=`, two for `==` (lower then upper). */
  readonly proofs: readonly RangeProof[];
}

function numericThreshold(p: Predicate): bigint {
  if (!/^[0-9]+$/.test(p.value)) throw new Error(`predicate value is not a non-negative integer: ${p.value}`);
  return BigInt(p.value);
}

/**
 * Self-prove that a predicate holds over the holder's own `actualValue`, with no
 * attestor.
 *
 * @experimental UNAUDITED — see `./range-proof` `L1_ZK_STATUS`.
 *
 * Throws when the predicate is false (the shifted value would be
 * negative), when it is `!=` (not a range), or when the value/threshold is not a
 * non-negative integer — a proof of a false or unsupported statement must be
 * impossible to construct.
 */
export function proveNumericPredicate(
  predicate: Predicate | string,
  actualValue: bigint,
  bits: number = DEFAULT_PREDICATE_BITS,
): NumericPredicateProof {
  const parsed = typeof predicate === 'string' ? parsePredicate(predicate) : predicate;
  if (parsed === null) throw new Error(`malformed predicate: ${String(predicate)}`);
  const canon = encodePredicate(parsed);
  // `!=` is a non-membership statement, not a range — refuse it regardless of the
  // threshold's shape, so the reason is always the honest one.
  if (parsed.op === 'ne') {
    throw new Error('`ne` is a non-membership statement, not a range — not supported by numeric self-proof');
  }
  const t = numericThreshold(parsed);
  if (actualValue < 0n) throw new Error('actualValue must be non-negative');

  const { commitment, opening } = commit(actualValue);
  const negBlind = (): BigNumber => negateScalar(opening.blinding);
  const proofs: RangeProof[] = [];

  switch (parsed.op) {
    case 'gte':
      proofs.push(proveRange({ value: actualValue - t, blinding: opening.blinding }, bits).proof);
      break;
    case 'lte':
      proofs.push(proveRange({ value: t - actualValue, blinding: negBlind() }, bits).proof);
      break;
    case 'eq':
      proofs.push(proveRange({ value: actualValue - t, blinding: opening.blinding }, bits).proof);
      proofs.push(proveRange({ value: t - actualValue, blinding: negBlind() }, bits).proof);
      break;
    default:
      throw new Error(`unsupported op: ${String(parsed.op)}`); // `ne` already refused above
  }

  return { predicate: canon, commitment, bits, proofs };
}

/**
 * Verify a numeric predicate self-proof.
 *
 * @experimental UNAUDITED — see `./range-proof` `L1_ZK_STATUS`.
 *
 * Re-derives the shifted commitment(s)
 * from the committed value and the predicate's threshold — the verifier never
 * needs the value — and range-checks each. Returns false on any malformation.
 */
export function verifyNumericPredicate(p: NumericPredicateProof): boolean {
  try {
    const parsed = parsePredicate(p.predicate);
    if (parsed === null) return false;
    const t = numericThreshold(parsed);

    const lower = (): boolean =>
      p.proofs[0] !== undefined
      && p.proofs[0].bits === p.bits
      && verifyRange(shiftCommitment(p.commitment, t), p.proofs[0]); // (v − t) ∈ [0,2^bits)
    const upper = (idx: number): boolean =>
      p.proofs[idx] !== undefined
      && p.proofs[idx]!.bits === p.bits
      && verifyRange(upperShiftCommitment(p.commitment, t), p.proofs[idx]!); // (t − v) ∈ [0,2^bits)

    switch (parsed.op) {
      case 'gte':
        return p.proofs.length === 1 && lower();
      case 'lte':
        return p.proofs.length === 1 && upper(0);
      case 'eq':
        return p.proofs.length === 2 && lower() && upper(1);
      default:
        return false; // `ne` and anything else are not provable this way
    }
  } catch {
    return false;
  }
}
