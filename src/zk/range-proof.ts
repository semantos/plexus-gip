/**
 * Range proofs over Pedersen commitments — L1 of the predicate-proof ladder.
 *
 * @experimental UNAUDITED. See {@link L1_ZK_STATUS}. Not for production use until
 * a cryptographer has reviewed the construction.
 *
 * ⚠️ HAND-ROLLED ZERO-KNOWLEDGE CRYPTOGRAPHY. Read this before trusting it.
 *
 * This lets a holder prove a committed integer lies in `[0, 2^bits)` WITHOUT
 * revealing it and WITHOUT any attestor — the "self-provable numeric predicate"
 * rung of `docs/design/GIP-V2-PREDICATE-PROOFS.md`. Unlike L0, no one is trusted
 * to compute the property; unlike a signed attestation, "my tests pass" does NOT
 * establish soundness. **This construction has NOT been externally audited and
 * must be reviewed by a cryptographer before it guards anything of value.** It
 * is built to a standard, textbook sigma-protocol design precisely so that its
 * soundness can be argued, not merely demonstrated on happy-path inputs.
 *
 * ## Why a sigma-protocol range proof, not the literal Bulletproof
 *
 * The scoping note names "Bulletproofs" for this rung. A from-scratch
 * Bulletproofs *inner-product argument* is O(log n)-sized but has many places to
 * be subtly, silently unsound, and I cannot verify it correct without reference
 * test vectors. This delivers the SAME capability — Pedersen commitment + range
 * self-proof, no trusted setup, on secp256k1 — via a **bit-decomposition +
 * Schnorr-OR** proof whose every piece is a standard sigma protocol. The cost is
 * O(n) proof size instead of O(log n); for genealogical ranges (n ≤ 16 bits:
 * ages, birth years, generation counts) that is nothing. `RangeProof` is an
 * opaque interface, so a vetted Bulletproof can replace the internals later
 * without changing callers.
 *
 * ## The construction, and why it is sound
 *
 * A Pedersen commitment `V = v·G + γ·H`, where `H` is a nothing-up-my-sleeve
 * generator whose discrete log w.r.t. `G` is unknown (derived by hashing a fixed
 * domain to a curve point). Because dlog_G(H) is unknown, a commitment is
 * binding: you cannot open `V` to a different `v'` without solving a DL.
 *
 * To prove `v ∈ [0, 2^bits)`:
 *   1. Commit each bit `B_i = b_i·G + r_i·H` with fresh random `r_i`.
 *   2. Prove each `b_i ∈ {0,1}` with a CDS OR-proof: knowledge of `r` s.t.
 *      `B_i = r·H` (bit 0) OR `B_i − G = r·H` (bit 1). One branch is real, the
 *      other simulated; the Fiat-Shamir challenge splits additively.
 *   3. Prove `D = V − Σ 2^i·B_i` has NO G-component: a base-`H` Schnorr proof of
 *      knowledge of `δ = dlog_H(D)`. If the bits summed to `v`, `D = (γ − Σ2^i r_i)·H`
 *      and the prover knows `δ`. If they did NOT, `D` carries a nonzero G-term and
 *      the prover would need dlog_G(H) to answer — which the NUMS `H` denies. So a
 *      valid proof forces `Σ b_i 2^i = v`, hence `v ∈ [0, 2^bits)`.
 *
 * No modular inverse is needed anywhere (the consistency step absorbs the blinding
 * difference into `δ` rather than solving for a last bit), which removes one whole
 * class of implementation bug.
 *
 * ## What it does NOT do
 *
 * - It is not unlinkable across presentations: the same commitment re-presented
 *   is recognisable. Re-blind (fresh `γ`) per audience if that matters.
 * - It proves a range, not identity; bind the commitment to a subject/context at
 *   the layer above (`./numeric-predicate`).
 */

import { BigNumber, Curve, Hash, Point } from '@bsv/sdk';

/**
 * Status of this module's zero-knowledge code.
 *
 * @experimental Hand-rolled and NOT externally audited. Any caller placing this
 * on a trust path should assert on this value, so the choice to rely on
 * unaudited crypto is explicit and greppable rather than accidental.
 */
export const L1_ZK_STATUS = 'experimental-unaudited' as const;

const curve = new Curve();
const G: Point = curve.g;
/** Curve group order. All scalars live in [0, N). */
const N: BigNumber = curve.n;

// ── scalar helpers (mod N) ──────────────────────────────────────────────────
const sMod = (a: BigNumber): BigNumber => a.umod(N);
const sAdd = (a: BigNumber, b: BigNumber): BigNumber => sMod(a.add(b));
const sSub = (a: BigNumber, b: BigNumber): BigNumber => sMod(a.sub(b));
const sMul = (a: BigNumber, b: BigNumber): BigNumber => sMod(a.mul(b));
const bnFromBigint = (v: bigint): BigNumber => new BigNumber(v.toString(10), 10);
const two = (i: number): BigNumber => bnFromBigint(2n ** BigInt(i));

/** A uniformly random non-zero scalar in [1, N). */
function randScalar(): BigNumber {
  for (;;) {
    const s = sMod(new BigNumber(Array.from(crypto.getRandomValues(new Uint8Array(32)))));
    if (!s.isZero()) return s;
  }
}

const enc = (p: Point): string => p.encode(true, 'hex') as string;
const decode = (hex: string): Point => Point.fromString(hex);

/**
 * The second Pedersen generator `H`, nothing-up-my-sleeve.
 *
 * Try-and-increment: hash a fixed domain (+counter) to an x-coordinate and take
 * the first that lies on the curve. Its discrete log w.r.t. `G` is therefore
 * nobody's to know — the property the commitment's binding rests on. Computed
 * once, deterministically.
 */
function deriveH(): Point {
  const domain = 'semantos/zk/pedersen-H/secp256k1/v1';
  for (let i = 0; i < 256; i++) {
    const x = new BigNumber(Hash.sha256(Array.from(new TextEncoder().encode(`${domain}:${i}`))));
    try {
      return Point.fromX(sMod(x), false);
    } catch {
      /* x not on curve — increment */
    }
  }
  throw new Error('unreachable: no H generator found in 256 tries');
}
const H: Point = deriveH();

/** Fiat-Shamir challenge: hash a label + points to a scalar mod N. */
function challenge(label: string, points: readonly Point[]): BigNumber {
  const bytes = Array.from(new TextEncoder().encode(label));
  for (const p of points) for (const b of p.encode(true) as number[]) bytes.push(b);
  return sMod(new BigNumber(Hash.sha256(bytes)));
}

/** A Pedersen commitment and, kept private by the prover, its opening. */
export interface Commitment {
  /** `V = value·G + blinding·H`, compressed hex. */
  readonly point: string;
}
export interface Opening {
  readonly value: bigint;
  readonly blinding: BigNumber;
}

/** Commit to a non-negative integer. Returns the commitment and its opening. */
export function commit(value: bigint, blinding: BigNumber = randScalar()): { commitment: Commitment; opening: Opening } {
  if (value < 0n) throw new Error('value must be non-negative');
  const V = G.mul(bnFromBigint(value)).add(H.mul(blinding));
  return { commitment: { point: enc(V) }, opening: { value, blinding } };
}

// ── CDS OR-proof: B commits to 0 or 1 ───────────────────────────────────────
interface OrProof {
  readonly a0: string; readonly a1: string;
  readonly e0: string; readonly e1: string;
  readonly z0: string; readonly z1: string;
}

/** Prove B = bit·G + r·H with bit ∈ {0,1}, knowing (bit, r). `stmt` binds context. */
function proveBit(stmt: string, i: number, B: Point, bit: 0 | 1, r: BigNumber): OrProof {
  // Branch 0 proves B = r·H; branch 1 proves (B − G) = r·H.
  const P: [Point, Point] = [B, B.add(G.neg())];
  const t = bit; // true branch
  const f = (1 - bit) as 0 | 1; // false branch

  // Simulate the false branch: pick z_f, e_f; A_f = z_f·H − e_f·P_f.
  const zF = randScalar();
  const eF = randScalar();
  const AF = H.mul(zF).add(P[f].mul(eF).neg());

  // Real commitment for the true branch.
  const kT = randScalar();
  const AT = H.mul(kT);

  const A: Point[] = [];
  A[t] = AT; A[f] = AF;
  const c = challenge(`${stmt}|bit:${i}`, [B, A[0]!, A[1]!]);
  const eT = sSub(c, eF);
  const zT = sAdd(kT, sMul(eT, r));

  const e: BigNumber[] = []; const z: BigNumber[] = [];
  e[t] = eT; e[f] = eF; z[t] = zT; z[f] = zF;
  return {
    a0: enc(A[0]!), a1: enc(A[1]!),
    e0: e[0]!.toHex(), e1: e[1]!.toHex(),
    z0: z[0]!.toHex(), z1: z[1]!.toHex(),
  };
}

function verifyBit(stmt: string, i: number, B: Point, pr: OrProof): boolean {
  try {
    const A0 = decode(pr.a0); const A1 = decode(pr.a1);
    const e0 = BigNumber.fromHex(pr.e0); const e1 = BigNumber.fromHex(pr.e1);
    const z0 = BigNumber.fromHex(pr.z0); const z1 = BigNumber.fromHex(pr.z1);
    // The challenge must split: e0 + e1 ≡ c. A prover who controlled both
    // branches' challenges could forge, so this equality is the crux.
    const c = challenge(`${stmt}|bit:${i}`, [B, A0, A1]);
    if (!sAdd(e0, e1).eq(sMod(c))) return false;
    const P0 = B; const P1 = B.add(G.neg());
    // z_j·H == A_j + e_j·P_j for both branches.
    const lhs0 = H.mul(z0); const rhs0 = A0.add(P0.mul(e0));
    const lhs1 = H.mul(z1); const rhs1 = A1.add(P1.mul(e1));
    return lhs0.eq(rhs0) && lhs1.eq(rhs1);
  } catch {
    return false;
  }
}

// ── base-H Schnorr: D = δ·H (D has no G-component) ──────────────────────────
interface SchnorrH {
  readonly a: string; readonly z: string;
}
function proveDlogH(stmt: string, D: Point, delta: BigNumber): SchnorrH {
  const k = randScalar();
  const A = H.mul(k);
  const e = challenge(`${stmt}|consistency`, [D, A]);
  const z = sAdd(k, sMul(e, delta));
  return { a: enc(A), z: z.toHex() };
}
function verifyDlogH(stmt: string, D: Point, pr: SchnorrH): boolean {
  try {
    const A = decode(pr.a); const z = BigNumber.fromHex(pr.z);
    const e = challenge(`${stmt}|consistency`, [D, A]);
    return H.mul(z).eq(A.add(D.mul(e)));
  } catch {
    return false;
  }
}

// ── the range proof ─────────────────────────────────────────────────────────
export interface RangeProof {
  readonly bits: number;
  /** Per-bit commitments B_i, compressed hex. */
  readonly bitCommitments: readonly string[];
  readonly bitProofs: readonly OrProof[];
  readonly consistency: SchnorrH;
}

/** A statement id binding a proof to its commitment + range, so a proof for one cannot be replayed for another. */
function statementId(V: Point, bits: number): string {
  return `semantos/zk/range/v1|bits:${bits}|V:${enc(V)}`;
}

/**
 * Prove the committed `value` lies in `[0, 2^bits)`.
 *
 * @experimental UNAUDITED — see {@link L1_ZK_STATUS}.
 *
 * Requires the opening (value + blinding) — this is a proof BY the committer.
 * Throws if the value does not actually fit `bits`; a range proof of a false
 * statement must be impossible to produce, and refusing here is the honest place
 * to stop (the protocol itself also could not produce a verifying one).
 */
export function proveRange(opening: Opening, bits: number): { commitment: Commitment; proof: RangeProof } {
  if (bits <= 0 || bits > 32) throw new Error('bits must be in 1..32');
  const { value, blinding } = opening;
  if (value < 0n || value >= 2n ** BigInt(bits)) {
    throw new Error(`value ${value} is not in [0, 2^${bits})`);
  }
  const V = G.mul(bnFromBigint(value)).add(H.mul(blinding));
  const stmt = statementId(V, bits);

  const Bs: Point[] = [];
  const rs: BigNumber[] = [];
  const bitProofs: OrProof[] = [];
  for (let i = 0; i < bits; i++) {
    const bit = ((value >> BigInt(i)) & 1n) === 1n ? 1 : 0;
    const r = randScalar();
    // B_i = bit·G + r·H  (bit is 0 or 1)
    const Bi = bit === 1 ? G.add(H.mul(r)) : H.mul(r);
    Bs.push(Bi);
    rs.push(r);
    bitProofs.push(proveBit(stmt, i, Bi, bit, r));
  }

  // D = V − Σ 2^i B_i ; δ = γ − Σ 2^i r_i  (so D = δ·H exactly).
  let sumB: Point | null = null;
  let delta = blinding;
  for (let i = 0; i < bits; i++) {
    const term = Bs[i]!.mul(two(i));
    sumB = sumB === null ? term : sumB.add(term);
    delta = sSub(delta, sMul(two(i), rs[i]!));
  }
  const D = sumB === null ? V : V.add(sumB.neg());
  const consistency = proveDlogH(stmt, D, delta);

  return {
    commitment: { point: enc(V) },
    proof: { bits, bitCommitments: Bs.map(enc), bitProofs, consistency },
  };
}

/**
 * Verify that `commitment` opens to some value in `[0, 2^proof.bits)`.
 * @experimental UNAUDITED — see {@link L1_ZK_STATUS}.
 */
export function verifyRange(commitment: Commitment, proof: RangeProof): boolean {
  try {
    if (proof.bits <= 0 || proof.bits > 32) return false;
    if (proof.bitCommitments.length !== proof.bits || proof.bitProofs.length !== proof.bits) return false;
    const V = decode(commitment.point);
    const stmt = statementId(V, proof.bits);
    const Bs = proof.bitCommitments.map(decode);

    for (let i = 0; i < proof.bits; i++) {
      if (!verifyBit(stmt, i, Bs[i]!, proof.bitProofs[i]!)) return false;
    }
    let sumB: Point | null = null;
    for (let i = 0; i < proof.bits; i++) {
      const term = Bs[i]!.mul(two(i));
      sumB = sumB === null ? term : sumB.add(term);
    }
    const D = sumB === null ? V : V.add(sumB.neg());
    return verifyDlogH(stmt, D, proof.consistency);
  } catch {
    return false;
  }
}

/** Homomorphic shift: the commitment to `value − k` (blinding unchanged), given V. Underpins `v ≥ k`. */
export function shiftCommitment(commitment: Commitment, k: bigint): Commitment {
  const V = decode(commitment.point);
  const shifted = k >= 0n ? V.add(G.mul(bnFromBigint(k)).neg()) : V.add(G.mul(bnFromBigint(-k)));
  return { point: enc(shifted) };
}

/** The commitment to `k − value` (blinding negated), i.e. `k·G − V`. Underpins `v ≤ k`. */
export function upperShiftCommitment(commitment: Commitment, k: bigint): Commitment {
  const V = decode(commitment.point);
  return { point: enc(G.mul(bnFromBigint(k)).add(V.neg())) };
}

/** Negate a scalar mod the curve order — the blinding for `k − value` given the blinding for `value`. */
export function negateScalar(s: BigNumber): BigNumber {
  return s.isZero() ? s : sSub(N, s);
}

export { randScalar, N as CURVE_ORDER };
