/**
 * Per-field intra-tx Merkle tree primitive.
 *
 * CW Lift L8 (docs/canon/cw-lift-matrix.yml).
 *
 * Semantos commits cell payloads as a whole (via cell-pushdrop or one
 * of the L13 carrier variants) and pins the payload integrity in
 * `cellHeader.domainPayloadRoot` as a single SHA-256 of the bytes.
 * That's sufficient when the verifier needs the whole payload.
 *
 * This module adds the FIELD-tree shape: each field of a structured
 * payload (think: an invoice with `amount`, `vat`, `lineitem[i].sku`,
 * etc.) becomes a leaf in a Merkle tree, and the root is what gets
 * committed. The selective-disclosure benefit: a verifier can be shown
 * ONE field's value + the Merkle path to the root WITHOUT being shown
 * the other fields. The unrevealed fields stay as sibling hashes.
 *
 * Where this slots in:
 *   - The field-tree root is a candidate value for `domainPayloadRoot`
 *     when the payload is structured (vs an opaque blob). The same
 *     cell-pushdrop / OP_FALSE OP_IF / OP_DROP P2PKH carrier (L13)
 *     puts the cell on chain; verification (L4) walks the same path.
 *   - The L9 scoped-disclosure envelope (Tier 2 lift) is what
 *     AUTHORISES disclosure of a specific field to a specific verifier;
 *     this primitive is what makes that disclosure CHECKABLE.
 *
 * Source repos (both MIT):
 *   - prof-faustus/verifiable-accounting-bsv @ packages/evidence/src/fieldtree.ts
 *     (per-field leaves, "VARP" magic, schema-versioned)
 *   - prof-faustus/triple-entry-bsv-sql @ crypto-core/go/keystone.go
 *     (the ECDH-HMAC keystone — provides the per-field commitment
 *      pattern; not adopted wholesale here because the field-tree is
 *      the simpler primitive — adopt that pattern in L9/L10/L12.)
 *
 * Schema-fingerprint binding: the leaf hash includes the schema's
 * fingerprint so the same fields under different schemas produce
 * different roots. Caller picks the fingerprint (typically a 32-byte
 * SHA-256 of the canonical schema-definition bytes).
 *
 * Field ordering: leaves are sorted by canonical label (UTF-8
 * lexicographic, ascending). Two callers with the same set of
 * (label, value) pairs compute the same root regardless of input order.
 */

import { createHash } from 'node:crypto';

// ── Domain separator + magic ──────────────────────────────────────

/**
 * "VARP" magic — Versioned Anchored Record Payload. Identifies this
 * field-tree wire format. 4 bytes, ASCII.
 */
export const FIELD_TREE_MAGIC = new Uint8Array([0x56, 0x41, 0x52, 0x50]); // "VARP"

/** Wire-format version. Bumped only when the leaf-hash preimage shape
 *  changes; downstream-stored field trees are invalidated when this
 *  version changes. */
export const FIELD_TREE_VERSION = 1 as const;

/** Domain separator string for leaf hash inputs. Prevents cross-
 *  protocol collision (anchor-attestation v2 uses
 *  `computeDomainPayloadRoot`, batchId uses
 *  `"semantos.anchor.batch/v1"`, etc.) */
export const FIELD_TREE_DOMAIN = 'semantos.field-tree/v1' as const;

// ── Types ────────────────────────────────────────────────────────

/** A single field — caller supplies the canonical bytes for its value.
 *  Callers wanting structured values (numbers, JSON, etc.) canonicalise
 *  to bytes themselves; this primitive treats values as opaque. */
export interface FieldLeaf {
  /** UTF-8 label. Sorted ascending by these to define canonical order. */
  label: string;
  /** Canonical bytes for this field's value. */
  value: Uint8Array;
}

/** A built field-tree. Roots are 32 bytes (SHA-256). */
export interface FieldTree {
  /** Caller-supplied 32B schema fingerprint. Binds the tree to a
   *  specific schema-definition. */
  readonly schemaFingerprint: Uint8Array;
  /** 32B Merkle root of the leaf hashes. */
  readonly root: Uint8Array;
  /** Number of fields in the tree. */
  readonly leafCount: number;
  /** Sorted-canonical field list with per-field commitment (= leaf hash).
   *  Order matches the leaf order in the Merkle tree. */
  readonly fields: readonly { label: string; commitment: Uint8Array }[];
}

/** A disclosure proof: enough material for a verifier to confirm that
 *  `(label, value)` is part of a tree with the supplied root, without
 *  seeing the other fields. */
export interface FieldDisclosureProof {
  /** 32B schema fingerprint — must match the tree's. */
  readonly schemaFingerprint: Uint8Array;
  /** The field being disclosed. */
  readonly label: string;
  readonly value: Uint8Array;
  /** Leaf hash recomputed by the verifier from (label, value, schemaFingerprint).
   *  Carried in the proof for convenience; verifier MUST recompute. */
  readonly commitment: Uint8Array;
  /** Position of the leaf in the canonically-sorted tree. */
  readonly leafIndex: number;
  /** Sibling hashes from leaf to root. Each carries its position. */
  readonly siblings: readonly { hash: Uint8Array; position: 'left' | 'right' }[];
  /** The root the proof walks to. Verifier compares against the
   *  trusted root (typically from the cell header's domainPayloadRoot
   *  or from an L9 envelope). */
  readonly root: Uint8Array;
}

// ── Leaf hash ────────────────────────────────────────────────────

/**
 * Per-field leaf hash:
 *
 *   leaf = SHA-256(
 *     FIELD_TREE_MAGIC (4B "VARP")
 *     || u8(FIELD_TREE_VERSION)
 *     || varint(|domain|) || domain                  (= "semantos.field-tree/v1")
 *     || varint(|schemaFingerprint|) || schemaFingerprint  (32B)
 *     || varint(|label.utf8|) || label.utf8
 *     || varint(|value|) || value
 *   )
 *
 * The domain separator + magic + version prevent cross-protocol +
 * cross-version collision. The schema fingerprint binds the leaf to a
 * specific schema-definition.
 */
export function computeFieldLeaf(
  schemaFingerprint: Uint8Array,
  field: FieldLeaf,
): Uint8Array {
  assertSchemaFp(schemaFingerprint);
  const h = createHash('sha256');
  h.update(FIELD_TREE_MAGIC);
  h.update(Uint8Array.of(FIELD_TREE_VERSION));
  const domainBytes = new TextEncoder().encode(FIELD_TREE_DOMAIN);
  h.update(varint(domainBytes.length));
  h.update(domainBytes);
  h.update(varint(schemaFingerprint.byteLength));
  h.update(schemaFingerprint);
  const labelBytes = new TextEncoder().encode(field.label);
  h.update(varint(labelBytes.length));
  h.update(labelBytes);
  h.update(varint(field.value.byteLength));
  h.update(field.value);
  return new Uint8Array(h.digest());
}

// ── Tree construction ────────────────────────────────────────────

/**
 * Build a field tree from an unordered set of fields. Leaves are
 * sorted by label (UTF-8 lex ascending) — two callers with the same
 * (label, value) set compute the same root regardless of submission
 * order.
 *
 * Throws if:
 *   - fields is empty
 *   - two fields share the same label
 *   - schemaFingerprint is not 32 bytes
 */
export function buildFieldTree(
  schemaFingerprint: Uint8Array,
  fields: readonly FieldLeaf[],
): FieldTree {
  assertSchemaFp(schemaFingerprint);
  if (fields.length === 0) {
    throw new Error('buildFieldTree: fields must be non-empty');
  }
  // Detect duplicate labels (silent dedup would hide structural bugs).
  const seen = new Set<string>();
  for (const f of fields) {
    if (seen.has(f.label)) {
      throw new Error(`buildFieldTree: duplicate label "${f.label}"`);
    }
    seen.add(f.label);
  }
  // Sort canonical
  const sorted = [...fields].sort((a, b) =>
    a.label < b.label ? -1 : a.label > b.label ? 1 : 0,
  );
  // Per-field leaf hashes
  const leaves = sorted.map(f => computeFieldLeaf(schemaFingerprint, f));
  const root = computeMerkleRoot(leaves);
  return {
    schemaFingerprint: copy(schemaFingerprint),
    root,
    leafCount: sorted.length,
    fields: sorted.map((f, i) => ({ label: f.label, commitment: leaves[i] })),
  };
}

// ── Disclosure ──────────────────────────────────────────────────

/**
 * Build a disclosure proof for ONE field of the tree. The returned
 * proof can be handed to a verifier (along with the trusted root); the
 * verifier sees the disclosed field's (label, value) but only the
 * SIBLING HASHES of the other fields — not their values.
 *
 * Throws if `label` is not in the tree.
 */
export function discloseField(
  schemaFingerprint: Uint8Array,
  fields: readonly FieldLeaf[],
  label: string,
): FieldDisclosureProof {
  // Rebuild the tree (cheap, deterministic) to get sorted order + leaves
  const tree = buildFieldTree(schemaFingerprint, fields);
  const leafIndex = tree.fields.findIndex(f => f.label === label);
  if (leafIndex < 0) {
    throw new Error(`discloseField: label "${label}" not in tree`);
  }
  const target = fields.find(f => f.label === label)!;
  const leaves = tree.fields.map(f => f.commitment);
  const proof = computeMerkleProof(leaves, leafIndex);
  return {
    schemaFingerprint: copy(schemaFingerprint),
    label,
    value: copy(target.value),
    commitment: tree.fields[leafIndex].commitment,
    leafIndex,
    siblings: proof.siblings,
    root: copy(tree.root),
  };
}

/**
 * Verify a disclosure proof against a trusted root.
 *
 *   1. Recompute the leaf hash from (schemaFingerprint, label, value)
 *      and assert it matches `proof.commitment`.
 *   2. Walk the Merkle path from leaf via siblings to a computed root.
 *   3. Assert computed root === proof.root === expectedRoot.
 *
 * Returns true on success; never throws (caller may want to log the
 * disclosure attempt without aborting the request).
 */
export function verifyFieldDisclosure(
  proof: FieldDisclosureProof,
  expectedRoot: Uint8Array,
): boolean {
  try {
    if (!bytesEqual(proof.root, expectedRoot)) return false;
    const recomputedLeaf = computeFieldLeaf(proof.schemaFingerprint, {
      label: proof.label,
      value: proof.value,
    });
    if (!bytesEqual(recomputedLeaf, proof.commitment)) return false;
    let cur = recomputedLeaf;
    for (const sib of proof.siblings) {
      const pair =
        sib.position === 'right'
          ? concat(cur, sib.hash)
          : concat(sib.hash, cur);
      cur = sha256(pair);
    }
    return bytesEqual(cur, expectedRoot);
  } catch {
    return false;
  }
}

// ── Merkle helpers (BSV double-SHA-256 convention is used by the
//    L4 / cell-ops merkle path; the field-tree uses plain SHA-256 once
//    because the leaf is already a hash. See merkleEnvelope.ts for the
//    on-chain BUMP convention.) ────────────────────────────────────

function computeMerkleRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) throw new Error('computeMerkleRoot: empty');
  if (leaves.length === 1) return copy(leaves[0]);
  let level = leaves.map(copy);
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i];
      const r = i + 1 < level.length ? level[i + 1] : level[i]; // odd → duplicate last
      next.push(sha256(concat(l, r)));
    }
    level = next;
  }
  return level[0];
}

function computeMerkleProof(
  leaves: Uint8Array[],
  leafIndex: number,
): { siblings: { hash: Uint8Array; position: 'left' | 'right' }[] } {
  if (leafIndex < 0 || leafIndex >= leaves.length) {
    throw new Error('computeMerkleProof: leafIndex out of bounds');
  }
  const siblings: { hash: Uint8Array; position: 'left' | 'right' }[] = [];
  let idx = leafIndex;
  let level = leaves.map(copy);
  while (level.length > 1) {
    const sibIdx = idx ^ 1; // toggle low bit
    const sibHash = sibIdx < level.length ? level[sibIdx] : level[idx]; // duplicate on odd-end
    siblings.push({
      hash: copy(sibHash),
      position: sibIdx > idx ? 'right' : 'left',
    });
    // Compute the next level
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i];
      const r = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(sha256(concat(l, r)));
    }
    level = next;
    idx = Math.floor(idx / 2);
  }
  return { siblings };
}

// ── Internal helpers ─────────────────────────────────────────────

function assertSchemaFp(fp: Uint8Array): void {
  if (fp.byteLength !== 32) {
    throw new Error(`schemaFingerprint must be 32 bytes, got ${fp.byteLength}`);
  }
}

function sha256(b: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(b).digest());
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(a, 0);
  out.set(b, a.byteLength);
  return out;
}

function copy(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b.byteLength);
  out.set(b);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
  return true;
}

function varint(n: number): Uint8Array {
  if (n < 0 || !Number.isInteger(n)) {
    throw new Error(`varint: must be non-negative integer, got ${n}`);
  }
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) {
    const b = new Uint8Array(3);
    b[0] = 0xfd;
    b[1] = n & 0xff;
    b[2] = (n >>> 8) & 0xff;
    return b;
  }
  if (n <= 0xffffffff) {
    const b = new Uint8Array(5);
    b[0] = 0xfe;
    b[1] = n & 0xff;
    b[2] = (n >>> 8) & 0xff;
    b[3] = (n >>> 16) & 0xff;
    b[4] = (n >>> 24) & 0xff;
    return b;
  }
  throw new Error(`varint: value ${n} exceeds u32; not supported`);
}
