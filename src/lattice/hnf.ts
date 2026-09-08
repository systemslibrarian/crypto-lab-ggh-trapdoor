/**
 * The Hermite normal form public key (Micciancio, CaLC 2001).
 *
 * WHY THIS FILE IS THE ONE THAT USES BigInt.
 *
 * Everywhere else in this lab, exact integers live in doubles and there is an
 * enormous margin: the largest intermediate value anywhere in keygen, round-off
 * or the I1 proof was measured at 3.4e4 against 2^53 = 9.007e15. The HNF is not
 * like that, and it cannot be made like that, because of one identity:
 *
 *     prod_i H[i][i] = |det R|
 *
 * The diagonal of the HNF multiplies to the determinant of the lattice. That is
 * not an implementation detail to be optimised away -- it is what the HNF *is*.
 * Measured at this lab's shipped keygen (k = ceil(2*l*sqrt(n)) + 4l), mean over
 * 8 keys per dimension:
 *
 *     n                                   8      16     32      60
 *     log10|det R|                      12.75  26.88  57.40  113.53
 *     largest HNF entry fits in 2^53?    yes     no     no      no
 *
 * log10(2^53) = 15.95, so at n=60 the HNF carries entries 97.6 orders of
 * magnitude past what a double can hold exactly. The crossover was measured, not
 * assumed: the HNF still fits in Number for 8 of 8 keys at n = 8 and n = 9, for
 * 2 of 8 at n = 10, and for none from n = 11 up. The lab's slider starts at 8,
 * so BigInt is required across almost the whole of its own range.
 *
 * (Under GGH's own k = round(sqrt(n)*l) the determinant is 10^89.2 at n=60
 * instead of 10^113.5 -- still 73 orders past 2^53. The k rule changes the
 * number; it does not change the verdict.)
 *
 * A double would not throw here. It would return a finite, wrong, non-integer
 * value and every downstream check would quietly become a lie. So this file is
 * BigInt end to end, including its own same-lattice proof.
 *
 * COEFFICIENT EXPLOSION AND THE MODULO-DETERMINANT FIX.
 *
 * Naive integer HNF is famous for intermediate entries far larger than anything
 * in the input or the output. The fix used here is the classical one (Domich,
 * Kannan and Trotter 1987): compute d = |det R| first by fraction-free (Bareiss)
 * elimination, then run the elimination with every entry reduced modulo d. This
 * is sound because d*Z^n is a sublattice of L(R) -- adj(R)*R = det(R)*I gives
 * d*e_c in L(R) for every c -- so subtracting a multiple of d*e_c from a row
 * subtracts a lattice vector and cannot leave the lattice. Every intermediate is
 * then bounded by d, and the whole computation is n^3 BigInt operations on
 * numbers of at most 114 decimal digits at n=60.
 *
 * CONVENTION -- stated once, used everywhere in this file.
 *
 * The lab is a ROW lattice: L(B) = { x*B }, rows of B are basis vectors. The HNF
 * here is therefore ROW-STYLE and UPPER TRIANGULAR, obtained by clearing one
 * COLUMN at a time with integer row operations (left multiplication by a
 * unimodular matrix, which is exactly what preserves a row lattice):
 *
 *     H[i][j] = 0                for j < i      (upper triangular)
 *     H[i][i] > 0                               (positive pivots)
 *     0 <= H[j][i] < H[i][i]     for j < i      (reduced above each pivot)
 *
 * Micciancio writes column lattices and gets the lower-triangular transpose of
 * this; the two conventions are the same theorem. `isHnf` checks all three
 * conditions above, and the uniqueness theorem says any matrix satisfying them
 * that generates L is THE HNF of L -- which is what makes the canonicity test in
 * hnf.test.ts a proof rather than a coincidence.
 *
 * WALL CLOCK -- measured, Apple M5, Node v26.5.0, median of 5 warmed runs.
 *
 *     n        hnf()   proveSameLatticeHnf()   total
 *     8        0.09    0.08                    0.17 ms
 *     16       0.51    0.59                    1.10 ms
 *     32       3.9     4.6                     8.5  ms
 *     60       34      34                      68   ms
 *
 * Nothing here needs a Web Worker. 68 ms at the top dimension is four frames --
 * visible if it ran every keystroke, invisible for a one-shot key operation. The
 * numbers are exported as `MEASURED_HNF_MS` with `estimateHnfMs` so the UI gates
 * on a measurement rather than on a guess; see the note there about extrapolation.
 */

import type { Mat, Vec } from './types';
import { TWO53 } from './matrix';

/** A dense BigInt matrix as an array of rows. Rows are basis vectors, as elsewhere. */
export type BigMat = bigint[][];

/** A dense BigInt row vector. */
export type BigVec = bigint[];

/** |x| for bigint. */
function babs(x: bigint): bigint {
  return x < 0n ? -x : x;
}

/** x mod d, always in [0, d). BigInt `%` keeps the sign of the dividend, which is not what we want. */
function emod(x: bigint, d: bigint): bigint {
  const r = x % d;
  return r < 0n ? r + d : r;
}

// ---------------------------------------------------------------------------
// Number <-> BigInt conversion, with the guard that makes the boundary honest
// ---------------------------------------------------------------------------

/**
 * Lift a Number matrix to BigInt.
 *
 * Rejects any entry that is not already an exact integer within 2^53. `BigInt()`
 * would throw a bare RangeError on a fractional double; this throws with the
 * offending position, because at this boundary a silent or unhelpful failure is
 * the whole risk.
 */
export function toBigMat(A: Mat): BigMat {
  const out: BigMat = [];
  for (let i = 0; i < A.length; i++) {
    const row: bigint[] = new Array<bigint>(A[i].length);
    for (let j = 0; j < A[i].length; j++) {
      const v = A[i][j];
      if (!Number.isSafeInteger(v)) {
        throw new Error(`toBigMat: entry [${i}][${j}] = ${v} is not an exact integer within 2^53`);
      }
      row[j] = BigInt(v);
    }
    out.push(row);
  }
  return out;
}

/** Lift a Number vector to BigInt, with the same guard. */
export function toBigVec(v: Vec): BigVec {
  const out: bigint[] = new Array<bigint>(v.length);
  for (let i = 0; i < v.length; i++) {
    if (!Number.isSafeInteger(v[i])) {
      throw new Error(`toBigVec: entry [${i}] = ${v[i]} is not an exact integer within 2^53`);
    }
    out[i] = BigInt(v[i]);
  }
  return out;
}

/** Accept either representation. Lets the UI hand a `Mat` straight to `hnf`. */
export function asBigMat(A: Mat | BigMat): BigMat {
  const out: BigMat = [];
  for (const row of A) {
    if (row instanceof Float64Array) {
      const r: bigint[] = new Array<bigint>(row.length);
      for (let j = 0; j < row.length; j++) {
        if (!Number.isSafeInteger(row[j])) {
          throw new Error(`asBigMat: entry ${row[j]} is not an exact integer within 2^53`);
        }
        r[j] = BigInt(row[j]);
      }
      out.push(r);
    } else {
      out.push(row.slice());
    }
  }
  return out;
}

/** Largest absolute entry, as a bigint (it will not fit in a Number and must not be coerced). */
export function bigMaxAbs(A: BigMat): bigint {
  let m = 0n;
  for (const r of A) for (const v of r) { const a = babs(v); if (a > m) m = a; }
  return m;
}

/**
 * Can this matrix be brought back to Number without losing exactness?
 *
 * Ask this before `fromBigMat`, which refuses. For an HNF this is false from
 * n = 10 up -- see the file header -- so the UI must render HNF entries from
 * their decimal strings, never from a coerced double.
 */
export function bigFitsInNumber(A: BigMat): boolean {
  const cap = BigInt(TWO53);
  for (const r of A) for (const v of r) if (babs(v) > cap) return false;
  return true;
}

/**
 * Bring a BigInt matrix back to Number -- and REFUSE if any entry exceeds 2^53.
 *
 * This guard is the point of the function. `Number(10n ** 113n)` returns a
 * finite double happily; it is simply not that integer any more. Silently
 * accepting it would put a wrong value into the same `Mat` type the exact I1
 * proof consumes, so the only safe behaviour at this boundary is to throw.
 */
export function fromBigMat(A: BigMat): Mat {
  const cap = BigInt(TWO53);
  const out: Mat = [];
  for (let i = 0; i < A.length; i++) {
    const row = new Float64Array(A[i].length);
    for (let j = 0; j < A[i].length; j++) {
      const v = A[i][j];
      if (babs(v) > cap) {
        throw new Error(
          `fromBigMat: entry [${i}][${j}] has ${babs(v).toString().length} digits, ` +
            `which exceeds 2^53 = ${TWO53}; converting it to Number would silently change its value`,
        );
      }
      row[j] = Number(v);
    }
    out.push(row);
  }
  return out;
}

/** Bring a BigInt vector back to Number, with the same refusal. */
export function fromBigVec(v: BigVec): Vec {
  const cap = BigInt(TWO53);
  const out = new Float64Array(v.length);
  for (let i = 0; i < v.length; i++) {
    if (babs(v[i]) > cap) {
      throw new Error(
        `fromBigVec: entry [${i}] has ${babs(v[i]).toString().length} digits, ` +
          `which exceeds 2^53 = ${TWO53}; converting it to Number would silently change its value`,
      );
    }
    out[i] = Number(v[i]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// BigInt matrix primitives. Deliberately the same shapes as matrix.ts, so the
// exact checks in this file read identically to the ones in invariants.ts.
// ---------------------------------------------------------------------------

/** n x m matrix of zeros. */
export function bigZeros(n: number, m: number): BigMat {
  const A: BigMat = [];
  for (let i = 0; i < n; i++) A.push(new Array<bigint>(m).fill(0n));
  return A;
}

/** n x n identity. */
export function bigEye(n: number): BigMat {
  const A = bigZeros(n, n);
  for (let i = 0; i < n; i++) A[i][i] = 1n;
  return A;
}

/**
 * Matrix product. Iterated i-t-j rather than i-j-t so the inner loop skips whole
 * rows when A[i][t] is zero -- the transforms in the proof below are dominated by
 * multiplies against sparse triangular matrices, and skipping the zeros is the
 * difference between 34 ms and several hundred at n=60.
 */
export function bigMatmul(A: BigMat, B: BigMat): BigMat {
  const n = A.length, p = B.length, m = B[0].length;
  const C = bigZeros(n, m);
  for (let i = 0; i < n; i++) {
    const Ai = A[i], Ci = C[i];
    for (let t = 0; t < p; t++) {
      const a = Ai[t];
      if (a === 0n) continue;
      const Bt = B[t];
      for (let j = 0; j < m; j++) Ci[j] += a * Bt[j];
    }
  }
  return C;
}

/** Exact entrywise equality. Used in proofs, so it must be `===`, never a tolerance. */
export function bigMatEq(A: BigMat, B: BigMat): boolean {
  if (A.length !== B.length) return false;
  for (let i = 0; i < A.length; i++) {
    if (A[i].length !== B[i].length) return false;
    for (let j = 0; j < A[i].length; j++) if (A[i][j] !== B[i][j]) return false;
  }
  return true;
}

/** Exactly the identity matrix. */
export function bigIsIdentity(A: BigMat): boolean {
  for (let i = 0; i < A.length; i++) {
    if (A[i].length !== A.length) return false;
    for (let j = 0; j < A.length; j++) if (A[i][j] !== (i === j ? 1n : 0n)) return false;
  }
  return true;
}

/** Extended Euclid: returns [g, x, y] with g = x*a + y*b and g >= 0. */
export function extgcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  let oldR = a, r = b;
  let oldS = 1n, s = 0n;
  let oldT = 0n, t = 1n;
  while (r !== 0n) {
    const q = oldR / r; // BigInt division truncates; Euclid is correct with either rounding
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  return oldR < 0n ? [-oldR, -oldS, -oldT] : [oldR, oldS, oldT];
}

// ---------------------------------------------------------------------------
// Fraction-free (Bareiss) elimination: determinant and adjugate
// ---------------------------------------------------------------------------

/**
 * Exact determinant by Bareiss fraction-free elimination.
 *
 * Every division in the update is exact -- that is Bareiss's theorem, and each
 * intermediate is itself a minor of the input, so nothing grows past the
 * Hadamard bound. Ordinary Gaussian elimination over the integers without that
 * division would double the entry length at every step and reach 2^n * 114
 * digits by the end; over the rationals it would need a gcd per entry. This is
 * the cheap exact route, and `hnf` needs the determinant before it can start.
 *
 * Measured: 0.01 ms at n=8, 8.1 ms at n=60.
 */
export function bigDet(A: BigMat): bigint {
  const n = A.length;
  const M = A.map((r) => r.slice());
  let prev = 1n;
  let sign = 1n;
  for (let k = 0; k < n - 1; k++) {
    if (M[k][k] === 0n) {
      let p = -1;
      for (let r = k + 1; r < n; r++) if (M[r][k] !== 0n) { p = r; break; }
      if (p < 0) return 0n; // whole column below the pivot is zero => singular
      [M[k], M[p]] = [M[p], M[k]];
      sign = -sign;
    }
    const pk = M[k][k];
    for (let i = k + 1; i < n; i++) {
      const mik = M[i][k];
      for (let j = k + 1; j < n; j++) M[i][j] = (M[i][j] * pk - mik * M[k][j]) / prev;
      M[i][k] = 0n;
    }
    prev = pk;
  }
  return n === 0 ? 1n : sign * M[n - 1][n - 1];
}

/**
 * The adjugate: adj(A) = det(A) * A^-1, an exact integer matrix.
 *
 * Bareiss forward elimination on [A | I], then back-substitution scaled by det.
 * The scaling is what keeps it in the integers: A^-1 is rational, det*A^-1 is
 * not, and Cramer's rule says each entry of det*A^-1 is a cofactor of A. Every
 * back-substitution division is therefore exact, and the code asserts that
 * rather than assuming it -- an inexact division would mean the elimination had
 * gone wrong, and it must not be allowed to round.
 *
 * This exists so `proveSameLatticeHnf` can build the integer transform
 * T = H * R^-1 without ever forming a rational. At n=60 the entries of adj(R)
 * run to 10^111 and T's to 10^111.4; both are ordinary BigInt values.
 */
export function bigAdjugate(A: BigMat): { adj: BigMat; det: bigint } {
  const n = A.length;
  const w = 2 * n;
  const M: BigMat = [];
  for (let i = 0; i < n; i++) {
    const row = A[i].slice();
    for (let j = 0; j < n; j++) row.push(i === j ? 1n : 0n);
    M.push(row);
  }
  let prev = 1n;
  let sign = 1n;
  for (let k = 0; k < n - 1; k++) {
    if (M[k][k] === 0n) {
      let p = -1;
      for (let r = k + 1; r < n; r++) if (M[r][k] !== 0n) { p = r; break; }
      if (p < 0) throw new Error('bigAdjugate: matrix is singular');
      [M[k], M[p]] = [M[p], M[k]];
      sign = -sign;
    }
    const pk = M[k][k];
    for (let i = k + 1; i < n; i++) {
      const mik = M[i][k];
      for (let j = k + 1; j < w; j++) M[i][j] = (M[i][j] * pk - mik * M[k][j]) / prev;
      M[i][k] = 0n;
    }
    prev = pk;
  }
  if (M[n - 1][n - 1] === 0n) throw new Error('bigAdjugate: matrix is singular');
  const det = sign * M[n - 1][n - 1];

  // Solve M_upper * X = (right block) for X = det * A^-1, one column at a time.
  const X = bigZeros(n, n);
  for (let c = 0; c < n; c++) {
    for (let i = n - 1; i >= 0; i--) {
      let acc = det * M[i][n + c];
      for (let j = i + 1; j < n; j++) acc -= M[i][j] * X[j][c];
      if (acc % M[i][i] !== 0n) throw new Error('bigAdjugate: back-substitution division was not exact');
      X[i][c] = acc / M[i][i];
    }
  }
  return { adj: X, det };
}

// ---------------------------------------------------------------------------
// The Hermite normal form itself
// ---------------------------------------------------------------------------

/** What `hnf` computed, plus the numbers the UI needs to show that it is honest. */
export interface HnfResult {
  /** The canonical basis: upper triangular, positive diagonal, reduced above each pivot. */
  readonly H: BigMat;
  /** det of the input basis, signed. HNF discards the sign; the lattice does not have one. */
  readonly det: bigint;
  /** d = |det|. Every intermediate entry in the computation was bounded by this. */
  readonly d: bigint;
  /** The diagonal H[i][i]. Multiplies to exactly `d` -- that identity is why this file uses BigInt. */
  readonly pivots: readonly bigint[];
  /** Wall-clock milliseconds for this call, determinant included. Measured, not estimated. */
  readonly ms: number;
}

/**
 * HNF(A) by the modulo-determinant method.
 *
 * Column i is cleared with integer row operations built from the extended
 * Euclidean algorithm, so the transform is unimodular at every step and the
 * lattice never changes. Two things make it cheap:
 *
 *  1. Every entry is kept reduced mod d. Legal because d*e_c is in the lattice
 *     for every c (adj(A)*A = det(A)*I), so subtracting multiples of it
 *     subtracts lattice vectors. Without this the entries grow without bound;
 *     with it nothing exceeds d.
 *  2. d*e_i is available for free as an extra generator when column i is
 *     cleared, so the pivot is gcd(column entries, d) rather than just
 *     gcd(column entries). At GGH parameters this makes almost every pivot 1:
 *     measured, 59 of the 60 pivots are 1 at n=60 and the last one is the whole
 *     determinant, because a random lattice's quotient Z^n/L is cyclic. That
 *     shape is exactly why the HNF is a small public key.
 *
 * Throws on a singular input: the method needs d, and a GGH basis is never
 * singular (keygen rejects R whose det is not even coprime to 6).
 */
export function hnf(input: Mat | BigMat): HnfResult {
  const t0 = performance.now();
  const A = asBigMat(input);
  const n = A.length;
  const det = bigDet(A);
  if (det === 0n) throw new Error('hnf: basis is singular, so the lattice is not full rank');
  const d = babs(det);

  // Workspace: the input rows reduced into [0, d). Rows are dropped once they
  // become zero, which they mostly do immediately -- d is huge and the rows of a
  // GGH basis are tiny, so this is not an optimisation for its own sake.
  let W: BigMat = A.map((r) => r.map((v) => emod(v, d)));
  const H = bigZeros(n, n);

  for (let i = 0; i < n; i++) {
    W = W.filter((r) => r.some((v) => v !== 0n));

    // Clear column i across the workspace, leaving one row holding the gcd.
    let p = -1;
    for (let r = 0; r < W.length; r++) if (W[r][i] !== 0n) { p = r; break; }
    if (p >= 0) {
      for (let r = p + 1; r < W.length; r++) {
        const b = W[r][i];
        if (b === 0n) continue;
        const a = W[p][i];
        const [g, x, y] = extgcd(a, b);
        // [[x, y], [-b/g, a/g]] has determinant (x*a + y*b)/g = 1, so this pair
        // of row operations is unimodular and the lattice is unchanged.
        const ag = a / g, bg = b / g;
        const Rp = W[p], Rr = W[r];
        for (let t = i; t < n; t++) {
          const u = emod(x * Rp[t] + y * Rr[t], d);
          const v = emod(ag * Rr[t] - bg * Rp[t], d);
          Rp[t] = u;
          Rr[t] = v;
        }
      }
    }

    // Fold in the free generator d*e_i. gcd(pivot, d) is the true HNF pivot; the
    // leftover row -(d/g)*pivotRow has a zero in column i and stays in play.
    if (p < 0) {
      const row = new Array<bigint>(n).fill(0n);
      row[i] = d; // no input row reaches column i: the pivot is d itself
      H[i] = row;
    } else {
      const a = W[p][i];
      const [g, x] = extgcd(a, d);
      const leftover = W[p].map((v) => emod(-(d / g) * v, d));
      leftover[i] = 0n; // exactly zero by construction: (d/g)*a is a multiple of d
      const pivotRow = W[p].map((v) => emod(x * v, d));
      pivotRow[i] = g;
      W[p] = leftover;
      H[i] = pivotRow;
    }
  }

  // Every remaining workspace row is now zero in every column, i.e. the zero
  // vector. If one were not, a generator would have been dropped and H would
  // span a strict sublattice -- so this is checked, not trusted.
  for (const r of W) {
    for (const v of r) if (v !== 0n) throw new Error('hnf: workspace not exhausted; a generator was lost');
  }

  // Reduce above each pivot: 0 <= H[j][i] < H[i][i] for j < i. Rows are handled
  // bottom-up and columns left to right, so each reducer row is already final in
  // the columns it is used on. Reducing H[j][t] mod d is safe for t > j because
  // d*e_t is an integer combination of rows t..n-1 only, i.e. never of row j
  // itself, so it is a genuine unimodular row operation. That mod is what stops
  // the back-reduction from growing entries by a factor of d at every column.
  for (let j = n - 1; j >= 0; j--) {
    for (let t = j + 1; t < n; t++) {
      const piv = H[t][t];
      const q = H[j][t] / piv; // H[j][t] is in [0, d) so it is non-negative; truncation is floor
      if (q !== 0n) {
        for (let s = t; s < n; s++) H[j][s] = emod(H[j][s] - q * H[t][s], d);
      }
    }
  }

  const pivots: bigint[] = [];
  for (let i = 0; i < n; i++) pivots.push(H[i][i]);
  return { H, det, d, pivots, ms: performance.now() - t0 };
}

/**
 * Does H satisfy this file's HNF conditions? Upper triangular, positive
 * diagonal, every entry above a pivot reduced into [0, pivot).
 *
 * Together with "generates the same lattice" this is the whole uniqueness
 * theorem: a matrix satisfying these conditions and generating L IS HNF(L).
 */
export function isHnf(H: BigMat): boolean {
  const n = H.length;
  for (let i = 0; i < n; i++) {
    if (H[i].length !== n) return false;
    if (H[i][i] <= 0n) return false;
    for (let j = 0; j < i; j++) if (H[i][j] !== 0n) return false;
    for (let j = 0; j < i; j++) if (H[j][i] < 0n || H[j][i] >= H[i][i]) return false;
  }
  return true;
}

/** Determinant of a triangular matrix: the product of the diagonal. Exact, no elimination. */
export function hnfDeterminant(H: BigMat): bigint {
  let p = 1n;
  for (let i = 0; i < H.length; i++) p *= H[i][i];
  return p;
}

/**
 * Coordinates of v in the basis H, or null if v is not in L(H).
 *
 * Forward substitution, which is all lattice membership costs once the basis is
 * triangular: x[j] is forced by coordinate j, and it is only a lattice vector if
 * every forced quotient is an exact integer. O(n^2) and completely exact -- this
 * is a second thing the HNF buys that Micciancio does not advertise.
 */
export function coordinatesInHnf(H: BigMat, v: BigVec): BigVec | null {
  const n = H.length;
  const x: bigint[] = new Array<bigint>(n).fill(0n);
  const w = v.slice();
  for (let j = 0; j < n; j++) {
    if (w[j] % H[j][j] !== 0n) return null;
    const q = w[j] / H[j][j];
    x[j] = q;
    if (q !== 0n) for (let t = j; t < n; t++) w[t] -= q * H[j][t];
  }
  for (let t = 0; t < n; t++) if (w[t] !== 0n) return null;
  return x;
}

/**
 * The canonical representative of the coset v + L(H): the unique point of that
 * coset with 0 <= result[i] < H[i][i] for every i.
 *
 * This is Micciancio's ciphertext compression. A GGH ciphertext c = m*B + e and
 * its reduction c mod H differ by a lattice vector, and Babai round-off with the
 * private basis recovers exactly the same error from either -- round(v*R^-1)*R
 * shifts by that same lattice vector, so the difference c - roundOff(c) does not
 * move at all. What changes is the size: all but the last coordinate are reduced
 * against a pivot of 1 and become 0. Measured below in `compareCiphertextSize`.
 */
export function reduceModHnf(v: BigVec, H: BigMat): BigVec {
  const n = H.length;
  const w = v.slice();
  for (let i = 0; i < n; i++) {
    const piv = H[i][i];
    let q = w[i] / piv;
    if (w[i] - q * piv < 0n) q -= 1n; // BigInt division truncates toward zero; we need floor
    if (q !== 0n) for (let t = i; t < n; t++) w[t] -= q * H[i][t];
  }
  return w;
}

// ---------------------------------------------------------------------------
// The same-lattice proof, in BigInt
// ---------------------------------------------------------------------------

/**
 * Result of proving L(H) = L(R) with exact BigInt arithmetic.
 *
 * The structure deliberately mirrors `SameLatticeProof` in types.ts so the UI can
 * render this proof and the I1 proof the same way. The transforms are named T
 * and S rather than U and V because they are not the keygen pair: T = H*R^-1 has
 * entries around 10^111 at n=60, since expressing the HNF's huge rows in the
 * short private basis genuinely needs huge coefficients.
 */
export interface HnfSameLatticeProof {
  /** True only if every exact check below passed. */
  readonly ok: boolean;
  /** What was proved, or which check failed. */
  readonly reason: string;
  /** T with T*R = H, so every row of H is an integer combination of rows of R. */
  readonly T: BigMat | null;
  /** S with S*H = R, so every row of R is an integer combination of rows of H. */
  readonly S: BigMat | null;
  /** Per-check results, so the UI can show the proof step by step. */
  readonly checks: {
    readonly hnfShape: boolean;
    readonly determinantsMatch: boolean;
    readonly tIsIntegral: boolean;
    readonly tTimesREqualsH: boolean;
    readonly sIsIntegral: boolean;
    readonly sTimesHEqualsR: boolean;
    readonly tTimesSIsIdentity: boolean;
  };
  /** Wall-clock milliseconds for this proof. */
  readonly ms: number;
}

/**
 * Prove L(H) = L(R) by exact BigInt arithmetic -- both inclusions, no floats.
 *
 * This is invariant I1 again, moved into BigInt because the HNF's entries are
 * 97 orders past 2^53 and `inverse()` from matrix.ts cannot be used on them at
 * all. Same skeleton, different arithmetic:
 *
 *   1. T = H * adj(R) / det(R). Integral iff every entry divides exactly, which
 *      is checked; integrality alone already proves L(H) is a subset of L(R).
 *   2. S is read off by forward substitution against the triangular H, one row
 *      of R at a time. Existence proves L(R) is a subset of L(H).
 *   3. T*R === H and S*H === R are re-multiplied and compared exactly, so the
 *      two transforms are verified rather than assumed.
 *   4. T*S === I, which forces det(T)*det(S) = 1 over the integers and hence
 *      det(T) = +-1: T is unimodular.
 *   5. prod H[i][i] === |det R|, the determinant identity the whole file rests on.
 *
 * Steps 1 and 2 are the two inclusions and together they are the lattice
 * equality. Steps 4 and 5 are redundant given 1-3 and are computed anyway,
 * because a redundant check that agrees is evidence and this proof is the only
 * thing standing between the HNF act and a claim nobody verified.
 *
 * Never throws on a bad basis: a failing invariant is a result the UI must be
 * able to display.
 *
 * Measured: PASS at n = 8, 16, 32, 60 over 3 keys each; 0.08 ms at n=8 and
 * 34 ms at n=60.
 */
export function proveSameLatticeHnf(R: BigMat, H: BigMat): HnfSameLatticeProof {
  const t0 = performance.now();
  const fail = (
    reason: string,
    checks: HnfSameLatticeProof['checks'],
    T: BigMat | null = null,
    S: BigMat | null = null,
  ): HnfSameLatticeProof => ({ ok: false, reason, T, S, checks, ms: performance.now() - t0 });

  const blank = {
    hnfShape: false,
    determinantsMatch: false,
    tIsIntegral: false,
    tTimesREqualsH: false,
    sIsIntegral: false,
    sTimesHEqualsR: false,
    tTimesSIsIdentity: false,
  };

  const hnfShape = isHnf(H);
  if (!hnfShape) {
    return fail('H is not in Hermite normal form under this file\'s conventions', { ...blank });
  }

  let detR: bigint;
  let adj: BigMat;
  try {
    const a = bigAdjugate(R);
    detR = a.det;
    adj = a.adj;
  } catch {
    return fail('R is singular, so H * R^-1 does not exist', { ...blank, hnfShape });
  }
  if (detR === 0n) return fail('R is singular, so H * R^-1 does not exist', { ...blank, hnfShape });

  const determinantsMatch = hnfDeterminant(H) === babs(detR);

  // T = H * R^-1 = (H * adj(R)) / det(R). Exact divisibility IS the integrality proof.
  const HA = bigMatmul(H, adj);
  let tIsIntegral = true;
  const T: BigMat = HA.map((row) =>
    row.map((v) => {
      if (v % detR !== 0n) { tIsIntegral = false; return 0n; }
      return v / detR;
    }),
  );
  const tTimesREqualsH = tIsIntegral && bigMatEq(bigMatmul(T, R), H);

  // S from forward substitution: every row of R read in the triangular basis H.
  const S: BigMat = [];
  let sIsIntegral = true;
  for (const row of R) {
    const x = coordinatesInHnf(H, row);
    if (x === null) { sIsIntegral = false; break; }
    S.push(x);
  }
  const sTimesHEqualsR = sIsIntegral && bigMatEq(bigMatmul(S, H), R);
  const tTimesSIsIdentity = tIsIntegral && sIsIntegral && bigIsIdentity(bigMatmul(T, S));

  const checks = {
    hnfShape,
    determinantsMatch,
    tIsIntegral,
    tTimesREqualsH,
    sIsIntegral,
    sTimesHEqualsR,
    tTimesSIsIdentity,
  };
  const Tout = tIsIntegral ? T : null;
  const Sout = sIsIntegral ? S : null;

  if (!tIsIntegral) return fail('H * R^-1 is not an integer matrix, so L(H) is not inside L(R)', checks, Tout, Sout);
  if (!tTimesREqualsH) return fail('T * R does not equal H', checks, Tout, Sout);
  if (!sIsIntegral) return fail('some row of R is not an integer combination of rows of H', checks, Tout, Sout);
  if (!sTimesHEqualsR) return fail('S * H does not equal R', checks, Tout, Sout);
  if (!tTimesSIsIdentity) return fail('T * S does not equal I, so T is not invertible over the integers', checks, Tout, Sout);
  if (!determinantsMatch) return fail('the HNF diagonal does not multiply to |det R|', checks, Tout, Sout);

  return {
    ok: true,
    reason:
      'T and S are integer matrices with T*R = H, S*H = R and T*S = I, so each basis is an ' +
      'integer recombination of the other and the two generate exactly the same lattice. ' +
      'The HNF diagonal multiplies to |det R|, confirming it independently.',
    T,
    S,
    checks,
    ms: performance.now() - t0,
  };
}

// ---------------------------------------------------------------------------
// What the HNF buys: measured, not quoted
// ---------------------------------------------------------------------------

/**
 * Bits needed to store one signed integer: magnitude plus a sign bit, minimum 1.
 *
 * A serialisation convention has to be fixed before any size claim means
 * anything; this is the one used by every function below and it is the same for
 * both matrices being compared, which is what makes the ratio meaningful.
 */
export function bitsOfInt(x: bigint): number {
  const a = babs(x);
  return a === 0n ? 1 : a.toString(2).length + 1;
}

/** Bits for every entry of a matrix -- what a dense serialiser costs. */
export function bitsOfMat(A: BigMat): number {
  let s = 0;
  for (const r of A) for (const v of r) s += bitsOfInt(v);
  return s;
}

/**
 * Bits for the upper triangle only.
 *
 * Fair for an HNF and only for an HNF: triangularity is part of the format, so a
 * serialiser knows the lower entries are zero without being told. Both numbers
 * are reported by `compareKeySize` so nobody has to take this on trust.
 */
export function bitsOfUpperTriangle(A: BigMat): number {
  let s = 0;
  for (let i = 0; i < A.length; i++) for (let j = i; j < A.length; j++) s += bitsOfInt(A[i][j]);
  return s;
}

/** Bits for every entry of a vector. */
export function bitsOfVec(v: BigVec): number {
  let s = 0;
  for (const x of v) s += bitsOfInt(x);
  return s;
}

/** A measured public-key size comparison. Every field is computed from the actual matrices. */
export interface HnfSizeComparison {
  readonly n: number;
  /** Dense serialisation of the ordinary public basis B. */
  readonly basisBits: number;
  /** Dense serialisation of HNF(B), counting the zeros below the diagonal. */
  readonly hnfDenseBits: number;
  /** HNF(B) counting only the upper triangle, which is all a serialiser needs. */
  readonly hnfBits: number;
  /** basisBits / hnfBits. Measured for these two matrices, not an asymptotic claim. */
  readonly ratio: number;
  /** Mean bits per entry of B -- the quantity Micciancio's O(n^3 log n) assumes is O(n log n). */
  readonly basisBitsPerEntry: number;
  /** Number of HNF pivots greater than 1. Usually 1: the lattice quotient is cyclic. */
  readonly nontrivialPivots: number;
  /** Bits in the largest HNF entry, i.e. roughly log2|det|. */
  readonly largestHnfEntryBits: number;
}

/**
 * Measure what the HNF actually costs to store against what B costs.
 *
 * Micciancio's claim is asymptotic: key size from O(n^3 log n) to O(n^2 log n),
 * "a factor n equal to the dimension of the lattice". The n^3 assumes each of
 * the n^2 entries of the public basis needs O(n log n) bits, which is true of a
 * fully mixed GGH public key and is NOT true of this lab's. Keygen mixes U with
 * only 6 elementary operations per row and caps entries at 512, so max|B| stays
 * around 10^3 and B costs about 7 bits per entry at every dimension. Measured
 * consequences, one key per cell:
 *
 *     n     bits(B)   bits(HNF)   ratio
 *     8       487        381       1.28
 *     16     1972       1553       1.27
 *     32     7715       6623       1.16
 *     60    27026      24497       1.10
 *
 * So at the shipped parameters the HNF is smaller, but by 10-28%, not by a
 * factor of n. Raising the mixing recovers the effect, because that is exactly
 * the variable Micciancio's exponent is about -- same n=60 lattice, same HNF:
 *
 *     ops/row   max|B|    bits/entry   bits(B)   ratio
 *     6         1.3e3     7.4           26712    1.09
 *     20        1.5e6     16.9          60977    2.50
 *     40        1.9e10    31.0         111445    4.56
 *     80        8.6e13    44.7         161054    6.59
 *
 * bits(HNF) does not move across that sweep -- 24434 bits at every row -- which
 * is the actual lesson: the HNF's size depends only on the lattice, while the
 * ordinary public basis costs whatever the key generator happened to make it.
 * The UI should show the measured ratio for the key on screen and say plainly
 * that the factor-n figure is asymptotic and assumes a fully mixed basis.
 */
export function compareKeySize(B: Mat | BigMat, H: BigMat): HnfSizeComparison {
  const Bb = asBigMat(B);
  const n = Bb.length;
  const basisBits = bitsOfMat(Bb);
  const hnfBits = bitsOfUpperTriangle(H);
  let nontrivialPivots = 0;
  for (let i = 0; i < H.length; i++) if (H[i][i] > 1n) nontrivialPivots++;
  return {
    n,
    basisBits,
    hnfDenseBits: bitsOfMat(H),
    hnfBits,
    ratio: basisBits / hnfBits,
    basisBitsPerEntry: basisBits / (n * n),
    nontrivialPivots,
    largestHnfEntryBits: bitsOfInt(bigMaxAbs(H)),
  };
}

/** A measured ciphertext size comparison. */
export interface CiphertextSizeComparison {
  /** Bits to send c as it comes out of the encryptor. */
  readonly rawBits: number;
  /** Bits to send c mod HNF(B) instead -- the same coset, canonically named. */
  readonly reducedBits: number;
  /** rawBits / reducedBits. */
  readonly ratio: number;
  /** The reduced ciphertext, for display. */
  readonly reduced: BigVec;
  /** How many of its coordinates collapsed to zero because their pivot is 1. */
  readonly zeroCoordinates: number;
}

/**
 * Measure Micciancio's ciphertext reduction on one real ciphertext.
 *
 * The paper's claim is O(n^2 log n) -> O(n log n) bits. The mechanism is visible
 * in the output: every coordinate whose pivot is 1 reduces to 0, so what is left
 * is essentially one residue mod |det|. Measured at this lab's parameters, one
 * ciphertext per dimension: 121 -> 49 bits at n=8 (2.47x), 258 -> 101 at n=16
 * (2.55x), 545 -> 217 at n=32 (2.51x), 1017 -> 437 at n=60 (2.33x). As with the
 * key, the ratio is smaller than the asymptotic n for the same reason -- this
 * lab's B is small, so its ciphertexts were never n log n bits per coordinate to
 * begin with.
 */
export function compareCiphertextSize(c: BigVec, H: BigMat): CiphertextSizeComparison {
  const reduced = reduceModHnf(c, H);
  const rawBits = bitsOfVec(c);
  const reducedBits = bitsOfVec(reduced);
  let zeroCoordinates = 0;
  for (const x of reduced) if (x === 0n) zeroCoordinates++;
  return { rawBits, reducedBits, ratio: rawBits / reducedBits, reduced, zeroCoordinates };
}

/** One of the things the HNF buys, with its source and how this lab checks it. */
export interface HnfBenefit {
  readonly title: string;
  readonly claim: string;
  readonly source: string;
  /** How this repository substantiates it -- or plainly, that it does not. */
  readonly checkedBy: string;
}

/**
 * The three things Micciancio's HNF public key buys, quoted from the paper.
 *
 * Exported for the UI so the in-page text and the code cannot drift apart. Two
 * of the three are checked here by computation; the third is a theorem this lab
 * does not reprove, and says so.
 */
export const HNF_BENEFITS: readonly HnfBenefit[] = [
  {
    title: 'Canonical',
    claim:
      'HNF(B) does not depend on the particular basis it was computed from: it is uniquely ' +
      'defined by the lattice L(B). A public key in Hermite normal form therefore leaks nothing ' +
      'about how the key was generated -- Nguyen and Regev put it as "the HNF gives an attacker ' +
      'the least advantage (in a certain precise sense)".',
    source: 'Micciancio, CaLC 2001, section 2; quoted in Nguyen-Regev, EUROCRYPT 2006, section 2.2',
    checkedBy:
      'hnf.test.ts computes HNF(R) and HNF(U*R) for the same lattice and asserts they are ' +
      'identical entry for entry, at n = 8, 16, 32 and 60.',
  },
  {
    title: 'Smaller key and ciphertext',
    claim:
      'Key size drops from O(n^3 log n) to O(n^2 log n) and ciphertext from O(n^2 log n) to ' +
      'O(n log n) -- "reducing the size of both key and ciphertext by a factor n equal to the ' +
      'dimension of the lattice".',
    source: 'Micciancio, CaLC 2001, abstract and section 1',
    checkedBy:
      'compareKeySize and compareCiphertextSize measure the serialised bit length of the actual ' +
      'matrices on screen. The measured factor is 1.1-1.3x for the key and 2.3-2.6x for the ' +
      'ciphertext at this lab\'s parameters, not n: the asymptotic claim assumes a fully mixed ' +
      'public basis with O(n log n)-bit entries, and this lab mixes U gently so B stays around ' +
      '7 bits per entry. See the note on compareKeySize for the measured mixing sweep.',
  },
  {
    title: 'Provably no worse',
    claim:
      'Any attack on the HNF variant can be provably transformed into an at least equally ' +
      'effective attack against the original GGH, so the change cannot cost security.',
    source: 'Micciancio, CaLC 2001, section 1',
    checkedBy:
      'Not checked here. This is a reduction proved in the paper, not a computation; this lab ' +
      'states it and cites it rather than pretending to verify it.',
  },
];

// ---------------------------------------------------------------------------
// Cost, so the UI can gate on a measurement
// ---------------------------------------------------------------------------

/** One measured cost row. */
export interface HnfTiming {
  readonly n: number;
  /** hnf(), determinant included. */
  readonly hnfMs: number;
  /** proveSameLatticeHnf(). */
  readonly proofMs: number;
}

/**
 * Wall clock, measured on Apple M5 / Node v26.5.0, median of 5 warmed runs, and
 * stable to within 10% over three independent repetitions.
 *
 * The verdict is that nothing here needs a Web Worker. The whole HNF path at the
 * lab's top dimension is 68 ms -- four frames for a one-shot key operation. The
 * cold first call at n=60 was 38 ms against a 33 ms warm median, so JIT warm-up
 * is not hiding anything either.
 *
 * These are Node numbers on one machine; a phone will be slower. `estimateHnfMs`
 * is what the UI should gate on, not these constants directly.
 */
export const MEASURED_HNF_MS: readonly HnfTiming[] = [
  { n: 8, hnfMs: 0.09, proofMs: 0.08 },
  { n: 16, hnfMs: 0.51, proofMs: 0.59 },
  { n: 32, hnfMs: 3.9, proofMs: 4.6 },
  { n: 60, hnfMs: 34, proofMs: 34 },
];

/** Longest total the HNF act may take before the UI should move it off the main thread. */
export const HNF_MAIN_THREAD_BUDGET_MS = 150;

/** An honest cost estimate for dimension n, anchored on the measurements above. */
export interface HnfCostEstimate {
  readonly n: number;
  readonly hnfMs: number;
  readonly proofMs: number;
  readonly totalMs: number;
  /** True if the estimate fits the main-thread budget. */
  readonly mainThreadSafe: boolean;
  /** True when n matches a row of MEASURED_HNF_MS exactly rather than being interpolated. */
  readonly measured: boolean;
}

/**
 * Estimate the cost at dimension n.
 *
 * Scaled from the n=60 anchor as n^3, which is the operation count -- n^2 entries
 * touched n times. The measured growth from n=32 to n=60 is slightly steeper,
 * n^3.45, because the BigInt operands themselves get longer as the determinant
 * grows. So this UNDERSTATES the cost above n=60 and OVERSTATES it below, which
 * is the safe direction for every dimension this lab offers: the slider stops at
 * 60, the anchor is at 60, and everything smaller is estimated pessimistically.
 * If the slider is ever raised past 60, re-measure rather than trusting this.
 */
export function estimateHnfMs(n: number): HnfCostEstimate {
  const exact = MEASURED_HNF_MS.find((t) => t.n === n);
  if (exact) {
    const totalMs = exact.hnfMs + exact.proofMs;
    return {
      n,
      hnfMs: exact.hnfMs,
      proofMs: exact.proofMs,
      totalMs,
      mainThreadSafe: totalMs <= HNF_MAIN_THREAD_BUDGET_MS,
      measured: true,
    };
  }
  const anchor = MEASURED_HNF_MS[MEASURED_HNF_MS.length - 1];
  const scale = (n / anchor.n) ** 3;
  const hnfMs = anchor.hnfMs * scale;
  const proofMs = anchor.proofMs * scale;
  const totalMs = hnfMs + proofMs;
  return {
    n,
    hnfMs,
    proofMs,
    totalMs,
    mainThreadSafe: totalMs <= HNF_MAIN_THREAD_BUDGET_MS,
    measured: false,
  };
}
