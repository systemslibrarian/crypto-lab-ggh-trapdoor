/**
 * Break 1, step A -- Nguyen's mod-2*sigma reduction, as EXACT linear algebra.
 *
 * THE CONGRUENCE. Every entry of GGH's error is +-sigma, and -sigma = +sigma
 * (mod 2*sigma), so the whole error vector collapses to a single known constant:
 *
 *     e = sigma * (1, ..., 1)   (mod 2*sigma)
 *
 * Nguyen (CRYPTO '99, section 3) writes the consequence as
 *
 *     m * B = c + s   (mod 2*sigma),   s = (sigma, ..., sigma)
 *
 * and that is the form `congruenceRhs` builds. From c = m*B + e the direct
 * rearrangement is m*B = c - s, but the two are the SAME vector mod 2*sigma
 * because +s = -s there (2s = 0 mod 2 sigma), so either sign yields the same m0.
 * We follow Nguyen's sign here so the code can be read against the paper, and use
 * `c - s` in break1.ts's division step only because that choice makes the
 * residual error come out in {0,-1}^n rather than {0,+1}^n.
 *
 * WHY NEVER ELIMINATE DIRECTLY MOD 6. 2*sigma = 6 is not prime: Z/6 has zero
 * divisors (2*3 = 0), so a pivot may be nonzero and still not invertible, and
 * "divide the pivot row by the pivot" -- the single move Gaussian elimination is
 * built on -- is not a legal operation. Any mod-6 elimination is therefore a
 * heuristic pretending to be linear algebra, which invariant I3 forbids. Instead
 * we solve twice over honest FIELDS, GF(2) and GF(3), where every nonzero element
 * is a unit and elimination is exact, and glue the two answers with the Chinese
 * remainder theorem: gcd(2,3) = 1, so the pair (m0 mod 2, m0 mod 3) determines
 * m0 mod 6 uniquely.
 *
 * SINGULARITY IS THE COMMON CASE, NOT THE EDGE CASE (invariant I3). Measured on
 * this lab's own keygen with the coprimality rejection switched off, 150 fresh
 * keys at each of n = 8, 16, 32, 60:
 *
 *     singular mod 2   71.3%  72.0%  74.0%  78.0%
 *     singular mod 3   45.3%  38.7%  47.3%  46.7%
 *     singular mod 6   83.3%  84.0%  83.3%  88.0%   -> usable 12.0-16.7%
 *
 * That matches theory: a uniform random matrix over GF(p) is invertible with
 * probability prod_{i>=1}(1 - p^-i), which is 0.2888 for p=2 and 0.5601 for p=3,
 * product 0.162. So the singular branch here is load-bearing rather than
 * defensive -- it fires on roughly five keys in six. It names WHICH modulus
 * failed and hands that to the caller, which re-keys (keygen.ts rejects R whose
 * det is not coprime to 6 by default, at a mean of 5.8-6.5 draws). It never
 * fudges a pivot.
 *
 * `solveRowModPFull` is the alternative to re-keying: it returns the full
 * solution set (particular solution + kernel basis) so an attacker can enumerate
 * the mod-6 cosets on a key it was not allowed to choose. Measured on
 * unrestricted keys, the corank is almost always 1, the median number of cosets
 * to try is 2 (max observed 29 at n=60), and the pattern + re-encryption checks
 * in break1.ts pick the right coset with zero false positives.
 */

import type { Mat, Vec } from '../lattice/types';

/** Non-negative residue of x modulo p. Inputs here are always exact integers. */
export function modP(x: number, p: number): number {
  return ((x % p) + p) % p;
}

/**
 * Multiplicative inverse in GF(p), or null when a = 0 mod p.
 *
 * p is only ever 2 or 3 in this lab, so a linear scan is exact, allocation-free
 * and faster than the extended Euclidean algorithm.
 */
export function invModP(a: number, p: number): number | null {
  const r = modP(a, p);
  if (r === 0) return null;
  for (let i = 1; i < p; i++) if (modP(r * i, p) === 1) return i;
  return null;
}

/**
 * Solve A x = rhs over GF(p) for a square A by Gauss-Jordan elimination.
 *
 * Returns the unique solution, or null if A is singular mod p. p must be prime:
 * the algorithm inverts every pivot, which is legal exactly when the ring is a
 * field.
 */
export function solveGFp(A: number[][], rhs: number[], p: number): number[] | null {
  const n = A.length;
  const M: number[][] = A.map((row, i) => {
    const r = new Array<number>(n + 1);
    for (let j = 0; j < n; j++) r[j] = modP(row[j], p);
    r[n] = modP(rhs[i], p);
    return r;
  });
  for (let col = 0; col < n; col++) {
    let piv = -1;
    for (let r = col; r < n; r++) {
      if (M[r][col] !== 0) { piv = r; break; }
    }
    if (piv < 0) return null; // singular mod p: no pivot in this column
    if (piv !== col) { const t = M[col]; M[col] = M[piv]; M[piv] = t; }
    const inv = invModP(M[col][col], p);
    if (inv === null) return null; // unreachable for prime p; kept so the invariant is explicit
    for (let j = col; j <= n; j++) M[col][j] = modP(M[col][j] * inv, p);
    for (let r = 0; r < n; r++) {
      if (r === col || M[r][col] === 0) continue;
      const f = M[r][col];
      for (let j = col; j <= n; j++) M[r][j] = modP(M[r][j] - f * M[col][j], p);
    }
  }
  return M.map((r) => r[n]);
}

/**
 * Solve the ROW system x * B = rhs (mod p).
 *
 * The whole lab is in the row convention, so the system to solve is x*B = rhs,
 * not B*x = rhs. Transposing turns it into the column system B^T x^T = rhs^T,
 * which is what `solveGFp` expects.
 */
export function solveRowModP(B: Mat, rhs: Vec, p: number): Vec | null {
  const n = B.length;
  const At: number[][] = [];
  for (let i = 0; i < n; i++) {
    const row = new Array<number>(n);
    for (let j = 0; j < n; j++) row[j] = modP(B[j][i], p);
    At.push(row);
  }
  const b = new Array<number>(n);
  for (let i = 0; i < n; i++) b[i] = modP(rhs[i], p);
  const x = solveGFp(At, b, p);
  return x === null ? null : Float64Array.from(x);
}

/** The complete solution set of a row system mod p: x0 + span(kernel). */
export interface RowSolutionSet {
  /** One particular solution. */
  readonly x0: Vec;
  /** A basis of the kernel { v : v*B = 0 (mod p) }. Empty iff B is invertible mod p. */
  readonly kernel: readonly Vec[];
}

/**
 * Full solution set of x * B = rhs (mod p), for use when B is NOT invertible.
 *
 * Returns null only if the system is inconsistent -- which cannot happen for a
 * genuine GGH ciphertext, since m itself is a solution by construction. The
 * kernel dimension is the corank; measured on unrestricted random keys it is 0
 * or 1 for ~90% of keys at every dimension from 8 to 60.
 */
export function solveRowModPFull(B: Mat, rhs: Vec, p: number): RowSolutionSet | null {
  const n = B.length;
  const M: number[][] = [];
  for (let i = 0; i < n; i++) {
    const row = new Array<number>(n + 1);
    for (let j = 0; j < n; j++) row[j] = modP(B[j][i], p); // M = [B^T | rhs^T]
    row[n] = modP(rhs[i], p);
    M.push(row);
  }
  const pivotOf = new Array<number>(n).fill(-1); // pivotOf[col] = row holding that pivot
  let r = 0;
  for (let col = 0; col < n && r < n; col++) {
    let piv = -1;
    for (let q = r; q < n; q++) {
      if (M[q][col] !== 0) { piv = q; break; }
    }
    if (piv < 0) continue; // free column
    const t = M[r]; M[r] = M[piv]; M[piv] = t;
    const inv = invModP(M[r][col], p);
    if (inv === null) return null;
    for (let j = col; j <= n; j++) M[r][j] = modP(M[r][j] * inv, p);
    for (let q = 0; q < n; q++) {
      if (q === r || M[q][col] === 0) continue;
      const f = M[q][col];
      for (let j = col; j <= n; j++) M[q][j] = modP(M[q][j] - f * M[r][j], p);
    }
    pivotOf[col] = r;
    r++;
  }
  // A zero row with a nonzero right-hand side means 0 = nonzero: inconsistent.
  for (let q = r; q < n; q++) if (M[q][n] !== 0) return null;

  const x0 = new Float64Array(n);
  for (let col = 0; col < n; col++) if (pivotOf[col] >= 0) x0[col] = M[pivotOf[col]][n];
  const kernel: Vec[] = [];
  for (let free = 0; free < n; free++) {
    if (pivotOf[free] >= 0) continue;
    const v = new Float64Array(n);
    v[free] = 1;
    for (let col = 0; col < n; col++) {
      if (pivotOf[col] >= 0) v[col] = modP(-M[pivotOf[col]][free], p);
    }
    kernel.push(v);
  }
  return { x0, kernel };
}

/**
 * Chinese remainder theorem for the coprime pair (2, 3).
 *
 * x = 3*a2 + 4*a3 (mod 6) is the unique residue with x = a2 (mod 2) and
 * x = a3 (mod 3): 3 is 1 mod 2 and 0 mod 3, and 4 is 0 mod 2 and 1 mod 3, so each
 * term carries exactly one of the two constraints and cannot disturb the other.
 */
export function crt23(a2: Vec, a3: Vec): Vec {
  const out = new Float64Array(a2.length);
  for (let i = 0; i < a2.length; i++) out[i] = modP(3 * a2[i] + 4 * a3[i], 6);
  return out;
}

/** Which modulus made the mod-6 solve impossible. Invariant I3 requires naming it. */
export interface Mod6Singularity {
  /** B has no inverse over GF(2). */
  readonly singularMod2: boolean;
  /** B has no inverse over GF(3). */
  readonly singularMod3: boolean;
  /** 2 or 3 when exactly one failed; 6 when both did. */
  readonly modulus: 2 | 3 | 6;
  /** Display string naming the failure, for the UI to show before it re-keys. */
  readonly reason: string;
}

/** Outcome of the mod-6 solve: either the residue vector, or a named singularity. */
export type Mod6Solution =
  | { readonly ok: true; readonly m0: Vec; readonly singular: null }
  | { readonly ok: false; readonly m0: null; readonly singular: Mod6Singularity };

/**
 * Nguyen's right-hand side, c + s with s = (sigma, ..., sigma), reduced mod 2*sigma.
 *
 * Reduced on the way out so the vector the UI displays is the residue the solve
 * actually consumes, and so nothing downstream depends on the size of c.
 */
export function congruenceRhs(c: Vec, sigma: number): Vec {
  const twoSigma = 2 * sigma;
  const out = new Float64Array(c.length);
  for (let i = 0; i < c.length; i++) out[i] = modP(c[i] + sigma, twoSigma);
  return out;
}

/**
 * Solve m0 * B = rhs (mod 6) exactly, via GF(2) and GF(3) followed by CRT.
 *
 * `rhs` is expected to be `congruenceRhs(c, sigma)`. The result m0 is the unique
 * representative in {0..5}^n of m mod 6 whenever B is invertible mod 6 -- it is
 * *the* solution of the congruence, which is why break1.ts's division by 6 is
 * always exact even when the ciphertext is not a legal GGH ciphertext (see the
 * header of break1.ts).
 */
export function solveMod6(B: Mat, rhs: Vec): Mod6Solution {
  const x2 = solveRowModP(B, rhs, 2);
  const x3 = solveRowModP(B, rhs, 3);
  if (x2 === null || x3 === null) {
    const singularMod2 = x2 === null;
    const singularMod3 = x3 === null;
    const modulus: 2 | 3 | 6 = singularMod2 && singularMod3 ? 6 : singularMod2 ? 2 : 3;
    const which =
      modulus === 6
        ? 'both GF(2) and GF(3)'
        : modulus === 2
          ? 'GF(2)'
          : 'GF(3)';
    return {
      ok: false,
      m0: null,
      singular: {
        singularMod2,
        singularMod3,
        modulus,
        reason:
          `the public basis B is singular over ${which}, so m mod ${modulus === 6 ? 6 : modulus} ` +
          'is not determined by the congruence. Nguyen\'s step needs B invertible mod 2 AND mod 3; ' +
          're-key, or enumerate the kernel cosets with solveRowModPFull.',
      },
    };
  }
  return { ok: true, m0: crt23(x2, x3), singular: null };
}
