/**
 * Dense integer/float matrix primitives.
 *
 * Everything here is deliberately small and inspectable: this lab exists to let
 * a learner read the arithmetic, so no linear-algebra library is used for the
 * teaching path.
 *
 * OVERFLOW POLICY. All lattice bases in this lab hold exact integers stored in
 * doubles, which is exact for |x| <= 2^53. That is safe by an enormous margin at
 * the shipped parameters -- the largest intermediate value anywhere in keygen,
 * round-off, or the I1 proof was measured at 3.4e4 against 9.007e15, a margin of
 * 2.7e11 (38 spare bits) at n=60. It is NOT safe for one specific algorithm:
 * fraction-free (Bareiss) LLL carries leading principal minors of the Gram
 * matrix, whose final value is det(B)^2 -- 10^16.3 at n=8 and 10^177.8 at n=60,
 * i.e. already past 2^53 at the SMALLEST dimension this lab offers. That is why
 * `lll.ts` uses floating-point Gram-Schmidt with exact integer basis updates and
 * a runtime guard, rather than the fraction-free variant.
 */

import type { Mat, Vec, Rng } from './types';

/** Largest integer exactly representable as a double. */
export const TWO53 = Number.MAX_SAFE_INTEGER; // 9007199254740991

/** n x m matrix of zeros. */
export function zeros(n: number, m: number): Mat {
  const A: Mat = [];
  for (let i = 0; i < n; i++) A.push(new Float64Array(m));
  return A;
}

/** n x n identity. */
export function eye(n: number): Mat {
  const A = zeros(n, n);
  for (let i = 0; i < n; i++) A[i][i] = 1;
  return A;
}

/** Deep copy. */
export function cloneMat(A: Mat): Mat {
  return A.map((r) => Float64Array.from(r));
}

/**
 * Round half away from zero.
 *
 * NOT `Math.round`, which resolves every tie towards +infinity (`Math.round(-0.5)`
 * is `-0`). That would decide the x = -1/2 tie without reference to the sign of
 * the coordinate. Neither rule makes the decryption bound an if-and-only-if at
 * the boundary -- see roundoff.ts, where both tie outcomes are constructed --
 * but this one at least makes the tie symmetric in the sign of the error, and it
 * is the rule roundoff.ts documents.
 */
export function rnd(x: number): number {
  const r = x >= 0 ? Math.floor(x + 0.5) : -Math.floor(-x + 0.5);
  // Normalise -0 to 0. Without this, any small negative input returns -0, which
  // renders as "-0" in the UI and makes Object.is-based test assertions fail
  // against a plain 0. Arithmetic is unaffected either way.
  return r === 0 ? 0 : r;
}

/** Round every entry, half away from zero. */
export function roundMat(A: Mat): Mat {
  return A.map((r) => Float64Array.from(r, rnd));
}

/** Round every entry of a vector, half away from zero. */
export function roundVec(v: Vec): Vec {
  return Float64Array.from(v, rnd);
}

/** Largest absolute entry. */
export function maxAbs(A: Mat): number {
  let m = 0;
  for (const r of A) for (const v of r) { const a = Math.abs(v); if (a > m) m = a; }
  return m;
}

/** Largest absolute entry of a vector. */
export function maxAbsVec(v: Vec): number {
  let m = 0;
  for (const x of v) { const a = Math.abs(x); if (a > m) m = a; }
  return m;
}

/** Euclidean norm. */
export function norm2(v: Vec): number {
  let s = 0;
  for (const x of v) s += x * x;
  return Math.sqrt(s);
}

/** Statistics collected while multiplying, so overflow headroom can be shown, not assumed. */
export interface MulStats {
  /** Largest absolute product or running partial sum seen. */
  maxIntermediate: number;
}

/**
 * Matrix product. When `stats` is supplied, records the largest absolute
 * intermediate value -- both individual products and running partial sums, since
 * either can overflow first.
 */
export function matmul(A: Mat, B: Mat, stats?: MulStats): Mat {
  const n = A.length, p = B.length, m = B[0].length;
  const C = zeros(n, m);
  let maxSeen = 0;
  for (let i = 0; i < n; i++) {
    const Ai = A[i], Ci = C[i];
    for (let j = 0; j < m; j++) {
      let s = 0;
      for (let t = 0; t < p; t++) {
        const pr = Ai[t] * B[t][j];
        const ap = pr < 0 ? -pr : pr;
        if (ap > maxSeen) maxSeen = ap;
        s += pr;
        const as = s < 0 ? -s : s;
        if (as > maxSeen) maxSeen = as;
      }
      Ci[j] = s;
    }
  }
  if (stats && maxSeen > stats.maxIntermediate) stats.maxIntermediate = maxSeen;
  return C;
}

/** Row vector times matrix: v * A. */
export function vecMat(v: Vec, A: Mat): Vec {
  const p = A.length, m = A[0].length;
  const out = new Float64Array(m);
  for (let j = 0; j < m; j++) {
    let s = 0;
    for (let t = 0; t < p; t++) s += v[t] * A[t][j];
    out[j] = s;
  }
  return out;
}

/** Transpose. */
export function transpose(A: Mat): Mat {
  const n = A.length, m = A[0].length;
  const T = zeros(m, n);
  for (let i = 0; i < n; i++) for (let j = 0; j < m; j++) T[j][i] = A[i][j];
  return T;
}

/** Exact entrywise equality. Used for the I1 proof, so it must be `===`, never a tolerance. */
export function matEq(A: Mat, B: Mat): boolean {
  if (A.length !== B.length) return false;
  for (let i = 0; i < A.length; i++) {
    if (A[i].length !== B[i].length) return false;
    for (let j = 0; j < A[i].length; j++) if (A[i][j] !== B[i][j]) return false;
  }
  return true;
}

/** Exactly the identity matrix. */
export function isIdentity(A: Mat): boolean {
  for (let i = 0; i < A.length; i++) {
    for (let j = 0; j < A.length; j++) if (A[i][j] !== (i === j ? 1 : 0)) return false;
  }
  return true;
}

/**
 * Every entry is an exact integer within +-2^53.
 *
 * This is the runtime overflow guard. It is checked rather than trusted, because
 * a silent loss of integer exactness would turn the I1 proof into a false claim.
 */
export function allIntegersUnder2p53(A: Mat): boolean {
  for (const r of A) for (const v of r) if (!Number.isSafeInteger(v)) return false;
  return true;
}

/** Every entry of a vector is an exact integer within +-2^53. */
export function vecIntegersUnder2p53(v: Vec): boolean {
  for (const x of v) if (!Number.isSafeInteger(x)) return false;
  return true;
}

/** Gauss-Jordan inverse with partial pivoting. Floating point by nature. */
export function inverse(A: Mat): Mat {
  const n = A.length;
  const M = cloneMat(A), I = eye(n);
  for (let c = 0; c < n; c++) {
    let piv = c, best = Math.abs(M[c][c]);
    for (let r = c + 1; r < n; r++) {
      const v = Math.abs(M[r][c]);
      if (v > best) { best = v; piv = r; }
    }
    if (best === 0) throw new Error('singular matrix');
    if (piv !== c) { [M[c], M[piv]] = [M[piv], M[c]]; [I[c], I[piv]] = [I[piv], I[c]]; }
    const d = M[c][c];
    for (let j = 0; j < n; j++) { M[c][j] /= d; I[c][j] /= d; }
    for (let r = 0; r < n; r++) {
      if (r === c) continue;
      const f = M[r][c];
      if (f === 0) continue;
      for (let j = 0; j < n; j++) { M[r][j] -= f * M[c][j]; I[r][j] -= f * I[c][j]; }
    }
  }
  return I;
}

/**
 * Householder QR of A^T; returns log10|R_kk| for k = 0..n-1.
 *
 * The product of the first j+1 values is the volume of the parallelepiped
 * spanned by the first j+1 rows of A, so these are the numbers the orthogonality
 * defect is built from.
 *
 * Returned as log10 on purpose. det(B) reaches 10^89.7 at n=60 and the
 * orthogonality defect of the PUBLIC basis reaches 10^69.2 -- both far past
 * 2^53, so neither may ever be formed in linear arithmetic. `Math.pow` would
 * happily return a finite double for these and it would not be an integer any
 * more, which is exactly the silent-wrongness this avoids.
 */
export function log10PivotNorms(A: Mat): number[] {
  const n = A.length, m = A[0].length;
  const W = zeros(m, n);
  for (let i = 0; i < n; i++) for (let j = 0; j < m; j++) W[j][i] = A[i][j];
  const out: number[] = [];
  const rows = m, cols = n;
  for (let c = 0; c < cols; c++) {
    let normx = 0;
    for (let r = c; r < rows; r++) normx += W[r][c] * W[r][c];
    normx = Math.sqrt(normx);
    out.push(normx === 0 ? -Infinity : Math.log10(normx));
    if (normx === 0) continue;
    const alpha = W[c][c] > 0 ? -normx : normx;
    const v = new Float64Array(rows);
    for (let r = c; r < rows; r++) v[r] = W[r][c];
    v[c] -= alpha;
    let vn = 0;
    for (let r = c; r < rows; r++) vn += v[r] * v[r];
    if (vn === 0) continue;
    for (let j = c; j < cols; j++) {
      let dot = 0;
      for (let r = c; r < rows; r++) dot += v[r] * W[r][j];
      const f = (2 * dot) / vn;
      for (let r = c; r < rows; r++) W[r][j] -= f * v[r];
    }
  }
  return out;
}

/**
 * log10 of the orthogonality defect: (prod_i ||b_i||) / |det B|.
 *
 * 1 (log10 = 0) means a perfectly orthogonal basis. Measured at the shipped
 * parameters this is ~0.86 for the private basis and ~69 for the public one at
 * n=60 -- which is the trapdoor, in one number.
 */
export function log10OrthogonalityDefect(A: Mat): number {
  const pivots = log10PivotNorms(A);
  let logDet = 0;
  for (const p of pivots) logDet += p;
  let logRowNorms = 0;
  for (const r of A) logRowNorms += Math.log10(norm2(r));
  return logRowNorms - logDet;
}

/** log10|det A|, via the same QR. Never form the linear value: it reaches 10^89.7 at n=60. */
export function log10AbsDet(A: Mat): number {
  let s = 0;
  for (const p of log10PivotNorms(A)) s += p;
  return s;
}

/**
 * Gram-Schmidt of the rows of A. Returns the orthogonal rows and the mu
 * coefficients. Used by LLL and by Klein's sampler.
 */
export function gramSchmidtRows(A: Mat): { star: Mat; mu: Mat; normSq: number[] } {
  const n = A.length, m = A[0].length;
  const star = zeros(n, m);
  const mu = zeros(n, n);
  const normSq: number[] = new Array(n).fill(0);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < m; j++) star[i][j] = A[i][j];
    for (let j = 0; j < i; j++) {
      if (normSq[j] === 0) { mu[i][j] = 0; continue; }
      let dot = 0;
      for (let t = 0; t < m; t++) dot += A[i][t] * star[j][t];
      const c = dot / normSq[j];
      mu[i][j] = c;
      for (let t = 0; t < m; t++) star[i][t] -= c * star[j][t];
    }
    let s = 0;
    for (let t = 0; t < m; t++) s += star[i][t] * star[i][t];
    normSq[i] = s;
  }
  return { star, mu, normSq };
}

/** Deterministic seeded PRNG (mulberry32), so every exhibit is reproducible. */
export function makeRng(seed: number): Rng {
  let a = seed >>> 0;
  return function rng(): number {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Uniform integer in [lo, hi], inclusive. */
export function randInt(rng: Rng, lo: number, hi: number): number {
  return lo + Math.floor(rng() * (hi - lo + 1));
}
