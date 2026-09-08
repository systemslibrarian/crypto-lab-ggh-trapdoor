/**
 * Break 2, step 1: whitening. Turning a skewed parallelepiped into a cube.
 *
 * Every signature hands the attacker one sample v = x*R with x uniform in
 * [-1/2,1/2)^n (see sign.ts). The covariance of such a v is
 *
 *     E[v^T v] = R^T E[x^T x] R = (1/12) * R^T R
 *
 * because the coordinates of x are independent, mean zero, variance 1/12. So the
 * attacker can estimate
 *
 *     G = 12 * mean_t (v_t^T v_t)  ->  R^T R
 *
 * from public data alone. G is symmetric positive definite; factor it as
 * G = L^T L with L upper triangular (Cholesky) and set
 *
 *     w = v * L^-1  =  x * (R * L^-1)  =  x * Q.
 *
 * Then Q^T Q = L^-T R^T R L^-1 = L^-T (L^T L) L^-1 = I, so Q is ORTHOGONAL.
 * The samples are now a uniform cube [-1/2,1/2)^n rotated by an unknown rotation,
 * and the rows of R map to the rows of Q, which are an orthonormal frame. All the
 * attack has to do from here is find that frame -- and a rotated cube is easy to
 * find, because a cube has corners and a sphere does not. That is moments.ts.
 *
 * WHAT THIS BUYS, MEASURED. max |(R*L^-1)(R*L^-1)^T - I| against sample count N,
 * essentially independent of n and clean 1/sqrt(N):
 *
 *     n \ N     125     500    2000    8000   32000
 *     8      0.4525  0.1193  0.0646  0.0270  0.0149
 *     16     0.3911  0.1219  0.0598  0.0334  0.0134
 *
 * A DELIBERATE NON-FINDING. Re-running the whole attack with an EXACT whitening
 * oracle (L = chol(R^T R), which uses the secret) barely moves the number of
 * signatures needed -- at n=16 both the estimated and the exact L first succeed at
 * N=32000. The covariance estimate is not the bottleneck; the angular accuracy of
 * the recovered direction is (see break2.ts). Worth knowing before optimising the
 * wrong thing.
 */

import type { Mat } from '../lattice/types';
import { inverse, transpose, zeros } from '../lattice/matrix';

/** The whitening transform, its inputs, and the whitened sample set. */
export interface Whitening {
  /** Lattice dimension. */
  readonly n: number;
  /** Number of samples used. */
  readonly N: number;
  /** G = 12 * mean(v^T v), the estimate of R^T R. */
  readonly G: Mat;
  /** Upper-triangular L with G = L^T L. */
  readonly L: Mat;
  /** L^-1, also exactly upper triangular. */
  readonly Linv: Mat;
  /** Whitened samples, packed row-major: W[t*n + j] is coordinate j of sample t. */
  readonly W: Float64Array;
}

/**
 * G = 12 * mean_t (v_t^T v_t): the attacker's estimate of R^T R.
 *
 * Only the upper triangle is accumulated and then mirrored -- the matrix is
 * symmetric by construction, and doing the work twice would also let float
 * asymmetry creep in and upset the Cholesky.
 */
export function covariance(V: Mat, n: number): Mat {
  const N = V.length;
  const G = zeros(n, n);
  for (let t = 0; t < N; t++) {
    const v = V[t];
    for (let i = 0; i < n; i++) {
      const vi = v[i];
      if (vi === 0) continue;
      const Gi = G[i];
      for (let j = i; j < n; j++) Gi[j] += vi * v[j];
    }
  }
  for (let i = 0; i < n; i++) {
    for (let j = i; j < n; j++) {
      const g = (12 * G[i][j]) / N;
      G[i][j] = g;
      G[j][i] = g;
    }
  }
  return G;
}

/**
 * Cholesky in the form G = L^T L with L UPPER triangular.
 *
 * Computed as the standard lower-triangular C with G = C C^T, then transposed.
 * Upper is the form the whitening loop wants: with L upper triangular, L^-1 is
 * upper triangular too, so w_j = sum_{p<=j} v_p Linv[p][j] touches half the
 * matrix. Throws on a non-positive-definite G, which at these sample counts means
 * the caller handed it something that is not a covariance.
 */
export function choleskyUpper(G: Mat): Mat {
  const n = G.length;
  const C = zeros(n, n);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j <= i; j++) {
      let s = G[i][j];
      for (let p = 0; p < j; p++) s -= C[i][p] * C[j][p];
      if (i === j) {
        if (s <= 0) throw new Error(`Cholesky: matrix not positive definite (${s})`);
        C[i][j] = Math.sqrt(s);
      } else {
        C[i][j] = s / C[j][j];
      }
    }
  }
  return transpose(C);
}

/**
 * Apply an already-computed whitening to a sample set: W = V * Linv, packed.
 *
 * Split out from `whiten` because the hold-out scoring in break2.ts MUST reuse
 * the training whitening rather than fitting a fresh one -- re-fitting on the
 * hold-out would reintroduce exactly the in-sample bias the hold-out exists to
 * remove.
 *
 * The inner loop stops at p <= j because Linv is upper triangular. That is not a
 * micro-optimisation: it halves the cost of the single largest data pass in the
 * attack, and Gauss-Jordan on a triangular matrix does no row swaps, so the
 * sub-diagonal entries of Linv are exact zeros, not small numbers.
 */
export function applyWhitening(V: Mat, Linv: Mat): Float64Array {
  const N = V.length;
  const n = Linv.length;
  const W = new Float64Array(N * n);
  for (let t = 0; t < N; t++) {
    const v = V[t];
    const off = t * n;
    for (let j = 0; j < n; j++) {
      let s = 0;
      for (let p = 0; p <= j; p++) s += v[p] * Linv[p][j];
      W[off + j] = s;
    }
  }
  return W;
}

/** Estimate the covariance, factor it, and whiten the samples. Public data only. */
export function whiten(V: Mat, n: number): Whitening {
  const G = covariance(V, n);
  const L = choleskyUpper(G);
  const Linv = inverse(L);
  return { n, N: V.length, G, L, Linv, W: applyWhitening(V, Linv) };
}

/** max |A - I| entrywise. */
export function devFromIdentity(A: Mat): number {
  let m = 0;
  for (let i = 0; i < A.length; i++) {
    for (let j = 0; j < A[i].length; j++) {
      const d = Math.abs(A[i][j] - (i === j ? 1 : 0));
      if (d > m) m = d;
    }
  }
  return m;
}

/**
 * Shape of the estimated covariance: max |G / mean(diag G) - I|.
 *
 * Entirely public -- it never touches R -- and it is a free pre-check before the
 * descent runs at all. A round-off signer's G is R^T R, which is far from a
 * scalar matrix (measured 0.467 at n=16); a Klein signer's G is a scalar matrix
 * by construction (measured 0.0118). If this number is near zero the samples are
 * spherical and there is no parallelepiped to learn.
 */
export function covarianceShape(G: Mat): number {
  const n = G.length;
  let meanDiag = 0;
  for (let i = 0; i < n; i++) meanDiag += G[i][i] / n;
  const scaled = G.map((r) => Float64Array.from(r, (x) => x / meanDiag));
  return devFromIdentity(scaled);
}

/**
 * DIAGNOSTIC ONLY -- uses the secret basis.
 *
 * How close the estimated whitening came to orthogonalising: max |Q Q^T - I| for
 * Q = R * Linv. The attack must never call this; it exists so the lab can show
 * the convergence table in this file's header honestly instead of asserting it.
 */
export function whiteningError(R: Mat, Linv: Mat): number {
  const n = R.length;
  const Q = zeros(n, n);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      let s = 0;
      for (let p = 0; p <= j; p++) s += R[i][p] * Linv[p][j];
      Q[i][j] = s;
    }
  }
  const QQt = zeros(n, n);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      let s = 0;
      for (let p = 0; p < n; p++) s += Q[i][p] * Q[j][p];
      QQt[i][j] = s;
    }
  }
  return devFromIdentity(QQt);
}
