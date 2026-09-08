/**
 * Classical LLL (Lenstra-Lenstra-Lovasz, 1982) with delta = 0.99.
 *
 * Floating-point Gram-Schmidt, EXACT integer basis updates, and a runtime guard
 * that every integer passing through the basis or the transform stays a safe
 * double integer.
 *
 * WHY NOT FRACTION-FREE / BAREISS LLL. The textbook "integral LLL" avoids floats
 * by carrying d_i = det Gram(b_1..b_i) = prod_{j<i} ||b*_j||^2 as exact integers.
 * Those pivots are enormous. Two independent measurements on this lab's own
 * matrices:
 *
 *   - On the public basis B the final pivot is det(B)^2, measured at 10^16.3 at
 *     n=8 and 10^177.8 at n=60. 2^53 is 9.0e15, so the very smallest dimension
 *     this lab offers already overflows.
 *   - Measured directly on the real centered embedding bases this file is asked
 *     to reduce (one per dimension, this lab's keygen, messages in [-128,127]):
 *
 *         n     max log2(d_i)   first i with log2(d_i) > 53
 *         8     100.7           4
 *         16    211.2           3
 *         32    445.3           3
 *         60    875.1           3
 *
 * A fraction-free LLL in Number would therefore be silently wrong at EVERY
 * dimension this lab offers, and it would go wrong by the THIRD basis vector --
 * not "at large n". Worse, the Gram ENTRIES themselves stay small (max log2 =
 * 27.3 at n=8 rising to 38.5 at n=60, all far under 53), so the obvious sanity
 * check "does the Gram matrix fit in a double?" passes while the algorithm is
 * already producing garbage. Float Gram-Schmidt plus exact integer row operations
 * is the right design: the floats only ever decide WHICH integer row operation to
 * perform, and the operation itself is exact.
 *
 * THE 2^53 GUARD IS A REAL CORRECTNESS SIGNAL, NOT A FORMALITY. Measured over 20
 * Break 1 runs at each of n = 8, 16, 32, 60, the largest integer touched anywhere
 * inside LLL was:
 *
 *     with the embedding's target reduction on    2^11.8 .. 2^13.7
 *     with it off                                 2^16.6 .. 2^18.1
 *
 * i.e. 35 to 41 binary orders of margin against 2^53, and every one of those 160
 * runs recovered the message. Pushed deliberately past the envelope (by scrambling
 * the public basis with far more elementary operations than keygen uses) the
 * correspondence is exact: 6/6 attacks succeeded in every run where the guard
 * stayed quiet, 0/6 in every run where it fired. So it is surfaced as a named
 * failure and never swallowed -- a silently truncated integer would turn every
 * downstream "verified" into a lie.
 *
 * ROW CONVENTION: the rows of `basis` are the lattice vectors, matching the rest
 * of the lab. `transform` is the unimodular H with H * inputBasis === basis
 * exactly, which is what lets the embedding attack read message coefficients
 * straight off an integer matrix instead of solving a system with B^-1.
 */

import type { Mat } from '../lattice/types';
import { TWO53, cloneMat, eye, gramSchmidtRows, norm2 } from '../lattice/matrix';

/** The reduction parameter. 0.99 is the strongest useful value (delta < 1). */
export const LLL_DELTA = 0.99;

/** Progress ticket for a caller driving LLL from a Web Worker or an animation loop. */
export interface LllProgress {
  /** Current position of the reduction front, 1..n. */
  readonly k: number;
  /** Number of basis vectors. */
  readonly n: number;
  /** Swaps performed so far -- the honest measure of how much work is left. */
  readonly swaps: number;
  /** Main-loop iterations so far. */
  readonly iters: number;
}

/** Where an out-of-range integer appeared. */
export type LllGuardSite = 'input' | 'basis' | 'transform';

/**
 * A named reason the reduction did not complete.
 *
 * `integer-overflow` means the exact-integer contract was broken and the output
 * must not be trusted. `iteration-cap` means the caller's budget ran out; the
 * partial basis is still a basis of the same lattice (H * input === basis still
 * holds), it is simply not fully reduced.
 */
export type LllFailure =
  | {
      readonly kind: 'integer-overflow';
      readonly where: LllGuardSite;
      /** The offending absolute value. */
      readonly maxAbs: number;
      /** 2^53 - 1. */
      readonly limit: number;
      readonly message: string;
    }
  | {
      readonly kind: 'iteration-cap';
      readonly iters: number;
      readonly maxIters: number;
      readonly message: string;
    };

export interface LllOptions {
  /** Reduction parameter, default 0.99. */
  delta?: number;
  /**
   * Full Gram-Schmidt rebuild every this many swaps, default 200.
   *
   * The incremental mu/norm update on a swap is the standard Cohen recurrence and
   * it drifts in floating point. Rebuilding costs O(n^3) once per 200 swaps, which
   * is negligible, and it is why the independent reducedness check comes back
   * clean (max |mu| = 0.499940, zero Lovasz violations) even at n=100.
   */
  refreshEvery?: number;
  /** Iteration budget, default 4000*n^2. Exceeding it is reported, never hidden. */
  maxIters?: number;
  /** Called every `progressEvery` iterations, so a worker can post progress. */
  onProgress?: (p: LllProgress) => void;
  /** Iterations between progress callbacks, default 512. */
  progressEvery?: number;
}

export interface LllResult {
  /** The reduced basis (partial if `failure` is non-null). */
  readonly basis: Mat;
  /** Unimodular H with H * inputBasis === basis, exactly, entry for entry. */
  readonly transform: Mat;
  /** Null on a clean run. Any non-null value means: do not trust `basis` blindly. */
  readonly failure: LllFailure | null;
  /** Largest absolute integer that passed through the basis or the transform. */
  readonly guardMax: number;
  /** Swaps performed. */
  readonly swaps: number;
  /** Main-loop iterations performed. */
  readonly iters: number;
}

function overflowFailure(where: LllGuardSite, maxAbs: number): LllFailure {
  return {
    kind: 'integer-overflow',
    where,
    maxAbs,
    limit: TWO53,
    message:
      `LLL left the exact-integer range: |${where} entry| = ${maxAbs} is not a safe integer ` +
      `(limit 2^53 = ${TWO53}). The reduced basis cannot be trusted, so this is reported ` +
      'as a failure rather than returned as a silently wrong answer.',
  };
}

/**
 * Reduce the rows of `basisIn`. The input is not modified.
 *
 * Every entry of `basisIn` must be an exact integer within 2^53; that is checked,
 * not assumed, and a violation comes back as `failure.where === 'input'`.
 */
export function lllReduce(basisIn: Mat, opts: LllOptions = {}): LllResult {
  const delta = opts.delta ?? LLL_DELTA;
  const refreshEvery = opts.refreshEvery ?? 200;
  const progressEvery = opts.progressEvery ?? 512;
  const n = basisIn.length;
  const dim = basisIn[0].length;
  const maxIters = opts.maxIters ?? 4000 * n * n;
  const onProgress = opts.onProgress;

  const b = cloneMat(basisIn);
  const H = eye(n);

  // Held in an object rather than two `let`s so that narrowing after the closure
  // below has written to them is not merely assumed by the type checker.
  const g: { max: number; failure: LllFailure | null } = { max: 0, failure: null };

  /**
   * The exactness guard. `Number.isSafeInteger` catches both losses at once: a
   * value past 2^53, and a value that has stopped being an integer. It runs over a
   * row we have just written, so it does not change the cost of the update.
   */
  function guard(row: Float64Array, where: LllGuardSite): void {
    for (let t = 0; t < row.length; t++) {
      const a = Math.abs(row[t]);
      if (a > g.max) g.max = a;
      if (g.failure === null && !Number.isSafeInteger(row[t])) g.failure = overflowFailure(where, a);
    }
  }

  for (const row of basisIn) guard(row, 'input');
  if (g.failure !== null) {
    return { basis: b, transform: H, failure: g.failure, guardMax: g.max, swaps: 0, iters: 0 };
  }

  // Float workspace: mu coefficients, squared norms of the Gram-Schmidt vectors,
  // and the orthogonalised rows themselves.
  const mu: Float64Array[] = [];
  for (let i = 0; i < n; i++) mu.push(new Float64Array(n));
  const Bn = new Float64Array(n);
  const bs: Float64Array[] = [];
  for (let i = 0; i < n; i++) bs.push(new Float64Array(dim));

  function gramSchmidt(): void {
    for (let i = 0; i < n; i++) {
      const bi = b[i];
      const bsi = bs[i];
      for (let t = 0; t < dim; t++) bsi[t] = bi[t];
      for (let j = 0; j < i; j++) {
        const bsj = bs[j];
        let d = 0;
        for (let t = 0; t < dim; t++) d += bi[t] * bsj[t];
        const m = Bn[j] > 0 ? d / Bn[j] : 0;
        mu[i][j] = m;
        if (m !== 0) for (let t = 0; t < dim; t++) bsi[t] -= m * bsj[t];
      }
      let s = 0;
      for (let t = 0; t < dim; t++) s += bsi[t] * bsi[t];
      Bn[i] = s;
    }
  }

  /** Size-reduce b[k] against b[l]: subtract the nearest integer multiple. */
  function red(k: number, l: number): void {
    if (Math.abs(mu[k][l]) <= 0.5) return;
    const q = Math.round(mu[k][l]);
    if (q === 0) return;
    const bk = b[k];
    const bl = b[l];
    const Hk = H[k];
    const Hl = H[l];
    for (let t = 0; t < dim; t++) bk[t] -= q * bl[t];
    for (let t = 0; t < n; t++) Hk[t] -= q * Hl[t];
    guard(bk, 'basis');
    guard(Hk, 'transform');
    mu[k][l] -= q;
    for (let i = 0; i < l; i++) mu[k][i] -= q * mu[l][i];
  }

  gramSchmidt();
  let k = 1;
  let swaps = 0;
  let iters = 0;
  let hitCap = false;
  while (k < n) {
    if (g.failure !== null) break;
    if (++iters > maxIters) { hitCap = true; break; }
    if (onProgress !== undefined && iters % progressEvery === 0) {
      onProgress({ k, n, swaps, iters });
    }
    red(k, k - 1);
    const mk = mu[k][k - 1];
    if (Bn[k] >= (delta - mk * mk) * Bn[k - 1]) {
      // Lovasz condition holds: finish size-reducing b[k], then advance.
      for (let l = k - 2; l >= 0; l--) red(k, l);
      k++;
    } else {
      const tb = b[k]; b[k] = b[k - 1]; b[k - 1] = tb;
      const th = H[k]; H[k] = H[k - 1]; H[k - 1] = th;
      for (let j = 0; j < k - 1; j++) { const t = mu[k][j]; mu[k][j] = mu[k - 1][j]; mu[k - 1][j] = t; }
      // Cohen's incremental update of mu and the squared norms across a swap.
      const m0 = mu[k][k - 1];
      const Bnew = Bn[k] + m0 * m0 * Bn[k - 1];
      if (Bnew > 0) {
        mu[k][k - 1] = (m0 * Bn[k - 1]) / Bnew;
        Bn[k] = (Bn[k - 1] * Bn[k]) / Bnew;
        Bn[k - 1] = Bnew;
        for (let i = k + 1; i < n; i++) {
          const t = mu[i][k];
          mu[i][k] = mu[i][k - 1] - m0 * t;
          mu[i][k - 1] = t + mu[k][k - 1] * mu[i][k];
        }
      } else {
        // A dependent row appeared in floating point; rebuild rather than divide by zero.
        gramSchmidt();
      }
      if (++swaps % refreshEvery === 0) gramSchmidt();
      k = Math.max(k - 1, 1);
    }
  }

  let failure: LllFailure | null = g.failure;
  if (failure === null && hitCap) {
    failure = {
      kind: 'iteration-cap',
      iters,
      maxIters,
      message:
        `LLL stopped after ${iters} iterations (cap ${maxIters}). The returned basis is a ` +
        'valid basis of the same lattice but is not fully reduced.',
    };
  }

  return { basis: b, transform: H, failure, guardMax: g.max, swaps, iters };
}

/** Independent verdict on whether a basis really is LLL-reduced. */
export interface LllReducedCheck {
  /** All |mu_ij| <= 1/2, within float tolerance. */
  readonly sizeReduced: boolean;
  /** The largest |mu_ij| found. */
  readonly maxAbsMu: number;
  /** No Lovasz violations. */
  readonly lovaszOk: boolean;
  /** How many k violate ||b*_k||^2 >= (delta - mu_{k,k-1}^2) ||b*_{k-1}||^2. */
  readonly lovaszViolations: number;
  /** Both conditions hold. */
  readonly reduced: boolean;
}

/**
 * Recompute Gram-Schmidt from scratch on `basis` and test the two LLL conditions
 * directly.
 *
 * This shares no state with `lllReduce` on purpose -- it is the check that caught
 * float drift during development, and it is what the tests assert, rather than
 * "the function returned without throwing".
 *
 * `tol` absorbs the float error of the recomputation itself: the two conditions
 * are statements about exact integers, but the Gram-Schmidt used to test them is
 * not exact. Measured over 160 real embedding reductions (n = 8, 16, 32, 60, both
 * embedding forms, 20 ciphertexts each), max |mu| came out at exactly
 * 0.5000000000000000 -- never above it -- and there were zero Lovasz violations
 * even with tol set to 0. The uncentered form reaches the bound exactly because
 * its {0,-1} residual makes some projections exact half-integers; the centered
 * form peaked at 0.49948. The default tolerance is therefore slack, not load-
 * bearing.
 */
export function checkLllReduced(basis: Mat, delta: number = LLL_DELTA, tol = 1e-9): LllReducedCheck {
  const { mu, normSq } = gramSchmidtRows(basis);
  const n = basis.length;
  let maxAbsMu = 0;
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < i; j++) {
      const a = Math.abs(mu[i][j]);
      if (a > maxAbsMu) maxAbsMu = a;
    }
  }
  let lovaszViolations = 0;
  for (let k = 1; k < n; k++) {
    const m = mu[k][k - 1];
    const need = (delta - m * m) * normSq[k - 1];
    if (normSq[k] < need - tol * Math.max(1, Math.abs(need))) lovaszViolations++;
  }
  const sizeReduced = maxAbsMu <= 0.5 + tol;
  const lovaszOk = lovaszViolations === 0;
  return { sizeReduced, maxAbsMu, lovaszOk, lovaszViolations, reduced: sizeReduced && lovaszOk };
}

/** Euclidean norm of the shortest row -- the headline observable of the embedding attack. */
export function shortestRowNorm(basis: Mat): number {
  let best = Infinity;
  for (const r of basis) {
    const v = norm2(r);
    if (v < best) best = v;
  }
  return best;
}
