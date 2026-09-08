/**
 * Klein / GPV discrete-Gaussian signing -- the fix, and the negative case C5'.
 *
 * Round-off signing (sign.ts) leaks a uniform sample from the parallelepiped
 * P(R), and the parallelepiped's corners point along the rows of R. Klein's
 * sampler (Klein, SODA 2000; Gentry-Peikert-Vaikuntanathan, STOC 2008) replaces
 * the deterministic rounding at each Gram-Schmidt coordinate with a DISCRETE
 * GAUSSIAN draw. Above a width threshold the output distribution of s - h is
 * within 2^-40 statistical distance of a SPHERICAL discrete Gaussian -- and a
 * sphere has no corners, no edges, and no fourth-moment structure. There is
 * nothing left to learn: the basis is provably hidden.
 *
 * THE WIDTH IS NOT A TUNING KNOB. It is
 *
 *     sigma = eta_eps(Z^n) * max_i ||b*_i||,   eta_eps = sqrt(ln(2n(1+2/eps))/pi)
 *
 * with eps = 2^-40 -- the smoothing parameter of the integers. `kleinFactor`
 * computes it; at n=16 it evaluates to 3.186, so with the measured maxGS = 18.98
 * the width is sigma = 60.48. The number is right because of that inequality,
 * not because it "looks big enough": below the smoothing parameter the per-
 * coordinate lattice structure shows through and the output is not spherical.
 *
 * MEASURED (n=16, 4 keys per mode, held-out scoring -- see break2.ts):
 *
 *     mode      sumA4 held-out   integrality gap   rows recovered   forgeries
 *     roundoff  1.0010           0.174             16.0/16          4/4
 *     klein     0.0061           0.473              0.0/16           0/4
 *
 * Per-key Klein sumA4 values straddle zero (0.0127, -0.0055, 0.0217, -0.0043).
 * That is the signature of NO structure at all, not of weak structure.
 *
 * THE HONEST CAVEAT. Klein signatures are about 4x longer than round-off ones
 * (measured ||v||inf 121-151 against a round-off bound of 29-31), so a verifier
 * calibrated for round-off rejects them outright. A Klein signer publishes its
 * own bound, `kleinBoundInf(sigma)` = 144.8 at these parameters. Measured against
 * its own bound each signer verifies 200/200. C5' therefore compares two valid
 * signature schemes over the same lattice, one broken and one not -- not a
 * working scheme against a broken one.
 */

import type { Mat, Rng, Vec } from '../lattice/types';
import { gramSchmidtRows, rnd, vecMat } from '../lattice/matrix';
import type { SignFn } from './sign';

/** Statistical-distance target for the smoothing parameter. */
export const KLEIN_EPS = Math.pow(2, -40);

/** Just enough of `gramSchmidtRows`' output to run the sampler. */
export interface RowGso {
  /** Gram-Schmidt orthogonalised rows b*_i. */
  readonly star: Mat;
  /** ||b*_i||^2. */
  readonly normSq: readonly number[];
}

/**
 * The smoothing parameter eta_eps(Z^n) = sqrt(ln(2n(1+2/eps))/pi).
 *
 * Computed, never hardcoded: at eps = 2^-40 it is 3.151 at n=8, 3.186 at n=16,
 * 3.251 at n=60 -- it grows like sqrt(log n), which is why quoting a single
 * constant would be wrong at the ends of the dimension slider.
 */
export function kleinFactor(n: number, eps: number = KLEIN_EPS): number {
  return Math.sqrt(Math.log(2 * n * (1 + 2 / eps)) / Math.PI);
}

/** max_i ||b*_i|| for the rows of R -- the quantity the width scales. */
export function maxGramSchmidtNorm(R: Mat): number {
  const { normSq } = gramSchmidtRows(R);
  let m = 0;
  for (const q of normSq) if (q > m) m = q;
  return Math.sqrt(m);
}

/** The width Klein must be run at over this basis: eta_eps(Z^n) * max_i ||b*_i||. */
export function kleinSigma(R: Mat, eps: number = KLEIN_EPS): number {
  return kleinFactor(R.length, eps) * maxGramSchmidtNorm(R);
}

/**
 * Published bound for a Klein signer.
 *
 * s - h is a discrete Gaussian of parameter sigma in the exp(-pi x^2/sigma^2)
 * convention, whose per-coordinate standard deviation is sigma/sqrt(2*pi). At
 * tail = 6 the per-coordinate rejection probability is below 1e-9, so a signer
 * can publish this and essentially never fail to verify its own signatures --
 * measured 200/200 at n=16.
 */
export function kleinBoundInf(sigma: number, tail = 6): number {
  return (tail * sigma) / Math.sqrt(2 * Math.PI);
}

/** Optional counters for the rejection sampler, so the acceptance rate can be shown. */
export interface SampleZStats {
  /** Candidate integers drawn. */
  draws: number;
  /** Candidates accepted. */
  accepts: number;
  /** Times the try cap was hit and `round(c)` was returned instead. */
  fallbacks: number;
}

/** A fresh, zeroed stats block. */
export function newSampleZStats(): SampleZStats {
  return { draws: 0, accepts: 0, fallbacks: 0 };
}

/**
 * Cap on rejection-sampling tries per coordinate.
 *
 * Acceptance is the ratio of the Gaussian's mass to the enclosing uniform box on
 * [c-6s, c+6s], measured at 8-10% here, so 500 tries fail with probability about
 * (0.92)^500 ~ 1e-18. The cap exists so a pathological width cannot hang the
 * browser, not because it is expected to fire; the fallback to round(c) is a
 * deliberate, visible degradation rather than an infinite loop.
 */
export const SAMPLE_Z_TRIES = 500;

/**
 * One draw from the discrete Gaussian over Z with centre c and width sigma,
 * i.e. Pr[z] proportional to exp(-pi (z-c)^2 / sigma^2).
 *
 * Rejection sampling against the uniform distribution on [c-6sigma, c+6sigma];
 * six widths leaves less than 1e-9 of the mass outside.
 */
export function sampleZ(c: number, sigma: number, rng: Rng, stats?: SampleZStats): number {
  const lo = Math.ceil(c - 6 * sigma);
  const hi = Math.floor(c + 6 * sigma);
  const span = hi - lo + 1;
  for (let t = 0; t < SAMPLE_Z_TRIES; t++) {
    const z = lo + Math.floor(rng() * span);
    const d = (z - c) / sigma;
    if (stats) stats.draws++;
    if (rng() < Math.exp(-Math.PI * d * d)) {
      if (stats) stats.accepts++;
      return z;
    }
  }
  if (stats) stats.fallbacks++;
  return rnd(c);
}

/**
 * Klein/GPV signature: a lattice point s in L(R) with s - h distributed as a
 * spherical discrete Gaussian of width sigma.
 *
 * Sequential, from the LAST Gram-Schmidt coordinate down to the first. At step i
 * the residual centre is d = <c, b*_i> / ||b*_i||^2 and the width in that integer
 * coordinate is sigma / ||b*_i|| -- narrow directions get narrow draws, which is
 * exactly what makes the OUTPUT spherical even though the basis is not. The
 * per-coordinate widths are the only place R enters, and the smoothing condition
 * is what stops them from being readable in the output.
 */
export function signKlein(
  h: Vec,
  R: Mat,
  gso: RowGso,
  sigma: number,
  rng: Rng,
  stats?: SampleZStats,
): Vec {
  const n = R.length;
  const c = Float64Array.from(h);
  const z = new Float64Array(n);
  for (let i = n - 1; i >= 0; i--) {
    const star = gso.star[i];
    let dot = 0;
    for (let q = 0; q < n; q++) dot += c[q] * star[q];
    const centre = dot / gso.normSq[i];
    const width = sigma / Math.sqrt(gso.normSq[i]);
    const zi = sampleZ(centre, width, rng, stats);
    z[i] = zi;
    const Ri = R[i];
    for (let q = 0; q < n; q++) c[q] -= zi * Ri[q];
  }
  return vecMat(z, R);
}

/**
 * Bind a basis to a Klein `SignFn`, computing the Gram-Schmidt data and the
 * smoothing width once.
 *
 * Returned as the same `SignFn` the round-off signer produces, so break2.ts
 * cannot tell them apart -- which is the point of C5'.
 */
export function makeKleinSigner(
  R: Mat,
  rng: Rng,
  sigma: number = kleinSigma(R),
  stats?: SampleZStats,
): SignFn {
  const gso = gramSchmidtRows(R);
  return (h: Vec) => signKlein(h, R, gso, sigma, rng, stats);
}
