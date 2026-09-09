/**
 * Klein / GPV discrete-Gaussian signing -- the fix, and the negative case C5'.
 *
 * Round-off signing (sign.ts) leaks a sample spread over the parallelepiped
 * P(R), and the parallelepiped's corners point along the rows of R. Klein's
 * sampler (Klein, SODA 2000; Gentry-Peikert-Vaikuntanathan, STOC 2008) replaces
 * the deterministic rounding at each Gram-Schmidt coordinate with a DISCRETE
 * GAUSSIAN draw. Above a width threshold the IDEAL sampler's output distribution
 * for s - h is within 2^-40 statistical distance of a SPHERICAL discrete
 * Gaussian -- and a sphere has no corners, no edges, and no fourth-moment
 * structure.
 *
 * WHAT IS DEMONSTRATED HERE, AND WHAT IS CITED. The 2^-40 is the GPV/Klein
 * statement about the ideal sampler at the smoothing parameter; it is a citation,
 * not something this file establishes. What this file establishes is narrower and
 * it is worth stating exactly: the Nguyen-Regev fourth-moment attack, run
 * byte-identically against both signers through the same `SignFn` seam, finds no
 * held-out signal against this one at n=16 on 4 keys (table below). That is a
 * null result for ONE attack at ONE parameter set. It is not a total-variation
 * measurement, and it does not say "there is nothing left to learn" -- no
 * experiment can say that.
 *
 * TWO PLACES WHERE THIS IMPLEMENTATION IS NOT THE IDEAL SAMPLER, both measured
 * rather than waved at:
 *
 *   truncation   each coordinate is drawn by rejection on [c-6s, c+6s], so the
 *                tails are cut. `truncationTailMass` computes what that removes:
 *                1.3e-50 to 2.1e-50 at the per-coordinate widths this key
 *                actually uses (3.19 to 5.71 at n=16), against the 2^-40 = 9.1e-13
 *                the citation is about. Truncation is therefore 37 orders of
 *                magnitude away from being the weak point, and 6 is not a number
 *                that needs defending.
 *   fallback     after SAMPLE_Z_TRIES rejections `sampleZ` returns round(c),
 *                which is round-off -- exactly the leak Break 2 lives on. It is
 *                the one place where a Klein signature could carry parallelepiped
 *                structure. MEASURED at n=16 on the key of seed 5150, 500
 *                signatures = 8,000 coordinate draws from 96,328 candidates:
 *                acceptance 0.0830, fallbacks 0. The per-coordinate probability
 *                is at most (1-0.0830)^500 = 1.5e-19, and even at a width of 0.5
 *                -- far narrower than the 3.19-5.71 this lab actually runs --
 *                acceptance is 0.0548 and the bound is 5.9e-13. `fallbackProbability`
 *                computes that from a measured acceptance rate, and the sampler
 *                counts fallbacks so the UI can report the real one rather than
 *                the bound.
 *
 * Both are per-coordinate statements about the sampler, not about the attack. The
 * attack result stands on the table below and on nothing else.
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
 * That is what no structure looks like to THIS statistic at THIS sample size --
 * a signal too small for the fourth moment to see, which is the strongest thing
 * a null result of this shape can say.
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
 * Probability that the try cap is reached for one coordinate, given a MEASURED
 * per-try acceptance rate: (1 - acceptance)^tries.
 *
 * The tries are independent, so this is exact for the model and the only input
 * it needs is a number the sampler already counts. It is a bound on the rate of
 * the one degradation that would matter -- see the fallback note in the file
 * header -- rather than a claim that the fallback never happens.
 */
export function fallbackProbability(acceptance: number, tries: number = SAMPLE_Z_TRIES): number {
  return Math.pow(1 - acceptance, tries);
}

/**
 * The discrete Gaussian mass `sampleZ` throws away by truncating at +-tail*sigma,
 * as a fraction of the untruncated mass.
 *
 * Summed over the integers rather than approximated by the continuous tail, and
 * maximised over 16 centre offsets in [0,1) because the mass depends slightly on
 * where c sits between two integers. Terms beyond (tail+8)*sigma underflow to
 * zero at every width used here, so the window is complete.
 *
 * At tail = 6 this is 6.6e-51 at sigma = 1 and 1.3e-50 to 2.1e-50 at the
 * per-coordinate widths the n=16 key actually uses -- against the 2^-40 = 9.1e-13
 * the smoothing parameter is chosen for, so truncation is not what limits the
 * claim.
 */
export function truncationTailMass(sigma: number, tail = 6): number {
  let worst = 0;
  for (let offset = 0; offset < 16; offset++) {
    const c = offset / 16;
    const limit = Math.ceil((tail + 8) * sigma) + 2;
    let inside = 0;
    let outside = 0;
    for (let z = -limit; z <= limit + 1; z++) {
      const d = z - c;
      const w = Math.exp((-Math.PI * d * d) / (sigma * sigma));
      if (Math.abs(d) > tail * sigma) outside += w;
      else inside += w;
    }
    const frac = outside / (inside + outside);
    if (frac > worst) worst = frac;
  }
  return worst;
}

/**
 * One draw from the discrete Gaussian over Z with centre c and width sigma,
 * i.e. Pr[z] proportional to exp(-pi (z-c)^2 / sigma^2).
 *
 * Rejection sampling against the uniform distribution on [c-6sigma, c+6sigma].
 * Six widths is 6*sqrt(2*pi) = 15.0 standard deviations in this convention, so
 * what is cut off is 1.3e-50 to 2.1e-50 at the widths in use, not 1e-9;
 * `truncationTailMass` computes it for a given width instead of quoting one.
 *
 * On the fallback path -- the try cap reached -- this returns round(c), which is
 * Babai round-off for that coordinate and therefore the one output of this file
 * that could carry the structure Break 2 hunts for. It is counted in `stats` and
 * bounded by `fallbackProbability`; measured 0 in 8,000 coordinate draws.
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
 * spherical discrete Gaussian of width sigma (up to the truncation and fallback
 * accounted for in the file header).
 *
 * Sequential, from the LAST Gram-Schmidt coordinate down to the first. At step i
 * the residual centre is d = <c, b*_i> / ||b*_i||^2 and the width in that integer
 * coordinate is sigma / ||b*_i|| -- narrow directions get narrow draws, which is
 * exactly what makes the OUTPUT spherical even though the basis is not. The
 * per-coordinate widths are the only place R enters, and the smoothing condition
 * is what makes the cited theorem apply to them; what is measured here is that
 * the fourth-moment attack cannot read them (see the header).
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
