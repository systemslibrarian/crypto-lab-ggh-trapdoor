/**
 * Break 2, step 2: the fourth moment. The single number that finds a cube.
 *
 * After whitening (whiten.ts) the samples are w = x*Q with x uniform in
 * [-1/2,1/2)^n and Q orthogonal. Look at the fourth moment along a unit
 * direction u, and write a_i = <q_i, u> for the direction's coordinates in the
 * unknown orthonormal frame (so sum_i a_i^2 = |u|^2 = 1):
 *
 *     <w, u> = sum_i x_i a_i
 *     E[<w,u>^4] = E[x^4] sum a_i^4 + 3 E[x^2]^2 ( (sum a_i^2)^2 - sum a_i^4 )
 *                = (1/80) sum a_i^4 + (1/48) ( 1 - sum a_i^4 )
 *
 *     mom4(u) = 1/48 - (1/120) * sum_i a_i^4                    (1)
 *
 * using E[x^2] = 1/12 and E[x^4] = 1/80 for x uniform on [-1/2,1/2).
 *
 * Formula (1) is the attack. sum a_i^4 is maximal exactly when u is one of the
 * +-q_i (value 1) and minimal when u is equally spread over the frame (value
 * 1/n). Since the coefficient of sum a_i^4 is NEGATIVE, MINIMISING the fourth
 * moment over the unit sphere lands precisely on +-q_i -- a row of the secret
 * basis, in whitened coordinates. A sphere would give 1/48 from every direction
 * and there would be nothing to descend.
 *
 * COMPARING WITH THE PAPER. Nguyen and Regev print
 *
 *     mom4(u) = 1/3 - (2/15) sum a_i^4,   minimised at 1/5,
 *
 * which looks like a different result and is not. Their parallelepiped is
 * [-1,1]^n; ours is [-1/2,1/2)^n, because that is what Babai round-off actually
 * produces -- round(y) - y can never exceed 1/2. Scaling x by 2 scales <w,u>^4 by
 * 2^4 = 16, and indeed 16 * (1/48) = 1/3 and 16 * (1/120) = 2/15 and
 * 16 * 0.0125 = 1/5. Both statements are correct under their own scaling; a
 * reader checking this file against the paper should expect exactly a factor 16.
 *
 * VERIFIED NUMERICALLY, not asserted. With an exact whitening oracle
 * (max|QQ^T - I| = 4.4e-16, so the only error left is Monte-Carlo), formula (1)
 * matched the sample estimate to 0.064% at n=8 and 0.079% at n=16 with N=256000,
 * across sum a_i^4 from 0.127 to 1.000, with the error falling as 1/sqrt(N)
 * (0.278% at N=1000, 2.1% at N=8000 for n=16).
 *
 * THE GRADIENT. Off the unit sphere, mom4(u) = (1/48)|u|^4 - (1/120) sum a_i^4, so
 *
 *     grad mom4 = (1/12) |u|^2 u - (1/30) sum_i a_i^3 q_i,        (2)
 *
 * which at |u| = 1 is (1/12) u - (1/30) sum a_i^3 q_i. Note that the sample-based
 * gradient 4 * E[<w,u>^3 w] computed by `mom4Grad` is the same object -- it is
 * (2) with the a_i estimated from data instead of read off a frame nobody has.
 * descent.ts is what turns (2) into a search.
 */

import type { Vec } from '../lattice/types';

/**
 * The fourth moment of a direction with NO structure behind it: 1/48.
 *
 * If the samples were spherical, every direction would return this. It is the
 * ceiling of the objective and the reference point for the headline statistic.
 */
export const MOM4_SPHERICAL = 1 / 48;

/**
 * Monte-Carlo estimate of E[<w,u>^4] over packed whitened samples.
 *
 * `W` is row-major, N samples of length n, as produced by `whiten`. This is the
 * hot loop of the whole attack: 2*N*n flops, run ~36 times per restart and
 * ~10n restarts per attempt.
 */
export function mom4(W: Float64Array, N: number, n: number, u: Vec): number {
  let s = 0;
  for (let t = 0; t < N; t++) {
    const off = t * n;
    let p = 0;
    for (let j = 0; j < n; j++) p += W[off + j] * u[j];
    const p2 = p * p;
    s += p2 * p2;
  }
  return s / N;
}

/**
 * Gradient of E[<w,u>^4], namely 4 * E[<w,u>^3 * w].
 *
 * Equal to expression (2) in the file header with the frame estimated from data.
 * `out` may be supplied to avoid an allocation per iteration -- the descent
 * reuses one buffer for all 250 iterations.
 */
export function mom4Grad(W: Float64Array, N: number, n: number, u: Vec, out?: Vec): Vec {
  const g = out ?? new Float64Array(n);
  g.fill(0);
  for (let t = 0; t < N; t++) {
    const off = t * n;
    let p = 0;
    for (let j = 0; j < n; j++) p += W[off + j] * u[j];
    const p3 = 4 * p * p * p;
    for (let j = 0; j < n; j++) g[j] += p3 * W[off + j];
  }
  for (let j = 0; j < n; j++) g[j] /= N;
  return g;
}

/**
 * THE HEADLINE PUBLIC STATISTIC: sum_i a_i^4, recovered from a measured moment.
 *
 * Inverting (1): sum a_i^4 = 120 * (1/48 - mom4). It needs no secret and no
 * frame -- only the whitened samples and the direction -- yet it reads 1.0 when
 * the direction is a basis row and 0 when the samples have no structure. Measured
 * on held-out signatures at n=16: 1.0010 for round-off signing, 0.0061 for Klein.
 *
 * Negative values are legitimate and informative: they mean the measured moment
 * came out ABOVE the spherical 1/48, which is what pure sampling noise around
 * zero structure looks like. Per-key Klein values measured 0.0127, -0.0055,
 * 0.0217, -0.0043. Do not clamp this at zero; the sign straddling zero is the
 * evidence.
 */
export function sumA4FromMom4(m: number): number {
  return 120 * (MOM4_SPHERICAL - m);
}

/** The inverse of `sumA4FromMom4`, for drawing landmark gridlines. */
export function mom4FromSumA4(sumA4: number): number {
  return MOM4_SPHERICAL - sumA4 / 120;
}

/** Formula (1) evaluated directly from the frame coefficients a_i. */
export function mom4Analytic(a: ArrayLike<number>): number {
  let s4 = 0;
  for (let i = 0; i < a.length; i++) {
    const a2 = a[i] * a[i];
    s4 += a2 * a2;
  }
  return MOM4_SPHERICAL - s4 / 120;
}

/**
 * The coefficients a_i = <q_i, u> of a direction in a known orthonormal frame.
 *
 * The attack never has Q, so this is for tests and exhibits: it is how formula
 * (1) is checked against a Monte-Carlo estimate.
 */
export function frameCoefficients(u: Vec, Q: readonly Float64Array[]): Vec {
  const a = new Float64Array(Q.length);
  for (let i = 0; i < Q.length; i++) {
    let s = 0;
    const qi = Q[i];
    for (let j = 0; j < u.length; j++) s += qi[j] * u[j];
    a[i] = s;
  }
  return a;
}

/** A reference value of the objective, for gridlines on the descent plot. */
export interface Mom4Landmark {
  readonly label: string;
  readonly sumA4: number;
  readonly mom4: number;
  readonly note: string;
}

/**
 * The four values worth drawing on the objective axis.
 *
 * At n=16 these evaluate to mom4 = 0.02083333 (spherical), 0.02031250 (1/n),
 * 0.01944444 (random u) and 0.01250000 (u = +-q_i) -- the descent's whole job is
 * to travel from the third to the fourth.
 */
export function mom4Landmarks(n: number): Mom4Landmark[] {
  const at = (label: string, sumA4: number, note: string): Mom4Landmark => ({
    label,
    sumA4,
    mom4: mom4FromSumA4(sumA4),
    note,
  });
  return [
    at('spherical', 0, 'no parallelepiped structure at all: every direction reads 1/48'),
    at('flat u', 1 / n, 'the minimum of sum a^4 on the sphere, at u spread equally over the frame'),
    at('random u', 3 / (n + 2), 'the expected value of sum a^4 for a uniformly random unit u'),
    at('u = +-q_i', 1, 'a row of the secret basis: the maximum of sum a^4, so the minimum of mom4'),
  ];
}
