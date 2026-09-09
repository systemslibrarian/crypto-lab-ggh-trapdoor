/**
 * Break 2, step 3: gradient descent on the sphere.
 *
 * Minimise mom4 over unit vectors. One step, then renormalise:
 *
 *     u <- normalize( u - delta * grad ),   grad = (1/12) u - (1/30) sum a_i^3 q_i
 *
 * WHAT THE STEP RULE REALLY IS. Substituting the gradient,
 *
 *     u - delta*grad = (1 - delta/12) u + (delta/30) sum a_i^3 q_i
 *
 * and while 1 - delta/12 > 0, normalising kills that positive scalar, so this is
 *
 *     u <- normalize( u + c * sum a_i^3 q_i ),   c = (delta/30) / (1 - delta/12).
 *
 * That is a POWER ITERATION on a_i^3 -- each step cubes the coordinates in the
 * hidden frame and renormalises, so the largest a_i runs away from the rest.
 * Knowing this changes how delta should be picked: delta is not a stability
 * parameter to be kept small, it is a gear ratio.
 *
 * WHAT HAPPENS AT delta = 12, AND WHY IT IS NOT A SINGULARITY. c has a pole
 * there, but the pole belongs to the FACTORED form, not to the update. The
 * original step is perfectly well defined at 12: the u term vanishes and it
 * becomes
 *
 *     u <- normalize( (12/30) * sum a_i^3 q_i ) = normalize( sum a_i^3 q_i ),
 *
 * a PURE cubic power iteration with no memory of the previous iterate at all --
 * the cleanest form of the rule, not a breakdown of it. c -> infinity says
 * exactly that: the cubic term has become infinitely dominant over a u term that
 * is no longer there.
 *
 * Above 12 the u coefficient turns negative, so the step subtracts the previous
 * iterate, u <- normalize( (delta/30) S - (delta/12 - 1) u ). Still defined,
 * still convergent while the subtracted part stays small next to the cubic one --
 * and that is where it eventually fails, not at 12. Measured with the protocol
 * below on one frame (seed 20260908, starts from makeRng(777), maxIter 400):
 *
 *     delta   hit    converged   mean iters   ms/start
 *     9       88.3%    100%          42         5.9
 *     11.5    90.0%    100%          22         3.0
 *     11.9    90.0%    100%          19         2.6
 *     12      90.0%    100%          19         2.6      <- the pure cubic step
 *     12.1    90.0%    100%          18         2.5
 *     13      38.3%     40%         253        34.9      <- the u term starts to bite
 *     15       0.0%      0%         400        54.7      <- dead
 *
 * (Hit rates in that sweep sit at 88-90% where the table below reads 100%: it
 * draws its own frame, not the table's. What it is used for is the comparison
 * across delta within itself, which uses the same frame and the same starts at
 * every row.)
 *
 * DELTA, MEASURED (n=16, N=8000, 60 random starts; hit = sum a^4 > 0.99, i.e.
 * |cos(u, q_i)| > 0.9975):
 *
 *     delta   c        hit rate  mean iters  ms/start
 *     0.3     0.0103      8.3%      400      59.2      <- fails to converge
 *     0.7     0.0248     86.7%      400      61.1      <- the paper's value
 *     1.5     0.0571    100.0%      388      57.8
 *     3       0.1333    100.0%      190      26.8
 *     6       0.4000    100.0%       76      10.6
 *     9       1.2000    100.0%       36       5.1      <- shipped
 *     10.5    2.8000    100.0%       24       3.3
 *     11.5    9.2000    100.0%       17       2.4
 *
 * The surprise is in the same sweep at N=1000: EVERY delta gives a 0% hit rate
 * and they all land in the same place (best |cos| 0.9891 to 0.9894). So delta
 * controls SPEED, not ACCURACY -- accuracy is bought with samples, and nothing
 * else. delta = 9 is shipped because it is 10x faster than the paper's 0.7 at
 * identical accuracy and sits well inside the region where the u term still has
 * the sign the derivation assumes. The remaining speedup from 9 to 12 is 42
 * iterations down to 19, about 2x, and it is bought by moving towards a cliff
 * whose edge is between 12.1 and 13 on the sweep above and is a property of the
 * sample set rather than of the algebra. That is a bad trade for a demo that has
 * to be reliable on somebody else's machine.
 *
 * RESTARTS. Each descent converges to ONE row, chosen by which basin the random
 * start fell into, so recovering all n rows is a coupon-collector problem needing
 * about n*H_n draws. Measured medians 16 / 32.5 / 53 restarts at n = 8 / 12 / 16
 * against the prediction 21.7 / 37.2 / 54.0. The budget is 10n: a budget of 6n was
 * measured to be too tight, exhausting on one n=16 key in four.
 */

import type { Rng, Vec } from '../lattice/types';
import { mom4, mom4Grad } from './moments';

/** Step size. See the file header for the measured sweep behind this number. */
export const DEFAULT_DELTA = 9;

/** Iteration cap per restart. At delta = 9 convergence takes ~36. */
export const DEFAULT_MAX_ITER = 250;

/** Convergence test: max |u_new - u| below this. */
export const DEFAULT_TOL = 1e-9;

/** |cos| above which two directions are treated as the same one, up to sign. */
export const DEFAULT_DEDUPE = 0.99;

/**
 * The two coefficients the step rule really has:
 *
 *     u - delta*grad = uTerm * u + cubicTerm * sum a_i^3 q_i
 *
 * at |u| = 1. `uTerm` is 0 exactly at delta = 12 and negative above it. This is
 * the form that stays defined everywhere; `powerIterationCoefficient` is their
 * ratio, which is not.
 */
export function stepCoefficients(delta: number): { uTerm: number; cubicTerm: number } {
  return { uTerm: 1 - delta / 12, cubicTerm: delta / 30 };
}

/**
 * The power-iteration gain the step rule applies WHILE the u term is positive:
 * c = (delta/30) / (1 - delta/12).
 *
 * The pole at delta = 12 is a pole of this RATIO, not of the update. At delta =
 * 12 the u term is exactly zero and the step is the pure cubic power iteration
 * u <- normalize(sum a_i^3 q_i), which converges fastest of all -- see the file
 * header for the measured sweep through and past 12. Read a non-finite or
 * negative value here as "the u term has vanished or reversed", not as "the
 * iteration has broken".
 */
export function powerIterationCoefficient(delta: number): number {
  return delta / 30 / (1 - delta / 12);
}

/**
 * Restart budget for a full recovery: 10n.
 *
 * Coupon collector says n*H_n (21.7 at n=8, 54.0 at n=16) and the measured
 * medians match it, but the tail is long -- the worst observed n=16 key needed
 * 110. 6n was measured to exhaust on one n=16 key in four; 10n did not fail in
 * 30 keys across n = 8, 12, 16.
 */
export function restartBudget(n: number): number {
  return 10 * n;
}

/** One standard normal, Box-Muller. Used only to pick unbiased random starts. */
export function gaussian(rng: Rng): number {
  let u = 0;
  let v = 0;
  while (u === 0) u = rng();
  while (v === 0) v = rng();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

/** A uniformly random point on the unit sphere. */
export function randomUnitVector(n: number, rng: Rng): Vec {
  const u = new Float64Array(n);
  for (let i = 0; i < n; i++) u[i] = gaussian(rng);
  return normalize(u);
}

/** u / |u|. */
export function normalize(u: Vec): Vec {
  let s = 0;
  for (const x of u) s += x * x;
  const inv = 1 / Math.sqrt(s);
  const out = new Float64Array(u.length);
  for (let i = 0; i < u.length; i++) out[i] = u[i] * inv;
  return out;
}

/** Inner product of two vectors of equal length. */
export function dot(a: Vec, b: Vec): number {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += a[i] * b[i];
  return s;
}

export interface DescentOptions {
  /** Step size. Default 9. */
  delta?: number;
  /** Iteration cap. Default 250. */
  maxIter?: number;
  /** Convergence threshold on max |u_new - u|. Default 1e-9. */
  tol?: number;
}

export interface DescentResult {
  /** The direction converged to, a unit vector in whitened coordinates. */
  readonly u: Vec;
  /** Iterations actually used. */
  readonly iters: number;
  /** In-sample fourth moment at u. */
  readonly mom4: number;
  /** False if the iteration cap was hit before the tolerance was met. */
  readonly converged: boolean;
}

/**
 * One descent run from one random unit start.
 *
 * No line search, no momentum, no restarts inside: this is the plain rule from
 * the paper with the step size retuned, and it is deliberately the simplest thing
 * that works, because a learner has to be able to read it.
 */
export function descend(
  W: Float64Array,
  N: number,
  n: number,
  rng: Rng,
  opts: DescentOptions = {},
): DescentResult {
  const delta = opts.delta ?? DEFAULT_DELTA;
  const maxIter = opts.maxIter ?? DEFAULT_MAX_ITER;
  const tol = opts.tol ?? DEFAULT_TOL;

  let u = randomUnitVector(n, rng);
  const g = new Float64Array(n);
  const step = new Float64Array(n);
  let iters = 0;
  let converged = false;
  for (let it = 0; it < maxIter; it++) {
    iters = it + 1;
    mom4Grad(W, N, n, u, g);
    for (let j = 0; j < n; j++) step[j] = u[j] - delta * g[j];
    const next = normalize(step);
    let d = 0;
    for (let j = 0; j < n; j++) {
      const diff = Math.abs(next[j] - u[j]);
      if (diff > d) d = diff;
    }
    u = next;
    if (d < tol) {
      converged = true;
      break;
    }
  }
  return { u, iters, mom4: mom4(W, N, n, u), converged };
}

/**
 * Add `u` to `list` unless it duplicates a direction already there, UP TO SIGN.
 *
 * Up to sign because -q_i minimises the fourth moment exactly as well as q_i
 * does; the two are the same face of the parallelepiped seen from opposite sides,
 * and no amount of data can separate them. That indifference is one half of
 * invariant I4 (the other half is permutation, which is simply the order the
 * restarts happen to find them in).
 */
export function addUnique(list: Vec[], u: Vec, thresh: number = DEFAULT_DEDUPE): boolean {
  for (const d of list) if (Math.abs(dot(d, u)) > thresh) return false;
  list.push(u);
  return true;
}

/** Progress report, emitted once per restart. */
export interface RecoveryProgress {
  /** Restarts run so far, including this one. */
  readonly restarts: number;
  /** Distinct directions found so far. */
  readonly found: number;
  /** How many are needed: n. */
  readonly target: number;
  /** Whether this restart produced a new direction. */
  readonly isNew: boolean;
  /** Iterations this restart used. */
  readonly iters: number;
}

export interface RecoveryOptions extends DescentOptions {
  /** Restart cap. Default `restartBudget(n)` = 10n. */
  maxRestarts?: number;
  /** Dedupe |cos| threshold. Default 0.99. */
  dedupe?: number;
  /**
   * Called once per restart.
   *
   * One restart is ~35 ms at n=16 / N=64000, which is the natural tick
   * granularity for a UI: fine enough to feel live, coarse enough that posting a
   * message per tick costs nothing.
   */
  onRestart?: (p: RecoveryProgress) => void;
}

export interface DirectionRecovery {
  /** The distinct directions found, unit vectors in whitened coordinates. */
  readonly dirs: Vec[];
  /** Restarts used. */
  readonly restarts: number;
  /** Total descent iterations across all restarts. */
  readonly iterations: number;
  /** True if the restart budget ran out before n directions were found. */
  readonly exhausted: boolean;
}

/**
 * Restart the descent until n distinct directions have been found, or the budget
 * runs out.
 *
 * Reports exhaustion rather than throwing or padding the list: an incomplete
 * recovery is a legitimate outcome that the lab has to be able to display, and
 * the edge case "signature counter exceeds the cap without recovery" is exactly
 * this returning `exhausted: true`.
 */
export function recoverDirections(
  W: Float64Array,
  N: number,
  n: number,
  rng: Rng,
  opts: RecoveryOptions = {},
): DirectionRecovery {
  const maxRestarts = opts.maxRestarts ?? restartBudget(n);
  const dedupe = opts.dedupe ?? DEFAULT_DEDUPE;
  const dirs: Vec[] = [];
  let restarts = 0;
  let iterations = 0;
  while (dirs.length < n && restarts < maxRestarts) {
    restarts++;
    const r = descend(W, N, n, rng, opts);
    iterations += r.iters;
    const isNew = addUnique(dirs, r.u, dedupe);
    opts.onRestart?.({ restarts, found: dirs.length, target: n, isNew, iters: r.iters });
  }
  return { dirs, restarts, iterations, exhausted: dirs.length < n };
}
