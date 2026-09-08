import { describe, expect, it } from 'vitest';
import { gramSchmidtRows, makeRng, zeros } from '../lattice/matrix';
import type { Mat, Rng } from '../lattice/types';
import { sumA4FromMom4 } from './moments';
import {
  DEFAULT_DELTA,
  addUnique,
  descend,
  dot,
  gaussian,
  normalize,
  powerIterationCoefficient,
  randomUnitVector,
  recoverDirections,
  restartBudget,
} from './descent';

/** An exact orthonormal frame -- the thing the descent is supposed to find. */
function randomFrame(n: number, rng: Rng): Mat {
  const A = zeros(n, n);
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) A[i][j] = gaussian(rng);
  const { star, normSq } = gramSchmidtRows(A);
  return star.map((r, i) => Float64Array.from(r, (x) => x / Math.sqrt(normSq[i])));
}

/** N samples of w = x*Q with x uniform in [-1/2,1/2)^n, packed row-major. */
function cubeSamples(Q: Mat, N: number, rng: Rng): Float64Array {
  const n = Q.length;
  const W = new Float64Array(N * n);
  for (let t = 0; t < N; t++) {
    const off = t * n;
    for (let i = 0; i < n; i++) {
      const xi = rng() - 0.5;
      const qi = Q[i];
      for (let j = 0; j < n; j++) W[off + j] += xi * qi[j];
    }
  }
  return W;
}

/** How well u lines up with the nearest frame row, up to sign. */
function bestAlignment(u: Float64Array, Q: Mat): number {
  let best = 0;
  for (const q of Q) best = Math.max(best, Math.abs(dot(u, q)));
  return best;
}

describe('the step rule', () => {
  it('is a power iteration on a^3 with gain c = (delta/30)/(1 - delta/12)', () => {
    expect(powerIterationCoefficient(0.7)).toBeCloseTo(0.0248, 4);
    expect(powerIterationCoefficient(DEFAULT_DELTA)).toBeCloseTo(1.2, 12);
    expect(powerIterationCoefficient(11.5)).toBeCloseTo(9.2, 12);
    // Singular at delta = 12: the u term vanishes entirely.
    expect(Number.isFinite(powerIterationCoefficient(12))).toBe(false);
    // Above it the sign flips and the iteration climbs instead of descending.
    expect(powerIterationCoefficient(13)).toBeLessThan(0);
  });

  it('budgets 10n restarts, comfortably above the coupon-collector estimate n*H_n', () => {
    expect(restartBudget(8)).toBe(80);
    expect(restartBudget(16)).toBe(160);
    let harmonic = 0;
    for (let i = 1; i <= 16; i++) harmonic += 1 / i;
    expect(restartBudget(16)).toBeGreaterThan(3 * 16 * harmonic - 2 * 16 * harmonic);
    expect(16 * harmonic).toBeCloseTo(54.0, 0);
  });
});

describe('descent on the sphere', () => {
  const n = 8;
  const N = 20000;
  const rng = makeRng(20260908);
  const Q = randomFrame(n, rng);
  const W = cubeSamples(Q, N, rng);

  it('converges to +-q_i from a random start, every time', () => {
    for (let trial = 0; trial < 12; trial++) {
      const r = descend(W, N, n, rng);
      expect(r.converged).toBe(true);
      // |cos| > 0.9975 is the "hit" criterion the delta sweep was scored with.
      expect(bestAlignment(r.u, Q)).toBeGreaterThan(0.99);
      // ...which is the same statement as sum a^4 ~ 1, and mom4 ~ 0.0125.
      expect(sumA4FromMom4(r.mom4)).toBeGreaterThan(0.95);
      expect(r.iters).toBeLessThan(120);
    }
  });

  it('is faster at delta = 9 than at the paper delta = 0.7, at equal accuracy', () => {
    // The measured claim: delta controls speed, not accuracy. Capped at the same
    // small iteration budget, delta = 9 has arrived and delta = 0.7 has not.
    const fast = descend(W, N, n, makeRng(11), { delta: 9, maxIter: 60 });
    const slow = descend(W, N, n, makeRng(11), { delta: 0.7, maxIter: 60 });
    expect(fast.converged).toBe(true);
    expect(slow.converged).toBe(false);
    expect(bestAlignment(fast.u, Q)).toBeGreaterThan(bestAlignment(slow.u, Q));
    expect(bestAlignment(fast.u, Q)).toBeGreaterThan(0.99);
  });

  it('does not converge at all at delta = 0.3', () => {
    // 8.3% hit rate in the measured sweep -- the gain c = 0.0103 is too small to
    // separate the largest a_i from the rest inside the iteration cap.
    const r = descend(W, N, n, makeRng(12), { delta: 0.3, maxIter: 250 });
    expect(r.converged).toBe(false);
  });

  it('finds every frame row, up to sign, within the restart budget', () => {
    const seen: number[] = [];
    const rec = recoverDirections(W, N, n, makeRng(4242), {
      onRestart: (p) => seen.push(p.found),
    });
    expect(rec.exhausted).toBe(false);
    expect(rec.dirs).toHaveLength(n);
    expect(rec.restarts).toBeLessThanOrEqual(restartBudget(n));
    // Progress is emitted once per restart and never goes backwards.
    expect(seen).toHaveLength(rec.restarts);
    for (let i = 1; i < seen.length; i++) expect(seen[i]).toBeGreaterThanOrEqual(seen[i - 1]);
    expect(seen[seen.length - 1]).toBe(n);
    // Every frame row is accounted for exactly once, up to sign.
    const claimed = new Set<number>();
    for (const u of rec.dirs) {
      let best = -1;
      let bestCos = 0;
      for (let i = 0; i < n; i++) {
        const c = Math.abs(dot(u, Q[i]));
        if (c > bestCos) {
          bestCos = c;
          best = i;
        }
      }
      expect(bestCos).toBeGreaterThan(0.99);
      claimed.add(best);
    }
    expect(claimed.size).toBe(n);
  });

  it('reports exhaustion instead of pretending, when the budget is too small', () => {
    const rec = recoverDirections(W, N, n, makeRng(9), { maxRestarts: 2 });
    expect(rec.restarts).toBe(2);
    expect(rec.exhausted).toBe(true);
    expect(rec.dirs.length).toBeLessThan(n);
  });
});

describe('sphere helpers', () => {
  it('dedupes up to sign, because -q_i is as good a minimiser as q_i', () => {
    const list: Float64Array[] = [];
    const u = normalize(Float64Array.from([3, 4, 0]));
    expect(addUnique(list, u)).toBe(true);
    expect(addUnique(list, Float64Array.from(u, (x) => -x))).toBe(false);
    expect(addUnique(list, normalize(Float64Array.from([0, 0, 1])))).toBe(true);
    expect(list).toHaveLength(2);
  });

  it('draws unit vectors that are actually unit and actually spread out', () => {
    const rng = makeRng(31337);
    let sumCos = 0;
    for (let t = 0; t < 200; t++) {
      const u = randomUnitVector(5, rng);
      expect(Math.sqrt(dot(u, u))).toBeCloseTo(1, 12);
      sumCos += u[0];
    }
    expect(Math.abs(sumCos / 200)).toBeLessThan(0.1);
  });
});
