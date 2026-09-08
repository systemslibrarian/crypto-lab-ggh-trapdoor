import { describe, expect, it } from 'vitest';
import { gramSchmidtRows, makeRng, zeros } from '../lattice/matrix';
import type { Mat, Rng, Vec } from '../lattice/types';
import { gaussian, randomUnitVector } from './descent';
import {
  MOM4_SPHERICAL,
  frameCoefficients,
  mom4,
  mom4Analytic,
  mom4FromSumA4,
  mom4Grad,
  mom4Landmarks,
  sumA4FromMom4,
} from './moments';

/**
 * An exact orthonormal frame. Gives a whitening oracle with no estimation error,
 * so the only thing left between the formula and the sample estimate is
 * Monte-Carlo noise -- which is what these tests are measuring.
 */
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

describe('the fourth-moment formula mom4(u) = 1/48 - (1/120) sum a^4', () => {
  const n = 8;
  const N = 64000;
  const rng = makeRng(20260908);
  const Q = randomFrame(n, rng);
  const W = cubeSamples(Q, N, rng);

  it('matches Monte-Carlo along a frame row, where sum a^4 = 1', () => {
    const u = Float64Array.from(Q[0]);
    const a = frameCoefficients(u, Q);
    expect(mom4Analytic(a)).toBeCloseTo(0.0125, 9);
    const measured = mom4(W, N, n, u);
    expect(Math.abs(measured - 0.0125) / 0.0125).toBeLessThan(0.02);
  });

  it('matches Monte-Carlo along random directions too', () => {
    for (let trial = 0; trial < 6; trial++) {
      const u = randomUnitVector(n, rng);
      const analytic = mom4Analytic(frameCoefficients(u, Q));
      const measured = mom4(W, N, n, u);
      expect(Math.abs(measured - analytic) / analytic).toBeLessThan(0.03);
    }
  });

  it('is minimised at the frame rows and maximal for a spread-out direction', () => {
    const row = mom4(W, N, n, Float64Array.from(Q[0]));
    const flat = new Float64Array(n);
    for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) flat[j] += Q[i][j] / Math.sqrt(n);
    expect(row).toBeLessThan(mom4(W, N, n, flat));
    // The flat direction sits at sum a^4 = 1/n, the minimum of that sum.
    expect(sumA4FromMom4(mom4(W, N, n, flat))).toBeCloseTo(1 / n, 1);
  });

  it('recovers sum a^4 from a measured moment with no secret in sight', () => {
    const u = Float64Array.from(Q[2]);
    expect(sumA4FromMom4(mom4(W, N, n, u))).toBeCloseTo(1, 1);
    // Round trip.
    expect(sumA4FromMom4(mom4FromSumA4(0.37))).toBeCloseTo(0.37, 12);
    // A spherical sample set reads exactly zero structure.
    expect(sumA4FromMom4(MOM4_SPHERICAL)).toBe(0);
  });

  it('gives a gradient that agrees with a central difference of the same samples', () => {
    // 4*E[<w,u>^3 w] is the gradient of E[<w,u>^4]; checking it against a finite
    // difference on the SAME sample set removes Monte-Carlo noise entirely, so
    // this is an exact-arithmetic check of the formula rather than a statistical one.
    const u = randomUnitVector(n, rng);
    const g = mom4Grad(W, N, n, u);
    const eps = 1e-5;
    for (let j = 0; j < n; j++) {
      const up = Float64Array.from(u);
      const dn = Float64Array.from(u);
      up[j] += eps;
      dn[j] -= eps;
      const fd = (mom4(W, N, n, up) - mom4(W, N, n, dn)) / (2 * eps);
      expect(Math.abs(fd - g[j])).toBeLessThan(1e-8);
    }
  });

  it('agrees with the analytic gradient (1/12)u - (1/30) sum a^3 q_i', () => {
    const u = randomUnitVector(n, rng);
    const a = frameCoefficients(u, Q);
    const analytic = new Float64Array(n);
    for (let j = 0; j < n; j++) analytic[j] = u[j] / 12;
    for (let i = 0; i < n; i++) {
      const c = (a[i] * a[i] * a[i]) / 30;
      for (let j = 0; j < n; j++) analytic[j] -= c * Q[i][j];
    }
    const g = mom4Grad(W, N, n, u);
    // Relative, because this comparison DOES carry Monte-Carlo error -- the
    // analytic side knows the exact frame and the sampled side does not.
    let diff = 0;
    let scale = 0;
    for (let j = 0; j < n; j++) {
      diff += (g[j] - analytic[j]) ** 2;
      scale += analytic[j] ** 2;
    }
    expect(Math.sqrt(diff / scale)).toBeLessThan(0.05);
  });
});

describe('landmarks and the comparison with the paper', () => {
  it('places the four reference values where the report measured them', () => {
    const marks = mom4Landmarks(16);
    const byLabel = Object.fromEntries(marks.map((m) => [m.label, m]));
    expect(byLabel['spherical'].mom4).toBeCloseTo(0.02083333, 8);
    expect(byLabel['spherical'].mom4).toBe(MOM4_SPHERICAL);
    expect(byLabel['flat u'].mom4).toBeCloseTo(0.02031250, 8);
    expect(byLabel['random u'].mom4).toBeCloseTo(0.01944444, 8);
    expect(byLabel['u = +-q_i'].mom4).toBeCloseTo(0.01250000, 8);
    expect(byLabel['u = +-q_i'].sumA4).toBe(1);
  });

  it('is the Nguyen-Regev statement rescaled by 2^4, as the header claims', () => {
    // Their parallelepiped is [-1,1]^n and ours is [-1/2,1/2)^n, so every fourth
    // moment differs by exactly 16. If this test ever fails, one of the two
    // statements has drifted.
    expect(16 * MOM4_SPHERICAL).toBeCloseTo(1 / 3, 12);
    expect(16 / 120).toBeCloseTo(2 / 15, 12);
    expect(16 * mom4FromSumA4(1)).toBeCloseTo(1 / 5, 12);
  });
});

describe('frameCoefficients', () => {
  it('gives coordinates that square-sum to one for a unit direction', () => {
    const rng = makeRng(55555);
    const Q = randomFrame(10, rng);
    const u: Vec = randomUnitVector(10, rng);
    const a = frameCoefficients(u, Q);
    let s = 0;
    for (const ai of a) s += ai * ai;
    expect(s).toBeCloseTo(1, 10);
  });
});
