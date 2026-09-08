import { describe, expect, it } from 'vitest';
import type { Mat, Vec } from '../lattice/types';
import { inverse, makeRng, randInt, vecMat } from '../lattice/matrix';
import { gghKeygen } from '../lattice/keygen';
import type { Rng } from '../lattice/types';
import {
  buildEmbedding,
  expectedShortNorm,
  maxAbsGram,
  reduceTargetModLattice,
  solveByEmbedding,
  type EmbeddingForm,
} from './embedding';

const mat = (rows: number[][]): Mat => rows.map((r) => Float64Array.from(r));

/** A residual CVP exactly like the one Break 1's division step hands over. */
function residualInstance(n: number, seed: number, mpRange = 60) {
  const rng: Rng = makeRng(seed);
  const key = gghKeygen(n, { rng });
  const mp = new Float64Array(n);
  for (let i = 0; i < n; i++) mp[i] = randInt(rng, -mpRange, mpRange);
  const ep = new Float64Array(n);
  for (let i = 0; i < n; i++) ep[i] = rng() < 0.5 ? 0 : -1;
  const mpB = vecMat(mp, key.B);
  const target = new Float64Array(n);
  for (let i = 0; i < n; i++) target[i] = mpB[i] + ep[i];
  return { B: key.B, mp, ep, target };
}

describe('the embedding basis', () => {
  it('is [2B | 0] over [2t+1 | t] in the centered form', () => {
    const B = mat([[3, 1], [1, 4]]);
    const target = Float64Array.from([10, -7]);
    const M = buildEmbedding(target, B, 'centered', 1);
    expect(Array.from(M[0])).toEqual([6, 2, 0]);
    expect(Array.from(M[1])).toEqual([2, 8, 0]);
    expect(Array.from(M[2])).toEqual([21, -13, 1]);
  });

  it('is [B | 0] over [t | t] in the uncentered form', () => {
    const B = mat([[3, 1], [1, 4]]);
    const target = Float64Array.from([10, -7]);
    const M = buildEmbedding(target, B, 'uncentered', 1);
    expect(Array.from(M[0])).toEqual([3, 1, 0]);
    expect(Array.from(M[1])).toEqual([1, 4, 0]);
    expect(Array.from(M[2])).toEqual([10, -7, 1]);
  });

  it('plants exactly the vector Nguyen says it does', () => {
    const { B, mp, ep, target } = residualInstance(8, 202);
    const n = B.length;
    const x = new Float64Array(n + 1);
    for (let i = 0; i < n; i++) x[i] = mp[i];
    x[n] = -1;

    // Centered: (mp,-1) * basis = (-f, -1) with f = 2*ep + 1 in {+1,-1}^n.
    const vc = vecMat(x, buildEmbedding(target, B, 'centered', 1));
    for (let j = 0; j < n; j++) expect(vc[j]).toBe(-(2 * ep[j] + 1));
    expect(vc[n]).toBe(-1);
    let sq = 0;
    for (const v of vc) sq += v * v;
    // Exactly sqrt(n + t^2), whatever the ciphertext was. That is the observable.
    expect(Math.sqrt(sq)).toBeCloseTo(expectedShortNorm(n, 'centered', 1), 12);

    // Uncentered: (mp,-1) * basis = (-ep, -1) with ep in {0,-1}^n.
    const vu = vecMat(x, buildEmbedding(target, B, 'uncentered', 1));
    // `===` rather than toBe: -ep[j] is -0 where ep[j] is 0, and Object.is
    // distinguishes -0 from 0 while the arithmetic does not.
    for (let j = 0; j < n; j++) expect(vu[j] === -ep[j]).toBe(true);
    expect(vu[n]).toBe(-1);
  });

  it('expectedShortNorm is sqrt(n+t^2) centered and sqrt(n/2+t^2) uncentered', () => {
    expect(expectedShortNorm(8, 'centered', 1)).toBeCloseTo(3, 12);
    expect(expectedShortNorm(60, 'centered', 1)).toBeCloseTo(Math.sqrt(61), 12);
    expect(expectedShortNorm(8, 'uncentered', 1)).toBeCloseTo(Math.sqrt(5), 12);
  });

  it('maxAbsGram reads the largest inner product', () => {
    expect(maxAbsGram(mat([[1, 0], [0, 1]]))).toBe(1);
    expect(maxAbsGram(mat([[3, 4], [0, 0]]))).toBe(25);
  });
});

describe('target reduction is exact attacker-side preprocessing', () => {
  it('subtracts a genuine lattice vector and shrinks the target', () => {
    const { B, target } = residualInstance(16, 303);
    const red = reduceTargetModLattice(target, B, inverse(B));
    expect(red.applied).toBe(true);
    expect(red.maxAbsAfter).toBeLessThan(red.maxAbsBefore);
    // Exact: reduced + shift*B === original, entry for entry, over the integers.
    const back = vecMat(red.shift, B);
    for (let i = 0; i < target.length; i++) {
      expect(Number.isSafeInteger(red.target[i])).toBe(true);
      expect(red.target[i] + back[i]).toBe(target[i]);
    }
  });

  it('declines when it would not help', () => {
    // A target already inside the fundamental region: round(t*Binv) is 0.
    const { B, ep } = residualInstance(8, 404);
    const red = reduceTargetModLattice(ep, B, inverse(B));
    expect(red.applied).toBe(false);
    expect(Array.from(red.shift)).toEqual(new Array(B.length).fill(0));
    expect(red.target).toBe(ep);
  });

  it('does not change the answer, only the magnitudes', () => {
    const { B, mp, target } = residualInstance(16, 505);
    const withRed = solveByEmbedding(target, B, { reduceTarget: true });
    const withoutRed = solveByEmbedding(target, B, { reduceTarget: false });
    expect(withRed.reduction.applied).toBe(true);
    expect(withoutRed.reduction.applied).toBe(false);
    for (const r of [withRed, withoutRed]) {
      expect(r.readOff.candidates.length).toBeGreaterThan(0);
      expect(Array.from(r.readOff.candidates[0].mp)).toEqual(Array.from(mp));
    }
    // Measured 111x-1291x across n = 8..60; assert only the direction, not the size.
    expect(withRed.gramMaxAbs).toBeLessThan(withoutRed.gramMaxAbs);
  });
});

describe('solveByEmbedding recovers the residual CVP', () => {
  for (const form of ['centered', 'uncentered'] as EmbeddingForm[]) {
    it(`recovers mp and ep exactly, ${form}, at n = 8, 16, 32`, () => {
      for (const n of [8, 16, 32]) {
        const { B, mp, ep, target } = residualInstance(n, 6060 + n);
        const out = solveByEmbedding(target, B, { form });
        expect(out.lll.failure).toBeNull();
        expect(out.readOff.patternFound).toBe(true);
        const best = out.readOff.best;
        expect(best).not.toBeNull();
        if (best === null) continue;
        expect(best.exact).toBe(true);
        expect(Array.from(best.mp)).toEqual(Array.from(mp));
        expect(Array.from(best.ep)).toEqual(Array.from(ep));
      }
    });
  }

  it('returns a shortest row of exactly sqrt(n+1) in the centered form', () => {
    for (const n of [8, 16, 32]) {
      const { B, target } = residualInstance(n, 7070 + n);
      const out = solveByEmbedding(target, B, { form: 'centered' });
      expect(out.readOff.minRowNorm).toBeCloseTo(Math.sqrt(n + 1), 9);
      expect(out.readOff.normRatio).toBeCloseTo(1, 9);
    }
  });

  it('reports the LLL failure rather than a bogus candidate', () => {
    const { B, target } = residualInstance(16, 8080);
    const out = solveByEmbedding(target, B, { maxIters: 2 });
    expect(out.lll.failure).not.toBeNull();
    expect(out.lll.failure?.kind).toBe('iteration-cap');
  });

  it('an ep outside {0,-1}^n is rejected, not rounded into shape', () => {
    // Build a target whose residual is 2 on one coordinate: no planted +-1 vector.
    const { B, mp } = residualInstance(16, 9090);
    const n = B.length;
    const bad = new Float64Array(n);
    const mpB: Vec = vecMat(mp, B);
    for (let i = 0; i < n; i++) bad[i] = mpB[i] + (i === 3 ? 2 : 0);
    const out = solveByEmbedding(bad, B, { form: 'centered' });
    expect(out.readOff.patternFound).toBe(false);
    expect(out.readOff.candidates).toHaveLength(0);
    // A best-effort answer is still offered, so the caller can show it failing.
    expect(out.readOff.best).not.toBeNull();
    expect(out.readOff.best?.exact).toBe(false);
  });
});
