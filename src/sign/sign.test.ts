import { describe, expect, it } from 'vitest';
import { gghKeygen, paperK } from '../lattice/keygen';
import { inverse, makeRng, maxAbsVec, randInt, vecMat } from '../lattice/matrix';
import type { Mat } from '../lattice/types';
import {
  DEFAULT_H_RANGE,
  collectLeaks,
  leakFourierBound,
  leakUniformityBound,
  makeRoundOffSigner,
  parallelepipedCoords,
  randomH,
  roundOffBoundInf,
  signRoundOff,
  signatureLeak,
} from './sign';

const N_SIGS = 400;

function key(n: number, seed: number) {
  const rng = makeRng(seed);
  const k = gghKeygen(n, { rng, k: paperK(n) });
  return { key: k, rng, Rinv: inverse(k.R), Binv: inverse(k.B) };
}

describe('round-off signing', () => {
  it('produces genuine lattice points of the PUBLIC basis', () => {
    const { key: k, rng, Rinv, Binv } = key(12, 20260908);
    let worstFrac = 0;
    for (let t = 0; t < N_SIGS; t++) {
      const h = randomH(12, rng);
      const s = signRoundOff(h, k.R, Rinv);
      const z = vecMat(s, Binv);
      for (const zi of z) worstFrac = Math.max(worstFrac, Math.abs(zi - Math.round(zi)));
    }
    // The verifier's 1e-6 tolerance is calibrated against exactly this number;
    // the prototype measured 4.89e-12 at n=12 and this is the same computation.
    expect(worstFrac).toBeLessThan(1e-9);
  });

  it('leaks a sample that is equidistributed over P(R) only approximately, by a measured amount', () => {
    // The claim being pinned: a finite hash box makes x APPROXIMATELY uniform,
    // not exactly. The approximation is a number, so it is asserted as one.
    const { key: k } = key(12, 20260908);
    const Rinv = inverse(k.R);
    const e0 = new Float64Array(12);
    e0[0] = 1;
    // Global bound, every nonzero frequency at once, at the shipped range.
    expect(leakUniformityBound(k.R, DEFAULT_H_RANGE)).toBeLessThan(0.01);
    expect(leakUniformityBound(k.R, DEFAULT_H_RANGE)).toBeGreaterThan(0);
    // The frequencies a per-coordinate statistic can see are far smaller.
    expect(leakFourierBound(Rinv, e0, DEFAULT_H_RANGE)).toBeLessThan(1e-20);
    // It is the box size that buys this: both bounds scale as 1/range, and at a
    // range comparable with the basis they say nothing at all.
    expect(leakFourierBound(Rinv, e0, 10)).toBeGreaterThan(0.1);
    expect(leakUniformityBound(k.R, 1)).toBeGreaterThan(1);
    expect(leakUniformityBound(k.R, DEFAULT_H_RANGE) * 1e4).toBeCloseTo(
      leakUniformityBound(k.R, 1),
      6,
    );
  });

  it('stops filling the parallelepiped when the hash box shrinks to the basis', () => {
    // The caveat with teeth: at range = 1 the hashed point never leaves one cell,
    // so x is just -y and E|x_i| collapses. Measured 0.0396 at n=12 against 0.25.
    const { key: k } = key(12, 20260908);
    const Rinv = inverse(k.R);
    const meanAbsX = (range: number): number => {
      const rng = makeRng(555);
      let sum = 0;
      let count = 0;
      for (let t = 0; t < 2000; t++) {
        const h = randomH(12, rng, range);
        const x = parallelepipedCoords(h, signRoundOff(h, k.R, Rinv), Rinv);
        for (const xi of x) { sum += Math.abs(xi); count++; }
      }
      return sum / count;
    };
    // se of E|x| over 24000 uniform draws is 1/4 * sqrt(1/3) / sqrt(24000) = 9.3e-4.
    expect(meanAbsX(DEFAULT_H_RANGE)).toBeCloseTo(0.25, 2);
    expect(meanAbsX(1)).toBeLessThan(0.15);
  });

  it('leaks a sample from the fundamental parallelepiped of R', () => {
    const { key: k, rng, Rinv } = key(12, 424242);
    let maxCoord = 0;
    let meanAbs = 0;
    let meanSigned = 0;
    let count = 0;
    for (let t = 0; t < N_SIGS; t++) {
      const h = randomH(12, rng);
      const s = signRoundOff(h, k.R, Rinv);
      const x = parallelepipedCoords(h, s, Rinv);
      for (const xi of x) {
        maxCoord = Math.max(maxCoord, Math.abs(xi));
        meanAbs += Math.abs(xi);
        meanSigned += xi;
        count++;
      }
    }
    meanAbs /= count;
    meanSigned /= count;
    // x = round(y) - y can never leave [-1/2, 1/2]: that is the geometry, not a
    // statistical claim, so it holds for every single coordinate.
    expect(maxCoord).toBeLessThanOrEqual(0.5 + 1e-9);
    // ...and it fills the box: uniform on [-1/2,1/2) has E|x| = 1/4 and E[x] = 0.
    expect(maxCoord).toBeGreaterThan(0.49);
    expect(meanAbs).toBeCloseTo(0.25, 2);
    expect(Math.abs(meanSigned)).toBeLessThan(0.01);
  });

  it('never exceeds the bound published with the public key', () => {
    const { key: k, rng, Rinv } = key(12, 777);
    const bound = roundOffBoundInf(k.R);
    let worst = 0;
    for (let t = 0; t < N_SIGS; t++) {
      const h = randomH(12, rng);
      worst = Math.max(worst, maxAbsVec(signatureLeak(h, signRoundOff(h, k.R, Rinv))));
    }
    expect(worst).toBeLessThanOrEqual(bound);
    // The bound is tight in principle but not attained by any single draw, since
    // it needs all n coordinates of x at their extreme simultaneously.
    expect(worst).toBeGreaterThan(0.3 * bound);
  });

  it('publishes a bound that sign flips and row permutations cannot change', () => {
    // This is the load-bearing fact behind invariant I5: Break 2 can only ever
    // recover Rhat = P*D*R, and if that changed the published bound then the
    // forgery would be graded against a different number than a real signature.
    const { key: k, rng } = key(12, 31337);
    const n = 12;
    const perm = [...Array(n).keys()];
    for (let i = n - 1; i > 0; i--) {
      const j = randInt(rng, 0, i);
      [perm[i], perm[j]] = [perm[j], perm[i]];
    }
    const scrambled: Mat = perm.map((p) => {
      const flip = rng() < 0.5 ? -1 : 1;
      return Float64Array.from(k.R[p], (x) => flip * x);
    });
    expect(roundOffBoundInf(scrambled)).toBe(roundOffBoundInf(k.R));
  });

  it('collects leaks through the SignFn seam', () => {
    const { key: k, rng, Rinv } = key(8, 99);
    const leaks = collectLeaks(50, 8, rng, makeRoundOffSigner(k.R, Rinv));
    expect(leaks).toHaveLength(50);
    for (const v of leaks) expect(v).toHaveLength(8);
    const bound = roundOffBoundInf(k.R);
    for (const v of leaks) expect(maxAbsVec(v)).toBeLessThanOrEqual(bound);
  });
});
