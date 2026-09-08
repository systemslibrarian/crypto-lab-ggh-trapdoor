import { describe, expect, it } from 'vitest';
import { gghKeygen, paperK } from '../lattice/keygen';
import { gramSchmidtRows, inverse, makeRng, maxAbsVec, vecMat } from '../lattice/matrix';
import { randomH, roundOffBoundInf, signRoundOff, signatureLeak } from './sign';
import { publicKey, verify } from './verify';
import {
  KLEIN_EPS,
  kleinBoundInf,
  kleinFactor,
  kleinSigma,
  makeKleinSigner,
  maxGramSchmidtNorm,
  newSampleZStats,
  sampleZ,
  signKlein,
} from './klein';

describe('the smoothing parameter', () => {
  it('computes eta_eps(Z^n) rather than quoting a constant', () => {
    // sqrt(ln(2n(1+2/eps))/pi) at eps = 2^-40. The lab's report quotes 3.186 at
    // n=16; the point of computing it is that it is NOT the same at other n.
    expect(kleinFactor(8, KLEIN_EPS)).toBeCloseTo(3.1510, 3);
    expect(kleinFactor(16, KLEIN_EPS)).toBeCloseTo(3.1858, 3);
    expect(kleinFactor(60, KLEIN_EPS)).toBeCloseTo(3.2511, 3);
    // It grows like sqrt(log n) -- slowly, but monotonically.
    expect(kleinFactor(60)).toBeGreaterThan(kleinFactor(8));
    // A looser statistical-distance target gives a smaller width.
    expect(kleinFactor(16, 1e-6)).toBeLessThan(kleinFactor(16, KLEIN_EPS));
  });

  it('scales the width by the largest Gram-Schmidt norm of R', () => {
    const rng = makeRng(5150);
    const k = gghKeygen(16, { rng, k: paperK(16) });
    const maxGS = maxGramSchmidtNorm(k.R);
    const { normSq } = gramSchmidtRows(k.R);
    expect(maxGS).toBeCloseTo(Math.sqrt(Math.max(...normSq)), 12);
    expect(kleinSigma(k.R)).toBeCloseTo(kleinFactor(16) * maxGS, 12);
  });
});

describe('the discrete Gaussian sampler', () => {
  it('reproduces the centre and the width it was asked for', () => {
    const rng = makeRng(20260908);
    const centre = 0.3;
    const sigma = 5;
    const stats = newSampleZStats();
    const draws = 20000;
    let sum = 0;
    let sumSq = 0;
    for (let t = 0; t < draws; t++) {
      const z = sampleZ(centre, sigma, rng, stats);
      sum += z;
      sumSq += (z - centre) * (z - centre);
    }
    const mean = sum / draws;
    const sd = Math.sqrt(sumSq / draws);
    expect(mean).toBeCloseTo(centre, 1);
    // In the exp(-pi x^2/sigma^2) convention the standard deviation is
    // sigma/sqrt(2 pi) -- which is exactly what kleinBoundInf is built from.
    expect(sd).toBeCloseTo(sigma / Math.sqrt(2 * Math.PI), 1);
    // Acceptance is the Gaussian's mass over the enclosing box on [c-6s, c+6s],
    // measured at 8-10% in the prototype. The 500-try cap therefore never fires.
    const acceptance = stats.accepts / stats.draws;
    expect(acceptance).toBeGreaterThan(0.05);
    expect(acceptance).toBeLessThan(0.2);
    expect(stats.fallbacks).toBe(0);
  });
});

describe('Klein/GPV signing', () => {
  const n = 12;
  const rng = makeRng(99991);
  const k = gghKeygen(n, { rng, k: paperK(n) });
  const Rinv = inverse(k.R);
  const Binv = inverse(k.B);
  const gso = gramSchmidtRows(k.R);
  const sigma = kleinSigma(k.R);

  it('produces genuine lattice points', () => {
    let worstFrac = 0;
    for (let t = 0; t < 200; t++) {
      const h = randomH(n, rng);
      const s = signKlein(h, k.R, gso, sigma, rng);
      const z = vecMat(s, Binv);
      for (const zi of z) worstFrac = Math.max(worstFrac, Math.abs(zi - Math.round(zi)));
    }
    expect(worstFrac).toBeLessThan(1e-6);
  });

  it('verifies 100% against its OWN published bound, which is what makes C5-prime fair', () => {
    // Both signers are valid schemes over the same lattice. Each publishes the
    // bound its own output distribution obeys; the attack is then compared
    // between two working schemes, not against a straw man.
    const kleinPub = publicKey(k.B, kleinBoundInf(sigma));
    const roundOffPub = publicKey(k.B, roundOffBoundInf(k.R));
    const sign = makeKleinSigner(k.R, rng, sigma);
    let kleinAccepted = 0;
    let roundOffAccepted = 0;
    let worstLeak = 0;
    for (let t = 0; t < 200; t++) {
      const h = randomH(n, rng);
      const s = sign(h);
      worstLeak = Math.max(worstLeak, maxAbsVec(signatureLeak(h, s)));
      if (verify(kleinPub, h, s).ok) kleinAccepted++;
      const rs = signRoundOff(h, k.R, Rinv);
      if (verify(roundOffPub, h, rs).ok) roundOffAccepted++;
    }
    expect(kleinAccepted).toBe(200);
    expect(roundOffAccepted).toBe(200);
    // The honest caveat, made checkable: Klein signatures are several times
    // longer, so a verifier calibrated for round-off rejects them outright.
    expect(worstLeak).toBeGreaterThan(roundOffBoundInf(k.R));
    expect(kleinBoundInf(sigma)).toBeGreaterThan(3 * roundOffBoundInf(k.R));
  });

  it('is rejected by a round-off verifier for being too far, not for being off-lattice', () => {
    const roundOffPub = publicKey(k.B, roundOffBoundInf(k.R));
    const sign = makeKleinSigner(k.R, rng, sigma);
    const h = randomH(n, rng);
    const res = verify(roundOffPub, h, sign(h));
    expect(res.ok).toBe(false);
    expect(res.reason).toBe('too-far');
  });
});
