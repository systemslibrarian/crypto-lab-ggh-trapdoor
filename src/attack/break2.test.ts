import { describe, expect, it } from 'vitest';
import { gghKeygen, paperK } from '../lattice/keygen';
import { inverse, makeRng } from '../lattice/matrix';
import type { GghKey, Mat } from '../lattice/types';
import { makeRoundOffSigner, roundOffBoundInf } from '../sign/sign';
import { kleinBoundInf, kleinSigma, makeKleinSigner } from '../sign/klein';
import { publicKey } from '../sign/verify';
import {
  MIN_DEMO_DIM,
  dimensionCaveat,
  liftDirection,
  matchUpToSignPerm,
  runBreak2,
} from './break2';

/**
 * Dimension for the end-to-end cases.
 *
 * n = 8 is the smallest dimension where the attack is legible (see
 * MIN_DEMO_DIM) and the only one fast enough for a unit suite.
 *
 * MEASURED for this port, whole ladder from 1000, first rung that forges 20/20:
 *
 *     n    keys  N            wall clock
 *     8    8     8000-16000   0.08-0.24 s
 *     12   3     16000-32000  0.45-1.18 s
 *     16   3     32000-64000  2.53-6.09 s
 *
 * The positive case below runs in about 0.2 s and the Klein case in about 1.2 s
 * (Klein signing is 4-5x the cost of round-off signing, and the negative case
 * burns its full restart budget by construction). An n=16 end-to-end case would
 * add 2.5-6 s to every unit run for no extra coverage, so it is left to the
 * Playwright claims spec (C5) -- and its cost is why the browser runs the descent
 * in a worker.
 */
const n = 8;

/**
 * GGH's own diagonal shift, k = round(sqrt(n)*l), not this lab's larger
 * `gghK`.
 *
 * The lab raises k so that Babai round-off DECRYPTION is guaranteed (invariant
 * I2), and that choice has a measured cost here: the lift threshold round(u*L)
 * has to beat is the absolute number 0.5 while ||L|| grows like k, so the
 * signature requirement scales as k^2. Measured on four keys per dimension, the
 * lab's k = 39 at n=8 needs 64000-128000 signatures where the paper's k = 11
 * needs 4000-16000. Break 2 attacks a signature scheme and needs no decryption
 * guarantee, so it is honest -- and much faster -- to run it at the paper's
 * parameters. `gghKeygen` takes `k` for exactly this reason.
 */
function signingKey(seed: number): GghKey {
  return gghKeygen(n, { rng: makeRng(seed), k: paperK(n) });
}

describe('invariant I4: the matcher, up to sign and permutation only', () => {
  const R: Mat = [
    Float64Array.from([11, -2, 3]),
    Float64Array.from([1, 9, -4]),
    Float64Array.from([-3, 0, 12]),
  ];

  it('accepts rows permuted and negated, exactly', () => {
    const cands: Mat = [
      Float64Array.from([-1, -9, 4]),
      Float64Array.from([-3, 0, 12]),
      Float64Array.from([11, -2, 3]),
    ];
    const m = matchUpToSignPerm(cands, R);
    expect(m.complete).toBe(true);
    expect(m.matched).toBe(3);
    expect(m.perm).toEqual([1, 2, 0]);
    expect(m.signs).toEqual([-1, 1, 1]);
    expect(m.absDetRatio).toBeCloseTo(1, 9);
  });

  it('rejects a row that is off by one in a single entry -- no tolerance at all', () => {
    const cands: Mat = [
      Float64Array.from([11, -2, 4]),
      Float64Array.from([1, 9, -4]),
      Float64Array.from([-3, 0, 12]),
    ];
    const m = matchUpToSignPerm(cands, R);
    expect(m.complete).toBe(false);
    expect(m.matched).toBe(2);
    expect(m.perm[0]).toBe(-1);
  });

  it('refuses to match one row twice', () => {
    const cands: Mat = [
      Float64Array.from([11, -2, 3]),
      Float64Array.from([-11, 2, -3]),
      Float64Array.from([-3, 0, 12]),
    ];
    const m = matchUpToSignPerm(cands, R);
    expect(m.matched).toBe(2);
    expect(m.complete).toBe(false);
  });
});

describe('the lift', () => {
  it('rounds u*L and reports how far it had to round', () => {
    const L: Mat = [Float64Array.from([10, 0.2]), Float64Array.from([0, 10])];
    const lifted = liftDirection(Float64Array.from([1, 0]), L);
    expect(Array.from(lifted.row)).toEqual([10, 0]);
    expect(lifted.integralityGap).toBeCloseTo(0.2, 12);
  });
});

describe('the dimension floor', () => {
  it('names the reason n < 8 is unusable as a demo instead of hiding it', () => {
    expect(MIN_DEMO_DIM).toBe(8);
    expect(dimensionCaveat(8)).toBeNull();
    expect(dimensionCaveat(4)).toMatch(/too thin/);
  });
});

describe('C5: Break 2 end to end against the REAL verifier', () => {
  it('recovers the basis up to sign and permutation and forges with it', () => {
    const key = signingKey(20260908);
    const pub = publicKey(key.B, roundOffBoundInf(key.R));
    const rng = makeRng(4242);
    const ticks: number[] = [];

    const res = runBreak2({
      pub,
      sign: makeRoundOffSigner(key.R, inverse(key.R)),
      rng,
      startN: 4000,
      capN: 32000,
      forgeries: 20,
      onProgress: (p) => {
        if (p.phase === 'descending') ticks.push(p.signatures);
      },
    });

    // I5: the pass/fail decision belongs to the verifier, which knows only B.
    expect(res.ok).toBe(true);
    expect(res.Rhat).not.toBeNull();
    expect(res.attempts[res.attempts.length - 1].forgeriesAccepted).toBe(20);

    // The counter is live and honest: it reports the rung that actually worked.
    expect(res.signaturesConsumed).toBeGreaterThanOrEqual(4000);
    expect(res.signaturesConsumed).toBeLessThanOrEqual(32000);
    expect(res.totalSignaturesObserved).toBe(2 * res.signaturesConsumed);
    expect(ticks.length).toBeGreaterThan(0);
    expect(Math.max(...ticks)).toBe(res.signaturesConsumed);

    // I4, for display only: the recovery is up to sign and permutation, exactly.
    const match = matchUpToSignPerm(res.Rhat as Mat, key.R);
    expect(match.complete).toBe(true);
    expect(match.matched).toBe(n);
    expect(match.absDetRatio).toBeCloseTo(1, 6);
    // Some row really did come back negated or out of order -- otherwise this
    // test would not be exercising "up to sign and permutation" at all.
    expect(match.perm.some((p, i) => p !== i) || match.signs.some((s) => s === -1)).toBe(true);

    // The public discriminators, with no secret in sight.
    expect(res.discriminators.sumA4HeldOut).toBeGreaterThan(0.9);
    expect(res.discriminators.integralityGap).toBeLessThan(0.4);
    // Every row rounded unambiguously, which is why the lift was right.
    expect(res.discriminators.worstIntegralityGap).toBeLessThan(0.5);
    expect(res.discriminators.covarianceShape).toBeGreaterThan(0.1);
  });

  it('reports failure honestly when the cap is too small to succeed', () => {
    const key = signingKey(555);
    const pub = publicKey(key.B, roundOffBoundInf(key.R));
    const res = runBreak2({
      pub,
      sign: makeRoundOffSigner(key.R, inverse(key.R)),
      rng: makeRng(7),
      startN: 250,
      capN: 250,
      forgeries: 20,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/cap of 250/);
    expect(res.attempts).toHaveLength(1);
    expect(res.signaturesConsumed).toBe(250);
    // Failure is reported, not disguised as a partial success.
    expect(res.attempts[0].forgeriesAccepted).toBeLessThan(20);
  });
});

describe("C5': Klein/GPV signing defeats the same attack", () => {
  it('leaves nothing to learn, and says so with public statistics only', () => {
    const key = signingKey(9090);
    const sigma = kleinSigma(key.R);
    // Each signer is verified against ITS OWN published bound, so this is a
    // comparison between two working schemes over one lattice.
    const pub = publicKey(key.B, kleinBoundInf(sigma));
    const rng = makeRng(31337);

    const res = runBreak2({
      pub,
      sign: makeKleinSigner(key.R, rng, sigma),
      rng,
      startN: 4000,
      capN: 8000,
      forgeries: 20,
    });

    expect(res.ok).toBe(false);
    // Not one row comes back, even scored against the secret with the generous
    // display-only matcher.
    if (res.Rhat !== null) expect(matchUpToSignPerm(res.Rhat, key.R).matched).toBe(0);

    const d = res.discriminators;
    // The headline discriminator: 1.0 for round-off, ~0 for Klein. Values
    // straddling zero are the signature of no structure at all, so this is a
    // two-sided bound and must NOT be clamped.
    expect(Math.abs(d.sumA4HeldOut)).toBeLessThan(0.25);
    // The in-sample number overfits and reads structure that is not there --
    // which is precisely why the hold-out split is built in rather than optional.
    expect(d.sumA4InSample).toBeGreaterThan(d.sumA4HeldOut);
    // Second, independent discriminator: rounding uniform noise leaves a gap
    // near 1/2, so the lifted candidates are not lattice vectors.
    expect(d.integralityGap).toBeGreaterThan(0.35);
    // Free pre-check before the descent even runs: Klein's covariance is scalar.
    expect(d.covarianceShape).toBeLessThan(0.1);
  });
});
