import { describe, expect, it } from 'vitest';
import { gghKeygen, paperK } from '../lattice/keygen';
import { inverse, makeRng } from '../lattice/matrix';
import type { GghKey, Mat } from '../lattice/types';
import { makeRoundOffSigner, randomH, roundOffBoundInf, signRoundOff } from '../sign/sign';
import { kleinBoundInf, kleinSigma, makeKleinSigner } from '../sign/klein';
import { publicKey, verify } from '../sign/verify';
import { lllReduce } from './lll';
import type { Break2Result } from './break2';
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
  /**
   * OUTCOME COMBINATION 1 OF 5: forgery accepted AND the candidate really is R.
   *
   * The other four -- forgery without recovery, a candidate that forges nothing,
   * the cap running out, and Gaussian signatures defeating the attack -- are in
   * the "forgery capability is not secret-row recovery" block below.
   */
  it('recovers the basis up to sign and permutation and forges with it', () => {
    const key = signingKey(20260908);
    const pub = publicKey(key.B, roundOffBoundInf(key.R));
    const rng = makeRng(4242);
    const ticks: number[] = [];
    const observedTicks: number[] = [];

    const res = runBreak2({
      pub,
      sign: makeRoundOffSigner(key.R, inverse(key.R)),
      rng,
      startN: 4000,
      capN: 32000,
      forgeries: 20,
      // LAB ONLY, and only for the ground-truth line below. The attack path never
      // reads it -- see "identical with and without the ground truth" below.
      groundTruthR: key.R,
      onProgress: (p) => {
        if (p.phase !== 'descending') return;
        ticks.push(p.signatures);
        observedTicks.push(p.totalObserved);
        // The live counter counts TRAINING signatures; the victim published twice
        // that. Both names are on the ticket so a UI cannot pick the wrong one by
        // accident.
        expect(p.trainingSignatures).toBe(p.signatures);
        expect(p.heldOutSignatures).toBe(p.trainingSignatures);
        expect(p.totalObserved).toBe(p.observed);
        expect(p.totalObserved).toBe(2 * p.trainingSignatures);
      },
    });

    // I5: the pass/fail decision belongs to the verifier, which knows only B.
    expect(res.ok).toBe(true);
    // `ok` has not changed meaning: it is the forgery verdict, under both names.
    expect(res.forgeryOk).toBe(res.ok);
    expect(res.Rhat).not.toBeNull();
    expect(res.attempts[res.attempts.length - 1].forgeriesAccepted).toBe(20);

    // The counter is live and honest: it reports the rung that actually worked.
    expect(res.signaturesConsumed).toBeGreaterThanOrEqual(4000);
    expect(res.signaturesConsumed).toBeLessThanOrEqual(32000);
    // Sample accounting, all three named: the old field is the TRAINING half.
    expect(res.trainingSignatures).toBe(res.signaturesConsumed);
    expect(res.heldOutSignatures).toBe(res.trainingSignatures);
    expect(res.totalObserved).toBe(2 * res.trainingSignatures);
    expect(res.totalSignaturesObserved).toBe(res.totalObserved);
    expect(res.reason).toMatch(/training \+ \d+ held out = \d+ oracle signatures observed/);
    expect(ticks.length).toBeGreaterThan(0);
    expect(Math.max(...ticks)).toBe(res.signaturesConsumed);
    expect(Math.max(...observedTicks)).toBe(res.totalObserved);

    // I4, LAB-ONLY ground truth, computed in production and reported: the
    // recovery is up to sign and permutation, exactly.
    expect(res.groundTruthRecovered).toBe(true);
    const match = res.groundTruthMatch;
    if (match === null) throw new Error('the ground truth was supplied, so it must be scored');
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
    expect(res.forgeryOk).toBe(false);
    expect(res.reason).toMatch(/cap of 250/);
    expect(res.attempts).toHaveLength(1);
    expect(res.signaturesConsumed).toBe(250);
    // The rung cost the victim 500 signatures, not 250, and the failure sentence
    // says so rather than quoting the training half as if it were the total.
    expect(res.totalObserved).toBe(500);
    expect(res.reason).toMatch(/250 training \+ 250 held out = 500 oracle signatures observed/);
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
      groundTruthR: key.R,
    });

    // OUTCOME COMBINATION 5 OF 5: both checks fail, and they fail independently.
    expect(res.ok).toBe(false);
    expect(res.forgeryOk).toBe(false);
    expect(res.groundTruthRecovered).toBe(false);
    // Not one row comes back, even scored against the secret with the generous
    // lab-only matcher.
    if (res.groundTruthMatch !== null) expect(res.groundTruthMatch.matched).toBe(0);

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
    // Explicit timeout, not the 5 s default. This test really does the work:
    // 16,000 Klein signatures (rejection sampling at ~8% acceptance) plus a full
    // fourth-moment descent that is REQUIRED to exhaust its restart budget,
    // because failing to converge is the result being asserted. Measured 1.9-2.1 s
    // locally; it exceeded the default on the CI runner, which is roughly 3x
    // slower. Nothing about the assertions changed -- only the time budget, which
    // was never sized for the work this test does.
  }, 60_000);
});

/**
 * AUDIT FINDING 3 -- forgery capability and secret-row recovery are two different
 * outcomes, so the result carries two independent fields and the tests cover all
 * five combinations of them.
 *
 *   forgeryOk             the PUBLIC verifier accepted every fresh signature made
 *                         with the candidate. Anyone watching the wire can check
 *                         it. This is what `ok` has always meant.
 *   groundTruthRecovered  the candidate IS the private rows up to sign and
 *                         permutation. Only the lab can check it, because it reads
 *                         the secret, and it gates nothing.
 *
 * The five combinations and where they live:
 *
 *   1. both pass                     -- "recovers the basis ... and forges with it" above
 *   2. forgery without recovery      -- here
 *   3. a candidate that forges nothing -- here
 *   4. the cap runs out, no candidate  -- here
 *   5. Gaussian signatures, both fail  -- the C5' Klein block above
 */
describe("audit finding 3: a basis that forges need not be the secret basis", () => {
  const pubKeyOf = (key: GghKey) => publicKey(key.B, roundOffBoundInf(key.R));
  const oracleOf = (key: GghKey) => makeRoundOffSigner(key.R, inverse(key.R));

  /** The working end-to-end configuration, optionally scored against `groundTruthR`. */
  function attack(key: GghKey, groundTruthR?: Mat): Break2Result {
    return runBreak2({
      pub: pubKeyOf(key),
      sign: oracleOf(key),
      rng: makeRng(4242),
      startN: 4000,
      capN: 32000,
      forgeries: 20,
      groundTruthR,
    });
  }

  /** Everything except the two lab-only fields, for the identical-run comparison. */
  function withoutGroundTruth(
    res: Break2Result,
  ): Omit<Break2Result, 'groundTruthRecovered' | 'groundTruthMatch'> {
    const { groundTruthRecovered, groundTruthMatch, ...rest } = res;
    void groundTruthRecovered;
    void groundTruthMatch;
    return rest;
  }

  it('2 of 5 -- a DIFFERENT basis of the same lattice forges, and is not R', () => {
    const key = signingKey(20260908);
    const pub = pubKeyOf(key);

    // Plain LLL on the PUBLIC basis. Audit finding 1 established that this alone
    // produces a good basis at these parameters; what matters here is that it is
    // a good basis that is NOT the secret one.
    const red = lllReduce(key.B);
    expect(red.failure).toBeNull();
    const lllVsR = matchUpToSignPerm(red.basis, key.R);
    // Same lattice: LLL returns a unimodular H with H*B = basis, so |det| is
    // preserved exactly. Measured ratio 1.000000000000004 or better on four keys.
    expect(lllVsR.absDetRatio).toBeCloseTo(1, 9);
    // ... but NOT the secret rows. Measured at n=8, k=paperK: 1, 4, 2 and 3 of the
    // 8 rows matched up to sign on seeds 20260908, 555, 9090, 1234.
    expect(lllVsR.complete).toBe(false);
    expect(lllVsR.matched).toBeLessThan(n);

    // And it forges anyway, under the victim's OWN published bound: measured
    // 20/20 accepted on every one of those four keys. This is the whole point --
    // the verifier cannot tell a good basis from THE basis.
    const forgeRng = makeRng(99);
    const lllInv = inverse(red.basis);
    let acceptedFromLll = 0;
    for (let t = 0; t < 20; t++) {
      const h = randomH(n, forgeRng);
      if (verify(pub, h, signRoundOff(h, red.basis, lllInv)).ok) acceptedFromLll++;
    }
    expect(acceptedFromLll).toBe(20);

    // So: run the real attack, and score its candidate against that other basis.
    // The forgery check passes and the ground-truth check fails, on the same run,
    // from the same candidate -- which is only possible because the two questions
    // are independent.
    const res = attack(key, red.basis);
    expect(res.forgeryOk).toBe(true);
    expect(res.ok).toBe(true);
    expect(res.groundTruthRecovered).toBe(false);
    const scored = res.groundTruthMatch;
    if (scored === null) throw new Error('a ground truth was supplied, so it must be scored');
    expect(scored.complete).toBe(false);
    expect(scored.matched).toBeLessThan(n);
    // The candidate really is the secret rows -- scored against R it is complete.
    // Only the rows it was COMPARED WITH changed, and the verdict flipped.
    expect(matchUpToSignPerm(res.Rhat as Mat, key.R).complete).toBe(true);
  });

  it('3 of 5 -- a candidate basis is assembled and forges nothing', () => {
    const key = signingKey(555);
    // 250 signatures is far under the measured 4000-16000 this key needs, so the
    // descent still returns 8 distinct directions but the lift rounds them to
    // integer rows that are not R and are not short enough to sign with.
    const res = runBreak2({
      pub: pubKeyOf(key),
      sign: oracleOf(key),
      rng: makeRng(7),
      startN: 250,
      capN: 250,
      forgeries: 20,
      groundTruthR: key.R,
    });

    // A candidate exists and was really offered to the verifier ...
    expect(res.Rhat).not.toBeNull();
    expect(res.attempts[0].directionsFound).toBe(n);
    expect(res.attempts[0].forgeriesAttempted).toBe(20);
    // ... and neither check passes. Measured 0/20 accepted and 0/8 rows matched
    // at N=250 on seeds 555, 20260908 and 99.
    expect(res.forgeryOk).toBe(false);
    expect(res.attempts[0].forgeriesAccepted).toBe(0);
    expect(res.groundTruthRecovered).toBe(false);
    const scored = res.groundTruthMatch;
    if (scored === null) throw new Error('a ground truth was supplied, so it must be scored');
    expect(scored.matched).toBe(0);
  });

  it('the acceptance rule is ALL forgeries, not nearly all', () => {
    // This test exists because a mutation survived without it. Weakening the rule
    // from `accepted === forgeries` to `accepted >= forgeries - 1` left the whole
    // suite green: every natural run is all-or-nothing, so no case distinguished
    // "all of them" from "all but one".
    //
    // With `forgeries: 1` the two rules diverge on a run that accepts none:
    // the real rule needs 1 === 1 and reports false, while a rule tolerating one
    // rejection reads 0 >= 0 and reports SUCCESS. The same N=250 configuration as
    // case 3, which is measured to assemble a candidate and forge nothing.
    const key = signingKey(555);
    const res = runBreak2({
      pub: pubKeyOf(key),
      sign: oracleOf(key),
      rng: makeRng(7),
      startN: 250,
      capN: 250,
      forgeries: 1,
      groundTruthR: key.R,
    });

    // The preconditions that make this a real test of the RULE and not of luck:
    // a candidate existed, and exactly one forgery was offered and refused.
    expect(res.Rhat).not.toBeNull();
    expect(res.attempts[0].forgeriesAttempted).toBe(1);
    expect(res.attempts[0].forgeriesAccepted).toBe(0);

    // One rejected forgery is a failed attack. There is no "close enough" here:
    // the verifier decides, and it said no.
    expect(res.forgeryOk).toBe(false);
    expect(res.ok).toBe(false);
  });

  it('4 of 5 -- the cap runs out with no candidate at all, and says so', () => {
    const key = signingKey(4321);
    // A restart budget of 3 cannot collect 8 distinct directions, so no candidate
    // is ever assembled: nothing is offered to the verifier and nothing is scored.
    const res = runBreak2({
      pub: pubKeyOf(key),
      sign: oracleOf(key),
      rng: makeRng(11),
      startN: 500,
      capN: 1000,
      forgeries: 20,
      maxRestarts: 3,
      groundTruthR: key.R,
    });

    expect(res.ok).toBe(false);
    expect(res.forgeryOk).toBe(false);
    expect(res.Rhat).toBeNull();
    expect(res.attempts).toHaveLength(2);
    expect(res.attempts.every((a) => a.forgeriesAttempted === 0)).toBe(true);
    expect(res.reason).toMatch(/cap of 1000/);
    expect(res.reason).toMatch(/restart budget 3 exhausted/);
    // Nothing to match, so nothing is reported as matched -- but the verdict is
    // still false and not null, because a ground truth WAS supplied and an
    // incomplete candidate cannot be an n x n nonsingular basis.
    expect(res.groundTruthMatch).toBeNull();
    expect(res.groundTruthRecovered).toBe(false);
  });

  it('names training, hold-out and total on every rung of the ladder', () => {
    const key = signingKey(555);
    // Three rungs -- 500, 1000, 2000 -- all far under what this key needs, which
    // is exactly the case where an ambiguous headline number would mislead.
    const res = runBreak2({
      pub: pubKeyOf(key),
      sign: oracleOf(key),
      rng: makeRng(7),
      startN: 500,
      capN: 2000,
      forgeries: 20,
    });

    expect(res.attempts.map((a) => a.trainingSignatures)).toEqual([500, 1000, 2000]);
    for (const a of res.attempts) {
      // The hold-out is drawn on EVERY rung, successful or not, so every rung
      // costs the victim twice what the descent consumed.
      expect(a.heldOutSignatures).toBe(a.trainingSignatures);
      expect(a.totalObserved).toBe(2 * a.trainingSignatures);
      // The old per-rung name is the training half, and cannot drift from it.
      expect(a.signatures).toBe(a.trainingSignatures);
    }
    // The headline numbers agree with the last rung.
    const last = res.attempts[res.attempts.length - 1];
    expect(res.trainingSignatures).toBe(last.trainingSignatures);
    expect(res.signaturesConsumed).toBe(res.trainingSignatures);
    expect(res.heldOutSignatures).toBe(last.heldOutSignatures);
    expect(res.totalObserved).toBe(2 * res.trainingSignatures);
    expect(res.totalSignaturesObserved).toBe(res.totalObserved);
  });

  it('is identical with and without the ground truth: the attack never reads it', () => {
    const key = signingKey(20260908);
    const scored = attack(key, key.R);
    const blind = attack(key);

    // Field for field -- ladder, discriminators, lifted rows, candidate, reason,
    // sample counts -- the two runs are the same run. The secret changed nothing.
    expect(withoutGroundTruth(scored)).toEqual(withoutGroundTruth(blind));

    expect(scored.groundTruthRecovered).toBe(true);
    // null, NOT false: the lab was never asked, and "not scored" is not "not
    // recovered". An attacker's own run always looks like this one.
    expect(blind.groundTruthRecovered).toBeNull();
    expect(blind.groundTruthMatch).toBeNull();
  });

  it('refuses a mis-shaped ground truth instead of scoring everything as a failure', () => {
    const key = signingKey(555);
    expect(() =>
      runBreak2({
        pub: pubKeyOf(key),
        sign: oracleOf(key),
        rng: makeRng(7),
        startN: 250,
        capN: 250,
        groundTruthR: [Float64Array.from([1, 2, 3])],
      }),
    ).toThrow(/8x8/);
  });
});
