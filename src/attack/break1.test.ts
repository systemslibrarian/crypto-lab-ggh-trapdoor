import { describe, expect, it } from 'vitest';
import type { GghKey, Vec } from '../lattice/types';
import { inverse, makeRng } from '../lattice/matrix';
import { SIGMA, gghKeygen, invertibleModP } from '../lattice/keygen';
import { encrypt, encryptNonCongruent, randomMessage, reEncryptionCheck } from '../lattice/roundoff';
import { modP } from './mod6';
import { Break1Stepper, runBreak1, type Break1StepKind } from './break1';
import type { Rng } from '../lattice/types';

const ALL_STEPS: Break1StepKind[] = ['mod6', 'divide', 'embed', 'readoff', 'recover', 'verify'];

/** Keep drawing keys until B is singular mod 6 -- ~83% of unrestricted keys are. */
function singularKey(n: number, rng: Rng): GghKey {
  for (let i = 0; i < 200; i++) {
    const key = gghKeygen(n, { rng, requireCoprime6: false });
    if (!invertibleModP(key.B, 2) || !invertibleModP(key.B, 3)) return key;
  }
  throw new Error('no singular key found');
}

describe('Break 1 end to end', () => {
  for (const n of [8, 16, 32]) {
    it(`recovers the message at n = ${n}, verified by re-encryption (I5)`, () => {
      const rng = makeRng(1000 + n);
      for (let trial = 0; trial < 4; trial++) {
        const key = gghKeygen(n, { rng });
        const m = randomMessage(n, rng);
        const ct = encrypt(m, key.B, rng);

        const r = runBreak1(ct.c, key.B);

        // The load-bearing claim: the attacker's own check, run with the public
        // key alone. Invariant I5 forbids resting the claim on anything else.
        expect(r.verified).toBe(true);
        expect(r.failedAt).toBeNull();
        expect(r.m).not.toBeNull();
        const recheck = reEncryptionCheck(ct.c, r.m as Vec, key.B, SIGMA);
        expect(recheck.ok).toBe(true);
        for (const v of recheck.residual) expect(Math.abs(v)).toBe(SIGMA);

        // Secondary, and only available to the test: it really is the message.
        expect(Array.from(r.m as Vec)).toEqual(Array.from(m));

        // Observables the UI shows on a success.
        expect(r.observables.divisionExact).toBe(true);
        expect(r.observables.patternOk).toBe(true);
        expect(r.observables.reEncryptionOk).toBe(true);
        expect(r.observables.minRowNorm).toBeCloseTo(Math.sqrt(n + 1), 9);
        expect(r.observables.normRatio).toBeCloseTo(1, 9);
        for (let j = 0; j < n; j++) {
          expect((r.observables.m0 as Vec)[j]).toBe(modP(m[j], 2 * SIGMA));
        }
      }
    });
  }

  it('works with the uncentered embedding too', () => {
    const rng = makeRng(2001);
    const key = gghKeygen(16, { rng });
    const m = randomMessage(16, rng);
    const ct = encrypt(m, key.B, rng);
    const r = runBreak1(ct.c, key.B, { form: 'uncentered' });
    expect(r.verified).toBe(true);
    expect(Array.from(r.m as Vec)).toEqual(Array.from(m));
  });

  it('works without the target reduction, and with a caller-supplied B^-1', () => {
    const rng = makeRng(2002);
    const key = gghKeygen(16, { rng });
    const m = randomMessage(16, rng);
    const ct = encrypt(m, key.B, rng);
    expect(runBreak1(ct.c, key.B, { reduceTarget: false }).verified).toBe(true);
    expect(runBreak1(ct.c, key.B, { Binv: inverse(key.B) }).verified).toBe(true);
  });
});

describe('the stepper', () => {
  it('emits the six steps in order and then stops', () => {
    const rng = makeRng(3003);
    const key = gghKeygen(16, { rng });
    const ct = encrypt(randomMessage(16, rng), key.B, rng);
    const stepper = new Break1Stepper(ct.c, key.B);

    const kinds: Break1StepKind[] = [];
    for (;;) {
      const step = stepper.next();
      if (step === null) break;
      kinds.push(step.kind);
      expect(step.ok).toBe(true);
      expect(step.note.length).toBeGreaterThan(0);
    }
    expect(kinds).toEqual(ALL_STEPS);
    expect(stepper.done).toBe(true);
    expect(stepper.next()).toBeNull();
    expect(stepper.steps).toHaveLength(6);
    expect(stepper.result().verified).toBe(true);
  });

  it('carries the data each step is supposed to show', () => {
    const rng = makeRng(3004);
    const n = 16;
    const key = gghKeygen(n, { rng });
    const ct = encrypt(randomMessage(n, rng), key.B, rng);
    const r = runBreak1(ct.c, key.B);

    const mod6 = r.steps[0];
    expect(mod6.kind).toBe('mod6');
    if (mod6.kind !== 'mod6') return;
    expect(mod6.singular).toBeNull();
    expect(mod6.m0).not.toBeNull();
    for (const v of mod6.rhs) expect(v).toBeGreaterThanOrEqual(0);

    const divide = r.steps[1];
    if (divide.kind !== 'divide') return;
    expect(divide.firstInexactIndex).toBe(-1);
    expect(divide.cpp).not.toBeNull();

    const embed = r.steps[2];
    if (embed.kind !== 'embed') return;
    expect(embed.form).toBe('centered');
    expect(embed.failure).toBeNull();
    expect(embed.guardMax).toBeGreaterThan(0);
    expect(embed.targetReduced).toBe(true);
    expect(embed.targetMaxAbsAfter).toBeLessThan(embed.targetMaxAbsBefore);

    const readoff = r.steps[3];
    if (readoff.kind !== 'readoff') return;
    expect(readoff.exactCandidates).toBeGreaterThan(0);
    // The recovered row really is the {+1,-1} pattern Nguyen predicts.
    for (const v of readoff.head as Vec) expect(Math.abs(v)).toBe(1);
    for (const v of readoff.ep as Vec) expect(v === 0 || v === -1).toBe(true);

    const recover = r.steps[4];
    if (recover.kind !== 'recover') return;
    expect(recover.mp).not.toBeNull();

    const verify = r.steps[5];
    if (verify.kind !== 'verify') return;
    expect(verify.ok).toBe(true);
    for (const v of verify.residual as Vec) expect(Math.abs(v)).toBe(SIGMA);
  });

  it('stops at a singular B and names the modulus (invariant I3)', () => {
    const rng = makeRng(4004);
    for (const n of [8, 16]) {
      const key = singularKey(n, rng);
      const ct = encrypt(randomMessage(n, rng), key.B, rng);
      const stepper = new Break1Stepper(ct.c, key.B);
      const step = stepper.next();
      expect(step).not.toBeNull();
      if (step === null || step.kind !== 'mod6') return;
      expect(step.ok).toBe(false);
      expect(step.singular).not.toBeNull();
      const bad2 = !invertibleModP(key.B, 2);
      const bad3 = !invertibleModP(key.B, 3);
      expect(step.singular?.singularMod2).toBe(bad2);
      expect(step.singular?.singularMod3).toBe(bad3);
      expect(step.singular?.modulus).toBe(bad2 && bad3 ? 6 : bad2 ? 2 : 3);
      // Nothing downstream is attempted: the act says so and re-keys.
      expect(stepper.next()).toBeNull();
      const r = stepper.result();
      expect(r.failedAt).toBe('mod6');
      expect(r.verified).toBe(false);
      expect(r.steps).toHaveLength(1);
    }
  });

  it('surfaces an LLL failure at the embed step instead of guessing', () => {
    const rng = makeRng(5005);
    const key = gghKeygen(16, { rng });
    const ct = encrypt(randomMessage(16, rng), key.B, rng);
    const r = runBreak1(ct.c, key.B, { maxIters: 2 });
    expect(r.verified).toBe(false);
    expect(r.failedAt).toBe('embed');
    const embed = r.steps[2];
    if (embed.kind !== 'embed') return;
    expect(embed.failure?.kind).toBe('iteration-cap');
    expect(r.steps).toHaveLength(3);
  });
});

describe('claim C4: a non-congruent error kills the attack', () => {
  it('fails with the measured observables, NOT with an inexact division', () => {
    const n = 16;
    const rng = makeRng(6006);
    const trials = 25;
    let divExact = 0;
    let m0Correct = 0;
    let pattern = 0;
    let verified = 0;
    let worstRatio = Infinity;
    let usable = 0;

    for (let trial = 0; trial < trials; trial++) {
      const key = gghKeygen(n, { rng });
      const m = randomMessage(n, rng);
      const ct = encryptNonCongruent(m, key.B, rng);
      // Guard against the (1e-9 likely) draw where e lands in {+-sigma}^n anyway.
      if (Array.from(ct.e).every((v) => Math.abs(v) === SIGMA)) continue;
      usable++;

      const r = runBreak1(ct.c, key.B);
      if (r.observables.divisionExact) divExact++;
      if (r.observables.patternOk) pattern++;
      if (r.verified) verified++;
      const m0 = r.observables.m0 as Vec;
      let same = true;
      for (let j = 0; j < n; j++) if (m0[j] !== modP(m[j], 2 * SIGMA)) same = false;
      if (same) m0Correct++;
      worstRatio = Math.min(worstRatio, r.observables.normRatio);
    }

    expect(usable).toBe(trials);
    // The correction the brief needed: the division ALWAYS succeeds, because m0
    // solves the congruence by construction whatever c was.
    expect(divExact).toBe(trials);
    // What actually breaks: the residue itself is wrong, every time.
    expect(m0Correct).toBe(0);
    // And the three observables the UI must show instead.
    expect(pattern).toBe(0);
    expect(verified).toBe(0);
    // Measured minimum over 25 tampered trials at n=16: 3.11x. Honest runs sit at
    // exactly 1.000x, so the two populations do not overlap.
    expect(worstRatio).toBeGreaterThan(2.5);
  });

  it('still produces an answer, and lets the re-encryption check reject it', () => {
    const rng = makeRng(7007);
    const key = gghKeygen(16, { rng });
    const m = randomMessage(16, rng);
    const ct = encryptNonCongruent(m, key.B, rng);
    const r = runBreak1(ct.c, key.B);

    // All six steps still run: a page that shows the answer being rejected
    // teaches more than one that shows nothing.
    expect(r.steps.map((s) => s.kind)).toEqual(ALL_STEPS);
    expect(r.failedAt).toBe('readoff');
    const verify = r.steps[5];
    if (verify.kind !== 'verify') return;
    expect(verify.ok).toBe(false);
    expect(r.m).toBeNull();
    // When LLL did hand back a usable row, the re-encryption check is what
    // rejects it -- never a comparison against the true message.
    if (verify.residual !== null) {
      expect(Array.from(verify.residual).some((v) => Math.abs(v) !== SIGMA)).toBe(true);
    } else {
      expect(verify.tried).toBe(0);
    }
  });

  it('one bad coordinate out of sixteen is enough: a cliff, not a slope', () => {
    const n = 16;
    const rng = makeRng(8008);
    for (let trial = 0; trial < 5; trial++) {
      const key = gghKeygen(n, { rng });
      const m = randomMessage(n, rng);

      // j = 0 deviating coordinates: the honest ciphertext, and the attack works.
      const good = encryptNonCongruent(m, key.B, rng, SIGMA, 0);
      expect(runBreak1(good.c, key.B).verified).toBe(true);

      // j = 1: exactly one coordinate outside {+-sigma}, and the attack dies.
      const bad = encryptNonCongruent(m, key.B, rng, SIGMA, 1);
      const r = runBreak1(bad.c, key.B);
      expect(r.verified).toBe(false);
      expect(r.observables.divisionExact).toBe(true);
      expect(r.observables.patternOk).toBe(false);
      // Non-local: a one-coordinate defect corrupts most of m0, because the fix-up
      // is multiplied by B^-1 mod 6. Measured mean 11.5 wrong of 16.
      let wrong = 0;
      const m0 = r.observables.m0 as Vec;
      for (let j = 0; j < n; j++) if (m0[j] !== modP(m[j], 2 * SIGMA)) wrong++;
      expect(wrong).toBeGreaterThan(1);
    }
  });
});
