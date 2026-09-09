import { describe, expect, it } from 'vitest';
import type { Mat, Vec } from '../lattice/types';
import { TWO53, inverse, makeRng, matEq, matmul } from '../lattice/matrix';
import { gghKeygen, paperK } from '../lattice/keygen';
import { proveSameLattice } from '../lattice/invariants';
import {
  decrypt,
  encrypt,
  latticePointToMessage,
  randomMessage,
  reEncryptionCheck,
  roundOff,
  worstCaseBound,
} from '../lattice/roundoff';
import { runPublicLllBaseline } from './baseline';

/** The dimensions the lab offers. The baseline must be recorded at every one. */
const DIMS = [8, 16, 32, 60];
/** Seeded keys per dimension. The audit asked for at least 8; 48 keys costs ~250 ms. */
const KEYS = 12;
/** Fresh ciphertexts pushed through the reduced basis per key. */
const CTS = 5;
/** One base seed, so every number below is reproducible by rerunning this file. */
const SEED = 3_140_000;

/**
 * Per-key ceilings on the LLL(B) reduction time.
 *
 * Measured medians over the 12 keys below, Node 24 on the development machine:
 * 0.044 / 0.089 / 0.81 / 6.2 ms at n = 8 / 16 / 32 / 60, worst single key 8.8 ms.
 * The same reduction was measured at 10 / 12 / 67 / 246 ms in the browser, which
 * is the number the UI has to live with. These ceilings are ~2.5x the browser
 * figure and ~50x the Node figure: loose enough that a slow CI runner cannot turn
 * variance into a red build, tight enough to catch the order-of-magnitude
 * regression that would make this unusable as a button the learner presses.
 */
const MS_BUDGET: Record<number, number> = { 8: 100, 16: 100, 32: 200, 60: 600 };

const median = (xs: number[]): number => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
};

/**
 * THE BASELINE, RECORDED. One test per dimension so a regression names the
 * dimension it broke at.
 *
 * Every number asserted here was measured first and is asserted at its measured
 * value. Nothing is softened: the match rate and the decryption rate really are
 * 100% at every dimension this lab offers, and if that ever stops being true the
 * right response is to change the claim, not the assertion.
 */
describe('the public-LLL baseline: ordinary reduction of B recovers the trapdoor', () => {
  for (const n of DIMS) {
    it(`recovers R up to sign and permutation on ${KEYS}/${KEYS} keys at n = ${n}, and decrypts ${KEYS * CTS}/${KEYS * CTS}`, () => {
      let matches = 0;
      let decrypted = 0;
      let attempted = 0;
      const ms: number[] = [];
      const wcb: number[] = [];
      const defect: number[] = [];

      for (let s = 0; s < KEYS; s++) {
        const rng = makeRng(SEED + 1000 * n + s);
        const key = gghKeygen(n, { rng });
        const r = runPublicLllBaseline(key, { rng, ciphertexts: CTS });

        // The reduction itself stayed inside the exact-integer contract.
        expect(r.failure).toBeNull();
        expect(r.guardMax).toBeLessThan(TWO53 / 1e6);

        // LAB-ONLY GROUND TRUTH: the rows really are the secret rows, entry for
        // entry, up to sign and order. An attacker cannot run this check -- it
        // reads R -- which is why it is recorded beside, never instead of, the
        // attacker-side checks below.
        expect(r.matchedRows).toBe(n);
        expect(r.matchesSecret).toBe(true);
        if (r.matchesSecret) matches++;

        // ATTACKER-SIDE (invariant I5): the real round-off decryptor and the real
        // re-encryption check, with no access to m, e or R.
        expect(r.attempted).toBe(CTS);
        expect(r.decrypted).toBe(CTS);
        expect(r.ok).toBe(true);
        decrypted += r.decrypted;
        attempted += r.attempted;

        // ATTACKER-SIDE: the reduced basis's own I2 bound. Measured 0.1133 to
        // 0.1403 across all 48 keys -- the same range as the PRIVATE basis's,
        // because it is the private basis. Below 0.5 means decryption through it
        // provably cannot fail for any error in {+-3}^n.
        expect(r.guaranteed).toBe(true);
        expect(r.worstCaseBound).toBeGreaterThan(0.1);
        expect(r.worstCaseBound).toBeLessThan(0.15);

        ms.push(r.ms);
        wcb.push(r.worstCaseBound);
        defect.push(r.log10DefectReduced);
      }

      expect(matches).toBe(KEYS);
      expect(decrypted).toBe(attempted);
      expect(decrypted).toBe(KEYS * CTS);

      // Measured medians: 0.044 / 0.089 / 0.81 / 6.2 ms; see MS_BUDGET.
      expect(median(ms)).toBeLessThan(MS_BUDGET[n]);

      // The orthogonality defect of the reduced basis lands where the PRIVATE
      // basis lands (measured log10: 0.039-0.080 at n=8 rising to 0.770-0.865 at
      // n=60), not where the public one does (~10^69 at n=60). This is the number
      // the UI puts beside R and B.
      expect(Math.max(...defect)).toBeLessThan(1);
    }, 120_000);
  }
});

describe('the reduced basis is a basis of the same lattice', () => {
  it('H * B === LLL(B) exactly, and I1 proves L(LLL(B)) = L(B) = L(R)', () => {
    for (const n of DIMS) {
      for (let s = 0; s < 3; s++) {
        const rng = makeRng(SEED + 700_000 + 1000 * n + s);
        const key = gghKeygen(n, { rng });
        const r = runPublicLllBaseline(key, { rng, ciphertexts: 1 });

        // Exact integer identity, no tolerance: the reduction is a unimodular
        // recombination of the public rows and nothing else.
        expect(matEq(matmul(r.transform, key.B), r.reducedBasis)).toBe(true);

        // And the full I1 proof, in both orientations. Reusing the production
        // prover rather than a determinant: det(B) is 10^89.7 at n=60.
        expect(proveSameLattice(key.B, r.reducedBasis).ok).toBe(true);
        expect(proveSameLattice(key.R, r.reducedBasis).ok).toBe(true);
      }
    }
  }, 120_000);
});

/**
 * The control the headline claim rests on, measured on the SAME keys and the SAME
 * ciphertexts as the baseline above, so the two can be shown side by side.
 *
 * This is what keeps the lab's headline true after the baseline is admitted: raw
 * Babai round-off with B genuinely does fail. What changes is the scope of the
 * sentence -- "B is a bad basis for round-off", not "B keeps R secret".
 */
describe('the raw public basis, for contrast', () => {
  it('raw B decrypts 2/30 at n=8 and 0/30 above it, where LLL(B) decrypts 30/30', () => {
    // Measured, and asserted at the measured value: at n=8 the worst-case I2
    // bound of B is only 1.76-6.40, so an occasional ciphertext really does land
    // inside the half-integer box and decrypt. Raw-B failure is a rate at n=8,
    // not a law, and the lab should not claim otherwise. These counts are a
    // RECORD for these seeds -- a deliberate change to keygen or to the error
    // distribution would legitimately move them, and moving them should be a
    // decision, not a silent drift.
    const expectedRawDecryptions: Record<number, number> = { 8: 2, 16: 0, 32: 0, 60: 0 };

    for (const n of DIMS) {
      let raw = 0;
      let reduced = 0;
      let attempted = 0;
      for (let s = 0; s < 6; s++) {
        const rng = makeRng(SEED + 500_000 + 1000 * n + s);
        const key = gghKeygen(n, { rng });
        const Binv = inverse(key.B);
        const r = runPublicLllBaseline(key, { rng, ciphertexts: 0, Binv });
        const redInv = inverse(r.reducedBasis);

        // The public basis has no I2 guarantee at all: measured worst-case bound
        // 1.76-6.40 at n=8 and 8.13-13.33 at n=60, against 0.113-0.140 for the
        // basis LLL just handed the attacker for free.
        expect(worstCaseBound(Binv)).toBeGreaterThan(1);
        expect(r.guaranteed).toBe(true);

        for (let t = 0; t < CTS; t++) {
          const m = randomMessage(n, rng);
          const ct = encrypt(m, key.B, rng);
          attempted++;
          // Identical arithmetic, identical ciphertext; only the basis differs.
          const mRaw = latticePointToMessage(roundOff(ct.c, key.B, Binv), Binv);
          if (reEncryptionCheck(ct.c, mRaw, key.B).ok) raw++;
          const mRed = latticePointToMessage(roundOff(ct.c, r.reducedBasis, redInv), Binv);
          if (reEncryptionCheck(ct.c, mRed, key.B).ok) reduced++;
        }
      }
      expect(attempted).toBe(30);
      expect(raw).toBe(expectedRawDecryptions[n]);
      expect(reduced).toBe(attempted);
    }
  }, 120_000);
});

/**
 * DOES THE LAB'S RAISED k CAUSE THIS? No.
 *
 * keygen.ts uses k = ceil(2*l*sqrt(n)) + 4*l instead of GGH's own
 * k = l*ceil(sqrt(n)), to buy a decryption guarantee at teaching dimensions. That
 * makes the private basis MORE orthogonal, so the honest worry is that the raised
 * k is what puts R inside LLL's reach. Measured with `paperK(n)`, 8 keys per
 * dimension, 5 ciphertexts per key, the reduced basis and the private basis
 * decrypting the SAME ciphertexts:
 *
 *   n    k    exact match   LLL(B) decrypts   R decrypts   bound ratio
 *   8    12     0 / 8          26 / 40          23 / 40     <= 1.194
 *   16   16     0 / 8          26 / 40          26 / 40     <= 1.203
 *   32   24     7 / 8          40 / 40          40 / 40     <= 1.084
 *   60   32     8 / 8          40 / 40          40 / 40     <= 1.000
 *
 * So the EXACT-MATCH rate does move with k -- at n = 8 and 16 under the paper's
 * rule, LLL returns a DIFFERENT basis. The conclusion does not move at all: the
 * different basis is at least as useful as the secret one. At n=8 it is strictly
 * better, decrypting 26 of the same 40 ciphertexts where the genuine private key
 * managed 23, because at paperK the private basis violates I2 itself (its own
 * worst-case bound measured 0.65 to 2.73 here, never once under 0.5) -- which is
 * the measurement keygen.ts documents from the other side. Nobody's key works
 * properly at paperK; the attacker's copy simply works as well.
 *
 * The audit finding-6 correction to `paperK` (round(l*sqrt(n)) -> l*ceil(sqrt(n)),
 * the formula GGH section 5.2 actually prints) landed while this was being
 * measured, so both readings were measured. They agree everywhere except n=32,
 * where the earlier round() reading gave 4/8 exact matches and 37/40 vs 38/40
 * decryptions. The assertions below are the ones that hold under EITHER reading;
 * where the two differ, the comment says so rather than pinning the number that
 * happens to be current.
 */
describe('the same result under the 1997 paper parameter rule', () => {
  /** Exact and identical under both readings of the paper's k; null where they differ. */
  const expectedMatches: Record<number, number | null> = { 8: 0, 16: 0, 32: null, 60: 8 };
  /** n=32 is the one cell that moved: 4/8 under round(l*sqrt n), 7/8 under l*ceil(sqrt n). */
  const matchFloor: Record<number, number> = { 8: 0, 16: 0, 32: 4, 60: 8 };

  it('LLL(B) is as good as the private basis at paperK(n) too, matched or not', () => {
    for (const n of DIMS) {
      let matches = 0;
      let byReduced = 0;
      let byPrivate = 0;
      let attempted = 0;
      let worstRatio = 0;
      let minPrivateBound = Infinity;

      for (let s = 0; s < 8; s++) {
        const rng = makeRng(SEED + 900_000 + 1000 * n + s);
        const key = gghKeygen(n, { rng, k: paperK(n) });
        const Binv = inverse(key.B);
        const Rinv = inverse(key.R);
        const r = runPublicLllBaseline(key, { rng, ciphertexts: 0, Binv });
        expect(r.failure).toBeNull();
        if (r.matchesSecret) matches++;

        // The guarantee flag is the I2 HALF threshold and nothing looser. At
        // paperK the reduced basis's own bound measured 0.6895 to 1.3125 across
        // both readings of the paper's k -- it decrypts most ciphertexts and is
        // still not guaranteed, which is the only place in this file where a
        // widened threshold would show.
        expect(r.worstCaseBound).toBeGreaterThan(0.5);
        expect(r.guaranteed).toBe(false);

        const privateBound = worstCaseBound(Rinv);
        minPrivateBound = Math.min(minPrivateBound, privateBound);
        worstRatio = Math.max(worstRatio, r.worstCaseBound / privateBound);

        const redInv = inverse(r.reducedBasis);
        for (let t = 0; t < CTS; t++) {
          const m: Vec = randomMessage(n, rng);
          const ct = encrypt(m, key.B, rng);
          attempted++;
          const mRed = latticePointToMessage(roundOff(ct.c, r.reducedBasis, redInv), Binv);
          if (reEncryptionCheck(ct.c, mRed, key.B).ok) byReduced++;
          const mPriv = decrypt(ct.c, key, Rinv, Binv);
          if (reEncryptionCheck(ct.c, mPriv, key.B).ok) byPrivate++;
        }
      }

      // Recorded exactly as measured, including the two dimensions where the
      // exact matcher goes to zero. Softening 0 to "at least 0" would hide the
      // one place where k genuinely changes the answer.
      const expected = expectedMatches[n];
      if (expected !== null) expect(matches).toBe(expected);
      expect(matches).toBeGreaterThanOrEqual(matchFloor[n]);

      // The load-bearing claim: the reduced PUBLIC basis decrypts at least as
      // well as the genuine PRIVATE basis at every dimension, under GGH's own
      // parameter rule. Measured margin (reduced minus private, out of 40):
      // +3, 0, 0, 0 under l*ceil(sqrt n), and -1, 0, -1, 0 under the earlier
      // round(l*sqrt n) reading, so the assertion is stated to the tolerance
      // both readings clear.
      expect(attempted).toBe(40);
      expect(byReduced).toBeGreaterThanOrEqual(byPrivate - 1);

      // Neither side reaches 40/40 at n = 8 or 16 because the private basis is
      // not good enough at paperK either: its own worst-case I2 bound never
      // drops below 0.65, so the honest owner has no guarantee to lose.
      expect(minPrivateBound).toBeGreaterThan(0.5);

      // And the attacker's basis is never much worse than the secret one.
      expect(worstRatio).toBeLessThan(1.3);
    }
  }, 120_000);
});

/**
 * The entry point must report a failed reduction as a failure, not as a quiet
 * "no match". If this ever went green with `ok: true`, the UI would show the
 * strongest claim in the lab on the strength of a reduction that never ran.
 */
describe('the baseline fails honestly', () => {
  it('an iteration-capped run reports the cap, recovers nothing, and is not ok', () => {
    const rng = makeRng(SEED + 42);
    const key = gghKeygen(16, { rng });
    const r = runPublicLllBaseline(key, { rng, ciphertexts: CTS, maxIters: 1 });

    expect(r.failure).not.toBeNull();
    expect(r.failure?.kind).toBe('iteration-cap');
    expect(r.ok).toBe(false);

    // Non-vacuity for the ground-truth matcher: it says NO on a basis that is
    // still essentially the public one.
    expect(r.matchesSecret).toBe(false);
    expect(r.matchedRows).toBe(0);
    expect(r.decrypted).toBe(0);
    expect(r.attempted).toBe(CTS);
    expect(r.guaranteed).toBe(false);

    // The partial basis is still a basis of the same lattice -- LLL's contract
    // holds even when the budget runs out.
    const partial: Mat = r.reducedBasis;
    expect(matEq(matmul(r.transform, key.B), partial)).toBe(true);
  }, 60_000);

  it('refuses an unsafe-integer basis instead of reducing it', () => {
    // 1e17 is a double but not a safe integer: the exact-integer contract is
    // broken before any reduction happens, so nothing downstream may be trusted.
    const rng = makeRng(SEED + 43);
    const key = gghKeygen(8, { rng });
    const B: Mat = key.B.map((row) => Float64Array.from(row));
    B[0][0] = 1e17;
    const r = runPublicLllBaseline({ ...key, B }, { rng, ciphertexts: CTS });

    expect(r.failure?.kind).toBe('integer-overflow');
    expect(r.ok).toBe(false);
    expect(r.attempted).toBe(0);
    expect(r.decrypted).toBe(0);
    expect(r.guaranteed).toBe(false);
    expect(r.worstCaseBound).toBe(Infinity);
  }, 60_000);
});
