/**
 * BREAK 2 -- Nguyen and Regev, "Learning a parallelepiped: cryptanalysis of GGH
 * and NTRU signatures", EUROCRYPT 2006 (J. Cryptology 2009).
 *
 * The whole attack, assembled from the three public steps:
 *
 *   1. Watch signatures. Each one leaks v = s - h = x*R with x uniform in
 *      [-1/2,1/2)^n -- a uniform sample from the fundamental parallelepiped of
 *      the SECRET basis (sign.ts).
 *   2. Whiten. G = 12*mean(v^T v) estimates R^T R; Cholesky G = L^T L; then
 *      w = v*L^-1 = x*Q with Q = R*L^-1 orthogonal. The skewed box becomes a
 *      rotated cube (whiten.ts).
 *   3. Descend. Minimising the fourth moment over the unit sphere lands on the
 *      rows of Q, which are the rows of R in whitened coordinates (moments.ts,
 *      descent.ts).
 *   4. Lift. round(u * L) turns a recovered direction back into an integer
 *      candidate row of R.
 *
 * Nothing here touches lattice hardness. The attack never solves a CVP instance,
 * never runs a reduction, and would work just as well if the lattice were
 * astronomically hard: it attacks the SHAPE of the trapdoor, which the signature
 * scheme publishes one sample at a time.
 *
 * HOW MANY SIGNATURES -- MEASURED, AND NEVER HARDCODED. Ten independent keys per
 * dimension, doubling ladder, success meaning full recovery AND an accepted
 * forgery:
 *
 *     n    median N   min     max     median restarts
 *     8    8000       4000    16000   16
 *     12   16000      16000   32000   32.5
 *     16   32000      16000   64000   53
 *
 * The per-key spread is real -- at n=8 the ten keys needed 8000, 16000, 8000,
 * 4000, 8000, 8000, 16000, 8000, 8000, 8000 -- so `runBreak2` climbs a ladder and
 * REPORTS what this key actually cost. Median N scales as about n^2. A UI must
 * display the live counter, not the table above.
 *
 * AND THE COST DEPENDS ON k, WHICH THIS LAB CHANGED. The lift threshold that
 * round(u*L) has to beat is the absolute number 1/2, while ||L|| ~ ||R|| grows
 * with the diagonal shift k, so the signature requirement scales as k^2. The
 * table above is at GGH's own k = round(sqrt(n)*l), which is what `paperK`
 * returns. This lab's DEFAULT `gghK` is about 3.5x larger at n=8 (39 against 11)
 * because it is chosen to guarantee round-off DECRYPTION (invariant I2), and
 * measured on four keys per dimension it costs Break 2 roughly 16x more
 * signatures: 64000-128000 at n=8, and two n=16 keys in four still unrecovered at
 * 128000. Break 2 attacks a signature scheme and needs no decryption guarantee,
 * so the signature act should key with `k: paperK(n)`; using the decryption key
 * is legitimate but must be shown honestly, with the counter running much higher.
 *
 * Measured for this implementation at `paperK`, whole ladder from N=1000, first
 * rung whose forgeries all verify: n=8 needed 8000-16000 signatures over 8 keys
 * (0.08-0.24 s), n=12 needed 16000-32000 (0.45-1.2 s), n=16 needed 32000-64000
 * (2.5-6.1 s).
 *
 * WHAT SETS THE REQUIREMENT. Not the covariance: re-running with an exact
 * whitening oracle barely moves the threshold, and the descent finds all n
 * distinct directions from N=500 upward at every dimension tested. The bottleneck
 * is the ANGULAR accuracy of each recovered direction, amplified by ||L|| ~
 * k*sqrt(n) when it is lifted. Measured at n=16, the worst |u*L - R_j|inf across
 * recovered rows falls 9.20 -> 1.02 -> 0.49 -> 0.29 as N goes 500 -> 4000 ->
 * 16000 -> 64000, and plain rounding needs it under 0.5.
 *
 * [extension] FINISHING THE LIFT WITH A CVP STEP. At n=16, N=1000 the true row is
 * ALREADY the unique nearest lattice point to u*L (measured max L2 error 3.97
 * against lambda1/2 = 7.6), while plain rounding does not succeed until
 * N=16000-32000. Replacing round(u*L) with the embedding + LLL that Break 1
 * already builds would therefore cut the signature requirement by 16-32x and make
 * a live n=16 demo feel instant. It is deliberately NOT built here: plain
 * rounding is what the paper specifies, it is the honest default, and a lift that
 * silently borrowed the other attack's machinery would misreport what this attack
 * costs. Wire it as an option, never as the default.
 *
 * INVARIANT I4. Recovery is up to SIGN and PERMUTATION only, and it cannot be
 * anything better: -q_i minimises the objective exactly as well as q_i, and the
 * restarts find rows in whatever order their basins come up. `matchUpToSignPerm`
 * checks that with entrywise integer equality and no tolerance. It is a SCORING
 * function -- it uses the secret, so only the LAB can run it, and it is surfaced
 * as `groundTruthRecovered`. It never decides anything.
 *
 * INVARIANT I5. The pass/fail test is the REAL verifier. `runBreak2` assembles
 * Rhat from the recovered rows, signs FRESH messages with it, and requires
 * verify() -- which knows only B and the published bound -- to accept every one.
 * Measured: forgery success conditional on complete recovery was 2400/2400;
 * partial recovery forged 0 times out of 2400. The two outcomes are perfectly
 * binary, which is what makes the forgery test a real referee rather than a
 * formality.
 *
 * TWO OUTCOMES, AND THEY ARE NOT THE SAME OUTCOME. That 2400/2400 says the two
 * agreed on every candidate THIS descent produced; it is not a theorem that they
 * must, and the lab must not render one as the other:
 *
 *   forgeryOk             the public verifier accepted every fresh signature made
 *                         with the candidate. ATTACKER-OBSERVABLE -- it needs only
 *                         B and the published bound. This is what `ok` has always
 *                         meant and still means.
 *   groundTruthRecovered  the candidate IS the rows of R up to sign and
 *                         permutation. LAB-ONLY: computing it requires the secret,
 *                         so no attacker can, and it NEVER gates the attack. It is
 *                         null unless `groundTruthR` was handed in for scoring.
 *
 * They come apart, and not hypothetically. MEASURED here at n=8, k=paperK, four
 * keys: plain LLL on the PUBLIC basis returns a basis of the same lattice (|det|
 * ratio 1.000000000000004 or better) that forged 20/20 signatures accepted under
 * the victim's own published bound, while matching only 1, 2, 3 and 4 of the 8
 * rows of R up to sign. A DIFFERENT good basis forges perfectly well without being
 * the secret rows, so "the verifier accepted the forgeries" proves forgery
 * capability and nothing more. Saying "secret basis recovered" needs the second
 * check, which is why it is computed here rather than left in the tests.
 *
 * SAMPLE ACCOUNTING. Every rung draws N TRAINING signatures for the descent AND a
 * matching N HELD-OUT signatures the descent never sees, so a rung reported as
 * N=8000 cost the victim 16000 published signatures, not 8000. The result and
 * every rung name all three -- `trainingSignatures`, `heldOutSignatures`,
 * `totalObserved` = 2N -- and `signaturesConsumed` is kept only as the old name
 * for the training count of the rung that finished. Nothing here ever reports
 * training as if it were the total.
 */

import type { Mat, Rng, Vec } from '../lattice/types';
import { inverse, log10AbsDet, roundVec, vecMat } from '../lattice/matrix';
import type { SignFn } from '../sign/sign';
import { DEFAULT_H_RANGE, collectLeaks, randomH, signRoundOff } from '../sign/sign';
import type { PublicKey } from '../sign/verify';
import { verify } from '../sign/verify';
import { applyWhitening, covarianceShape, whiten } from './whiten';
import { mom4, sumA4FromMom4 } from './moments';
import type { RecoveryProgress } from './descent';
import { recoverDirections, restartBudget } from './descent';

/**
 * Smallest dimension this attack makes a legible demo at.
 *
 * NOT a mathematical floor -- measured over 20 keys per cell, the attack recovers
 * all n directions at every n and N tested, and the covariance estimate is
 * actually BETTER at small n (whitening deviation 0.079 at n=4 versus 0.108 at
 * n=8, both at N=500). The problem at n=4 and n=6 is that the outcome becomes a
 * coin flip nobody can interpret: n=4 succeeds 5% of the time at N=500 and 60% at
 * N=2000, same lattice, same code, a different answer each reload. And there is
 * nothing to watch -- n=4 collects its four directions in about nine restarts, so
 * the coupon-collector story has no time to happen. n=8 is the smallest size
 * where the failure mode is legible: 0% -> 70% -> 100% as N goes 2000 -> 8000 ->
 * 32000, over about 25 restarts.
 */
export const MIN_DEMO_DIM = 8;

/** Plain-language caveat for dimensions below `MIN_DEMO_DIM`, or null. */
export function dimensionCaveat(n: number): string | null {
  if (n >= MIN_DEMO_DIM) return null;
  return (
    `At n = ${n} the attack still works, but the statistics are too thin to watch: ` +
    'measured over 20 keys, n=4 recovers the basis 5% of the time at 500 signatures and ' +
    '60% at 2000, so the same code gives a different answer each run. Use n >= 8 for a ' +
    'result you can read.'
  );
}

/** One recovered direction lifted back to an integer candidate row of R. */
export interface LiftedRow {
  /** The unit direction in whitened coordinates. */
  readonly u: Vec;
  /** u * L, before rounding. */
  readonly real: Vec;
  /** round(u * L): the integer candidate. */
  readonly row: Vec;
  /** max_j |real_j - row_j|. Below 0.5 everywhere means the lift cannot be wrong. */
  readonly integralityGap: number;
}

/**
 * Lift a whitened direction back to the original coordinates: round(u * L).
 *
 * The rounding is what makes the result an integer vector and therefore a
 * plausible basis row. `integralityGap` is the honest self-check the attacker can
 * run WITHOUT the secret: if u were exactly a row direction, u*L would be exactly
 * an integer vector and the gap would be zero. Measured mean gap 0.174 for
 * round-off signatures against 0.473 for Klein -- 0.473 being what rounding pure
 * noise looks like, since a uniform fractional part averages 0.5.
 */
export function liftDirection(u: Vec, L: Mat): LiftedRow {
  const real = vecMat(u, L);
  const row = roundVec(real);
  let integralityGap = 0;
  for (let j = 0; j < real.length; j++) {
    const g = Math.abs(real[j] - row[j]);
    if (g > integralityGap) integralityGap = g;
  }
  return { u, real, row, integralityGap };
}

/** Result of the invariant I4 check. */
export interface MatchResult {
  /** How many candidates found a distinct partner row. */
  readonly matched: number;
  /** perm[c] is the row index candidate c matched, or -1. */
  readonly perm: number[];
  /** +1 if candidate c equals that row, -1 if it equals its negation, 0 if unmatched. */
  readonly signs: number[];
  /** Every row matched by a distinct candidate. */
  readonly complete: boolean;
  /** |det Rhat| / |det R|, which is exactly 1 iff Rhat is a basis of the same lattice. */
  readonly absDetRatio: number;
}

/**
 * INVARIANT I4 -- exact matching up to SIGN and PERMUTATION, and nothing weaker.
 *
 * Greedy perfect matching: candidate c matches an as-yet-unused row R_j iff
 * c[q] === R_j[q] for EVERY q, or c[q] === -R_j[q] for EVERY q. Entrywise integer
 * equality, no tolerance, no norm, no "close enough". Success requires all n
 * candidates to find distinct partners.
 *
 * USES THE SECRET. This is a scoring and display function, never a success test:
 * invariant I5 says the pass/fail decision belongs to the real verifier, and
 * `runBreak2` decides on the forgery. `runBreak2` calls this itself when it is
 * handed `groundTruthR`, and reports the verdict as `groundTruthRecovered` --
 * clearly labelled lab-only, because an attacker cannot compute it.
 *
 * Greedy is a genuine perfect matching here because the exact-equality relation
 * makes each candidate match at most one row (two distinct rows cannot both equal
 * +-c), so there is no ordering that does better.
 */
export function matchUpToSignPerm(cands: Mat, R: Mat): MatchResult {
  const n = R.length;
  const used = new Array<boolean>(n).fill(false);
  const perm = new Array<number>(cands.length).fill(-1);
  const signs = new Array<number>(cands.length).fill(0);
  let matched = 0;
  for (let c = 0; c < cands.length; c++) {
    for (let j = 0; j < n; j++) {
      if (used[j]) continue;
      let plus = true;
      let minus = true;
      for (let q = 0; q < n; q++) {
        if (cands[c][q] !== R[j][q]) plus = false;
        if (cands[c][q] !== -R[j][q]) minus = false;
        if (!plus && !minus) break;
      }
      if (plus || minus) {
        used[j] = true;
        perm[c] = j;
        signs[c] = plus ? 1 : -1;
        matched++;
        break;
      }
    }
  }
  // log10 rather than the determinants themselves: |det R| is 10^16.3 at n=8 and
  // far past 2^53 higher up, so the ratio must be formed in the exponent.
  let absDetRatio = NaN;
  if (cands.length >= n) {
    absDetRatio = Math.pow(10, log10AbsDet(cands.slice(0, n)) - log10AbsDet(R));
  }
  return { matched, perm, signs, complete: matched === n && cands.length >= n, absDetRatio };
}

/**
 * The C5' discriminators: everything below is computable by the attacker, with no
 * access to R. They are what lets the lab say "this signer is broken and that one
 * is not" without peeking.
 */
export interface Discriminators {
  /**
   * sum a^4 measured on HELD-OUT signatures, averaged over the recovered
   * directions. The headline. Measured 1.0010 for round-off against 0.0061 for
   * Klein at n=16; measured here at n=8, 0.982 to 1.023 over ten round-off keys
   * against -0.051 to 0.049 over six Klein keys. Two orders of magnitude apart,
   * with no secret anywhere in the computation.
   */
  readonly sumA4HeldOut: number;
  /** The same as a raw fourth moment. Measured 0.012492 vs 0.020782 (1/48 = 0.020833). */
  readonly mom4HeldOut: number;
  /**
   * The IN-SAMPLE fourth moment, reported only so the overfit is visible.
   * The descent optimised these directions ON this data, so the in-sample value
   * is biased downward and reads structure that is not there: at N=4000 the
   * in-sample Klein sumA4 reads 0.31, which looks like a signal. Held out it
   * collapses to zero. This is why the hold-out split is built in and not an
   * option.
   */
  readonly mom4InSample: number;
  /** In-sample sum a^4, the number that lies. */
  readonly sumA4InSample: number;
  /**
   * MEAN over the lifted rows of max_j |u*L - round(u*L)|: the second,
   * independent discriminator. Measured 0.174 for round-off against 0.473 for
   * Klein -- 0.473 being what rounding uniform noise gives, since a uniform
   * fractional part is 0.5 away from the nearest integer on average.
   *
   * The MEAN and not the maximum: a single marginal row can push the maximum to
   * 0.499 on a run that still recovers the basis perfectly (measured), so the
   * maximum does not separate the two signers at all. `worstIntegralityGap`
   * carries that number separately, where it answers a different question.
   *
   * The separation narrows at small n and should be quoted with the dimension.
   * Measured here at n=8: round-off 0.209-0.345 over ten keys against Klein
   * 0.414-0.460 over six. Still clean, but nothing like the 100x margin that
   * `sumA4HeldOut` gives, which is why that one is the headline.
   */
  readonly integralityGap: number;
  /**
   * The worst single row's gap. Below 0.5 for every row means no rounding in the
   * lift could have gone the wrong way -- a self-check on this run, not a
   * discriminator between signers.
   */
  readonly worstIntegralityGap: number;
  /** max |G/mean(diag G) - I|: a free pre-check. Measured 0.467 vs 0.0118. */
  readonly covarianceShape: number;
}

/**
 * One rung of the signature ladder.
 *
 * The three sample counts are all named, because a rung costs the victim TWICE
 * what the descent consumed: `totalObserved` = `trainingSignatures` +
 * `heldOutSignatures`, and the hold-out is drawn on every rung whether or not the
 * rung succeeds.
 */
export interface Break2Attempt {
  /**
   * The rung's training count -- the old name, identical to `trainingSignatures`
   * and kept only so existing readers (the worker's ladder message) still
   * compile. It is the TRAINING half, never the total.
   */
  readonly signatures: number;
  /** Signatures the descent trained on at this rung. Measured, not the target N. */
  readonly trainingSignatures: number;
  /** Signatures held out from the descent and used only to score it. Equal to the training count. */
  readonly heldOutSignatures: number;
  /** What the victim actually published for this rung: training + held out = 2N. */
  readonly totalObserved: number;
  /** Restarts used. */
  readonly restarts: number;
  /** Distinct directions found. */
  readonly directionsFound: number;
  /** True if the restart budget ran out before n directions were found. */
  readonly exhausted: boolean;
  /** The lifted integer candidate rows, in the order the descent found them. */
  readonly rows: LiftedRow[];
  /** Public statistics for this rung. */
  readonly discriminators: Discriminators;
  /** Fresh messages signed with Rhat and offered to the real verifier. */
  readonly forgeriesAttempted: number;
  /** How many the real verifier accepted. */
  readonly forgeriesAccepted: number;
  /** Why the forgery step could not run at all, if it could not. */
  readonly note: string;
}

export interface Break2Options {
  /** Everything the attacker legitimately knows. */
  readonly pub: PublicKey;
  /** The victim's signing oracle. Round-off or Klein -- the attack cannot tell. */
  readonly sign: SignFn;
  /** Deterministic generator, so every run is reproducible from a seed. */
  readonly rng: Rng;
  /** First rung of the ladder. Default 1000. */
  readonly startN?: number;
  /**
   * The cap. When it is exhausted without a forgery the attack REPORTS FAILURE.
   * Default 64000, which covered every one of 30 measured keys at n <= 16.
   */
  readonly capN?: number;
  /** Fresh forgeries required, all of which must verify. Default 20. */
  readonly forgeries?: number;
  /** Restart budget per rung. Default 10n. */
  readonly maxRestarts?: number;
  /** Descent step size. Default 9. */
  readonly delta?: number;
  /** Descent iteration cap. Default 250. */
  readonly maxIter?: number;
  /** Dedupe |cos| threshold. Default 0.99. */
  readonly dedupe?: number;
  /** Half-width of the hashed-message box. Default 1e4. */
  readonly hRange?: number;
  /**
   * LAB SCORING ONLY: the victim's private basis R, used once after the ladder has
   * stopped to fill in `groundTruthRecovered`. THE ATTACK PATH NEVER CONSULTS IT --
   * omitting it produces an identical run, field for field, which break2.test.ts
   * asserts.
   */
  readonly groundTruthR?: Mat;
  /** Live progress, once per restart plus once per phase change. */
  readonly onProgress?: (p: Break2Progress) => void;
}

export interface Break2Progress {
  readonly phase: 'collecting' | 'whitening' | 'descending' | 'forging';
  /**
   * Training signatures consumed so far -- the live counter. Never a constant.
   * The old name for `trainingSignatures`, and identical to it.
   */
  readonly signatures: number;
  /** Signatures observed in total, training plus hold-out. The old name for `totalObserved`. */
  readonly observed: number;
  /** Signatures the descent has trained on so far. */
  readonly trainingSignatures: number;
  /** Signatures drawn and withheld from the descent so far. */
  readonly heldOutSignatures: number;
  /** Everything the victim has published so far: training + held out. Twice the counter. */
  readonly totalObserved: number;
  readonly restarts: number;
  readonly directionsFound: number;
  readonly target: number;
}

export interface Break2Result {
  /**
   * True only if the REAL verifier accepted every forgery. UNCHANGED MEANING:
   * this is the forgery verdict, exactly as before, and it is always identical to
   * `forgeryOk`. It is NOT a claim that the secret rows were recovered -- that is
   * `groundTruthRecovered`, and the two are independent.
   */
  readonly ok: boolean;
  /**
   * OUTCOME 1, ATTACKER-OBSERVABLE. The public verifier -- which knows only B and
   * the published bound -- accepted all `forgeries` fresh signatures made with the
   * candidate. Computable by anyone watching the wire. Same value as `ok`; the
   * explicit name exists so the UI never has to guess which question `ok` answered.
   */
  readonly forgeryOk: boolean;
  /**
   * OUTCOME 2, LAB-ONLY GROUND TRUTH. `matchUpToSignPerm(Rhat, groundTruthR)` came
   * back complete: the candidate IS the private rows up to sign and permutation.
   *
   * AN ATTACKER CANNOT COMPUTE THIS -- it reads the secret basis -- and it never
   * gates the attack: the ladder stops on the forgery, and this is scored
   * afterwards. `null` means no `groundTruthR` was supplied, so the lab did not
   * score it; that is NOT the same as `false`. `false` with a non-null `Rhat`
   * means a basis that may still forge is not the secret rows, which is exactly
   * what plain LLL on the public basis produces (see the header measurement).
   */
  readonly groundTruthRecovered: boolean | null;
  /**
   * The full lab-only matching behind `groundTruthRecovered` -- how many rows
   * matched, which permutation, which signs -- or null when there was nothing to
   * score (no `groundTruthR`, or no candidate basis at all).
   */
  readonly groundTruthMatch: MatchResult | null;
  /** What happened, in one sentence. Reports the FORGERY outcome only, never ground truth. */
  readonly reason: string;
  /**
   * The old name for `trainingSignatures`, kept so existing readers compile: the
   * TRAINING signatures of the rung that finished (the successful one, or the last
   * one tried). It has never included the hold-out, so it is HALF of what the
   * victim published -- use `totalObserved` for that.
   */
  readonly signaturesConsumed: number;
  /** Signatures the descent trained on at the reported rung. */
  readonly trainingSignatures: number;
  /** Signatures withheld from the descent and used only to score it. Equal to the training count. */
  readonly heldOutSignatures: number;
  /** Everything the victim published: training + held out = 2 * trainingSignatures. */
  readonly totalObserved: number;
  /** The old name for `totalObserved`, kept so existing readers compile. Same number. */
  readonly totalSignaturesObserved: number;
  /** Every rung of the ladder, so the cost curve can be displayed. */
  readonly attempts: Break2Attempt[];
  /**
   * The candidate basis assembled from the last rung's recovered rows: n integer
   * rows that are, when the attack worked, the rows of R up to sign and
   * permutation. Null when the descent never found n directions or the lifted
   * rows were singular.
   *
   * NON-NULL IS NOT SUCCESS. A candidate exists on every rung that finished the
   * descent, including the ones that recovered garbage. `forgeryOk` (== `ok`) is
   * the verifier's verdict on it, and `groundTruthRecovered` is the lab's separate
   * verdict on whether it is really R. Neither is implied by this field being
   * non-null, and neither implies the other.
   */
  readonly Rhat: Mat | null;
  /** The lifted rows of the last rung. */
  readonly rows: LiftedRow[];
  /** Public statistics of the last rung. */
  readonly discriminators: Discriminators;
  /** The cap that was in force. */
  readonly capN: number;
}

/** Mean of a list, or NaN when empty. */
function mean(xs: number[]): number {
  if (xs.length === 0) return NaN;
  let s = 0;
  for (const x of xs) s += x;
  return s / xs.length;
}

/**
 * Run the whole attack against a signing oracle.
 *
 * Climbs a doubling ladder of signature counts and stops at the first rung whose
 * recovered basis produces forgeries the REAL verifier accepts. Every rung draws
 * a matching HOLD-OUT set that the descent never sees, and scores the fourth
 * moment on it -- built in, not optional, because the in-sample number overfits
 * and reads structure where there is none.
 *
 * On exceeding the cap it returns `ok: false` with the ladder it climbed and the
 * statistics it measured. It never reports a success it did not verify.
 *
 * TWO VERDICTS, ONE OF WHICH THE ATTACKER CANNOT REACH. The ladder is driven by
 * the forgery and nothing else. If `groundTruthR` is supplied, the secret is read
 * exactly once, after the ladder has already stopped, to score the candidate that
 * the verifier had already judged; every other number in the result is computed
 * before that line runs and cannot depend on it.
 */
export function runBreak2(opts: Break2Options): Break2Result {
  const { pub, sign, rng } = opts;
  const n = pub.n;
  const capN = opts.capN ?? 64000;
  const startN = Math.min(opts.startN ?? 1000, capN);
  const forgeries = opts.forgeries ?? 20;
  const hRange = opts.hRange ?? DEFAULT_H_RANGE;
  const maxRestarts = opts.maxRestarts ?? restartBudget(n);
  const report = opts.onProgress;

  // A mis-shaped ground truth would match nothing and the lab would render "not
  // the secret rows" for what is really a caller mistake, so it fails loudly
  // instead. Nothing about the attack depends on this argument.
  const groundTruthR = opts.groundTruthR;
  if (groundTruthR !== undefined) {
    const shaped = groundTruthR.length === n && groundTruthR.every((r) => r.length === n);
    if (!shaped) {
      throw new Error(
        `groundTruthR must be the ${n}x${n} private basis, and it is ` +
          `${groundTruthR.length}x${groundTruthR[0]?.length ?? 0}. Scoring against the wrong ` +
          'shape would report "not recovered" for every candidate, which reads as a failed ' +
          'attack rather than a lab mistake.',
      );
    }
  }

  // Both sets grow across rungs rather than being redrawn, so the ladder costs
  // 2*capN signatures in total and not the sum of every rung.
  const train: Mat = [];
  const held: Mat = [];
  const attempts: Break2Attempt[] = [];

  let N = startN;
  for (;;) {
    const tick = (
      phase: Break2Progress['phase'],
      restarts: number,
      directionsFound: number,
    ): void => {
      report?.({
        phase,
        signatures: train.length,
        observed: train.length + held.length,
        trainingSignatures: train.length,
        heldOutSignatures: held.length,
        totalObserved: train.length + held.length,
        restarts,
        directionsFound,
        target: n,
      });
    };

    // Spread-push would pass tens of thousands of arguments and overflow the
    // stack at the shipped sample counts, so extend the arrays by loop.
    for (const set of [train, held]) {
      while (set.length < N) {
        const batch = collectLeaks(N - set.length, n, rng, sign, hRange);
        for (const v of batch) set.push(v);
      }
    }
    tick('collecting', 0, 0);

    tick('whitening', 0, 0);
    const wh = whiten(train, n);
    // The hold-out is whitened with the TRAINING transform. Re-fitting on the
    // hold-out would leak the hold-out back into the estimate and undo the split.
    const heldW = applyWhitening(held, wh.Linv);

    const rec = recoverDirections(wh.W, N, n, rng, {
      delta: opts.delta,
      maxIter: opts.maxIter,
      dedupe: opts.dedupe,
      maxRestarts,
      onRestart: (p: RecoveryProgress) => tick('descending', p.restarts, p.found),
    });

    const rows = rec.dirs.map((u) => liftDirection(u, wh.L));
    const inSample = rec.dirs.map((u) => mom4(wh.W, N, n, u));
    const heldOut = rec.dirs.map((u) => mom4(heldW, held.length, n, u));
    const mom4HeldOut = mean(heldOut);
    const mom4InSample = mean(inSample);
    const discriminators: Discriminators = {
      sumA4HeldOut: sumA4FromMom4(mom4HeldOut),
      mom4HeldOut,
      mom4InSample,
      sumA4InSample: sumA4FromMom4(mom4InSample),
      integralityGap: mean(rows.map((r) => r.integralityGap)),
      worstIntegralityGap: rows.reduce((m, r) => Math.max(m, r.integralityGap), 0),
      covarianceShape: covarianceShape(wh.G),
    };

    // I5: assemble Rhat, sign FRESH messages with it, and let the real verifier
    // -- which knows only B and the published bound -- decide.
    let accepted = 0;
    let note = '';
    let Rhat: Mat | null = null;
    if (rec.dirs.length < n) {
      note = `restart budget ${maxRestarts} exhausted with ${rec.dirs.length}/${n} directions`;
    } else {
      tick('forging', rec.restarts, rec.dirs.length);
      const candidate = rows.slice(0, n).map((r) => Float64Array.from(r.row));
      try {
        const candidateInv = inverse(candidate);
        for (let t = 0; t < forgeries; t++) {
          const h = randomH(n, rng, hRange);
          if (verify(pub, h, signRoundOff(h, candidate, candidateInv)).ok) accepted++;
        }
        Rhat = candidate;
      } catch {
        // A singular candidate is a failed recovery, not an exception: the lifted
        // rows simply were not a basis.
        note = 'the lifted candidate rows are singular, so they are not a basis';
      }
    }

    attempts.push({
      // Measured off the sample arrays rather than off N, so the compat alias and
      // the three explicit counts can never drift apart from what was drawn.
      signatures: train.length,
      trainingSignatures: train.length,
      heldOutSignatures: held.length,
      totalObserved: train.length + held.length,
      restarts: rec.restarts,
      directionsFound: rec.dirs.length,
      exhausted: rec.exhausted,
      rows,
      discriminators,
      forgeriesAttempted: Rhat === null ? 0 : forgeries,
      forgeriesAccepted: accepted,
      note,
    });

    // OUTCOME 1. The verifier's verdict, and the only thing that drives the
    // ladder. `ok` keeps this exact meaning; `forgeryOk` is the same number under
    // a name that says which question it answered.
    const forgeryOk = Rhat !== null && accepted === forgeries && forgeries > 0;
    const ok = forgeryOk;
    const last = N >= capN;
    if (ok || last) {
      // OUTCOME 2, and the ONLY line in this function that touches the secret. It
      // runs after the ladder has already stopped, so it cannot influence the
      // attack; drop `groundTruthR` and every other field is unchanged.
      const groundTruthMatch =
        groundTruthR !== undefined && Rhat !== null ? matchUpToSignPerm(Rhat, groundTruthR) : null;
      // null = the lab was not asked to score it, which is NOT the same as false.
      // With a ground truth supplied but no candidate at all, false is the honest
      // answer and not a shortcut: R is a nonsingular n x n basis, so an
      // incomplete or singular candidate cannot be it up to sign and permutation.
      const groundTruthRecovered =
        groundTruthR === undefined ? null : groundTruthMatch !== null && groundTruthMatch.complete;

      const totalObserved = train.length + held.length;
      const sampleCounts =
        `${train.length} training + ${held.length} held out = ${totalObserved} oracle ` +
        'signatures observed';
      return {
        ok,
        forgeryOk,
        groundTruthRecovered,
        groundTruthMatch,
        // Attacker-observable only: the forgery verdict and the sample counts.
        // Whether the candidate is really R is deliberately absent, which is what
        // keeps this string identical with and without a ground truth.
        reason: ok
          ? `the real verifier accepted ${accepted}/${forgeries} fresh forgeries signed with a ` +
            `candidate basis built from ${train.length} training signatures (${sampleCounts}); ` +
            'that is forgery capability, which is a separate question from whether the candidate ' +
            'is the secret basis'
          : `no forgery was accepted within the cap of ${capN} signatures per rung ` +
            `(${sampleCounts})` +
            (note ? `; last rung: ${note}` : `; last rung forged ${accepted}/${forgeries}`),
        signaturesConsumed: train.length,
        trainingSignatures: train.length,
        heldOutSignatures: held.length,
        totalObserved,
        totalSignaturesObserved: totalObserved,
        attempts,
        Rhat,
        rows,
        discriminators,
        capN,
      };
    }
    N = Math.min(N * 2, capN);
  }
}
