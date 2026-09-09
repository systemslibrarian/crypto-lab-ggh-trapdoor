/**
 * THE PUBLIC-LLL BASELINE -- the attack this lab was missing.
 *
 * Break 1 (break1.ts) and Break 2 (break2.ts) each attack a SHAPE: the error's
 * congruence mod 2*sigma, and the parallelepiped's fourth moment. Neither one
 * attacks the lattice itself. This file does the dull thing that was never
 * written down here: it hands the PUBLIC basis to the textbook 1982 reduction
 * already in this repo (lll.ts) and reports exactly what comes back.
 *
 * WHAT COMES BACK IS THE PRIVATE BASIS. Measured over 12 seeded keys at each
 * dimension, and committed as a regression in baseline.test.ts:
 *
 *   n     LLL(B) rows == R      decrypts    worst-case I2      median LLL
 *         (sign & permutation)              of LLL(B)          time
 *   8         12 / 12            60 / 60     0.1172 - 0.1315    0.044 ms
 *   16        12 / 12            60 / 60     0.1156 - 0.1403    0.089 ms
 *   32        12 / 12            60 / 60     0.1133 - 0.1243    0.81 ms
 *   60        12 / 12            60 / 60     0.1177 - 0.1244    6.2 ms
 *
 * 48 keys of 48, entry for entry, with no secret input. "Decrypts" means five
 * fresh ciphertexts per key pushed through the REAL round-off decryptor and the
 * REAL re-encryption check -- no comparison with the hidden message anywhere.
 * The times are Node 24 on the development machine; the same reductions were
 * measured at 10 / 12 / 67 / 246 ms in the browser, which is the figure the UI
 * has to live with. The worst-case I2 bound of the reduced basis comes out
 * identical to the private basis's own (0.113-0.140 against R's 0.110-0.137)
 * because it IS the private basis, so decryption through it is not merely
 * observed to work: it is guaranteed for every error in {+-3}^n.
 *
 * SO AT THESE DIMENSIONS THE PUBLIC KEY HIDES NOTHING FROM ORDINARY LATTICE
 * REDUCTION. That is not a defect to bury, it is the missing half of the lesson.
 * LLL's approximation factor is exponential in n, which is exactly why GGH was
 * proposed at n = 200-400 (CRYPTO '97, section 5) and why Nguyen's congruence
 * attack and the parallelepiped attack were worth inventing at all: at challenge
 * dimensions plain reduction does not do this. At the dimensions a browser can
 * teach at, the gap has not opened yet, and a lab that shows the two historical
 * breaks without showing this one lets a newcomer leave believing the toy key
 * was secure against everything else. It was not.
 *
 * WHAT IT DOES NOT SAY. It does not falsify the lab's headline. Raw Babai
 * round-off with B really does fail: measured on the same keys, raw B decrypted
 * 2 of 30 ciphertexts at n=8 and 0 of 30 at n = 16, 32 and 60, while the reduced
 * basis decrypted 30 of 30 at every dimension. (The two at n=8 are real -- B's
 * worst-case bound there is only 1.76-6.40, so a lucky error vector occasionally
 * lands inside the box. Raw-B failure is a rate at n=8, not a law.) What changes
 * is the SCOPE of the sentence: "B is a bad basis to round off with", not "B
 * keeps R secret".
 *
 * IT IS NOT AN ARTEFACT OF THIS LAB'S RAISED k EITHER. keygen.ts uses
 * k = ceil(2*l*sqrt(n)) + 4*l instead of GGH's own k = l*ceil(sqrt(n)) to buy a
 * decryption guarantee, and that makes R more orthogonal -- so the honest worry
 * is that the raised k is what puts R inside LLL's reach. Measured under
 * `paperK(n)`, 8 keys per dimension: exact row recovery is 8/8 at n=60, 7/8 at
 * n=32 and 0/8 at n = 8 and 16. The exact-match RATE does move with k. The
 * conclusion does not: at n = 8 and 16 LLL returns a DIFFERENT basis that is at
 * least as useful, decrypting 26/40 and 26/40 of the same ciphertexts against the
 * genuine private basis's own 23/40 and 26/40 -- at n=8 the attacker's free basis
 * is strictly BETTER than the secret key -- with a worst-case I2 bound at most
 * 1.20x the private basis's. Both sides are far below 100% there only because at
 * paperK the private basis violates I2 itself (bound 0.65-2.73, never under 0.5).
 * The trapdoor is worth nothing at these dimensions under either parameter rule.
 * (Both readings of GGH section 5.2's k were measured -- round(l*sqrt(n)) and the
 * literal l*ceil(sqrt(n)) that `paperK` now implements. They differ only at n=32,
 * 4/8 against 7/8; see baseline.test.ts.)
 *
 * ATTACKER-COMPUTABLE VERSUS LAB-ONLY (invariant I5). The success verdict `ok`
 * rests only on things a real attacker holds -- B, the ciphertext, the reduction,
 * the public re-encryption check. `worstCaseBound` and `guaranteed` are likewise
 * computed from the reduced basis alone. `matchesSecret` and `matchedRows` read
 * R and are LAB-ONLY GROUND TRUTH: they are reported beside the attacker-side
 * verdict, never as it, exactly as break2.ts separates forgery from recovery.
 *
 * ROW CONVENTION: rows of B are the lattice vectors, c = m*B + e.
 */

import type { GghKey, Mat, Rng } from '../lattice/types';
import { inverse, log10OrthogonalityDefect } from '../lattice/matrix';
import { SIGMA } from '../lattice/keygen';
import {
  encrypt,
  latticePointToMessage,
  randomMessage,
  reEncryptionCheck,
  roundOff,
  worstCaseBound,
} from '../lattice/roundoff';
import type { LllFailure, LllProgress } from './lll';
import { lllReduce } from './lll';
import { matchUpToSignPerm } from './break2';

/**
 * Wall clock. `performance.now` where the host has it -- a worker and a Node test
 * both do -- and `Date.now` otherwise. Its 1 ms resolution is coarse against a
 * 0.044 ms reduction at n=8, which is why the tests assert a median rather than a
 * single run.
 */
const now: () => number =
  typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? () => performance.now()
    : () => Date.now();

export interface PublicLllBaselineOptions {
  /** Deterministic generator for the trial ciphertexts, so a run is reproducible. */
  readonly rng: Rng;
  /**
   * Fresh ciphertexts to push through the reduced basis. Default 5.
   *
   * Each one costs a vector-matrix product, not a reduction, so this is cheap;
   * it is an option so the UI can keep an n=60 run inside its frame budget.
   * Zero is legal and means "reduce and measure the basis, decrypt nothing".
   */
  readonly ciphertexts?: number;
  /** Error magnitude. Default 3, the GGH challenge value. */
  readonly sigma?: number;
  /** LLL reduction parameter. Default 0.99. */
  readonly delta?: number;
  /** LLL iteration cap, so a worker can bound the work. Exceeding it is reported. */
  readonly maxIters?: number;
  /** LLL progress callback, so a worker can post progress. */
  readonly onProgress?: (p: LllProgress) => void;
  /** Reuse an already-computed B^-1; the UI already has one. */
  readonly Binv?: Mat;
}

export interface PublicLllBaselineResult {
  /**
   * The attacker-side verdict: the reduction completed inside its guards AND
   * every ciphertext it was given decrypted and passed re-encryption. Never
   * depends on `matchesSecret` -- a verdict that read the private basis would not
   * be an attack result (invariant I5). With `ciphertexts: 0` there is nothing to
   * decrypt, so it reports the reduction alone; read it with `attempted`.
   */
  readonly ok: boolean;
  /** Non-null means the reduction did not complete; `basis` must not be trusted blindly. */
  readonly failure: LllFailure | null;
  /** LLL(B). At the shipped parameters, measured to be R up to sign and permutation. */
  readonly reducedBasis: Mat;
  /** Unimodular H with H * B === reducedBasis, exactly. */
  readonly transform: Mat;
  /**
   * LAB-ONLY GROUND TRUTH. Every row equals a distinct row of R, or its negation,
   * entry for entry. An attacker cannot run this check: it reads the secret. It
   * is here so the page can say "and these really are the secret rows" without
   * pretending that claim came from the attack.
   */
  readonly matchesSecret: boolean;
  /** LAB-ONLY GROUND TRUTH: how many rows matched, so a partial hit is visible. */
  readonly matchedRows: number;
  /**
   * worstCaseBound(inverse(reducedBasis)) -- the I2 quantity maximised over every
   * error in {+-sigma}^n. Attacker-computable: no secret enters it. Infinity when
   * the exact-integer guard refused the basis, so no bound may be claimed.
   */
  readonly worstCaseBound: number;
  /** worstCaseBound < 0.5: decryption through this basis provably cannot fail. */
  readonly guaranteed: boolean;
  /** Ciphertexts recovered and confirmed by the public re-encryption check. */
  readonly decrypted: number;
  /** Ciphertexts tried. Zero when the exact-integer guard refused the input. */
  readonly attempted: number;
  /** Milliseconds inside lllReduce only -- the attacker's actual cost. */
  readonly ms: number;
  /** Largest absolute integer LLL touched. Measured 2.4e3-7.0e3 against 2^53. */
  readonly guardMax: number;
  /** Swaps performed, the honest measure of how much work the reduction did. */
  readonly swaps: number;
  /** Main-loop iterations performed. */
  readonly iters: number;
  /**
   * log10 of the orthogonality defect of the reduced basis, so the UI can put one
   * number beside R and B. Measured 0.039-0.080 at n=8 rising to 0.770-0.865 at
   * n=60 -- the private basis's range, against ~69 for the public basis at n=60.
   * NaN when the exact-integer guard refused the basis.
   */
  readonly log10DefectReduced: number;
}

/**
 * Run the baseline: reduce the public basis, then try to use the result as a
 * decryption key.
 *
 * Nothing here reads `key.R` except the final ground-truth match, and nothing the
 * verdict depends on reads it at all. The decryption trial is the same round-off
 * the honest owner runs, with the reduced public basis substituted for the
 * private one, and every recovery is confirmed by `reEncryptionCheck` rather than
 * by comparing with the message that was encrypted.
 */
export function runPublicLllBaseline(
  key: GghKey,
  opts: PublicLllBaselineOptions,
): PublicLllBaselineResult {
  const sigma = opts.sigma ?? SIGMA;
  const trials = opts.ciphertexts ?? 5;

  const t0 = now();
  const red = lllReduce(key.B, {
    delta: opts.delta,
    maxIters: opts.maxIters,
    onProgress: opts.onProgress,
  });
  const ms = now() - t0;

  // An `integer-overflow` failure means the entries stopped being exact integers,
  // so every number downstream would be meaningless -- inverting that basis and
  // reporting a bound would be inventing a result. An `iteration-cap` failure is
  // different: the partial basis is still a valid basis of the same lattice, just
  // not fully reduced, and running the trial on it shows the learner what a
  // half-finished reduction actually buys (measured: nothing).
  const usable = red.failure === null || red.failure.kind !== 'integer-overflow';

  let decrypted = 0;
  let attempted = 0;
  let bound = Infinity;
  let defect = NaN;

  if (usable) {
    const reducedInv = inverse(red.basis);
    bound = worstCaseBound(reducedInv, sigma);
    defect = log10OrthogonalityDefect(red.basis);
    const Binv = opts.Binv ?? inverse(key.B);

    for (let t = 0; t < trials; t++) {
      const m = randomMessage(key.n, opts.rng);
      const ct = encrypt(m, key.B, opts.rng, sigma);
      // Babai round-off with the REDUCED basis, then the message read off in
      // public-basis coordinates: the legitimate decryptor, one substitution.
      const candidate = latticePointToMessage(roundOff(ct.c, red.basis, reducedInv), Binv);
      attempted++;
      if (reEncryptionCheck(ct.c, candidate, key.B, sigma).ok) decrypted++;
    }
  }

  // Last, and deliberately separate: the check only the lab can run.
  const match = matchUpToSignPerm(red.basis, key.R);

  return {
    ok: red.failure === null && decrypted === attempted,
    failure: red.failure,
    reducedBasis: red.basis,
    transform: red.transform,
    matchesSecret: match.complete,
    matchedRows: match.matched,
    worstCaseBound: bound,
    guaranteed: bound < 0.5,
    decrypted,
    attempted,
    ms,
    guardMax: red.guardMax,
    swaps: red.swaps,
    iters: red.iters,
    log10DefectReduced: defect,
  };
}
