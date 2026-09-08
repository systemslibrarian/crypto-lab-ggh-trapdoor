/**
 * Break 1 -- Nguyen's cryptanalysis of GGH (CRYPTO '99), as a stepper.
 *
 * The attack in one line: GGH's error vector is too regular. Every entry is
 * +-sigma, so modulo 2*sigma the entire error is the known constant
 * sigma*(1,...,1), and the ciphertext leaks m mod 2*sigma by exact linear algebra
 * -- no lattice reduction, no guessing. What is left after subtracting that
 * residue is a CVP whose error lies in {0,-1}^n, which LLL finishes instantly at
 * every dimension this lab offers. The attack never touches the private basis and
 * never solves a hard lattice problem; it attacks the SHAPE of the error.
 *
 * Six steps, each surfaced as one `Break1Step`:
 *   1. mod6     m0 = m mod 6, from  m0*B = c + sigma*1 (mod 6)   [mod6.ts]
 *   2. divide   cpp = (c - m0*B - sigma*1) / 6, exactly           [here]
 *   3. embed    residual CVP -> SVP, then LLL                     [embedding.ts]
 *   4. readoff  the {+1,-1} pattern and mp, off the LLL transform [embedding.ts]
 *   5. recover  m = m0 + 6*mp
 *   6. verify   re-encryption check (invariant I5)                [roundoff.ts]
 *
 * VERIFICATION IS NEVER A COMPARISON WITH THE SECRET. Step 6 calls
 * `reEncryptionCheck` from roundoff.ts: it recomputes c - m*B and demands every
 * entry be +-sigma. That is a check a real attacker can run with the public key
 * alone, which is what invariant I5 requires. Nothing in this file reads the true
 * m, the private basis, or the error that was actually used.
 *
 * ---------------------------------------------------------------------------
 * THE NEGATIVE CASE (claim C4) DOES NOT FAIL WHERE THE BRIEF PREDICTED.
 *
 * The brief expected that with a non-congruent error (entries uniform in
 * {-3..3} instead of {+-3}) the division by 6 in step 2 would come out
 * non-integer. IT NEVER DOES. Measured over 1120 trials at n = 8, 12, 16, 24, 32,
 * 48, 60:
 *
 *     exact division by 6 succeeded:  1120 / 1120   (100.0%)
 *     mod-6 solve returned a WRONG m0: 1120 / 1120  (100.0%)
 *
 * This is forced, not luck. m0 is BY CONSTRUCTION the solution of
 * m0*B = c + sigma*1 (mod 6), so c - m0*B - sigma*1 is identically 0 mod 6 and
 * the division is exact whatever c was -- including a c that is not a legal
 * ciphertext at all. What actually breaks is that (e_i - sigma) mod 6 is zero
 * only for e_i in {+-3}; the other five values inject a perturbation g, the solve
 * returns m + g*B^-1 (mod 6), and that is wrong in ~83% of its coordinates
 * (mean 13.1 wrong of 16 at n=16). cpp is then an integer vector far from L(B)
 * and the embedding has no planted short vector to find.
 *
 * So: DO NOT build a UI that shows "the division came out non-integer" as the
 * failure evidence -- it would display nothing, ever. The exactness assertion is
 * kept because it is a real internal invariant (a violation would mean a bug in
 * the mod-6 solve), but it is not the evidence. The three observables that DO
 * discriminate, all attacker-side, all measured:
 *
 *   a. shortest reduced row norm vs sqrt(n+1). On an honest ciphertext LLL
 *      returns a row of length EXACTLY sqrt(n+1) -- median == max over 120 runs
 *      at n = 8, 16, 32, 60 -- because (-f,-t) with f in {+1,-1}^n IS the shortest
 *      vector of the embedding. Tampered, it is 3-4x larger and never came within
 *      3x of sqrt(n+1) in 1120 trials. Zero overlap between the two populations.
 *   b. the {+1,-1} pattern check: 240/240 hits on honest ciphertexts,
 *      0/1120 false positives on tampered ones.
 *   c. the re-encryption check: 240/240 honest, 0/1120 tampered.
 *
 * Reproduced against THIS implementation, 25 tampered ciphertexts at each of
 * n = 8, 16, 32, 60 (100 in all): division exact 100/100, m0 correct 0/100,
 * pattern matched 0/100, re-encryption passed 0/100. The closest a tampered
 * shortest row ever came to sqrt(n+1) was 3.46x, 3.11x, 3.50x, 3.56x by
 * dimension, against exactly 1.000x on every one of the 60 honest runs.
 *
 * All three are on `Break1Observables`, and the stepper deliberately runs steps
 * 5 and 6 even when step 4 found no pattern match -- a real attacker takes LLL's
 * best answer and lets the verifier reject it, and a page that shows the answer
 * being rejected teaches more than one that shows nothing.
 *
 * The sharpest framing measured: with e in {+-3}^n except on ONE coordinate out of
 * sixteen, the attack fails completely and 11.5 of 16 message coordinates come out
 * wrong. The failure is a cliff, not a slope, and it is non-local -- multiplying
 * by B^-1 mod 6 smears a single-coordinate defect across the whole vector. The
 * attack does not need the error to be SMALL; it needs the error to be CONGRUENT.
 */

import type { Mat, Vec } from '../lattice/types';
import { SIGMA } from '../lattice/keygen';
import { vecMat } from '../lattice/matrix';
import { reEncryptionCheck } from '../lattice/roundoff';
import { congruenceRhs, solveMod6, type Mod6Singularity } from './mod6';
import {
  solveByEmbedding,
  type EmbeddingCandidate,
  type EmbeddingForm,
  type EmbeddingOptions,
  type EmbeddingResult,
} from './embedding';
import type { LllFailure, LllProgress } from './lll';

/** The six steps, in order. */
export type Break1StepKind = 'mod6' | 'divide' | 'embed' | 'readoff' | 'recover' | 'verify';

/** Step 1: solve the congruence m0*B = c + sigma*1 (mod 2*sigma). */
export interface Break1Mod6Step {
  readonly kind: 'mod6';
  readonly ok: boolean;
  /** Nguyen's right-hand side, reduced mod 2*sigma. */
  readonly rhs: Vec;
  /** m mod 2*sigma, in {0..2*sigma-1}^n. */
  readonly m0: Vec | null;
  /** Which modulus was singular, when it was (invariant I3). */
  readonly singular: Mod6Singularity | null;
  readonly note: string;
}

/** Step 2: exact integer division by 2*sigma. */
export interface Break1DivideStep {
  readonly kind: 'divide';
  readonly ok: boolean;
  /** c - m0*B - sigma*1, before dividing. */
  readonly numerator: Vec;
  /** First coordinate that was not a multiple of 2*sigma, or -1. Measured: always -1. */
  readonly firstInexactIndex: number;
  /** The residual CVP target cpp = numerator / (2*sigma). */
  readonly cpp: Vec | null;
  readonly note: string;
}

/** Step 3: build the embedding and reduce it. */
export interface Break1EmbedStep {
  readonly kind: 'embed';
  readonly ok: boolean;
  readonly form: EmbeddingForm;
  /** Whether the target was pulled into the fundamental region of B first. */
  readonly targetReduced: boolean;
  readonly targetMaxAbsBefore: number;
  readonly targetMaxAbsAfter: number;
  readonly embedMaxAbs: number;
  readonly gramMaxAbs: number;
  readonly lllSwaps: number;
  readonly lllIters: number;
  /** Largest integer LLL touched, against the 2^53 limit. */
  readonly guardMax: number;
  readonly failure: LllFailure | null;
  readonly note: string;
}

/** Step 4: read the error pattern and the message coefficients off the reduced basis. */
export interface Break1ReadOffStep {
  readonly kind: 'readoff';
  readonly ok: boolean;
  /** Shortest row norm LLL produced. */
  readonly minRowNorm: number;
  /** sqrt(n + t^2) for the centered form -- what an honest ciphertext gives exactly. */
  readonly expectedMinRowNorm: number;
  /** minRowNorm / expected. 1.000 honest, 3-4 tampered. */
  readonly normRatio: number;
  /** The candidate row's head: {+1,-1}^n on a hit. */
  readonly head: Vec | null;
  /** The residual error implied by that row: {0,-1}^n on a hit. */
  readonly ep: Vec | null;
  /** Number of rows that decomposed the target exactly. */
  readonly exactCandidates: number;
  readonly note: string;
}

/** Step 5: m = m0 + 2*sigma*mp. */
export interface Break1RecoverStep {
  readonly kind: 'recover';
  readonly ok: boolean;
  /** The message this candidate implies. Not yet verified. */
  readonly m: Vec | null;
  /** mp, the quotient coefficients. */
  readonly mp: Vec | null;
  /** How many candidate messages are queued for verification. */
  readonly candidates: number;
  readonly note: string;
}

/** Step 6: invariant I5 -- re-encrypt and check the residual is a legal error. */
export interface Break1VerifyStep {
  readonly kind: 'verify';
  readonly ok: boolean;
  readonly m: Vec | null;
  /** c - m*B. Must be in {+sigma,-sigma}^n. */
  readonly residual: Vec | null;
  /** How many candidates were tried before this verdict. */
  readonly tried: number;
  readonly note: string;
}

export type Break1Step =
  | Break1Mod6Step
  | Break1DivideStep
  | Break1EmbedStep
  | Break1ReadOffStep
  | Break1RecoverStep
  | Break1VerifyStep;

/** The numbers the UI shows, especially when the attack fails. */
export interface Break1Observables {
  /** m mod 2*sigma. Correct in 240/240 honest runs, wrong in 1120/1120 tampered ones. */
  readonly m0: Vec | null;
  /** Always true in 1120/1120 tampered trials -- kept as an internal invariant, not as evidence. */
  readonly divisionExact: boolean;
  /** Shortest reduced row norm, NaN before step 3 runs. */
  readonly minRowNorm: number;
  /** sqrt(n+1) for the centered form. */
  readonly expectedMinRowNorm: number;
  /** minRowNorm / expected: 1.000 honest, 3-4 tampered, zero overlap in 1120 trials. */
  readonly normRatio: number;
  /** Some reduced row matched the {+1,-1} pattern. 0/1120 false positives. */
  readonly patternOk: boolean;
  /** The re-encryption check passed. 240/240 honest, 0/1120 tampered. */
  readonly reEncryptionOk: boolean;
}

export interface Break1Result {
  /** The only claim that counts: re-encryption succeeded (invariant I5). */
  readonly verified: boolean;
  /** The recovered message, if verification passed. */
  readonly m: Vec | null;
  /** Every step emitted, in order. */
  readonly steps: readonly Break1Step[];
  /** The first step that reported ok === false, or null. */
  readonly failedAt: Break1StepKind | null;
  readonly reason: string;
  readonly observables: Break1Observables;
}

export interface Break1Options {
  /** Error magnitude. 2*sigma is the modulus of the congruence. Default 3. */
  sigma?: number;
  /** Which embedding. Default 'centered' -- see embedding.ts for the measurement. */
  form?: EmbeddingForm;
  /** Embedding coordinate, default 1. */
  t?: number;
  /** LLL reduction parameter. */
  delta?: number;
  /** LLL iteration cap, so a worker can bound the work. */
  maxIters?: number;
  /** LLL progress callback, so a worker can post progress. */
  onProgress?: (p: LllProgress) => void;
  /** Reuse an already-computed B^-1 for the target reduction. */
  Binv?: Mat;
  /** Pull the residual target into the fundamental region of B first. Default true. */
  reduceTarget?: boolean;
}

type Phase = Break1StepKind | 'done';

/**
 * Break 1 as a stepper, so the UI can advance one step at a time and show what
 * each one produced.
 *
 * `next()` returns the next step or null when the attack has finished. Steps 1-3
 * are hard stops: a singular B, an inexact division or an LLL failure leaves
 * nothing to continue with. Steps 4-6 always run once step 3 succeeded, even when
 * step 4 finds no pattern match, because a rejected answer is the evidence the
 * negative case needs.
 */
export class Break1Stepper {
  private readonly c: Vec;
  private readonly B: Mat;
  private readonly sigma: number;
  private readonly twoSigma: number;
  private readonly opts: Break1Options;
  private readonly emitted: Break1Step[] = [];

  private phase: Phase = 'mod6';
  private m0: Vec | null = null;
  private cpp: Vec | null = null;
  private divisionExact = false;
  private emb: EmbeddingResult | null = null;
  private queue: EmbeddingCandidate[] = [];
  private messages: Vec[] = [];
  private minRowNorm = NaN;
  private expectedMinRowNorm = NaN;
  private patternOk = false;
  private reEncryptionOk = false;
  private mFinal: Vec | null = null;
  private failedAt: Break1StepKind | null = null;
  private reason = 'attack has not finished';

  constructor(c: Vec, B: Mat, opts: Break1Options = {}) {
    this.c = c;
    this.B = B;
    this.sigma = opts.sigma ?? SIGMA;
    this.twoSigma = 2 * this.sigma;
    this.opts = opts;
  }

  /** True once `next()` has returned null. */
  get done(): boolean {
    return this.phase === 'done';
  }

  /** The steps emitted so far. */
  get steps(): readonly Break1Step[] {
    return this.emitted;
  }

  /** Advance one step. Returns null when there is nothing left to do. */
  next(): Break1Step | null {
    switch (this.phase) {
      case 'mod6':
        return this.emit(this.stepMod6());
      case 'divide':
        return this.emit(this.stepDivide());
      case 'embed':
        return this.emit(this.stepEmbed());
      case 'readoff':
        return this.emit(this.stepReadOff());
      case 'recover':
        return this.emit(this.stepRecover());
      case 'verify':
        return this.emit(this.stepVerify());
      case 'done':
        return null;
    }
  }

  /** Run every remaining step and return the whole result. */
  run(): Break1Result {
    while (this.next() !== null) {
      /* drive to completion */
    }
    return this.result();
  }

  result(): Break1Result {
    return {
      verified: this.reEncryptionOk,
      m: this.reEncryptionOk ? this.mFinal : null,
      steps: this.emitted,
      failedAt: this.failedAt,
      reason: this.reason,
      observables: {
        m0: this.m0,
        divisionExact: this.divisionExact,
        minRowNorm: this.minRowNorm,
        expectedMinRowNorm: this.expectedMinRowNorm,
        normRatio: this.minRowNorm / this.expectedMinRowNorm,
        patternOk: this.patternOk,
        reEncryptionOk: this.reEncryptionOk,
      },
    };
  }

  private emit(step: Break1Step): Break1Step {
    this.emitted.push(step);
    if (!step.ok && this.failedAt === null) this.failedAt = step.kind;
    return step;
  }

  // ---- Step 1 ------------------------------------------------------------
  private stepMod6(): Break1Mod6Step {
    const rhs = congruenceRhs(this.c, this.sigma);
    const sol = solveMod6(this.B, rhs);
    if (!sol.ok) {
      this.phase = 'done';
      this.reason = sol.singular.reason;
      return {
        kind: 'mod6',
        ok: false,
        rhs,
        m0: null,
        singular: sol.singular,
        note: sol.singular.reason,
      };
    }
    this.m0 = sol.m0;
    this.phase = 'divide';
    return {
      kind: 'mod6',
      ok: true,
      rhs,
      m0: sol.m0,
      singular: null,
      note:
        `every error entry is +-${this.sigma}, so e = ${this.sigma}*(1,...,1) mod ${this.twoSigma} ` +
        `and m mod ${this.twoSigma} falls out of exact linear algebra over GF(2) and GF(3).`,
    };
  }

  // ---- Step 2 ------------------------------------------------------------
  private stepDivide(): Break1DivideStep {
    const m0 = this.m0 as Vec;
    const n = this.B.length;
    const m0B = vecMat(m0, this.B);
    const numerator = new Float64Array(n);
    for (let i = 0; i < n; i++) numerator[i] = this.c[i] - m0B[i] - this.sigma;

    let firstInexactIndex = -1;
    for (let i = 0; i < n; i++) {
      if (numerator[i] % this.twoSigma !== 0) { firstInexactIndex = i; break; }
    }
    if (firstInexactIndex >= 0) {
      // Unreachable for any integer c: m0 solves the congruence exactly, so this
      // difference is identically 0 mod 2*sigma. Kept as an assertion because a
      // hit here means the mod-6 solve is broken, not that the ciphertext is.
      this.phase = 'done';
      this.divisionExact = false;
      this.reason =
        `coordinate ${firstInexactIndex} of c - m0*B - sigma*1 is not a multiple of ` +
        `${this.twoSigma}, which contradicts m0 solving the congruence: the mod-6 solve is wrong.`;
      return {
        kind: 'divide',
        ok: false,
        numerator,
        firstInexactIndex,
        cpp: null,
        note: this.reason,
      };
    }

    const cpp = new Float64Array(n);
    for (let i = 0; i < n; i++) cpp[i] = numerator[i] / this.twoSigma;
    this.cpp = cpp;
    this.divisionExact = true;
    this.phase = 'embed';
    return {
      kind: 'divide',
      ok: true,
      numerator,
      firstInexactIndex: -1,
      cpp,
      note:
        `exact, as it always is: m0 solves the congruence by construction. Writing ` +
        `m = m0 + ${this.twoSigma}*mp leaves cpp = mp*B + ep with ep in {0,-1}^n -- a CVP with ` +
        'an error of length at most sqrt(n).',
    };
  }

  // ---- Step 3 ------------------------------------------------------------
  private stepEmbed(): Break1EmbedStep {
    const cpp = this.cpp as Vec;
    const embOpts: EmbeddingOptions = {};
    if (this.opts.form !== undefined) embOpts.form = this.opts.form;
    if (this.opts.t !== undefined) embOpts.t = this.opts.t;
    if (this.opts.delta !== undefined) embOpts.delta = this.opts.delta;
    if (this.opts.maxIters !== undefined) embOpts.maxIters = this.opts.maxIters;
    if (this.opts.onProgress !== undefined) embOpts.onProgress = this.opts.onProgress;
    if (this.opts.Binv !== undefined) embOpts.Binv = this.opts.Binv;
    if (this.opts.reduceTarget !== undefined) embOpts.reduceTarget = this.opts.reduceTarget;

    const emb = solveByEmbedding(cpp, this.B, embOpts);
    this.emb = emb;
    this.minRowNorm = emb.readOff.minRowNorm;
    this.expectedMinRowNorm = emb.readOff.expectedNorm;

    const failure = emb.lll.failure;
    const ok = failure === null;
    if (!ok) {
      this.phase = 'done';
      this.reason = failure.message;
    } else {
      this.phase = 'readoff';
    }
    return {
      kind: 'embed',
      ok,
      form: emb.form,
      targetReduced: emb.reduction.applied,
      targetMaxAbsBefore: emb.reduction.maxAbsBefore,
      targetMaxAbsAfter: emb.reduction.maxAbsAfter,
      embedMaxAbs: emb.embedMaxAbs,
      gramMaxAbs: emb.gramMaxAbs,
      lllSwaps: emb.lll.swaps,
      lllIters: emb.lll.iters,
      guardMax: emb.lll.guardMax,
      failure,
      note: ok
        ? `LLL reduced the ${emb.embedded.length}-dimensional embedding in ${emb.lll.swaps} swaps; ` +
          `largest integer touched was ${emb.lll.guardMax}, against the 2^53 limit.`
        : failure.message,
    };
  }

  // ---- Step 4 ------------------------------------------------------------
  private stepReadOff(): Break1ReadOffStep {
    const emb = this.emb as EmbeddingResult;
    const ro = emb.readOff;
    this.patternOk = ro.candidates.length > 0;
    this.queue = ro.candidates.length > 0 ? [...ro.candidates] : ro.best === null ? [] : [ro.best];
    this.phase = 'recover';
    const best = ro.best;
    const ratio = ro.normRatio;
    // The centered embedding's head is f in {+1,-1}^n; the uncentered one's is ep
    // itself, in {0,-1}^n. Same test, different alphabet.
    const pattern = emb.form === 'centered' ? '{+1,-1}^n' : '{0,-1}^n';
    return {
      kind: 'readoff',
      ok: this.patternOk,
      minRowNorm: ro.minRowNorm,
      expectedMinRowNorm: ro.expectedNorm,
      normRatio: ratio,
      head: best === null ? null : best.head,
      ep: best === null ? null : best.ep,
      exactCandidates: ro.candidates.length,
      note: this.patternOk
        ? `the shortest reduced row has norm ${ro.minRowNorm.toFixed(3)} against the expected ` +
          `${ro.expectedNorm.toFixed(3)}, and its head is in ${pattern}: the planted vector.`
        : `the shortest reduced row has norm ${ro.minRowNorm.toFixed(3)}, ` +
          `${ratio.toFixed(2)}x the ${ro.expectedNorm.toFixed(3)} an honest ciphertext gives, and ` +
          `no row matches the ${pattern} pattern. There is no planted short vector to find.`,
    };
  }

  // ---- Step 5 ------------------------------------------------------------
  private stepRecover(): Break1RecoverStep {
    const m0 = this.m0 as Vec;
    this.messages = this.queue.map((cand) => {
      const m = new Float64Array(m0.length);
      for (let j = 0; j < m0.length; j++) m[j] = m0[j] + this.twoSigma * cand.mp[j];
      return m;
    });
    const ok = this.messages.length > 0;
    this.phase = 'verify';
    if (!ok) {
      // Possible on a tampered ciphertext: the reduced basis need not contain any
      // row whose embedding coordinate is +-t, because there is no planted vector
      // for LLL to find. Step 6 still runs and reports that there was nothing to
      // check, so the stepper always shows all six rows.
      return {
        kind: 'recover',
        ok,
        m: null,
        mp: null,
        candidates: 0,
        note:
          'LLL returned no row with the embedding coordinate set to +-t, so there is no ' +
          'candidate message to test. On an honest ciphertext there is always exactly one.',
      };
    }
    return {
      kind: 'recover',
      ok,
      m: this.messages[0],
      mp: this.queue[0].mp,
      candidates: this.messages.length,
      note:
        `m = m0 + ${this.twoSigma}*mp, with mp read exactly off the LLL transform -- no B^-1 and ` +
        'no rounding anywhere on this path.',
    };
  }

  // ---- Step 6 ------------------------------------------------------------
  private stepVerify(): Break1VerifyStep {
    let tried = 0;
    let firstResidual: Vec | null = null;
    for (const m of this.messages) {
      tried++;
      const chk = reEncryptionCheck(this.c, m, this.B, this.sigma);
      if (firstResidual === null) firstResidual = chk.residual;
      if (chk.ok) {
        this.mFinal = m;
        this.reEncryptionOk = true;
        this.phase = 'done';
        this.reason =
          `c - m*B is in {+${this.sigma},-${this.sigma}}^n, so m is a message that produces this ` +
          'exact ciphertext under a legal GGH error. Verified with the public key only.';
        return {
          kind: 'verify',
          ok: true,
          m,
          residual: chk.residual,
          tried,
          note: this.reason,
        };
      }
    }
    this.mFinal = this.messages[0] ?? null;
    this.phase = 'done';
    this.reason =
      tried === 0
        ? 'there was no candidate message to re-encrypt, so the attack recovered nothing.'
        : `no candidate re-encrypts: c - m*B has entries outside {+${this.sigma},-${this.sigma}}, ` +
          'so the attack did not recover the message. This is the check that decides, not a ' +
          'comparison with the secret.';
    return {
      kind: 'verify',
      ok: false,
      m: this.mFinal,
      residual: firstResidual,
      tried,
      note: this.reason,
    };
  }
}

/** Run the whole of Break 1 and return the result. */
export function runBreak1(c: Vec, B: Mat, opts: Break1Options = {}): Break1Result {
  return new Break1Stepper(c, B, opts).run();
}
