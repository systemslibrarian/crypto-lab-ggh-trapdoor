/**
 * Break 1, step C -- Kannan's embedding, in both of the forms Nguyen describes.
 *
 * After the mod-2*sigma step the attacker holds a residual target
 *
 *     cpp = mp * B + ep,    ep in {0,-1}^n
 *
 * which is a CVP instance with a very small error. Embedding turns it into an SVP
 * instance in one more dimension: put the lattice in the top-left block and the
 * target in the last row, and the vector (mp, -1) times that basis is exactly the
 * (negated) error, padded with the embedding coordinate.
 *
 * TWO FORMS.
 *
 *   uncentered   rows [B | 0] and [cpp | t].  (mp,-1)*basis = (-ep, -t) with
 *                ep in {0,-1}^n, so the planted vector has expected length
 *                sqrt(n/2 + t^2) and its actual length varies with the ciphertext.
 *
 *   centered     rows [2B | 0] and [d | t] with d = 2*cpp + (1,...,1).  Now
 *                (mp,-1)*basis = (-f, -t) with f = 2*ep + 1 in {+1,-1}^n, so the
 *                planted vector has length EXACTLY sqrt(n + t^2), every time.
 *
 * Nguyen (CRYPTO '99) states the centered form -- multiplying through by 2 so the
 * error entries become +-1 on the doubled lattice -- and notes the uncentered one
 * is "slightly worse". WHICH ONE WON HERE: neither. Measured on this lab's own
 * keys, 15 ciphertexts at each of n = 8, 16, 32, 60, both forms recovered the
 * message 15/15. At real GGH parameters they tie, because the residual error is
 * so far inside LLL's reach that the sqrt(2) difference in target length is
 * invisible. (The prototype swept this further -- 100% each at every dimension
 * from 8 to 200, LLL times within noise, 3.3 ms vs 3.3 ms at n=60 -- and only
 * separated them by deliberately shrinking the lattice until the CVP was
 * marginal: at det(R)^(1/n) = 3.04, n=32, centered broke 40/40 and uncentered
 * 16/40.)
 *
 * What the centered form does buy, measured here, is the observable. Its shortest
 * reduced row came out at EXACTLY sqrt(n+1) on all 60 honest runs -- min == max ==
 * 3.000000, 4.123106, 5.744563, 7.810250 at n = 8, 16, 32, 60 -- whereas the
 * uncentered form's fluctuated (1.732051..2.449490 at n=8 against an expected
 * 2.236068). A constant is a usable pass/fail test; a distribution is not.
 *
 * So: centered is the default because it never loses, it is strictly more robust
 * once the margin narrows, and its {+1,-1} readout is both a nicer thing to show a
 * learner and a sharper negative-case test. It is NOT what makes the attack work
 * at these parameters -- both forms win by a landslide, and saying otherwise would
 * be inventing a difference that is not there.
 *
 * TARGET REDUCTION (attacker-side preprocessing, exact). Before embedding we
 * replace cpp by cpp - round(cpp * B^-1) * B and remember the subtracted lattice
 * vector, adding it back to mp at the end. It uses nothing but the public basis,
 * so the attacker may do it; it is exact because the subtracted vector is an
 * integer combination of rows of B; and it leaves ep untouched, so the planted
 * short vector is the same one.
 *
 * The quantity it protects is NOT the 2^53 integer bound -- lll.ts guards that
 * separately, and the measurement below shows the basis entries are nowhere near
 * it either way. It is the magnitude the floating-point Gram-Schmidt inside LLL
 * has to resolve: LLL accumulates DOT PRODUCTS of these rows in doubles, and it is
 * the Gram entry, not the basis entry, that gets large. Measured, 12 ciphertexts
 * per dimension, messages uniform in [-128,127], centered form:
 *
 *     n    max|cpp| raw -> reduced   max|Gram| raw   max|Gram| reduced   shrink
 *     8    1.22e4 -> 2.82e2          1.94e9          5.37e6              362x
 *     16   2.58e4 -> 6.52e2          6.84e9          6.18e7              111x
 *     32   8.03e4 -> 7.30e2          6.98e10         8.79e7              793x
 *     60   8.11e4 -> 1.69e3          2.50e11         1.93e8              1291x
 *
 * It also shows up in the largest integer LLL touches: 2^11.8-2^13.7 with the
 * reduction on, 2^16.6-2^18.1 with it off, over 20 runs at each of
 * n = 8, 16, 32, 60.
 *
 * So the honest statement is: at this lab's parameters the reduction is not
 * required for correctness. Both settings recovered the message on every one of
 * the 128 ciphertexts across those two sweeps (256 runs in all), and even the
 * unreduced 2.50e11 is 4.6 orders of magnitude under 2^53. What it buys is two to
 * three orders of magnitude of headroom on the quantity that grows with the message
 * range, for the cost of one round-off with a basis the attacker already has, and
 * it is exact. That is worth taking. The claim it was originally added to defend
 * against -- Gram entries reaching ~5e14 at n=60 -- was NOT reproduced here;
 * 2.5e11 is what this keygen and a [-128,127] message actually produce.
 */

import type { Mat, Vec } from '../lattice/types';
import {
  inverse,
  maxAbs,
  maxAbsVec,
  roundVec,
  vecIntegersUnder2p53,
  vecMat,
  zeros,
} from '../lattice/matrix';
import { lllReduce, shortestRowNorm, type LllOptions, type LllProgress, type LllResult } from './lll';

/** Which of Nguyen's two embeddings to build. */
export type EmbeddingForm = 'centered' | 'uncentered';

/** Result of pulling the target back into the fundamental region of B. */
export interface TargetReduction {
  /** The target to embed: `cpp - shift*B` when applied, otherwise the original. */
  readonly target: Vec;
  /** The subtracted lattice coefficient vector; all zeros when not applied. */
  readonly shift: Vec;
  /** False when the reduction did not help or would have broken exactness. */
  readonly applied: boolean;
  /** max |entry| of the original target. */
  readonly maxAbsBefore: number;
  /** max |entry| of the reduced target. */
  readonly maxAbsAfter: number;
}

/**
 * Replace `target` by `target - round(target * Binv) * B`.
 *
 * This is Babai round-off run by the ATTACKER with the bad public basis. Round-off
 * with B is hopeless as a decryption method -- that is the whole point of the
 * trapdoor -- but it does not need to be good here: ANY integer vector q makes
 * `target - q*B` an equally valid CVP instance with the same error, because q is
 * added straight back to mp afterwards. A poor q only makes the reduction less
 * effective, never wrong. Exactness is checked rather than trusted, and the
 * reduction is skipped if it did not actually shrink the target.
 *
 * See the file header for the measured before/after magnitudes.
 */
export function reduceTargetModLattice(target: Vec, B: Mat, Binv: Mat): TargetReduction {
  const n = target.length;
  const maxAbsBefore = maxAbsVec(target);
  const q = roundVec(vecMat(target, Binv));
  const qB = vecMat(q, B);
  const reduced = new Float64Array(n);
  for (let i = 0; i < n; i++) reduced[i] = target[i] - qB[i];
  const maxAbsAfter = maxAbsVec(reduced);
  const exact = vecIntegersUnder2p53(q) && vecIntegersUnder2p53(reduced);
  if (!exact || maxAbsAfter >= maxAbsBefore) {
    return {
      target,
      shift: new Float64Array(n),
      applied: false,
      maxAbsBefore,
      maxAbsAfter: exact ? maxAbsAfter : NaN,
    };
  }
  return { target: reduced, shift: q, applied: true, maxAbsBefore, maxAbsAfter };
}

/**
 * Build the (n+1) x (n+1) embedding basis for `target` against the lattice L(B).
 *
 * `t` is the embedding coordinate. t = 1 is the standard choice and the only one
 * used here: it makes the planted vector's last entry a marker the read-off can
 * scan for.
 */
export function buildEmbedding(target: Vec, B: Mat, form: EmbeddingForm, t = 1): Mat {
  const n = B.length;
  const M = zeros(n + 1, n + 1);
  if (form === 'centered') {
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) M[i][j] = 2 * B[i][j];
    }
    for (let j = 0; j < n; j++) M[n][j] = 2 * target[j] + 1;
  } else {
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) M[i][j] = B[i][j];
    }
    for (let j = 0; j < n; j++) M[n][j] = target[j];
  }
  M[n][n] = t;
  return M;
}

/**
 * Length of the vector the embedding plants.
 *
 * Centered: EXACT, because f in {+1,-1}^n has squared length n whatever the
 * ciphertext was. Uncentered: an expectation, because ep in {0,-1}^n has about
 * n/2 nonzero entries and the actual length fluctuates. Measured on honest
 * ciphertexts, the centered form's shortest reduced row hit this value on the
 * nose in 60/60 runs (min == max at n = 8, 16, 32, 60), while the uncentered
 * form's ranged over 1.732051..2.449490 at n=8 around an expected 2.236068. That
 * is why the centered form is the one whose norm is used as a pass/fail test.
 */
export function expectedShortNorm(n: number, form: EmbeddingForm, t = 1): number {
  return Math.sqrt((form === 'centered' ? n : n / 2) + t * t);
}

/** Largest |<row_i, row_j>| in the Gram matrix -- the magnitude the float path must resolve. */
export function maxAbsGram(A: Mat): number {
  const n = A.length;
  let m = 0;
  for (let i = 0; i < n; i++) {
    for (let j = i; j < n; j++) {
      let s = 0;
      const ai = A[i];
      const aj = A[j];
      for (let t = 0; t < ai.length; t++) s += ai[t] * aj[t];
      const a = Math.abs(s);
      if (a > m) m = a;
    }
  }
  return m;
}

/** One reading of the reduced basis as a candidate answer to the residual CVP. */
export interface EmbeddingCandidate {
  /** Index of the reduced row it came from. */
  readonly row: number;
  /** Euclidean norm of that row. */
  readonly norm: number;
  /** The row's head, sign-corrected: {+1,-1}^n for centered, {0,-1}^n for uncentered. */
  readonly head: Vec;
  /** The implied residual error, defined as target - mp*B. In {0,-1}^n iff this is a real hit. */
  readonly ep: Vec;
  /** The message coefficients, read exactly off the LLL transform -- no B^-1 anywhere. */
  readonly mp: Vec;
  /** ep really is in {0,-1}^n, so target = mp*B + ep is the planted decomposition. */
  readonly exact: boolean;
}

/** What the reduced basis says, including the observables the negative case needs. */
export interface EmbeddingReadOff {
  /** Shortest row norm LLL actually produced. */
  readonly minRowNorm: number;
  /** What it should be if the ciphertext was honest. */
  readonly expectedNorm: number;
  /** minRowNorm / expectedNorm. 1.000 on every honest run measured; 3-4 when tampered. */
  readonly normRatio: number;
  /** Some row's head matched the {+1,-1} (resp. {0,-1}) pattern. */
  readonly patternFound: boolean;
  /** Rows that decompose the target exactly, shortest first. */
  readonly candidates: readonly EmbeddingCandidate[];
  /**
   * The shortest usable row, whether or not it passed the pattern test.
   *
   * A real attacker takes LLL's best answer and runs the verification on it; the
   * negative case is supposed to produce an answer and have the check reject it,
   * not to produce nothing. That is why this is exposed even when `exact` is false.
   */
  readonly best: EmbeddingCandidate | null;
}

function isResidualPattern(ep: Vec): boolean {
  for (const v of ep) if (v !== 0 && v !== -1) return false;
  return true;
}

/**
 * Read candidate solutions off a reduced embedding basis.
 *
 * The planted vector is (mp,-1) * basis, whose last coordinate is -t; the only row
 * of the embedding with a nonzero last column is the target row, so a reduced row
 * can only have |last| = t if its transform row has |last| = 1. Both are checked,
 * and `mp` is then read straight off the transform: exact integers, no rational
 * solve and no rounding on the recovery path.
 */
export function readOffCandidates(
  reduced: LllResult,
  target: Vec,
  B: Mat,
  form: EmbeddingForm,
  t = 1,
): EmbeddingReadOff {
  const n = B.length;
  const rows = reduced.basis;
  const Hs = reduced.transform;
  const found: EmbeddingCandidate[] = [];
  let patternFound = false;

  for (let i = 0; i <= n; i++) {
    const r = rows[i];
    if (Math.abs(r[n]) !== t) continue;
    const h = Hs[i];
    if (Math.abs(h[n]) !== 1) continue;
    // r = s * (planted vector); s = +1 when the last coordinate came out as -t.
    const s = r[n] === -t ? 1 : -1;
    const head = new Float64Array(n);
    for (let j = 0; j < n; j++) head[j] = s === 1 ? -r[j] : r[j];
    const sh = h[n] === -1 ? 1 : -1;
    const mp = new Float64Array(n);
    for (let j = 0; j < n; j++) mp[j] = sh === 1 ? h[j] : -h[j];
    const mpB = vecMat(mp, B);
    const ep = new Float64Array(n);
    for (let j = 0; j < n; j++) ep[j] = target[j] - mpB[j];
    const exact = isResidualPattern(ep);
    if (exact) patternFound = true;
    let norm = 0;
    for (let j = 0; j <= n; j++) norm += r[j] * r[j];
    found.push({ row: i, norm: Math.sqrt(norm), head, ep, mp, exact });
  }

  found.sort((a, b) => a.norm - b.norm);
  const candidates = found.filter((c) => c.exact);
  const expectedNorm = expectedShortNorm(n, form, t);
  const minRowNorm = shortestRowNorm(rows);
  return {
    minRowNorm,
    expectedNorm,
    normRatio: minRowNorm / expectedNorm,
    patternFound,
    candidates,
    best: candidates.length > 0 ? candidates[0] : (found.length > 0 ? found[0] : null),
  };
}

export interface EmbeddingOptions {
  /** Default 'centered'. */
  form?: EmbeddingForm;
  /** Embedding coordinate, default 1. */
  t?: number;
  /** Passed through to LLL. */
  delta?: number;
  /** Passed through to LLL. */
  maxIters?: number;
  /** Passed through to LLL, so a worker can report progress. */
  onProgress?: (p: LllProgress) => void;
  /** Reuse an already-computed B^-1 instead of inverting again. */
  Binv?: Mat;
  /** Pull the target into the fundamental region of B first. Default true. */
  reduceTarget?: boolean;
}

export interface EmbeddingResult {
  readonly form: EmbeddingForm;
  readonly t: number;
  /** What the target reduction did, for display and for the overflow story. */
  readonly reduction: TargetReduction;
  /** The embedding basis that was reduced. */
  readonly embedded: Mat;
  /** Largest |entry| of that basis. */
  readonly embedMaxAbs: number;
  /** Largest |Gram entry| of that basis -- the magnitude the float path must resolve. */
  readonly gramMaxAbs: number;
  readonly lll: LllResult;
  /** Candidates already shifted back through the target reduction. */
  readonly readOff: EmbeddingReadOff;
}

/** Add the reduction's lattice shift back into a candidate's message coefficients. */
function unshift(c: EmbeddingCandidate, shift: Vec): EmbeddingCandidate {
  const mp = new Float64Array(c.mp.length);
  for (let j = 0; j < mp.length; j++) mp[j] = c.mp[j] + shift[j];
  return { ...c, mp };
}

/**
 * Solve the residual CVP `target = mp*B + ep` by embedding plus LLL.
 *
 * `ep` is never assumed to be small -- it is recomputed as `target - mp*B` and
 * tested. That keeps the negative case honest: a tampered ciphertext still gets an
 * answer out of LLL, and it is the test that rejects it.
 */
export function solveByEmbedding(
  target: Vec,
  B: Mat,
  opts: EmbeddingOptions = {},
): EmbeddingResult {
  const form = opts.form ?? 'centered';
  const t = opts.t ?? 1;
  const n = B.length;

  let reduction: TargetReduction;
  if (opts.reduceTarget === false) {
    reduction = {
      target,
      shift: new Float64Array(n),
      applied: false,
      maxAbsBefore: maxAbsVec(target),
      maxAbsAfter: maxAbsVec(target),
    };
  } else {
    const Binv = opts.Binv ?? safeInverse(B);
    reduction =
      Binv === null
        ? {
            target,
            shift: new Float64Array(n),
            applied: false,
            maxAbsBefore: maxAbsVec(target),
            maxAbsAfter: maxAbsVec(target),
          }
        : reduceTargetModLattice(target, B, Binv);
  }

  const embedded = buildEmbedding(reduction.target, B, form, t);
  const lllOpts: LllOptions = {};
  if (opts.delta !== undefined) lllOpts.delta = opts.delta;
  if (opts.maxIters !== undefined) lllOpts.maxIters = opts.maxIters;
  if (opts.onProgress !== undefined) lllOpts.onProgress = opts.onProgress;
  const lll = lllReduce(embedded, lllOpts);

  const raw = readOffCandidates(lll, reduction.target, B, form, t);
  const readOff: EmbeddingReadOff = reduction.applied
    ? {
        ...raw,
        candidates: raw.candidates.map((c) => unshift(c, reduction.shift)),
        best: raw.best === null ? null : unshift(raw.best, reduction.shift),
      }
    : raw;

  return {
    form,
    t,
    reduction,
    embedded,
    embedMaxAbs: maxAbs(embedded),
    gramMaxAbs: maxAbsGram(embedded),
    lll,
    readOff,
  };
}

/** B^-1, or null when the basis handed in is singular. */
function safeInverse(B: Mat): Mat | null {
  try {
    return inverse(B);
  } catch {
    return null;
  }
}
