/**
 * GGH key generation.
 *
 * PARAMETERS -- and an honest note about where they depart from the 1997 paper.
 *
 * GGH offers two private-basis distributions (CRYPTO '97, section 3.2). We use
 * the second, "almost rectangular": pick E uniform in {-l..l}^(n x n), set
 * R = k*I + E. The paper says "we get the best parameters when k is about
 * sqrt(n)*l", and its own instantiation (section 5.2) is R = 4*ceil(sqrt(n))*I +
 * rand(+-4) -- that is k = l*ceil(sqrt(n)) with l = 4, a CEILING, not a rounding.
 * `paperK` implements that literally: it is 12 at n=8 where round(sqrt(n)*l) is
 * 11. The two rules agree exactly when ceil(sqrt(n)) - sqrt(n) <= 0.5/l, which
 * at l=4 covers n = 16 and 24 but not n = 8, 12, 32 or 60 -- so "round" is not a
 * harmless paraphrase of the cited formula.
 *
 * We keep l = 4 and sigma = 3 but we DO NOT use k = l*ceil(sqrt(n)). Measured,
 * that rule does not decrypt at the dimensions this lab teaches at: the honest
 * owner of the private key fails to recover the message 56-57% of the time at
 * n=8 and 2.7-3.3% of the time at n=32 (40 keys x 100 ciphertexts per seed,
 * three seeds), because invariant I2 is violated. The rate is not monotone in n
 * -- 18.5-21.4% at n=12 against 32.5-39.3% at n=16 -- because the ceiling steps:
 * n=12 and n=16 both get k=16, and only the larger dimension has to survive it.
 * That is not a bug in GGH -- sigma in the paper is DERIVED from the basis
 * (sigma_i = (gamma_i * sqrt(8 ln(2n/eps)))^-1, section 5.2) and only happens to
 * come out near 3 at the paper's dimensions of 200-400. The published challenges
 * used sigma = 3 exactly. At n = 8..60, sigma = 3 with k ~ sqrt(n)*l is simply
 * too much error for the basis.
 *
 * sigma = 3 is load-bearing here: 2*sigma = 6 is what makes Nguyen's mod-2-sigma
 * step work, and it is the challenge value. So we hold sigma at 3 and raise k
 * instead:
 *
 *     k = ceil(2*l*sqrt(n)) + 4*l
 *
 * The additive 4*l term is what flattens the margin across the range -- a pure
 * multiple of l*sqrt(n) cannot, because the required multiple runs from 2.46x at
 * n=8 down to 1.74x at n=60. With this rule the worst-case I2 bound is 0.119 to
 * 0.126 across n = 8, 12, 16, 24, 32, 60 -- a margin of 4.0x to 4.2x under the
 * 0.5 threshold -- so decryption provably cannot fail for ANY error in {+-3}^n.
 * Measured: 0 failures in 4,000 ciphertexts at each of those six dimensions
 * (24,000 in all), against 43% success at n=8 under the paper's rule.
 *
 * This trades notional security for a decryption guarantee, which is the right
 * trade for a teaching lab and the wrong one for a scheme. GGH is broken anyway
 * -- that is the lab's whole point -- and the larger k makes the private basis
 * MORE orthogonal, which strengthens the R-vs-B contrast the lab exists to show.
 */

import type { GghKey, Mat, Rng } from './types';
import { eye, matmul, randInt, zeros } from './matrix';

/** Default noise half-width, as in GGH section 5.2. */
export const DEFAULT_L = 4;

/** Default error magnitude. 2*sigma = 6 is the modulus Nguyen's break works in. */
export const SIGMA = 3;

/**
 * The one error magnitude Break 1's mod-2*sigma arithmetic is implemented for.
 *
 * `mod6.ts` solves the congruence over GF(2) and GF(3) and lifts by CRT, which
 * is 2*sigma = 6 and nothing else. Any API that takes a sigma and then calls
 * that path should take THIS type, so the signature cannot promise a generality
 * the code does not have. See the report note in break1.ts's `Break1Options`.
 */
export type BreakableSigma = typeof SIGMA;

/**
 * The diagonal shift. See the file header for why this is not GGH's
 * k = l*ceil(sqrt(n)).
 */
export function gghK(n: number, l: number = DEFAULT_L): number {
  return Math.ceil(2 * l * Math.sqrt(n)) + 4 * l;
}

/**
 * GGH's own rule, exactly as section 5.2 states it: R = 4*ceil(sqrt(n))*I with
 * l = 4, i.e. k = l*ceil(sqrt(n)). Kept so the UI can show what it does to the
 * I2 bound, and used by the signature acts, which need no decryption guarantee.
 *
 * The ceiling is not decoration: at n=8 it gives 12 where round(sqrt(n)*l) gives
 * 11, and the two coincide only when ceil(sqrt(n)) - sqrt(n) <= 0.5/l (n = 16
 * and 24 at l=4, not n = 8, 12, 32 or 60). This helper used to round;
 * every measured number in this file that mentions the paper's rule was re-taken
 * against the ceiling version.
 */
export function paperK(n: number, l: number = DEFAULT_L): number {
  return l * Math.ceil(Math.sqrt(n));
}

/**
 * Is M invertible modulo the prime p?
 *
 * Exact Gaussian elimination over GF(p). Used on R rather than B because
 * det(B) = +-det(R), so they always agree -- verified over 200 keys at each of
 * n = 8, 16, 32, 60 with zero disagreements -- and testing R lets keygen reject
 * a bad key before U is even built.
 */
export function invertibleModP(M: Mat, p: number): boolean {
  const n = M.length;
  const A: number[][] = M.map((r) => Array.from(r, (v) => ((v % p) + p) % p));
  for (let c = 0; c < n; c++) {
    let piv = -1;
    for (let r = c; r < n; r++) if (A[r][c] !== 0) { piv = r; break; }
    if (piv < 0) return false;
    [A[c], A[piv]] = [A[piv], A[c]];
    let inv = 1;
    while ((A[c][c] * inv) % p !== 1) inv++;
    for (let j = 0; j < n; j++) A[c][j] = (A[c][j] * inv) % p;
    for (let r = 0; r < n; r++) {
      if (r === c || A[r][c] === 0) continue;
      const f = A[r][c];
      for (let j = 0; j < n; j++) A[r][j] = (((A[r][j] - f * A[c][j]) % p) + p) % p;
    }
  }
  return true;
}

/** Is the lattice usable by Break 1? Requires B invertible mod 2 AND mod 3. */
export function invertibleMod6(M: Mat): boolean {
  return invertibleModP(M, 2) && invertibleModP(M, 3);
}

export interface KeygenOptions {
  /** Noise half-width. Default 4. */
  l?: number;
  /** Diagonal shift. Defaults to gghK(n, l). */
  k?: number;
  /** Entry cap for U and V during mixing. Default 512. */
  uCap?: number;
  /** Elementary row operations per row. Default 6. */
  opsPerRow?: number;
  /** Deterministic generator. */
  rng: Rng;
  /**
   * Reject keys whose det is not coprime to 6.
   *
   * Only 12-17% of random keys are invertible mod 6, so without this Break 1
   * fails on roughly 85% of keys. Mean draws to acceptance is 5.8-6.5, which is
   * negligible. Set false to demonstrate the singular case on purpose (I3 says
   * the act must name it and re-key rather than fudge it).
   */
  requireCoprime6?: boolean;
}

/**
 * Generate a GGH key pair.
 *
 * U is built as a product of elementary row operations and V = U^-1 is tracked
 * alongside them, so both are exact by construction. A candidate operation is
 * applied only if it keeps BOTH |U| and |V| within `uCap` -- capping U alone
 * would be meaningless, since it is the inverse that degrades first. At the
 * default opsPerRow = 6 the cap never actually binds (the +-1 random walk only
 * reaches 24-70), so it is a safety rail rather than a throttle.
 */
export function gghKeygen(n: number, opts: KeygenOptions): GghKey {
  const l = opts.l ?? DEFAULT_L;
  const k = opts.k ?? gghK(n, l);
  const uCap = opts.uCap ?? 512;
  const opsPerRow = opts.opsPerRow ?? 6;
  const requireCoprime6 = opts.requireCoprime6 ?? true;
  const rng = opts.rng;

  let R: Mat = [];
  let attempts = 0;
  for (;;) {
    attempts++;
    if (attempts > 500) throw new Error('keygen: no R with det coprime to 6 after 500 draws');
    R = [];
    for (let i = 0; i < n; i++) {
      const row = new Float64Array(n);
      for (let j = 0; j < n; j++) row[j] = (i === j ? k : 0) + randInt(rng, -l, l);
      R.push(row);
    }
    if (!requireCoprime6) break;
    if (invertibleMod6(R)) break;
  }

  // Unimodular U as a product of elementary row ops, with V = U^-1 tracked.
  // Row op  U[i] += c*U[j]  is matched by column op  V[:,j] -= c*V[:,i].
  const U = eye(n);
  const V = eye(n);
  for (let s = 0; s < opsPerRow * n; s++) {
    const i = randInt(rng, 0, n - 1);
    let j = randInt(rng, 0, n - 2);
    if (j >= i) j++;
    const c = rng() < 0.5 ? 1 : -1;
    let ok = true;
    for (let t = 0; t < n && ok; t++) if (Math.abs(U[i][t] + c * U[j][t]) > uCap) ok = false;
    for (let t = 0; t < n && ok; t++) if (Math.abs(V[t][j] - c * V[t][i]) > uCap) ok = false;
    if (!ok) continue;
    for (let t = 0; t < n; t++) U[i][t] += c * U[j][t];
    for (let t = 0; t < n; t++) V[t][j] -= c * V[t][i];
  }
  // Random row sign flips (det *= -1 each) and a random row permutation.
  for (let i = 0; i < n; i++) {
    if (rng() < 0.5) {
      for (let t = 0; t < n; t++) { U[i][t] = -U[i][t]; V[t][i] = -V[t][i]; }
    }
  }
  const perm = [...Array(n).keys()];
  for (let i = n - 1; i > 0; i--) {
    const j = randInt(rng, 0, i);
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }
  const Up: Mat = perm.map((p) => Float64Array.from(U[p]));
  const Vp = zeros(n, n);
  for (let r = 0; r < n; r++) for (let c2 = 0; c2 < n; c2++) Vp[r][c2] = V[r][perm[c2]];

  const B = matmul(Up, R);
  return { n, l, k, R, U: Up, V: Vp, B, keygenAttempts: attempts };
}
