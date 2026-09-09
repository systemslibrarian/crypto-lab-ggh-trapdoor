/**
 * Encryption, Babai round-off decryption, and invariant I2.
 *
 * This module IS the trapdoor. Encryption puts the message on a lattice point
 * and adds a small error; decryption is Babai's round-off (Babai, Combinatorica
 * 1986), which is the same three lines of arithmetic whichever basis you hand
 * it. The private basis makes it work and the public basis does not, and the
 * single number that decides is invariant I2 -- strictly, the number decides
 * everywhere except on its own boundary, where the tie rule does; see
 * `decryptBound`.
 */

import type { Ciphertext, DecryptBound, GghKey, Mat, Rng, Vec } from './types';
import { maxAbsVec, randInt, rnd, roundVec, vecMat } from './matrix';
import { SIGMA } from './keygen';

/**
 * Encrypt: c = m*B + e with every entry of e drawn from {+sigma, -sigma}.
 *
 * `sigma` is a real parameter here: every function in this file is written in
 * terms of it and works for any positive value. That is NOT true everywhere --
 * Break 1's mod-2*sigma step is implemented over GF(2) and GF(3) and so is fixed
 * at sigma = 3; see `BreakableSigma` in keygen.ts.
 */
export function encrypt(m: Vec, B: Mat, rng: Rng, sigma: number = SIGMA): Ciphertext {
  const c = vecMat(m, B);
  const e = new Float64Array(B.length);
  for (let i = 0; i < e.length; i++) {
    e[i] = rng() < 0.5 ? sigma : -sigma;
    c[i] += e[i];
  }
  return { c, e, m: Float64Array.from(m) };
}

/**
 * Encrypt with an error drawn uniformly from {-sigma..sigma} instead.
 *
 * This is the toggle that breaks Nguyen's attack, and GGH's own paper offers a
 * variant like it: "if we want e to have integral entries we can pick each entry
 * as equal to +-ceil(sigma) each with probability p = sigma^2/(2*ceil(sigma)^2),
 * and 0 with probability 1-2p". The entries are no longer all congruent mod
 * 2*sigma, which is the only thing Break 1 depends on.
 *
 * `badCoords`, if given, keeps the error in {+-sigma} everywhere EXCEPT that
 * many randomly chosen coordinates. One bad coordinate out of sixteen is enough
 * to destroy the attack completely -- the failure is a cliff, not a slope.
 */
export function encryptNonCongruent(
  m: Vec,
  B: Mat,
  rng: Rng,
  sigma: number = SIGMA,
  badCoords?: number,
): Ciphertext {
  const n = B.length;
  const c = vecMat(m, B);
  const e = new Float64Array(n);
  let bad: Set<number> | null = null;
  if (badCoords !== undefined) {
    bad = new Set<number>();
    const idx = [...Array(n).keys()];
    for (let i = n - 1; i > 0; i--) {
      const j = randInt(rng, 0, i);
      [idx[i], idx[j]] = [idx[j], idx[i]];
    }
    for (let i = 0; i < Math.min(badCoords, n); i++) bad.add(idx[i]);
  }
  for (let i = 0; i < n; i++) {
    if (bad === null) {
      // Fully uniform in {-sigma..sigma}.
      e[i] = randInt(rng, -sigma, sigma);
    } else if (bad.has(i)) {
      // Uniform in the strictly smaller range {-(sigma-1)..(sigma-1)}, so this
      // coordinate is never accidentally +-sigma and the demonstration is exact.
      e[i] = randInt(rng, -(sigma - 1), sigma - 1);
    } else {
      e[i] = rng() < 0.5 ? sigma : -sigma;
    }
    c[i] += e[i];
  }
  return { c, e, m: Float64Array.from(m) };
}

/**
 * Babai round-off with `basis`.
 *
 * Returns the recovered lattice point v = round(c * basisInv) * basis. The
 * caller reads the message off it with `latticePointToMessage`. Identical code
 * for the private and the public basis -- that is the point of the exhibit.
 */
export function roundOff(c: Vec, basis: Mat, basisInv: Mat): Vec {
  return vecMat(roundVec(vecMat(c, basisInv)), basis);
}

/** Read a lattice point's coordinates in the public basis. */
export function latticePointToMessage(v: Vec, Binv: Mat): Vec {
  return roundVec(vecMat(v, Binv));
}

/** Decrypt with the private basis: the legitimate path. */
export function decrypt(c: Vec, key: GghKey, Rinv: Mat, Binv: Mat): Vec {
  return latticePointToMessage(roundOff(c, key.R, Rinv), Binv);
}

/**
 * Invariant I2 for one ciphertext under one basis.
 *
 * Write x = e * basisInv and let z be the true lattice point's integer
 * coordinate vector in the same basis, so round-off rounds z + x. Then, exactly:
 *
 *     max_j |x_j| <  1/2   round-off ALWAYS recovers the point;
 *     max_j |x_j| >  1/2   round-off ALWAYS fails (some coordinate has a nearer
 *                          integer than z_j, and rounding returns that one);
 *     max_j |x_j| == 1/2   TIE-DEPENDENT: the outcome is decided by the tie rule
 *                          and by z, which `decryptBound` cannot see.
 *
 * So `actual < 0.5` is a sufficient condition that never lies, and `actual > 0.5`
 * is a sufficient condition for failure. It is NOT an iff at the boundary. With
 * this lab's `rnd` (half AWAY from zero, matrix.ts) the tie resolves coordinate
 * by coordinate: at x_j = +1/2 the point survives iff z_j <= -1, at x_j = -1/2
 * iff z_j >= 1 -- i.e. exactly when the error pushes that coordinate TOWARDS
 * zero. `roundOffSucceedsExactly` evaluates that rule with no ambiguity left, and
 * roundoff.test.ts builds one tie that succeeds and one that fails.
 *
 * Ties are a measure-zero event for a generic basis and are never observed on the
 * shipped path: e has entries +-sigma and basisInv is a generic float matrix, so
 * an exact 1/2 needs an exact cancellation. Measured, the strict criterion agreed
 * with the actual round-off in 5,600 of 5,600 ciphertexts -- but "no tie occurred
 * in 5,600 draws" is what that measurement shows, not that ties cannot occur.
 *
 * The criterion is basis-generic -- the same one number for the private and the
 * public basis, and the trapdoor is the only thing that makes it small: ~0.29-0.69
 * with the private basis versus 7.3-15.3 with the public one.
 */
export function decryptBound(e: Vec, basisInv: Mat, sigma: number = SIGMA): DecryptBound {
  const actual = maxAbsVec(vecMat(e, basisInv));
  const worstCase = worstCaseBound(basisInv, sigma);
  return {
    actual,
    worstCase,
    predictsSuccess: actual < 0.5,
    guaranteed: worstCase < 0.5,
    margin: actual === 0 ? Infinity : 0.5 / actual,
  };
}

/**
 * The exact round-off criterion, ties included.
 *
 * `x` is the displacement e * basisInv and `z` is the true lattice point's
 * integer coordinate vector in that same basis; round-off returns the point iff
 * rnd(z_j + x_j) == z_j for every j, which is what this evaluates. It needs z, so
 * it is an EXHIBIT (the attacker has no z), and it exists so that the boundary
 * case of invariant I2 is decided by running the actual rounding rule rather than
 * by a claim about it.
 *
 * Off the boundary it agrees with `decryptBound(...).predictsSuccess` by the
 * argument in that function's comment; at |x_j| == 1/2 it is the only one of the
 * two that is right.
 */
export function roundOffSucceedsExactly(x: Vec, z: Vec): boolean {
  for (let j = 0; j < x.length; j++) if (rnd(z[j] + x[j]) !== z[j]) return false;
  return true;
}

/** How many coordinates of `x` sit exactly on the 1/2 boundary. Zero on every measured ciphertext. */
export function tieCount(x: Vec): number {
  let ties = 0;
  for (const v of x) if (Math.abs(v) === 0.5) ties++;
  return ties;
}

/**
 * The maximum of the I2 quantity over EVERY error vector in {+sigma,-sigma}^n.
 *
 * Attained at e_i = sigma * sign(basisInv[i][j]) for the worst column j, so it is
 * tight rather than a loose upper bound. Below 1/2 means decryption cannot fail
 * for any error the encryptor might draw.
 */
export function worstCaseBound(basisInv: Mat, sigma: number = SIGMA): number {
  const n = basisInv.length;
  let w = 0;
  for (let j = 0; j < n; j++) {
    let s = 0;
    for (let i = 0; i < n; i++) s += Math.abs(basisInv[i][j]);
    if (s > w) w = s;
  }
  return sigma * w;
}

/** A random message with entries uniform in [-range, range]. GGH's challenges used [-128, 127]. */
export function randomMessage(n: number, rng: Rng, range = 128): Vec {
  const m = new Float64Array(n);
  for (let i = 0; i < n; i++) m[i] = randInt(rng, -range, range - 1);
  return m;
}

/**
 * Re-encryption check: does this candidate message reproduce the ciphertext with
 * a legal error vector?
 *
 * This is the check a real attacker can run, and invariant I5 requires every
 * "attack succeeded" claim to go through something like it rather than through a
 * comparison with the secret.
 */
export function reEncryptionCheck(
  c: Vec,
  candidateM: Vec,
  B: Mat,
  sigma: number = SIGMA,
): { ok: boolean; residual: Vec } {
  const v = vecMat(candidateM, B);
  const residual = new Float64Array(c.length);
  let ok = true;
  for (let i = 0; i < c.length; i++) {
    residual[i] = c[i] - v[i];
    if (rnd(residual[i]) !== residual[i] || Math.abs(residual[i]) !== sigma) ok = false;
  }
  return { ok, residual };
}
