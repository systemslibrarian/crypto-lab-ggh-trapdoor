/**
 * Encryption, Babai round-off decryption, and invariant I2.
 *
 * This module IS the trapdoor. Encryption puts the message on a lattice point
 * and adds a small error; decryption is Babai's round-off (Babai, Combinatorica
 * 1986), which is the same three lines of arithmetic whichever basis you hand
 * it. The private basis makes it work and the public basis does not, and the
 * single number that decides is invariant I2.
 */

import type { Ciphertext, DecryptBound, GghKey, Mat, Rng, Vec } from './types';
import { maxAbsVec, randInt, rnd, roundVec, vecMat } from './matrix';
import { SIGMA } from './keygen';

/** Encrypt: c = m*B + e with every entry of e drawn from {+sigma, -sigma}. */
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
 * Round-off with a basis succeeds if and only if every entry of e * basisInv is
 * strictly less than 1/2 in absolute value: that quantity is exactly how far the
 * error displaces the coordinate vector, and rounding recovers the right lattice
 * point precisely when no coordinate is pushed past the half-way mark.
 *
 * This is an exact iff and it is basis-generic -- the same criterion, the same
 * ciphertext, one number, and the trapdoor is the only thing that makes that
 * number small. Measured with zero mismatches over 5,600 ciphertexts: ~0.29-0.69
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
