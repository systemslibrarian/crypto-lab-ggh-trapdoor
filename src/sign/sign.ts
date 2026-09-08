/**
 * GGH round-off signatures -- and the leak that Break 2 lives on.
 *
 * Signing is the same three lines as decryption, run backwards. A message is
 * hashed to a point h in R^n (not on the lattice); the signature is the nearest
 * lattice point Babai's round-off can find with the PRIVATE basis:
 *
 *     s = round(h * R^-1) * R
 *
 * Anyone can check s is in the lattice using the public basis, and that s is
 * close to h. Only the holder of R can produce a close s, because round-off with
 * the public basis lands far away (measured at n=12: ||s-h||inf = 38.9 against a
 * published bound of 24.0 -- see verify.ts).
 *
 * THE LEAK. Write y = h * R^-1. Then
 *
 *     v = s - h = (round(y) - y) * R = x * R,   x_i = round(y_i) - y_i.
 *
 * Every x_i lies in [-1/2, 1/2], and for a generic h it is uniform there. So
 * every signature hands the world one uniform sample from the fundamental
 * parallelepiped P(R) = { x*R : x in [-1/2,1/2)^n }. The parallelepiped is a
 * skewed box whose EDGES are the rows of R, and enough samples pin the edges
 * down. That is the whole of Nguyen-Regev (EUROCRYPT 2006): the signature scheme
 * is a machine for publishing i.i.d. samples of its own secret key.
 *
 * Nothing in this file is an attack. It is the honest signer, written exactly as
 * GGH specifies it, and the leak is a property of the specification.
 */

import type { Mat, Rng, Vec } from '../lattice/types';
import { roundVec, vecMat } from '../lattice/matrix';

/**
 * A signing function: hashed point in, lattice point out.
 *
 * Break 2 is written against this type and nothing else, so the round-off signer
 * and the Klein signer (klein.ts) run through byte-identical attack code. That
 * is what makes claim C5' a fair comparison rather than two different programs.
 */
export type SignFn = (h: Vec) => Vec;

/**
 * Half-width of the box the hashed message point is drawn from.
 *
 * A real scheme hashes the message into a box; the box only has to be large
 * compared with the basis so that no h is special. 1e4 against max|R| ~ 20-53 at
 * the shipped dimensions is four orders of margin, which is what makes the
 * round-off residual x equidistributed in [-1/2,1/2)^n. Shrink it towards the
 * basis and the samples stop being uniform -- and the attack, which assumes
 * uniformity, degrades accordingly.
 */
export const DEFAULT_H_RANGE = 1e4;

/** A hashed message point: uniform in [-range, range)^n. Not a lattice point. */
export function randomH(n: number, rng: Rng, range: number = DEFAULT_H_RANGE): Vec {
  const h = new Float64Array(n);
  for (let i = 0; i < n; i++) h[i] = (rng() * 2 - 1) * range;
  return h;
}

/**
 * Babai round-off signature: s = round(h * basisInv) * basis.
 *
 * Identical arithmetic whichever basis is supplied -- the private basis gives a
 * short s - h and the public basis does not. The forgery step of Break 2 calls
 * this with the RECOVERED basis Rhat, which is why it is written to take any
 * basis rather than reaching for a key.
 */
export function signRoundOff(h: Vec, basis: Mat, basisInv: Mat): Vec {
  return vecMat(roundVec(vecMat(h, basisInv)), basis);
}

/** Bind a basis to a `SignFn`. */
export function makeRoundOffSigner(basis: Mat, basisInv: Mat): SignFn {
  return (h: Vec) => signRoundOff(h, basis, basisInv);
}

/**
 * The published signature bound for a round-off signer: half the largest column
 * L1 norm of R.
 *
 * Since v = s - h = x*R with every |x_i| <= 1/2,
 *
 *     |v_j| <= (1/2) * sum_i |R_ij|
 *
 * and the bound is TIGHT -- attained at x_i = (1/2)*sign(R_ij). GGH and NTRUSign
 * publish exactly such a norm alongside the public key; it reveals a norm, not R.
 *
 * CRITICAL FOR INVARIANT I5: permuting the rows of R and flipping their signs
 * changes no column's L1 norm. So a basis Rhat = P*D*R recovered up to sign and
 * permutation -- which is all Break 2 can ever recover -- has the IDENTICAL
 * published bound, and a forged signature is measured against the same number a
 * genuine one is. The forgery test is not graded on a curve.
 *
 * Measured at the shipped keygen: 9.5 (n=4) to 28.5 (n=16), against observed
 * max||s-h||inf of 8.4 to 15.8 over 200 signatures per key.
 */
export function roundOffBoundInf(R: Mat): number {
  const n = R.length;
  let bound = 0;
  for (let j = 0; j < n; j++) {
    let s = 0;
    for (let i = 0; i < n; i++) s += Math.abs(R[i][j]);
    if (0.5 * s > bound) bound = 0.5 * s;
  }
  return bound;
}

/**
 * The leaked sample: v = s - h.
 *
 * This is the only thing Break 2 ever looks at. It is public -- h is the hash of
 * a message anyone can compute and s is the signature -- so collecting these is
 * a passive, entirely legitimate observation of published data.
 */
export function signatureLeak(h: Vec, s: Vec): Vec {
  const v = new Float64Array(h.length);
  for (let i = 0; i < h.length; i++) v[i] = s[i] - h[i];
  return v;
}

/**
 * The parallelepiped coordinates of one signature: x = (s - h) * R^-1.
 *
 * Uses the secret, so this is an EXHIBIT, not part of the attack. Every entry
 * must land in [-1/2, 1/2] -- that is the claim "v is uniform in P(R)" made
 * checkable rather than asserted, and it is what act 4 draws.
 */
export function parallelepipedCoords(h: Vec, s: Vec, Rinv: Mat): Vec {
  return vecMat(signatureLeak(h, s), Rinv);
}

/**
 * Observe `count` signatures and keep only the leak v = s - h.
 *
 * Memory is the reason h and s are discarded: the sample set alone is N*n*8
 * bytes -- 4.1 MB at the measured n=16 median of N=32000 -- and keeping h and s
 * as well triples that to 24.6 MB at the worst configuration. The UI regenerates
 * individual (h, s) pairs on demand for display instead.
 */
export function collectLeaks(
  count: number,
  n: number,
  rng: Rng,
  sign: SignFn,
  range: number = DEFAULT_H_RANGE,
): Mat {
  const out: Mat = [];
  for (let t = 0; t < count; t++) {
    const h = randomH(n, rng, range);
    out.push(signatureLeak(h, sign(h)));
  }
  return out;
}
