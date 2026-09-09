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
 * Every x_i lies in [-1/2, 1/2] -- that part is geometry and holds for every h
 * without exception. So every signature hands the world one sample from the
 * fundamental parallelepiped P(R) = { x*R : x in [-1/2,1/2)^n }. The
 * parallelepiped is a skewed box whose EDGES are the rows of R, and enough
 * samples pin the edges down. That is the whole of Nguyen-Regev (EUROCRYPT 2006):
 * the signature scheme is a machine for publishing i.i.d. samples of its own
 * secret key.
 *
 * HOW UNIFORM, EXACTLY. x is uniform on the cube EXACTLY only if y is uniform
 * modulo Z^n -- which would need h uniform modulo the lattice L(R). A real
 * scheme hashes into a finite box instead, so x is only APPROXIMATELY
 * equidistributed, and the approximation is what `DEFAULT_H_RANGE` buys. It is
 * measurable rather than hand-waved. For an integer frequency k, <k, round(y)> is
 * an integer, so
 *
 *     E[ exp(2 pi i <k,x>) ] = E[ exp(-2 pi i <k,y>) ]
 *                            = prod_p sinc( 2 pi * range * (R^-1 k)_p )
 *
 * because the h_p are independent and uniform on [-range, range). Every nonzero
 * frequency's coefficient is therefore at most
 *
 *     prod_p min( 1, 1 / (2 pi * range * |(R^-1 k)_p|) )                (*)
 *
 * and, since ||R^-1 k||_inf >= ||k||_2 / (sqrt(n) * ||R||_2) >= 1/(sqrt(n)||R||_F),
 * at most sqrt(n)*||R||_F / (2 pi * range) for EVERY nonzero k at once.
 * `leakFourierBound` computes (*) and `leakUniformityBound` computes the global
 * one. Measured at the shipped range = 1e4 on the signing keys of seed 20260908
 * (k = paperK(n), the key act 4 uses): the global bound is 1.8e-3 at n=8 and
 * 3.4e-3 at n=12, while the frequencies a low-order statistic can actually see
 * are far smaller -- 3.0e-28 (n=8) and 1.8e-32 (n=12) for the per-coordinate
 * marginals k = e_i, and 1.3e-22 for the worst of EVERY frequency with
 * 0 < ||k||inf <= 2 at n=8 (390,624 of them, enumerated). The empirical side
 * agrees: E|x_i| measured 0.249848 at n=12 over 48,000 coordinates, against 0.25
 * for a uniform one and a standard error of 6.6e-4.
 *
 * The caveat has teeth, and shrinking the box is how you see them. At range = 10
 * the n=12 marginal bound is 0.31 -- no guarantee at all -- and the measured
 * E|x_i| is 0.2558, which is 9 standard errors off uniform; at range = 1 it is
 * 0.0396, because y never leaves one cell and x is just -y. Two further honest
 * caveats: the statement above is for a continuous box, while `randomH` draws on
 * the PRNG's 2^-32 grid (visible only at frequencies about 2^32/(2*range) = 2e5
 * times higher than the ones above), and it constrains one signature's law -- the
 * independence BETWEEN signatures is exact, since each draws its own h.
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
 * compared with the basis so that no h is special. 1e4 against a measured
 * max|R| of 16 (n=8) to 36 (n=60) at the signature act's k = paperK(n) is nearly
 * three orders of margin at the worst end, which is what makes the round-off
 * residual x equidistributed in [-1/2,1/2)^n to the accuracy measured in the
 * file header. Shrink it towards the basis and the samples stop
 * being uniform -- measurably so, at range = 10 and below -- and the attack,
 * which assumes uniformity, degrades accordingly.
 */
export const DEFAULT_H_RANGE = 1e4;

/**
 * Bound on the Fourier coefficient of the leak's law at one integer frequency:
 * prod_p min(1, 1 / (2 pi * range * |(R^-1 k)_p|)).
 *
 * This is the honest form of "the residual is uniform". A coefficient of 0 at
 * every nonzero k would BE exact uniformity; what a finite hash box gives is a
 * small number instead, and this is the number. `k` must have integer entries --
 * only integer frequencies survive the reduction mod 1 that round-off performs.
 *
 * Derivation and measured values are in the file header.
 */
export function leakFourierBound(Rinv: Mat, k: Vec, range: number = DEFAULT_H_RANGE): number {
  const n = Rinv.length;
  let bound = 1;
  for (let p = 0; p < n; p++) {
    let t = 0;
    for (let j = 0; j < n; j++) t += Rinv[p][j] * k[j];
    const theta = 2 * Math.PI * range * Math.abs(t);
    if (theta > 1) bound /= theta;
    if (bound === 0) break;
  }
  return bound;
}

/**
 * Bound on EVERY nonzero Fourier coefficient at once: sqrt(n)*||R||_F/(2 pi range).
 *
 * ||R^-1 k||_inf >= ||R^-1 k||_2/sqrt(n) >= ||k||_2/(sqrt(n)*||R||_2), and
 * ||k||_2 >= 1 for a nonzero integer k, so at least one factor of the product in
 * `leakFourierBound` is this small no matter which frequency is asked about. The
 * Frobenius norm is used for ||R||_2 because it is a certified upper bound for
 * the spectral norm and needs no iteration to compute; that makes this bound
 * loose by up to sqrt(n) and keeps it rigorous.
 *
 * Measured 1.8e-3 (n=8) and 3.4e-3 (n=12) at range = 1e4 on this lab's keys.
 */
export function leakUniformityBound(R: Mat, range: number = DEFAULT_H_RANGE): number {
  let frobeniusSq = 0;
  for (const row of R) for (const v of row) frobeniusSq += v * v;
  return (Math.sqrt(R.length) * Math.sqrt(frobeniusSq)) / (2 * Math.PI * range);
}

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
 * must land in [-1/2, 1/2] -- the containment half of "v is spread over P(R)"
 * made checkable rather than asserted, and it is what act 4 draws. The other
 * half, that x fills the cube evenly, is an approximation with a measured size:
 * see `leakFourierBound` and the file header.
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
