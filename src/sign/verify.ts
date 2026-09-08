/**
 * The REAL signature verifier.
 *
 * This module is the referee for invariant I5: every "the attack succeeded"
 * claim in the lab has to come back through here. It therefore gets to see
 * exactly what a verifier in the field sees and nothing else:
 *
 *   - B, the public basis, and its inverse (anyone can compute that);
 *   - `boundInf`, the norm published alongside the public key;
 *   - the pair (h, s) being checked.
 *
 * It never sees R, never sees the attack's internal state, and never compares
 * anything to a secret. A forgery is accepted or rejected on the same two tests a
 * genuine signature faces:
 *
 *   (a) s lies in the lattice L(B)  -- s*B^-1 rounds to integers, and those
 *       integers multiply back to exactly s;
 *   (b) ||s - h||inf <= boundInf     -- s is close enough to the hashed point.
 *
 * WHY (a) NEEDS BOTH HALVES. The fractional test alone is a numeric statement; a
 * vector could round to integers and still not reproduce s if the coordinates
 * were large enough for float error to matter. Multiplying back and comparing
 * against s is the exact statement, and the fractional test is what makes the
 * multiplication meaningful. Both are kept.
 *
 * WHY THE TOLERANCE IS 1e-6. Measured over 200 signatures at each of n = 4, 6, 8,
 * 12, 16, the worst float residue in s*B^-1 was 8.19e-12 (at n=16, where max|B|
 * reaches 53). 1e-6 sits six orders of magnitude above that and eleven orders
 * below the 0.5 that a genuinely non-lattice vector would have to beat. There is
 * no regime at these dimensions where the tolerance decides the answer.
 *
 * NEGATIVE CONTROLS, measured at n=12: perturbing s[0] by 0.5 is rejected as
 * `not-in-lattice(frac)`; Babai round-off using the PUBLIC basis produces a
 * lattice point that is rejected as `too-far`, with ||s-h||inf = 38.9 against a
 * bound of 24.0. The verifier bites on both axes, which is what makes it a
 * referee and not a rubber stamp.
 *
 * FAIRNESS ACROSS SIGNERS. `boundInf` is a property of the signer, published with
 * its key, not a constant of the lab: a round-off signer publishes
 * `roundOffBoundInf(R)` (sign.ts) and a Klein signer publishes
 * `kleinBoundInf(sigma)` (klein.ts), which is about 4x larger. Measured against
 * its OWN published bound each signer verifies 200/200, so the C5' comparison is
 * between two valid schemes rather than between a scheme and a straw man. What
 * makes the forgery test still honest is that the bound is invariant under row
 * permutation and sign flips of R -- see `roundOffBoundInf` -- so the recovered
 * Rhat = P*D*R is graded against precisely the number the victim published.
 */

import type { Mat, Vec } from '../lattice/types';
import { inverse, maxAbsVec, rnd, roundVec, vecMat } from '../lattice/matrix';

/** Everything a verifier is allowed to know. */
export interface PublicKey {
  readonly n: number;
  /** The public basis. */
  readonly B: Mat;
  /** B^-1, computable by anyone from B. */
  readonly Binv: Mat;
  /** The signature norm bound published with the key. */
  readonly boundInf: number;
}

/** Build a `PublicKey` from the public basis and the signer's published bound. */
export function publicKey(B: Mat, boundInf: number): PublicKey {
  return { n: B.length, B, Binv: inverse(B), boundInf };
}

/** Why a verification failed, or 'ok'. */
export type VerifyReason = 'ok' | 'not-in-lattice(frac)' | 'not-in-lattice(remul)' | 'too-far';

export interface VerifyResult {
  readonly ok: boolean;
  readonly reason: VerifyReason;
  /** max_i |z_i - round(z_i)| for z = s*B^-1. */
  readonly fracMax: number;
  /** max_i |(round(z)*B - s)_i|: the exact re-multiplication residue. */
  readonly remul: number;
  /** ||s - h||inf. */
  readonly distInf: number;
  /** The bound it was measured against. */
  readonly boundInf: number;
}

/**
 * Lattice-membership tolerance. See the file header: measured worst residue
 * 8.19e-12, so this carries six orders of margin.
 */
export const LATTICE_TOL = 1e-6;

/**
 * Verify (h, s) against a public key. Public data only.
 *
 * Returns a result rather than throwing, because a rejected forgery is a result
 * the UI has to display -- and because the negative claims in this lab are
 * checked by reading `reason`, not by catching an exception.
 */
export function verify(pub: PublicKey, h: Vec, s: Vec, tol: number = LATTICE_TOL): VerifyResult {
  const { n, B, Binv, boundInf } = pub;

  const z = vecMat(s, Binv);
  let fracMax = 0;
  for (let i = 0; i < n; i++) {
    const f = Math.abs(z[i] - rnd(z[i]));
    if (f > fracMax) fracMax = f;
  }

  let distInf = 0;
  for (let i = 0; i < n; i++) {
    const d = Math.abs(s[i] - h[i]);
    if (d > distInf) distInf = d;
  }

  if (fracMax > tol) {
    return { ok: false, reason: 'not-in-lattice(frac)', fracMax, remul: NaN, distInf, boundInf };
  }

  // Exact statement of "s is in L(B)": the integer coordinates multiply back to s.
  // Scaled by |s| because the residue of a legitimate product grows with the
  // magnitude of the entries, while a non-lattice vector misses by order 1.
  const back = vecMat(roundVec(z), B);
  let remul = 0;
  for (let i = 0; i < n; i++) {
    const r = Math.abs(back[i] - s[i]);
    if (r > remul) remul = r;
  }
  if (remul > tol * Math.max(1, maxAbsVec(s))) {
    return { ok: false, reason: 'not-in-lattice(remul)', fracMax, remul, distInf, boundInf };
  }

  if (distInf > boundInf + tol) {
    return { ok: false, reason: 'too-far', fracMax, remul, distInf, boundInf };
  }

  return { ok: true, reason: 'ok', fracMax, remul, distInf, boundInf };
}
