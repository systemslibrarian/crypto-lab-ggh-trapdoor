/**
 * The REAL signature verifier -- and it fails closed.
 *
 * This module is the referee for invariant I5: every "the attack succeeded"
 * claim in the lab has to come back through here. It therefore gets to see
 * exactly what a verifier in the field sees and nothing else:
 *
 *   - B, the public basis (and HNF(B), which anyone can compute from it);
 *   - `boundInf`, the norm published alongside the public key;
 *   - the pair (h, s) being checked.
 *
 * It never sees R, never sees the attack's internal state, and never compares
 * anything to a secret. A forgery is accepted or rejected on the same two tests a
 * genuine signature faces:
 *
 *   (a) s lies in the lattice L(B)  -- decided EXACTLY, in BigInt, by forward
 *       substitution against HNF(B);
 *   (b) ||s - h||inf <= boundInf    -- s is close enough to the hashed point.
 *
 * A trust boundary that assumes well-formed input is not a trust boundary. So
 * every input is validated before any arithmetic runs, and the answer to
 * anything malformed is a rejection with a machine-readable reason. NaN is the
 * specific hazard that motivated this: every comparison against NaN is false, so
 * a verifier written as a chain of `if (x > limit) reject` accepts NaN by
 * construction. Nothing here rejects by falling through.
 *
 * WHY MEMBERSHIP IS EXACT AND NOT A TOLERANCE.
 *
 * The retired test was float: z = s*B^-1 had to round to integers within 1e-6,
 * and then round(z)*B had to reproduce s within 1e-6 * max|s|. That second
 * tolerance is the flaw -- it GROWS with the signature, so a large enough s buys
 * itself slack the verifier never agreed to give. Measured at n=12, the vector
 * s = 1e17 * e_0 missed the lattice by a re-multiplication residue of 2.69e3 and
 * was accepted anyway, because at that magnitude the scaled tolerance had opened
 * to 1.0e11. `verify.test.ts` runs the retired rule beside the current one and
 * pins that, so the regression cannot come back quietly.
 *
 * The float margin also shrinks with dimension, which the old note (drawn from
 * n <= 16) could not show: over 100 signatures per dimension with the shipped
 * keygen, the worst residue in s*B^-1 is 4.00e-11 at n=8, 1.62e-10 at n=16 and
 * 7.19e-10 at n=60 -- 88x the 8.19e-12 that was quoted, and still climbing.
 *
 * So the decision is not a tolerance any more. HNF(B) is upper triangular, so the
 * coordinates of s are forced one at a time by forward substitution, and s is in
 * L(B) if and only if every forced quotient is an exact integer -- see
 * `coordinatesInHnf` in hnf.ts. That is an exact integer statement with no
 * epsilon in it at all. Measured cost of that call alone: 1.7 us at n=8, 2.6 us
 * at n=16, 15.0 us at n=60.
 *
 * The exactness claim is only as good as the Number -> BigInt boundary, so that
 * boundary REFUSES rather than rounds: s is admitted only if every entry is an
 * exact integer within +-2^53 (`Number.isSafeInteger`), which is exactly the set
 * `toBigVec` will convert. An integral double of magnitude 1e17 is not that
 * integer any more, and it is rejected as out of domain rather than lifted into
 * a BigInt that would make the wrong answer look exact.
 *
 * WHY A NON-INTEGER s IS `not-in-lattice(frac)` AND NOT A MALFORMED INPUT.
 * B is an integer matrix, so L(B) is a subset of Z^n. A finite non-integer
 * vector inside the accepted domain is therefore PROVED not to be a lattice
 * point -- that is mathematics, not malformedness, and it keeps the reason string
 * the float path used for the same situation.
 *
 * WHAT THE TOLERANCE STILL DOES.
 *
 * Only one thing: it is the slack on the distance test, `distInf <= boundInf +
 * tol`. It is a fixed absolute number over a bounded accepted domain, and it is
 * validated (0 < tol <= MAX_TOL, and `boundInf + tol > boundInf` so the slack it
 * promises actually exists at that bound's precision). It cannot decide a real
 * case: measured over both diagonal-shift rules, 5 keys per cell at n = 8, 12,
 * 16, 32 and 60, the smallest bound seen was 14.0 (round-off, GGH's k, n=8), and
 * MAX_TOL is 1e-3 -- four orders below it.
 *
 * The distance test is float, and it is honest about it. Both operands are
 * finite and within +-2^53, IEEE subtraction is correctly rounded, and the only
 * place rounding can change the verdict is at the comparison itself, where the
 * computed value is within an ulp of `boundInf`. `MAX_BOUND_INF` = 1e6 caps that
 * ulp at 1.2e-10. The largest bound the lab actually publishes is 653.6 (Klein,
 * n=60, measured), where the ulp is 1.1e-13 -- seven orders below the default
 * tolerance.
 *
 * COST, measured over 200 signatures per dimension with the shipped keygen:
 *
 *     n                8      12     16     32     60
 *     publicKey() ms   0.07   0.27   0.62   5.3    43.7
 *     verify() us      2.9    5.6    7.7    20.6   48.5
 *
 * `publicKey()` builds and PROVES the HNF once per key; verify() is O(n^2) after
 * that. A key is made once and verified against hundreds of times -- Break 2
 * alone calls verify 20 times per rung -- so this is the right place for the
 * work, and it is why the HNF is not rebuilt inside verify(). 43.7 ms at n=60 is
 * a one-shot key operation off the main thread (the attack runs in a worker), not
 * a per-frame cost.
 *
 * WHAT publicKey() PROVES, so that `H` is not taken on faith: HNF(B) is in
 * Hermite normal form (`isHnf`), its diagonal multiplies to |det B| (so L(H) and
 * L(B) have the same covolume), and every row of B has exact integer coordinates
 * in H (so L(B) is a subset of L(H)). Equal covolume plus containment is lattice
 * equality, so membership in L(H) IS membership in L(B). All three checks are
 * exact BigInt; none of them is a tolerance.
 *
 * NEGATIVE CONTROLS, measured on the n=12 fixture in verify.test.ts (GGH's own
 * k, seed 4242): perturbing s[0] by 0.5 is rejected as `not-in-lattice(frac)`;
 * Babai round-off using the PUBLIC basis produces a genuine lattice point that is
 * rejected as `too-far`, with ||s-h||inf = 114.3 against a published bound of
 * 22.5. The verifier bites on both axes, which is what makes it a referee and not
 * a rubber stamp.
 *
 * FAIRNESS ACROSS SIGNERS. `boundInf` is a property of the signer, published with
 * its key, not a constant of the lab: a round-off signer publishes
 * `roundOffBoundInf(R)` (sign.ts) and a Klein signer publishes
 * `kleinBoundInf(sigma)` (klein.ts), which is about 4x larger. Measured through
 * this hardened path at each of n = 8, 12, 16, 32 and 60, round-off verifies
 * 200/200 and Klein 100/100 against its own bound, so the C5' comparison is
 * between two valid schemes rather than between a scheme and a straw man. What
 * makes the forgery test still honest is that the bound is invariant under row
 * permutation and sign flips of R -- see `roundOffBoundInf` -- so the recovered
 * Rhat = P*D*R is graded against precisely the number the victim published.
 */

import type { Mat, Vec } from '../lattice/types';
import type { BigMat, BigVec } from '../lattice/hnf';
import { TWO53, inverse, rnd, roundVec, vecMat } from '../lattice/matrix';
import {
  asBigMat,
  bigDet,
  coordinatesInHnf,
  hnf,
  hnfDeterminant,
  isHnf,
  toBigVec,
} from '../lattice/hnf';

/**
 * Why a public key cannot verify anything, or 'ok'.
 *
 * Separate from the rest of `VerifyReason` because these are properties of the
 * KEY, decided once in `publicKey()`, not of the signature being checked. A
 * verifier holding one of these can never accept anything, and says which one.
 */
export type KeyReason =
  | 'ok'
  /** n is not a positive safe integer -- includes the empty basis. */
  | 'bad-key(dimension)'
  /** B is not n x n: non-square, ragged, or a missing row. */
  | 'bad-key(shape)'
  /** Some entry of B is not an exact integer within +-2^53 (NaN and Infinity land here). */
  | 'bad-key(entries)'
  /** det B = 0, so the rows of B do not span a full-rank lattice and have no HNF. */
  | 'bad-key(singular)'
  /** HNF(B) could not be built, or failed its own shape / same-lattice proof. */
  | 'bad-key(hnf)'
  /** The published bound is not finite, is negative, or exceeds MAX_BOUND_INF. */
  | 'bad-key(bound)';

/** Why a verification failed, or 'ok'. */
export type VerifyReason =
  | KeyReason
  /** tol is not finite, not positive, above MAX_TOL, or too small to exist at this bound. */
  | 'bad-tolerance'
  /** h or s does not have length exactly n -- empty, short, long, or mismatched. */
  | 'bad-vector(length)'
  /** h or s contains NaN, Infinity or -Infinity. */
  | 'bad-vector(nonfinite)'
  /** h or s has an entry outside +-2^53, where a double is no longer an exact integer. */
  | 'bad-vector(domain)'
  /** s is not in L(B): some exact coordinate of s in HNF(B) is not an integer. */
  | 'not-in-lattice(frac)'
  /** The recovered coordinates do not multiply back to s exactly. */
  | 'not-in-lattice(remul)'
  /** ||s - h||inf exceeds the published bound. */
  | 'too-far';

/**
 * Everything a verifier is allowed to know.
 *
 * `publicKey()` is the only supported constructor: it is where B is validated and
 * where H is bound to B by an exact proof. Assembling this object by hand skips
 * that proof, and verify() re-checks everything it can re-check in O(n^2) --
 * dimensions, shape, integrality, H's triangular diagonal, the bound -- but it
 * cannot re-derive HNF(B) on every call and does not pretend to.
 */
export interface PublicKey {
  readonly n: number;
  /** The public basis. */
  readonly B: Mat;
  /**
   * B^-1, computable by anyone from B. DIAGNOSTIC ONLY: it feeds the reported
   * float residues and decides nothing. null if B could not be inverted in
   * floating point, which does not stop the exact test.
   */
  readonly Binv: Mat | null;
  /** The signature norm bound published with the key. */
  readonly boundInf: number;
  /**
   * HNF(B) in exact BigInt -- the triangular basis membership is decided against.
   * null exactly when `keyReason` is not 'ok'.
   */
  readonly H: BigMat | null;
  /** 'ok', or why this key can never verify anything. */
  readonly keyReason: KeyReason;
  /** Which row, which entry, which check -- empty when `keyReason` is 'ok'. */
  readonly keyDetail: string;
}

export interface VerifyResult {
  readonly ok: boolean;
  readonly reason: VerifyReason;
  /** Which coordinate, which value, which limit. Empty when `reason` is 'ok'. */
  readonly detail: string;
  /**
   * max_i |z_i - round(z_i)| for z = s*B^-1. DIAGNOSTIC: reported because it is
   * the number the float verifier used to decide on, and watching it grow with n
   * is the argument for why the decision is now exact. NaN when it could not be
   * computed.
   */
  readonly fracMax: number;
  /** max_i |(round(z)*B - s)_i|, the float re-multiplication residue. DIAGNOSTIC. */
  readonly remul: number;
  /** ||s - h||inf. */
  readonly distInf: number;
  /** The bound it was measured against. */
  readonly boundInf: number;
}

/**
 * Default slack on the distance test.
 *
 * NOT a membership tolerance -- membership is exact (see the file header) and
 * this number cannot move it. 1e-6 sits seven orders below the smallest bound the
 * lab publishes (14.0) and seven orders above the ulp of the largest (1.1e-13 at
 * boundInf = 653.6), so it absorbs float subtraction without ever being the thing
 * that decides.
 */
export const LATTICE_TOL = 1e-6;

/**
 * Largest tolerance the verifier will accept from a caller.
 *
 * A tolerance is slack granted to the signature, so an unbounded one is a way to
 * turn the distance test off. 1e-3 is four orders below the smallest published
 * bound measured anywhere in this lab (14.0: round-off, GGH's k, n=8, over 5 keys
 * per cell at n = 8..60 under both diagonal-shift rules); a caller asking for
 * more is asking to change the scheme, and the verifier refuses.
 */
export const MAX_TOL = 1e-3;

/**
 * Largest published bound the verifier will accept.
 *
 * The bound sets the scale at which the distance comparison happens, and a double
 * near 1e6 is spaced 1.2e-10 apart -- four orders below the default tolerance, so
 * the comparison still means what it says at the cap. The largest bound this lab
 * publishes is 653.6 (Klein, n=60, measured), so this is three orders of
 * headroom, not a constraint on anything real.
 */
export const MAX_BOUND_INF = 1e6;

/** |x| for bigint. Local because hnf.ts keeps its own copy private. */
function babs(x: bigint): bigint {
  return x < 0n ? -x : x;
}

/**
 * Build a `PublicKey` from the public basis and the signer's published bound.
 *
 * Never throws: a basis that cannot verify is a RESULT the UI has to be able to
 * display, exactly like a rejected signature. The fault is recorded in
 * `keyReason` and every later verify() with this key returns it.
 *
 * Does the O(n^3) work once -- the HNF and the proof that binds it to B -- so
 * that verify() is O(n^2). Measured end to end: 0.07 ms at n=8, 0.62 ms at n=16,
 * 43.7 ms at n=60.
 */
export function publicKey(B: Mat, boundInf: number): PublicKey {
  const n = (B as Mat | undefined)?.length ?? 0;
  const fail = (keyReason: KeyReason, keyDetail: string): PublicKey => ({
    n,
    B,
    Binv: null,
    boundInf,
    H: null,
    keyReason,
    keyDetail,
  });

  if (!Number.isSafeInteger(n) || n < 1) {
    return fail('bad-key(dimension)', `the basis has ${n} rows; n must be a positive integer`);
  }
  for (let i = 0; i < n; i++) {
    const row = B[i] as Vec | undefined;
    if (row === undefined || row.length !== n) {
      return fail(
        'bad-key(shape)',
        `row ${i} has length ${row === undefined ? 'none' : row.length}, but the basis must be ${n} x ${n}`,
      );
    }
    for (let j = 0; j < n; j++) {
      if (!Number.isSafeInteger(row[j])) {
        return fail(
          'bad-key(entries)',
          `B[${i}][${j}] = ${row[j]} is not an exact integer within +-2^53`,
        );
      }
    }
  }
  if (!Number.isFinite(boundInf) || boundInf < 0 || boundInf > MAX_BOUND_INF) {
    return fail(
      'bad-key(bound)',
      `published bound ${boundInf} must be finite and in [0, ${MAX_BOUND_INF}]`,
    );
  }

  // The determinant is computed here as well as inside hnf() so that a singular
  // basis gets its own reason instead of arriving as a caught exception.
  // Measured 0.01 ms at n=8 and 8.1 ms at n=60, once per key.
  const Bb = asBigMat(B);
  const det = bigDet(Bb);
  if (det === 0n) {
    return fail('bad-key(singular)', 'det B = 0, so the rows of B are not a basis of a full-rank lattice');
  }

  let H: BigMat;
  try {
    H = hnf(Bb).H;
  } catch (e) {
    return fail('bad-key(hnf)', `HNF(B) could not be built: ${e instanceof Error ? e.message : String(e)}`);
  }

  // H is the thing every later decision rests on, so it is proved, not assumed.
  // Shape, then equal covolume, then L(B) contained in L(H): containment plus
  // equal determinant is lattice equality, so membership in L(H) IS membership
  // in L(B). Exact BigInt throughout -- there is no tolerance in this proof.
  if (H.length !== n || !isHnf(H)) {
    return fail('bad-key(hnf)', 'HNF(B) is not in Hermite normal form under hnf.ts conventions');
  }
  if (hnfDeterminant(H) !== babs(det)) {
    return fail('bad-key(hnf)', 'the HNF diagonal does not multiply to |det B|, so L(H) is not L(B)');
  }
  for (let i = 0; i < n; i++) {
    if (coordinatesInHnf(H, toBigVec(B[i])) === null) {
      return fail('bad-key(hnf)', `row ${i} of B is not in L(HNF(B)), so the two lattices differ`);
    }
  }

  // Float inverse, for the reported diagnostics only. A basis can be exactly
  // non-singular and still defeat Gauss-Jordan, and that must not stop the
  // exact test, so a failure here is recorded as "no diagnostic", not a fault.
  let Binv: Mat | null = null;
  try {
    Binv = inverse(B);
  } catch {
    Binv = null;
  }

  return { n, B, Binv, boundInf, H, keyReason: 'ok', keyDetail: '' };
}

/**
 * Verify (h, s) against a public key. Public data only.
 *
 * Returns a result rather than throwing, because a rejected forgery is a result
 * the UI has to display -- and because the negative claims in this lab are
 * checked by reading `reason`, not by catching an exception.
 *
 * ORDER IS PART OF THE CONTRACT. Everything structural is settled before any
 * arithmetic: key, bound, tolerance, then vector lengths, then finiteness, then
 * the accepted domain. Only then does the mathematics run, and by then every
 * value it touches is a finite double inside +-2^53. Nothing is decided by a
 * comparison that a NaN could sneak past.
 */
export function verify(pub: PublicKey, h: Vec, s: Vec, tol: number = LATTICE_TOL): VerifyResult {
  const boundInf = pub.boundInf;
  const bad = (reason: VerifyReason, detail: string): VerifyResult => ({
    ok: false,
    reason,
    detail,
    fracMax: NaN,
    remul: NaN,
    distInf: NaN,
    boundInf,
  });

  // --- the key -------------------------------------------------------------
  if (pub.keyReason !== 'ok') return bad(pub.keyReason, pub.keyDetail);

  const n = pub.n;
  if (!Number.isSafeInteger(n) || n < 1) {
    return bad('bad-key(dimension)', `n = ${n} must be a positive integer`);
  }
  const B = pub.B;
  if (((B as Mat | undefined)?.length ?? 0) !== n) {
    return bad('bad-key(shape)', `the basis has ${(B as Mat | undefined)?.length ?? 0} rows, expected n = ${n}`);
  }
  for (let i = 0; i < n; i++) {
    const row = B[i] as Vec | undefined;
    if (row === undefined || row.length !== n) {
      return bad(
        'bad-key(shape)',
        `row ${i} has length ${row === undefined ? 'none' : row.length}, but the basis must be ${n} x ${n}`,
      );
    }
    for (let j = 0; j < n; j++) {
      if (!Number.isSafeInteger(row[j])) {
        return bad('bad-key(entries)', `B[${i}][${j}] = ${row[j]} is not an exact integer within +-2^53`);
      }
    }
  }

  // H is only trusted as far as it can be re-checked in O(n^2): square, and a
  // strictly positive diagonal. The diagonal check is not cosmetic -- forward
  // substitution divides by H[j][j], and a zero pivot would throw rather than
  // answer.
  const H = pub.H;
  if (H === null || H.length !== n) {
    return bad('bad-key(hnf)', `HNF(B) is ${H === null ? 'missing' : `${H.length} x ?`}, expected ${n} x ${n}`);
  }
  for (let i = 0; i < n; i++) {
    const row = H[i] as BigVec | undefined;
    if (row === undefined || row.length !== n) {
      return bad('bad-key(hnf)', `HNF row ${i} has length ${row === undefined ? 'none' : row.length}, expected ${n}`);
    }
    if (row[i] <= 0n) return bad('bad-key(hnf)', `HNF pivot ${i} is ${row[i]}, but every pivot must be positive`);
  }

  if (!Number.isFinite(boundInf) || boundInf < 0 || boundInf > MAX_BOUND_INF) {
    return bad('bad-key(bound)', `published bound ${boundInf} must be finite and in [0, ${MAX_BOUND_INF}]`);
  }

  // --- the tolerance -------------------------------------------------------
  if (!Number.isFinite(tol) || tol <= 0 || tol > MAX_TOL) {
    return bad('bad-tolerance', `tolerance ${tol} must be finite and in (0, ${MAX_TOL}]`);
  }
  if (!(boundInf + tol > boundInf)) {
    // A slack smaller than the spacing of doubles at `boundInf` vanishes when it
    // is added. Silently granting nothing is worse than refusing.
    return bad('bad-tolerance', `tolerance ${tol} is below the spacing of doubles at boundInf = ${boundInf}`);
  }

  // --- the vectors ---------------------------------------------------------
  const hLen = (h as Vec | undefined)?.length;
  const sLen = (s as Vec | undefined)?.length;
  if (hLen !== n) return bad('bad-vector(length)', `h has length ${hLen ?? 'none'}, expected n = ${n}`);
  if (sLen !== n) return bad('bad-vector(length)', `s has length ${sLen ?? 'none'}, expected n = ${n}`);

  for (let i = 0; i < n; i++) {
    if (!Number.isFinite(h[i])) return bad('bad-vector(nonfinite)', `h[${i}] = ${h[i]}`);
    if (!Number.isFinite(s[i])) return bad('bad-vector(nonfinite)', `s[${i}] = ${s[i]}`);
    // Past +-(2^53 - 1) the doubles are spaced more than 1 apart: the "point" is
    // quantised more coarsely than the lattice it is being tested against, and
    // the Number -> BigInt lift would stop being exact. Refuse rather than round.
    if (Math.abs(h[i]) > TWO53) {
      return bad('bad-vector(domain)', `|h[${i}]| = ${Math.abs(h[i])} is outside the exact domain +-${TWO53}`);
    }
    if (Math.abs(s[i]) > TWO53) {
      return bad('bad-vector(domain)', `|s[${i}]| = ${Math.abs(s[i])} is outside the exact domain +-${TWO53}`);
    }
  }

  // --- diagnostics, which decide nothing -----------------------------------
  let fracMax = NaN;
  let remul = NaN;
  const Binv = pub.Binv;
  if (Binv !== null) {
    try {
      const z = vecMat(s, Binv);
      let f = 0;
      for (let i = 0; i < n; i++) {
        const d = Math.abs(z[i] - rnd(z[i]));
        if (d > f) f = d;
      }
      const back = vecMat(roundVec(z), B);
      let r = 0;
      for (let i = 0; i < n; i++) {
        const d = Math.abs(back[i] - s[i]);
        if (d > r) r = d;
      }
      fracMax = f;
      remul = r;
    } catch {
      // A malformed Binv costs the display numbers and nothing else.
    }
  }

  let distInf = 0;
  for (let i = 0; i < n; i++) {
    const d = Math.abs(s[i] - h[i]);
    if (d > distInf) distInf = d;
  }

  const out = (reason: VerifyReason, detail: string): VerifyResult => ({
    ok: reason === 'ok',
    reason,
    detail,
    fracMax,
    remul,
    distInf,
    boundInf,
  });

  // --- (a) is s in L(B)? Exactly. -----------------------------------------
  // B is an integer matrix, so L(B) is a subset of Z^n: a non-integer entry is a
  // proof of non-membership. This is the cheap half of the same statement, and
  // it is what makes `toBigVec` below safe.
  for (let i = 0; i < n; i++) {
    if (!Number.isInteger(s[i])) {
      return out('not-in-lattice(frac)', `s[${i}] = ${s[i]} is not an integer, and L(B) is a subset of Z^n`);
    }
  }

  let x: BigVec | null;
  let sBig: BigVec;
  try {
    sBig = toBigVec(s);
    x = coordinatesInHnf(H, sBig);
  } catch (e) {
    // Unreachable given the validation above -- every entry is a safe integer and
    // every pivot is positive. If it ever fires, the answer is a rejection.
    return out('bad-key(hnf)', `the exact membership test failed: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (x === null) {
    return out('not-in-lattice(frac)', 'the exact coordinates of s in HNF(B) are not all integers');
  }

  // Re-multiply and compare entry for entry, exactly. Redundant by the forward
  // substitution's own theorem when H really is triangular -- and that is the
  // point: it is the check that does NOT assume the triangularity every other
  // step took on trust. The inner loop therefore runs over the whole column
  // rather than the upper triangle.
  const back: bigint[] = new Array<bigint>(n).fill(0n);
  for (let i = 0; i < n; i++) {
    const xi = x[i];
    if (xi === 0n) continue;
    const Hi = H[i];
    for (let j = 0; j < n; j++) back[j] += xi * Hi[j];
  }
  for (let j = 0; j < n; j++) {
    if (back[j] !== sBig[j]) {
      return out('not-in-lattice(remul)', `x*H differs from s at coordinate ${j}: ${back[j]} vs ${sBig[j]}`);
    }
  }

  // --- (b) is s close enough to h? ----------------------------------------
  if (distInf > boundInf + tol) {
    return out('too-far', `||s-h||inf = ${distInf} exceeds the published bound ${boundInf}`);
  }

  return out('ok', '');
}
