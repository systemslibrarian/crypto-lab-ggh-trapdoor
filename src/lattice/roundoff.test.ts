/**
 * The boundary of invariant I2: what happens at EXACTLY 1/2.
 *
 * The rest of the I2 evidence is in lattice.test.ts, which measures the strict
 * criterion over hundreds of real ciphertexts. This file exists for the one case
 * those cannot reach: an error whose displacement lands exactly on the half-way
 * mark, where "round-off succeeds iff max|e*basisInv| < 1/2" stops being an iff.
 * Ties need exact cancellation, so they are constructed here on purpose, with a
 * basis whose inverse has exact binary entries and no floating-point slack.
 */

import { describe, expect, it } from 'vitest';
import type { Mat, Vec } from './types';
import { inverse, makeRng, vecMat } from './matrix';
import { gghKeygen } from './keygen';
import {
  decryptBound,
  encrypt,
  latticePointToMessage,
  randomMessage,
  roundOff,
  roundOffSucceedsExactly,
  tieCount,
} from './roundoff';

const mat = (rows: number[][]): Mat => rows.map((r) => Float64Array.from(r));

/**
 * A basis whose inverse is exact in binary: B = [[2,1],[0,2]] gives
 * B^-1 = [[1/2, -1/4],[0, 1/2]], so e = (1,0) displaces the coordinate vector by
 * exactly (1/2, -1/4). The tie is real, not a rounding artefact.
 */
const B = mat([
  [2, 1],
  [0, 2],
]);
const Binv = inverse(B);
const E_TIE = Float64Array.from([1, 0]);

/** c = z*B + e, the ciphertext whose lattice point has coordinate vector z. */
function ciphertextAt(z: number[]): Vec {
  const v = vecMat(Float64Array.from(z), B);
  return Float64Array.from(v, (x, i) => x + E_TIE[i]);
}

describe('the I2 boundary is a tie, not a verdict', () => {
  const x = vecMat(E_TIE, Binv);

  it('puts the displacement exactly on 1/2', () => {
    expect(Array.from(x)).toEqual([0.5, -0.25]);
    expect(tieCount(x)).toBe(1);
    // The bound reports 0.5, so `predictsSuccess` (strictly below) is false --
    // and that is the whole point: below the line it would be right either way.
    const bound = decryptBound(E_TIE, Binv, 1);
    expect(bound.actual).toBe(0.5);
    expect(bound.predictsSuccess).toBe(false);
  });

  it('SUCCEEDS at the tie when the error pushes the coordinate towards zero', () => {
    // x_0 = +1/2 with z_0 = -1: rnd(-0.5) = -1 = z_0, because rnd rounds half
    // AWAY from zero and -0.5 is on the far side. The point survives.
    const z = [-1, 3];
    const c = ciphertextAt(z);
    const recovered = roundOff(c, B, Binv);
    const truePoint = vecMat(Float64Array.from(z), B);
    expect(Array.from(recovered)).toEqual(Array.from(truePoint));
    expect(roundOffSucceedsExactly(x, Float64Array.from(z))).toBe(true);
    // ...while the strict bound said "not guaranteed". Sufficient, not necessary.
    expect(decryptBound(E_TIE, Binv, 1).predictsSuccess).toBe(false);
    // The message reads back exactly, so this is a real decryption, not a near miss.
    expect(Array.from(latticePointToMessage(recovered, Binv))).toEqual(z);
  });

  it('FAILS at the same 1/2 when the error pushes it away from zero', () => {
    // x_0 = +1/2 with z_0 = +1: rnd(1.5) = 2 != z_0. Same |x|, same basis, same
    // error -- only the integer coordinate changed, and the outcome flipped.
    const z = [1, 3];
    const c = ciphertextAt(z);
    const recovered = roundOff(c, B, Binv);
    const truePoint = vecMat(Float64Array.from(z), B);
    expect(Array.from(recovered)).not.toEqual(Array.from(truePoint));
    expect(roundOffSucceedsExactly(x, Float64Array.from(z))).toBe(false);
    expect(decryptBound(E_TIE, Binv, 1).predictsSuccess).toBe(false);
  });

  it('flips the other way for the mirror-image tie', () => {
    // x_0 = -1/2 succeeds iff z_0 >= 1 -- the mirror of the case above.
    const eMinus = Float64Array.from([-1, 0]);
    const xMinus = vecMat(eMinus, Binv);
    expect(Array.from(xMinus)).toEqual([-0.5, 0.25]);
    expect(roundOffSucceedsExactly(xMinus, Float64Array.from([1, 3]))).toBe(true);
    expect(roundOffSucceedsExactly(xMinus, Float64Array.from([-1, 3]))).toBe(false);
    // z_j = 0 is the third case: there is no "towards zero", so the tie is lost.
    expect(roundOffSucceedsExactly(xMinus, Float64Array.from([0, 3]))).toBe(false);
    expect(roundOffSucceedsExactly(x, Float64Array.from([0, 3]))).toBe(false);
  });

  it('is decided by the bound everywhere off the boundary', () => {
    // Strictly below: always recovers. Strictly above: never recovers, whatever
    // z is. Only the equality case needed z, which is why the strict form is
    // stated as sufficient rather than as an iff. B4 = [[4,1],[0,4]] keeps the
    // errors integral while moving the displacement off 1/2.
    const B4 = mat([
      [4, 1],
      [0, 4],
    ]);
    const B4inv = inverse(B4);
    for (const [e, z, expected] of [
      [[1, 0], [4, -2], true], // x = (0.25, -0.0625): below
      [[3, 0], [4, -2], false], // x = (0.75, -0.1875): above
      [[3, 0], [-4, -2], false], // above, and the sign of z cannot save it
      [[1, 0], [-4, -2], true],
    ] as const) {
      const ev = Float64Array.from(e);
      const zv = Float64Array.from(z);
      const xv = vecMat(ev, B4inv);
      const strict = Math.max(...Array.from(xv, Math.abs)) < 0.5;
      expect(tieCount(xv)).toBe(0);
      expect(roundOffSucceedsExactly(xv, zv)).toBe(expected);
      expect(strict).toBe(expected);
    }
  });

  it('never sees a tie on the shipped path, which is a measurement and not a proof', () => {
    // 3,000 real ciphertexts at the shipped parameters: the exact criterion and
    // the strict bound agree every time, because no coordinate ever lands on 1/2.
    let ties = 0;
    let checked = 0;
    for (const n of [8, 16]) {
      const rng = makeRng(n * 101 + 7);
      const key = gghKeygen(n, { rng });
      const Rinv = inverse(key.R);
      const Binv2 = inverse(key.B);
      for (let t = 0; t < 750; t++) {
        const m = randomMessage(n, rng);
        const { e } = encrypt(m, key.B, rng);
        for (const inv of [Rinv, Binv2]) {
          const xv = vecMat(e, inv);
          ties += tieCount(xv);
          const z = latticePointToMessage(vecMat(m, key.B), inv);
          expect(roundOffSucceedsExactly(xv, z)).toBe(decryptBound(e, inv).predictsSuccess);
          checked++;
        }
      }
    }
    expect(checked).toBe(3000);
    expect(ties).toBe(0);
  });
});
