/**
 * Tests for the Hermite normal form public key.
 *
 * The load-bearing test in this file is `HNF(R) === HNF(U*R)`. Canonicity is the
 * single most teachable fact about the HNF and the entire reason Micciancio
 * proposes it as a public key, so it is asserted entry for entry on two bases of
 * the same lattice at every dimension the lab offers -- never claimed in prose.
 *
 * Everything is seeded through `makeRng`, so a failure here is reproducible.
 */

import { describe, expect, it } from 'vitest';
import { makeRng } from './matrix';
import { gghKeygen } from './keygen';
import type { BigMat } from './hnf';
import {
  asBigMat,
  bigDet,
  bigEye,
  bigFitsInNumber,
  bigIsIdentity,
  bigMatEq,
  bigMatmul,
  bigMaxAbs,
  bitsOfUpperTriangle,
  compareCiphertextSize,
  compareKeySize,
  coordinatesInHnf,
  estimateHnfMs,
  fromBigMat,
  hnf,
  hnfDeterminant,
  HNF_BENEFITS,
  HNF_MAIN_THREAD_BUDGET_MS,
  isHnf,
  MEASURED_HNF_MS,
  proveSameLatticeHnf,
  reduceModHnf,
  toBigMat,
} from './hnf';

/** The dimensions the lab's slider offers, sampled at both ends and the middle. */
const DIMS = [8, 16, 32, 60] as const;

const babs = (x: bigint): bigint => (x < 0n ? -x : x);

/** A deterministic key at dimension n. */
function key(n: number, seed: number) {
  return gghKeygen(n, { rng: makeRng(seed) });
}

/**
 * A third basis of the same lattice, built by unimodular row operations in
 * BigInt so the test never has to worry about Number overflow of its own making.
 */
function scramble(B: BigMat, seed: number): BigMat {
  const n = B.length;
  const V = bigEye(n);
  const rng = makeRng(seed);
  for (let s = 0; s < 4 * n; s++) {
    const i = Math.floor(rng() * n);
    let j = Math.floor(rng() * (n - 1));
    if (j >= i) j++;
    const c = rng() < 0.5 ? 1n : -1n;
    for (let t = 0; t < n; t++) V[i][t] += c * V[j][t];
  }
  return bigMatmul(V, B);
}

describe('HNF conventions', () => {
  it('is upper triangular with positive pivots and entries above each pivot reduced', () => {
    for (const n of DIMS) {
      const { H, pivots } = hnf(key(n, 1000 + n).B);
      for (let i = 0; i < n; i++) {
        expect(H[i][i]).toBe(pivots[i]);
        expect(H[i][i] > 0n).toBe(true);
        for (let j = 0; j < i; j++) {
          // below the diagonal: exactly zero
          expect(H[i][j]).toBe(0n);
          // above the pivot in column i: reduced into [0, H[i][i])
          expect(H[j][i] >= 0n).toBe(true);
          expect(H[j][i] < H[i][i]).toBe(true);
        }
      }
      expect(isHnf(H)).toBe(true);
    }
  });

  it('leaves a matrix that is already in Hermite normal form alone', () => {
    // diag(3, 5, 7) is upper triangular with positive diagonal and nothing above
    // a pivot to reduce, so it is its own HNF. If the elimination "normalised"
    // anything here it would be doing something the lattice did not ask for.
    const D: BigMat = [
      [3n, 0n, 0n],
      [0n, 5n, 0n],
      [0n, 0n, 7n],
    ];
    expect(isHnf(D)).toBe(true);
    expect(bigMatEq(hnf(D).H, D)).toBe(true);
  });

  it('reduces a unimodular basis to the identity, because it spans all of Z^n', () => {
    const U: BigMat = [
      [1n, 2n, 3n],
      [0n, 1n, 4n],
      [5n, 6n, 0n],
    ];
    expect(babs(bigDet(U))).toBe(1n);
    expect(bigMatEq(hnf(U).H, bigEye(3))).toBe(true);
  });

  it('matches a hand-computable 2x2 case', () => {
    // Rows (2,1) and (1,3), determinant 5. Clearing column 0 with gcd(2,1) = 1
    // gives (1,3) and 2*(1,3) - (2,1) = (0,5); reducing 3 mod 5 leaves it at 3.
    const A: BigMat = [
      [2n, 1n],
      [1n, 3n],
    ];
    const { H, d } = hnf(A);
    expect(H).toEqual([
      [1n, 3n],
      [0n, 5n],
    ]);
    expect(d).toBe(5n);
  });
});

describe('HNF is canonical', () => {
  it('HNF(R) === HNF(U*R) entry for entry, at every dimension', () => {
    for (const n of DIMS) {
      const k = key(n, 31337 + n);
      const hR = hnf(k.R);
      const hB = hnf(k.B);
      // The two bases are genuinely different matrices...
      expect(bigMatEq(toBigMat(k.R), toBigMat(k.B))).toBe(false);
      // ...and their Hermite normal forms are the same matrix.
      expect(hR.H).toEqual(hB.H);
      expect(hR.d).toBe(hB.d);
    }
  });

  it('a third basis of the same lattice gives the same HNF again', () => {
    for (const n of [8, 16, 32] as const) {
      const k = key(n, 5150 + n);
      const expected = hnf(k.R).H;
      const C = scramble(toBigMat(k.B), 909 + n);
      // The scrambled basis really is different and really is unimodular-equivalent.
      expect(bigMatEq(C, toBigMat(k.B))).toBe(false);
      expect(babs(bigDet(C))).toBe(babs(bigDet(toBigMat(k.R))));
      expect(hnf(C).H).toEqual(expected);
    }
  });

  it('the HNF costs the same to store whichever basis it came from', () => {
    // This is the canonicity claim restated as the size claim: the serialised
    // length of the public key stops depending on how the key was generated.
    const n = 32;
    const k = key(n, 777);
    const H = hnf(k.R).H;
    const viaR = compareKeySize(k.R, H);
    const viaB = compareKeySize(k.B, H);
    expect(viaR.hnfBits).toBe(viaB.hnfBits);
    expect(viaR.basisBits).not.toBe(viaB.basisBits);
    expect(bitsOfUpperTriangle(hnf(k.B).H)).toBe(viaR.hnfBits);
  });
});

describe('HNF spans the same lattice, proved in BigInt', () => {
  it('proves both inclusions and the unimodularity of the transform', () => {
    for (const n of DIMS) {
      const k = key(n, 4242 + n);
      const R = toBigMat(k.R);
      const { H } = hnf(R);
      const proof = proveSameLatticeHnf(R, H);
      expect(proof.checks).toEqual({
        hnfShape: true,
        determinantsMatch: true,
        tIsIntegral: true,
        tTimesREqualsH: true,
        sIsIntegral: true,
        sTimesHEqualsR: true,
        tTimesSIsIdentity: true,
      });
      expect(proof.ok).toBe(true);
      // The transforms are real matrices, re-checked here rather than trusted.
      expect(proof.T).not.toBeNull();
      expect(proof.S).not.toBeNull();
      expect(bigMatEq(bigMatmul(proof.T as BigMat, R), H)).toBe(true);
      expect(bigMatEq(bigMatmul(proof.S as BigMat, H), R)).toBe(true);
      expect(bigIsIdentity(bigMatmul(proof.T as BigMat, proof.S as BigMat))).toBe(true);
    }
  });

  it('proves it against the public basis too', () => {
    const k = key(16, 606);
    const B = toBigMat(k.B);
    expect(proveSameLatticeHnf(B, hnf(B).H).ok).toBe(true);
  });

  it('rejects a sublattice that is not the lattice, without throwing', () => {
    // Doubling the LAST row doubles the last pivot, which is the only one bigger
    // than 1. The result is still a valid Hermite normal form -- upper triangular,
    // positive diagonal, everything above the pivot still inside [0, 2d) -- but it
    // is the HNF of an index-2 sublattice. Every one of its rows is still in L(R),
    // so the T side passes and only the R side catches it. That is exactly the
    // case a one-directional check would wave through, which is why both
    // inclusions are computed.
    const k = key(16, 808);
    const R = toBigMat(k.R);
    const { H } = hnf(R);
    const n = H.length;
    const fake: BigMat = H.map((row, i) => (i === n - 1 ? row.map((v) => v * 2n) : row.slice()));
    expect(isHnf(fake)).toBe(true);
    const proof = proveSameLatticeHnf(R, fake);
    expect(proof.checks.tIsIntegral).toBe(true);
    expect(proof.checks.tTimesREqualsH).toBe(true);
    expect(proof.checks.sIsIntegral).toBe(false);
    expect(proof.checks.determinantsMatch).toBe(false);
    expect(proof.ok).toBe(false);
    expect(proof.reason).toMatch(/integer combination/);
  });

  it('rejects a matrix that is not in Hermite normal form', () => {
    const k = key(8, 909);
    const R = toBigMat(k.R);
    const { H } = hnf(R);
    const notReduced: BigMat = H.map((row) => row.slice());
    notReduced[0][H.length - 1] += H[H.length - 1][H.length - 1]; // push it out of [0, pivot)
    const proof = proveSameLatticeHnf(R, notReduced);
    expect(proof.ok).toBe(false);
    expect(proof.checks.hnfShape).toBe(false);
  });

  it('reports a singular basis instead of throwing', () => {
    const singular: BigMat = [
      [1n, 2n],
      [2n, 4n],
    ];
    expect(bigDet(singular)).toBe(0n);
    expect(() => hnf(singular)).toThrow(/singular/);
    const proof = proveSameLatticeHnf(singular, bigEye(2));
    expect(proof.ok).toBe(false);
  });
});

describe('the HNF diagonal multiplies to |det R|', () => {
  it('holds at every dimension, against an independent Bareiss determinant', () => {
    for (const n of DIMS) {
      const k = key(n, 2024 + n);
      const R = toBigMat(k.R);
      const { H, d, det, pivots } = hnf(R);
      const bareiss = babs(bigDet(R));
      expect(d).toBe(bareiss);
      expect(babs(det)).toBe(bareiss);
      expect(hnfDeterminant(H)).toBe(bareiss);
      // and the same number reached a third way, straight off the pivots
      let product = 1n;
      for (const p of pivots) product *= p;
      expect(product).toBe(bareiss);
      // det(B) = +-det(R) because U is unimodular -- an independent cross-check
      expect(babs(bigDet(toBigMat(k.B)))).toBe(bareiss);
    }
  });

  it('is a genuinely enormous number, which is why this file uses BigInt', () => {
    // n=60 at the shipped keygen: |det| is around 10^113.5, which is 97.6 orders of
    // magnitude past 2^53. If this ever fits in a double, the parameters changed.
    const { d } = hnf(key(60, 60).B);
    expect(d.toString().length).toBeGreaterThan(100);
    expect(d > BigInt(Number.MAX_SAFE_INTEGER)).toBe(true);
  });
});

describe('the Number conversion guard', () => {
  it('refuses an entry that exceeds 2^53 and accepts one that does not', () => {
    const tooBig: BigMat = [[BigInt(Number.MAX_SAFE_INTEGER) + 1n]];
    const justFits: BigMat = [[BigInt(Number.MAX_SAFE_INTEGER), -5n]];
    expect(bigFitsInNumber(tooBig)).toBe(false);
    expect(bigFitsInNumber(justFits)).toBe(true);
    expect(() => fromBigMat(tooBig)).toThrow(/exceeds 2\^53/);
    expect(Array.from(fromBigMat(justFits)[0])).toEqual([Number.MAX_SAFE_INTEGER, -5]);
    // negative entries are guarded on magnitude, not on sign
    expect(() => fromBigMat([[-(BigInt(Number.MAX_SAFE_INTEGER) + 1n)]])).toThrow(/exceeds 2\^53/);
  });

  it('refuses a real HNF from n=16 up, and permits one at n=8', () => {
    // Measured: the HNF still fits in Number at n = 8 and 9, exceeds it for most
    // keys at n = 10, and for every key from n = 11. This pins both sides of
    // that boundary with real matrices rather than synthetic ones.
    const small = hnf(key(8, 11).B).H;
    expect(bigFitsInNumber(small)).toBe(true);
    expect(() => fromBigMat(small)).not.toThrow();

    const big = hnf(key(16, 12).B).H;
    expect(bigMaxAbs(big) > BigInt(Number.MAX_SAFE_INTEGER)).toBe(true);
    expect(bigFitsInNumber(big)).toBe(false);
    expect(() => fromBigMat(big)).toThrow(/exceeds 2\^53/);
  });

  it('refuses to lift a non-integer double into BigInt', () => {
    const notInteger = [Float64Array.from([1.5])];
    expect(() => toBigMat(notInteger)).toThrow(/not an exact integer/);
    expect(() => asBigMat(notInteger)).toThrow(/not an exact integer/);
  });
});

describe('membership and ciphertext reduction', () => {
  it('reads a lattice point off the triangular basis and rejects a non-point', () => {
    const n = 16;
    const k = key(n, 313);
    const R = toBigMat(k.R);
    const { H } = hnf(R);
    // A genuine lattice point: an integer combination of rows of R.
    const coeffs = [3n, -1n, 0n, 7n];
    const v = new Array<bigint>(n).fill(0n);
    for (let i = 0; i < coeffs.length; i++) for (let t = 0; t < n; t++) v[t] += coeffs[i] * R[i][t];
    const x = coordinatesInHnf(H, v);
    expect(x).not.toBeNull();
    // and those coordinates really do reproduce v
    const back = bigMatmul([x as bigint[]], H)[0];
    expect(back).toEqual(v);

    // Nudge the last coordinate by 1. The last pivot is the whole determinant,
    // so the nudged vector cannot be in the lattice.
    const off = v.slice();
    off[n - 1] += 1n;
    expect(coordinatesInHnf(H, off)).toBeNull();
  });

  it('reduces a ciphertext into the fundamental domain of the same coset', () => {
    for (const n of DIMS) {
      const k = key(n, 707 + n);
      const B = toBigMat(k.B);
      const { H } = hnf(B);
      const rng = makeRng(31 + n);
      const c = new Array<bigint>(n).fill(0n);
      for (let i = 0; i < n; i++) {
        const mi = BigInt(Math.floor(rng() * 257) - 128);
        for (let t = 0; t < n; t++) c[t] += mi * B[i][t];
      }
      for (let t = 0; t < n; t++) c[t] += rng() < 0.5 ? 3n : -3n; // e in {+-sigma}^n

      const cmp = compareCiphertextSize(c, H);
      // In the fundamental domain: 0 <= c'_i < H[i][i] for every i.
      for (let i = 0; i < n; i++) {
        expect(cmp.reduced[i] >= 0n).toBe(true);
        expect(cmp.reduced[i] < H[i][i]).toBe(true);
      }
      // Same coset: the difference is an exact lattice vector, so round-off with
      // the private basis recovers exactly the same error from either.
      const diff = c.map((v, i) => v - cmp.reduced[i]);
      expect(coordinatesInHnf(H, diff)).not.toBeNull();
      // And it is smaller, measured rather than asserted from the paper.
      expect(cmp.reducedBits).toBeLessThan(cmp.rawBits);
      expect(cmp.ratio).toBeGreaterThan(1);
      // Every coordinate whose pivot is 1 collapses to zero: that IS the saving.
      expect(cmp.zeroCoordinates).toBeGreaterThanOrEqual(n - 2);
    }
  });

  it('reducing an actual lattice point gives the zero vector', () => {
    const k = key(8, 414);
    const { H } = hnf(toBigMat(k.R));
    const point = bigMatmul([[2n, -3n, 1n, 0n, 5n, -1n, 0n, 4n]], H)[0];
    expect(reduceModHnf(point, H).every((x) => x === 0n)).toBe(true);
  });
});

describe('what the HNF buys, measured', () => {
  it('measures a real size saving on the actual matrices', () => {
    for (const n of DIMS) {
      const k = key(n, 4242 + n);
      const cmp = compareKeySize(k.B, hnf(k.B).H);
      expect(cmp.n).toBe(n);
      expect(cmp.hnfBits).toBeLessThan(cmp.basisBits);
      expect(cmp.ratio).toBeGreaterThan(1);
      // The saving comes from the shape: almost every pivot is 1, so the whole
      // determinant sits in one entry and the rest of the matrix is an identity.
      expect(cmp.nontrivialPivots).toBeLessThanOrEqual(2);
      expect(cmp.largestHnfEntryBits).toBeGreaterThan(30);
    }
  });

  it('states its three claims with sources, and admits the one it does not check', () => {
    expect(HNF_BENEFITS).toHaveLength(3);
    for (const b of HNF_BENEFITS) {
      expect(b.source).toMatch(/Micciancio/);
      expect(b.claim.length).toBeGreaterThan(40);
      expect(b.checkedBy.length).toBeGreaterThan(40);
    }
    expect(HNF_BENEFITS[2].checkedBy).toMatch(/Not checked here/);
  });
});

describe('cost', () => {
  it('records the wall clock and stays inside the main-thread budget', () => {
    const rows: string[] = [];
    for (const n of DIMS) {
      const k = key(n, 555 + n);
      const R = toBigMat(k.R);
      const h = hnf(R);
      const proof = proveSameLatticeHnf(R, h.H);
      expect(proof.ok).toBe(true);
      expect(Number.isFinite(h.ms)).toBe(true);
      expect(h.ms).toBeGreaterThanOrEqual(0);
      rows.push(
        `  n=${String(n).padStart(2)}  hnf ${h.ms.toFixed(2).padStart(7)} ms   ` +
          `proof ${proof.ms.toFixed(2).padStart(7)} ms   ` +
          `estimate ${estimateHnfMs(n).totalMs.toFixed(2).padStart(7)} ms`,
      );
      // A ceiling loose enough for any CI machine but tight enough to catch the
      // failure that actually matters: losing the mod-determinant reduction turns
      // this from n^3 operations on 114-digit numbers into unbounded growth.
      expect(h.ms + proof.ms).toBeLessThan(4000);
    }
    console.log('HNF wall clock, this machine:\n' + rows.join('\n'));
  });

  it('estimates honestly: every lab dimension is main-thread safe', () => {
    for (const n of DIMS) {
      const e = estimateHnfMs(n);
      expect(e.measured).toBe(true);
      expect(e.mainThreadSafe).toBe(true);
      expect(e.totalMs).toBeLessThanOrEqual(HNF_MAIN_THREAD_BUDGET_MS);
    }
    // An unmeasured dimension interpolates and says so.
    const mid = estimateHnfMs(24);
    expect(mid.measured).toBe(false);
    expect(mid.totalMs).toBeGreaterThan(0);
    expect(mid.totalMs).toBeLessThan(estimateHnfMs(32).totalMs * 3);
    // The anchor row is the top of the slider, which is where the gate matters.
    expect(MEASURED_HNF_MS[MEASURED_HNF_MS.length - 1].n).toBe(60);
  });
});
