/**
 * Tests for the lattice foundation: keygen, the I1 same-lattice proof, and the
 * I2 decryption bound.
 *
 * These are claims C1 and C2 from the brief, checked at the unit level. The
 * page-level versions live in e2e/claims.spec.ts.
 */

import { describe, expect, it } from 'vitest';
import { gghK, gghKeygen, invertibleMod6, invertibleModP, paperK, SIGMA } from './keygen';
import { proveSameLattice } from './invariants';
import {
  decrypt,
  decryptBound,
  encrypt,
  randomMessage,
  reEncryptionCheck,
  roundOff,
  worstCaseBound,
} from './roundoff';
import {
  allIntegersUnder2p53,
  inverse,
  log10AbsDet,
  log10OrthogonalityDefect,
  makeRng,
  matEq,
  matmul,
  rnd,
  vecMat,
  type MulStats,
} from './matrix';

describe('rounding', () => {
  it('rounds half AWAY from zero, which Math.round does not', () => {
    expect(rnd(0.5)).toBe(1);
    expect(rnd(-0.5)).toBe(-1);
    // The bug this guards: Math.round(-0.5) is -0, which rounds the tie up and
    // breaks the I2 iff at exact ties.
    expect(Math.round(-0.5)).toBe(-0);
    expect(rnd(2.5)).toBe(3);
    expect(rnd(-2.5)).toBe(-3);
    expect(rnd(1.4)).toBe(1);
    expect(rnd(-1.4)).toBe(-1);
  });
});

describe('keygen', () => {
  it('produces exact integer matrices with R = k*I + E, |E| <= l', () => {
    const key = gghKeygen(16, { rng: makeRng(1) });
    expect(allIntegersUnder2p53(key.R)).toBe(true);
    expect(allIntegersUnder2p53(key.B)).toBe(true);
    expect(allIntegersUnder2p53(key.U)).toBe(true);
    expect(allIntegersUnder2p53(key.V)).toBe(true);
    for (let i = 0; i < key.n; i++) {
      for (let j = 0; j < key.n; j++) {
        const noise = key.R[i][j] - (i === j ? key.k : 0);
        expect(Math.abs(noise)).toBeLessThanOrEqual(key.l);
      }
    }
  });

  it('B equals U*R by construction', () => {
    const key = gghKeygen(12, { rng: makeRng(7) });
    expect(matEq(matmul(key.U, key.R), key.B)).toBe(true);
  });

  it('U and V are exact inverses by construction', () => {
    const key = gghKeygen(12, { rng: makeRng(8) });
    const I = matmul(key.U, key.V);
    for (let i = 0; i < key.n; i++) {
      for (let j = 0; j < key.n; j++) expect(I[i][j]).toBe(i === j ? 1 : 0);
    }
  });

  it('rejects keys whose determinant is not coprime to 6', () => {
    // Break 1 needs B invertible mod 2 and mod 3. Only 12-17% of random keys
    // are, so this filter is what stops Break 1 failing on ~85% of keys.
    for (let s = 1; s <= 10; s++) {
      const key = gghKeygen(10, { rng: makeRng(s) });
      expect(invertibleMod6(key.R)).toBe(true);
      expect(invertibleMod6(key.B)).toBe(true);
    }
  });

  it('det(B) = +-det(R), so testing R for coprimality is the same test as B', () => {
    for (let s = 1; s <= 8; s++) {
      const key = gghKeygen(10, { rng: makeRng(100 + s), requireCoprime6: false });
      expect(invertibleModP(key.R, 2)).toBe(invertibleModP(key.B, 2));
      expect(invertibleModP(key.R, 3)).toBe(invertibleModP(key.B, 3));
    }
  });

  it('the shipped k rule is larger than the 1997 paper rule at every dimension', () => {
    // The paper's k ~ sqrt(n)*l does not decrypt at these dimensions with
    // sigma = 3; see the header of keygen.ts for the measured failure rates.
    for (const n of [8, 16, 32, 60]) {
      expect(gghK(n, 4)).toBeGreaterThan(paperK(n, 4));
    }
  });
});

describe('invariant I1 - the two bases span the same lattice (claim C1)', () => {
  it('proves L(B) = L(R) by exact integer arithmetic, recovering U from R and B alone', () => {
    for (const n of [8, 16, 32]) {
      for (let s = 0; s < 4; s++) {
        const key = gghKeygen(n, { rng: makeRng(n * 1000 + s) });
        const proof = proveSameLattice(key.R, key.B);
        expect(proof.ok).toBe(true);
        expect(proof.checks.entriesSafe).toBe(true);
        expect(proof.checks.uTimesREqualsB).toBe(true);
        expect(proof.checks.vTimesBEqualsR).toBe(true);
        expect(proof.checks.uTimesVIsIdentity).toBe(true);
        // The recovered U must equal the one keygen actually used.
        expect(matEq(proof.U!, key.U)).toBe(true);
        expect(matEq(proof.V!, key.V)).toBe(true);
      }
    }
  });

  it('keeps every intermediate value far below 2^53', () => {
    const stats: MulStats = { maxIntermediate: 0 };
    const key = gghKeygen(60, { rng: makeRng(42) });
    const proof = proveSameLattice(key.R, key.B, { stats });
    expect(proof.ok).toBe(true);
    // Measured worst case at n=60 is ~3.4e4 against 9.007e15.
    expect(stats.maxIntermediate).toBeLessThan(1e8);
    expect(Number.MAX_SAFE_INTEGER / stats.maxIntermediate).toBeGreaterThan(1e7);
  });

  it('reports a failure rather than throwing when the claim is false', () => {
    const key = gghKeygen(8, { rng: makeRng(3) });
    // Corrupt one entry of B: it is no longer the same lattice.
    const badB = key.B.map((r) => Float64Array.from(r));
    badB[0][0] += 1;
    const proof = proveSameLattice(key.R, badB);
    expect(proof.ok).toBe(false);
    expect(proof.reason).toMatch(/does not equal/);
  });
});

describe('invariant I2 - the decryption bound (claim C2)', () => {
  it('predicts round-off success exactly, with both bases', () => {
    // The bound is an exact iff, and it is basis-generic: the same criterion
    // decides for the private and the public basis.
    let checked = 0;
    for (const n of [8, 16, 32]) {
      const rng = makeRng(n * 31 + 5);
      const key = gghKeygen(n, { rng });
      const Rinv = inverse(key.R);
      const Binv = inverse(key.B);
      for (let t = 0; t < 30; t++) {
        const m = randomMessage(n, rng);
        const { c, e } = encrypt(m, key.B, rng);

        for (const [basis, basisInv] of [
          [key.R, Rinv],
          [key.B, Binv],
        ] as const) {
          const bound = decryptBound(e, basisInv);
          const recovered = roundOff(c, basis, basisInv);
          const truePoint = vecMat(m, key.B);
          let exact = true;
          for (let i = 0; i < n; i++) if (recovered[i] !== truePoint[i]) exact = false;
          expect(bound.predictsSuccess).toBe(exact);
          checked++;
        }
      }
    }
    expect(checked).toBe(180);
  });

  it('is guaranteed for the private basis at every shipped dimension', () => {
    for (const n of [8, 16, 24, 32, 40, 50, 60]) {
      const key = gghKeygen(n, { rng: makeRng(n) });
      const worst = worstCaseBound(inverse(key.R), SIGMA);
      // Measured 0.121-0.136 across this range: a margin of at least 3.6x.
      expect(worst).toBeLessThan(0.5);
      expect(0.5 / worst).toBeGreaterThan(3.5);
    }
  });

  it('is violated by the public basis, so round-off with B almost always fails', () => {
    // "Almost always", not "always", and the distinction is honest rather than
    // defensive: the bound is a property of the error vector, so an unusually
    // short e can occasionally slip under 1/2 even with the public basis. That
    // was measured once in 200 ciphertexts at n=8. What the trapdoor buys is
    // that the quantity is 12-30x over the threshold with B and ~0.1 with R --
    // a guarantee versus a coin that almost always lands the same way.
    for (const n of [8, 16, 32]) {
      const rng = makeRng(n + 77);
      const key = gghKeygen(n, { rng });
      const Binv = inverse(key.B);
      const Rinv = inverse(key.R);
      let failures = 0;
      let sumB = 0;
      let sumR = 0;
      const trials = 20;
      for (let t = 0; t < trials; t++) {
        const m = randomMessage(n, rng);
        const { e } = encrypt(m, key.B, rng);
        const bB = decryptBound(e, Binv);
        sumB += bB.actual;
        sumR += decryptBound(e, Rinv).actual;
        if (!bB.predictsSuccess) failures++;
      }
      expect(failures).toBeGreaterThanOrEqual(trials - 1);
      // The public basis is worse by an order of magnitude on average, and it
      // carries no guarantee at all.
      expect(sumB / trials).toBeGreaterThan(10 * (sumR / trials));
      expect(worstCaseBound(Binv, SIGMA)).toBeGreaterThan(0.5);
    }
  });

  it('decrypts correctly with the private basis and reproduces the ciphertext', () => {
    const n = 24;
    const rng = makeRng(999);
    const key = gghKeygen(n, { rng });
    const Rinv = inverse(key.R);
    const Binv = inverse(key.B);
    for (let t = 0; t < 25; t++) {
      const m = randomMessage(n, rng);
      const { c } = encrypt(m, key.B, rng);
      const got = decrypt(c, key, Rinv, Binv);
      for (let i = 0; i < n; i++) expect(got[i]).toBe(m[i]);
      // Independent check: re-encryption, the one an attacker could run.
      expect(reEncryptionCheck(c, got, key.B).ok).toBe(true);
    }
  });

  it('the paper k rule really does fail to decrypt at n = 8', () => {
    // This is the measurement that justified changing the k rule, so it is
    // asserted rather than only described in a comment.
    const n = 8;
    const rng = makeRng(2468);
    let fails = 0;
    for (let key = 0; key < 6; key++) {
      const k = gghKeygen(n, { k: paperK(n, 4), rng });
      const Rinv = inverse(k.R);
      for (let t = 0; t < 20; t++) {
        const m = randomMessage(n, rng);
        const { e } = encrypt(m, k.B, rng);
        if (!decryptBound(e, Rinv).predictsSuccess) fails++;
      }
    }
    expect(fails).toBeGreaterThan(0);
  });
});

describe('orthogonality defect', () => {
  it('is far smaller for the private basis, and both dets agree', () => {
    for (const n of [8, 16, 32]) {
      const key = gghKeygen(n, { rng: makeRng(n * 7) });
      const dR = log10OrthogonalityDefect(key.R);
      const dB = log10OrthogonalityDefect(key.B);
      expect(dR).toBeLessThan(dB);
      // Unimodularity, checked a second way and independently of I1.
      expect(Math.abs(log10AbsDet(key.R) - log10AbsDet(key.B))).toBeLessThan(1e-6);
    }
  });

  it('the public basis defect exceeds 2^53 in linear form from n = 16 up', () => {
    // This is why the defect is carried as log10 everywhere and never
    // exponentiated: at n=60 it reaches 10^69.
    const key = gghKeygen(16, { rng: makeRng(5) });
    expect(log10OrthogonalityDefect(key.B)).toBeGreaterThan(Math.log10(Number.MAX_SAFE_INTEGER));
  });
});
