import { describe, expect, it } from 'vitest';
import type { Mat } from '../lattice/types';
import {
  TWO53,
  allIntegersUnder2p53,
  cloneMat,
  log10AbsDet,
  makeRng,
  matEq,
  matmul,
  norm2,
} from '../lattice/matrix';
import { gghKeygen } from '../lattice/keygen';
import { encrypt, randomMessage } from '../lattice/roundoff';
import { buildEmbedding } from './embedding';
import { LLL_DELTA, checkLllReduced, lllReduce, shortestRowNorm } from './lll';

const mat = (rows: number[][]): Mat => rows.map((r) => Float64Array.from(r));

/** A real centered embedding basis, i.e. the matrix this file actually has to reduce. */
function embeddingBasis(n: number, seed: number): Mat {
  const rng = makeRng(seed);
  const key = gghKeygen(n, { rng });
  const m = randomMessage(n, rng);
  const ct = encrypt(m, key.B, rng);
  // Any integer target works for a reducedness test; use the ciphertext itself.
  return buildEmbedding(ct.c, key.B, 'centered', 1);
}

describe('LLL produces a genuinely reduced basis', () => {
  it('satisfies size reduction and the Lovasz condition on GGH public bases', () => {
    for (const n of [8, 16, 32]) {
      const rng = makeRng(31337 + n);
      const key = gghKeygen(n, { rng });
      const out = lllReduce(key.B);
      expect(out.failure).toBeNull();
      const chk = checkLllReduced(out.basis, LLL_DELTA);
      // Asserted directly, not inferred from "it returned": max |mu| <= 1/2 and
      // no Lovasz violation anywhere.
      expect(chk.maxAbsMu).toBeLessThanOrEqual(0.5 + 1e-9);
      expect(chk.lovaszViolations).toBe(0);
      expect(chk.reduced).toBe(true);
    }
  });

  it('satisfies both conditions on real embedding bases', () => {
    for (const n of [8, 16, 32]) {
      const basis = embeddingBasis(n, 777 + n);
      const out = lllReduce(basis);
      expect(out.failure).toBeNull();
      const chk = checkLllReduced(out.basis, LLL_DELTA);
      expect(chk.sizeReduced).toBe(true);
      expect(chk.lovaszOk).toBe(true);
    }
  });

  it('shortens the basis it was given', () => {
    const basis = embeddingBasis(16, 12321);
    const before = shortestRowNorm(basis);
    const out = lllReduce(basis);
    expect(shortestRowNorm(out.basis)).toBeLessThan(before);
  });

  it('detects an un-reduced basis, so the check is not vacuous', () => {
    // Rows are far from size-reduced: mu_10 = 100.
    const chk = checkLllReduced(mat([[1, 0], [100, 1]]));
    expect(chk.sizeReduced).toBe(false);
    expect(chk.reduced).toBe(false);
  });
});

describe('the unimodular transform is exact', () => {
  it('H * input === output, entry for entry, and the input is untouched', () => {
    for (const n of [8, 16, 32]) {
      const basis = embeddingBasis(n, 5150 + n);
      const original = cloneMat(basis);
      const out = lllReduce(basis);
      expect(matEq(basis, original)).toBe(true);
      expect(matEq(matmul(out.transform, basis), out.basis)).toBe(true);
      expect(allIntegersUnder2p53(out.transform)).toBe(true);
      expect(allIntegersUnder2p53(out.basis)).toBe(true);
    }
  });

  it('preserves |det|, so the lattice is the same one', () => {
    const basis = embeddingBasis(16, 60606);
    const out = lllReduce(basis);
    expect(log10AbsDet(out.basis)).toBeCloseTo(log10AbsDet(basis), 6);
  });
});

describe('the 2^53 guard', () => {
  it('fires on a deliberately oversized input and names the site', () => {
    // 1e17 is exactly representable as a double but is NOT a safe integer, so
    // arithmetic on it silently stops being exact. LLL must refuse, not proceed.
    const basis = mat([[1e17, 1, 0], [0, 1, 0], [0, 0, 1]]);
    const out = lllReduce(basis);
    expect(out.failure).not.toBeNull();
    if (out.failure === null) return;
    expect(out.failure.kind).toBe('integer-overflow');
    if (out.failure.kind !== 'integer-overflow') return;
    expect(out.failure.where).toBe('input');
    expect(out.failure.maxAbs).toBeGreaterThan(TWO53);
    expect(out.failure.message).toContain('2^53');
  });

  it('fires mid-run when the transform grows past 2^53', () => {
    // Reducing b2 against b1 multiplies the two size-reduction coefficients
    // together inside H: H2 picks up (-1e8)*(1e8) = 1e16 > 2^53. The BASIS rows
    // stay small here, which is exactly why the transform has to be guarded too.
    const A = 1e8;
    const basis = mat([[1, 0, 0], [A, 1, 0], [0, A, 1]]);
    const out = lllReduce(basis);
    expect(out.failure).not.toBeNull();
    if (out.failure === null) return;
    expect(out.failure.kind).toBe('integer-overflow');
    if (out.failure.kind !== 'integer-overflow') return;
    expect(out.failure.where).toBe('transform');
    expect(out.failure.maxAbs).toBeGreaterThan(TWO53);
  });

  it('stays quiet, with room to spare, on every basis this lab actually produces', () => {
    for (const n of [8, 16, 32]) {
      const out = lllReduce(embeddingBasis(n, 24680 + n));
      expect(out.failure).toBeNull();
      // Measured: 2^11.8 to 2^13.7 across n = 8..60, i.e. ~39 binary orders of margin.
      expect(out.guardMax).toBeLessThan(TWO53 / 1e6);
    }
  });
});

describe('worker-friendly controls', () => {
  it('reports the iteration cap instead of pretending to be finished', () => {
    const basis = embeddingBasis(16, 4004);
    const out = lllReduce(basis, { maxIters: 3 });
    expect(out.failure).not.toBeNull();
    if (out.failure === null) return;
    expect(out.failure.kind).toBe('iteration-cap');
    if (out.failure.kind !== 'iteration-cap') return;
    expect(out.failure.maxIters).toBe(3);
    // The partial output is still a valid basis of the same lattice.
    expect(matEq(matmul(out.transform, basis), out.basis)).toBe(true);
  });

  it('calls the progress callback with a sane ticket', () => {
    const basis = embeddingBasis(16, 90210);
    const seen: number[] = [];
    const out = lllReduce(basis, {
      progressEvery: 1,
      onProgress: (p) => {
        seen.push(p.iters);
        expect(p.n).toBe(basis.length);
        expect(p.k).toBeGreaterThanOrEqual(1);
        expect(p.k).toBeLessThan(p.n);
      },
    });
    expect(out.failure).toBeNull();
    expect(seen.length).toBeGreaterThan(0);
    // Monotone, so a UI can use it as a progress signal.
    for (let i = 1; i < seen.length; i++) expect(seen[i]).toBeGreaterThan(seen[i - 1]);
  });

  it('a weaker delta still reduces, just less', () => {
    const basis = embeddingBasis(16, 13579);
    const strong = lllReduce(basis, { delta: 0.99 });
    const weak = lllReduce(basis, { delta: 0.51 });
    expect(checkLllReduced(strong.basis, 0.99).reduced).toBe(true);
    expect(checkLllReduced(weak.basis, 0.51).reduced).toBe(true);
    expect(norm2(strong.basis[0])).toBeLessThanOrEqual(norm2(weak.basis[0]) + 1e-9);
  });
});
