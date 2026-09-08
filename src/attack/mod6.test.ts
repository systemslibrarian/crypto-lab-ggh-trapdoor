import { describe, expect, it } from 'vitest';
import type { Mat, Vec } from '../lattice/types';
import { makeRng, vecMat } from '../lattice/matrix';
import { gghKeygen } from '../lattice/keygen';
import { encrypt, randomMessage } from '../lattice/roundoff';
import {
  congruenceRhs,
  crt23,
  invModP,
  modP,
  solveMod6,
  solveRowModP,
  solveRowModPFull,
} from './mod6';

const mat = (rows: number[][]): Mat => rows.map((r) => Float64Array.from(r));
const vec = (v: number[]): Vec => Float64Array.from(v);

/** Every m0 in {0..5}^n satisfying m0*B = rhs (mod 6), by exhaustive search. */
function bruteForceMod6(B: Mat, rhs: Vec): number[][] {
  const n = B.length;
  const sols: number[][] = [];
  const x = new Array<number>(n).fill(0);
  const rec = (i: number): void => {
    if (i === n) {
      const v = vecMat(Float64Array.from(x), B);
      for (let j = 0; j < n; j++) if (modP(v[j], 6) !== modP(rhs[j], 6)) return;
      sols.push([...x]);
      return;
    }
    for (let d = 0; d < 6; d++) { x[i] = d; rec(i + 1); }
  };
  rec(0);
  return sols;
}

describe('modular arithmetic primitives', () => {
  it('modP returns the non-negative residue', () => {
    expect(modP(-1, 6)).toBe(5);
    expect(modP(-7, 3)).toBe(2);
    expect(modP(12, 6)).toBe(0);
  });

  it('invModP inverts units and rejects zero', () => {
    expect(invModP(1, 2)).toBe(1);
    expect(invModP(0, 2)).toBeNull();
    expect(invModP(2, 3)).toBe(2);
    expect(invModP(3, 3)).toBeNull();
    expect(invModP(-1, 3)).toBe(2); // -1 = 2 mod 3, and 2*2 = 1 mod 3
  });

  it('crt23 reproduces both residues', () => {
    for (let a = 0; a < 2; a++) {
      for (let b = 0; b < 3; b++) {
        const x = crt23(vec([a]), vec([b]))[0];
        expect(modP(x, 2)).toBe(a);
        expect(modP(x, 3)).toBe(b);
        expect(x).toBeGreaterThanOrEqual(0);
        expect(x).toBeLessThan(6);
      }
    }
  });

  it('congruenceRhs is Nguyen c + s, and equals c - s modulo 2*sigma', () => {
    const c = vec([10, -4, 0, 7]);
    const plus = congruenceRhs(c, 3);
    for (let i = 0; i < c.length; i++) {
      expect(plus[i]).toBe(modP(c[i] + 3, 6));
      // -sigma = +sigma (mod 2*sigma), so Nguyen's sign and the direct
      // rearrangement of c = m*B + e give the same residue.
      expect(plus[i]).toBe(modP(c[i] - 3, 6));
    }
  });
});

describe('solveMod6 against brute force', () => {
  it('matches an exhaustive search at n = 3, over many random systems', () => {
    const rng = makeRng(20240611);
    let nonsingular = 0;
    let singular = 0;
    for (let trial = 0; trial < 120; trial++) {
      const B = mat([0, 1, 2].map(() => [0, 1, 2].map(() => Math.floor(rng() * 13) - 6)));
      const rhs = vec([0, 1, 2].map(() => Math.floor(rng() * 6)));
      const sols = bruteForceMod6(B, rhs);
      const got = solveMod6(B, rhs);
      if (got.ok) {
        nonsingular++;
        // Invertible mod 6 means exactly one solution, and it is the one we found.
        expect(sols).toHaveLength(1);
        expect(Array.from(got.m0)).toEqual(sols[0]);
      } else {
        singular++;
        // Singular mod 6: never a unique solution. Either none, or a whole coset.
        expect(sols.length === 0 || sols.length > 1).toBe(true);
      }
    }
    expect(nonsingular).toBeGreaterThan(0);
    expect(singular).toBeGreaterThan(0);
  });

  it('recovers m mod 6 from a real GGH ciphertext', () => {
    const rng = makeRng(4242);
    for (const n of [8, 16]) {
      const key = gghKeygen(n, { rng });
      const m = randomMessage(n, rng);
      const ct = encrypt(m, key.B, rng);
      const sol = solveMod6(key.B, congruenceRhs(ct.c, 3));
      expect(sol.ok).toBe(true);
      if (!sol.ok) return;
      for (let j = 0; j < n; j++) expect(sol.m0[j]).toBe(modP(m[j], 6));
    }
  });
});

describe('the singular case is named, never fudged (invariant I3)', () => {
  // det = 2: invertible over GF(3), not over GF(2).
  const singular2 = mat([[1, 2], [0, 2]]);
  // det = 3: invertible over GF(2), not over GF(3).
  const singular3 = mat([[1, 2], [0, 3]]);
  // det = 6: invertible over neither.
  const singular6 = mat([[1, 2], [0, 6]]);
  const rhs = vec([1, 1]);

  it('names GF(2)', () => {
    const s = solveMod6(singular2, rhs);
    expect(s.ok).toBe(false);
    if (s.ok) return;
    expect(s.singular.modulus).toBe(2);
    expect(s.singular.singularMod2).toBe(true);
    expect(s.singular.singularMod3).toBe(false);
    expect(s.singular.reason).toContain('GF(2)');
  });

  it('names GF(3)', () => {
    const s = solveMod6(singular3, rhs);
    expect(s.ok).toBe(false);
    if (s.ok) return;
    expect(s.singular.modulus).toBe(3);
    expect(s.singular.singularMod2).toBe(false);
    expect(s.singular.singularMod3).toBe(true);
    expect(s.singular.reason).toContain('GF(3)');
  });

  it('names both', () => {
    const s = solveMod6(singular6, rhs);
    expect(s.ok).toBe(false);
    if (s.ok) return;
    expect(s.singular.modulus).toBe(6);
    expect(s.singular.singularMod2).toBe(true);
    expect(s.singular.singularMod3).toBe(true);
  });

  it('solveRowModP agrees with solveMod6 about which modulus is singular', () => {
    expect(solveRowModP(singular2, rhs, 2)).toBeNull();
    expect(solveRowModP(singular2, rhs, 3)).not.toBeNull();
    expect(solveRowModP(singular3, rhs, 2)).not.toBeNull();
    expect(solveRowModP(singular3, rhs, 3)).toBeNull();
  });
});

describe('solveRowModPFull', () => {
  it('returns a particular solution and a genuine kernel basis', () => {
    // Singular mod 2 with a one-dimensional kernel.
    const B = mat([[1, 2], [0, 2]]);
    const rhs = vec([1, 0]);
    const set = solveRowModPFull(B, rhs, 2);
    expect(set).not.toBeNull();
    if (set === null) return;
    // x0 really solves the system.
    const v = vecMat(set.x0, B);
    for (let j = 0; j < 2; j++) expect(modP(v[j], 2)).toBe(modP(rhs[j], 2));
    // Every kernel vector really annihilates B, and is not the zero vector.
    expect(set.kernel.length).toBe(1);
    for (const k of set.kernel) {
      const kv = vecMat(k, B);
      for (let j = 0; j < 2; j++) expect(modP(kv[j], 2)).toBe(0);
      expect(Array.from(k).some((x) => x !== 0)).toBe(true);
    }
  });

  it('has an empty kernel exactly when the matrix is invertible mod p', () => {
    const rng = makeRng(999);
    for (let trial = 0; trial < 40; trial++) {
      const B = mat([0, 1, 2].map(() => [0, 1, 2].map(() => Math.floor(rng() * 7) - 3)));
      const rhs = vec([1, 0, 1]);
      for (const p of [2, 3]) {
        const unique = solveRowModP(B, rhs, p);
        const full = solveRowModPFull(B, rhs, p);
        if (unique !== null) {
          // Invertible: one solution, empty kernel, and the two routes agree.
          expect(full).not.toBeNull();
          if (full === null) continue;
          expect(full.kernel).toHaveLength(0);
          expect(Array.from(full.x0)).toEqual(Array.from(unique));
        } else if (full !== null) {
          // Singular but consistent: a whole coset, so the kernel is non-trivial.
          expect(full.kernel.length).toBeGreaterThan(0);
        }
      }
    }
  });
});
