import { describe, expect, it } from 'vitest';
import { gghKeygen, paperK } from '../lattice/keygen';
import { inverse, makeRng, matmul, transpose, zeros } from '../lattice/matrix';
import type { Mat } from '../lattice/types';
import { collectLeaks, makeRoundOffSigner } from '../sign/sign';
import { gaussian } from './descent';
import {
  applyWhitening,
  choleskyUpper,
  covariance,
  covarianceShape,
  devFromIdentity,
  whiten,
  whiteningError,
} from './whiten';

/** A random symmetric positive definite matrix, as M^T M + I. */
function spd(n: number, seed: number): Mat {
  const rng = makeRng(seed);
  const M = zeros(n, n);
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) M[i][j] = gaussian(rng);
  const G = matmul(transpose(M), M);
  for (let i = 0; i < n; i++) G[i][i] += n;
  return G;
}

describe('Cholesky in the G = L^T L form', () => {
  it('returns an UPPER triangular factor that reproduces G', () => {
    const n = 9;
    const G = spd(n, 4242);
    const L = choleskyUpper(G);
    for (let i = 0; i < n; i++) for (let j = 0; j < i; j++) expect(L[i][j]).toBe(0);
    const back = matmul(transpose(L), L);
    let worst = 0;
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) worst = Math.max(worst, Math.abs(back[i][j] - G[i][j]));
    }
    expect(worst).toBeLessThan(1e-9);
  });

  it('inverts to an exactly upper triangular Linv, which the hot loop relies on', () => {
    // Gauss-Jordan does no row swaps on a triangular matrix, so the sub-diagonal
    // entries stay exact zeros. The whitening inner loop stops at p <= j because
    // of this; if it were only ALMOST zero the loop would be wrong, not just slow.
    const n = 9;
    const Linv = inverse(choleskyUpper(spd(n, 777)));
    for (let i = 0; i < n; i++) for (let j = 0; j < i; j++) expect(Linv[i][j]).toBe(0);
  });

  it('refuses a matrix that is not positive definite instead of returning nonsense', () => {
    const G: Mat = [Float64Array.from([1, 2]), Float64Array.from([2, 1])];
    expect(() => choleskyUpper(G)).toThrow(/positive definite/);
  });
});

describe('whitening signature leaks', () => {
  const n = 8;
  const N = 8000;
  const rng = makeRng(20260908);
  const key = gghKeygen(n, { rng, k: paperK(n) });
  const V = collectLeaks(N, n, rng, makeRoundOffSigner(key.R, inverse(key.R)));
  const wh = whiten(V, n);

  it('estimates R^T R from public data alone', () => {
    // E[v^T v] = (1/12) R^T R, so G = 12*mean(v^T v) converges to R^T R.
    const truth = matmul(transpose(key.R), key.R);
    let worstAbs = 0;
    let scale = 0;
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        worstAbs = Math.max(worstAbs, Math.abs(wh.G[i][j] - truth[i][j]));
        scale = Math.max(scale, Math.abs(truth[i][j]));
      }
    }
    // Measured against the overall scale of R^T R, not entry by entry: the
    // sampling error of every entry is set by the size of the matrix, so a small
    // off-diagonal entry is not estimated to better absolute accuracy.
    expect(worstAbs / scale).toBeLessThan(0.05);
  });

  it('actually orthogonalises: R*Linv is orthogonal to a few percent', () => {
    // The prototype measured 0.027 at n=8, N=8000, falling as 1/sqrt(N).
    const dev = whiteningError(key.R, wh.Linv);
    expect(dev).toBeLessThan(0.1);
    // And it is genuinely doing work: the un-whitened R is nowhere near orthogonal.
    const RRt = matmul(key.R, transpose(key.R));
    expect(devFromIdentity(RRt)).toBeGreaterThan(1);
  });

  it('improves as 1/sqrt(N)', () => {
    const small = whiten(V.slice(0, 500), n);
    expect(whiteningError(key.R, small.Linv)).toBeGreaterThan(whiteningError(key.R, wh.Linv));
  });

  it('leaves the whitened samples with an identity covariance', () => {
    // The check that needs no secret: 12*mean(w^T w) must be the identity.
    const W: Mat = [];
    for (let t = 0; t < N; t++) W.push(wh.W.subarray(t * n, (t + 1) * n));
    expect(devFromIdentity(covariance(W, n))).toBeLessThan(1e-9);
  });

  it('applies an existing transform identically, which is how the hold-out is scored', () => {
    const again = applyWhitening(V, wh.Linv);
    expect(again.length).toBe(wh.W.length);
    for (let i = 0; i < again.length; i++) expect(again[i]).toBe(wh.W[i]);
  });

  it('reports a covariance shape far from scalar for round-off samples', () => {
    // Public pre-check: a spherical signer's G is a scalar matrix and this is ~0.
    expect(covarianceShape(wh.G)).toBeGreaterThan(0.1);
    const scalar = zeros(n, n);
    for (let i = 0; i < n; i++) scalar[i][i] = 17;
    expect(covarianceShape(scalar)).toBeLessThan(1e-12);
  });
});
