import { describe, expect, it } from 'vitest';
import { gghKeygen, paperK } from '../lattice/keygen';
import { inverse, makeRng, randInt } from '../lattice/matrix';
import type { Mat } from '../lattice/types';
import { randomH, roundOffBoundInf, signRoundOff } from './sign';
import { publicKey, verify } from './verify';

const n = 12;

function fixture(seed: number) {
  const rng = makeRng(seed);
  const key = gghKeygen(n, { rng, k: paperK(n) });
  const Rinv = inverse(key.R);
  const Binv = inverse(key.B);
  const pub = publicKey(key.B, roundOffBoundInf(key.R));
  return { key, rng, Rinv, Binv, pub };
}

describe('the real verifier', () => {
  it('accepts genuine signatures using only public data', () => {
    const { key, rng, Rinv, pub } = fixture(20260908);
    for (let t = 0; t < 200; t++) {
      const h = randomH(n, rng);
      const res = verify(pub, h, signRoundOff(h, key.R, Rinv));
      expect(res.ok).toBe(true);
      expect(res.reason).toBe('ok');
      expect(res.distInf).toBeLessThanOrEqual(pub.boundInf);
    }
  });

  it('rejects a perturbed signature as not being a lattice point', () => {
    const { key, rng, Rinv, pub } = fixture(1234);
    const h = randomH(n, rng);
    const s = signRoundOff(h, key.R, Rinv);
    const tampered = Float64Array.from(s);
    tampered[0] += 0.5;
    const res = verify(pub, h, tampered);
    expect(res.ok).toBe(false);
    expect(res.reason).toBe('not-in-lattice(frac)');
  });

  it('rejects Babai round-off done with the PUBLIC basis: that is the trapdoor', () => {
    // The forger has B and can find A lattice point near h -- just not a close
    // one. This is the same round-off code, the same h, the same lattice; only
    // the basis differs, and the verifier can tell.
    const { rng, Binv, pub } = fixture(4242);
    const h = randomH(n, rng);
    const s = signRoundOff(h, pub.B, Binv);
    const res = verify(pub, h, s);
    expect(res.ok).toBe(false);
    expect(res.reason).toBe('too-far');
    expect(res.distInf).toBeGreaterThan(pub.boundInf);
    // It IS a lattice point -- it fails on distance alone.
    expect(res.fracMax).toBeLessThan(1e-6);
  });

  it('rejects a genuine signature displaced by a lattice vector', () => {
    const { key, rng, Rinv, pub } = fixture(8888);
    const h = randomH(n, rng);
    const s = signRoundOff(h, key.R, Rinv);
    const moved = Float64Array.from(s, (x, i) => x + 3 * pub.B[0][i]);
    const res = verify(pub, h, moved);
    expect(res.ok).toBe(false);
    expect(res.reason).toBe('too-far');
  });

  it('accepts signatures made with P*D*R, which is all Break 2 can recover', () => {
    // Invariant I5 depends on this: a basis recovered up to sign and permutation
    // signs into the SAME lattice and is graded against the SAME published bound.
    const { key, rng, pub } = fixture(31337);
    const perm = [...Array(n).keys()];
    for (let i = n - 1; i > 0; i--) {
      const j = randInt(rng, 0, i);
      [perm[i], perm[j]] = [perm[j], perm[i]];
    }
    const scrambled: Mat = perm.map((p) => {
      const flip = rng() < 0.5 ? -1 : 1;
      return Float64Array.from(key.R[p], (x) => flip * x);
    });
    const scrambledInv = inverse(scrambled);
    for (let t = 0; t < 50; t++) {
      const h = randomH(n, rng);
      expect(verify(pub, h, signRoundOff(h, scrambled, scrambledInv)).ok).toBe(true);
    }
  });
});
