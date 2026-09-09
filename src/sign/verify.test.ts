import { describe, expect, it } from 'vitest';
import { runBreak2 } from '../attack/break2';
import { gghKeygen, paperK } from '../lattice/keygen';
import { inverse, makeRng, maxAbsVec, randInt, rnd, roundVec, vecMat } from '../lattice/matrix';
import type { Mat, Vec } from '../lattice/types';
import { kleinBoundInf, kleinSigma, makeKleinSigner } from './klein';
import { makeRoundOffSigner, randomH, roundOffBoundInf, signRoundOff } from './sign';
import type { PublicKey, VerifyReason } from './verify';
import { LATTICE_TOL, MAX_BOUND_INF, MAX_TOL, publicKey, verify } from './verify';

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

  it('accepts a hashed point that is nowhere near an integer', () => {
    // h is a point in R^n: only s has to be integral. If this ever fails, the
    // validation has been tightened past what the scheme actually says.
    const { key, rng, Rinv, pub } = fixture(90210);
    const h = randomH(n, rng);
    expect(Array.from(h).every((x) => !Number.isInteger(x))).toBe(true);
    expect(verify(pub, h, signRoundOff(h, key.R, Rinv)).reason).toBe('ok');
  });
});

// ---------------------------------------------------------------------------
// The adversarial corpus
// ---------------------------------------------------------------------------

/**
 * One malformed input per validation, each pinned to the exact reason it has to
 * come back with.
 *
 * This table is the mutation test the audit asked for, done by construction:
 * every gate in verify() and publicKey() owns at least one row, and deleting a
 * gate makes its row report a different reason -- or, for the three probes the
 * audit actually ran, makes it report `ok`. Reasons are asserted as strings, so
 * a rejection for the WRONG reason fails just as loudly as an acceptance.
 */
const corpus: ReadonlyArray<{
  readonly name: string;
  readonly reason: VerifyReason;
  readonly run: () => ReturnType<typeof verify>;
}> = (() => {
  const F = fixture(4242);
  const pub = F.pub;
  const h0 = randomH(n, makeRng(77));
  const s0 = signRoundOff(h0, F.key.R, F.Rinv);

  /** The genuine signature with one entry replaced. */
  const withS = (i: number, x: number): Vec => {
    const v = Float64Array.from(s0);
    v[i] = x;
    return v;
  };
  /** The genuine hashed point with one entry replaced. */
  const withH = (i: number, x: number): Vec => {
    const v = Float64Array.from(h0);
    v[i] = x;
    return v;
  };
  /** A copy of the public basis, safe to damage. */
  const damagedB = (): Mat => F.key.B.map((r) => Float64Array.from(r));
  /** A key assembled by hand, so verify()'s own re-checks are exercised. */
  const withKey = (over: Partial<PublicKey>): PublicKey => ({ ...pub, ...over });
  const mat = (rows: number[][]): Mat => rows.map((r) => Float64Array.from(r));

  return [
    // --- lengths: empty, short, long, mismatched ---------------------------
    { name: 'empty s', reason: 'bad-vector(length)', run: () => verify(pub, h0, new Float64Array(0)) },
    { name: 'empty h', reason: 'bad-vector(length)', run: () => verify(pub, new Float64Array(0), s0) },
    { name: 's one short', reason: 'bad-vector(length)', run: () => verify(pub, h0, s0.slice(0, n - 1)) },
    {
      name: 's one long',
      reason: 'bad-vector(length)',
      run: () => verify(pub, h0, Float64Array.from([...s0, 0])),
    },
    {
      name: 'h and s of different lengths',
      reason: 'bad-vector(length)',
      run: () => verify(pub, h0.slice(0, n - 1), s0),
    },

    // --- non-finite entries: the NaN hazard, in both vectors ----------------
    { name: 'NaN in s', reason: 'bad-vector(nonfinite)', run: () => verify(pub, h0, withS(3, NaN)) },
    { name: 'NaN in h', reason: 'bad-vector(nonfinite)', run: () => verify(pub, withH(0, NaN), s0) },
    { name: 'Infinity in s', reason: 'bad-vector(nonfinite)', run: () => verify(pub, h0, withS(5, Infinity)) },
    { name: '-Infinity in s', reason: 'bad-vector(nonfinite)', run: () => verify(pub, h0, withS(5, -Infinity)) },
    { name: '-Infinity in h', reason: 'bad-vector(nonfinite)', run: () => verify(pub, withH(2, -Infinity), s0) },

    // --- the accepted domain: past 2^53 a double is not the integer it prints
    {
      name: 'an unsafe integer in s (2^53)',
      reason: 'bad-vector(domain)',
      run: () => verify(pub, h0, withS(0, 9007199254740992)),
    },
    {
      name: "the audit's 1e17 probe in s",
      reason: 'bad-vector(domain)',
      run: () => verify(pub, h0, withS(0, 1e17)),
    },
    {
      name: 'an unsafe magnitude in h',
      reason: 'bad-vector(domain)',
      run: () => verify(pub, withH(1, -1e17), s0),
    },

    // --- mathematics, not malformedness ------------------------------------
    {
      name: 'a fractional s, which no integer lattice can contain',
      reason: 'not-in-lattice(frac)',
      run: () => verify(pub, h0, withS(0, s0[0] + 0.5)),
    },
    {
      name: 'an integer s one step off the lattice',
      reason: 'not-in-lattice(frac)',
      run: () => verify(pub, h0, withS(0, s0[0] + 1)),
    },

    // --- the published bound -----------------------------------------------
    {
      name: 'a negative bound',
      reason: 'bad-key(bound)',
      run: () => verify(publicKey(F.key.B, -1), h0, s0),
    },
    { name: 'a NaN bound', reason: 'bad-key(bound)', run: () => verify(publicKey(F.key.B, NaN), h0, s0) },
    {
      name: 'an infinite bound',
      reason: 'bad-key(bound)',
      run: () => verify(publicKey(F.key.B, Infinity), h0, s0),
    },
    {
      name: 'a bound above MAX_BOUND_INF',
      reason: 'bad-key(bound)',
      run: () => verify(publicKey(F.key.B, MAX_BOUND_INF * 2), h0, s0),
    },
    {
      name: 'a NaN bound smuggled past the constructor',
      reason: 'bad-key(bound)',
      run: () => verify(withKey({ boundInf: NaN }), h0, s0),
    },

    // --- the tolerance ------------------------------------------------------
    { name: 'a zero tolerance', reason: 'bad-tolerance', run: () => verify(pub, h0, s0, 0) },
    { name: 'a negative tolerance', reason: 'bad-tolerance', run: () => verify(pub, h0, s0, -1e-9) },
    { name: 'a NaN tolerance', reason: 'bad-tolerance', run: () => verify(pub, h0, s0, NaN) },
    { name: 'an infinite tolerance', reason: 'bad-tolerance', run: () => verify(pub, h0, s0, Infinity) },
    {
      name: 'a tolerance above MAX_TOL',
      reason: 'bad-tolerance',
      run: () => verify(pub, h0, s0, MAX_TOL * 10),
    },
    {
      // 1e-16 is positive and under the cap, but boundInf + 1e-16 === boundInf at
      // this bound: the slack it promises does not survive being added.
      name: 'a tolerance below the spacing of doubles at this bound',
      reason: 'bad-tolerance',
      run: () => verify(pub, h0, s0, 1e-16),
    },

    // --- the basis ----------------------------------------------------------
    { name: 'an empty basis', reason: 'bad-key(dimension)', run: () => verify(publicKey([], 10), h0, s0) },
    {
      name: 'a non-square basis',
      reason: 'bad-key(shape)',
      run: () => verify(publicKey(mat([[1, 0, 0], [0, 1, 0]]), 10), h0, s0),
    },
    {
      name: 'a ragged basis',
      reason: 'bad-key(shape)',
      run: () => {
        const B = damagedB();
        B[3] = B[3].slice(0, n - 1);
        return verify(publicKey(B, 10), h0, s0);
      },
    },
    {
      name: 'a non-square basis smuggled past the constructor',
      reason: 'bad-key(shape)',
      run: () => verify(withKey({ B: mat([[1, 0, 0], [0, 1, 0]]) }), h0, s0),
    },
    {
      name: 'a NaN in the basis',
      reason: 'bad-key(entries)',
      run: () => {
        const B = damagedB();
        B[1][1] = NaN;
        return verify(publicKey(B, 10), h0, s0);
      },
    },
    {
      name: 'a fractional basis entry',
      reason: 'bad-key(entries)',
      run: () => {
        const B = damagedB();
        B[0][2] = 0.5;
        return verify(publicKey(B, 10), h0, s0);
      },
    },
    {
      name: 'an unsafe basis entry',
      reason: 'bad-key(entries)',
      run: () => {
        const B = damagedB();
        B[2][2] = 1e17;
        return verify(publicKey(B, 10), h0, s0);
      },
    },
    {
      name: 'a singular basis, which has no lattice to be a member of',
      reason: 'bad-key(singular)',
      run: () => {
        const B = damagedB();
        B[1] = Float64Array.from(B[0]);
        return verify(publicKey(B, 10), h0, s0);
      },
    },

    // --- H itself, re-checked as far as O(n^2) allows -----------------------
    { name: 'a missing HNF', reason: 'bad-key(hnf)', run: () => verify(withKey({ H: null }), h0, s0) },
    {
      // Without the pivot check, forward substitution divides by zero and throws
      // a RangeError instead of answering.
      name: 'an HNF with a zero pivot',
      reason: 'bad-key(hnf)',
      run: () =>
        verify(
          {
            n: 2,
            B: mat([[1, 0], [0, 1]]),
            Binv: mat([[1, 0], [0, 1]]),
            boundInf: 10,
            H: [[0n, 1n], [0n, 1n]],
            keyReason: 'ok',
            keyDetail: '',
          },
          Float64Array.from([0, 1]),
          Float64Array.from([0, 1]),
        ),
    },
    {
      // Forward substitution assumes H is upper triangular. This H is not: it
      // returns integer coordinates that do NOT reproduce s, which is exactly
      // what the exact re-multiplication exists to catch. s = (0,1) really is in
      // L(B) here -- the key is lying about H, and the verifier refuses rather
      // than taking H on faith.
      name: 'an HNF that is not triangular',
      reason: 'not-in-lattice(remul)',
      run: () =>
        verify(
          {
            n: 2,
            B: mat([[1, 0], [0, 1]]),
            Binv: mat([[1, 0], [0, 1]]),
            boundInf: 10,
            H: [[1n, 0n], [5n, 1n]],
            keyReason: 'ok',
            keyDetail: '',
          },
          Float64Array.from([0, 1]),
          Float64Array.from([0, 1]),
        ),
    },
  ];
})();

describe('the verifier fails closed', () => {
  for (const c of corpus) {
    it(`rejects ${c.name} as ${c.reason}`, () => {
      const res = c.run();
      expect(res.ok).toBe(false);
      expect(res.reason).toBe(c.reason);
      // Every rejection names something a caller can act on.
      expect(res.detail.length).toBeGreaterThan(0);
    });
  }

  it('reports a broken key at construction instead of throwing', () => {
    // publicKey() is where the O(n^3) work happens, and a bad basis is a result
    // the UI has to display -- not an exception thrown at whoever asked for it.
    const { key } = fixture(4242);
    const singular = key.B.map((r) => Float64Array.from(r));
    singular[1] = Float64Array.from(singular[0]);
    expect(publicKey(singular, 10).keyReason).toBe('bad-key(singular)');
    expect(publicKey([], 10).keyReason).toBe('bad-key(dimension)');
    expect(publicKey([], 10).H).toBeNull();
    expect(publicKey(key.B, NaN).keyReason).toBe('bad-key(bound)');
    expect(publicKey(key.B, roundOffBoundInf(key.R)).keyReason).toBe('ok');
  });

  it('has a probe for every reason the type declares', () => {
    // A new VerifyReason with no probe fails here. 'ok' and 'too-far' are owned
    // by the positive suite above.
    const declared: VerifyReason[] = [
      'bad-key(dimension)',
      'bad-key(shape)',
      'bad-key(entries)',
      'bad-key(singular)',
      'bad-key(hnf)',
      'bad-key(bound)',
      'bad-tolerance',
      'bad-vector(length)',
      'bad-vector(nonfinite)',
      'bad-vector(domain)',
      'not-in-lattice(frac)',
      'not-in-lattice(remul)',
    ];
    const covered = new Set(corpus.map((c) => c.reason));
    expect(declared.filter((r) => !covered.has(r))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The rule this file retired, kept as a witness
// ---------------------------------------------------------------------------

/**
 * The float membership rule as it stood before the hardening, transcribed
 * exactly -- including the shape that makes it fail OPEN.
 *
 * It rejects only when a comparison is TRUE, and every comparison against NaN is
 * false, so anything that poisons the arithmetic walks out of the bottom of the
 * function with an `ok`. Its second tolerance, 1e-6 * max|s|, grows with the
 * signature, so a large enough vector is graded against a limit it set itself.
 * Both failures are demonstrated below rather than asserted in prose.
 */
function retiredVerdict(pub: PublicKey, h: Vec, s: Vec, tol: number = LATTICE_TOL): VerifyReason {
  const B = pub.B;
  const Binv = pub.Binv as Mat;
  const z = vecMat(s, Binv);
  let fracMax = 0;
  for (let i = 0; i < pub.n; i++) {
    const f = Math.abs(z[i] - rnd(z[i]));
    if (f > fracMax) fracMax = f;
  }
  let distInf = 0;
  for (let i = 0; i < pub.n; i++) {
    const d = Math.abs(s[i] - h[i]);
    if (d > distInf) distInf = d;
  }
  if (fracMax > tol) return 'not-in-lattice(frac)';
  const back = vecMat(roundVec(z), B);
  let remul = 0;
  for (let i = 0; i < pub.n; i++) {
    const r = Math.abs(back[i] - s[i]);
    if (r > remul) remul = r;
  }
  if (remul > tol * Math.max(1, maxAbsVec(s))) return 'not-in-lattice(remul)';
  if (distInf > pub.boundInf + tol) return 'too-far';
  return 'ok';
}

describe('the three inputs the audit got past the old verifier', () => {
  const F = fixture(4242);
  const h0 = randomH(n, makeRng(77));
  const s0 = signRoundOff(h0, F.key.R, F.Rinv);

  it('accepted the empty vector, which is now bad-vector(length)', () => {
    const empty = new Float64Array(0);
    expect(retiredVerdict(F.pub, h0, empty)).toBe('ok');
    expect(verify(F.pub, h0, empty).reason).toBe('bad-vector(length)');
  });

  it('accepted a NaN-bearing vector, which is now bad-vector(nonfinite)', () => {
    const poisoned = Float64Array.from(s0);
    poisoned[3] = NaN;
    expect(retiredVerdict(F.pub, h0, poisoned)).toBe('ok');
    expect(verify(F.pub, h0, poisoned).reason).toBe('bad-vector(nonfinite)');
  });

  it('accepted a non-lattice vector at 1e17, which is now bad-vector(domain)', () => {
    const huge = new Float64Array(n);
    huge[0] = 1e17;
    expect(retiredVerdict(F.pub, huge, huge)).toBe('ok');

    // Why it got in: the vector misses the lattice by a re-multiplication residue
    // of about 2.7e3, and the old rule compared that against 1e-6 * 1e17 = 1e11.
    // The tolerance had grown eight orders past the error it was policing.
    const Binv = F.pub.Binv as Mat;
    const back = vecMat(roundVec(vecMat(huge, Binv)), F.pub.B);
    let residue = 0;
    for (let i = 0; i < n; i++) residue = Math.max(residue, Math.abs(back[i] - huge[i]));
    expect(residue).toBeGreaterThan(1e3);
    expect(residue).toBeLessThan(1e-6 * maxAbsVec(huge));

    expect(verify(F.pub, huge, huge).reason).toBe('bad-vector(domain)');
  });
});

// ---------------------------------------------------------------------------
// Everything that must STILL be accepted
// ---------------------------------------------------------------------------

describe('the hardened verifier still accepts what is genuine', () => {
  it('accepts Klein/GPV signatures against the Klein bound', () => {
    // Klein signatures are about 4x longer than round-off ones, so they are
    // graded against their own published bound. They are lattice points made by
    // a different sampler, and the exact membership test must not care which.
    const { key, rng } = fixture(20260908);
    const sigma = kleinSigma(key.R);
    const kleinPub = publicKey(key.B, kleinBoundInf(sigma));
    const roundOffPub = publicKey(key.B, roundOffBoundInf(key.R));
    const sign = makeKleinSigner(key.R, rng, sigma);
    let accepted = 0;
    let tooFar = 0;
    for (let t = 0; t < 100; t++) {
      const h = randomH(n, rng);
      const s = sign(h);
      if (verify(kleinPub, h, s).reason === 'ok') accepted++;
      // Against the round-off signer's bound the same signature is a lattice
      // point that is simply too long: it fails on distance, never on membership.
      if (verify(roundOffPub, h, s).reason === 'too-far') tooFar++;
    }
    expect(accepted).toBe(100);
    // Measured on this fixture: bound 22.5 for round-off against 137.4 for Klein,
    // and ||s-h||inf over 100 Klein signatures runs 20.4 (min) / 41.3 (median) /
    // 84.6 (max). The two distributions just overlap at n=12 with GGH's small k,
    // so 98 of 100 are too long for the round-off bound and 2 are legitimately
    // short enough. That overlap is a fact about these parameters, not a verifier
    // fault -- klein.ts measures 121-151 against a bound of 29-31 at n=16 with
    // the lab's larger k, where there is no overlap at all. Asserting the
    // majority rather than all of them keeps this test honest.
    expect(tooFar).toBeGreaterThanOrEqual(90);
  });

  it('accepts every forgery a successful Break 2 produces', () => {
    // Claim C5 is decided by this verifier, so hardening it is only honest if the
    // attack still gets past it. n=8 with GGH's own k is the fast configuration
    // (measured ~0.2 s); see break2.test.ts for why k matters to this attack.
    const bn = 8;
    const key = gghKeygen(bn, { rng: makeRng(20260908), k: paperK(bn) });
    const pub = publicKey(key.B, roundOffBoundInf(key.R));
    expect(pub.keyReason).toBe('ok');

    const rng = makeRng(4242);
    const res = runBreak2({
      pub,
      sign: makeRoundOffSigner(key.R, inverse(key.R)),
      rng,
      startN: 4000,
      capN: 32000,
      forgeries: 20,
    });

    // Break 2's own success test IS this verifier, so 20/20 here is already the
    // hardened path saying yes.
    expect(res.ok).toBe(true);
    expect(res.Rhat).not.toBeNull();
    expect(res.attempts[res.attempts.length - 1].forgeriesAccepted).toBe(20);

    // And again on fresh messages, reading the reason rather than just the flag.
    const Rhat = res.Rhat as Mat;
    const RhatInv = inverse(Rhat);
    for (let t = 0; t < 50; t++) {
      const h = randomH(bn, rng);
      const out = verify(pub, h, signRoundOff(h, Rhat, RhatInv));
      expect(out.reason).toBe('ok');
      expect(out.ok).toBe(true);
      expect(out.distInf).toBeLessThanOrEqual(pub.boundInf);
    }
  }, 60000);
});
