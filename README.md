# GGH Trapdoor

**Goldreich–Goldwasser–Halevi · CRYPTO 1997 · lattice trapdoor**

Same lattice, two bases: the short one decrypts, the long one doesn't — then the two
breaks that turned GGH into a lesson.

---

## What It Is

A browser demo of the **Goldreich–Goldwasser–Halevi** lattice cryptosystem (CRYPTO 1997) and
of the two classical attacks that ended it: **Nguyen's mod-2σ reduction** (CRYPTO 1999) against
GGH *encryption*, and the **Nguyen–Regev learning-a-parallelepiped** attack (EUROCRYPT 2006)
against GGH *signatures*. Everything runs on real integer matrices you can inspect: Babai
round-off decryption (Babai, Combinatorica 1986), exact linear algebra over GF(2) and GF(3),
a real LLL reduction, a real fourth-moment gradient descent, and a real Hermite Normal Form
public key (Micciancio, CaLC 2001). Nothing is simulated and no result is hardcoded.

**The idea it teaches.** A lattice trapdoor is a *good basis*. Encryption puts the message on
a lattice point and adds a small error; decryption is Babai round-off, which recovers the
right point only when the basis is nearly orthogonal. The public and private bases describe
the *identical* set of points — the page proves that with exact integer arithmetic — and the
only thing separating them is shape.

**What the two breaks actually show.** Neither one solves a hard lattice problem head-on;
both exploit the shape of GGH's own randomness, and they attack **two different schemes**:

- **Nguyen 1999 broke GGH encryption.** Every entry of the error `e` is `±σ`, so all of them
  are congruent to `σ` mod `2σ`. Then `c + s ≡ m·B (mod 2σ)` for `s = (σ,…,σ)`, which leaks
  `m mod 2σ` by linear algebra and shrinks the residual error from `σ√n` to `√(n/4)`. Ordinary
  lattice reduction finishes the job. Nguyen solved four of the five published challenges;
  dimension 400 held out until 2010.
- **Nguyen–Regev 2006 broke the GGH signature design**, and NTRUSign with it. Every
  deterministic Babai signature is a uniform sample from the parallelepiped spanned by the
  secret basis, and a fourth-moment descent recovers that basis up to sign and order.

Falcon's Gaussian sampling and ML-KEM's centered-binomial errors exist because of these two
results. Act 5 shows the contrast directly.

**Security model, stated plainly.** Not production cryptography. This is a teaching demo at
dimensions 8–60, where the attacks finish in a browser tab; GGH was proposed at 200–400. GGH
is broken at *every* dimension — that is the subject of the lab, not a caveat about the code.
The private key exists only in the page's memory for the session and is never persisted or
transmitted. The demo does **not** prove anything about the security of modern lattice
cryptography: ML-KEM and Falcon are not vulnerable to either attack here, and the page says
why.

**One deliberate parameter change, and why.** GGH's own recipe is `R = k·I + E` with `E`
uniform in `{−l..l}` and `k ≈ √n·l` (its §5.2 instantiation is `4⌈√n⌉·I + rand(±4)`). Measured
at these dimensions, that rule *does not decrypt*: with `σ = 3` the legitimate key owner fails
to recover the message **74% of the time at n=8** and 10.5% at n=32, because invariant I2 is
violated. That is not a bug in GGH — the paper *derives* σ from the basis and it only lands
near 3 at the paper's own dimensions of 200–400, while the published challenges fixed σ = 3
exactly. Since `2σ = 6` is the modulus Break 1 runs in, σ is held at 3 and `k` is raised to
`ceil(2·l·√n) + 4l`, which gives a worst-case I2 bound of **0.121–0.136, flat from n=8 to
n=60** — a guarantee rather than luck. Act 4 keys separately with GGH's *own* `k`, because it
attacks a signature scheme where I2 does not apply and the larger `k` costs ~16× more
signatures. Both choices are stated on the page.

## Exhibits

1. **Two bases, one lattice.** Generates the private basis `R = k·I + E` and the public
   `B = U·R`. Proves `L(B) = L(R)` by recovering integer `U` and `V` from `R` and `B` alone and
   checking `U·R = B`, `V·B = R` and `U·V = I` exactly — no determinant is ever formed, because
   `det B` reaches 10^89 here. Reports the orthogonality defect of each basis (as log10; the
   public basis defect passes 2^53 in linear form from n=16 up) and plots both bases at one
   shared scale.
2. **Encrypt, then decrypt twice.** `c = m·B + e`. The same Babai round-off runs with each
   basis; only the basis changes. Invariant **I2** is displayed per ciphertext: round-off
   succeeds *if and only if* `max|e·basis⁻¹| < ½`. Measured with zero mismatches over 5,600
   ciphertexts — ~0.1 with the private basis, 7–15 with the public one.
3. **Break 1 — Nguyen 1999**, as a six-step stepper: the mod-6 solve (exact, over GF(2) and
   GF(3) then CRT — never eliminating mod 6, which has zero divisors), the exact division, the
   embedding plus LLL, the read-off, the recovery, and verification **by re-encryption** rather
   than by peeking at the message. Switch the error to a non-constant magnitude and watch it
   fail.
4. **Break 2 — Nguyen–Regev 2006**, in a Web Worker: collect round-off signatures, plot the
   offsets `s − h` against the *true* projection of `P(R)` (a zonogon computed exactly from the
   secret rows, never a drawn box), whiten by the covariance, and minimise the fourth moment on
   the sphere. The signatures-consumed counter is measured live. Recovery is claimed only when
   the **real verifier** accepts forgeries signed with the recovered rows.
5. **Why modern schemes look different.** Falcon's sampler lineage (Klein → GPV → Peikert →
   Ducas–Prest) and its spherical Gaussian output; ML-KEM's centered binomial with η₁/η₂; and
   a note that "GGH" names three different constructions, two of which are multilinear maps —
   Shai Halevi is an author of all three.

## When to Use It

- Use it to **see what a trapdoor actually is**, because "a good basis" is much more concrete
  once the same lattice is drawn twice and only one basis decrypts.
- Use it to **teach why Falcon samples instead of rounding**, because the parallelepiped is on
  screen and the Gaussian comparison runs the same attack code against both signers.
- Use it to **show that a broken scheme is not usually broken by brute force**, because both
  attacks here are about the shape of the randomness and neither needs the private key.
- Do **not** use it as a lattice-cryptography implementation, as evidence about ML-KEM or
  Falcon, or for anything real — it is a demo app and does not provide hardened operational
  controls.

## Live Demo

**https://systemslibrarian.github.io/crypto-lab-ggh-trapdoor/**

Drag the dimension slider, generate a key pair and read the same-lattice proof, encrypt a
message and compare the two decryptions, step through Break 1, then flip the error mode to
`uniform` and step through it again to watch the attack die. In Act 4, run the descent and
then run it again against Gaussian signatures.

## What Can Go Wrong

- **The public basis is singular mod 6.** Break 1 needs `B` invertible mod 2 *and* mod 3, and
  only **12–17%** of random keys are. Keygen resamples until the determinant is coprime to 6
  (mean 5.8–6.5 draws) and the page reports how many keys it drew. Without that filter the
  attack fails on ~85% of keys.
- **Decryption fails even for the legitimate owner** if `k` is too small for `σ`. That is
  invariant I2, and the page displays both the per-ciphertext value and the worst case over
  *every* error vector, so a failure is predicted rather than surprising.
- **A non-congruent error defeats Break 1 — but not the way it looks like it should.** The
  intuitive story is that the exact division by 6 comes out fractional. It does not: measured
  exact in **1120/1120** tampered trials, because `m₀` solves the congruence by construction.
  What breaks is that `m₀` is the *wrong residue* (~83% of coordinates wrong), so the residual
  problem has no short planted vector. The page says exactly this.
- **Break 2 can exceed its cap.** It then reports failure with the ladder it climbed. It never
  claims a success it did not verify against the real verifier, and a non-null candidate basis
  is explicitly *not* treated as success.
- **The in-sample fourth moment lies.** At N=4000 it reads 0.31 for Gaussian signatures, which
  looks like structure. Held out, it collapses to zero. The hold-out split is built in and not
  optional.
- **Below n=8 the attack still works but is unreadable** — at n=4 it succeeds 5% of the time
  at 500 signatures and 60% at 2000, so the same code gives a different answer each run. The
  page says so rather than pretending the dimension is unsupported.

## Real-World Usage

GGH itself is dead, and its two breaks are why several live standards look the way they do.
**Falcon** (FIPS 206 draft) signs by sampling a spherical discrete Gaussian over the shifted
lattice rather than rounding, using the Ducas–Prest fast-Fourier sampler in the GPV framework;
its specification states that setting the sampler width to zero — signing deterministically —
"opens the door to learning attacks" of exactly the Nguyen–Regev kind. **ML-KEM** (FIPS 203)
draws every secret and error coefficient from a centered binomial distribution with parameters
η₁, η₂, so no single modulus makes every coefficient congruent to the same thing and Nguyen's
mod-2σ observation has no analogue. **NTRUSign** shipped the same round-off signature shape as
GGH and fell to the same descent, at 400 signatures without perturbation. **Micciancio's HNF
public key** is the standard fix for GGH-style key size and is implemented here.

## How to Run Locally

```sh
npm ci
npm run dev          # http://localhost:5173/crypto-lab-ggh-trapdoor/
```

```sh
npm run build        # tsc --noEmit && vite build
npm test             # Vitest unit + KAT suite
npm run test:a11y    # axe-core WCAG 2.1 A/AA gate against the production build
npm run test:claims  # the claims suite: does the page tell the truth?
```

## Related Demos

- [Lattice Gentle](https://systemslibrarian.github.io/crypto-lab-lattice-gentle/) — lattices,
  SVP and CVP from zero. Start there if the words are new.
- [LLL Break](https://systemslibrarian.github.io/crypto-lab-lll-break/) — LLL itself, as the
  subject rather than as a step.
- [Falcon Seal](https://systemslibrarian.github.io/crypto-lab-falcon-seal/) — the Gaussian
  sampler that Act 5 contrasts against round-off signing.
- [NTRU Classic](https://systemslibrarian.github.io/crypto-lab-ntru-classic/) — the lattice
  scheme that survived, next to the one that did not.

## Build & Verify

**157 tests, all passing**: 141 Vitest unit tests across 13 files, 2 Playwright accessibility
tests, and 14 claims tests.

The unit suite covers the same-lattice proof (C1), the decryption bound as an exact iff (C2),
the mod-6 solve against brute force at small dimensions, LLL reducedness checked by
independently recomputing the Lovász and size-reduction conditions, Break 1 end to end at
n = 8/16/32 verified by re-encryption (C3), the negative case (C4), the fourth-moment formula
against Monte-Carlo, Break 2 recovery verified by **forgery against the real verifier** (C5),
the Gaussian negative case (C5′), and the HNF's canonicity — asserted, not claimed, by
computing `HNF(R)` and `HNF(U·R)` and requiring them identical.

The claims suite checks that the *page* tells the truth: every headline number is either
cross-checked against another value the page printed, or re-derived from the page's own
displayed inputs by a different route than the source takes. It also covers retirement (a new
key clears every stale verdict), the no-op guard (re-selecting the same value must *not*
retire a fresh verdict), the `[hidden]` cascade probe, and the §4.1d negative claim with its
evidence fixture.

The accessibility gate scans the **production build** for zero WCAG 2.1 A/AA violations across
18 driven states at two viewports, asserting axe's `incomplete` bucket as well as `violations`
and running the tag and rule sets as separate `analyze()` calls. It blocks the deploy.

### Measured numbers, and one correction to the plan

Everything below was measured through this implementation, not estimated.

| Quantity | Measured |
|---|---|
| I1 largest intermediate value at n=60 | 3.4e4 against 2^53 — margin 2.7e11 |
| I2 worst case, private basis, n=8→60 | 0.121–0.136 (guarantee, margin ≥3.6×) |
| I2 actual, public basis | 7.3–15.3 — 12–30× over the ½ threshold |
| Keys invertible mod 6 | 12.0–17.0% |
| Break 1, whole attack at n=60 | 4.6 ms median (LLL 2.9 ms) |
| Break 1 shortest reduced row, honest | exactly √(n+1); tampered 3–4× larger, zero overlap in 1120 trials |
| Break 2 at n=8 / n=16 | recovers at 8,000 / 32,000 signatures; 20/20 forgeries accepted |
| Break 2 held-out `Σa⁴`, round-off vs Gaussian | ~1.00 vs ~0.006 |
| HNF at n=60 | 34 ms; transform coefficients reach 10^111 |

**The plan said this could be BigInt-free. It cannot.** Fraction-free (Bareiss) LLL carries
the leading principal minors of the Gram matrix, whose final value is `det(B)²` — that is
10^16.3 at **n=8**, the smallest dimension offered, and 10^177.8 at n=60 (10^213.9 for Break 1's
embedding lattice). `det(B)²` is a lattice invariant, so no reduction makes it smaller. LLL
here therefore uses floating-point Gram–Schmidt with exact integer basis updates and a runtime
`Number.isSafeInteger` guard, and BigInt is confined to the HNF path. Everything else is
Number-safe with the margins above.

## Performance

Break 1 runs on the main thread: 4.6 ms at n=60, well inside one animation frame. Break 2's
descent runs in a **Web Worker** — it is the part that blocks, at ~2.1 s for n=16 — and posts
progress once per restart, which is what drives the live counter. The worker is instantiated as
`new Worker(new URL('./break2.worker.ts', import.meta.url), { type: 'module' })`, the only form
Vite rewrites into a base-prefixed chunk under a GitHub Pages project subpath.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
