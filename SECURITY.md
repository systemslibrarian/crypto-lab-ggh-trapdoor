# Security policy

## This is a teaching demo, not production cryptography

Read this part before anything else.

The scheme this lab implements — GGH, the 1997 lattice trapdoor — **is broken, and this
repository breaks it on purpose.** Two working attacks ship inside the page: Nguyen's mod-2σ
reduction (CRYPTO 1999) against GGH encryption, and the Nguyen–Regev learning-a-parallelepiped
attack (EUROCRYPT 2006) against the GGH signature design. They are the exhibits. They succeed.

Nothing in `src/` is fit to protect real data, and the reasons are not subtle:

- **Toy parameters.** Dimensions run from n = 8 to n = 60. Real lattice schemes live in the
  hundreds, and the attacks demonstrated here are what forced that.
- **Floating-point lattice arithmetic.** The maths is carried in JavaScript doubles with
  explicit integer-exactness guards (see `allIntegersUnder2p53` in `src/lattice/matrix.ts`).
  Those guards exist so the *proofs on screen* are honest, not so the *scheme* is safe.
- **Determinism is a feature.** Every experiment runs off a seeded PRNG, never
  `Math.random()`, so results reproduce. Predictable randomness is a requirement of a lab and
  a fatal flaw in a cryptosystem.
- **The private key is on screen by design.** The whole lesson is the private basis `R` next
  to the public basis `B = U·R`. It is rendered, logged, and handed to the attacks.
- **No side-channel resistance of any kind.** Nothing here is constant-time.

If you want the modern versions of these ideas, look at ML-KEM (FIPS 203) and ML-DSA
(FIPS 204), which are designed against exactly the attacks this lab demonstrates.

## What is *not* a vulnerability in this repository

These are all working as intended, and reports of them will be closed with a pointer to this
section:

- The GGH scheme is breakable. Yes. That is the lesson.
- The private basis, the seed, and the error vector are visible in the page and in memory.
- Seeded, reproducible randomness.
- Small dimensions, or key generation that visibly re-keys when a basis is singular mod 6.

## What *is* worth reporting

1. **A claim the code does not prove.** A verdict on the page that is stronger than the check
   that produced it — "recovered" where only "forged" was demonstrated, a bound stated without
   the caveat it needs, a number in the README that no run reproduces. In this repository that
   is the most serious class of defect there is, and it is treated with the priority a security
   bug would get elsewhere. See the invariants I1–I5 in [CONTRIBUTING.md](CONTRIBUTING.md).
2. **Anything that makes the published page unsafe for a visitor.** Injection through a URL
   parameter or input field, a request to a third-party origin (the built page loads no
   third-party scripts, styles, fonts, or analytics — every asset it fetches is its own), or
   anything that could execute attacker-controlled content.
3. **Anything in the build or release path.** The lab has no runtime dependencies; build tools
   install from the committed `package-lock.json` with `npm ci`, GitHub Actions are pinned to
   full commit SHAs, and the workflow holds `contents: read` except in the single job that
   publishes. A hole in any of that — a way to get unreviewed content onto the Pages site, or a
   dependency bump that could merge itself without passing the gate — is in scope.

## How to report

Open an issue: <https://github.com/systemslibrarian/crypto-lab-ggh-trapdoor/issues>

Public is the right default here. There is no server, no account system, no user data and no
deployed secret to protect, so nothing is made worse by discussing the problem in the open, and
the fix is a commit anyone can review. If you would still rather not post publicly, use
GitHub's private vulnerability reporting on the repository's **Security** tab where it is
enabled.

Useful in a report:

- the commit SHA or the live URL you were on;
- browser and version;
- the controls you used (dimension `n`, seed, which act);
- what the page **claimed**, and what you can show is actually true.

## Supported versions

`main`, and the GitHub Pages deployment built from it. There are no tagged releases yet and
there are no backports: the supported version is the one currently published.

No bounty and no response-time guarantee. This is a single-maintainer educational project.
