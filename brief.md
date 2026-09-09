NEW DEMO BRIEF
- Repo name:         crypto-lab-ggh-trapdoor
- Short name (H1):   GGH Trapdoor
- Subtitle:          Goldreich-Goldwasser-Halevi · CRYPTO 1997 · lattice trapdoor
- One-liner:         Same lattice, two bases: the short one decrypts, the long one doesn't — then the two breaks that turned GGH into a lesson.
- Concept to teach:  A lattice trapdoor is a *good basis*. Encryption is a lattice point plus a
                     small error; decryption is Babai round-off, which only works with a
                     nearly-orthogonal basis. Both historic breaks attack the trapdoor's *shape*,
                     not lattice hardness: Nguyen 1999 exploits a too-regular error vector,
                     Nguyen-Regev 2006 exploits the parallelepiped that round-off signatures leak.
                     Falcon's Gaussian sampling answers the second paper directly; ML-KEM's
                     binomial errors are why the first has no analogue there. (Amended: the
                     original "exist because of these two papers" is a stronger causal claim
                     than the sources support for ML-KEM.)
- Primitives/spec:   Integer lattices (dim 8-60), Babai round-off (Babai 1986), LLL (in-browser,
                     real), Hermite normal form public key (Micciancio 2001 variant, shown as the
                     fix for pk size), Nguyen 1999 mod-2sigma reduction + embedding attack,
                     Nguyen-Regev 2006 learning-a-parallelepiped (moment-based gradient descent).
                     All classical, all real, no simulation.
- Accent (--accent): #35d6bb
- Favicon emoji:     🧱
- In scope:          see ACTS
- Non-goals:         Re-teaching SVP/CVP/LLL from zero (link lattice-gentle and lll-break); GGH at
                     the 1997 challenge dimensions (200-400); BKZ in the browser; NTRUSign itself
                     (mention as the same break); GGH13 multilinear maps (name-collision note only)

Accent note: assigned centrally as #35d6bb (teal). It is the only colour in the catalog's
four-colour rotation not already used by the four named neighbours — falcon-seal #ffb84d,
ntru-classic #ffb84d, lll-break #9f88ff, lattice-gentle #ff6b7f.

----------------------------------------------------------------------
SCOPE

Teach one asymmetry (good basis vs bad basis) and two shape attacks.
Dimension slider 8 -> 60. Everything runs on real integer matrices the
learner can inspect; no hidden constants.

ACTS
 1. Two bases, one lattice. Secret R = square-ish integer matrix near
    kI with small noise (GGH's recipe). Public B = U·R for a random
    unimodular U (and, as a toggle, Micciancio's HNF(R)). Show both
    generate identical lattice points; show orthogonality defect of
    each. Headline visual: the 2-D projection of both bases.
 2. Encrypt / decrypt. c = m·B + e, e in {±sigma}^n with sigma = 3 (GGH's
    original choice). Decrypt with R via round-off round(c·R^-1)·R; show
    the same round-off with B failing. This IS the trapdoor.
 3. Break 1 — Nguyen 1999. Because every entry of e is ±sigma,
    e = sigma·(1,...,1) (mod 2sigma). So c - sigma·(1,...,1) = m·B (mod 2sigma); solve
    m mod 2sigma by linear algebra mod 6 whenever B is invertible mod 6.
    Write m = m0 + 2sigma·m', the residual CVP has error in {0,-1}^n,
    small enough for embedding + LLL to finish at these dimensions.
    Learner toggles: sigma = 3 vs a non-constant-magnitude error -> the
    mod-2sigma step stops working. That toggle is the lesson.
 4. Break 2 — Nguyen-Regev 2006 (GGH *signatures*). Sign = round-off
    of hashed message with R: s = round(h·R^-1)·R. Show s - h is uniform in
    the fundamental parallelepiped P(R). Collect signatures, plot the
    cloud, run the moment-based descent (whiten with covariance, then
    minimise the fourth moment on the sphere) and recover ±rows of R.
    Counter of signatures consumed until recovery is measured live,
    never stated as a constant.
 5. Why it matters. Side-by-side: GGH round-off vs Falcon's Gaussian
    sampler (link falcon-seal) — same lattice picture, but the
    signature cloud no longer has the parallelepiped's corners.
    One-line pointer to ML-KEM's centered-binomial errors.

SECURITY / CORRECTNESS INVARIANTS
 I1. Both bases must provably span the same lattice: compute integer
     U = B·R^-1 and V = R·B^-1 and verify U·V = I over the integers;
     display U.
 I2. Decryption correctness is a bound, not a claim: round-off with R succeeds
     whenever |e·R^-1|_inf < 1/2 and fails whenever it exceeds 1/2; equality is
     decided by the tie rule and the integer coordinate. Compute and display it
     per ciphertext. (Amended: "iff" is false at exactly 1/2; both tie outcomes
     are now constructed deliberately in roundoff.test.ts.)
 I3. Break 1's mod-2sigma step must be exact linear algebra mod 6, never
     a heuristic; when B is singular mod 6 the act says so and re-keys.
 I4. Break 2 recovers R up to sign/permutation only — display and
     check that, don't claim "recovered R". (Amended after audit: forging and
     recovering are TWO independent outcomes. Accepted forgeries prove only that
     the candidate is a good basis of the lattice; only the lab, holding the
     secret, can say whether it is the secret one. The page renders both and
     never collapses them. Sample cost is reported as training + held-out =
     total observed, never as the training half alone.)
 I5. Every "attack succeeded" is checked against the real decryptor /
     real signature verifier, not by comparing to the secret.

ARCHITECTURE
 Single page, TypeScript. LLL uses floating-point Gram-Schmidt with exact
 integer basis updates, plus runtime guards on the float path; BigInt is
 confined to the HNF path. (Amended: the original brief said "BigInt-free,
 dim <= 60 fits in Number with fraction-free LLL" and asked that the
 overflow bounds be verified rather than assumed. They were: fraction-free
 LLL carries leading principal minors of the Gram matrix, which overflow
 Number long before dim 60, so the fraction-free route is not taken. The
 measured figures are recorded in the README's Build & Verify section.)
 Round-off, mod-6 solve, whitening, and descent are separate modules with no
 shared code path to the break-check. (Amended: the brief puts LLL in the Web
 Worker, but measured it does not block -- the whole of Break 1 is 4.6 ms at
 n=60, of which LLL is 2.9 ms. The fourth-moment DESCENT is what blocks, at
 ~1-3 s, so that is what runs in the worker.)

UI
 Dimension slider · sigma selector · basis pair viewer · ciphertext strip
 with e highlighted · Break 1 stepper · Break 2 signature-cloud canvas
 with live "signatures consumed" counter · Falcon comparison panel.
 Plain-language intro before any matrix appears.

VISUAL SEMANTICS
 Short basis = warm/accent; long basis = neutral. The parallelepiped
 is drawn as the actual P(R) projection, never a stylised box. Never
 draw the error e larger than it is relative to the basis — the
 picture must agree with I2.

EDGE CASES
 dim < 8 (Break 2 statistics too thin — say so); B singular mod 6;
 LLL not finishing the embedding at dim 60 in the browser (show the
 partial result and the honest time); signature counter exceeding a
 configurable cap without recovery (report failure, do not fake it).

EXTENSION SEAMS
 HNF public key act (Micciancio 2001) as optional depth; NTRUSign
 parallelepiped as a second dataset behind the same descent module.

CLAIMS (e2e/claims.spec.ts)
 C1 same-lattice check (I1) on 50 random keys at dims 8/16/32.
 C2 decryption bound (I2) predicts success on 200 ciphertexts.
 C3 Break 1 recovers m on every key with B invertible mod 6, dim <= 32.
 C4 Break 1 FAILS its mod-2sigma step when e entries are drawn from
    {-3..3} — the negative claim per §4.1d.
 C5 Break 2 recovers rows of R up to sign/perm at dim 16 within the
    cap; C5' Break 2 fails when signatures use Gaussian sampling.

CITATIONS (verified before this brief)
 Goldreich, Goldwasser, Halevi — "Public-key cryptosystems from lattice
   reduction problems", CRYPTO 1997.
 Nguyen — "Cryptanalysis of the Goldreich-Goldwasser-Halevi cryptosystem
   from Crypto '97", CRYPTO 1999.
 Nguyen, Regev — "Learning a parallelepiped: cryptanalysis of GGH and
   NTRU signatures", EUROCRYPT 2006 (J. Cryptology 2009).
 Babai — "On Lovasz' lattice reduction and the nearest lattice point
   problem", Combinatorica 1986.
 Micciancio — "Improving lattice based cryptosystems using the Hermite
   normal form", CaLC 2001.

POST-BUILD AMENDMENT (external audit, 2026-09-08)
 An audit scored the first release 7.8/10 and found one thing the brief did not
 anticipate: at dimensions 8-60 ordinary LLL on the PUBLIC basis alone already
 recovers a basis as good as the private one (12/12 seeded keys per dimension,
 60/60 ciphertexts decrypted). That is not a defect -- it is why GGH was proposed
 at 200-400 -- but the lab was implying a security property it does not have at
 these sizes. A public-LLL baseline exhibit was added between Acts 2 and 3, and
 every headline claim is now scoped to raw-basis Babai. The HNF act, listed above
 as a toggle, was also shipped for real: it had been implemented and tested but
 never wired into the page while the README described it as an exhibit.

VERIFY BEFORE BUILD (do not assume)
 - grep the catalog for GGH, Babai, parallelepiped, NTRUSign — the live
   card list I read shows none, but confirm against source.
 - Category chip: POST-QUANTUM or ATTACKS — check CATEGORIES and report
   the resulting split; do not add a category.
 - README section ids per the §5 list in _MASTER-TEMPLATE.md.
