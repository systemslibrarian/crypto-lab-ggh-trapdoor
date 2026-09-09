# GGH Trapdoor: path to a 10/10 gold standard

> Audit date: 2026-09-08  
> Audited commit: `2dcda07cc029b577b141ed51ce33807a0e47aad3`  
> Scope: mathematics, claim honesty, pedagogy, UX, accessibility, testing, CI, and release maturity.

## Executive verdict

**Current defensible score: about 7.8/10.**

This is already an unusually rigorous educational crypto demo. It runs real lattice operations, states meaningful invariants, uses deterministic seeds, tests negative claims, drives a production build in Playwright, and has a much stronger accessibility oracle than a routine axe scan.

It is not yet a defensible 10/10 because several trust-boundary claims are stronger than the implementation proves, and the central interaction can leave contradictory evidence on screen. The most important work is not adding more algorithms. It is making every claim exactly match what was demonstrated, making the decisive comparison persist, and turning the excellent but static evidence into reproducible release artifacts.

The shortest summary is:

1. Show that ordinary public-basis LLL also breaks these toy keys.
2. Make the signature verifier genuinely fail closed.
3. Separate "forgeries accepted" from "the secret rows were recovered."
4. Preserve private and public decryption results side by side and eliminate stale captions.
5. Either expose HNF in the app or stop presenting it as an app exhibit.
6. Tighten edge-case mathematics, evidence provenance, mobile canvases, async states, and release hardening.

## Evidence collected

| Check | Result |
|---|---|
| `npm run build` | Passed: TypeScript and Vite production build |
| `npm test` | Passed: 141/141 tests in 13 files |
| `npm run test:e2e` | Passed: 16/16 Playwright tests |
| `CI=1 npm run test:claims` | Passed: 14/14 with local server reuse disabled |
| Browser inspection | Desktop 1440x1000 and mobile 320x800 |
| Horizontal reflow at 320 px | Passed: 318 px document width in a 320 px viewport |
| Mobile page length | 12,240 px at the initial 320x800 state |
| Mobile basis canvas | 720x360 bitmap displayed at 241x120 CSS pixels |
| Working tree before report | Clean |

The green suites are real strengths, but they do not cover every finding below. Targeted audit probes found verifier and public-LLL cases that should become committed regressions.

## Scorecard

| Area | Score | Why it is not yet 10 |
|---|---:|---|
| Core mathematical implementation | 8.5 | Strong algorithms, but several boundary statements and recovery labels are too strong |
| Claim honesty and provenance | 7.0 | Public LLL baseline is absent; empirical tables are not generated artifacts |
| Test rigor | 9.0 | Excellent breadth, but no adversarial verifier corpus, public-LLL baseline, automated mutation gate, or fail-on-flaky policy |
| Pedagogy | 7.5 | Excellent narrative backbone; proof detail arrives before the central comparison and the comparison is not persistent |
| UX and interaction state | 6.5 | Contradictory captions, overwritten outcomes, incomplete cancellation/error states |
| Accessibility | 8.5 | Deep custom gate; missing 320 px, keyboard-only, touch, forced-colors, and WebKit/VoiceOver coverage |
| Reproducibility and release | 7.5 | Deterministic app and lockfile; missing generated evidence, pinned toolchain/actions, and immutable release artifacts |

## What is already gold-standard material

- The same-lattice proof checks both inclusions and the integer inverse relation instead of relying on an unsafe floating-point determinant. See [src/lattice/invariants.ts](src/lattice/invariants.ts#L77).
- The mod-6 attack correctly solves over GF(2) and GF(3), then combines with CRT, rather than pretending that integers modulo 6 form a field. See [src/attack/mod6.ts](src/attack/mod6.ts#L20).
- LLL keeps exact integer basis updates while guarding the floating-point Gram-Schmidt path. The tests independently check reducedness.
- Break 1 is verified by re-encryption rather than by comparing only with a hidden message.
- Break 2 uses held-out data, reports a cap honestly, and routes claimed forgeries through a public verifier.
- The HNF implementation and tests are unusually substantial, including canonicity and same-lattice checks in BigInt. See [src/lattice/hnf.ts](src/lattice/hnf.ts#L651).
- The plain-language introduction precedes formulas, and the two attacks are correctly identified as attacks on different schemes. See [index.html](index.html#L192).
- The app is seeded and reproducible. It does not call `Math.random()` for its experiments.
- Attack success is styled as an alarm, not as a green success state.
- The accessibility gate checks axe `incomplete` results, computed contrast, non-text contrast, reduced motion, hidden-state behavior, and driven states.
- CI gates unit tests, typechecking, both browser projects, and Pages deployment. Dependency PRs are tested before auto-merge.
- The project has no runtime package dependencies, carries an MIT license, and clearly says it is not production cryptography.

## Priority 0: truth and correctness blockers

These should be fixed before using "10/10" or "gold standard" publicly.

### 1. Show the ordinary public-LLL baseline

**Finding.** The app compares Babai round-off with the raw private basis `R` and the raw public basis `B`. At the toy dimensions and strengthened diagonal shift used here, ordinary LLL on `B` appears to recover an equally useful short basis directly.

A targeted audit probe using the repository's existing `lllReduce(B)` recovered `R` up to sign/permutation on 20/20 seeded keys at each of dimensions 8, 16, 32, and 60. It decrypted 30/30 ciphertexts at each dimension. This probe is not currently a committed test. The existing LLL test reduces a public basis but checks reducedness, not whether the result has recovered the trapdoor capability. See [src/attack/lll.test.ts](src/attack/lll.test.ts#L25).

**Why this matters.** "Raw `B` fails Babai" remains a valid demonstration of basis quality. It is not evidence that the toy public key hides a good basis. Without the baseline, a newcomer can reasonably leave believing that only the historical shape attacks can defeat the displayed keys.

**Gold-standard fix.** Add a compact `Raw B / LLL(B) / secret R` comparison immediately after Act 2. Show the bound, decryption result, runtime, and whether the reduced rows match `R` up to sign/order. Explain that toy dimensions make ordinary reduction decisive, while the historical attacks explain specific design failures at challenge dimensions.

**Acceptance criteria.**

- A visible statement scopes the headline to raw-basis Babai.
- The learner can run `LLL(B)` from public data and see the result through the real decryptor.
- A deterministic multi-seed test records success/failure at 8, 16, 32, and 60.
- README and in-app claims distinguish educational parameters from historical security.

### 2. Make the signature verifier fail closed

**Finding.** `verify()` assumes well-formed finite vectors. It does not validate dimensions, finite values, safe integers, matrix shape, tolerance, or the published bound before arithmetic. Comparisons with `NaN` are false, and the re-multiplication tolerance scales with the magnitude of `s`. See [src/sign/verify.ts](src/sign/verify.ts#L97).

Targeted probes accepted empty vectors, vectors containing `NaN`, and a numerically unsafe non-lattice value at magnitude `1e17` in a scalar test. The normal attack outputs are small and finite, so this does not invalidate the current seeded demonstration, but it invalidates the module's "real verifier" claim as a general trust boundary.

**Gold-standard fix.** Reject malformed inputs before any linear algebra. Require exact dimensions, finite safe integers where integers are required, a finite non-negative bound, and a fixed validated tolerance. For lattice membership, precompute the public HNF and use exact BigInt coordinates, or otherwise provide an exact integer membership proof with a clearly bounded conversion layer.

**Acceptance criteria.**

- Empty, short, long, ragged, `NaN`, `Infinity`, unsafe-integer, negative-bound, and invalid-tolerance inputs all reject with explicit reasons.
- Lattice membership is exact for accepted-domain values.
- Genuine round-off and Gaussian signatures still pass.
- Every Break 2 success still passes the hardened verifier.
- Mutation tests prove that removing each validation causes an owning test to fail.

### 3. Separate forgery capability from secret-row recovery

**Finding.** Break 2 declares success when a candidate basis signs fresh messages that the verifier accepts. That proves forgery capability. It does not prove that the candidate is `R` up to sign/permutation. See [src/attack/break2.ts](src/attack/break2.ts#L499). The UI nevertheless says `SECRET BASIS RECOVERED` and "Recovered the rows of R." See [src/ui/act4.ts](src/ui/act4.ts#L193).

The distinction matters even more once the public-LLL baseline is acknowledged: a different good basis may forge without being the original secret rows.

The sample headline is also ambiguous. Each rung collects `N` training signatures and `N` held-out signatures, but the result says recovery was from `N` signatures. The implementation already tracks `2N` as total observed. See [src/attack/break2.ts](src/attack/break2.ts#L422).

**Gold-standard fix.** Render two independent checks:

- `Forgery check`: a public verifier accepted fresh signatures.
- `Ground-truth recovery check`: the lab, separately, matched the candidate to secret rows up to sign/permutation.

Call it "secret basis recovered" only when the second check passes. Otherwise call it "forgery-capable basis found." Report `N training + N held-out = 2N oracle signatures observed` wherever sample complexity is summarized.

**Acceptance criteria.**

- Production code performs the sign/permutation matcher instead of leaving it test-only.
- UI and README distinguish the attacker-observable forgery result from lab-only ground truth.
- Tests cover: both pass, forgery-only pass, candidate-only/no-forgery, cap failure, and Gaussian failure.
- Every sample count names training, hold-out, and total observations.

### 4. Repair Act 2, the central learning interaction

**Finding A: stale contradictory captions.** `renderCiphertext()` clears the strip, then appends a new caption to the panel without removing the old caption. See [src/ui/act2.ts](src/ui/act2.ts#L18). Direct browser testing produced three captions after three encryptions: two said every entry was `+/-3`, while the third said the coordinates were not `+/-3`.

**Finding B: the comparison erases itself.** Private and public decryptions write to the same verdict container. See [src/ui/act2.ts](src/ui/act2.ts#L119). Running the intended private-then-public sequence replaces `DECRYPTED` with `WRONG MESSAGE`, so the defining comparison cannot remain side by side.

**Why this matters.** This is not cosmetic. The lab's core idea is "same algorithm, same ciphertext, only the basis changed." The interface should leave that proof visible.

**Gold-standard fix.** Give the ciphertext panel one dedicated caption that is replaced on state changes. Give private and public decryption separate persistent result cells, plus one concise comparison sentence. Retire both only when their shared ciphertext/key becomes stale.

**Acceptance criteria.**

- Exactly one current ciphertext explanation exists after any sequence of encryptions and error-mode changes.
- Private and public results remain visible together for the same ciphertext.
- Each result names its basis, bound, prediction, and re-encryption outcome.
- E2E tests exercise repeated encryption, mode changes, both click orders, retirement, and no-op interactions.

### 5. Either ship the HNF exhibit or narrow the claims

**Finding.** The brief asks for a `B = U*R` versus `HNF(R)` toggle, and the README presents HNF as implemented in the browser experience. See [brief.md](brief.md#L38) and [README.md](README.md#L13). The production app never imports the HNF module; its use is confined to implementation and tests.

**Gold-standard fix.** Prefer shipping the toggle because the implementation already exists. Compute HNF on demand, show its BigInt proof, storage-size comparison, timing, and the fact that canonicity gives `HNF(R) = HNF(B)`. Keep large matrices behind disclosure.

**Acceptance criteria.**

- Act 1 exposes `scrambled basis B` and `canonical HNF basis` modes.
- The HNF same-lattice claim is checked in production, not copied from a test.
- UI handles n=60 timing and very large entries without truncating their mathematical meaning.
- If the feature is intentionally omitted, the brief and README stop calling it an app exhibit.

### 6. Tighten mathematical statements at edge cases

These do not break the shipped seeded path, but a gold-standard teaching tool must be correct at its stated abstraction boundaries.

- **Babai bound ties.** The strict `< 1/2` condition is a clean guarantee. Calling it an exact "if and only if" is false at exactly `1/2`, where the result depends on the integer coefficient and tie rule. See [src/lattice/roundoff.ts](src/lattice/roundoff.ts#L93). State: below half succeeds, above half may fail, equality is tie-dependent, or evaluate the actual rounding condition exactly. Add tie-success and tie-failure tests.
- **Descent at delta 12.** The factored coefficient has a pole at 12, but the original update remains defined as a pure cubic iteration because the `u` term vanishes. See [src/attack/descent.ts](src/attack/descent.ts#L8). Correct the analysis and test delta 12 explicitly.
- **Paper parameter naming.** The prose names `4*ceil(sqrt(n))`, while `paperK()` returns `round(4*sqrt(n))`. See [src/lattice/keygen.ts](src/lattice/keygen.ts#L65). Implement the cited formula exactly or rename the helper as an approximation.
- **Generic sigma API.** Break 1 accepts a `sigma` option but calls a hard-coded mod-6 path. Either implement generic `2*sigma` arithmetic or make sigma 3 part of the type/API contract.
- **Expected norm wording.** `sqrt(n/2 + t^2)` is the square root of expected squared norm, not generally the expected Euclidean norm. See [src/attack/embedding.ts](src/attack/embedding.ts#L13).
- **Uniform leak wording.** A finite-box hash point makes the residual approximately equidistributed, not automatically an exact independent continuous-uniform sample. See [src/sign/sign.ts](src/sign/sign.ts#L14). State the approximation and measure or bound its discrepancy.
- **Gaussian claim scope.** The implementation proves that this fourth-moment attack finds no held-out signal for the tested Klein sampler. It does not by itself prove a `2^-40` total-variation guarantee or that "there is nothing left to learn," especially with truncation and a deterministic fallback. See [src/sign/klein.ts](src/sign/klein.ts#L3). Narrow the UI claim or add a derivation and fallback accounting.
- **Historical causality.** "Falcon and ML-KEM exist because of exactly these two results" is stronger than the displayed citations establish. Preserve the excellent structural comparison, but phrase ML-KEM as an analogous design contrast unless a primary source supports the direct causal claim.

## Priority 1: make the lesson effortless and inclusive

### 7. Create a guided core path with progressive disclosure

The first viewport is strong, but Act 1 immediately exposes a 12x12 matrix, determinant discussion, floating-point headroom, and orthogonality diagnostics. The full page is about 6,183 px at 1440x1000 and 12,240 px at 320x800 before running attacks.

Keep expert depth, but establish a visible three-step core path:

1. Generate one lattice and compare basis shape.
2. Encrypt once and preserve both decryption outcomes.
3. Break the vulnerable randomness, then flip the control and watch the break fail.

Move full matrices, numeric proof internals, benchmark details, and citations into native disclosures. Add a compact act navigator/progress indicator that does not hide page sections or turn the lab into a wizard. The expert should still be able to inspect everything without leaving the page.

### 8. Make canvases responsive and truthful

At 320 px, the 720x360 basis bitmap is displayed at 241x120. Its embedded 11-12 px labels become effectively unreadable. The renderer also draws axes and basis arrows, while the nearby text and accessible name claim that lattice points are drawn. See [src/ui/plot.ts](src/ui/plot.ts#L136) and [index.html](index.html#L267).

Use device-pixel-ratio-aware rendering at the element's actual CSS size. Move legends and explanatory text into HTML so they retain readable type. Either draw actual lattice points or say accurately that the chart shows projected basis vectors. Update the Break 2 text alternative when the state changes from round-off to Gaussian.

### 9. Complete the asynchronous interaction states

Break 2 has a worker and a Cancel button, but cancellation provides no explicit cancelled status, a new run can coexist briefly with stale output, worker construction errors occur before event handlers, and progress replaces a broad live region very frequently. See [src/ui/act4.ts](src/ui/act4.ts#L106).

Model `idle`, `running`, `cancelled`, `error`, `failed`, and `succeeded` explicitly. Clear or mark stale evidence at run start. Preserve keyboard focus when controls disable. Announce concise milestones through a throttled live region and expose numeric progress separately.

The brief says LLL runs in a worker, while Break 1 currently runs synchronously and the README reports a 4.6 ms median. Do not add worker complexity only to satisfy stale prose. First establish p95 and long-task budgets on a representative low-end device. If the operation stays under budget, correct the brief; if it does not, move the embedding phase to a cancellable worker.

### 10. Scope controls to the scheme they affect

The error-distribution selector belongs to GGH encryption in Acts 2 and 3. Changing it currently retires/cancels Break 2 even though Act 4 explicitly uses a different signature scheme and a separate key. See [src/main.ts](src/main.ts#L53).

Place the error control with the encryption experiment and retire only dependent state. Keep the global seed/dimension controls global, but show which experiments will regenerate before doing so.

### 11. Raise accessibility coverage from excellent to comprehensive

The existing gate is unusually strong. The remaining gold-standard work is behavioral and platform-specific:

- Test the WCAG reference width of 320 px, not only 380 px.
- Add a keyboard-only journey through every core action, reset, Gaussian run, and cancellation.
- Add a real mobile/touch profile so coarse-pointer rules are exercised.
- Add forced-colors and 200%/400% zoom checks.
- Keep the pixel oracle in Chromium, but run functional claims and semantic smoke tests in Firefox and WebKit.
- Verify the ordered Break 1 stepper retains list semantics when CSS markers are removed.
- Replace rapidly changing broad `role=status` regions with concise milestone announcements.
- Give matrices captions and row/column context; represent ciphertext coordinates as a semantic list/table rather than title-dependent generic divs.
- Manually document VoiceOver + Safari results for each release until that journey can be automated reliably.

## Priority 1: make every number reproducible

### 12. Add a generated evidence pipeline

The README and source comments contain many impressive measured numbers, but they are hand-maintained prose. The brief's claimed sample counts also differ from some committed loops, and the README's accessibility state count can drift as the gate evolves.

Add a deterministic command such as `npm run evidence` that emits machine-readable JSON containing:

- commit SHA, Node/npm/browser versions, OS/architecture, and seed corpus;
- I1 numeric headroom by dimension;
- I2 actual and worst-case values;
- mod-6 key acceptance rate;
- raw `B`, `LLL(B)`, and `R` decryption outcomes;
- Break 1 success, negative-control separation, and p50/p95 time;
- Break 2 training/hold-out/total counts, recovery truth, forgery truth, and p50/p95 time;
- HNF time, proof time, bit size, and peak intermediate size;
- Gaussian held-out statistics and sampler fallback count;
- bundle sizes and accessibility scan-state count.

Generate README tables from that artifact or test every copied constant against it. Commit a small canonical evidence file and upload the full artifact in CI. This turns "measured" from an assertion into something another engineer can reproduce.

### 13. Prove important tests bite automatically

The repository documents mutation discipline but has no repeatable mutation command. Add a small curated mutation suite for the highest-value claims:

- invert the I1 integer/unimodular decision;
- change the I2 half threshold;
- bypass Break 1 re-encryption;
- accept one failed Break 2 forgery;
- remove verifier finite/dimension checks;
- merge training and held-out data;
- stop retiring stale results;
- append instead of replace the ciphertext caption.

The command should require a successful build, verify the bundle hash changed, require the owning test to fail, and restore cleanly. A general mutation framework is optional; a small deterministic harness around these trust boundaries is more valuable.

## Priority 2: engineering and release maturity

### 14. Define one canonical gate

Add `npm run check` that runs formatting/lint, typecheck/build, unit tests with coverage, claims, accessibility, and evidence-consistency checks. Keep expensive multi-browser and benchmark jobs separately named if necessary, but make the release workflow call an explicit aggregate target.

Add coverage thresholds around trust-boundary modules rather than chasing 100% repository-wide coverage. Configure Playwright traces/screenshots on first failure and `failOnFlakyTests` so a retry cannot silently turn instability green.

### 15. Pin the toolchain and reduce supply-chain privilege

- Add `engines`, an exact `packageManager`, and a checked-in Node version file matching CI.
- Pin third-party GitHub Actions to full commit SHAs, with version comments for Dependabot.
- Keep workflow-wide permissions at `contents: read`; grant Pages and OIDC write only to the deploy job.
- Add a lightweight dependency/license policy, SBOM generation, and artifact attestation on releases.
- Add the MIT license to package metadata.

The app has no runtime dependencies, so this is hardening rather than remediation.

### 16. Define browser support and release provenance

Document the supported browser matrix. Keep deterministic Chromium for the pixel oracle, but require current Chromium, Firefox, and WebKit functional smoke coverage.

Publish versioned GitHub Releases tied to tags, with changelog, checksums, generated evidence, SBOM, and build provenance. The Pages URL can remain the live demo, but a gold-standard result should also be recoverable as an immutable artifact.

### 17. Make citations first-class evidence

The in-app bibliography is good but plain text. Link papers to DOI/publisher pages and standards to official NIST/specification URLs. For every direct quote or historical-causality claim, include a section/page locator. Date-stamp time-sensitive standard status such as the FIPS 206 label and review it in the evidence/release process.

Add `CITATION.cff`, `SECURITY.md`, and a short `CONTRIBUTING.md` explaining the invariant, evidence, and mutation expectations. These are small files with outsized value for an educational reference implementation.

## Recommended implementation order

### Phase 1: repair the truth boundary

1. Harden the verifier and add adversarial tests.
2. Add the public `LLL(B)` baseline and scope the headline claim.
3. Split Break 2 forgery and row-recovery checks; fix total sample reporting.
4. Correct tie, delta, paper-parameter, uniformity, Gaussian, and causality language.

Exit condition: no success label is stronger than the independent check that produced it.

### Phase 2: repair the central lesson

1. Replace the accumulating ciphertext caption.
2. Preserve private/public decryption outcomes side by side.
3. Expose the HNF toggle or narrow the brief/README.
4. Add a guided core path and progressive disclosures.
5. Scope controls and retirement to their actual dependencies.

Exit condition: a newcomer can reach and retain the main `R` versus `B` comparison in under three actions, while an expert can inspect every proof.

### Phase 3: make every state inclusive

1. Re-render canvases responsively and fix alternatives.
2. Complete worker cancellation/error/focus/live-region behavior.
3. Add 320 px, keyboard-only, touch, forced-colors, WebKit, and Firefox coverage.
4. Improve list, matrix, and ciphertext semantics.

Exit condition: the entire core journey works without a pointer, at 320 px, at zoom, with reduced motion, and in Safari/VoiceOver without contradictory announcements.

### Phase 4: institutionalize the evidence

1. Add generated evidence and performance budgets.
2. Add curated mutations and fail-on-flaky behavior.
3. Add the canonical check command and cross-browser smoke suite.
4. Pin actions/toolchain and publish an immutable release with provenance.

Exit condition: a fresh checkout can regenerate every headline number and a release cannot ship when any truth-boundary mutation survives.

## 10/10 definition of done

The project can reasonably call itself a gold standard when all of the following are true:

- The raw-basis demo explicitly coexists with a public-LLL baseline.
- Every verifier input is validated and lattice membership is exact over the accepted domain.
- "Secret recovered" and "forgery accepted" are independent rendered checks.
- Training, held-out, and total oracle samples are never conflated.
- Private and public decryption outcomes persist side by side.
- Repeated interactions cannot leave stale or contradictory captions/verdicts.
- HNF is either a real browser exhibit or no longer advertised as one.
- All mathematical edge statements include their tie, approximation, and tested-scope caveats.
- The first-use path foregrounds the mechanism; matrices and diagnostics are progressive depth.
- Canvas labels remain readable and alternatives remain state-accurate at 320 px.
- Cancellation, errors, focus, and progress have explicit accessible states.
- WCAG 2.2 AA, keyboard, touch, zoom, forced-colors, and semantic checks gate releases.
- Chromium, Firefox, and WebKit pass the declared support matrix.
- Every README measurement comes from a versioned evidence artifact.
- High-value mutations are known to fail their owning tests.
- CI rejects flaky passes and preserves useful first-failure diagnostics.
- Node, npm, browser, and Actions versions are controlled and reproducible.
- Releases are tagged, immutable, checksummed, and accompanied by evidence/provenance.
- Primary-source links support direct quotes and causal historical claims.
- A fresh clone can run one documented command and reproduce the release verdict.

## What not to add

A 10/10 version does not need BKZ, dimensions 200-400 in the browser, a backend, a production cryptographic API, NTRUSign, or a full Falcon implementation. Those would widen the surface without fixing the current trust and teaching gaps.

The project is closest to gold standard when it stays narrow: one basis-quality lesson, two historically distinct shape failures, every result independently checked, and no sentence stronger than the evidence on screen.
