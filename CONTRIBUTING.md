# Contributing

Short version: `npm ci && npm run check`. When it is green — and when you have *watched your
new test fail* — open the pull request.

Beyond "the tests pass", this lab enforces three things. They are the reason the repository
exists, and a change that ignores them is a regression even when CI is green:

1. the numbered invariants **I1–I5**,
2. every measured number traces back to a **generated evidence run**, not to prose,
3. **mutation discipline** — no test is trusted until it has been watched to fail.

---

## The one command

```sh
nvm use                            # .nvmrc pins the Node line CI uses
npm ci                             # from the committed lock — never `npm install`
npx playwright install chromium    # once. NEVER with --with-deps (see deploy.yml)
npm run check                      # the whole gate, in CI's order
```

`npm run check` is the aggregate:

```
npm run build && npm test && npm run test:claims && npm run test:a11y
```

CI runs those same four scripts as four *separately named* steps, so a red run tells you which
gate rejected the change rather than just "check failed". The cost of that choice is drift, so
a step in [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) asserts that `check`
still composes exactly those four scripts in that order. Change one and you must change the
other; the workflow will stop you if you forget.

Two commands are deliberately *not* in `check`, because both are slow and neither is a pass/fail
gate on an ordinary change: `npm run evidence` (§2) regenerates measurements, and
`npm run mutate` (§3) rebuilds the bundle once per mutation. Run them when your change touches
what they cover. If they are ever folded into `check`, the workflow's guard step has to learn
about them in the same commit — that is the point of the guard.

**Toolchain.** `engines` in `package.json` is not a preference. `vitest` 5 declares
`^22.12.0 || ^24.0.0 || >=26.0.0` — it rejects Node below 22.12 *and* every odd-numbered Node
line — and `vite` 8 wants `>=22.12.0` too, so that intersection is the honest floor.
`packageManager` is `npm@10.9.8`, which is the npm bundled with the current Node 22 release
(v22.23.2, read from `https://nodejs.org/dist/index.json` on 2026-09-08) — that is, exactly
what CI resolves from `.nvmrc`. CI reads `.nvmrc` through `setup-node`'s `node-version-file`
rather than repeating the version, so the checked-in file and CI cannot say different things.

**One local trap.** `playwright.config.ts` sets `reuseExistingServer: !process.env.CI`, so a
`vite preview` already listening on port 4666 gets adopted by the suites — including one
belonging to a *sibling lab*, which has really happened in this fleet. If a result surprises
you, re-run as `CI=1 npm run test:claims` to force a fresh build and server.

---

## 1. The numbered invariants I1–I5

The convention throughout is **row lattices**: `L(B) = { x·B }`, rows are basis vectors, and a
ciphertext is `c = m·B + e`.

The five invariants are stated in [`brief.md`](brief.md) and are the contract the page is
written against:

- **I1 — the two bases span the same lattice, provably.** Compute integer `U = B·R⁻¹` and
  `V = R·B⁻¹` and verify `U·V = I` *over the integers*; display `U`. Not a float determinant:
  both inclusions plus the integer inverse relation.
- **I2 — decryption correctness is a bound, not a claim.** Round-off with `R` succeeds iff
  `|e·R⁻¹|_∞ < 1/2`. Compute and display that number per ciphertext, so the prediction can be
  falsified on screen.
- **I3 — Break 1's mod-2σ step is exact linear algebra mod 6, never a heuristic.** It solves
  over GF(2) and GF(3) and combines with CRT. When `B` is singular modulo one of them, the act
  says which one and re-keys instead of guessing.
- **I4 — Break 2 recovers `R` up to sign and permutation only.** Display and check exactly
  that. Do not say "recovered `R`".
- **I5 — every "attack succeeded" is checked against the real decryptor or the real signature
  verifier**, never by comparing against the secret the attack was not supposed to see.

Each invariant lives in three places at once: the code that computes it, the verdict the page
renders, and an assertion in `e2e/claims.spec.ts` that checks the *rendered* value. A change to
one of them has to move all three.

The failure mode this is defending against is a verdict that outruns its evidence. "The
verifier accepted a forged signature" and "the secret rows were recovered" are two different
results with two different checks; a label that merges them is a bug of the most serious kind
in this repository, regardless of how green the suite is. When in doubt, make the sentence on
screen *weaker* than the check behind it.

Two rules that follow from I5 and are easy to break by accident:

- A test that re-derives the same expression the source uses will happily agree with a bug —
  that has already happened here. Prefer a **cross-check** (two surfaces that must agree) or an
  **independent re-derivation** (recompute the claim from the page's raw inputs by a different
  route).
- Training data and held-out data are not interchangeable, and neither is the total. If a
  number is reported, say which population it came from.

---

## 2. The evidence artifact

**A measured number in prose is not evidence.** Every number in the README, in a source
comment, or on the page is one of two things:

- computed live by the code the reader is looking at, or
- a **measurement**, which means it came out of a run you can repeat, is labelled as measured,
  and carries the conditions that make it reproducible: the dimension, the seed or seed corpus,
  the sample count, and what "success" meant.

Do not hand-edit a measured number to make it match a change. Re-run the thing that produced
it and copy the new value, or delete the claim. Numbers that drift silently are exactly how a
demo stops being trustworthy while every test stays green.

The mechanised form of this rule is the generated evidence artifact:

```sh
npm run evidence        # -> evidence/baseline.json, recomputed from src/ with fixed seeds
```

It emits machine-readable JSON — commit SHA, Node/npm versions, the seed corpus, I1 headroom by
dimension, I2 actual and worst case, break success rates, timings, bundle sizes — recomputed
from the real modules on every run, off seeds that are literals in the script and are copied
into the artifact's provenance block. Wall-clock timings and bundle sizes are machine-dependent
and are labelled as such; every other value is expected to come out identical on a re-run, on
your machine and on CI.

If your change moves a number, regenerate the artifact and commit it in the same pull request,
so a reviewer can diff the numbers instead of trusting them.

---

## 3. Mutation discipline — no test is trusted until it has failed

A green suite is not evidence. Before you trust a test you added or changed, watch it go red
for the right reason:

1. **Invert a condition in the SOURCE** — not in the test.
2. Confirm **the build still succeeds**. A mutation that breaks `tsc` proves nothing: the
   browser suites run against the last good bundle and pass.
3. Confirm the **bundle hash changed** (`md5 dist/assets/*.js`) — proof the mutation reached
   the browser.
4. Confirm **the owning test fails**, and that the failure names the finding.
5. **Restore**, and confirm the hash returns to its pre-mutation value.

Rules learned the hard way in this fleet:

- **Commit the real work BEFORE mutating.** A session that dies mid-check otherwise strands an
  inverted condition in the tree. Four were caught in one day here; two did not break `tsc` and
  would have shipped.
- One mutation at a time, restored immediately.
- Do **not** `git checkout -- <file>` to undo a mutation if that file also holds real work. Use
  a surgical string-level revert.
- **If a mutation leaves every test green, the branch may be unreachable.** That is evidence
  about the *source*, not about the tests, and the right fix may be deleting dead code.
- Verify the mutation actually applied before trusting a negative result. A no-op mutation
  produces a convincing false "the oracle is dead".

The mutations worth this treatment are the ones on the trust boundary: the I1 integer/unimodular
decision, the I2 half threshold, Break 1's re-encryption check, a failed Break 2 forgery, the
verifier's finite/dimension validation, the training/held-out split, retirement of stale
verdicts, and the ciphertext caption. That curated set is automated:

```sh
npm run mutate -- --list          # what is in the set and which test owns each entry
npm run mutate -- --only <id>     # one boundary, while you are working on it
npm run mutate                    # the whole set; a SURVIVOR exits non-zero
```

The harness performs the five steps above for each mutation and restores every file in a
`finally` (and on SIGINT), so a run that dies does not strand an inverted condition in a tree
other people are editing. A survivor is a finding about the *tests* — or about unreachable
source. Fix the test. Never relax the harness to clear the table.

---

## Housekeeping

- **Comments explain WHY.** The repository is read by people learning the mathematics; a
  comment that restates the line below it is noise, and a comment that records the reason a
  line is written *that way* is the point. Cite measured numbers as measured.
- **TypeScript is strict**, with `verbatimModuleSyntax`, `noUnusedLocals` and
  `noUnusedParameters`. Type-only imports must use `import type`.
- **Unit tests are colocated** as `src/**/*.test.ts` and run with Vitest. Browser-level truth
  claims go in `e2e/claims.spec.ts`; accessibility goes in `e2e/a11y.spec.ts`.
- **There is no linter or formatter in this repo.** Adding one is its own decision, not a
  side effect of an unrelated pull request.
- **Keep the lab narrow.** It teaches one basis-quality lesson and two historically distinct
  failures. BKZ, browser dimensions in the hundreds, a backend, a production cryptographic API,
  NTRUSign or a full Falcon would widen the surface without making anything on screen truer.

By contributing you agree that your contribution is licensed under the repository's
[MIT license](LICENSE).
