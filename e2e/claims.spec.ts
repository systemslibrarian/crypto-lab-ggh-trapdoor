import { expect, test, type Page } from '@playwright/test';
import { assertHiddenAttributeHides, SELECTORS, settle, watchPageErrors } from './gate';

/**
 * ────────────────────────────────────────────────────────────────────────────
 * THE CLAIMS SUITE — does the page tell the truth?
 * ────────────────────────────────────────────────────────────────────────────
 *
 * Separate from the a11y gate, which asks whether the page is usable. This one
 * asks whether what it prints is true.
 *
 * THE RULE THAT MAKES THESE WORTH ANYTHING (master template 4.1b): compare two
 * values THE PAGE ITSELF PRINTED, or re-derive a claim from the page's own raw
 * inputs by a different route than the source takes. A test that recomputes the
 * same expression the source uses will happily agree with a bug — that has
 * happened in this fleet, where a fix was "verified" by a test that recomputed
 * the identical faulty branch.
 *
 * Internal consistency alone is not enough either: a page can be consistently
 * wrong, and a corrupted value gets reported consistently everywhere. So the
 * mix here is:
 *
 *   cross-checks          the I1 verdict against the four checks it lists;
 *                         the decrypt verdict against the I2 number beside it;
 *                         the Break 1 verdict against the stepper rows.
 *   re-derivations        the I2 threshold decision recomputed from the numbers
 *                         on screen, by parsing them back out rather than by
 *                         calling the source; the norm ratio recomputed from the
 *                         measured and expected norms the page prints separately.
 *   retirement            change an input, assert the stale verdict is GONE.
 *   no-op guard           re-select the SAME value, assert a fresh verdict is
 *                         NOT retired.
 *   negative claim (4.1d) reach a state where every check the page performs
 *                         reports success and the named property is violated
 *                         anyway, and assert the limitation is on screen there.
 *
 * Claim ids are the brief's: C1 same-lattice, C2 decryption bound, C3 Break 1
 * recovers, C4 Break 1 fails on a non-congruent error, C5/C5' Break 2 and its
 * Gaussian negative case.
 */

const NEGATIVE_CLAIM = '#negative-claim';
const DEFECT_TABLE = '#defect-table';
const KEYGEN_NOTE = '#keygen-note';
const STEPPER = '#break1-steps';

/** Read one labelled value out of a definition list the page rendered. */
async function kv(page: Page, selector: string, labelStartsWith: string): Promise<string> {
  const rows = page.locator(`${selector} .kv > div`);
  const count = await rows.count();
  for (let i = 0; i < count; i++) {
    const dt = (await rows.nth(i).locator('dt').innerText()).trim();
    if (dt.toLowerCase().startsWith(labelStartsWith.toLowerCase())) {
      return (await rows.nth(i).locator('dd').innerText()).trim();
    }
  }
  throw new Error(`no row starting "${labelStartsWith}" in ${selector}`);
}

async function open(page: Page): Promise<string[]> {
  const errors = watchPageErrors(page);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('./');
  await expect(page.locator(SELECTORS.i1)).not.toBeEmpty();
  await settle(page);
  return errors;
}

/** Drive Act 2 to a decrypted state with the private basis. */
async function encryptAndDecrypt(page: Page, which: 'private' | 'public'): Promise<void> {
  await page.click(SELECTORS.encrypt);
  await expect(page.locator(SELECTORS.i2)).not.toBeEmpty();
  await page.click(which === 'private' ? SELECTORS.decryptPrivate : SELECTORS.decryptPublic);
  await expect(page.locator(SELECTORS.verdictDecrypt)).not.toBeEmpty();
}

/** Step Break 1 to completion. */
async function runBreak1(page: Page): Promise<void> {
  const step = page.locator(SELECTORS.break1Step);
  for (let i = 0; i < 12 && !(await step.isDisabled()); i++) {
    await step.click();
  }
  await expect(step).toBeDisabled();
  await expect(page.locator(SELECTORS.verdictBreak1)).not.toBeEmpty();
}

// ───────────────────────────── C1 ─────────────────────────────

test('C1: the same-lattice verdict agrees with the four checks it lists', async ({ page }) => {
  const errors = await open(page);
  const proof = page.locator(SELECTORS.i1);

  await expect(proof).toHaveAttribute('data-verdict', 'pass');

  // Cross-check: the headline verdict must agree with every individual check
  // rendered beneath it. If any row said FAILS while the box said SAME LATTICE,
  // the page would be contradicting itself.
  for (const label of ['every entry', 'U * R', 'V * B', 'U * V']) {
    const value = await kv(page, SELECTORS.i1, label);
    expect(value, `${label} must not report a failure under a passing verdict`).not.toMatch(/FAILS|^no$/i);
  }

  // Re-derivation: the page prints the largest value it touched and the headroom
  // under 2^53 as two separate numbers. Recompute one from the other.
  const largest = Number(await kv(page, SELECTORS.i1, 'largest value touched'));
  const headroomText = await kv(page, SELECTORS.i1, 'headroom under');
  const headroom = Number(headroomText.replace(/x$/, ''));
  expect(Number.isFinite(largest)).toBe(true);
  expect(largest).toBeLessThan(Number.MAX_SAFE_INTEGER);
  // Compared as a RATIO, not with toBeCloseTo: both values are ~1e11, where an
  // absolute-difference tolerance is meaningless. The page prints the headroom
  // to one significant figure, so a few percent of disagreement is the display,
  // not an error.
  expect(headroom / (Number.MAX_SAFE_INTEGER / largest)).toBeCloseTo(1, 1);

  expect(errors).toEqual([]);
});

test('C1: the two orthogonality defects are consistent with their per-dimension values', async ({
  page,
}) => {
  await open(page);
  const n = Number(await page.locator(SELECTORS.i1).getAttribute('data-n'));
  const dim = Number(await kv(page, DEFECT_TABLE, 'dimension'));
  expect(dim, 'the dimension on the proof and in the shape table must agree').toBe(n);

  const defectR = Number(await kv(page, DEFECT_TABLE, 'log10 orthogonality defect, R'));
  const defectB = Number(await kv(page, DEFECT_TABLE, 'log10 orthogonality defect, B'));
  const perR = Number(await kv(page, DEFECT_TABLE, 'per dimension, R'));
  const perB = Number(await kv(page, DEFECT_TABLE, 'per dimension, B'));

  // Re-derivation by a different route than the source takes: divide.
  expect(perR).toBeCloseTo(defectR / n, 2);
  expect(perB).toBeCloseTo(defectB / n, 2);
  // The whole point of Act 1: the private basis is the better-shaped one.
  expect(defectR).toBeLessThan(defectB);
});

// ───────────────────────────── C2 ─────────────────────────────

test('C2: the decryption verdict is exactly what the printed bound predicts', async ({ page }) => {
  const errors = await open(page);

  // Private basis: the number must be under 1/2 and the verdict must be a pass.
  await encryptAndDecrypt(page, 'private');
  const withR = Number(await kv(page, SELECTORS.i2, 'max |e * R inverse|'));
  await expect(page.locator(SELECTORS.verdictDecrypt)).toHaveAttribute('data-verdict', 'pass');
  expect(withR, 'a passing decryption must have had its bound under 1/2').toBeLessThan(0.5);

  // The threshold the page prints is the one it used.
  expect(Number(await kv(page, SELECTORS.i2, 'threshold'))).toBe(0.5);

  // The headroom is re-derived from the bound, not read from the same source.
  const marginR = Number((await kv(page, SELECTORS.i2, 'headroom with R')).replace(/x$/, ''));
  expect(marginR).toBeCloseTo(0.5 / withR, 1);

  // Public basis: same ciphertext, same algorithm, the other basis.
  const withB = Number(await kv(page, SELECTORS.i2, 'max |e * B inverse|'));
  await page.click(SELECTORS.decryptPublic);
  await expect(page.locator(SELECTORS.verdictDecrypt)).toHaveAttribute('data-verdict', 'fail');
  expect(withB, 'a failed decryption must have had its bound at or over 1/2').toBeGreaterThan(0.5);

  // The page must name the actual cause, not just report a failure.
  const text = await page.locator(SELECTORS.verdictDecrypt).innerText();
  expect(text).toContain('public basis B');
  expect(text).toMatch(/only the basis changed/i);

  // Parts-sum-to-whole, of the kind this construction offers: the worst case
  // over EVERY error must bound the one actually drawn.
  const worstR = Number(await kv(page, SELECTORS.i2, 'worst case over EVERY error, R'));
  expect(worstR).toBeGreaterThanOrEqual(withR);
  expect(worstR, 'the shipped parameters must make decryption unconditional').toBeLessThan(0.5);
  expect(await kv(page, SELECTORS.i2, 'decryption guaranteed with R?')).toMatch(/yes/i);

  expect(errors).toEqual([]);
});

// ───────────────────────────── C3 ─────────────────────────────

test('C3: Break 1 recovers the message and the page reports it as an alarm', async ({ page }) => {
  const errors = await open(page);
  await encryptAndDecrypt(page, 'private');
  await runBreak1(page);

  const verdict = page.locator(SELECTORS.verdictBreak1);
  // An attack that WORKED is never a green pass.
  await expect(verdict).toHaveAttribute('data-verdict', 'alarm');

  const text = await verdict.innerText();
  // The page must say WHY it worked, and it must be the true reason: the
  // congruence, not the size of the error.
  expect(text).toMatch(/congruent/i);
  expect(text).toMatch(/not because the error is small/i);

  // Cross-check the verdict against the stepper it was derived from: the final
  // step is the re-encryption check, and it must have passed.
  const steps = page.locator(`${STEPPER} li`);
  await expect(steps).toHaveCount(6);
  await expect(steps.last()).toContainText('Verify by re-encryption');
  await expect(steps.last()).toHaveClass(/step-ok/);

  // Re-derivation: the read-off step prints the measured shortest row norm and
  // the value a real solution would give. Recompute the ratio from those two.
  const readoff = await steps.nth(3).innerText();
  const measured = Number(/norm ([\d.]+)/.exec(readoff)?.[1]);
  const expectedNorm = Number(/= (\d+\.\d+)\. Ratio/.exec(readoff)?.[1]);
  const ratio = Number(/Ratio (\d+\.\d+)/.exec(readoff)?.[1]);
  expect(ratio).toBeCloseTo(measured / expectedNorm, 2);
  // On an honest ciphertext the planted vector IS the shortest, exactly.
  expect(ratio).toBeCloseTo(1, 2);

  // And the expected value is sqrt(n+1), recomputed from the dimension the
  // page stamped on the I1 proof.
  const n = Number(await page.locator(SELECTORS.i1).getAttribute('data-n'));
  expect(expectedNorm).toBeCloseTo(Math.sqrt(n + 1), 3);

  expect(errors).toEqual([]);
});

// ───────────────────────────── C4 (negative claim, 4.1d) ─────────────────────

test('C4: a non-congruent error defeats Break 1, and the page names the real cause', async ({
  page,
}) => {
  const errors = await open(page);
  await page.selectOption(SELECTORS.sigma, 'uniform');
  await encryptAndDecrypt(page, 'private');
  await runBreak1(page);

  const verdict = page.locator(SELECTORS.verdictBreak1);
  await expect(verdict).toHaveAttribute('data-verdict', 'fail');
  const text = await verdict.innerText();

  // THE CORRECTION THIS TEST EXISTS TO PIN DOWN. The intuitive story is that the
  // division by 6 comes out fractional. It does not — measured exact in
  // 1120/1120 tampered trials, because m0 solves the congruence by construction.
  // The page must say so rather than claiming the division failed.
  expect(text).toMatch(/division by 6 was still exact/i);
  expect(text).toMatch(/wrong\s+residue/i);
  expect(text, 'the page must not claim the division failed').not.toMatch(
    /division (was not|failed|inexact)/i,
  );

  // Cross-check against the stepper: the divide step must have SUCCEEDED even
  // though the attack as a whole failed.
  const steps = page.locator(`${STEPPER} li`);
  await expect(steps.nth(1)).toContainText('Divide out the known part');
  await expect(steps.nth(1), 'the division step still succeeds on a tampered ciphertext').toHaveClass(
    /step-ok/,
  );

  // The real discriminator: the shortest reduced row is far longer than a
  // planted solution would be. Re-derived from the two printed norms.
  const readoff = await steps.nth(3).innerText();
  const measured = Number(/norm ([\d.]+)/.exec(readoff)?.[1]);
  const expectedNorm = Number(/= (\d+\.\d+)\. Ratio/.exec(readoff)?.[1]);
  expect(measured / expectedNorm, 'measured 3-4x on tampered ciphertexts').toBeGreaterThan(2);
  expect(readoff).toMatch(/No row matches the \{\+1,-1\} pattern/);

  expect(errors).toEqual([]);
});

test('4.1d: in the fixture where every check reports success, the limitation is on screen', async ({
  page,
}) => {
  const errors = await open(page);

  // 1. REACH THE FIXTURE, through the UI: GGH's own error distribution, a
  //    legitimate decryption, and the attack run to completion.
  await expect(page.locator(SELECTORS.sigma)).toHaveValue('pm3');
  await encryptAndDecrypt(page, 'private');
  await runBreak1(page);

  // 2. EVERYTHING THE PAGE CHECKS REPORTS SUCCESS, asserted against the rendered
  //    verdicts rather than a flag this test sets. The owner's decryption
  //    genuinely worked, the same-lattice proof genuinely holds, and the attack
  //    genuinely produced a message the re-encryption check accepted.
  await expect(page.locator(SELECTORS.i1)).toHaveAttribute('data-verdict', 'pass');
  await expect(page.locator(SELECTORS.verdictDecrypt)).toHaveAttribute('data-verdict', 'pass');
  await expect(page.locator(SELECTORS.verdictBreak1)).toHaveAttribute('data-verdict', 'alarm');
  await expect(page.locator(`${STEPPER} li`).last()).toHaveClass(/step-ok/);

  // 3. THE LIMITATION IS VISIBLE IN THAT STATE — on screen, not in the README
  //    and not behind a disclosure the reader has to open.
  const claim = page.locator(NEGATIVE_CLAIM);
  await expect(claim).toBeVisible();
  const claimText = await claim.innerText();
  expect(claimText).toMatch(/not evidence of confidentiality/i);
  expect(claimText).toMatch(/public basis and the\s+ciphertext alone/i);
  // Scoped to THIS construction, never to the field.
  expect(claimText).toMatch(/GGH encryption at these\s+parameters/i);

  expect(errors).toEqual([]);
});

test('4.1d: the limitation is absent when the fixture is not reached', async ({ page }) => {
  // The negative claim must be tied to its fixture, not printed unconditionally
  // — otherwise assertion 3 above would pass on a page that never demonstrated
  // anything.
  await open(page);
  await expect(page.locator(NEGATIVE_CLAIM)).toBeEmpty();

  await page.selectOption(SELECTORS.sigma, 'uniform');
  await encryptAndDecrypt(page, 'private');
  await runBreak1(page);
  await expect(page.locator(SELECTORS.verdictBreak1)).toHaveAttribute('data-verdict', 'fail');
  await expect(
    page.locator(NEGATIVE_CLAIM),
    'confidentiality was not broken in this state, so the claim must not be shown',
  ).toBeEmpty();
});

// ───────────────────────────── C5 / C5' ─────────────────────────────

test("C5/C5': Break 2 reports a measured signature count and never fakes success", async ({
  page,
}) => {
  test.setTimeout(10 * 60 * 1000);
  const errors = await open(page);

  const counter = page.locator(SELECTORS.sigCounter);
  // The counter starts at a real zero, not an empty box.
  expect(await kv(page, SELECTORS.sigCounter, 'signatures consumed')).toBe('0');

  await page.click(SELECTORS.break2Run);
  const verdict = page.locator(SELECTORS.verdictBreak2);
  await expect(verdict).toHaveAttribute('data-verdict', /^(alarm|fail)$/, { timeout: 8 * 60 * 1000 });

  // C5 proper: at the page's shipped seed and dimension the attack DOES recover
  // the basis, so this is asserted rather than left open. Measured on the
  // signature key (GGH's own k): n=8 recovers at 8,000 signatures in 85 ms and
  // n=16 at 32,000 in 2.1 s, both with 20/20 forgeries accepted by the real
  // verifier. The page is seeded, so this is deterministic, not a coin flip.
  // The branch below still handles an honest cap failure, because that path must
  // stay correct for any dimension a reader drags the slider to.
  await expect(
    verdict,
    'at the shipped seed and dimension the attack recovers the basis',
  ).toHaveAttribute('data-verdict', 'alarm');

  const consumed = Number(await kv(page, SELECTORS.sigCounter, 'signatures consumed'));
  // MEASURED, not stated: whatever the outcome, the page must have counted.
  expect(consumed, 'the signature counter must be a measured total').toBeGreaterThan(0);
  expect(await counter.innerText()).toMatch(/basis directions found/i);

  const state = await verdict.getAttribute('data-verdict');
  const text = await verdict.innerText();
  const heldOut = Number(await kv(page, SELECTORS.sigCounter, 'sum a^4, held out'));

  if (state === 'alarm') {
    // C5. Success is only ever claimed off the REAL verifier accepting forgeries,
    // and the page must say the recovery is up to sign and order (invariant I4).
    expect(text).toMatch(/up to sign and permutation/i);
    expect(text).toMatch(/accepted every one/i);
    expect(text, 'the page must never claim it recovered R itself').not.toMatch(/recovered R\b/);
    // The public statistic must agree with the claim: round-off leaks, so the
    // held-out fourth-moment statistic is near 1.
    expect(heldOut).toBeGreaterThan(0.5);
  } else {
    // Honest failure: the cap is reported, nothing is claimed.
    expect(text).toMatch(/cap was \d+/i);
    expect(text).toMatch(/rather than claiming a success it did not verify/i);
  }

  expect(errors).toEqual([]);
});

test("C5': Gaussian signatures defeat the same attack, judged on held-out data", async ({
  page,
}) => {
  test.setTimeout(10 * 60 * 1000);
  await open(page);

  await page.click('#btn-break2-gaussian');
  const verdict = page.locator(SELECTORS.verdictBreak2);
  await expect(verdict).toHaveAttribute('data-verdict', /^(alarm|fail)$/, { timeout: 8 * 60 * 1000 });

  // The attack must NOT succeed against a Gaussian sampler. This is the whole
  // reason Falcon samples instead of rounding.
  await expect(verdict).toHaveAttribute('data-verdict', 'fail');
  const text = await verdict.innerText();
  expect(text).toMatch(/GAUSSIAN SIGNATURES HOLD/i);

  // The discriminator is judged on HELD-OUT signatures. The in-sample number
  // overfits and reads structure that is not there, so the page must print both
  // and the held-out one must be the near-zero one.
  const heldOut = Number(await kv(page, SELECTORS.sigCounter, 'sum a^4, held out'));
  const inSample = Number(await kv(page, SELECTORS.sigCounter, 'sum a^4, in sample'));
  expect(Math.abs(heldOut), 'no structure survives on data the descent never saw').toBeLessThan(0.5);
  expect(inSample, 'the in-sample figure is printed precisely because it overfits').toBeGreaterThan(
    heldOut,
  );

  // Cross-check against the raw fourth moment the page prints beside it:
  // sumA4 = 120 * (1/48 - mom4). Re-derived here rather than read.
  const mom4 = Number(await kv(page, SELECTORS.sigCounter, 'fourth moment, held out'));
  expect(120 * (1 / 48 - mom4)).toBeCloseTo(heldOut, 2);
});

// ───────────────────────────── retirement + no-op guard ──────────────────────

test('retirement: a new key clears every stale verdict', async ({ page }) => {
  await open(page);
  await encryptAndDecrypt(page, 'private');
  await runBreak1(page);
  await expect(page.locator(SELECTORS.verdictDecrypt)).toHaveAttribute('data-verdict', 'pass');
  await expect(page.locator(SELECTORS.verdictBreak1)).toHaveAttribute('data-verdict', 'alarm');

  const beforeNote = await page.locator(KEYGEN_NOTE).innerText();
  await page.click(SELECTORS.keygen);

  // Every verdict computed from the retired key must be gone, not merely stale.
  await expect(page.locator(SELECTORS.verdictDecrypt)).toBeEmpty();
  await expect(page.locator(SELECTORS.verdictBreak1)).toBeEmpty();
  await expect(page.locator(SELECTORS.i2)).toBeEmpty();
  await expect(page.locator(NEGATIVE_CLAIM)).toBeEmpty();
  await expect(page.locator(STEPPER)).toBeEmpty();
  await expect(page.locator(SELECTORS.break1Step)).toBeDisabled();
  // And the page must say a new key exists, so retirement is visible and not
  // merely an empty box the reader cannot account for.
  expect(await page.locator(KEYGEN_NOTE).innerText()).not.toBe('');
  expect(beforeNote).toContain('candidate key');
});

test('retirement: changing the error mode clears the verdicts it invalidates', async ({ page }) => {
  await open(page);
  await encryptAndDecrypt(page, 'private');
  await runBreak1(page);
  await expect(page.locator(SELECTORS.verdictBreak1)).toHaveAttribute('data-verdict', 'alarm');

  await page.selectOption(SELECTORS.sigma, 'uniform');
  await expect(page.locator(SELECTORS.verdictBreak1)).toBeEmpty();
  await expect(page.locator(SELECTORS.verdictDecrypt)).toBeEmpty();
  await expect(page.locator(SELECTORS.i2)).toBeEmpty();
  await expect(page.locator(NEGATIVE_CLAIM)).toBeEmpty();
});

test('no-op guard: re-selecting the SAME error mode does not retire a fresh verdict', async ({
  page,
}) => {
  await open(page);
  await encryptAndDecrypt(page, 'private');
  await expect(page.locator(SELECTORS.verdictDecrypt)).toHaveAttribute('data-verdict', 'pass');
  const before = await page.locator(SELECTORS.verdictDecrypt).innerText();

  // Selecting the value that is already selected fires no change event, so a
  // correct page leaves the verdict alone. This is the guard that stops
  // "retire on any interaction" from passing the retirement tests above.
  await page.selectOption(SELECTORS.sigma, 'pm3');
  await settle(page);
  await expect(page.locator(SELECTORS.verdictDecrypt)).toHaveAttribute('data-verdict', 'pass');
  expect(await page.locator(SELECTORS.verdictDecrypt).innerText()).toBe(before);
});

// ───────────────────────────── structural honesty ────────────────────────────

test('the [hidden] attribute actually hides, in the state the claims run in', async ({ page }) => {
  await open(page);
  await encryptAndDecrypt(page, 'private');
  await runBreak1(page);
  // Same probe the a11y gate runs, repeated here because this suite reaches
  // states that one does not.
  await assertHiddenAttributeHides(page);
});

test('the scope note names what the lab does not do, unprompted', async ({ page }) => {
  await open(page);
  const intro = await page.locator('.intro').innerText();
  expect(intro).toMatch(/not production/i);
  // The honest framing must be present before any matrix is shown.
  expect(intro).toMatch(/broken at every dimension/i);
});
