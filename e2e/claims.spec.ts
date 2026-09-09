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
  // under 2^53 as two separate numbers. Recompute one from the other. They live
  // behind a disclosure now (progressive depth), so open it the way a reader
  // would rather than reaching into hidden DOM.
  await page.locator('#i1-internals > summary').click();
  await expect(page.locator('#i1-internals')).toHaveAttribute('open', '');
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

  // The page PREDICTS both outcomes from the bound before either decryption is
  // run. Capture the predictions first, then drive the real thing and require
  // them to match -- two surfaces that must agree, which is the cross-check that
  // makes I2 a claim rather than a decoration. Without this, weakening the
  // threshold in the source changes only a CSS tone and no page-level test
  // notices (measured: it did not).
  await page.click(SELECTORS.encrypt);
  await expect(page.locator(SELECTORS.i2)).not.toBeEmpty();
  const predictedR = await kv(page, SELECTORS.i2, 'predicted outcome with R');
  const predictedB = await kv(page, SELECTORS.i2, 'predicted outcome with B');

  // Private basis: the number must be under 1/2 and the verdict must be a pass.
  await page.click(SELECTORS.decryptPrivate);
  await expect(page.locator(SELECTORS.verdictDecrypt)).not.toBeEmpty();
  const withR = Number(await kv(page, SELECTORS.i2, 'max |e * R inverse|'));
  await expect(page.locator(SELECTORS.verdictDecrypt)).toHaveAttribute('data-verdict', 'pass');
  expect(withR, 'a passing decryption must have had its bound under 1/2').toBeLessThan(0.5);
  expect(predictedR, 'the page predicted this decryption would succeed').toBe('will decrypt');
  // The prediction must be exactly what the printed number implies -- re-derived
  // here from the number, not read from the same place the prediction came from.
  expect(withR < 0.5 ? 'will decrypt' : 'will fail').toBe(predictedR);

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
  expect(predictedB, 'the page predicted this decryption would fail').toBe('will fail');
  expect(withB < 0.5 ? 'will decrypt' : 'will fail').toBe(predictedB);

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
    expect(text).toMatch(/accepted by the real verifier/i);
    expect(text, 'the page must never claim it recovered R itself').not.toMatch(/recovered R\b/);
    // The public statistic must agree with the claim: round-off leaks, so the
    // held-out fourth-moment statistic is near 1.
    expect(heldOut).toBeGreaterThan(0.5);

    // Audit finding 3: the two outcomes are rendered INDEPENDENTLY, and only one
    // of them is something an attacker could compute.
    const checksText = await page.locator('#break2-checks').innerText();
    expect(checksText).toMatch(/Forgery check \(attacker-observable\)/);
    expect(checksText).toMatch(/Ground-truth recovery \(lab only\)/);

    // Sample accounting: training, held out, and total must all be named, and
    // the total must be exactly twice the training half. Reporting recovery
    // "from N" understated the oracle cost by half.
    const training = Number(await kv(page, SELECTORS.sigCounter, 'signatures consumed'));
    const held = Number(await kv(page, SELECTORS.sigCounter, 'signatures held out'));
    const total = Number(await kv(page, SELECTORS.sigCounter, 'total oracle signatures'));
    expect(held).toBe(training);
    expect(total).toBe(2 * training);
    // And the prose must quote the total, not just the training half.
    expect(text).toContain(String(total));
    expect(text).toMatch(/oracle signatures observed/i);
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

// ───────────────────────── Act 2, the central comparison ─────────────────────
// Acceptance criteria for audit finding 4. Both of these were real defects:
// captions accumulated until three contradictory ones were on screen at once,
// and the second decryption erased the first, destroying the comparison.

test('Act 2: exactly one ciphertext caption survives any sequence of encryptions', async ({
  page,
}) => {
  await open(page);
  const caption = page.locator('#ciphertext-caption');

  await page.click(SELECTORS.encrypt);
  await page.click(SELECTORS.encrypt);
  await page.click(SELECTORS.encrypt);
  await expect(page.locator('#ciphertext-caption')).toHaveCount(1);
  const afterThree = await caption.innerText();
  expect(afterThree).toMatch(/Every entry is \+-3/);

  // Switching the error mode must REPLACE the caption, not add a contradictory
  // one beside it.
  await page.selectOption(SELECTORS.sigma, 'uniform');
  await page.click(SELECTORS.encrypt);
  await expect(page.locator('#ciphertext-caption')).toHaveCount(1);
  const afterMode = await caption.innerText();
  expect(afterMode).toMatch(/coordinates are not \+-3/);
  expect(afterMode, 'the stale congruent caption must be gone').not.toMatch(/Every entry is \+-3/);

  // And the page must not be asserting both things anywhere at once.
  const act2 = await page.locator('#act-2').innerText();
  const congruentClaims = (act2.match(/Every entry is \+-3/g) ?? []).length;
  expect(congruentClaims).toBe(0);
});

test('Act 2: both decryptions of the same ciphertext stay visible together', async ({ page }) => {
  await open(page);
  await page.click(SELECTORS.encrypt);
  await page.click(SELECTORS.decryptPrivate);
  await expect(page.locator('#result-private')).toBeVisible();

  await page.click(SELECTORS.decryptPublic);
  // The whole point: running the second decryption must NOT erase the first.
  await expect(page.locator('#result-private'), 'the private result must survive').toBeVisible();
  await expect(page.locator('#result-public')).toBeVisible();
  await expect(page.locator('#result-private')).toHaveAttribute('data-outcome', 'pass');
  await expect(page.locator('#result-public')).toHaveAttribute('data-outcome', 'fail');

  // Each cell names its basis, its deciding number, and its re-encryption outcome.
  const priv = await page.locator('#result-private').innerText();
  const pub = await page.locator('#result-public').innerText();
  expect(priv).toMatch(/private basis R/);
  expect(priv).toMatch(/Deciding number [\d.]+/);
  expect(priv).toMatch(/Re-encryption confirms/);
  expect(priv).toMatch(/as the bound predicted/);
  expect(pub).toMatch(/public basis B/);
  expect(pub).toMatch(/Deciding number [\d.]+/);
  expect(pub).toMatch(/Re-encryption rejects/);

  // The comparison sentence ties them together and quotes both numbers.
  const compare = await page.locator('.result-compare').innerText();
  expect(compare).toMatch(/[Oo]nly the basis changed/);
  const nums = [...compare.matchAll(/(\d+\.\d+)/g)].map((m) => Number(m[1]));
  expect(nums.length).toBeGreaterThanOrEqual(2);
  expect(nums[0], 'the private bound must be the smaller one').toBeLessThan(nums[1]);
});

test('Act 2: the reverse click order also leaves both results visible', async ({ page }) => {
  await open(page);
  await page.click(SELECTORS.encrypt);
  await page.click(SELECTORS.decryptPublic);
  await expect(page.locator('#verdict-decrypt')).toHaveAttribute('data-verdict', 'fail');
  await page.click(SELECTORS.decryptPrivate);
  await expect(page.locator('#verdict-decrypt')).toHaveAttribute('data-verdict', 'pass');
  await expect(page.locator('#result-private')).toBeVisible();
  await expect(page.locator('#result-public')).toBeVisible();
});

test('Act 2: a fresh encryption retires both stale decryption results', async ({ page }) => {
  await open(page);
  await page.click(SELECTORS.encrypt);
  await page.click(SELECTORS.decryptPrivate);
  await page.click(SELECTORS.decryptPublic);
  await expect(page.locator('#result-private')).toBeVisible();

  // A new key retires everything: the old results describe a ciphertext that no
  // longer exists.
  await page.click(SELECTORS.keygen);
  await expect(page.locator('#result-private')).toHaveCount(0);
  await expect(page.locator('#result-public')).toHaveCount(0);
  await expect(page.locator('#ciphertext-caption')).toBeEmpty();
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

test('retirement is SCOPED: the error mode does not retire Act 4', async ({ page }) => {
  // Audit finding 10. The error distribution is a property of GGH ENCRYPTION.
  // Act 4 attacks a signature scheme, with its own key, and never reads it, so
  // retiring a finished Break 2 because the encryption error changed would be
  // discarding a result that is still valid.
  test.setTimeout(10 * 60 * 1000);
  await open(page);
  await page.click(SELECTORS.break2Run);
  await expect(page.locator(SELECTORS.verdictBreak2)).toHaveAttribute(
    'data-verdict',
    /^(alarm|fail)$/,
    { timeout: 8 * 60 * 1000 },
  );
  const before = await page.locator(SELECTORS.verdictBreak2).innerText();

  await page.selectOption(SELECTORS.sigma, 'uniform');
  await settle(page);
  await expect(
    page.locator(SELECTORS.verdictBreak2),
    'Act 4 does not depend on the encryption error distribution',
  ).not.toBeEmpty();
  expect(await page.locator(SELECTORS.verdictBreak2).innerText()).toBe(before);

  // A NEW KEY, by contrast, does invalidate it.
  await page.click(SELECTORS.keygen);
  await expect(page.locator(SELECTORS.verdictBreak2)).toBeEmpty();
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

// ─────────────────── the public-LLL baseline (audit finding 1) ───────────────

test('baseline: LLL on the PUBLIC basis alone is shown, and scoped honestly', async ({ page }) => {
  // The lab used to compare raw R against raw B and leave the impression that
  // the public key hides a good basis. At these dimensions it does not, and the
  // page must say so itself rather than letting a reader infer security.
  const errors = await open(page);
  await page.click('#btn-baseline');

  const body = page.locator('#baseline-body');
  await expect(body).not.toBeEmpty();
  // An attack that works is an ALARM, never a green pass.
  await expect(body.locator('[data-verdict]')).toHaveAttribute('data-verdict', 'alarm');

  // The result must come through the REAL decryptor, and be complete.
  const decrypted = await kv(page, '#baseline-body', 'decrypted, through the real decryptor');
  const [got, tried] = decrypted.split('/').map((x) => Number(x.trim()));
  expect(tried).toBeGreaterThan(0);
  expect(got, 'the reduced public basis decrypts everything at these dimensions').toBe(tried);

  // Its bound must actually beat the threshold -- that is the claim, not a vibe.
  const bound = Number(await kv(page, '#baseline-body', 'worst-case bound of the reduced basis'));
  expect(bound).toBeLessThan(0.5);
  expect(await kv(page, '#baseline-body', 'decryption guaranteed with it?')).toMatch(/yes/i);

  // The ground-truth row must be labelled LAB ONLY: an attacker cannot compute it.
  const matched = await kv(page, '#baseline-body', 'rows equal to R up to sign and order');
  expect(matched).toMatch(/\d+ \/ \d+/);

  // And the scope statement must be present and must NOT overclaim in either
  // direction: it says the raw comparison is about basis quality, and that these
  // dimensions demonstrate no security.
  const scope = await page.locator('#baseline-scope').innerText();
  expect(scope).toMatch(/BASIS QUALITY/i);
  expect(scope).toMatch(/not a statement about security/i);
  expect(scope).toMatch(/200 to 400/);

  expect(errors).toEqual([]);
});

test('baseline: the raw public basis is described as a rate, not a law', async ({ page }) => {
  await open(page);
  await page.click('#btn-baseline');
  const text = await page.locator('#baseline-body').innerText();
  // Measured: raw B decrypted 2 of 30 at n=8. Saying "never" would be false.
  expect(text).toMatch(/rate, not a law/i);
  expect(text, 'the page must not claim raw B never decrypts').not.toMatch(/never decrypts/i);
});

// ─────────────────────── the HNF public key (audit finding 5) ────────────────

test('HNF: canonicity is demonstrated, not asserted', async ({ page }) => {
  // The brief and README described HNF as a browser exhibit while the app never
  // imported the module. It is a real exhibit now, and the headline property --
  // that the HNF depends only on the lattice -- is COMPUTED both ways and
  // compared, not quoted from a test.
  const errors = await open(page);
  await page.click('#btn-hnf');

  const body = page.locator('#hnf-body');
  await expect(body).not.toBeEmpty();
  await expect(body.locator('[data-verdict]')).toHaveAttribute('data-verdict', 'pass');

  expect(await kv(page, '#hnf-body', 'HNF(R) equals HNF(B)?')).toMatch(/identical/i);
  expect(await kv(page, '#hnf-body', 'in Hermite normal form?')).toMatch(/yes/i);
  expect(await kv(page, '#hnf-body', 'same lattice, proved in BigInt')).toMatch(/both inclusions exact/i);
  expect(await kv(page, '#hnf-body', 'product of pivots equals')).toMatch(/exact/i);

  // The size claim must be the MEASURED one, not Micciancio's asymptotic factor
  // of n, because this lab mixes U gently and does not reproduce that factor.
  const ratio = Number((await kv(page, '#hnf-body', 'size ratio B : HNF')).replace(/x$/, ''));
  expect(ratio).toBeGreaterThan(1);
  const text = await body.innerText();
  expect(text).toMatch(/asymptotic/i);
  expect(text, 'the page must not claim the factor-n saving it does not measure').toMatch(
    /not n\b/,
  );

  // Determinants past 2^53 must never be shown truncated into a double.
  expect(Number(await kv(page, '#hnf-body', 'bits in |det R|'))).toBeGreaterThan(53);

  expect(errors).toEqual([]);
});

// ───────────────────────────── keyboard-only journey ─────────────────────────

/** Tab forward until `id` holds focus, or fail saying what was reachable. */
async function tabTo(page: Page, id: string, max = 60): Promise<string[]> {
  const seen: string[] = [];
  for (let i = 0; i < max; i++) {
    const active = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null;
      return el ? el.id || el.tagName.toLowerCase() + (el.className ? '.' + String(el.className).split(' ')[0] : '') : '';
    });
    if (active && seen[seen.length - 1] !== active) seen.push(active);
    if (active === id) return seen;
    await page.keyboard.press('Tab');
  }
  throw new Error(`never reached #${id} by keyboard. Reached: ${seen.join(' -> ')}`);
}

test('keyboard: the whole core path works with no pointer at all', async ({ page }) => {
  // Audit finding 11. Every core action must be reachable and operable from the
  // keyboard alone -- not merely focusable, actually driven to a result.
  const errors = await open(page);
  await page.evaluate(() => document.body.focus());

  // The skip link is the first focusable thing and must move focus into #app.
  await page.keyboard.press('Tab');
  const first = await page.evaluate(() => document.activeElement?.className ?? '');
  expect(first, 'the skip link must be the first stop').toContain('cl-skip-link');
  await page.keyboard.press('Enter');
  await expect(page.locator('#app')).toBeFocused();

  // Encrypt, by keyboard.
  await tabTo(page, 'btn-encrypt');
  await page.keyboard.press('Enter');
  await expect(page.locator(SELECTORS.i2)).not.toBeEmpty();

  // Decrypt with each basis, by keyboard, and confirm both results persist.
  await tabTo(page, 'btn-decrypt-private');
  await page.keyboard.press('Enter');
  await expect(page.locator('#result-private')).toBeVisible();
  await tabTo(page, 'btn-decrypt-public');
  await page.keyboard.press('Enter');
  await expect(page.locator('#result-public')).toBeVisible();
  await expect(page.locator('#result-private')).toBeVisible();

  // Break 1, stepped to completion by keyboard.
  await tabTo(page, 'btn-break1-step');
  for (let i = 0; i < 12; i++) {
    if (await page.locator(SELECTORS.break1Step).isDisabled()) break;
    await page.keyboard.press('Enter');
  }
  await expect(page.locator(SELECTORS.verdictBreak1)).toHaveAttribute('data-verdict', 'alarm');

  expect(errors).toEqual([]);
});

test('keyboard: the error-mode select is operable and retires by keyboard', async ({ page }) => {
  await open(page);
  await page.click(SELECTORS.encrypt);
  await page.click(SELECTORS.decryptPrivate);
  await expect(page.locator('#result-private')).toBeVisible();

  // Change the select with the keyboard rather than selectOption, so the real
  // change-event path a keyboard user takes is the one exercised.
  //
  // Type-ahead ("u" jumps to the Uniform option) rather than ArrowDown: on macOS
  // a closed <select> opens its popup on ArrowDown instead of moving the
  // selection, so an arrow-key assertion passes on Linux CI and fails locally.
  // Type-ahead behaves the same on every platform.
  await page.locator(SELECTORS.sigma).focus();
  await expect(page.locator(SELECTORS.sigma)).toBeFocused();
  await page.keyboard.press('u');
  await expect(page.locator(SELECTORS.sigma)).toHaveValue('uniform');
  await expect(page.locator('#result-private')).toHaveCount(0);
});

test('every disclosure is operable by keyboard and starts closed', async ({ page }) => {
  await open(page);
  const summaries = page.locator('details > summary');
  const n = await summaries.count();
  expect(n, 'the page uses progressive disclosure').toBeGreaterThan(0);
  for (let i = 0; i < n; i++) {
    await expect(summaries.nth(i).locator('..')).not.toHaveAttribute('open', '');
  }
  // Open the first one with the keyboard and confirm it really opened.
  await summaries.first().focus();
  await page.keyboard.press('Enter');
  await expect(summaries.first().locator('..')).toHaveAttribute('open', '');
});

// ───────────────────────────── mobile reality ────────────────────────────────

/**
 * These are measurements, not opinions, and they run at the WCAG reflow width.
 * The a11y gate already scans 320px for axe violations; this checks the two
 * things axe cannot: that the document never scrolls sideways, and that every
 * target a finger must hit is big enough to hit.
 */
test('mobile: no horizontal scrolling at 320px, in the busiest state', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await open(page);
  // Drive into the heaviest layout: every on-demand panel open, both matrices
  // rendered, the stepper full.
  await page.click('#btn-baseline');
  await page.click('#btn-hnf');
  await page.click(SELECTORS.encrypt);
  await page.click(SELECTORS.decryptPrivate);
  await page.click(SELECTORS.decryptPublic);
  await runBreak1(page);
  for (const d of await page.locator('details > summary').all()) await d.click();

  const m = await page.evaluate(() => ({
    vw: document.documentElement.clientWidth,
    scrollW: document.documentElement.scrollWidth,
  }));
  // The document must not scroll sideways. Wide content (matrices, the
  // ciphertext strip) is allowed to scroll INSIDE its own container -- that is
  // what .matrix-scroll and .strip are for -- but it must never widen the page.
  expect(m.scrollW, 'the document must never scroll horizontally').toBeLessThanOrEqual(m.vw + 1);
});

test('mobile: every non-inline target meets the 24px floor', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await open(page);
  await page.click(SELECTORS.encrypt);

  const small = await page.evaluate(() => {
    const out: Array<{ what: string; w: number; h: number; inline: boolean }> = [];
    document.querySelectorAll('a,button,select,input,summary,[tabindex]').forEach((el) => {
      const b = el.getBoundingClientRect();
      if (b.width === 0 && b.height === 0) return;
      if (b.width >= 24 && b.height >= 24) return;
      // WCAG 2.5.8 exempts a target "in a sentence or whose size is otherwise
      // constrained by the line-height of non-target text". The related-demos
      // line is exactly that: prose with links in it.
      const inline = el.closest('p.footer-links') !== null;
      out.push({
        what: `${el.tagName.toLowerCase()}#${(el as HTMLElement).id} "${(el.textContent || '').trim().slice(0, 20)}"`,
        w: Math.round(b.width),
        h: Math.round(b.height),
        inline,
      });
    });
    return out;
  });

  const violations = small.filter((t) => !t.inline);
  expect(
    violations,
    `targets under 24px that are not inline-in-a-sentence: ${JSON.stringify(violations)}`,
  ).toEqual([]);
});

test('mobile: the canvas backing store matches the device pixel ratio', async ({ page }) => {
  // A fixed 720x360 bitmap squashed into a 241px box made the painted labels
  // unreadable on a phone, which is why legends are HTML now and the backing
  // store is sized from the real box.
  await page.setViewportSize({ width: 320, height: 800 });
  await open(page);
  const c = await page.evaluate(() => {
    const el = document.getElementById('basis-canvas') as HTMLCanvasElement;
    const r = el.getBoundingClientRect();
    return { cssW: Math.round(r.width), backingW: el.width, dpr: window.devicePixelRatio };
  });
  expect(c.cssW).toBeLessThanOrEqual(320);
  expect(c.backingW).toBe(Math.round(c.cssW * Math.min(c.dpr, 3)));
  // And the legend is real text, not painted pixels.
  await expect(page.locator('#basis-legend .plot-legend li').first()).toBeVisible();
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
