import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  REFLOW_320,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * ────────────────────────────────────────────────────────────────────────────
 * THE SELECTOR CONTRACT — what the gate drives, and what the page must provide
 * ────────────────────────────────────────────────────────────────────────────
 *
 * This gate was written alongside the UI rather than after it, so the set of
 * hooks it depends on is written down here IN ONE PLACE instead of being
 * scattered through the drive and discovered by whoever breaks one. Everything
 * below is what `gate.ts` actually queries; `SELECTORS` (re-exported at the
 * bottom of this block) is the same list as executable data.
 *
 * The rule that shapes it: the gate NEVER waits on a fixed timeout and never
 * clicks by label regex. Every step needs a real DOM completion signal, because
 * a click that silently did nothing has to be distinguishable from one that
 * worked — that was the single worst defect in the gate this one replaces. So a
 * handful of these hooks are state, not structure, and they are called out.
 *
 * IDENTITY AND LANDMARKS
 *   #app                  the content wrapper the shared skip link targets
 *                         (`a.cl-skip-link[href="#app"]`). Exactly one <main>,
 *                         exactly one banner landmark (the shared top bar).
 *   #act-1 … #act-5       the five act sections, in the brief's narrative order:
 *                         1 two bases one lattice · 2 encrypt/decrypt ·
 *                         3 Break 1 (Nguyen 1999) · 4 Break 2 (Nguyen–Regev
 *                         2006) · 5 why it matters. All five are IN THE DOM and
 *                         visible at first paint — this lab is a scrolled page
 *                         of acts, not a tablist, so nothing is lazily rendered
 *                         and nothing is hidden behind a tab.
 *
 * CONTROLS
 *   #dim-slider           <input type="range" min="8" max="60"> — the lattice
 *                         dimension. min/max are asserted; the shipped default
 *                         is only required to lie inside them.
 *   #sigma-select         <select> — the error mode. At least two option
 *                         VALUES, and these exact strings:
 *                           "pm3"     e ∈ {±3}^n, GGH's own choice — the default
 *                           "uniform" e ∈ {−3..3}^n, non-constant magnitude
 *                         Switching to "uniform" is the toggle Act 3 exists to
 *                         teach: it is what makes Break 1's mod-6 step stop
 *                         working.
 *   #btn-keygen           Act 1: a fresh (R, U, B) at the slider's dimension.
 *   #btn-encrypt          Act 2: c = m·B + e.
 *   #btn-decrypt-private  Act 2: Babai round-off with R — succeeds.
 *   #btn-decrypt-public   Act 2: the same round-off with B — fails. This IS the
 *                         trapdoor, and it is the lab's headline failure state.
 *   #btn-break1-step      Act 3: advance the Nguyen-1999 stepper one step.
 *   #btn-break2-run       Act 4: run the moment-based descent.
 *
 * READOUTS
 *   #i1-proof             Act 1: invariant I1, the integer U·V = I check.
 *   #i2-bound             Act 2: invariant I2, |e·R⁻¹|∞ against ½.
 *   #break2-canvas        Act 4: the signature cloud. A <canvas> is non-text
 *                         content (WCAG 1.1.1) and axe cannot see inside it, so
 *                         it must carry an accessible name AND a text
 *                         alternative that says what the picture shows.
 *   #sig-counter          Act 4: signatures consumed, measured live. Its text
 *                         must contain the count as a plain integer, so the
 *                         gate can parse it and watch it climb; the brief
 *                         forbids stating it as a constant. It renders "0"
 *                         before any descent has run — never nothing — because
 *                         the gate polls the parsed number as its wait.
 *   #verdict-decrypt      Act 2 verdict.
 *   #verdict-break1       Act 3 verdict.
 *   #verdict-break2       Act 4 verdict.
 *
 * TWO PIECES OF STATE THE GATE WAITS ON (the only additions beyond the ids)
 *
 *   [data-verdict] on each of the three verdict elements, one of:
 *       "pass"   the honest operation succeeded (round-off with R recovered m)
 *       "fail"   the operation did not succeed (round-off with B did not; or
 *                an attack that was blocked)
 *       "alarm"  AN ATTACK SUCCEEDED — the system is broken. Per the template's
 *                visual semantics, a break that works reads as ALARM, never as
 *                green success.
 *     The gate asserts the VALUE, not the wording, so the prose can be rewritten
 *     without touching this file — and so that "the verdict rendered" can never
 *     be confused with "the verdict said what we expected".
 *
 *   [data-n] on #i1-proof — the dimension of the key the proof belongs to.
 *     Without it, a re-keygen has no completion signal at all: the I1 proof
 *     renders the same "U·V = I" either way, so waiting for it to be non-empty
 *     would pass against a button that did nothing.
 *
 *   [data-step] on #act-3 — the Break 1 stepper's current index, from "0".
 *     Same argument: the per-click signal the stepper otherwise does not have.
 *     #btn-break1-step must be DISABLED once there is no further step, which is
 *     how the drive knows the stepper is finished without counting steps it
 *     cannot see.
 *
 * RETIREMENT (asserted, and also how several waits are made honest)
 *   Changing an input retires everything computed downstream of it: a new key
 *   (#btn-keygen) or a new error mode (#sigma-select) empties #i2-bound,
 *   #verdict-decrypt, #verdict-break1 and #verdict-break2. A stale verdict left
 *   on screen beside a fresh key is a lie about which key it judged; here it is
 *   also the signal that tells the gate the click landed, because the I1 proof
 *   renders the same "U·V = I" for every key and has nothing to wait on.
 *
 * If any of this is missing when the gate runs, the gate FAILS naming the
 * locator. Do not weaken an assertion to accommodate a control that is not
 * there — add the control, or bring the change back here first.
 */
export { SELECTORS } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where Act 1
 * has already generated a key at the shipped dimension and the I1 proof
 * (U·V = I over the integers) is on screen while every downstream verdict is
 * still empty; the shared skip link focused; a ciphertext encrypted so the I2
 * bound |e·R⁻¹|∞ is rendered against ½; the round-off decrypted with the
 * PRIVATE basis and succeeding, then with the PUBLIC basis and failing, which
 * is the trapdoor itself and the one failure state the whole lab is built
 * around; a re-key at dimension 8 — the floor, below which Break 2's statistics
 * are too thin — retiring every verdict that belonged to the old key; Break 1
 * at step 0, mid-stepper, and at the recovered-message alarm; the error mode
 * switched to a non-constant magnitude, retiring the break, and Break 1 then
 * failing its mod-6 step, which is the lesson of Act 3; a re-key at dimension
 * 16 for Break 2; the descent running with the signature counter climbing and
 * the parallelepiped cloud painting; its end, whether that is the rows of R
 * recovered up to sign and permutation or the cap reported without recovery;
 * every disclosure on the page opened through its own summary; two hover
 * states; and two focus rings, on the range slider and on the select. Every one
 * of those states is scanned, in the one shipped theme (dark), at desktop and
 * phone width.
 *
 * See `gate.ts` for why nothing is injected into the page (the old gate's
 * `addStyleTag` motion kill bypassed the stylesheet's own reduced-motion
 * block, so the rendering reduced-motion readers get was never the one
 * scanned), why no panel is revealed from script (the old gate stripped every
 * `[hidden]` and opened every `<details>` by JS before its only scan), why the
 * lab's defaults are asserted rather than assumed, and why `violations` is not
 * the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  /**
   * 320 CSS pixels is the width WCAG 2.1 SC 1.4.10 Reflow actually names. The
   * lab scanned 380 and 1440 but never the normative width, so the criterion it
   * claims to meet was the one width not being checked.
   */
  test(`no WCAG A/AA violations in ${theme} theme at the 320px reflow width`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(REFLOW_320);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @320px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
