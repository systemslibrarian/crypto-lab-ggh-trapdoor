import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };
/**
 * The WCAG 2.1 reference width for reflow (1.4.10). 380px was the lab's only
 * narrow scan, which left the actual normative width untested; an external audit
 * flagged it. 320 is the width the success criterion names.
 */
export const REFLOW_320 = { width: 320, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the gate
 * this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the one rendering a reduced-motion reader actually gets was never once
 *     the rendering that got scanned. Worse, where a page parks content at
 *     `opacity: 0` and reveals it with an animation's `forwards` fill, the
 *     injection kills the reveal and the content is SCANNED INVISIBLE. This lab
 *     has live candidates for that shape — a signature cloud that fades in as
 *     points accumulate, a stepper line revealed per step — so the difference
 *     is not academic. This gate sets the preference through `emulateMedia`,
 *     asserts from inside the page that it took effect (`test.use({
 *     reducedMotion })` and the config key are both measured no-ops on
 *     Playwright 1.61.x), and injects nothing.
 *
 *  2. IT FORCED EVERY PANEL VISIBLE FROM SCRIPT. The old drive stripped every
 *     `[hidden]` attribute and set every `<details>.open` by JS before its only
 *     scan. Stripping `hidden` renders a state no reader can reach and axe then
 *     scans it instead of the real one; script-opening the disclosures means the
 *     SHUT state, which is what every reader arrives at, was never scanned at
 *     all. It also destroys the ability to catch the `[hidden]` CASCADE TRAP —
 *     a class rule setting `display` outranks the UA `[hidden]` rule, so the
 *     element paints while the code believes it is hidden. This gate strips
 *     nothing, opens each disclosure through its `<summary>`, and probes every
 *     `[hidden]` element for rendered visibility at every driven state
 *     (`assertHiddenAttributeHides`).
 *
 *  3. IT DROVE BLIND AND THEN THREW THE STATES AWAY. The old drive clicked
 *     every button whose label matched a regex, swallowed every failure with
 *     `.catch(() => {})`, waited a fixed 120ms, and scanned ONCE at the end —
 *     so the public-basis decryption failure, the retired verdicts after a
 *     re-key, the Break 1 stepper's intermediate states and the descent's
 *     mid-run counter were all overwritten before anything measured them, and a
 *     click that silently did nothing looked identical to one that worked.
 *     This drive names every control it touches, asserts a real completion
 *     signal after each, and scans after every step, at 1280 and at 380.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. The surfaces that carry
 *     this lab's meaning — the three verdict tones behind `#verdict-decrypt`,
 *     `#verdict-break1` and `#verdict-break2`, any tint under the I1 proof or
 *     the I2 bound, and the shared top bar's `color-mix()` ink — are
 *     `color-mix()` fills axe files under `incomplete` rather than judging. So
 *     is an `aria-label` on a role-less element, which matters on a page whose
 *     matrices and canvas are labelled that way.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE. The old
 *     spec hand-rolled one luminance check over two input selectors, reading
 *     the DECLARED `border-top-color` and `background-color` — blind to
 *     `color-mix()`, to composited backdrops, to the range slider, the select
 *     and all seven buttons, and to every state past first paint. `nontext.ts`
 *     replaces it with a measured oracle over every control at every driven
 *     state, and `expectNoHorizontalOverflow` adds the 1.4.10 check axe has no
 *     rule for — which on a page that renders 60×60 integer matrices at 380px
 *     is the check most likely to bite.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, a stylesheet whose
 * reduced-motion block cancels its animations and transitions leaves
 * `getAnimations()` empty and this returns on the sixth frame. It stays for two
 * reasons that are specific to this lab. The shared top bar's `.cl-btn`
 * transitions are declared OUTSIDE the lab's own `@media` block, so whether
 * they are cancelled is a property of the current stylesheet rather than of the
 * page. And Act 4 paints a signature cloud while a descent runs: a `<canvas>`
 * redraw is not a web animation and is invisible to `getAnimations()`, so any
 * CSS motion wrapped around it — a fade on the counter, a pulse on the run
 * button — is the only part of that state this can wait for. Which is the
 * argument for the budget: this returns rather than hangs when a lab does have
 * something running forever.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. Any
 * keyframe on this page that starts `from { opacity: 0 }` is a candidate, and
 * this lab's exhibits invite them: a verdict that fades in when a decryption
 * finishes, a stepper line revealed per Break 1 step, a Break 2 readout that
 * appears when the descent converges. Every one of those carries a RESULT, so
 * the failure would not be cosmetic — it would hide the answer from exactly the
 * readers who set the preference. A reduced-motion block that writes
 * `animation: none` restores the static `opacity: 1` and is correct; this
 * assertion is what makes that a measurement rather than a reading of the
 * stylesheet.
 *
 * `aria-hidden` subtrees are excluded — decorative glyphs beside their own
 * words are not blank, they are decorative; see `contrast.ts`, which measures
 * them separately with the exemption lifted.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. This matters more here than in most of this fleet, because the
 * heavy work runs in a Web Worker: LLL for the Break 1 embedding attack and the
 * fourth-moment descent for Break 2. A worker that throws does not stop the
 * page — the act simply never fills in, and an empty region is exactly what a
 * scan reports as perfectly accessible. The same is true of the numeric guards
 * the float LLL path carries: a runtime guard that fires and logs is a real
 * failure of the exhibit, and this is the only oracle that sees it. Attach
 * before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`, and it is meant
 * to be the only one. The risk on a page built as five `<section>` acts is a
 * `<header>` inside one of them: a `<header>` scoped inside `MAIN`, `ARTICLE`,
 * `ASIDE`, `NAV` or `SECTION` is NOT a banner, which the check below encodes —
 * but a hero `<header>` sitting outside `<main>` is, and a second banner
 * landmark makes both of them useless to a reader navigating by landmark.
 * Asserting the OUTCOME rather than the markup is what catches that edit
 * wherever it lands.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * List semantics survive their styling.
 *
 * A list styled `list-style: none` is exactly the declaration that makes Safari
 * and VoiceOver DROP the list's implicit role, and the documented compensation
 * is an explicit `role="list"` on the `<ol>`/`<ul>` plus `role="listitem"` on
 * every child. So an explicit role on a list here is as likely to be the fix as
 * the defect, and what is asserted is the SHAPE of that fix rather than its
 * presence: any explicit role on a `ul`/`ol` must be `list` (any other value
 * orphans every `<li>` under it), and a `role="list"` must never sit on an
 * EMPTY element, because axe applies `aria-required-children` to the explicit
 * role and fails it the moment the list renders with nothing in it. That second
 * half is the one this lab can actually trip: the Break 1 stepper's list of
 * completed steps is empty at step 0, and the list of recovered rows in Act 4
 * is empty until the descent converges. Roles are often assigned as JS
 * properties in an element-creation helper, so ask the DOM rather than grepping
 * the source.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
      )
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children'
  ).toEqual([]);
}

/**
 * THE SELECTOR CONTRACT, as executable data.
 *
 * The prose version — what each hook is, what state it must carry, and why —
 * lives at the top of `a11y.spec.ts`, which re-exports this object so the two
 * cannot drift apart. Everything the drive touches is named here; nothing is
 * located by label regex, because a click that silently did nothing has to be
 * distinguishable from one that worked.
 */
export const SELECTORS = {
  /** The content wrapper the shared skip link targets. */
  app: '#app',
  /** The five act sections, in the brief's narrative order. */
  acts: ['#act-1', '#act-2', '#act-3', '#act-4', '#act-5'],
  /** Act 1: the lattice dimension, `<input type="range" min=8 max=60>`. */
  dim: '#dim-slider',
  /** Act 3's toggle: `pm3` (e in {±3}^n, the default) or `uniform` (e in {−3..3}^n). */
  sigma: '#sigma-select',
  keygen: '#btn-keygen',
  encrypt: '#btn-encrypt',
  decryptPrivate: '#btn-decrypt-private',
  decryptPublic: '#btn-decrypt-public',
  break1Step: '#btn-break1-step',
  break2Run: '#btn-break2-run',
  /** Invariant I1: the integer U·V = I proof. `data-n` is the key's dimension. */
  i1: '#i1-proof',
  /** Invariant I2: |e·R⁻¹|∞ against ½. */
  i2: '#i2-bound',
  /** The signature cloud. A `<canvas>` — see `contrast.ts` on why it needs text. */
  break2Canvas: '#break2-canvas',
  /** Signatures consumed, measured live; its text must contain a plain integer. */
  sigCounter: '#sig-counter',
  /** Each carries `data-verdict` of `pass` | `fail` | `alarm`. */
  verdictDecrypt: '#verdict-decrypt',
  verdictBreak1: '#verdict-break1',
  verdictBreak2: '#verdict-break2',
} as const;

/**
 * The `[hidden]` cascade probe.
 *
 * `hidden` is an attribute the UA styles with `[hidden] { display: none }` — an
 * ordinary author-origin rule with the lowest possible specificity. ANY class
 * rule that sets `display` outranks it, so an element can carry `hidden`, be
 * treated as hidden by every line of code that reads the attribute, and paint
 * anyway. Four live instances were found across this fleet in a single day.
 *
 * The tab-and-panel labs catch this structurally, with a per-panel
 * `toBeHidden()` loop over their lazily-rendered tabpanels. This lab has no
 * tabpanels — it is five acts on one scrolled page, all rendered — so the
 * equivalent bite is a sweep of EVERY element carrying the attribute, asking
 * the renderer rather than the markup. It is vacuous while the page hides
 * nothing, and it starts biting the moment something is hidden: a "show the
 * full U matrix" toggle, an act that stays out of the way until a key exists,
 * an error banner for a basis singular mod 6.
 *
 * `checkVisibility({ checkVisibilityCSS: true })` is the question a reader asks
 * — is this rendered? — not the question the attribute answers.
 */
export async function assertHiddenAttributeHides(page: Page): Promise<void> {
  const painted = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('[hidden]'))
      .filter((el) => el.checkVisibility?.({ checkVisibilityCSS: true }) === true)
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}` +
          `.${(el.getAttribute('class') ?? '').trim()} (display: ${getComputedStyle(el).display})`
      )
  );
  expect(
    painted,
    'elements carrying [hidden] that still render — a class rule is outranking the UA [hidden] rule'
  ).toEqual([]);
}

/**
 * Load the page with reduced motion actually in effect, and assert the content
 * every scan relies on is really on the page — including the lab's DEFAULTS,
 * which are never assumed.
 *
 * `test.use({ reducedMotion })` and the `reducedMotion` key in
 * `playwright.config.ts` are both measured no-ops on Playwright 1.61.x, so the
 * emulation is applied imperatively BEFORE the navigation and then *asserted*
 * from inside the page. That assertion is the difference between scanning the
 * reduced-motion rendering and merely believing we did.
 *
 * The theme is seeded through `localStorage` even though this lab pins
 * `data-theme="dark"` on `<html>` and ships no toggle. It costs one line and it
 * pins down a coupling that would otherwise be untested: if an anti-flash
 * script in `index.html` reads `localStorage.getItem('theme')`, the seed and
 * the pin must agree, and if the key ever drifts this boot fails on
 * `data-theme` instead of quietly scanning something else.
 *
 * The defaults are asserted at length because a navigation that resolves proves
 * NOTHING. This lab computes its first key in JS — with an LLL/descent worker
 * behind it — so a module that throws leaves the acts standing but empty, and
 * an empty region is exactly what a scan reports as perfectly accessible. That
 * is the failure `waitForTimeout(400)` used to hide.
 */
export async function boot(page: Page, theme: 'dark'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);
  await assertListSemantics(page);
  await assertHiddenAttributeHides(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main')).toHaveCount(1);

  // The shared skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run
  // says nothing about.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator(SELECTORS.app)).toHaveCount(1);

  // All five acts, present and NON-EMPTY at first paint. This lab is a scrolled
  // page rather than a tablist: nothing is lazily rendered, so "hidden and
  // empty until activated" has no analogue here and the assertion is the
  // stronger one — every act is on screen from the start, and an act that
  // rendered nothing is a renderer that threw.
  for (const act of SELECTORS.acts) {
    await expect(page.locator(act)).toHaveCount(1);
    await expect(page.locator(act)).toBeVisible();
    await expect(page.locator(act)).not.toBeEmpty();
  }

  // Dark is the only theme, so the page must carry no theme control at all —
  // not the shared bar's, and not a lab-local one. The shared CSS hides any lab
  // toggle with `display:none !important`, which would leave a dead-but-known
  // element behind; asserting the count at zero catches the day one is added
  // without going through that list.
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]')
  ).toHaveCount(0);
  await expect(page.locator('#cl-theme-toggle')).toHaveCount(0);

  // ── Every shipped control ───────────────────────────────────────────────
  // The slider's RANGE is asserted rather than its shipped value. The range is
  // the load-bearing default — the brief's dimensions are 8 to 60, below 8 the
  // Break 2 statistics are too thin to mean anything and above 60 the float LLL
  // path leaves the regime its guards were measured in — whereas which
  // dimension the lab happens to open on is an editorial choice that should not
  // need a test edit. The value is then checked to lie inside the range the
  // control itself declares, which is the part that can actually be wrong.
  const dim = page.locator(SELECTORS.dim);
  await expect(dim).toHaveAttribute('min', '8');
  await expect(dim).toHaveAttribute('max', '60');
  const shipped = Number(await dim.inputValue());
  expect(shipped, 'the shipped dimension must lie inside the slider’s own min/max').toBeGreaterThanOrEqual(8);
  expect(shipped, 'the shipped dimension must lie inside the slider’s own min/max').toBeLessThanOrEqual(60);

  // GGH's own error distribution is the default; `uniform` is the toggle Act 3
  // teaches with, and a lab that shipped it on by default would be teaching the
  // broken-attack case as if it were the scheme.
  await expect(page.locator(SELECTORS.sigma)).toHaveValue('pm3');

  for (const control of [
    SELECTORS.keygen,
    SELECTORS.encrypt,
    SELECTORS.decryptPrivate,
    SELECTORS.decryptPublic,
    SELECTORS.break1Step,
    SELECTORS.break2Run,
  ]) {
    await expect(page.locator(control)).toHaveCount(1);
  }
  // Only keygen is asserted OPERABLE at arrival: the rest legitimately wait on
  // a key or a ciphertext, and 1.4.11 exempts an inactive component, so a
  // disabled button here is a real and correct state.
  await expect(page.locator(SELECTORS.keygen)).toBeEnabled();

  // ── The arrival state: a key exists, nothing downstream has been claimed ──
  // Act 1 generates a key at the shipped dimension on load, so invariant I1 —
  // the integer U·V = I proof — is on screen at first paint, tagged with the
  // dimension it belongs to. Everything downstream of it is EMPTY, because
  // nothing has been encrypted, decrypted or attacked yet; asserting that is
  // what makes the retirement rule the drive leans on real rather than assumed.
  await expect(page.locator(SELECTORS.i1)).toBeVisible();
  await expect(page.locator(SELECTORS.i1)).not.toBeEmpty();
  await expect(page.locator(SELECTORS.i1)).toHaveAttribute('data-n', String(shipped));
  for (const readout of [
    SELECTORS.i2,
    SELECTORS.verdictDecrypt,
    SELECTORS.verdictBreak1,
    SELECTORS.verdictBreak2,
  ]) {
    await expect(page.locator(readout)).toBeEmpty();
  }

  // The signature cloud is a `<canvas>`: no oracle in this gate can read a
  // pixel of it, so the accessible name is the only part of that exhibit any of
  // them can judge — and the only part a reader who cannot see the cloud gets.
  await expect(page.locator(SELECTORS.break2Canvas)).toHaveCount(1);
  const canvasName = await page
    .locator(SELECTORS.break2Canvas)
    .evaluate(
      (el) => el.getAttribute('aria-label') ?? el.getAttribute('aria-labelledby') ?? el.textContent ?? ''
    );
  expect(
    canvasName.trim().length,
    'the signature-cloud canvas needs an accessible name — axe cannot see inside a canvas and neither can this gate'
  ).toBeGreaterThan(0);

  // ── Disclosures ship shut ───────────────────────────────────────────────
  // The shut state is what every reader arrives at, and the gate this replaces
  // scanned it exactly never — it opened every `<details>` from script before
  // its only scan. The drive opens each one later, through its `<summary>`.
  await expect(page.locator(`${SELECTORS.app} details[open]`)).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and on this page
 * it is the check most likely to bite: the lab's long values are MATRICES. A
 * 60×60 integer basis is a grid, and a grid does not reflow — `overflow-wrap`
 * has nothing to work with, because there is no text run to break. So the
 * shapes at risk here are the ones this lab cannot avoid having: a basis pair
 * laid out side by side, a ciphertext strip with one column per coordinate, and
 * any grid item whose automatic minimum size is the min-content of a row of 60
 * numbers. The correct answer is a scroll region, which is why the assertion
 * below deliberately does NOT blame an element clipped inside one — and why
 * `expectScrollersReachable` immediately demands that region be operable from
 * the keyboard. At 380px, with the acts stacked, this is the whole ballgame.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This is NOT a vacuous assertion in this lab, and that is worth stating: a
 * matrix viewer holding a 60×60 basis is a horizontal scroll region by
 * necessity, and at 380px so is almost every wide readout. A scroll region born
 * without a keyboard route is invisible to axe and unreachable to anyone not
 * using a mouse — the content is on the page and simply cannot be got to.
 * §4.2 of the template asks for `tabindex="0"` plus `role="region"` (or
 * `group`) plus an `aria-label` on exactly these containers; this check is the
 * half of that requirement a machine can enforce. It also fails on the Linux CI
 * runner in cases that pass on local Chromium, so it is asserted at every
 * driven state rather than once.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden`
 * DO remove an element from the tab order, so those are skipped rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair. It is
 * the exact inverse of the trap `assertHiddenAttributeHides` catches, and
 * between them they cover both directions of "the code thinks this is hidden".
 *
 * The candidate here is a control faded out instead of disabled — a decrypt
 * button before a ciphertext exists, the Break 1 stepper at its last step, the
 * run button mid-descent. `disabled` removes a button from the tab order;
 * `opacity: 0` or a zero-area collapse does not, and the reader is left tabbing
 * into nothing.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks above the viewport at
 * full opacity and slides in on focus. The drive scans it focused.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding as it happens and then fails at the end, so
 * a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it from inside `scan` is
 * what makes it run at every driven state, `:hover` and `:disabled` included —
 * and any baseline this repo ever records must be captured through this same
 * live path, which is the whole reason capture mode lives inside this function
 * rather than in a script beside it.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Ten assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters here because the surfaces carrying
 *    this lab's meaning are `color-mix()` fills axe cannot resolve: the three
 *    verdict tones, any tint under the I1 proof or the I2 bound, and the shared
 *    bar's ink. Everything else in that bucket is a real result axe simply
 *    could not finish — including `aria-prohibited-attr`, which is where an
 *    `aria-label` on a role-less element hides. This page leans on getting that
 *    right: a matrix viewer, a ciphertext strip and a `<canvas>` are all things
 *    whose only name is an `aria-label`, and a label on an element with no role
 *    to carry it is silently discarded.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted —
 *    SC 1.4.3 is about what a reader SEES; see `contrast.ts` for why this is
 *    measured rather than reasoned about.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1, which on a page
 *    of matrices is a live requirement rather than a formality.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 *  - the `[hidden]` cascade probe. The tabbed labs get this structurally, from
 *    a per-panel `toBeHidden()` loop in `boot`; this lab renders all five acts
 *    at once and has no such loop, so the probe runs here instead — at every
 *    driven state, which is where a mid-drive `hidden` toggle actually happens.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the shape they catch: a sticky `<header role="banner">` above a
  // `<div id="app">` holding one `<main>` with five `<section>` acts in it, the
  // shared bar's `<nav>`, and a footer. Five sibling sections, each wanting a
  // heading and possibly a `<nav>` of act links, is precisely the layout that
  // grows a duplicate landmark by accident — `landmark-unique` is the rule that
  // notices two regions with the same accessible name, which five acts built
  // from one template helper will produce the first time the name is forgotten.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // The aria-hidden walk, exemption lifted — axe skips this text entirely and
  // the default walk honours the same boundary, so this second call is the
  // ONLY thing that ever measures it. See `contrast.ts` for the inventory.
  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)
      )
    )
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
  await soft(() => assertHiddenAttributeHides(page));
}


// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Budgets for the two exhibits that do real work off the main thread.
 *
 * Neither number is tuned to a measurement, and saying so matters: they are
 * deliberately far larger than any observed run, because a budget tuned to the
 * fast case turns a slow machine into a flaky gate, and a flaky gate gets
 * disabled. They are ceilings that catch a hang, not waits — every step below
 * still completes on a real DOM signal, and reaching one of these means the
 * exhibit never finished at all.
 *
 * `WORKER_MS` covers the LLL embedding attack that finishes Break 1; the brief
 * flags dimension 60 in the browser as a case where LLL may not finish, and the
 * act is required to show the partial result and the honest time rather than
 * hang. `DESCENT_MS` covers Break 2's fourth-moment gradient descent, which
 * consumes signatures until it converges or hits the lab's own configurable cap.
 */
const WORKER_MS = 120_000;
const DESCENT_MS = 300_000;

/**
 * The Break 1 stepper cannot run away.
 *
 * Nguyen's attack is a handful of named stages — recover m mod 6 by exact
 * linear algebra, subtract, rescale, embed, reduce — so a real stepper has
 * single-digit steps. 32 is far above that, and it is a CAP rather than an
 * expectation: the loop asserts it was never reached, so a stepper that
 * silently never disables its own button fails here instead of spinning.
 */
const BREAK1_STEP_CAP = 32;

/**
 * Signatures consumed, read off the page as a number.
 *
 * The brief is explicit that this counter is measured live and never stated as
 * a constant, which is exactly why the gate parses it rather than trusting it:
 * a counter that renders "—" or "many" satisfies every accessibility rule in
 * this file and still fails the honesty rule the exhibit exists for. Thousand
 * separators and a trailing unit are fine; anything with no digits at all is
 * not — which includes an EMPTY counter, so the contract has it render "0"
 * rather than nothing before a descent has run. That is what lets the drive
 * poll this function safely as a wait.
 */
async function signaturesConsumed(page: Page): Promise<number> {
  const text = (await page.locator(SELECTORS.sigCounter).textContent()) ?? '';
  const match = text.match(/\d[\d, \s]*/);
  expect(
    match,
    `${SELECTORS.sigCounter} must print the count as a plain integer; got ${JSON.stringify(text)}`
  ).not.toBeNull();
  return Number((match ?? [''])[0].replace(/[^\d]/g, ''));
}

/**
 * Everything downstream of a changed input is retired.
 *
 * A verdict left on screen beside a fresh key is a lie about which key it
 * judged, so this is a correctness rule first — but the drive also uses it as a
 * COMPLETION SIGNAL, which is why it is a helper rather than a comment. After a
 * re-key the I1 proof renders the same "U·V = I" it rendered before; there is
 * nothing in it to wait for. The verdicts going empty is the observable event
 * that says the click landed, and without it a keygen button that silently did
 * nothing would be indistinguishable from one that worked.
 */
async function expectDownstreamRetired(page: Page, after: string): Promise<void> {
  for (const readout of [
    SELECTORS.i2,
    SELECTORS.verdictDecrypt,
    SELECTORS.verdictBreak1,
    SELECTORS.verdictBreak2,
  ]) {
    await expect(page.locator(readout), `${after} must retire ${readout}`).toBeEmpty();
  }
}

/** Generate a key at `n`, and prove the click landed rather than assuming it. */
async function keygenAt(page: Page, n: number): Promise<void> {
  await page.locator(SELECTORS.dim).fill(String(n));
  await expect(page.locator(SELECTORS.dim)).toHaveValue(String(n));
  await page.locator(SELECTORS.keygen).click();
  // `data-n` on the I1 proof is the only thing that distinguishes a new key
  // from the old one on screen — see the selector contract in `a11y.spec.ts`.
  await expect(page.locator(SELECTORS.i1)).toHaveAttribute('data-n', String(n));
  await expect(page.locator(SELECTORS.i1)).not.toBeEmpty();
  await expectDownstreamRetired(page, `a new key at dimension ${n}`);
}

/** Encrypt, and wait on the I2 bound rather than on a timer. */
async function encryptOnce(page: Page): Promise<void> {
  await page.locator(SELECTORS.encrypt).click();
  // I2 is computed per ciphertext — |e·R⁻¹|∞ against ½ — so it is empty until
  // there IS a ciphertext, and non-empty exactly when there is one.
  await expect(page.locator(SELECTORS.i2)).not.toBeEmpty();
}

/**
 * Run the Break 1 stepper to its end, scanning the states along the way.
 *
 * Two contract facts make this loop honest. `#act-3[data-step]` advances with
 * the click, so every click has a signal and a click that did nothing fails
 * here rather than passing quietly. And `#btn-break1-step` is DISABLED once
 * there is no further step, which is how the loop knows it is finished without
 * counting steps it cannot see — and which makes the final state a disabled
 * control, a state 1.4.11 exempts and this gate therefore scans deliberately
 * rather than by accident.
 *
 * The verdict is allowed to arrive later than the last step: the embedding
 * attack runs in a worker, so `data-step` can reach its end while LLL is still
 * reducing. Hence `WORKER_MS` on that one assertion and nowhere else.
 */
async function driveBreak1(
  page: Page,
  scanAt: (s: string) => Promise<void>,
  mode: string,
  expected: 'alarm' | 'fail'
): Promise<void> {
  const act3 = page.locator(SELECTORS.acts[2]);
  const step = page.locator(SELECTORS.break1Step);

  await expect(act3).toHaveAttribute('data-step', '0');
  await expect(step).toBeEnabled();
  await scanAt(`Break 1 (${mode}): the stepper at step 0, nothing solved yet`);

  let taken = 0;
  for (let i = 1; i <= BREAK1_STEP_CAP; i++) {
    if (await step.isDisabled()) break;
    await step.click();
    await expect(act3).toHaveAttribute('data-step', String(i));
    taken = i;
    if (i === 1) {
      await scanAt(`Break 1 (${mode}): one step in — c − σ·(1…1) ≡ m·B taken mod 6`);
    }
  }
  expect(taken, 'the Break 1 stepper must actually advance when its button is clicked').toBeGreaterThan(0);
  expect(
    taken,
    'the Break 1 stepper never disabled its own button — it has no end, or the end never renders'
  ).toBeLessThan(BREAK1_STEP_CAP);

  await expect(step).toBeDisabled();
  await expect(page.locator(SELECTORS.verdictBreak1)).toHaveAttribute('data-verdict', expected, {
    timeout: WORKER_MS,
  });
}

/**
 * Open every disclosure on the page, one at a time, through its `<summary>`.
 *
 * Not `details.open = true` from script, which is what the gate this replaces
 * did to every `<details>` at once before its only scan: that renders a state
 * no reader reaches and destroys the shut state, which is the state every
 * reader actually arrives at. `boot` asserts they all ship shut and the arrival
 * scan measures them that way; this opens them the way a reader does.
 *
 * The sweep is structural rather than a list of named disclosures, because this
 * lab's depth-on-demand material is exactly the part most likely to grow: the
 * HNF public-key variant, the full unimodular U, the per-coordinate round-off
 * arithmetic. A disclosure added later is scanned open without an edit here.
 * Each click still asserts a real signal — the open count going up by exactly
 * one — so a summary that does nothing fails.
 */
async function openEveryDisclosure(page: Page): Promise<number> {
  const summaries = page.locator(`${SELECTORS.app} details > summary`);
  const total = await summaries.count();
  for (let i = 0; i < total; i++) {
    await summaries.nth(i).click();
    await expect(page.locator(`${SELECTORS.app} details[open]`)).toHaveCount(i + 1);
  }
  return total;
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, exactly as a reader gets it: a key
 *    already generated at the shipped dimension, the I1 proof on screen, every
 *    downstream verdict still empty and every disclosure shut. The gate this
 *    replaces force-revealed all of it before its only scan.
 *
 *  - THE FAILURE STATES ARE THE POINT OF THIS LAB, not an edge case. Round-off
 *    with the PUBLIC basis failing is the trapdoor itself; Break 1's mod-6 step
 *    collapsing when the error stops having constant magnitude is the lesson of
 *    Act 3. Neither is reachable without deliberately asking for it, and a gate
 *    that only ever sees the happy path has never scanned the tones this lab is
 *    built to show. Both are driven, and both are scanned.
 *
 *  - DIMENSION IS A STATE. The drive re-keys at 8 — the floor, where the brief
 *    says Break 2's statistics are too thin to mean anything — and at 16, and
 *    scans at both. It is also the reflow variable: at 380px a basis is the
 *    widest thing on the page, and 8 columns and 16 columns are different
 *    layout problems.
 *
 *  - DISABLED IS A STATE, AND SO IS HOVER. This lab disables controls
 *    constantly — the stepper at its last step, the run button mid-descent —
 *    and 1.4.11 exempts an inactive component, so those states change what the
 *    non-text oracle will accept and have to be measured as themselves.
 *    `:hover` persists on the element under the pointer after `page.click()`
 *    resolves, so it is the state a reader occupies the instant after pressing
 *    a button; it is scanned explicitly.
 *
 *  - NO FIXED TIMEOUTS. Every wait is on a real DOM completion signal: a
 *    verdict's `data-verdict`, the stepper's `data-step`, the I1 proof's
 *    `data-n`, an input value, an enabled/disabled transition, a counter with a
 *    digit in it. `waitForTimeout` appears nowhere in this file.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('arrival: a key at the shipped dimension, I1 proved, nothing else claimed yet');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused, slid in from above the viewport');

  // ── Act 2: the trapdoor ─────────────────────────────────────────────────
  await encryptOnce(page);
  await scanAt('Act 2: a ciphertext c = m·B + e, with the I2 bound |e·R⁻¹|∞ shown against ½');

  await page.locator(SELECTORS.decryptPrivate).click();
  await expect(page.locator(SELECTORS.verdictDecrypt)).toHaveAttribute('data-verdict', 'pass');
  await scanAt('Act 2: Babai round-off with the PRIVATE basis — the message comes back');

  // The headline failure. Same three lines of arithmetic, other basis: this is
  // the trapdoor, and it is the one state the whole lab is built around. A gate
  // that never drove it never scanned the failure tone at all.
  await page.locator(SELECTORS.decryptPublic).click();
  await expect(page.locator(SELECTORS.verdictDecrypt)).toHaveAttribute('data-verdict', 'fail');
  await scanAt('Act 2: the same round-off with the PUBLIC basis — it does not come back');

  // ── Act 1: a fresh key at the floor, and retirement ─────────────────────
  // Dimension 8 is the brief's floor: below it Break 2's statistics are too
  // thin to mean anything, and the act says so rather than pretending. The
  // retirement assertion inside `keygenAt` is what proves the click landed —
  // the I1 proof reads the same either way.
  await keygenAt(page, 8);
  await scanAt('Act 1: re-keyed at dimension 8 — every verdict from the old key retired');

  // ── Act 3: Break 1, Nguyen 1999 ─────────────────────────────────────────
  // The attack needs a ciphertext to attack, and the fresh key retired the last
  // one. Error mode is still `pm3`, which is what makes every entry of e
  // congruent mod 2σ and the whole attack possible.
  await encryptOnce(page);
  await driveBreak1(page, scanAt, 'σ = 3', 'alarm');
  await scanAt(
    'Break 1: m recovered from the public basis alone — the alarm verdict, stepper button now disabled'
  );

  // ── The toggle that IS the lesson ───────────────────────────────────────
  // With e drawn uniformly from {−3..3} the entries are no longer all congruent
  // mod 6, and the mod-6 step has nothing to solve. Everything downstream is
  // retired by the change, which is both correct and the signal that the select
  // took effect.
  await page.locator(SELECTORS.sigma).selectOption('uniform');
  await expect(page.locator(SELECTORS.sigma)).toHaveValue('uniform');
  await expectDownstreamRetired(page, 'switching to a non-constant-magnitude error');
  await scanAt('Act 3: error mode switched to uniform — every downstream verdict retired');

  await encryptOnce(page);
  await driveBreak1(page, scanAt, 'e uniform in {−3..3}', 'fail');
  await scanAt('Break 1: the mod-6 step fails on a non-constant-magnitude error — the lesson of Act 3');

  await page.locator(SELECTORS.sigma).selectOption('pm3');
  await expect(page.locator(SELECTORS.sigma)).toHaveValue('pm3');
  await expectDownstreamRetired(page, 'switching back to σ = 3');

  // ── Act 4: Break 2, Nguyen–Regev 2006 ───────────────────────────────────
  // Dimension 16 is where the brief's own claim (C5) puts the parallelepiped
  // recovery, and it is a different reflow problem from 8.
  await keygenAt(page, 16);
  await expect(page.locator(SELECTORS.break2Canvas)).toBeVisible();
  await scanAt('Act 4: keyed at dimension 16, the signature cloud empty and waiting');

  await page.locator(SELECTORS.break2Run).click();
  // The counter is the live signal that the descent started consuming
  // signatures, and the wait is on the PARSED COUNT rising above zero rather
  // than on the text matching a digit. Measured, not chosen: the first form of
  // this waited for `/\d/` and passed instantly against the counter's own
  // resting "0 signatures consumed" — a digit was already there, so the drive
  // scanned an untouched canvas and then failed one line later on a count of 0.
  // Polling the same parser the assertion uses is what makes this a wait for
  // the descent rather than a wait for the markup.
  await expect
    .poll(() => signaturesConsumed(page), {
      message: 'the signature counter must climb off zero once the descent is consuming signatures',
      timeout: DESCENT_MS,
    })
    .toBeGreaterThan(0);
  const consumed = await signaturesConsumed(page);
  await scanAt('Act 4: the descent running — signatures consumed climbing, the cloud filling in');

  // Either documented outcome is a real state and both are scanned as whichever
  // one happens: recovery reads as ALARM (an attack that worked is never green
  // success), and exceeding the lab's configurable cap without recovery reads
  // as FAIL. Which one it is on a given run is a claim for `claims.spec.ts`
  // (C5) to pin down — asserting convergence here would make an accessibility
  // gate hostage to a statistic. What this gate requires is that a verdict
  // RENDERS: an empty verdict region is exactly what scans as perfectly
  // accessible.
  await expect(page.locator(SELECTORS.verdictBreak2)).toHaveAttribute(
    'data-verdict',
    /^(alarm|fail)$/,
    { timeout: DESCENT_MS }
  );
  const finished = await signaturesConsumed(page);
  expect(
    finished,
    'the signature counter must not go backwards — it is a measured total, not a display'
  ).toBeGreaterThanOrEqual(consumed);
  await scanAt('Act 4: the descent finished — rows of R recovered up to sign and permutation, or the cap reported');

  // ── Disclosures, opened the way a reader opens them ─────────────────────
  const opened = await openEveryDisclosure(page);
  await scanAt(`every disclosure on the page open (${opened})`);

  // ── Hover, which persists after a click ─────────────────────────────────
  await page.locator(SELECTORS.keygen).hover();
  await scanAt('a lab button hovered — its fill repainted, its edge still a 1.4.11 case');

  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered');

  // ── Focus rings on the two controls that are not buttons ────────────────
  // A range input and a select are the two places a focus ring is most often
  // lost: the slider because `appearance: none` throws the UA's ring away with
  // the UA's track, the select because §4.2 requires it to be repainted with a
  // custom chevron.
  await page.locator(SELECTORS.dim).focus();
  await expect(page.locator(SELECTORS.dim)).toBeFocused();
  await scanAt('the dimension slider focused, showing its focus-visible ring');

  await page.locator(SELECTORS.sigma).focus();
  await expect(page.locator(SELECTORS.sigma)).toBeFocused();
  await scanAt('the error-mode select focused');
}
