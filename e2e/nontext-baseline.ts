/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * IT IS EMPTY BECAUSE NOTHING HAS BEEN RECORDED, NOT BECAUSE NOTHING WAS FOUND.
 * That distinction matters, so it is stated rather than implied: this file was
 * written alongside the gate, before this lab's stylesheet existed, and no
 * capture run has been taken against it yet. An empty record is the STRICTEST
 * possible starting position — every finding the first drive turns up is `NEW`
 * and fails the run — so it cannot hide anything; it simply has not yet been
 * confirmed to be the ratchet's terminal state.
 *
 * WHAT THIS LAB IS LIKELY TO SURFACE ON ITS FIRST DRIVE, and what to do about
 * it. This page's controls are a range slider (`#dim-slider`), a `<select>`
 * (`#sigma-select`) and seven buttons, plus the shared top bar's `.cl-btn`
 * links. Three shapes in that set are the fleet's repeat offenders:
 *   - a PRIMARY button that paints its border the same colour as its own accent
 *     fill, so it has no edge of its own and lives or dies by fill-vs-surround.
 *     This lab's accent is `#35d6bb` — a light teal — and the surround is a
 *     near-black dark canvas, so fill-vs-surround should clear 3:1 comfortably
 *     here; it is the DISABLED and hover repaints that need watching.
 *   - a control whose only delineator is a low-percentage `color-mix()` toward
 *     a decorative divider token, which reads as a 1.3–2.5:1 edge.
 *   - the shared top bar's `.cl-btn`, baselined in older labs at ~1.49:1. It
 *     clears 3:1 only if its edge is drawn from the bar's own ink token.
 * A `<select>` with `appearance: none` and a custom chevron (which §4.2 of the
 * template requires) puts a `::before`/`::after` glyph on the page, so the
 * generated-content half of `nontext.ts` is live here rather than inert —
 * unlike the tab-and-disclosure labs whose only generated marks are the UA's
 * own `::marker` triangles.
 *
 * THE RULE, PLAINLY: when the gate reports `NEW …`, fix the CSS. Re-recording
 * the baseline to turn a red run green is forbidden (`CRYPTO-LAB-TEMPLATE.md`
 * line 79, "no re-recorded a11y baseline"). `NT_BASELINE_CAPTURE=1` prints every
 * finding through this same path and asserts nothing; it exists for the FIRST
 * baselining of a lab and for confirming that a fix produced zero findings —
 * never for absorbing a fresh failure.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};
